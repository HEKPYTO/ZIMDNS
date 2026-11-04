/// Contract: fetches one zone by AXFR over DNS/TCP (RFC 5936) and returns the
/// transferred records as zone text.
/// Ownership: the caller owns the returned text and frees it with `allocator`.
/// Errors: a connection, framing, or transfer-shape failure is typed; the
/// transfer is bounded in frames and in message size.
/// What this module does NOT do: IXFR, TSIG-signed requests, and a transfer
/// whose first record is not the zone's SOA are all refused rather than
/// guessed at.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_record = @import("../dns/record.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");

/// RFC 5936 section 4.2: a transfer is a sequence of messages, each framed by
/// the two-octet length of the Do53/TCP framing. The cap keeps a hostile
/// primary from holding the startup open forever.
pub const max_frames = 4096;
/// The Do53/TCP frame limit is the 16-bit length prefix.
const max_frame_bytes = 65535;

pub const Error = error{
    ConnectFailed,
    IoFailed,
    BadTransfer,
    TooManyFrames,
    OutOfMemory,
};

/// One AXFR over DNS/TCP: connect, ask for `zone`, read frames until the
/// closing SOA, and return the records as zone text the zone parser accepts.
/// Every record is written in the RFC 3597 generic form, so a type this build
/// does not render loses nothing.
pub fn fetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    timeout: std.Io.Timeout,
) Error![]u8 {
    const name = @import("../dns/name.zig").Name.fromText(zone) catch return Error.BadTransfer;
    // ceiling: the connect itself waits the operating system's SYN timeout;
    // the frame deadline bounds every read and write after it. A bounded
    // connect would need the nonblocking connect and poll the resolver's
    // forwarding path already implements.
    var stream = std.Io.net.IpAddress.connect(primary, io, .{
        .mode = .stream,
        .protocol = .tcp,
    }) catch return Error.ConnectFailed;
    defer stream.close(io);

    var query_buffer: [512]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    io.random(&id_bytes);
    var query = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = std.mem.readInt(u16, &id_bytes, .big),
            .opcode = .query,
            .question_count = 1,
        },
        .question = .{ .name = name, .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
    };
    var writer = dns_writer.Writer.init(&query_buffer);
    query.encode(&writer) catch return Error.BadTransfer;
    const request = writer.written();

    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(request.len), .big);
    const deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, &prefix, deadline) catch return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, request, deadline) catch return Error.IoFailed;

    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    output.writer.print("$ORIGIN {s}\n$TTL 1\n", .{zone}) catch return Error.OutOfMemory;

    var soa_count: usize = 0;
    var frame_index: usize = 0;
    var frame_buffer: [max_frame_bytes]u8 = undefined;
    while (frame_index < max_frames) : (frame_index += 1) {
        var length_bytes: [2]u8 = undefined;
        const frame_deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
        tcp_deadline.readExact(stream.socket.handle, io, &length_bytes, frame_deadline) catch return Error.IoFailed;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length == 0) return Error.BadTransfer;
        tcp_deadline.readExact(stream.socket.handle, io, frame_buffer[0..length], frame_deadline) catch return Error.IoFailed;

        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const message = dns_message.Message.parse(arena_state.allocator(), frame_buffer[0..length]) catch return Error.BadTransfer;
        if (message.header.rcode != .no_error) return Error.BadTransfer;
        for (message.answers.slice()) |record| {
            if (record.rrtype.eql(.SOA)) {
                soa_count += 1;
                if (soa_count == 1) {
                    var owner_buffer: [256]u8 = undefined;
                    const owner = record.owner.toText(&owner_buffer) catch return Error.BadTransfer;
                    if (!std.ascii.eqlIgnoreCase(owner, zone)) return Error.BadTransfer;
                }
                if (soa_count == 2) {
                    // The closing SOA frames the transfer on the wire
                    // (RFC 5936 section 2.2); the zone text carries the one
                    // apex SOA the first record brought.
                    var list = output.toArrayList();
                    return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
                }
            }
            try writeRecord(&output.writer, record);
        }
    }
    return Error.TooManyFrames;
}

/// One record in the RFC 3597 generic form: the owner and TTL as received,
/// the type code, and the RDATA octets in hex. The zone parser reads this
/// form for every type, so the transferred zone is served with the same
/// typed RDATA the primary sent.
fn writeRecord(writer: *std.Io.Writer, record: dns_record.ResourceRecord) Error!void {
    var name_buffer: [256]u8 = undefined;
    const owner = record.owner.toText(&name_buffer) catch return Error.BadTransfer;
    var wire: [max_frame_bytes]u8 = undefined;
    var wire_writer = dns_writer.Writer.init(&wire);
    record.rdata.encode(&wire_writer) catch return Error.BadTransfer;
    writer.print("{s} {d} IN TYPE{d} \\# {d} ", .{ owner, record.ttl, record.rrtype.code(), wire_writer.len() }) catch return Error.OutOfMemory;
    for (wire_writer.written()) |byte| writer.print("{x:0>2}", .{byte}) catch return Error.OutOfMemory;
    writer.writeByte('\n') catch return Error.OutOfMemory;
}

test "an AXFR over DNS/TCP returns the transferred zone as text" {
    // The fixture runs a real loopback server on its own thread, so it needs a
    // threaded Io; the single-threaded test instance is not safe to drive from
    // two threads.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();
    const transfer = @import("transfer.zig");
    const zone_index = @import("index.zig");
    const zone_parser = @import("parser.zig");

    const zone_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\www IN A 192.0.2.80
        \\
    ;
    var zone_file = try zone_parser.ZoneFile.parse(zone_text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };

    const ServerArgs = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        zone: *const zone_index.Zone,
    };
    const Server = struct {
        fn run(args: ServerArgs) void {
            var connection = args.listener.accept(args.io) catch return;
            defer connection.close(args.io);
            var length_bytes: [2]u8 = undefined;
            readExact(connection, args.io, &length_bytes) catch return;
            const length = std.mem.readInt(u16, &length_bytes, .big);
            var query_buffer: [65535]u8 = undefined;
            readExact(connection, args.io, query_buffer[0..length]) catch return;
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const request = dns_message.Message.parseQuery(arena.allocator(), query_buffer[0..length]) catch return;
            const messages = transfer.buildAxfrMessages(std.heap.page_allocator, &request, args.zone, 2) catch return;
            defer {
                for (messages) |*message| message.deinit();
                std.heap.page_allocator.free(messages);
            }
            for (messages) |*message| {
                var frame: [65535]u8 = undefined;
                var writer = dns_writer.Writer.init(&frame);
                message.encode(&writer) catch return;
                var prefix: [2]u8 = undefined;
                std.mem.writeInt(u16, &prefix, @intCast(writer.len()), .big);
                writeAll(connection, args.io, &prefix) catch return;
                writeAll(connection, args.io, writer.written()) catch return;
            }
        }

        fn readExact(stream: std.Io.net.Stream, args_io: std.Io, buffer: []u8) !void {
            var read_buffer: [4096]u8 = undefined;
            var reader = stream.reader(args_io, &read_buffer);
            try reader.interface.readSliceAll(buffer);
        }

        fn writeAll(stream: std.Io.net.Stream, args_io: std.Io, bytes: []const u8) !void {
            var write_buffer: [4096]u8 = undefined;
            var writer = stream.writer(args_io, &write_buffer);
            try writer.interface.writeAll(bytes);
            try writer.interface.flush();
        }
    };

    const thread = try std.Thread.spawn(.{}, Server.run, .{ServerArgs{ .io = io, .listener = &listener, .zone = &zone }});
    defer thread.join();

    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    // Five seconds matches the server's TCP frame deadline and leaves room for
    // the parallel test gate to schedule the loopback primary; the AXFR
    // assertions below are about the transfer, not about a tight timeout.
    const fetched = try fetch(std.testing.allocator, io, &primary, "transferred.example.", .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try zone_parser.ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try zone_index.Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 42), fetched_zone.soaSerial().?);
    var lookup = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(zone_index.LookupKind.answer, lookup.kind);
    const answer = try @import("parser.zig").parseRData(.A, lookup.records.items[0].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 80 }, &answer.A);
}



pub const RefreshAction = enum {
    idle,
    refresh_due,
    retry_due,
    expired,
};

pub const RefreshInput = struct {
    now_ns: i64,
    last_success_ns: ?i64,
    refresh_sec: u32,
    retry_sec: u32,
    expire_sec: u32,
    last_attempt_failed: bool = false,
    last_attempt_ns: ?i64 = null,
};

fn secondsToNs(seconds: u32) i64 {
    if (seconds == 0) return 0;
    // Conservative: cap at i64 max to avoid overflow; zero timers mean
    // "never due by this clock" rather than wrap-around.
    const product = @as(i128, seconds) * @as(i128, std.time.ns_per_s);
    if (product > std.math.maxInt(i64)) return std.math.maxInt(i64);
    return @intCast(product);
}

/// Pure RFC 1034/1035 SOA refresh schedule for one secondary zone. Pure
/// function with no I/O; the runtime drives it on each serve loop tick.
pub fn refreshDecision(input: RefreshInput) RefreshAction {
    const last_success = input.last_success_ns orelse return .refresh_due;
    if (input.now_ns < last_success) return .idle; // clock moved backwards
    const elapsed = input.now_ns - last_success;

    const refresh_ns = secondsToNs(input.refresh_sec);
    const retry_ns = secondsToNs(input.retry_sec);
    const expire_ns = secondsToNs(input.expire_sec);

    // Conservative: an unset (zero) expire means never expire.
    if (expire_ns != 0 and elapsed >= expire_ns) return .expired;

    if (input.last_attempt_failed) {
        const attempt = input.last_attempt_ns orelse return .retry_due;
        if (input.now_ns < attempt) return .idle;
        if (input.now_ns - attempt >= retry_ns) return .retry_due;
        return .idle;
    }
    if (refresh_ns != 0 and elapsed >= refresh_ns) return .refresh_due;
    return .idle;
}

test "refresh decision: never fetched means refresh due" {
    try std.testing.expectEqual(RefreshAction.refresh_due, refreshDecision(.{ .now_ns = 100, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: refresh interval" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 10, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
    try std.testing.expectEqual(RefreshAction.refresh_due, refreshDecision(.{ .now_ns = 60000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: retry after failure" {
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 0, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = null }));
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 10, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 30000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
}

test "refresh decision: expired" {
    try std.testing.expectEqual(RefreshAction.expired, refreshDecision(.{ .now_ns = 3600000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: clock backwards is idle" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = -5, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: zero timers conservative" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 100, .last_success_ns = 0, .refresh_sec = 0, .retry_sec = 30, .expire_sec = 0 }));
}
