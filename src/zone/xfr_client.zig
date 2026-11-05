/// Contract: fetches one zone over DNS/TCP, by AXFR (RFC 5936) or by an
/// incremental IXFR delta (RFC 1995) applied to the served copy.
/// Ownership: the caller owns the returned text and frees it with `allocator`.
/// Errors: a connection, framing, or transfer-shape failure is typed; the
/// transfer is bounded in frames and in message size.
/// What this module does NOT do: TSIG-signed requests, and a transfer whose
/// first record is not the zone's SOA are refused rather than guessed at.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_record = @import("../dns/record.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const zone_mod = @import("index.zig");
const zone_update = @import("update.zig");

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
        if (message.header.truncated) return Error.BadTransfer;
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
/// One IXFR over DNS/TCP (RFC 1995 section 3): ask with the served copy's
/// serial, then either keep the copy, fall back to a full AXFR when the
/// primary answers with the full zone, or apply the incremental delta to the
/// records the copy already holds and return the rebuilt zone text.
pub fn fetchIxfr(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    current: *const zone_mod.Zone,
    timeout: std.Io.Timeout,
) Error![]u8 {
    const name = @import("../dns/name.zig").Name.fromText(zone) catch return Error.BadTransfer;
    const current_serial = current.soaSerial() orelse return fetch(allocator, io, primary, zone, timeout);
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
            .authority_count = 1,
        },
        .question = .{ .name = name, .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .authorities = dns_message.RecordSection.init(allocator, 1) catch return Error.OutOfMemory,
    };
    defer query.deinit();
    query.authorities.append(.{
        .owner = name,
        .rrtype = dns_types.RecordType.SOA,
        .class = dns_types.Class.IN,
        .ttl = 0,
        .rdata = .{ .SOA = .{
            .mname = name,
            .rname = name,
            .serial = current_serial,
            .refresh = 0,
            .retry = 0,
            .expire = 0,
            .minimum = 0,
        } },
    }) catch return Error.OutOfMemory;
    var writer = dns_writer.Writer.init(&query_buffer);
    query.encode(&writer) catch return Error.BadTransfer;
    const request = writer.written();

    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(request.len), .big);
    const deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, &prefix, deadline) catch return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, request, deadline) catch return Error.IoFailed;

    // The parsed answer records point into these bytes; the arena outlives
    // every frame so the delta can be applied after the last frame arrives.
    var response_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer response_arena_state.deinit();
    const response_arena = response_arena_state.allocator();

    const Phase = enum { first, second, deletions, additions, done, full, full_done };
    var phase: Phase = .first;
    var soa_seen: usize = 0;
    var total_answers: usize = 0;
    var new_serial: u32 = 0;
    var deletions: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer deletions.deinit(response_arena);
    var additions: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer additions.deinit(response_arena);
    var serial_added = false;
    var first_soa_record: ?dns_record.ResourceRecord = null;
    var full_records: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer full_records.deinit(response_arena);
    var full_soa_seen: usize = 0;

    var frame_index: usize = 0;
    var frame_buffer: [max_frame_bytes]u8 = undefined;
    while (frame_index < max_frames) : (frame_index += 1) {
        var length_bytes: [2]u8 = undefined;
        const frame_deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
        tcp_deadline.readExact(stream.socket.handle, io, &length_bytes, frame_deadline) catch return Error.IoFailed;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length == 0) return Error.BadTransfer;
        tcp_deadline.readExact(stream.socket.handle, io, frame_buffer[0..length], frame_deadline) catch return Error.IoFailed;
        const message = dns_message.Message.parse(response_arena, frame_buffer[0..length]) catch return Error.BadTransfer;
        if (message.header.truncated) return Error.BadTransfer;
        if (message.header.rcode != .no_error) return Error.BadTransfer;
        for (message.answers.slice()) |record| {
            total_answers += 1;
            if (record.rrtype.eql(.SOA)) {
                soa_seen += 1;
                const serial = switch (record.rdata) {
                    .SOA => |soa| soa.serial,
                    else => return Error.BadTransfer,
                };
                switch (phase) {
                    .first => {
                        var owner_buffer: [256]u8 = undefined;
                        const owner = record.owner.toText(&owner_buffer) catch return Error.BadTransfer;
                        if (!std.ascii.eqlIgnoreCase(owner, zone)) return Error.BadTransfer;
                        // RFC 1982: the first SOA must be newer than the served
                        // copy, unless it equals it (the up-to-date answer is
                        // a single SOA, checked below). Anything else is a
                        // stale or wrapped answer the refresh must not apply.
                        if (serial != current_serial and !zone_update.serialGreaterThan(serial, current_serial)) return Error.BadTransfer;
                        new_serial = serial;
                        first_soa_record = record;
                        phase = .second;
                    },
                    .second => {
                        if (serial == new_serial) return Error.BadTransfer;
                        phase = .deletions;
                    },
                    .deletions => {
                        // The old SOA frames the deletions; the next new SOA
                        // opens the additions and carries the new serial.
                        // A second delta's boundary SOA is neither the served
                        // serial nor the final serial: reject it so the refresh
                        // retries instead of misapplying half a delta.
                        if (serial != new_serial) return Error.BadTransfer;
                        additions.append(response_arena, record) catch return Error.OutOfMemory;
                        serial_added = true;
                        phase = .additions;
                    },
                    .additions => {
                        if (serial == new_serial) {
                            phase = .done;
                            break;
                        }
                        return Error.BadTransfer;
                    },
                    .done, .full_done => return Error.BadTransfer,
                    .full => {
                        full_soa_seen += 1;
                        if (full_soa_seen == 2) {
                            phase = .full_done;
                            break;
                        }
                        full_records.append(response_arena, record) catch return Error.OutOfMemory;
                    },
                }
                continue;
            }
            switch (phase) {
                .deletions => {
                    var deleted = record;
                    // RFC 2136 section 2.4: a delete-one RR carries the
                    // record to match, with class NONE and TTL zero.
                    deleted.class = dns_types.Class.fromCode(254);
                    deleted.ttl = 0;
                    deletions.append(response_arena, deleted) catch return Error.OutOfMemory;
                },
                .additions => {
                    if (!record.class.eql(dns_types.Class.IN)) return Error.BadTransfer;
                    additions.append(response_arena, record) catch return Error.OutOfMemory;
                    if (record.rrtype.eql(.SOA)) serial_added = true;
                },
                .second => {
                    // A non-SOA second record shows the full zone: fall back
                    // to the AXFR-shaped answer on this same connection.
                    full_records.append(response_arena, first_soa_record.?) catch return Error.OutOfMemory;
                    full_records.append(response_arena, record) catch return Error.OutOfMemory;
                    full_soa_seen = 1;
                    phase = .full;
                },
                .first => return Error.BadTransfer,
                .full => {
                    full_records.append(response_arena, record) catch return Error.OutOfMemory;
                },
                .done, .full_done => {},
            }
        }
        if (phase == .done or phase == .full_done) break;
        // RFC 1995 section 2: the up-to-date answer is a single SOA carrying
        // the served serial. Anything else alone is not up-to-date.
        if (total_answers == 1 and soa_seen == 1 and phase == .second) {
            if (new_serial != current_serial) return Error.BadTransfer;
            return zone_update.renderZoneText(allocator, zone, current.records.items[0..current.records.len]);
        }
    }
    if (phase == .full_done) {
        // RFC 1995 section 4: the primary answered with the whole zone. Write
        // the same generic text `fetch` writes, minus the closing SOA.
        var output = std.Io.Writer.Allocating.init(allocator);
        errdefer output.deinit();
        output.writer.print("$ORIGIN {s}\n$TTL 1\n", .{zone}) catch return Error.OutOfMemory;
        for (full_records.items) |record| try writeRecord(&output.writer, record);
        var list = output.toArrayList();
        return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
    }
    if (phase != .done) return Error.BadTransfer;
    if (!serial_added) return Error.BadTransfer;
    // One RFC 2136 transaction carries the delta in RFC 1995 order: the
    // delete-one records first, then the added records (the new SOA included,
    // so the primary's serial is applied exactly rather than raised by one).
    var updates: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer updates.deinit(allocator);
    updates.appendSlice(allocator, deletions.items) catch return Error.OutOfMemory;
    updates.appendSlice(allocator, additions.items) catch return Error.OutOfMemory;
    const outcome = zone_update.apply(allocator, current, zone, &.{}, updates.items) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
    };
    return switch (outcome) {
        .zone_text => |text| text,
        .rcode => Error.BadTransfer,
    };
}

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
    // The fixture runs a real loopback server on its own thread. The two
    // sides get separate threaded Io backends: sharing one backend across a
    // blocked accept and a blocked client poll can starve the poll and turn
    // the transfer into a timeout under a loaded test gate.
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
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
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };

    const ServerArgs = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        zone: *const zone_index.Zone,
        ready: *std.atomic.Value(bool),
    };
    const Server = struct {
        fn run(args: ServerArgs) void {
            args.ready.store(true, .release);
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

    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, Server.run, .{ServerArgs{ .io = server_io, .listener = &listener, .zone = &zone, .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    // Fifteen seconds leaves room for a loaded parallel test runner to
    // schedule the loopback primary; the AXFR assertions below are about
    // the transfer, not about a tight timeout.
    const fetched = try fetch(std.testing.allocator, io, &primary, "transferred.example.", .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
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

const FrameServerArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    bytes: []const u8,
    ready: *std.atomic.Value(bool),
};
const FrameServer = struct {
    fn run(args: FrameServerArgs) void {
        args.ready.store(true, .release);
        var connection = args.listener.accept(args.io) catch return;
        defer connection.close(args.io);
        var length_bytes: [2]u8 = undefined;
        readExact(connection, args.io, &length_bytes) catch return;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        var query_buffer: [65535]u8 = undefined;
        readExact(connection, args.io, query_buffer[0..length]) catch return;
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(args.bytes.len), .big);
        writeAll(connection, args.io, &prefix) catch return;
        writeAll(connection, args.io, args.bytes) catch return;
    }
    fn readExact(stream: std.Io.net.Stream, stream_io: std.Io, buffer: []u8) !void {
        var read_buffer: [4096]u8 = undefined;
        var reader = stream.reader(stream_io, &read_buffer);
        try reader.interface.readSliceAll(buffer);
    }
    fn writeAll(stream: std.Io.net.Stream, stream_io: std.Io, bytes: []const u8) !void {
        var write_buffer: [4096]u8 = undefined;
        var writer = stream.writer(stream_io, &write_buffer);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }
};

fn testSoa(owner: []const u8, serial: u32) !dns_record.ResourceRecord {
    const name = try @import("../dns/name.zig").Name.fromText(owner);
    return .{
        .owner = name,
        .rrtype = dns_types.RecordType.SOA,
        .class = dns_types.Class.IN,
        .ttl = 0,
        .rdata = .{ .SOA = .{
            .mname = name,
            .rname = name,
            .serial = serial,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
}

fn testA(owner: []const u8, address: [4]u8) !dns_record.ResourceRecord {
    return .{
        .owner = try @import("../dns/name.zig").Name.fromText(owner),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .A = address },
    };
}

test "an incremental IXFR applies the delta to the served copy" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\dns IN A 192.0.2.54
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4242,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 6,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("dns.transferred.example.", .{ 192, 0, 2, 54 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 43), fetched_zone.soaSerial().?);
    var added = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer added.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, added.kind);
    const added_rdata = try @import("parser.zig").parseRData(.A, added.records.items[0].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 99 }, &added_rdata.A);
    var deleted = fetched_zone.lookup(std.testing.allocator, "dns.transferred.example.", .A);
    defer deleted.deinit(std.testing.allocator);
    try std.testing.expect(deleted.kind != @import("index.zig").LookupKind.answer);
}

test "an IXFR answered with the full zone is applied without a second connection" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4244,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 5,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 5),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(.{
        .owner = try @import("../dns/name.zig").Name.fromText(zone_name),
        .rrtype = dns_types.RecordType.NS,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .NS = try @import("../dns/name.zig").Name.fromText("ns.transferred.example.") },
    });
    try response.answers.append(try testA("dns.transferred.example.", .{ 192, 0, 2, 54 }));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 43), fetched_zone.soaSerial().?);
    var added = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer added.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, added.kind);
}

test "an up-to-date IXFR keeps the served copy" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\dns IN A 192.0.2.54
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4243,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 1,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 42), fetched_zone.soaSerial().?);
    var kept = fetched_zone.lookup(std.testing.allocator, "dns.transferred.example.", .A);
    defer kept.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, kept.kind);
}

test "an IXFR with an older first SOA is rejected and the served copy is untouched" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 43 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4250, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 6 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("evil.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 43), current.soaSerial().?);
}

test "a single-SOA IXFR with a different serial is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4251, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 1 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}

test "a two-delta IXFR is rejected rather than half-applied" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4252, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 9 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 9),
    };
    try response.answers.append(try testSoa(zone_name, 44));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("a.transferred.example.", .{ 192, 0, 2, 1 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("b.transferred.example.", .{ 192, 0, 2, 2 }));
    try response.answers.append(try testSoa(zone_name, 44));
    try response.answers.append(try testSoa(zone_name, 44));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}
const TwoFrameServerArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    first: []const u8,
    second: []const u8,
    ready: *std.atomic.Value(bool),
};
const TwoFrameServer = struct {
    fn run(args: TwoFrameServerArgs) void {
        args.ready.store(true, .release);
        var connection = args.listener.accept(args.io) catch return;
        defer connection.close(args.io);
        var length_bytes: [2]u8 = undefined;
        FrameServer.readExact(connection, args.io, &length_bytes) catch return;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        var query_buffer: [65535]u8 = undefined;
        FrameServer.readExact(connection, args.io, query_buffer[0..length]) catch return;
        for ([_][]const u8{ args.first, args.second }) |bytes| {
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(bytes.len), .big);
            FrameServer.writeAll(connection, args.io, &prefix) catch return;
            FrameServer.writeAll(connection, args.io, bytes) catch return;
        }
    }
};

test "an AXFR frame with TC set is rejected as a failed transfer" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4260, .qr = true, .truncated = true, .opcode = .query, .question_count = 1, .answer_count = 2 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 2),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetch(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
}

test "an IXFR first frame with TC set is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4261, .qr = true, .truncated = true, .opcode = .query, .question_count = 1, .answer_count = 6 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [65535]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = frame_writer.written(), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}

test "an IXFR with TC set on a later frame is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var first = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4262, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 2 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 2),
    };
    try first.answers.append(try testSoa(zone_name, 43));
    try first.answers.append(try testSoa(zone_name, 42));
    var second = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4262, .qr = true, .truncated = true, .opcode = .query, .answer_count = 1 },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try second.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    var first_buffer: [65535]u8 = undefined;
    var first_writer = dns_writer.Writer.init(&first_buffer);
    try first.encode(&first_writer);
    const first_bytes = first_writer.written();
    var second_buffer: [65535]u8 = undefined;
    var second_writer = dns_writer.Writer.init(&second_buffer);
    try second.encode(&second_writer);
    const second_bytes = second_writer.written();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, TwoFrameServer.run, .{TwoFrameServerArgs{ .io = server_io, .listener = &listener, .first = first_bytes, .second = second_bytes, .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
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
