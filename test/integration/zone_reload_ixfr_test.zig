/// Contract: a zone reloaded from its zone file serves the new data, and an
/// IXFR client at the pre-reload serial gets the incremental answer while a
/// client at an unknown serial still gets the full transfer.
/// Ownership: the test owns the runtime, the sockets, and the temporary
/// directory; every opened handle is closed before the test returns.
/// Errors: a failed expectation fails the test.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const Runtime = zimdns.auth_runtime.Runtime;
const dns_message = zimdns.dns_message;
const dns_name = zimdns.dns_name;
const dns_record = zimdns.dns_record;
const dns_writer = zimdns.dns_writer;

const zone_origin = "example.";
const zone_file_name = "zone.txt";
const zone_serial: u32 = 10;
const next_zone_serial: u32 = 11;

const zone_text =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\
;

const next_zone_text =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.2
    \\
;

const ixfr_type: @FieldType(dns_record.ResourceRecord, "rrtype") = .IXFR;

/// A runtime that serves `zone_text` and can reload it from its zone file.
fn loadReloadableRuntime(io: std.Io, tmp: *std.testing.TmpDir) !Runtime {
    try tmp.dir.writeFile(io, .{ .sub_path = zone_file_name, .data = zone_text });
    var runtime = try Runtime.fromZoneText(zone_text);
    errdefer runtime.deinit();
    // The transfer ACL denies by default; this loopback grant permits the fixture's IXFR.
    try runtime.addTransferAllow(zone_origin, try zimdns.config_parser.Cidr.parse("127.0.0.1/32"));
    try runtime.setReloadSource(tmp.dir, zone_file_name, zone_origin);
    return runtime;
}

/// The operator replaces the zone file and asks for the reload, exactly as
/// the SIGHUP handler does.
fn requestReload(io: std.Io, tmp: *std.testing.TmpDir, runtime: *Runtime) !void {
    try tmp.dir.writeFile(io, .{ .sub_path = zone_file_name, .data = next_zone_text });
    runtime.requestZoneReload();
}

test "a reloaded zone file serves the new data" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var runtime = try loadReloadableRuntime(io, &tmp);
    defer runtime.deinit();
    try requestReload(io, &tmp, &runtime);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4b01, "www.example.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    // The serve path performs the reload the handler asked for.
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &response.answers.items[0].rdata.A);
}

test "a reloaded zone keeps serving the old data when its zone file is broken" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var runtime = try loadReloadableRuntime(io, &tmp);
    defer runtime.deinit();
    // A zone file that does not parse must not replace the served zone.
    try tmp.dir.writeFile(io, .{ .sub_path = zone_file_name, .data = "not a zone file\n" });
    runtime.requestZoneReload();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4b02, "www.example.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
}

test "an IXFR from the pre-reload serial is answered incrementally" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var runtime = try loadReloadableRuntime(io, &tmp);
    defer runtime.deinit();
    try requestReload(io, &tmp, &runtime);

    const frames = try exchangeIxfr(arena.allocator(), io, &runtime, zone_serial);
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    const answers = frames[0].answers.slice();
    // The incremental sequence opens with the current SOA and carries the
    // superseded SOA the client asked from.
    try std.testing.expect(answers[0].rrtype.eql(.SOA));
    try std.testing.expectEqual(next_zone_serial, answers[0].rdata.SOA.serial);
    try std.testing.expect(answers[1].rrtype.eql(.SOA));
    try std.testing.expectEqual(zone_serial, answers[1].rdata.SOA.serial);
    // The added section carries the reloaded zone's records.
    try std.testing.expectEqual(@as(usize, 1), countAddress(answers, 192, 0, 2, 2));
    try std.testing.expectEqual(@as(usize, 1), countAddress(answers, 192, 0, 2, 1));
    // The sequence closes with the current SOA.
    const last = answers[answers.len - 1];
    try std.testing.expect(last.rrtype.eql(.SOA));
    try std.testing.expectEqual(next_zone_serial, last.rdata.SOA.serial);
}

test "an IXFR from an unknown serial still gets the full transfer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var runtime = try loadReloadableRuntime(io, &tmp);
    defer runtime.deinit();
    try requestReload(io, &tmp, &runtime);

    const frames = try exchangeIxfr(arena.allocator(), io, &runtime, zone_serial - 5);
    const answers = frames[0].answers.slice();
    // The full transfer carries the current zone only: no SOA of a serial the
    // server no longer serves.
    try std.testing.expect(answers[0].rrtype.eql(.SOA));
    try std.testing.expectEqual(next_zone_serial, answers[0].rdata.SOA.serial);
    for (answers) |record| {
        if (!record.rrtype.eql(.SOA)) continue;
        try std.testing.expectEqual(next_zone_serial, record.rdata.SOA.serial);
    }
    try std.testing.expectEqual(@as(usize, 1), countAddress(answers, 192, 0, 2, 2));
    const last = answers[answers.len - 1];
    try std.testing.expect(last.rrtype.eql(.SOA));
    try std.testing.expectEqual(next_zone_serial, last.rdata.SOA.serial);
}

const TcpServerArgs = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    runtime: *Runtime,
    ok: bool = false,

    fn run(self: *@This()) void {
        const stream = self.server.accept(self.io) catch return;
        defer stream.close(self.io);
        listener.serveTcpStreamOnce(stream, self.io, self.runtime) catch return;
        self.ok = true;
    }
};

/// One IXFR exchange over a loopback TCP connection: the query carries the
/// client's serial in its authority SOA, and the reply is read as
/// two-octet-prefixed frames to end of stream.
fn exchangeIxfr(allocator: std.mem.Allocator, io: std.Io, runtime: *Runtime, client_serial: u32) ![]dns_message.Message {
    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try buildIxfrQuery(&query_buffer, 0x4b03, client_serial);
    try cli_query.sendTcpQuery(client, io, query);
    try client.shutdown(io, .send);

    var args = TcpServerArgs{ .io = io, .server = &server, .runtime = runtime };
    const thread = try std.Thread.spawn(.{}, TcpServerArgs.run, .{&args});

    var read_buffer: [4096]u8 = undefined;
    var reader = client.reader(io, &read_buffer);
    const frames = try readTransferSequence(allocator, &reader.interface);
    thread.join();
    try std.testing.expect(args.ok);
    return frames;
}

/// RFC 1995 IXFR request: the question plus the client's serial in an
/// authority SOA owned by the question name.
fn buildIxfrQuery(buffer: []u8, id: u16, client_serial: u32) ![]const u8 {
    const base = try cli_query.buildQueryPacket(buffer, id, zone_origin, ixfr_type, false);
    std.mem.writeInt(u16, buffer[8..10], 1, .big);
    const client_soa = dns_record.ResourceRecord{
        .owner = try dns_name.Name.fromText(zone_origin),
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns.example."),
            .rname = try dns_name.Name.fromText("hostmaster.example."),
            .serial = client_serial,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
    var writer = dns_writer.Writer.init(buffer[base.len..]);
    try client_soa.encode(&writer);
    return buffer[0 .. base.len + writer.len()];
}

fn readTransferSequence(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]dns_message.Message {
    var frames: std.ArrayList(dns_message.Message) = .empty;
    while (true) {
        const len_bytes = reader.takeArray(2) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const length = std.mem.readInt(u16, len_bytes, .big);
        try std.testing.expect(length > 0);
        try frames.append(allocator, try dns_message.Message.parse(allocator, try reader.take(length)));
    }
    try std.testing.expect(frames.items.len > 0);
    return frames.toOwnedSlice(allocator);
}

fn countAddress(answers: []const dns_record.ResourceRecord, a: u8, b: u8, c: u8, d: u8) usize {
    var count: usize = 0;
    for (answers) |record| {
        if (!record.rrtype.eql(.A)) continue;
        if (!std.mem.eql(u8, &record.rdata.A, &.{ a, b, c, d })) continue;
        count += 1;
    }
    return count;
}
