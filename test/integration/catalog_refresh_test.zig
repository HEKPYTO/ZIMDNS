/// Contract: an RFC 9432 catalog consumer reads its catalog and members at
/// start, adds a member the catalog later publishes, drops one it stops
/// publishing, and answers a NOTIFY for the catalog by reading it again.
/// Ownership: the test owns both runtimes, both listeners, and every socket;
/// all are released before it returns.
/// Errors: a failed expectation fails the test.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const Runtime = zimdns.auth_runtime.Runtime;
const dns_message = zimdns.dns_message;

const catalog_apex = "catalog.example.";
/// Mirrors `auth.runtime.catalog_refresh_window_ns`.
const catalog_window_ms: u64 = 1000;

const boot_text =
    \\$ORIGIN boot.
    \\$TTL 3600
    \\@ IN SOA ns.boot. hostmaster.boot. 1 3600 900 1209600 3600
    \\@ IN NS ns.boot.
    \\host IN A 192.0.2.9
    \\
;

const first_member_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

const second_member_text =
    \\$ORIGIN two.example.
    \\$TTL 3600
    \\@ IN SOA ns.two.example. hostmaster.two.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.two.example.
    \\www IN A 192.0.2.2
    \\
;

/// Secondaries refresh on the SOA timers (REFRESH 1, RETRY 1, EXPIRE 3),
/// so a test can advance the clock past the refresh interval and observe
/// the pull.
const refresh_member_v1_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 1 1 1 3 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

const refresh_member_v2_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 2 1 1 3 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

const first_catalog_text =
    \\$ORIGIN catalog.example.
    \\$TTL 3600
    \\@ IN SOA invalid. hostmaster.invalid. 2 3600 900 1209600 3600
    \\@ IN NS invalid.
    \\version IN TXT "2"
    \\m1.zones IN PTR one.example.
    \\
;

const second_catalog_text =
    \\$ORIGIN catalog.example.
    \\$TTL 3600
    \\@ IN SOA invalid. hostmaster.invalid. 3 3600 900 1209600 3600
    \\@ IN NS invalid.
    \\version IN TXT "2"
    \\m2.zones IN PTR two.example.
    \\
;

const third_catalog_text =
    \\$ORIGIN catalog.example.
    \\$TTL 3600
    \\@ IN SOA invalid. hostmaster.invalid. 4 3600 900 1209600 3600
    \\@ IN NS invalid.
    \\version IN TXT "2"
    \\m3.zones IN PTR two.example.
    \\
;

const fourth_catalog_text =
    \\$ORIGIN catalog.example.
    \\$TTL 3600
    \\@ IN SOA invalid. hostmaster.invalid. 5 3600 900 1209600 3600
    \\@ IN NS invalid.
    \\version IN TXT "2"
    \\m4.zones IN PTR one.example.
    \\
;

/// A member whose apex ZONEMD digest cannot match the data it carries.
const bad_digest_member_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.one.example.
    \\@ IN ZONEMD 1 1 1 (
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000 )
    \\www IN A 192.0.2.1
    \\
;

/// Serves `connections` transfers from one runtime, then stops.
const TransferServer = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    runtime: *Runtime,
    connections: usize,
    thread: std.Thread = undefined,
    ok: bool = false,

    fn run(self: *@This()) void {
        var served: usize = 0;
        while (served < self.connections) : (served += 1) {
            const stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);
            listener.serveTcpStreamOnce(stream, self.io, self.runtime) catch return;
        }
        self.ok = true;
    }
};

fn startPrimary(io: std.Io, server: *std.Io.net.Server, runtime: *Runtime, connections: usize) !*TransferServer {
    const args = try std.testing.allocator.create(TransferServer);
    args.* = .{ .io = io, .server = server, .runtime = runtime, .connections = connections };
    args.thread = try std.Thread.spawn(.{}, TransferServer.run, .{args});
    return args;
}

fn joinPrimary(args: *TransferServer, joined: *bool) !void {
    args.thread.join();
    joined.* = true;
    try std.testing.expect(args.ok);
}

test "a catalog consumer adds, replaces, and drops members on refresh" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var first_primary = try Runtime.fromZoneTexts(&.{ first_catalog_text, first_member_text });
    defer first_primary.deinit();
    var second_primary = try Runtime.fromZoneTexts(&.{ second_catalog_text, second_member_text });
    defer second_primary.deinit();

    // First catalog: one member, fetched once for the catalog and once for
    // the member.
    var first_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var first_server = try std.Io.net.IpAddress.listen(&first_addr, io, .{ .reuse_address = true });
    const first_args = try startPrimary(io, &first_server, &first_primary, 2);
    var first_joined = false;
    // On a failed expectation the listener is closed first, so the accept
    // loop returns and the join cannot hang; the struct outlives both.
    defer {
        first_server.deinit(io);
        if (!first_joined) first_args.thread.join();
        std.testing.allocator.destroy(first_args);
    }

    var consumer = try Runtime.fromZoneTexts(&.{boot_text});
    defer consumer.deinit();
    try consumer.setCatalogConsumer(catalog_apex, first_server.socket.address, null);
    consumer.requestCatalogRefresh();
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .updated), consumer.refreshCatalogIfRequested(io));
    try joinPrimary(first_args, &first_joined);

    try expectAddress(io, &consumer, "www.one.example.", 192, 0, 2, 1);
    try expectAddress(io, &consumer, "host.boot.", 192, 0, 2, 9);

    // A NOTIFY for the catalog sets the refresh request the serve path
    // answers; the second refresh finds an unchanged serial and fetches only
    // the catalog.
    // The refresh window has to pass before the next attempt starts.
    try std.Io.sleep(io, .fromMilliseconds(catalog_window_ms + 100), .awake);
    var second_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var second_server = try std.Io.net.IpAddress.listen(&second_addr, io, .{ .reuse_address = true });
    const second_args = try startPrimary(io, &second_server, &second_primary, 3);
    var second_joined = false;
    defer {
        second_server.deinit(io);
        if (!second_joined) second_args.thread.join();
        std.testing.allocator.destroy(second_args);
    }

    try consumer.setCatalogConsumer(catalog_apex, second_server.socket.address, null);
    try sendNotify(io, &consumer);
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .updated), consumer.refreshCatalogIfRequested(io));
    try expectAddress(io, &consumer, "www.two.example.", 192, 0, 2, 2);
    // The member the new catalog stopped naming is no longer served.
    try expectRefused(io, &consumer, "www.one.example.");

    // A second read of the same catalog changes nothing and fetches no
    // member. The refresh window has to pass again.
    try std.Io.sleep(io, .fromMilliseconds(catalog_window_ms + 100), .awake);
    consumer.requestCatalogRefresh();
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .unchanged), consumer.refreshCatalogIfRequested(io));
    try joinPrimary(second_args, &second_joined);

    // The same member under a new label is removed and added again with
    // fresh state (RFC 9432 section 5.4).
    try std.Io.sleep(io, .fromMilliseconds(catalog_window_ms + 100), .awake);
    var third_primary = try Runtime.fromZoneTexts(&.{ third_catalog_text, second_member_text });
    defer third_primary.deinit();
    var third_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var third_server = try std.Io.net.IpAddress.listen(&third_addr, io, .{ .reuse_address = true });
    const third_args = try startPrimary(io, &third_server, &third_primary, 2);
    var third_joined = false;
    defer {
        third_server.deinit(io);
        if (!third_joined) third_args.thread.join();
        std.testing.allocator.destroy(third_args);
    }
    try consumer.setCatalogConsumer(catalog_apex, third_server.socket.address, null);
    try sendNotify(io, &consumer);
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .updated), consumer.refreshCatalogIfRequested(io));
    try expectAddress(io, &consumer, "www.two.example.", 192, 0, 2, 2);
    try joinPrimary(third_args, &third_joined);

    // A member whose ZONEMD digest does not match is refused and the served
    // set stays as it was.
    try std.Io.sleep(io, .fromMilliseconds(catalog_window_ms + 100), .awake);
    var fourth_primary = try Runtime.fromZoneTexts(&.{ fourth_catalog_text, bad_digest_member_text });
    defer fourth_primary.deinit();
    var fourth_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var fourth_server = try std.Io.net.IpAddress.listen(&fourth_addr, io, .{ .reuse_address = true });
    const fourth_args = try startPrimary(io, &fourth_server, &fourth_primary, 2);
    var fourth_joined = false;
    defer {
        fourth_server.deinit(io);
        if (!fourth_joined) fourth_args.thread.join();
        std.testing.allocator.destroy(fourth_args);
    }
    try consumer.setCatalogConsumer(catalog_apex, fourth_server.socket.address, null);
    try sendNotify(io, &consumer);
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .failed), consumer.refreshCatalogIfRequested(io));
    try expectAddress(io, &consumer, "www.two.example.", 192, 0, 2, 2);
    try joinPrimary(fourth_args, &fourth_joined);
}

/// Sends a NOTIFY for the catalog through the runtime's UDP path and checks
/// the answer is NOERROR.
fn sendNotify(io: std.Io, runtime: *Runtime) !void {
    return sendNotifyFrom(io, runtime, "127.0.0.1");
}

fn sendNotifyFrom(io: std.Io, runtime: *Runtime, source_ip: []const u8) !void {
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr = try std.Io.net.IpAddress.parse(source_ip, 0);
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const base = try cli_query.buildQueryPacket(&query_buffer, 0x4b11, catalog_apex, .SOA, false);
    // RFC 1996: opcode NOTIFY (4) with QR clear.
    query_buffer[2] = 4 << 3;
    {
        var probe_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer probe_arena.deinit();
        var probe = try dns_message.Message.parse(probe_arena.allocator(), base);
        defer probe.deinit();
        try std.testing.expectEqual(@as(@TypeOf(probe.header.opcode), .notify), probe.header.opcode);
    }
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, base);
    try listener.serveUdpOnce(&server_socket, io, runtime);

    var response_buffer: [512]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, base);
    defer response.deinit();
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
}

fn expectRefused(io: std.Io, runtime: *Runtime, qname: []const u8) !void {
    var response = try ask(io, runtime, qname, 0x4b13);
    defer response.deinit();
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .refused), response.header.rcode);
}

fn ask(io: std.Io, runtime: *Runtime, qname: []const u8, id: u16) !dns_message.Message {
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, id, qname, .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, runtime);

    var response_buffer: [512]u8 = undefined;
    return cli_query.receiveUdpResponse(std.testing.allocator, &client_socket, io, &response_buffer, &server_socket.address, query);
}

fn expectAddress(io: std.Io, runtime: *Runtime, qname: []const u8, a: u8, b: u8, c: u8, d: u8) !void {
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4b12, qname, .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, runtime);

    var response_buffer: [512]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqualSlices(u8, &.{ a, b, c, d }, &response.answers.items[0].rdata.A);
}

fn expectSoaSerial(io: std.Io, runtime: *Runtime, qname: []const u8, expected: u32, id: u16) !void {
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, id, qname, .SOA, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, runtime);

    var response_buffer: [512]u8 = undefined;
    var response = try cli_query.receiveUdpResponse(std.testing.allocator, &client_socket, io, &response_buffer, &server_socket.address, query);
    defer response.deinit();
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.SOA));
    try std.testing.expectEqual(expected, response.answers.items[0].rdata.SOA.serial);
}

test "secondary refresh pulls a changed member after the SOA refresh interval" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var primary_a = try Runtime.fromZoneTexts(&.{ first_catalog_text, refresh_member_v1_text });
    defer primary_a.deinit();
    var primary_b = try Runtime.fromZoneTexts(&.{ first_catalog_text, refresh_member_v2_text });
    defer primary_b.deinit();

    var first_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var first_server = try std.Io.net.IpAddress.listen(&first_addr, io, .{ .reuse_address = true });
    const first_args = try startPrimary(io, &first_server, &primary_a, 2);
    var first_joined = false;
    var first_closed = false;
    defer {
        if (!first_closed) first_server.deinit(io);
        if (!first_joined) first_args.thread.join();
        std.testing.allocator.destroy(first_args);
    }

    var consumer = try Runtime.fromZoneTexts(&.{boot_text});
    defer consumer.deinit();
    try consumer.setCatalogConsumer(catalog_apex, first_server.socket.address, null);
    consumer.requestCatalogRefresh();
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .updated), consumer.refreshCatalogIfRequested(io));
    try expectSoaSerial(io, &consumer, "one.example.", 1, 0x4b21);
    const clock_now_ns: u64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    try joinPrimary(first_args, &first_joined);
    // The second primary takes over the same loopback port after the first
    // listener is gone, so the secondary's stored primary address reaches
    // it even though the unchanged catalog serial is not re-provisioned.
    const shared_addr = first_server.socket.address;
    first_server.deinit(io);
    first_closed = true;

    // The catalog refresh window has to pass before the next attempt runs.
    // The synthetic refresh clock stays anchored to provisioning so the
    // 2s advance lands inside the (1,3) refresh-to-expire window.
    try std.Io.sleep(io, .fromMilliseconds(catalog_window_ms + 100), .awake);
    var second_addr = shared_addr;
    var second_server = try std.Io.net.IpAddress.listen(&second_addr, io, .{ .reuse_address = true });
    const second_args = try startPrimary(io, &second_server, &primary_b, 2);
    var second_joined = false;
    defer {
        second_server.deinit(io);
        if (!second_joined) second_args.thread.join();
        std.testing.allocator.destroy(second_args);
    }

    try consumer.setCatalogConsumer(catalog_apex, second_server.socket.address, null);
    consumer.requestCatalogRefresh();
    try std.testing.expectEqual(@as(?zimdns.auth_runtime.CatalogRefreshOutcome, .unchanged), consumer.refreshCatalogIfRequested(io));
    try consumer.maybeRefreshSecondaries(clock_now_ns + 2_000_000_000, Runtime.fetchSecondaryViaXfr, &consumer);
    try expectSoaSerial(io, &consumer, "one.example.", 2, 0x4b22);
    try joinPrimary(second_args, &second_joined);
}
