/// Contract: a standalone secondary zone is fetched once at startup over
/// AXFR, served like a primary zone, and after the SOA refresh interval
/// the serve-loop refresh tick pulls the primary's newer serial.
/// Ownership: the test owns both runtimes, both listeners, and every socket;
/// all are released before it returns.
/// Errors: a failed expectation fails the test.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const Runtime = zimdns.auth_runtime.Runtime;
const ServerContext = zimdns.config_loader.ServerContext;
const dns_message = zimdns.dns_message;

const zone_v1_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 1 1 1 3 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

const zone_v2_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 2 1 1 3 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

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
    var response = try cli_query.receiveUdpResponse(std.testing.allocator, &client_socket, io, &response_buffer, &server_socket.address, query, false);
    defer response.deinit();
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.SOA));
    try std.testing.expectEqual(expected, response.answers.items[0].rdata.SOA.serial);
}

test "a standalone secondary serves the fetched zone and refreshes to the newer serial" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    var primary_a = try Runtime.fromZoneTexts(&.{zone_v1_text});
    defer primary_a.deinit();
    // The transfer ACL denies by default; this loopback grant permits the secondary's AXFR.
    try primary_a.addTransferAllow("one.example.", try zimdns.config_parser.Cidr.parse("127.0.0.1/32"));
    var primary_b = try Runtime.fromZoneTexts(&.{zone_v2_text});
    defer primary_b.deinit();
    try primary_b.addTransferAllow("one.example.", try zimdns.config_parser.Cidr.parse("127.0.0.1/32"));

    var first_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var first_server = try std.Io.net.IpAddress.listen(&first_addr, io, .{ .reuse_address = true });
    const first_port = switch (first_server.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    const first_args = try startPrimary(io, &first_server, &primary_a, 1);
    var first_joined = false;
    var first_closed = false;
    defer {
        if (!first_closed) first_server.deinit(io);
        if (!first_joined) first_args.thread.join();
        std.testing.allocator.destroy(first_args);
    }

    var config_buffer: [256]u8 = undefined;
    const config_text = try std.fmt.bufPrint(&config_buffer, "zone one.example. secondary 127.0.0.1:{d}\n", .{first_port});
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = config_text });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
    try std.testing.expectEqual(@as(usize, 1), context.secondary_zones.items.len);
    try std.testing.expectEqualStrings("one.example.", context.secondary_zones.items[0].apex);
    try std.testing.expectEqual(@as(u32, 1), context.secondary_zones.items[0].refresh_sec);

    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();
    try std.testing.expectEqual(@as(usize, 1), runtime.secondary_zones.items.len);
    try expectSoaSerial(io, &runtime, "one.example.", 1, 0x5a01);
    const clock_now_ns: u64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    try joinPrimary(first_args, &first_joined);

    const shared_addr = first_server.socket.address;
    first_server.deinit(io);
    first_closed = true;

    var second_addr = shared_addr;
    var second_server = try std.Io.net.IpAddress.listen(&second_addr, io, .{ .reuse_address = true });
    const second_args = try startPrimary(io, &second_server, &primary_b, 1);
    var second_joined = false;
    defer {
        second_server.deinit(io);
        if (!second_joined) second_args.thread.join();
        std.testing.allocator.destroy(second_args);
    }

    try runtime.maybeRefreshSecondaries(clock_now_ns + 2_000_000_000, Runtime.fetchSecondaryViaXfr, &runtime);
    try expectSoaSerial(io, &runtime, "one.example.", 2, 0x5a02);
    try joinPrimary(second_args, &second_joined);
}

test "a standalone secondary refuses to start when the primary does not answer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var transfer_server = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    const port = switch (transfer_server.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    transfer_server.deinit(io);

    var config_buffer: [256]u8 = undefined;
    const config_text = try std.fmt.bufPrint(&config_buffer, "zone one.example. secondary 127.0.0.1:{d}\n", .{port});
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = config_text });
    try std.testing.expectError(zimdns.config_loader.Error.BadSecondary, ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator));
}
