const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const metrics = zimdns.metrics;
const Runtime = zimdns.auth_runtime.Runtime;
const Resolver = zimdns.resolver.Resolver;
const resolver = zimdns.resolver;
const dns_message = zimdns.dns_message;

const UpstreamMode = enum { valid, nxdomain, wrong_source, wrong_id, wrong_question, truncated_tcp, trickle_tcp };
const TestTimeout = std.Io.Timeout{ .duration = .{
    .raw = .fromSeconds(2),
    .clock = .awake,
} };

const ResponseBytes = struct {
    bytes: [512]u8 = undefined,
    len: usize = 0,
};

const CliTcpArgs = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    runtime: *Runtime,
    ok: bool = false,
};

const BoundedTcpArgs = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    runtime: *Runtime,
    max_requests: ?usize,
    ok: bool = false,
};

const UpstreamArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    tcp: ?*std.Io.net.Server = null,
    mode: UpstreamMode,
    ok: bool = false,
    requests: usize = 0,
};

test "UDP request pipeline answers A query and records metrics" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var counters = metrics.Counters{};
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4242, "dns.home.arpa.", .A);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnceWithMetrics(&server_socket, io, &runtime, &counters);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectAResponse(response);
    try std.testing.expectEqual(@as(u16, 0x4242), response.header.id);
    try expectMetrics(counters);
}

test "TCP request pipeline answers A query and records metrics" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4243, "dns.home.arpa.", .A);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    var counters = metrics.Counters{};
    try listener.serveTcpStreamOnceWithMetrics(server_stream, io, &runtime, &counters);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectAResponse(response);
    try expectMetrics(counters);
}

test "UDP request pipeline answers SSHFP query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4247, "host.home.arpa.", .SSHFP);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectSshfpResponse(response, 0x4247);
}

test "TCP request pipeline answers SSHFP query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4248, "host.home.arpa.", .SSHFP);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectSshfpResponse(response, 0x4248);
}

test "UDP request pipeline answers TLSA query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4249, "_443._tcp.home.arpa.", .TLSA);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectTlsaResponse(response, 0x4249);
}

test "TCP request pipeline answers TLSA query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4250, "_443._tcp.home.arpa.", .TLSA);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectTlsaResponse(response, 0x4250);
}

test "UDP request pipeline answers URI query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4251, "_https._tcp.home.arpa.", .URI);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectUriResponse(response, 0x4251);
}

test "TCP request pipeline answers URI query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4252, "_https._tcp.home.arpa.", .URI);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectUriResponse(response, 0x4252);
}

test "UDP request pipeline answers NAPTR query with nonroot replacement" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4253, "naptr.home.arpa.", .NAPTR);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectNaptrResponse(response, 0x4253, "", "replacement.example.");
}

test "TCP request pipeline answers NAPTR query with root replacement" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4254, "naptr-root.home.arpa.", .NAPTR);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectNaptrResponse(response, 0x4254, "!^.*$!sip:info@example.com!", ".");
}

test "UDP request pipeline answers ordered APL query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4255, "apl.home.arpa.", .APL);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectAplResponse(response, 0x4255);
}

test "TCP request pipeline answers ordered APL query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4256, "apl.home.arpa.", .APL);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectAplResponse(response, 0x4256);
}

test "UDP request pipeline answers CAA query with raw value bytes" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4259, "caa.home.arpa.", .CAA);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectCaaResponse(response, 0x4259);
}

test "TCP request pipeline answers CAA query with raw value bytes" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425a, "caa.home.arpa.", .CAA);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectCaaResponse(response, 0x425a);
}

test "UDP request pipeline answers AFSDB query without synthesized additional A" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4257, "afsdb.home.arpa.", .AFSDB);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectAfsdbResponse(response, 0x4257);
}

test "TCP request pipeline answers AFSDB query without synthesized additional A" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4258, "afsdb.home.arpa.", .AFSDB);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try expectAfsdbResponse(response, 0x4258);
}

test "TCP request pipeline preserves FIFO responses for pipelined queries" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var first_query_buffer: [512]u8 = undefined;
    var second_query_buffer: [512]u8 = undefined;
    const first_query = try cli_query.buildQueryPacket(&first_query_buffer, 0x4245, "dns.home.arpa.", .A);
    const second_query = try cli_query.buildQueryPacket(&second_query_buffer, 0x4246, "dns.home.arpa.", .A);
    try cli_query.sendTcpQuery(client_stream, io, first_query);
    try cli_query.sendTcpQuery(client_stream, io, second_query);
    try client_stream.shutdown(io, .send);

    var args = CliTcpArgs{ .io = io, .server = &server, .runtime = &runtime };
    const thread = try std.Thread.spawn(.{}, serveCliTcp, .{&args});

    var response_read_buffer: [1024]u8 = undefined;
    var response_reader = client_stream.reader(io, &response_read_buffer);
    const first_response_len_bytes = try response_reader.interface.takeArray(2);
    const first_response_len = std.mem.readInt(u16, first_response_len_bytes, .big);
    const first_response_bytes = try response_reader.interface.take(first_response_len);
    const first_response = try dns_message.Message.parse(arena.allocator(), first_response_bytes);
    const second_response_len_bytes = try response_reader.interface.takeArray(2);
    const second_response_len = std.mem.readInt(u16, second_response_len_bytes, .big);
    const second_response_bytes = try response_reader.interface.take(second_response_len);
    const second_response = try dns_message.Message.parse(arena.allocator(), second_response_bytes);
    thread.join();

    try std.testing.expect(args.ok);
    try expectAResponse(first_response);
    try expectAResponse(second_response);
    try std.testing.expectEqual(@as(u16, 0x4245), first_response.header.id);
    try std.testing.expectEqual(@as(u16, 0x4246), second_response.header.id);
}

test "CLI TCP exchange uses the bounded connection path" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4244, "dns.home.arpa.", .A);
    var args = CliTcpArgs{ .io = io, .server = &server, .runtime = &runtime };
    const thread = try std.Thread.spawn(.{}, serveCliTcp, .{&args});
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.exchangeTcpQuery(arena.allocator(), io, &server.socket.address, query, &response_buffer);
    thread.join();

    try std.testing.expect(args.ok);
    try expectAResponse(response);
}

test "configured two-zone UDP loop dispatches by longest origin" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var runtime = try loadConfiguredRuntime(io, &tmp);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var parent_query_buffer: [512]u8 = undefined;
    var child_query_buffer: [512]u8 = undefined;
    const parent_query = try cli_query.buildQueryPacket(&parent_query_buffer, 0x5101, "www.example.", .A);
    const child_query = try cli_query.buildQueryPacket(&child_query_buffer, 0x5102, "www.sub.example.", .A);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, parent_query);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, child_query);
    try listener.serveUdpLoop(&server_socket, io, &runtime, 2);

    var response_buffer: [512]u8 = undefined;
    const parent_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, parent_query);
    try expectAddress(parent_response, .{ 192, 0, 2, 1 });
    const child_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, child_query);
    try expectAddress(child_response, .{ 192, 0, 2, 2 });
}

test "configured two-zone TCP loop accepts bounded independent connections" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(listener.TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var runtime = try loadConfiguredRuntime(io, &tmp);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    var parent_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer parent_client.close(io);
    var child_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer child_client.close(io);

    var parent_query_buffer: [512]u8 = undefined;
    var child_query_buffer: [512]u8 = undefined;
    const parent_query = try cli_query.buildQueryPacket(&parent_query_buffer, 0x5201, "www.example.", .A);
    const child_query = try cli_query.buildQueryPacket(&child_query_buffer, 0x5202, "www.sub.example.", .A);
    try cli_query.sendTcpQuery(parent_client, io, parent_query);
    try cli_query.sendTcpQuery(child_client, io, child_query);
    try parent_client.shutdown(io, .send);
    try child_client.shutdown(io, .send);

    try listener.serveTcpLoop(&server, io, &runtime, 2);

    var parent_response_buffer: [512]u8 = undefined;
    var child_response_buffer: [512]u8 = undefined;
    const parent_response = try cli_query.receiveTcpResponse(arena.allocator(), parent_client, io, &parent_response_buffer, parent_query);
    try expectAddress(parent_response, .{ 192, 0, 2, 1 });
    const child_response = try cli_query.receiveTcpResponse(arena.allocator(), child_client, io, &child_response_buffer, child_query);
    try expectAddress(child_response, .{ 192, 0, 2, 2 });
}

test "authoritative TCP loop caps active connections at eight" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(listener.TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var clients: [listener.TCP_MAX_CONNECTION_WORKERS]?std.Io.net.Stream = [_]?std.Io.net.Stream{null} ** listener.TCP_MAX_CONNECTION_WORKERS;
    var client_queries: [listener.TCP_MAX_CONNECTION_WORKERS][512]u8 = undefined;
    var client_query_slices: [listener.TCP_MAX_CONNECTION_WORKERS][]const u8 = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
        client_query_slices[index] = try cli_query.buildQueryPacket(&client_queries[index], @intCast(0x5300 + index), "dns.home.arpa.", .A);
        try cli_query.sendTcpQuery(client.*.?, io, client_query_slices[index]);
    }

    var excess_client: ?std.Io.net.Stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    var excess_query_buffer: [512]u8 = undefined;
    const excess_query = try cli_query.buildQueryPacket(&excess_query_buffer, 0x53ff, "dns.home.arpa.", .A);
    try cli_query.sendTcpQuery(excess_client.?, io, excess_query);
    try excess_client.?.shutdown(io, .send);

    var args = BoundedTcpArgs{ .io = io, .server = &server, .runtime = &runtime, .max_requests = 9 };
    const server_thread = try std.Thread.spawn(.{}, serveBoundedTcp, .{&args});
    var joined = false;
    defer {
        for (&clients) |*client| {
            if (client.*) |stream| {
                stream.close(io);
                client.* = null;
            }
        }
        if (excess_client) |client| {
            client.close(io);
            excess_client = null;
        }
        if (!joined) server_thread.join();
    }

    var response_buffers: [listener.TCP_MAX_CONNECTION_WORKERS][512]u8 = undefined;
    for (&clients, 0..) |*client, index| {
        const response = try cli_query.receiveTcpResponse(arena.allocator(), client.*.?, io, &response_buffers[index], client_query_slices[index]);
        try expectAResponse(response);
        try std.testing.expectEqual(@as(u16, @intCast(0x5300 + index)), response.header.id);
    }

    var excess_poll_fd = [_]std.posix.pollfd{.{
        .fd = excess_client.?.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&excess_poll_fd, 5_000));
    var excess_bytes: [512]u8 = undefined;
    const excess_read = std.posix.read(excess_client.?.socket.handle, &excess_bytes) catch |err| switch (err) {
        error.ConnectionResetByPeer => 0,
        else => return err,
    };
    try std.testing.expectEqual(@as(usize, 0), excess_read);

    for (&clients) |*client| {
        if (client.*) |stream| {
            stream.close(io);
            client.* = null;
        }
    }
    excess_client.?.close(io);
    excess_client = null;
    server_thread.join();
    joined = true;
    try std.testing.expect(args.ok);
}

test "resolver accepts only an exact UDP upstream response" {
    try expectForwarderExchange(.valid);
    try expectForwarderExchange(.wrong_source);
    try expectForwarderExchange(.wrong_id);
    try expectForwarderExchange(.wrong_question);
}

test "resolver falls back from UDP truncation to one TCP exchange" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var udp = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer udp.close(io);
    var tcp_addr = udp.address;
    var tcp = try std.Io.net.IpAddress.listen(&tcp_addr, io, .{ .reuse_address = true });
    defer tcp.deinit(io);

    var args = UpstreamArgs{ .io = io, .udp = &udp, .tcp = &tcp, .mode = .truncated_tcp };
    const thread = try std.Thread.spawn(.{}, serveUpstream, .{&args});

    const policy = resolver.Policy{ .forwarder = .{ .address = udp.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();
    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7001, "example.com.", .A);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41001);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try upstream.answer(query_bytes, query, &client, &output);
    thread.join();
    try std.testing.expect(args.ok);
    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try expectForwardedAResponse(response, 0x7001);
}

test "trickle TCP upstream cannot extend one absolute frame deadline" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var udp = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer udp.close(io);
    var tcp_addr = udp.address;
    var tcp = try std.Io.net.IpAddress.listen(&tcp_addr, io, .{ .reuse_address = true });
    defer tcp.deinit(io);

    var args = UpstreamArgs{ .io = io, .udp = &udp, .tcp = &tcp, .mode = .trickle_tcp };
    const thread = try std.Thread.spawn(.{}, serveUpstream, .{&args});

    var zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var policy = resolver.Policy{ .forwarder = .{ .address = udp.address } };
    policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("127.0.0.0/8");
    policy.recursion_allow_len = 1;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try buildEdnsQuery(&query_buffer, 0x7007);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41007);
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const response_bytes = try runtime.answerFrom(query_bytes, &output, &client);
    const elapsed = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    thread.join();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .servfail), response.header.rcode);
    try expectEde(response, resolver.EDE_NETWORK_ERROR);
    try std.testing.expect(elapsed < 3 * std.time.ns_per_s);
}

test "recursive ACL rejects before contacting an upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var policy = resolver.Policy{};
    policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("192.0.2.0/24");
    policy.recursion_allow_len = 1;
    policy.forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) };
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7002, "outside.example.", .A);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const denied_client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(query_bytes, &output, &denied_client);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .refused), response.header.rcode);

    var tcp_output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const tcp_response_bytes = try runtime.answer(query_bytes, &tcp_output);
    const tcp_response = try dns_message.Message.parse(arena.allocator(), tcp_response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(tcp_response.header.rcode), .refused), tcp_response.header.rcode);
}

test "authorized UDP listener request reaches a local upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid };
    const upstream_thread = try std.Thread.spawn(.{}, serveUpstream, .{&upstream_args});

    var zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("127.0.0.0/8");
    policy.recursion_allow_len = 1;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7003, "example.com.", .A);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    upstream_thread.join();
    try std.testing.expect(upstream_args.ok);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try expectForwardedAResponse(response, 0x7003);
}

test "resolver caches a live upstream NXDOMAIN response" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .nxdomain };
    const upstream_thread = try std.Thread.spawn(.{}, serveUpstream, .{&upstream_args});
    const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7004, "missing.example.", .A);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const fixture = makeNxDomainResponse(query_bytes);
    try std.testing.expectEqual(@as(usize, 48), fixture.len - query_bytes.len);
    const fixture_message = try dns_message.Message.parse(query_arena.allocator(), fixture.bytes[0..fixture.len]);
    try std.testing.expectEqual(@as(@TypeOf(fixture_message.header.rcode), .nxdomain), fixture_message.header.rcode);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41004);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const first_bytes = try upstream.answer(query_bytes, query, &client, &output);
    const first = try dns_message.Message.parse(query_arena.allocator(), first_bytes);
    try std.testing.expectEqual(@as(@TypeOf(first.header.rcode), .nxdomain), first.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), first.header.authority_count);
    upstream_thread.join();
    try std.testing.expectEqual(@as(usize, 1), upstream_args.requests);

    var second_query_buffer: [512]u8 = undefined;
    const second_query_bytes = try cli_query.buildQueryPacket(&second_query_buffer, 0x7005, "missing.example.", .A);
    const second_query = try dns_message.Message.parseQuery(query_arena.allocator(), second_query_bytes);
    const second_bytes = try upstream.answer(second_query_bytes, second_query, &client, &output);
    const second = try dns_message.Message.parse(query_arena.allocator(), second_bytes);
    try std.testing.expectEqual(@as(@TypeOf(second.header.rcode), .nxdomain), second.header.rcode);
    try std.testing.expect(second.authorities.items[0].ttl > 0 and second.authorities.items[0].ttl <= 60);
}

test "non-query opcode returns NOTIMP before cache or upstream reuse" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid };
    const upstream_thread = try std.Thread.spawn(.{}, serveUpstream, .{&upstream_args});

    var zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("127.0.0.0/8");
    policy.recursion_allow_len = 1;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7006, "example.com.", .A);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41006);
    const first_response_bytes = try runtime.answerFrom(query, &output, &client);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const first_response = try dns_message.Message.parse(arena.allocator(), first_response_bytes);
    try expectForwardedAResponse(first_response, 0x7006);
    upstream_thread.join();
    try std.testing.expectEqual(@as(usize, 1), upstream_args.requests);

    var non_query_buffer: [512]u8 = undefined;
    @memcpy(non_query_buffer[0..query.len], query);
    non_query_buffer[2] |= 0x10;
    const non_query_response_bytes = try runtime.answerFrom(non_query_buffer[0..query.len], &output, &client);
    const non_query_response = try dns_message.Message.parse(arena.allocator(), non_query_response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(non_query_response.header.opcode), .status), non_query_response.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(non_query_response.header.rcode), .notimp), non_query_response.header.rcode);
    try std.testing.expectEqual(@as(usize, 1), upstream_args.requests);
}

fn expectForwarderExchange(mode: UpstreamMode) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var udp = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer udp.close(io);
    var args = UpstreamArgs{ .io = io, .udp = &udp, .mode = mode };
    const thread = try std.Thread.spawn(.{}, serveUpstream, .{&args});

    const policy = resolver.Policy{ .forwarder = .{ .address = udp.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();
    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7000, "example.com.", .A);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41000);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try upstream.answer(query_bytes, query, &client, &output);
    thread.join();
    try std.testing.expect(args.ok);
    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try expectForwardedAResponse(response, 0x7000);
}

fn expectForwardedAResponse(response: dns_message.Message, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
}

fn expectEde(response: dns_message.Message, expected_code: u16) !void {
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const data = record.rdata.OPT.bytes();
        var offset: usize = 0;
        while (offset + 4 <= data.len) {
            const option_code = std.mem.readInt(u16, data[offset..][0..2], .big);
            const option_len = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
            offset += 4;
            if (offset + option_len > data.len) break;
            if (option_code == resolver.EDE_OPTION_CODE and option_len == 2) {
                try std.testing.expectEqual(expected_code, std.mem.readInt(u16, data[offset..][0..2], .big));
                return;
            }
            offset += option_len;
        }
    }
    return error.ExpectedEde;
}

fn serveCliTcp(args: *CliTcpArgs) void {
    const stream = args.server.accept(args.io) catch return;
    defer stream.close(args.io);
    listener.serveTcpStreamOnce(stream, args.io, args.runtime) catch return;
    args.ok = true;
}

fn serveBoundedTcp(args: *BoundedTcpArgs) void {
    listener.serveTcpLoop(args.server, args.io, args.runtime, args.max_requests) catch return;
    args.ok = true;
}

fn serveUpstream(args: *UpstreamArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    args.requests += 1;
    var valid = makeAResponse(incoming.data, false, false, false);
    switch (args.mode) {
        .valid => args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return,
        .nxdomain => {
            const response = makeNxDomainResponse(incoming.data);
            args.udp.send(args.io, &incoming.from, response.bytes[0..response.len]) catch return;
        },
        .wrong_source => {
            var wrong_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            var wrong_socket = std.Io.net.IpAddress.bind(&wrong_addr, args.io, .{ .mode = .dgram, .protocol = .udp }) catch return;
            defer wrong_socket.close(args.io);
            wrong_socket.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
        },
        .wrong_id => {
            valid.bytes[0] ^= 1;
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
            valid = makeAResponse(incoming.data, false, false, false);
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
        },
        .wrong_question => {
            valid.bytes[13] ^= 1;
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
            valid = makeAResponse(incoming.data, false, false, false);
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
        },
        .truncated_tcp => {
            valid = makeAResponse(incoming.data, true, false, false);
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
            const server = args.tcp orelse return;
            var stream = server.accept(args.io) catch return;
            defer stream.close(args.io);
            var read_buffer: [1024]u8 = undefined;
            var reader = stream.reader(args.io, &read_buffer);
            const length_bytes = reader.interface.takeArray(2) catch return;
            const length = std.mem.readInt(u16, length_bytes, .big);
            if (length == 0 or length > resolver.MAX_UPSTREAM_MESSAGE) return;
            var tcp_query: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
            reader.interface.readSliceAll(tcp_query[0..length]) catch return;
            var response = makeAResponse(tcp_query[0..length], false, false, false);
            var write_buffer: [1024]u8 = undefined;
            var writer = stream.writer(args.io, &write_buffer);
            var response_length: [2]u8 = undefined;
            std.mem.writeInt(u16, &response_length, @intCast(response.len), .big);
            writer.interface.writeAll(&response_length) catch return;
            writer.interface.writeAll(response.bytes[0..response.len]) catch return;
            writer.interface.flush() catch return;
        },
        .trickle_tcp => {
            valid = makeAResponse(incoming.data, true, false, false);
            args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
            const server = args.tcp orelse return;
            var stream = server.accept(args.io) catch return;
            defer stream.close(args.io);
            var read_buffer: [1024]u8 = undefined;
            var reader = stream.reader(args.io, &read_buffer);
            const length_bytes = reader.interface.takeArray(2) catch return;
            const length = std.mem.readInt(u16, length_bytes, .big);
            if (length == 0 or length > resolver.MAX_UPSTREAM_MESSAGE) return;
            var tcp_query: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
            reader.interface.readSliceAll(tcp_query[0..length]) catch return;
            const response = makeAResponse(tcp_query[0..length], false, false, false);
            var write_buffer: [1024]u8 = undefined;
            var writer = stream.writer(args.io, &write_buffer);
            var response_length: [2]u8 = undefined;
            std.mem.writeInt(u16, &response_length, @intCast(response.len), .big);
            var frame: [2 + 512]u8 = undefined;
            @memcpy(frame[0..2], &response_length);
            @memcpy(frame[2 .. 2 + response.len], response.bytes[0..response.len]);
            for (frame[0 .. 2 + response.len]) |byte| {
                writer.interface.writeByte(byte) catch return;
                writer.interface.flush() catch return;
                std.Io.sleep(args.io, .fromMilliseconds(250), .awake) catch return;
            }
        },
    }
    args.ok = true;
}

fn buildEdnsQuery(buffer: []u8, id: u16) ![]const u8 {
    const base = try cli_query.buildQueryPacket(buffer, id, "example.com.", .A);
    if (base.len + 11 > buffer.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, buffer[10..12], 1, .big);
    var offset = base.len;
    buffer[offset] = 0;
    offset += 1;
    std.mem.writeInt(u16, buffer[offset..][0..2], 41, .big);
    offset += 2;
    std.mem.writeInt(u16, buffer[offset..][0..2], 1232, .big);
    offset += 2;
    std.mem.writeInt(u32, buffer[offset..][0..4], 0, .big);
    offset += 4;
    std.mem.writeInt(u16, buffer[offset..][0..2], 0, .big);
    return buffer[0 .. offset + 2];
}

fn makeAResponse(query: []const u8, truncated: bool, wrong_id: bool, wrong_question: bool) ResponseBytes {
    var response = ResponseBytes{};
    @memcpy(response.bytes[0..query.len], query);
    response.len = query.len;
    response.bytes[2] = if (truncated) 0x83 else 0x81;
    response.bytes[3] = 0x80;
    std.mem.writeInt(u16, response.bytes[6..8], if (truncated) 0 else 1, .big);
    if (wrong_id) response.bytes[0] ^= 1;
    if (wrong_question) response.bytes[13] ^= 1;
    if (!truncated) {
        const answer = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1 };
        @memcpy(response.bytes[response.len .. response.len + answer.len], &answer);
        response.len += answer.len;
    }
    return response;
}

fn makeNxDomainResponse(query: []const u8) ResponseBytes {
    var response = ResponseBytes{};
    @memcpy(response.bytes[0..query.len], query);
    response.len = query.len;
    response.bytes[2] = 0x81;
    response.bytes[3] = 0x83;
    std.mem.writeInt(u16, response.bytes[6..8], 0, .big);
    std.mem.writeInt(u16, response.bytes[8..10], 1, .big);
    const soa = [_]u8{
        0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x24,
        0x02, 'n',  's',  0x00, 0x0a, 'h',  'o',  's',  't',  'm',  'a',  's',
        't',  'e',  'r',  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x03, 0x84, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x00, 0x1e,
    };
    @memcpy(response.bytes[response.len .. response.len + soa.len], &soa);
    response.len += soa.len;
    return response;
}

fn expectAResponse(response: anytype) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &response.answers.items[0].rdata.A);
}

fn expectSshfpResponse(response: anytype, expected_id: u16) !void {
    const fingerprint = [_]u8{
        0xa8, 0x7f, 0x1b, 0x68, 0x7a, 0xc0, 0xe5, 0x7d,
        0x2a, 0x08, 0x1a, 0x2f, 0x28, 0x26, 0x72, 0x33,
        0x4d, 0x90, 0xed, 0x31, 0x6d, 0x2b, 0x81, 0x8c,
        0xa9, 0x58, 0x0e, 0xa3, 0x84, 0xd9, 0x24, 0x01,
    };
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.SSHFP));
    try std.testing.expectEqual(@as(u8, 4), answer.rdata.SSHFP.algorithm);
    try std.testing.expectEqual(@as(u8, 2), answer.rdata.SSHFP.fingerprint_type);
    try std.testing.expectEqualSlices(u8, &fingerprint, answer.rdata.SSHFP.fingerprintBytes());
}

fn expectTlsaResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.TLSA));
    try std.testing.expectEqual(@as(u8, 0), answer.rdata.TLSA.usage);
    try std.testing.expectEqual(@as(u8, 0), answer.rdata.TLSA.selector);
    try std.testing.expectEqual(@as(u8, 1), answer.rdata.TLSA.matching_type);
    try std.testing.expectEqual(@as(usize, tlsa_association.len), @as(usize, answer.rdata.TLSA.association_len));
    try std.testing.expectEqualSlices(u8, &tlsa_association, answer.rdata.TLSA.association[0..answer.rdata.TLSA.association_len]);
}

fn expectUriResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.URI));
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.URI.priority);
    try std.testing.expectEqual(@as(u16, 20), answer.rdata.URI.weight);
    try std.testing.expectEqualStrings("https://example.test/path", answer.rdata.URI.targetBytes());
}

fn expectNaptrResponse(response: anytype, expected_id: u16, expected_regexp: []const u8, expected_replacement: []const u8) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.NAPTR));
    try std.testing.expectEqual(@as(u16, 100), answer.rdata.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.NAPTR.preference);
    try std.testing.expectEqualStrings("U", answer.rdata.NAPTR.flagsText());
    try std.testing.expectEqualStrings("E2U+sip", answer.rdata.NAPTR.servicesText());
    try std.testing.expectEqualStrings(expected_regexp, answer.rdata.NAPTR.regexpText());
    var replacement: [256]u8 = undefined;
    try std.testing.expectEqualStrings(expected_replacement, try answer.rdata.NAPTR.replacement.toText(&replacement));
}

fn expectAplResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.APL));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x18, 0x83, 0xc0, 0x00, 0x02,
        0x00, 0x02, 0x30, 0x06, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x01, 0x18, 0x03,
        0xc0, 0x00, 0x02,
    }, answer.rdata.APL.bytes());
}

fn expectCaaResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.CAA));
    try std.testing.expectEqual(@as(u8, 128), answer.rdata.CAA.flags);
    try std.testing.expectEqualStrings("issue", answer.rdata.CAA.tagText());
    try std.testing.expectEqualSlices(u8, &.{ 'a', 0, 128, 255 }, answer.rdata.CAA.valueText());
}

fn expectAfsdbResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.AFSDB));
    try std.testing.expectEqual(@as(u16, 42), answer.rdata.AFSDB.preference);
    var hostname: [256]u8 = undefined;
    try std.testing.expectEqualStrings("server.home.arpa.", try answer.rdata.AFSDB.exchange.toText(&hostname));
}

fn expectMetrics(counters: metrics.Counters) !void {
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total);
    try std.testing.expectEqual(@as(u64, 0), counters.encode_failures_total);
}

fn expectAddress(response: anytype, expected: [4]u8) !void {
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &expected, &response.answers.items[0].rdata.A);
}

fn loadConfiguredRuntime(io: std.Io, tmp: *std.testing.TmpDir) !Runtime {
    try tmp.dir.writeFile(io, .{ .sub_path = "parent.zone", .data = parent_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "child.zone", .data = child_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone example primary parent.zone
        \\zone sub.example primary child.zone
        \\
    });
    var context = try zimdns.config_loader.ServerContext.load(tmp.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    return context.takeRuntime(io);
}

const fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2026053001 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\ns1 IN A 192.168.1.1
    \\dns IN A 192.168.1.1
    \\host IN SSHFP 4 2 a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401
    \\_443._tcp IN TLSA 0 0 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    \\_https._tcp IN URI 10 20 "https://example.test/path"
    \\naptr IN NAPTR 100 10 "U" "E2U+sip" "" replacement.example.
    \\naptr-root IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .
    \\apl IN APL !1:192.0.2.7/24 2:2001:db8:1::/48 1:192.0.2.7/24
    \\caa IN CAA 128 issue "a\000\128\255"
    \\afsdb IN AFSDB 42 server.home.arpa.
    \\server IN A 192.0.2.53
    \\
;

const tlsa_association = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

const parent_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\ns IN A 192.0.2.10
    \\www IN A 192.0.2.1
    \\
;

const child_zone =
    \\$ORIGIN sub.example.
    \\$TTL 3600
    \\@ IN SOA ns.sub.example. hostmaster.sub.example. 1 3600 900 1209600 300
    \\@ IN NS ns.sub.example.
    \\ns IN A 192.0.2.20
    \\www IN A 192.0.2.2
    \\
;
