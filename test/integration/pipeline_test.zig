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
    const io = std.Io.Threaded.global_single_threaded.io();
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
    \\
;

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
