const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const metrics = zimdns.metrics;
const Runtime = zimdns.auth_runtime.Runtime;
const Resolver = zimdns.resolver.Resolver;
const resolver = zimdns.resolver;
const dns_message = zimdns.dns_message;
const dns_tsig = zimdns.dns_tsig;
const dns_writer = zimdns.dns_writer;
const dns_rdata = zimdns.dns_rdata;
const dns_record = zimdns.dns_record;
const dns_name = zimdns.dns_name;
const auth_keyring = zimdns.auth_keyring;

const UpstreamMode = enum { valid, valid_rrsig, valid_nsec, nxdomain, wrong_source, wrong_id, wrong_question, truncated_tcp, trickle_tcp };
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4242, "dns.home.arpa.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnceWithMetrics(&server_socket, io, &runtime, &counters);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectAResponse(response);
    try std.testing.expectEqual(@as(u16, 0x4242), response.header.id);
    try expectMetrics(counters);
}

test "UDP pipeline echoes the question in the case the client sent" {
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
    // "Dns.Home.Arpa." as the client spelled it. RFC 4343 section 4.1 requires
    // the answer to carry the same question, so the response keeps the case.
    const query = [_]u8{
        0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'D',  'n',  's',  4,    'H',  'o',  'm',  'e',  4,    'A',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    };
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, &query);
    try listener.serveUdpOnceWithMetrics(&server_socket, io, &runtime, &counters);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, &query, false);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Dns.Home.Arpa.", try response.question.?.name.toText(&text));
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "UDP signed query pipeline authenticates and returns signed success and unsigned BADKEY" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var keyring = try auth_keyring.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(fixture_zone, &keyring);
    defer runtime.deinit();
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query = try buildIntegrationSignedQuery(now);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query.bytes[0..query.len]);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var response_buffer: [1024]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, TestTimeout);
    const response = try dns_message.Message.parse(arena.allocator(), incoming.data);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    const request_final = (try dns_tsig.parseFinalAdditional(query.bytes[0..query.len])).?;
    const response_final = (try dns_tsig.parseFinalAdditional(incoming.data)).?;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    _ = try dns_tsig.verify(incoming.data, "01234567890123456789012345678901", request_final.tsig.macBytes());

    query.bytes[query.owner_start + 1] = 'b';
    query.bytes[query.owner_start + 2] = 'a';
    query.bytes[query.owner_start + 3] = 'd';
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query.bytes[0..query.len]);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    const bad_incoming = try client_socket.receiveTimeout(io, &response_buffer, TestTimeout);
    const bad_response = try dns_message.Message.parse(arena.allocator(), bad_incoming.data);
    try std.testing.expectEqual(@as(@TypeOf(bad_response.header.rcode), .notauth), bad_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), bad_response.header.additional_count);
    try std.testing.expectEqual(@as(u16, 17), bad_response.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(usize, 0), bad_response.additionals.items[0].rdata.TSIG.macBytes().len);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4243, "dns.home.arpa.", .A, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    var counters = metrics.Counters{};
    try listener.serveTcpStreamOnceWithMetrics(server_stream, io, &runtime, &counters);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectAResponse(response);
    try expectMetrics(counters);
}

// RFC 7766 section 8 and RFC 6891 section 4.3: an answer that does not fit
// the negotiated datagram payload is truncated with TC=1 so the client
// retries over TCP, where the same answer arrives whole.
test "oversized answer is truncated over UDP and served whole over TCP" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // A round-robin A RRset whose wire form is well past the 1232-octet
    // EDNS payload cap, so one zone exercises both transports.
    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.writeAll(
        "$ORIGIN example.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300\n" ++
            "@ IN NS ns.example.\n",
    );
    var address_index: usize = 1;
    while (address_index <= 100) : (address_index += 1) {
        try zone_text.writer.print("many IN A 192.0.2.{d}\n", .{address_index});
    }
    var runtime = try Runtime.fromZoneText(zone_text.written());
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4a58, "many.example.", .A, true);

    // The datagram answer does not fit 1232 octets, so the server truncates
    // it and sets TC for the client to retry over TCP.
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var datagram_buffer: [4096]u8 = undefined;
    const datagram = try client_socket.receiveTimeout(io, &datagram_buffer, TestTimeout);
    const datagram_response = try dns_message.Message.parse(arena.allocator(), datagram.data);
    try std.testing.expect(datagram.data.len <= 1232);
    try std.testing.expect(datagram_response.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), datagram_response.header.answer_count);
    try std.testing.expect(datagram_response.edns != null);

    // The same query over TCP gets the whole answer, untruncated.
    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);
    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_read_buffer: [4096]u8 = undefined;
    var response_reader = client_stream.reader(io, &response_read_buffer);
    const response_len_bytes = try response_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, response_len_bytes, .big);
    const response_bytes = try response_reader.interface.take(response_len);
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);

    try std.testing.expect(response_len > 1232);
    try std.testing.expect(!response.header.truncated);
    try std.testing.expectEqual(@as(u16, 100), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 100 }, &response.answers.items[99].rdata.A);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4247, "host.home.arpa.", .SSHFP, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4248, "host.home.arpa.", .SSHFP, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4249, "_443._tcp.home.arpa.", .TLSA, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4250, "_443._tcp.home.arpa.", .TLSA, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4251, "_https._tcp.home.arpa.", .URI, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4252, "_https._tcp.home.arpa.", .URI, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4253, "naptr.home.arpa.", .NAPTR, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4254, "naptr-root.home.arpa.", .NAPTR, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectNaptrResponse(response, 0x4254, "!^.*$!sip:info@example.com!", ".");
}

test "UDP request pipeline answers RP query without synthesized TXT additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425b, "rp.home.arpa.", .RP, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectRpResponse(response, 0x425b);
}

test "TCP request pipeline answers RP query without synthesized TXT additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425c, "rp.home.arpa.", .RP, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectRpResponse(response, 0x425c);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4255, "apl.home.arpa.", .APL, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4256, "apl.home.arpa.", .APL, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4259, "caa.home.arpa.", .CAA, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425a, "caa.home.arpa.", .CAA, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4257, "afsdb.home.arpa.", .AFSDB, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4258, "afsdb.home.arpa.", .AFSDB, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectAfsdbResponse(response, 0x4258);
}

test "UDP request pipeline answers X25 query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425d, "x25.home.arpa.", .X25, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectX25Response(response, 0x425d);
}

test "TCP request pipeline answers X25 query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425e, "x25.home.arpa.", .X25, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectX25Response(response, 0x425e);
}

test "UDP request pipeline answers ISDN query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x425f, "isdn.home.arpa.", .ISDN, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectIsdnResponse(response, 0x425f);
}

test "TCP request pipeline answers ISDN query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4260, "isdn.home.arpa.", .ISDN, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectIsdnResponse(response, 0x4260);
}

test "UDP request pipeline answers HINFO query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4265, "hinfo.home.arpa.", .HINFO, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectHinfoResponse(response, 0x4265);
}

test "TCP request pipeline answers HINFO query without synthesized additional" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4266, "hinfo.home.arpa.", .HINFO, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectHinfoResponse(response, 0x4266);
}

test "UDP request pipeline answers RT query without synthesized additionals" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4261, "rt.home.arpa.", .RT, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectRtResponse(response, 0x4261);
}

test "TCP request pipeline answers RT query without synthesized additionals" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4262, "rt.home.arpa.", .RT, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectRtResponse(response, 0x4262);
}

test "UDP request pipeline answers SRV query without synthesized A or AAAA additionals" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4263, "srv.home.arpa.", .SRV, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectSrvResponse(response, 0x4263);
}

test "TCP request pipeline answers SRV query without synthesized A or AAAA additionals" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4264, "srv.home.arpa.", .SRV, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectSrvResponse(response, 0x4264);
}
test "UDP request pipeline answers DNAME query with target" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42D1, "legacy.home.arpa.", .DNAME, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectDnameResponse(response, 0x42D1);
}

test "TCP request pipeline answers DNAME query with target" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42D2, "legacy.home.arpa.", .DNAME, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectDnameResponse(response, 0x42D2);
}

test "UDP request pipeline answers SVCB query with params" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42B1, "svc.home.arpa.", .SVCB, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectSvcbResponse(response, 0x42B1);
}

test "TCP request pipeline answers SVCB query with params" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42B2, "svc.home.arpa.", .SVCB, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectSvcbResponse(response, 0x42B2);
}
test "UDP request pipeline answers HTTPS alias query" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42C1, "alias.home.arpa.", .HTTPS, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectHttpsResponse(response, 0x42C1);
}

test "TCP request pipeline answers HTTPS alias query" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42C2, "alias.home.arpa.", .HTTPS, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectHttpsResponse(response, 0x42C2);
}

test "UDP request pipeline answers AAAA query with address" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42A1, "target.home.arpa.", .AAAA, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectAaaaResponse(response, 0x42A1);
}

test "TCP request pipeline answers AAAA query with address" {
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x42A2, "target.home.arpa.", .AAAA, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try expectAaaaResponse(response, 0x42A2);
}
test "UDP request pipeline answers ZONEVERSION with SOA serial" {
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

    // Hand-built query: A for target.home.arpa. + OPT carrying one empty
    // ZONEVERSION option (code 19, len 0). buildQueryPacket cannot attach
    // options, so the wire is literal: header, qname, QTYPE/CLASS, then
    // root + OPT(41) + CLASS(udp size) + TTL(0) + RDLEN(4) + opt(19,0).
    const query = &[_]u8{
        0x42, 0xE1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 't',  'a',  'r',  'g',  'e',  't',  0x04, 'h',  'o',  'm',  'e',
        0x04, 'a',  'r',  'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x13, 0x00,
        0x00,
    };
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x42E1), response.header.id);
    // Response OPT carries ZONEVERSION: LABELCOUNT(2 for the responding zone home.arpa.),
    // TYPE 0 (SOA-SERIAL), 4-octet serial 2026053001 = 0x78C31D89.
    var found = false;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const opt = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) orelse continue;
        found = true;
        try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x78, 0xC3, 0x1D, 0x89 }, opt);
    }
    try std.testing.expect(found);
}

test "TCP request pipeline answers ZONEVERSION with SOA serial" {
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

    const query = &[_]u8{
        0x42, 0xE2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 't',  'a',  'r',  'g',  'e',  't',  0x04, 'h',  'o',  'm',  'e',
        0x04, 'a',  'r',  'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x13, 0x00,
        0x00,
    };
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x42E2), response.header.id);
    var found = false;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const opt = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) orelse continue;
        found = true;
        try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x78, 0xC3, 0x1D, 0x89 }, opt);
    }
    try std.testing.expect(found);
}
test "UDP request pipeline answers NSID with configured payload" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    // Operator identifier "ns1.example." — heap-owned like loader output.
    runtime.answer_policy.nsid = try std.heap.page_allocator.dupe(u8, "ns1.example.");

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    // Hand-built query: A for target.home.arpa. + OPT carrying one empty
    // NSID option (code 3, len 0); query payload is never read.
    const query = &[_]u8{
        0x42, 0xF1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 't',  'a',  'r',  'g',  'e',  't',  0x04, 'h',  'o',  'm',  'e',
        0x04, 'a',  'r',  'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
        0x00,
    };
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expect(response.header.qr);
    var found = false;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const opt = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_NSID_OPTION_CODE) orelse continue;
        found = true;
        try std.testing.expectEqualSlices(u8, "ns1.example.", opt);
    }
    try std.testing.expect(found);
}

test "the query CLI asks for NSID and prints the server's identifier" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.nsid = try std.heap.page_allocator.dupe(u8, "ns1.example.");

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    // The CLI's own packet: the NSID request is the empty RFC 5001 option.
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacketWithEdns(&query_buffer, 0x42f1, "target.home.arpa.", .A, .{ .nsid = true });
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try cli_query.writeResponse(response, &output.writer);
    // RFC 5001 section 2.4: the identifier prints as two hexadecimal digits
    // per octet.
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "; NSID: 6e73312e6578616d706c652e") != null);
}

test "TCP request pipeline answers NSID with configured payload" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.nsid = try std.heap.page_allocator.dupe(u8, "ns1.example.");

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    const query = &[_]u8{
        0x42, 0xF2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 't',  'a',  'r',  'g',  'e',  't',  0x04, 'h',  'o',  'm',  'e',
        0x04, 'a',  'r',  'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x29, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
        0x00,
    };
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query, false);
    try std.testing.expect(response.header.qr);
    var found = false;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const opt = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_NSID_OPTION_CODE) orelse continue;
        found = true;
        try std.testing.expectEqualSlices(u8, "ns1.example.", opt);
    }
    try std.testing.expect(found);
}

test "TCP request pipeline answers pipelined queries by id" {
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
    const first_query = try cli_query.buildQueryPacket(&first_query_buffer, 0x4245, "dns.home.arpa.", .A, false);
    const second_query = try cli_query.buildQueryPacket(&second_query_buffer, 0x4246, "dns.home.arpa.", .A, false);
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
    const ids = [_]u16{ first_response.header.id, second_response.header.id };
    try std.testing.expect(ids[0] != ids[1]);
    try std.testing.expect(ids[0] == 0x4245 or ids[0] == 0x4246);
    try std.testing.expect(ids[1] == 0x4245 or ids[1] == 0x4246);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4244, "dns.home.arpa.", .A, false);
    var args = CliTcpArgs{ .io = io, .server = &server, .runtime = &runtime };
    const thread = try std.Thread.spawn(.{}, serveCliTcp, .{&args});
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.exchangeTcpQuery(arena.allocator(), io, &server.socket.address, query, &response_buffer, false);
    thread.join();

    try std.testing.expect(args.ok);
    try expectAResponse(response);
}

test "TCP AXFR carries a length-framed SOA-bounded transfer sequence" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(transfer_zone);
    defer runtime.deinit();
    // The transfer ACL denies by default; this loopback grant permits the fixture's AXFR.
    try runtime.addTransferAllow("home.arpa.", try zimdns.config_parser.Cidr.parse("127.0.0.1/32"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4a01, "home.arpa.", axfr_type, false);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    var args = CliTcpArgs{ .io = io, .server = &server, .runtime = &runtime };
    const thread = try std.Thread.spawn(.{}, serveCliTcp, .{&args});

    // Reading to end of stream is deterministic: the server writes the whole
    // sequence and closes the connection, so no assertion waits on a clock.
    var read_buffer: [4096]u8 = undefined;
    var reader = client_stream.reader(io, &read_buffer);
    const frames = try readTransferSequence(arena.allocator(), &reader.interface);
    thread.join();

    try std.testing.expect(args.ok);
    try expectTransferSequence(frames, 0x4a01);
}

test "TCP IXFR from a stale serial falls back to a full AXFR sequence" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(transfer_zone);
    defer runtime.deinit();
    // The transfer ACL denies by default; this loopback grant permits the fixture's IXFR.
    try runtime.addTransferAllow("home.arpa.", try zimdns.config_parser.Cidr.parse("127.0.0.1/32"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    // The zone has never been reloaded under this runtime, so it holds no
    // delta chain from the client's serial. RFC 1995 answers that request with
    // a full transfer instead of a delta.
    var query_buffer: [512]u8 = undefined;
    const query = try buildIxfrQuery(&query_buffer, 0x4a02, transfer_zone_serial - 1);
    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    var args = CliTcpArgs{ .io = io, .server = &server, .runtime = &runtime };
    const thread = try std.Thread.spawn(.{}, serveCliTcp, .{&args});

    var read_buffer: [4096]u8 = undefined;
    var reader = client_stream.reader(io, &read_buffer);
    const frames = try readTransferSequence(arena.allocator(), &reader.interface);
    thread.join();

    try std.testing.expect(args.ok);
    try expectTransferSequence(frames, 0x4a02);
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
    const parent_query = try cli_query.buildQueryPacket(&parent_query_buffer, 0x5101, "www.example.", .A, false);
    const child_query = try cli_query.buildQueryPacket(&child_query_buffer, 0x5102, "www.sub.example.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, parent_query);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, child_query);
    try listener.serveUdpLoop(&server_socket, io, &runtime, 2);

    var response_buffer: [512]u8 = undefined;
    const parent_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, parent_query, false);
    try expectAddress(parent_response, .{ 192, 0, 2, 1 });
    const child_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, child_query, false);
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
    const parent_query = try cli_query.buildQueryPacket(&parent_query_buffer, 0x5201, "www.example.", .A, false);
    const child_query = try cli_query.buildQueryPacket(&child_query_buffer, 0x5202, "www.sub.example.", .A, false);
    try cli_query.sendTcpQuery(parent_client, io, parent_query);
    try cli_query.sendTcpQuery(child_client, io, child_query);
    try parent_client.shutdown(io, .send);
    try child_client.shutdown(io, .send);

    try listener.serveTcpLoop(&server, io, &runtime, 2);

    var parent_response_buffer: [512]u8 = undefined;
    var child_response_buffer: [512]u8 = undefined;
    const parent_response = try cli_query.receiveTcpResponse(arena.allocator(), parent_client, io, &parent_response_buffer, parent_query, false);
    try expectAddress(parent_response, .{ 192, 0, 2, 1 });
    const child_response = try cli_query.receiveTcpResponse(arena.allocator(), child_client, io, &child_response_buffer, child_query, false);
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

    var clients: [listener.TCP_MAX_CONNECTION_WORKERS]?std.Io.net.Stream = @as([listener.TCP_MAX_CONNECTION_WORKERS]?std.Io.net.Stream, @as([listener.TCP_MAX_CONNECTION_WORKERS]?std.Io.net.Stream, @splat(@as(?std.Io.net.Stream, null))));
    var client_queries: [listener.TCP_MAX_CONNECTION_WORKERS][512]u8 = undefined;
    var client_query_slices: [listener.TCP_MAX_CONNECTION_WORKERS][]const u8 = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
        client_query_slices[index] = try cli_query.buildQueryPacket(&client_queries[index], @intCast(0x5300 + index), "dns.home.arpa.", .A, false);
        try cli_query.sendTcpQuery(client.*.?, io, client_query_slices[index]);
    }

    var excess_client: ?std.Io.net.Stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    var excess_query_buffer: [512]u8 = undefined;
    const excess_query = try cli_query.buildQueryPacket(&excess_query_buffer, 0x53ff, "dns.home.arpa.", .A, false);
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
        const response = try cli_query.receiveTcpResponse(arena.allocator(), client.*.?, io, &response_buffers[index], client_query_slices[index], false);
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

test "concurrent TCP connections each answer every pipelined frame while workers are occupied" {
    const stalled_connections = 2;
    const query_connections = listener.TCP_MAX_CONNECTION_WORKERS - stalled_connections;

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

    // Two connections park mid-frame, so every worker slot is busy for the
    // whole exchange. A server that handled one connection at a time could
    // not answer the query connections inside their read deadline.
    const stalled_frame = [_]u8{ 0x00, 0x40, 1, 2, 3, 4, 5, 6, 7, 8 };
    var stalled = @as([stalled_connections]?std.Io.net.Stream, @splat(@as(?std.Io.net.Stream, null)));
    var stalled_write_buffer: [64]u8 = undefined;
    for (&stalled) |*stream| {
        stream.* = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
        var writer = stream.*.?.writer(io, &stalled_write_buffer);
        try writer.interface.writeAll(&stalled_frame);
        try writer.interface.flush();
    }

    var clients = @as([query_connections]?std.Io.net.Stream, @splat(@as(?std.Io.net.Stream, null)));
    for (&clients) |*client| {
        client.* = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    }

    // All 96 frames (6 connections x the documented 16-frame cap) are written
    // before the server starts, so every request is already buffered when the
    // workers begin: no query can win a race and no assertion waits on a clock.
    var query_buffer: [512]u8 = undefined;
    for (&clients, 0..) |client, connection_index| {
        for (0..listener.TCP_MAX_FRAMES_PER_CONNECTION) |frame_index| {
            try cli_query.sendTcpQuery(client.?, io, try buildConcurrentQuery(&query_buffer, connection_index, frame_index));
        }
    }

    var args = BoundedTcpArgs{ .io = io, .server = &server, .runtime = &runtime, .max_requests = listener.TCP_MAX_CONNECTION_WORKERS };
    const server_thread = try std.Thread.spawn(.{}, serveBoundedTcp, .{&args});
    var joined = false;
    defer if (!joined) server_thread.join();
    defer closeStreams(&clients, io);
    defer closeStreams(&stalled, io);

    // RFC 7766 section 7: a server may send pipelined responses out of order,
    // so the client matches each frame to its query by message ID and checks
    // every expected answer arrives exactly once.
    for (&clients, 0..) |client, connection_index| {
        var seen: [listener.TCP_MAX_FRAMES_PER_CONNECTION]bool = @splat(false);
        var read_buffer: [1024]u8 = undefined;
        var client_reader = client.?.reader(io, &read_buffer);
        const base: u16 = @intCast(0x5400 + connection_index * listener.TCP_MAX_FRAMES_PER_CONNECTION);
        for (0..listener.TCP_MAX_FRAMES_PER_CONNECTION) |_| {
            const frame = try arena.allocator().alloc(u8, 512);
            const response = try receivePipelinedFrame(arena.allocator(), &client_reader.interface, frame);
            try std.testing.expect(response.header.id >= base);
            const frame_index = response.header.id - base;
            try std.testing.expect(frame_index < listener.TCP_MAX_FRAMES_PER_CONNECTION);
            try std.testing.expect(!seen[frame_index]);
            seen[frame_index] = true;
            try expectAddress(response, concurrentQueryFixture(connection_index, frame_index).address);
        }
        for (seen) |matched| try std.testing.expect(matched);
    }

    closeStreams(&stalled, io);
    closeStreams(&clients, io);
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
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7001, "example.com.", .A, false);
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
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7002, "outside.example.", .A, false);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7003, "example.com.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    upstream_thread.join();
    try std.testing.expect(upstream_args.ok);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectForwardedAResponse(response, 0x7003);
}

test "locally served zones win over a configured forwarder and never reach it" {
    const io = std.Io.Threaded.global_single_threaded.io();
    // A live upstream that answers this exact name with 192.0.2.1.
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid };
    const upstream_thread = try std.Thread.spawn(.{}, serveUpstream, .{&upstream_args});

    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41031);
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7a11, "1.2.3.10.in-addr.arpa.", .A, false);

    // Control: with locally served zones off the question reaches the
    // forwarder and is answered positively, so the upstream really does answer
    // this name and the counter below is a real reachability signal.
    var open_zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var open_policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    open_policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("127.0.0.0/8");
    open_policy.recursion_allow_len = 1;
    var open_runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &open_zones, .{}, io, open_policy);
    defer open_runtime.deinit();
    open_runtime.local_zones = false;
    var open_output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const open_bytes = try open_runtime.answerFrom(query, &open_output, &client);
    upstream_thread.join();
    try std.testing.expect(upstream_args.ok);
    try std.testing.expectEqual(@as(usize, 1), upstream_args.requests);

    var open_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer open_arena.deinit();
    const open_response = try dns_message.Message.parse(open_arena.allocator(), open_bytes);
    try expectForwardedAResponse(open_response, 0x7a11);

    // Same question on a default runtime: an authoritative NXDOMAIN carrying the
    // RFC 6303 section 3 empty-zone SOA, and the upstream counter is unchanged
    // because the cache and the forwarder are both consulted after the local
    // zone and neither ever saw this question.
    var default_zones = std.ArrayList(zimdns.zone_index.Zone).empty;
    var default_policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    default_policy.recursion_allow[0] = try zimdns.config_parser.Cidr.parse("127.0.0.0/8");
    default_policy.recursion_allow_len = 1;
    var default_runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &default_zones, .{}, io, default_policy);
    defer default_runtime.deinit();
    try std.testing.expect(default_runtime.local_zones);

    // Fill the cache with a positive answer from the forwarder for a name it
    // owns, then repeat it from the cache. The cache sits after the local
    // zone, so a cached positive must not change the answer for a locally
    // served name either.
    var warm_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid };
    const warm_thread = try std.Thread.spawn(.{}, serveUpstream, .{&warm_args});
    var cached_buffer: [512]u8 = undefined;
    const cached_query = try cli_query.buildQueryPacket(&cached_buffer, 0x7a12, "host.in-addr.arpa.", .A, false);
    var cached_output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const cached_bytes = try default_runtime.answerFrom(cached_query, &cached_output, &client);
    warm_thread.join();
    try std.testing.expect(warm_args.ok);
    try std.testing.expectEqual(@as(usize, 1), warm_args.requests);

    var warm_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer warm_arena.deinit();
    const warm_response = try dns_message.Message.parse(warm_arena.allocator(), cached_bytes);
    try expectForwardedAResponse(warm_response, 0x7a12);

    var repeat_output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    _ = try default_runtime.answerFrom(cached_query, &repeat_output, &client);
    try std.testing.expectEqual(@as(usize, 1), warm_args.requests);

    var default_output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const default_bytes = try default_runtime.answerFrom(query, &default_output, &client);
    try std.testing.expectEqual(@as(usize, 1), warm_args.requests);

    var default_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer default_arena.deinit();
    const default_response = try dns_message.Message.parse(default_arena.allocator(), default_bytes);
    try expectLocalNxdomain(default_response, 0x7a11, "10.in-addr.arpa.");
}

test "locally served zone answers over UDP from a config with no forwarder" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data =
        \\$ORIGIN one.example.
        \\$TTL 3600
        \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.one.example.
        \\www IN A 192.0.2.1
        \\
    });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary one.zone\n" });

    var context = try zimdns.config_loader.ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();
    // No forwarder, no recursion ACL, so no resolver exists at all. The local
    // zone must still answer, which is the operator-reachable path.
    try std.testing.expect(runtime.resolver == null);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7a21, "1.0.0.127.in-addr.arpa.", .PTR, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectLocalNxdomain(response, 0x7a21, "127.in-addr.arpa.");

    // The operator's own zone is untouched by the local-zone table.
    const zone_query = try cli_query.buildQueryPacket(&query_buffer, 0x7a22, "www.one.example.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, zone_query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var zone_response_buffer: [512]u8 = undefined;
    const zone_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &zone_response_buffer, &server_socket.address, zone_query, false);
    try expectAddress(zone_response, .{ 192, 0, 2, 1 });
}
test "local-zones except falls through to refused without a forwarder" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data =
        \\$ORIGIN one.example.
        \\$TTL 3600
        \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.one.example.
        \\www IN A 192.0.2.1
        \\
    });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\local-zones except 127.in-addr.arpa.
        \\
    });

    var context = try zimdns.config_loader.ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Excluded apex: no local answer, no forwarder, no cache — REFUSED.
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7a31, "1.0.0.127.in-addr.arpa.", .PTR, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .refused), response.header.rcode);

    // Non-excluded apex still answered locally.
    const kept_query = try cli_query.buildQueryPacket(&query_buffer, 0x7a32, "1.2.3.10.in-addr.arpa.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, kept_query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var kept_buffer: [512]u8 = undefined;
    const kept = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &kept_buffer, &server_socket.address, kept_query, false);
    try expectLocalNxdomain(kept, 0x7a32, "10.in-addr.arpa.");
}

test "the shipped --config invocation loads through the config Dir and answers a query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    // Exactly what `zimdns server run --config examples/config.gdns` passes:
    // the config file's own directory and the basename.
    var examples = try std.Io.Dir.cwd().openDir(io, "examples", .{});
    defer examples.close(io);
    var context = try zimdns.config_loader.ServerContext.load(examples, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
    try std.testing.expectEqualStrings("home.arpa.", context.zones.items[0].originText());

    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x5a11, "dns.home.arpa.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try expectAddress(response, .{ 192, 168, 1, 1 });
}

fn expectLocalNxdomain(response: dns_message.Message, expected_id: u16, apex: []const u8) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .nxdomain), response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);

    const soa = response.authorities.items[0];
    try std.testing.expect(soa.rrtype.eql(.SOA));
    try std.testing.expectEqual(zimdns.local_zone.RECORD_TTL, soa.ttl);
    try std.testing.expectEqual(zimdns.local_zone.RECORD_TTL, soa.rdata.SOA.minimum);
    var owner_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(apex, try soa.owner.toText(&owner_buffer));
    var mname_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(apex, try soa.rdata.SOA.mname.toText(&mname_buffer));
    var rname_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings("nobody.invalid.", try soa.rdata.SOA.rname.toText(&rname_buffer));
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
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7004, "missing.example.", .A, false);
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
    const second_query_bytes = try cli_query.buildQueryPacket(&second_query_buffer, 0x7005, "missing.example.", .A, false);
    const second_query = try dns_message.Message.parseQuery(query_arena.allocator(), second_query_bytes);
    const second_bytes = try upstream.answer(second_query_bytes, second_query, &client, &output);
    const second = try dns_message.Message.parse(query_arena.allocator(), second_bytes);
    try std.testing.expectEqual(@as(@TypeOf(second.header.rcode), .nxdomain), second.header.rcode);
    try std.testing.expect(second.authorities.items[0].ttl > 0 and second.authorities.items[0].ttl <= 60);
}
test "unvalidated upstream NSEC never feeds the aggressive cache (RFC 8198 §5/§9)" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    // Two requests: the mock answers every query, so a second upstream hit
    // proves the first answer's NSEC was not harvested into the denial cache.
    var upstream_args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid_nsec };
    const upstream_thread = try std.Thread.spawn(.{}, serveUpstream, .{&upstream_args});
    const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    // No trust anchors: the upstream answer is never validated, so its NSEC
    // must not become an aggressive denial proof.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41007);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;

    var first_buffer: [512]u8 = undefined;
    const first_bytes = try cli_query.buildQueryPacket(&first_buffer, 0x7010, "example.com.", .A, true);
    const first_query = try dns_message.Message.parseQuery(arena.allocator(), first_bytes);
    const first_response = try dns_message.Message.parse(arena.allocator(), try upstream.answer(first_bytes, first_query, &client, &output));
    try std.testing.expectEqual(@as(u16, 2), first_response.header.answer_count);

    // `mail.example.com.` falls inside the NSEC span example.→www.example.;
    // a harvested proof would answer this denial without upstream I/O.
    var second_buffer: [512]u8 = undefined;
    const second_bytes = try cli_query.buildQueryPacket(&second_buffer, 0x7011, "mail.example.com.", .A, true);
    const second_query = try dns_message.Message.parseQuery(arena.allocator(), second_bytes);
    _ = try upstream.answer(second_bytes, second_query, &client, &output);
    upstream_thread.join();
    try std.testing.expectEqual(@as(usize, 2), upstream_args.requests);
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
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x7006, "example.com.", .A, false);
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
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7000, "example.com.", .A, false);
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

test "upstream UDP attempts each bind a fresh ephemeral source port" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var udp = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer udp.close(io);
    var capture = PortCaptureArgs{ .io = io, .udp = &udp };
    const capture_thread = try std.Thread.spawn(.{}, servePortCapture, .{&capture});

    const policy = resolver.Policy{ .forwarder = .{ .address = udp.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();
    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7020, "example.com.", .A, false);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41020);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try upstream.answer(query_bytes, query, &client, &output);
    capture_thread.join();
    try std.testing.expect(capture.ok);
    try std.testing.expectEqual(@as(usize, 2), capture.requests);

    // RFC 5452 §9.2: a blind spoof has to guess the per-attempt randomized
    // query ID *and* the ephemeral source port, so the two attempts must not
    // share a port. `incoming.from` is the address the kernel stamped on each
    // datagram, i.e. the port the resolver's per-attempt socket actually used.
    const first_port = capture.first_from.getPort();
    const second_port = capture.second_from.getPort();
    try std.testing.expect(first_port != 0);
    try std.testing.expect(second_port != 0);
    if (first_port == second_port) {
        std.debug.print("both upstream UDP attempts left the same ephemeral source port: {d}\n", .{first_port});
        return error.SameUpstreamSourcePort;
    }

    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try expectForwardedAResponse(response, 0x7020);
}

const PortCaptureArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    first_from: std.Io.net.IpAddress = undefined,
    second_from: std.Io.net.IpAddress = undefined,
    requests: usize = 0,
    ok: bool = false,
};

/// Leaves the first attempt unanswered on purpose. The resolver's own
/// `UDP_TIMEOUT` then expires, it closes that socket, and only afterwards does
/// the second attempt reach the wire — so this thread observes both datagrams
/// and both source ports with no sleep, no retry, and no timing threshold.
fn servePortCapture(args: *PortCaptureArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const first = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    args.requests = 1;
    args.first_from = first.from;
    const second = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    args.requests = 2;
    args.second_from = second.from;
    const valid = makeAResponse(second.data, false, false, false);
    args.udp.send(args.io, &second.from, valid.bytes[0..valid.len]) catch return;
    args.ok = true;
}

test "forwarder sends full QNAME upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var capture = QminCaptureArgs{ .io = io, .udp = &upstream_socket };
    const capture_thread = try std.Thread.spawn(.{}, serveQminCapture, .{&capture});

    const policy = resolver.Policy{
        .forwarder = .{ .address = upstream_socket.address },
    };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7010, "www.example.com.", .A, false);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41010);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try upstream.answer(query_bytes, query, &client, &output);
    capture_thread.join();
    try std.testing.expect(capture.ok);
    // A forwarder never minimizes: the full QNAME reaches its upstream.
    try std.testing.expectEqualStrings("www.example.com.", capture.qname[0..capture.qname_len]);
    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try expectForwardedAResponse(response, 0x7010);
}
const KeyTagCaptureArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    tags: [64]u8 = @as([64]u8, @splat(@as(u8, 0))),
    tags_len: usize = 0,
    ok: bool = false,
};

fn serveKeyTagCapture(args: *KeyTagCaptureArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), incoming.data) catch return;
    for (parsed.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const opt = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_KEY_TAG_OPTION_CODE) orelse continue;
        @memcpy(args.tags[0..opt.len], opt);
        args.tags_len = opt.len;
    }
    const valid = makeAResponse(incoming.data, false, false, false);
    args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
    args.ok = true;
}

test "forwarder signals anchor key tags on upstream DNSKEY query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var capture = KeyTagCaptureArgs{ .io = io, .udp = &upstream_socket };
    const capture_thread = try std.Thread.spawn(.{}, serveKeyTagCapture, .{&capture});

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Parsed with the same allocator the Resolver frees with: anchors move
    // into the policy by value and Resolver.deinit owns them.
    const anchors = try zimdns.dns_validate.Anchors.parse(std.testing.allocator,
        \\example.com. DNSKEY 257 3 8 QUJDRA==
        \\
    );
    // Anchors move into the policy; Resolver.deinit owns them.

    const policy = resolver.Policy{
        .forwarder = .{ .address = upstream_socket.address },
        .anchors = anchors,
    };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7011, "example.com.", .DNSKEY, true);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41011);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    _ = try upstream.answer(query_bytes, query, &client, &output);
    capture_thread.join();
    try std.testing.expect(capture.ok);
    // 0x888f is the RFC 4034 Appendix B checksum of RDATA 01 01 03 08 41 42 43 44.
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x8f }, capture.tags[0..capture.tags_len]);
}

const KeyTagQueryCapture = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    saw_null_query: bool = false,
    name: [256]u8 = undefined,
    name_len: usize = 0,
    ok: bool = false,
};

/// Serves the three datagrams the DDR-style chain fetch makes: the client's
/// signed A answer, the RFC 8145 section 5.2 Key Tag query, and the DNSKEY
/// chain query. Records the NULL query's name.
fn serveKeyTagQueryCapture(args: *KeyTagQueryCapture) void {
    var buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var served: usize = 0;
    while (served < 3) : (served += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &buffer, TestTimeout) catch return;
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const parsed = dns_message.Message.parse(arena.allocator(), incoming.data) catch return;
        var response = makeAResponse(incoming.data, false, false, false);
        if (parsed.question) |question| {
            if (question.qtype.code() == 10) {
                args.saw_null_query = true;
                var text: [256]u8 = undefined;
                const name = question.name.toText(&text) catch return;
                @memcpy(args.name[0..name.len], name);
                args.name_len = name.len;
            }
            // The client's A answer must look signed so the validator fetches
            // the chain; the chain queries themselves need no signature.
            if (question.qtype.eql(.A)) appendMockRrsig(&response);
        }
        args.udp.send(args.io, &incoming.from, response.bytes[0..response.len]) catch return;
    }
    args.ok = true;
}

test "forwarder sends the RFC 8145 key tag query for an anchor zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var capture = KeyTagQueryCapture{ .io = io, .udp = &upstream_socket };
    const capture_thread = try std.Thread.spawn(.{}, serveKeyTagQueryCapture, .{&capture});

    // The mock RRSIG signs with `example.`, so the anchor names that zone.
    const anchors = try zimdns.dns_validate.Anchors.parse(std.testing.allocator,
        \\example. DNSKEY 257 3 8 QUJDRA==
        \\
    );
    const policy = resolver.Policy{
        .forwarder = .{ .address = upstream_socket.address },
        .anchors = anchors,
    };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7012, "www.example.", .A, true);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41012);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    _ = try upstream.answer(query_bytes, query, &client, &output);
    capture_thread.join();

    try std.testing.expect(capture.ok);
    try std.testing.expect(capture.saw_null_query);
    // 0x888f is the RFC 4034 Appendix B checksum of the anchor's DNSKEY.
    try std.testing.expectEqualStrings("_ta-888f.example.", capture.name[0..capture.name_len]);
}

const DoCaptureArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    do_bit: bool = false,
    ok: bool = false,
};

/// Records the DO bit of the upstream query and answers it.
fn serveDoCapture(args: *DoCaptureArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), incoming.data) catch return;
    args.do_bit = parsed.edns != null and parsed.edns.?.dnssec_ok;
    const valid = makeAResponse(incoming.data, false, false, false);
    args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
    args.ok = true;
}

test "forwarder asks upstream with DO=1 for a client query without EDNS" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var capture = DoCaptureArgs{ .io = io, .udp = &upstream_socket };
    const capture_thread = try std.Thread.spawn(.{}, serveDoCapture, .{&capture});

    const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    var upstream = try Resolver.init(std.testing.allocator, io, policy);
    defer upstream.deinit();

    // A client query without EDNS still reaches the upstream with the DO bit
    // set (RFC 3225 section 3), and the answer comes back to the client.
    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7030, "example.com.", .A, false);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41030);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try upstream.answer(query_bytes, query, &client, &output);
    capture_thread.join();
    try std.testing.expect(capture.ok);
    try std.testing.expect(capture.do_bit);
    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try expectForwardedAResponse(response, 0x7030);
}

// RFC 3225 section 3: an answer to a client that did not ask for proofs
// carries no security RRs, while the same answer to a DO=1 client does.
test "a forwarded answer reaches a DO=0 client without the security RRs" {
    const io = std.Io.Threaded.global_single_threaded.io();

    // --- a client that asked for no proofs: the RRSIG does not reach it.
    {
        var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
        defer upstream_socket.close(io);
        var args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid_rrsig };
        const thread = try std.Thread.spawn(.{}, serveUpstream, .{&args});

        const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
        var forwarder = try Resolver.init(std.testing.allocator, io, policy);
        defer forwarder.deinit();

        var query_buffer: [512]u8 = undefined;
        const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7040, "example.com.", .A, false);
        var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer query_arena.deinit();
        const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
        const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41040);
        var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
        const response_bytes = try forwarder.answer(query_bytes, query, &client, &output);
        thread.join();
        try std.testing.expect(args.ok);

        const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
        try std.testing.expect(response.answers.items[0].rrtype.eql(.A));
    }

    // --- a client that asked for the proofs: the RRSIG rides along.
    {
        var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
        defer upstream_socket.close(io);
        var args = UpstreamArgs{ .io = io, .udp = &upstream_socket, .mode = .valid_rrsig };
        const thread = try std.Thread.spawn(.{}, serveUpstream, .{&args});

        const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
        var forwarder = try Resolver.init(std.testing.allocator, io, policy);
        defer forwarder.deinit();

        var query_buffer: [512]u8 = undefined;
        const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7041, "example.com.", .A, true);
        var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer query_arena.deinit();
        const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
        const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41041);
        var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
        const response_bytes = try forwarder.answer(query_bytes, query, &client, &output);
        thread.join();
        try std.testing.expect(args.ok);

        const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
        try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
        try std.testing.expect(response.answers.items[1].rrtype.eql(.RRSIG));
    }
}

const QminCaptureArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    qname: [256]u8 = @as([256]u8, @as([256]u8, @splat(@as(u8, 0)))),
    qname_len: usize = 0,
    ok: bool = false,
};

fn serveQminCapture(args: *QminCaptureArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
    const question = parsed.question orelse return;
    const text = question.name.toText(&args.qname) catch return;
    args.qname_len = text.len;
    const valid = makeAResponse(incoming.data, false, false, false);
    args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
    args.ok = true;
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
            // INFO-CODE is the first two octets; RFC 8914 EXTRA-TEXT may follow.
            if (option_code == resolver.EDE_OPTION_CODE and option_len >= 2) {
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

fn closeStreams(streams: []?std.Io.net.Stream, io: std.Io) void {
    for (streams) |*stream| {
        if (stream.*) |value| {
            value.close(io);
            stream.* = null;
        }
    }
}

const ConcurrentQueryFixture = struct { name: []const u8, address: [4]u8 };

/// Reads one length-prefixed response frame from a pipelined connection.
fn receivePipelinedFrame(allocator: std.mem.Allocator, reader: *std.Io.Reader, buffer: []u8) !dns_message.Message {
    const length_bytes = try reader.takeArray(2);
    const length = std.mem.readInt(u16, length_bytes, .big);
    if (length == 0 or length > buffer.len) return error.BadResponse;
    try reader.readSliceAll(buffer[0..length]);
    return dns_message.Message.parse(allocator, buffer[0..length]);
}

/// Alternates qnames so a response swapped between connections or frames
/// carries the wrong answer, not just a wrong id.
fn concurrentQueryFixture(connection_index: usize, frame_index: usize) ConcurrentQueryFixture {
    const fixtures = [_]ConcurrentQueryFixture{
        .{ .name = "dns.home.arpa.", .address = .{ 192, 168, 1, 1 } },
        .{ .name = "target.home.arpa.", .address = .{ 192, 0, 2, 21 } },
    };
    return fixtures[(connection_index + frame_index) % fixtures.len];
}

fn buildConcurrentQuery(buffer: []u8, connection_index: usize, frame_index: usize) ![]const u8 {
    const fixture = concurrentQueryFixture(connection_index, frame_index);
    const id = @as(u16, @intCast(0x5400 + connection_index * listener.TCP_MAX_FRAMES_PER_CONNECTION + frame_index));
    return cli_query.buildQueryPacket(buffer, id, fixture.name, .A, false);
}

/// RFC 1995 IXFR request: the question plus the client's serial in an
/// authority SOA owned by the question name.
fn buildIxfrQuery(buffer: []u8, id: u16, client_serial: u32) ![]const u8 {
    const base = try cli_query.buildQueryPacket(buffer, id, "home.arpa.", ixfr_type, false);
    std.mem.writeInt(u16, buffer[8..10], 1, .big);
    const client_soa = dns_record.ResourceRecord{
        .owner = try dns_name.Name.fromText("home.arpa."),
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns1.home.arpa."),
            .rname = try dns_name.Name.fromText("hostmaster.home.arpa."),
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

const IntegrationSignedQuery = struct {
    bytes: [512]u8,
    len: usize,
    owner_start: usize,
};

fn buildIntegrationSignedQuery(time_signed: u64) !IntegrationSignedQuery {
    const algorithm = try dns_name.Name.fromText("hmac-sha256.");
    const owner = try dns_name.Name.fromText("key.");
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try writer.writeBytes(&.{ 3, 'd', 'n', 's', 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    const owner_start = writer.len();
    var zeros: [32]u8 = @splat(0);
    const value = try dns_rdata.Tsig.init(algorithm, time_signed, 300, &zeros, 0x1234, 0, &.{});
    try (dns_record.ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(&writer);
    const final = (try dns_tsig.parseFinalAdditional(writer.written())).?;
    const signed = try dns_tsig.sign(writer.written(), "01234567890123456789012345678901", final.owner, final.tsig, null);
    try dns_tsig.patchMac(packet[0..writer.len()], final, signed.slice());
    return .{ .bytes = packet, .len = writer.len(), .owner_start = owner_start };
}

/// The wire length of an OPT record: root owner, type, class, TTL, RDLENGTH.
const opt_record_len: usize = 11;

/// True when the query ends in an empty OPT record (root owner, type 41,
/// RDLENGTH 0): the client's EDNS record. A real server answers the question
/// and never echoes that record into its own answer section.
/// The byte length of the OPT record that ends `query`, options and all.
/// The forwarder always appends one (RFC 6891), and its RDATA may carry the
/// Cookie option, so the record is located from its root owner and its own
/// RDATA length rather than assumed to be the bare eleven-octet form.
fn trailingOptLen(query: []const u8) ?usize {
    if (query.len < 12 + opt_record_len) return null;
    var start = query.len - opt_record_len;
    while (true) {
        if (query[start] == 0 and std.mem.readInt(u16, query[start + 1 ..][0..2], .big) == 41) {
            const rdata_len = std.mem.readInt(u16, query[start + 9 ..][0..2], .big);
            const total = opt_record_len + rdata_len;
            if (start + total == query.len) return total;
        }
        if (start == 0) return null;
        start -= 1;
    }
}

fn serveUpstream(args: *UpstreamArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    args.requests += 1;
    var valid = makeAResponse(incoming.data, false, false, false);
    switch (args.mode) {
        .valid => args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return,
        .valid_rrsig => {
            // The answer carries the A record and its RRSIG, as a signed
            // zone's server sends them.
            var rrsig_response = makeAResponse(incoming.data, false, false, false);
            appendMockRrsig(&rrsig_response);
            args.udp.send(args.io, &incoming.from, rrsig_response.bytes[0..rrsig_response.len]) catch return;
        },
        .valid_nsec => {
            // The mock drops the client's OPT record before it builds the
            // answer (see makeAResponse), so the A + NSEC land in the answer
            // section.
            var nsec_response = makeAResponse(incoming.data, false, false, false);
            appendMockNsec(&nsec_response);
            args.udp.send(args.io, &incoming.from, nsec_response.bytes[0..nsec_response.len]) catch return;
            // A second query follows: it must reach upstream too, proving
            // the first answer's NSEC was not harvested.
            const second = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
            args.requests += 1;
            var second_response = makeAResponse(second.data, false, false, false);
            appendMockNsec(&second_response);
            args.udp.send(args.io, &second.from, second_response.bytes[0..second_response.len]) catch return;
        },
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
    const base = try cli_query.buildQueryPacket(buffer, id, "example.com.", .A, false);
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
    // A real server answers the question and never echoes the client's OPT
    // record into its own answer section. The forwarder asks upstream with an
    // OPT (RFC 3225 section 3), so the mock drops that trailing record and
    // the record count that carried it.
    const opt_len = trailingOptLen(query);
    const echoed = if (opt_len) |len| query[0 .. query.len - len] else query;
    @memcpy(response.bytes[0..echoed.len], echoed);
    response.len = echoed.len;
    if (opt_len != null) {
        const additional_count = std.mem.readInt(u16, response.bytes[10..12], .big);
        std.mem.writeInt(u16, response.bytes[10..12], additional_count -| 1, .big);
    }
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
/// Appends an RRSIG to a mock A response, bumping ANCOUNT. The RDATA is the
/// RFC 4034 section 3.2 shape the resolver reads as an opaque proof record:
/// the covered type, the algorithm, the label count, the TTL, the validity
/// window, the key tag, the signer's name, and the signature.
fn appendMockRrsig(response: *ResponseBytes) void {
    const rrsig = [_]u8{
        0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x1f,
        0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x0e, 0x10, 0x7f, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',
        'l',  'e',  0x00, 0x00, 0x00, 0x00, 0x00,
    };
    @memcpy(response.bytes[response.len .. response.len + rrsig.len], &rrsig);
    response.len += rrsig.len;
    const ancount = std.mem.readInt(u16, response.bytes[6..8], .big);
    std.mem.writeInt(u16, response.bytes[6..8], ancount + 1, .big);
}

/// Appends an NSEC denying everything between the question owner and
/// `www.<owner>` (bitmap: A + NSEC) to a mock A response, bumping ANCOUNT.
/// The forwarder must not feed this proof to its aggressive cache without
/// DNSSEC validation (RFC 8198 §5/§9: harvest gated on AD=secure).
fn appendMockNsec(response: *ResponseBytes) void {
    // Owner = question pointer; next = www.<qname>; bitmap window 0 carries
    // A(1) and NSEC(47) — deny() rejects bitmaps lacking the NSEC bit.
    const nsec = [_]u8{
        0xc0, 0x0c, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x19,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x01,
    };
    @memcpy(response.bytes[response.len .. response.len + nsec.len], &nsec);
    response.len += nsec.len;
    const ancount = std.mem.readInt(u16, response.bytes[6..8], .big);
    std.mem.writeInt(u16, response.bytes[6..8], ancount + 1, .big);
}

fn makeNxDomainResponse(query: []const u8) ResponseBytes {
    var response = ResponseBytes{};
    // The client's OPT record is not echoed into the answer, as in
    // makeAResponse.
    const opt_len = trailingOptLen(query);
    const echoed = if (opt_len) |len| query[0 .. query.len - len] else query;
    @memcpy(response.bytes[0..echoed.len], echoed);
    response.len = echoed.len;
    if (opt_len != null) {
        const additional_count = std.mem.readInt(u16, response.bytes[10..12], .big);
        std.mem.writeInt(u16, response.bytes[10..12], additional_count -| 1, .big);
    }
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

fn expectRpResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.RP));
    var mbox: [256]u8 = undefined;
    var txt: [256]u8 = undefined;
    try std.testing.expectEqualStrings("mbox.home.arpa.", try answer.rdata.RP.mbox.toText(&mbox));
    try std.testing.expectEqualStrings("txt-dname.home.arpa.", try answer.rdata.RP.txt.toText(&txt));
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

fn expectX25Response(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.X25));
    try std.testing.expectEqualStrings("1234", answer.rdata.X25.text());
}

fn expectIsdnResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.ISDN));
    try std.testing.expectEqualStrings("1234", answer.rdata.ISDN.addressText());
    try std.testing.expect(answer.rdata.ISDN.has_subaddress);
    try std.testing.expectEqualStrings("aBf", answer.rdata.ISDN.subaddressText());
}

fn expectHinfoResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.HINFO));
    try std.testing.expectEqualStrings("Intel", answer.rdata.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", answer.rdata.HINFO.osText());
}

fn expectRtResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.RT));
    try std.testing.expectEqual(@as(u16, 100), answer.rdata.RT.preference);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.RT.exchange.toText(&target));
}

fn expectSrvResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.additional_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.SRV));
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.SRV.priority);
    try std.testing.expectEqual(@as(u16, 20), answer.rdata.SRV.weight);
    try std.testing.expectEqual(@as(u16, 8443), answer.rdata.SRV.port);
    try std.testing.expectEqualSlices(u8, &.{
        0x06, 't', 'a', 'r',  'g', 'e',  't',
        0x04, 'h', 'o', 'm',  'e', 0x04, 'a',
        'r',  'p', 'a', 0x00,
    }, answer.rdata.SRV.target.asWire());
}
fn expectDnameResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.DNAME));
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.", try answer.rdata.DNAME.toText(&target));
}

fn expectSvcbResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.SVCB));
    try std.testing.expectEqual(@as(u16, 1), answer.rdata.SVCB.priority);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.SVCB.target.toText(&target));
    // alpn=h2 (key 1, len 3: alpn-list len 2 + "h2") + port=443 (key 3, 0x01bb), in key order.
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0, 3, 2, 'h', '2', 0, 3, 0, 2, 0x01, 0xbb }, answer.rdata.SVCB.paramsBytes());
}
fn expectHttpsResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.HTTPS));
    try std.testing.expectEqual(@as(u16, 0), answer.rdata.HTTPS.priority);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.HTTPS.target.toText(&target));
    try std.testing.expectEqual(@as(u16, 0), answer.rdata.HTTPS.params_len);
}

fn expectAaaaResponse(response: anytype, expected_id: u16) !void {
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(expected_id, response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21 }, &answer.rdata.AAAA);
}

fn expectMetrics(counters: metrics.Counters) !void {
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.encode_failures_total.load(.monotonic));
}

fn expectAddress(response: anytype, expected: [4]u8) !void {
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &expected, &response.answers.items[0].rdata.A);
}

/// Reads a Do53 transfer sequence: a two-octet length prefix per RFC 1035
/// section 4.2.2 followed by that many octets of DNS message, until the server
/// closes the connection. A prefix that disagrees with the octets that follow
/// it fails here: a short frame parses as a truncated message, a long one
/// never delivers `length` octets, and a missing prefix is read as a length of
/// the query id.
fn readTransferSequence(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]dns_message.Message {
    var frames: std.ArrayList(dns_message.Message) = .empty;
    while (true) {
        const len_bytes = reader.takeArray(2) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const length = std.mem.readInt(u16, len_bytes, .big);
        // RFC 1035 section 4.2.2: zero is not a legal message length.
        try std.testing.expect(length > 0);
        try frames.append(allocator, try dns_message.Message.parse(allocator, try reader.take(length)));
    }
    // Anything still buffered would be an octet the frame lengths never
    // accounted for, so the sequence would not be framed end to end.
    try std.testing.expectEqual(@as(usize, 0), reader.bufferedLen());
    try std.testing.expect(frames.items.len > 0);
    return frames.toOwnedSlice(allocator);
}

/// Every frame of a transfer sequence is a standalone authoritative response,
/// and the concatenated answers are exactly the loaded zone's records in
/// RFC 5936 order: apex SOA first, apex SOA last, nothing else in between.
fn expectTransferSequence(frames: []dns_message.Message, expected_id: u16) !void {
    var name_buffer: [256]u8 = undefined;
    var index: usize = 0;
    var first_soa: ?u32 = null;
    var last_soa: ?u32 = null;
    for (frames) |frame| {
        try std.testing.expect(frame.header.qr);
        try std.testing.expectEqual(expected_id, frame.header.id);
        try std.testing.expectEqual(@as(@TypeOf(frame.header.rcode), .no_error), frame.header.rcode);
        // AA: the zone that owns the transfer answers it.
        try std.testing.expect(frame.header.authoritative);
        // Each frame echoes the question so it parses standalone.
        try std.testing.expectEqual(@as(u16, 1), frame.header.question_count);
        const question = frame.question orelse return error.MissingQuestion;
        try std.testing.expectEqualStrings("home.arpa.", try question.name.toText(&name_buffer));
        try std.testing.expectEqual(@as(u16, 0), frame.header.authority_count);
        try std.testing.expectEqual(@as(u16, 0), frame.header.additional_count);
        try std.testing.expectEqual(@as(u16, @intCast(frame.answers.len)), frame.header.answer_count);
        for (frame.answers.slice()) |record| {
            if (index >= expected_transfer_records.len) return error.TooManyAnswers;
            const expected = expected_transfer_records[index];
            try std.testing.expect(record.rrtype.eql(expected.rrtype));
            try std.testing.expectEqualStrings(expected.owner, try record.owner.toText(&name_buffer));
            if (record.rrtype.eql(.SOA)) {
                if (first_soa == null) first_soa = record.rdata.SOA.serial;
                last_soa = record.rdata.SOA.serial;
            }
            index += 1;
        }
    }
    try std.testing.expectEqual(expected_transfer_records.len, index);
    // SOA-framed: the apex SOA of the loaded zone opens and closes the
    // sequence, and it is the same record at both ends.
    try std.testing.expectEqual(transfer_zone_serial, first_soa orelse return error.MissingSoa);
    try std.testing.expectEqual(first_soa, last_soa);
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
    \\rp IN RP mbox.home.arpa. txt-dname.home.arpa.
    \\txt-dname IN TXT "target text"
    \\caa IN CAA 128 issue "a\000\128\255"
    \\afsdb IN AFSDB 42 server.home.arpa.
    \\server IN A 192.0.2.53
    \\x25 IN X25 1234
    \\isdn IN ISDN 1234 "aBf"
    \\hinfo IN HINFO "Intel" "Linux"
    \\rt IN RT 100 target.home.arpa.
    \\srv IN SRV 10 20 8443 target.home.arpa.
    \\legacy IN DNAME target.example.
    \\svc IN SVCB 1 target.home.arpa. alpn=h2 port=443
    \\alias IN HTTPS 0 target
    \\target IN A 192.0.2.21
    \\target IN AAAA 2001:db8::21
    \\target IN X25 1234
    \\target IN ISDN 1234 "aBf"
    \\
;

const TransferRecord = struct {
    owner: []const u8,
    rrtype: @FieldType(dns_record.ResourceRecord, "rrtype"),
};

const axfr_type: @FieldType(TransferRecord, "rrtype") = .AXFR;
const ixfr_type: @FieldType(TransferRecord, "rrtype") = .IXFR;
const transfer_zone_serial: u32 = 2026053001;

const transfer_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2026053001 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\ns1 IN A 192.168.1.1
    \\dns IN A 192.168.1.1
    \\
;

/// The records `transfer_zone` must put on the wire: apex SOA, the zone's own
/// records in zone order, apex SOA again.
const expected_transfer_records = [_]TransferRecord{
    .{ .owner = "home.arpa.", .rrtype = .SOA },
    .{ .owner = "home.arpa.", .rrtype = .NS },
    .{ .owner = "ns1.home.arpa.", .rrtype = .A },
    .{ .owner = "dns.home.arpa.", .rrtype = .A },
    .{ .owner = "home.arpa.", .rrtype = .SOA },
};

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

// ------------------------------------------------- validating forwarder (AD)

const SignedUpstreamArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    zone: *const zimdns.zone_index.Zone,
    /// Flip one octet of the answer, so the signature no longer covers it.
    tamper: bool,
    ok: bool = false,
};

/// Serves the A RRset and its RRSIG out of an already-signed zone, exactly as
/// an upstream recursive server would for a DO=1 query, and answers the
/// signer's DNSKEY query the validator makes to learn the zone's ZSKs.
fn serveSignedUpstream(args: *SignedUpstreamArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var served: usize = 0;
    while (served < 8) : (served += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const parsed = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        const question = parsed.question orelse return;
        const dnskey_query = question.qtype.eql(.DNSKEY);

        var message = dns_message.Message{
            .allocator = arena.allocator(),
            .header = .{
                .id = parsed.header.id,
                .qr = true,
                .recursion_desired = true,
                .recursion_available = true,
                .question_count = 1,
            },
            .question = parsed.question,
            .answers = dns_message.RecordSection.init(arena.allocator(), 0) catch return,
            .authorities = dns_message.RecordSection.init(arena.allocator(), 0) catch return,
            .additionals = dns_message.RecordSection.init(arena.allocator(), 0) catch return,
            .edns = null,
        };
        for (args.zone.records.items[0..args.zone.records.len]) |*record| {
            const is_answer = record.rrtype.eql(.A) or record.rrtype.eql(.RRSIG);
            if (!is_answer) continue;
            const owner_is_www = std.ascii.eqlIgnoreCase(record.ownerText(), "www.signed.example.");
            if (!owner_is_www) continue;
            var wire = dns_record.ResourceRecord{
                .owner = dns_name.Name.fromText(record.ownerText()) catch return,
                .rrtype = record.rrtype,
                .class = .IN,
                .ttl = record.ttl,
                .rdata = zimdns.zone_parser.parseRData(record.rrtype, record.rdataText()) catch return,
            };
            if (args.tamper and wire.rrtype.eql(.A)) wire.rdata.A[3] ^= 0xff;
            message.answers.append(wire) catch return;
        }
        if (dnskey_query) {
            message.answers.len = 0;
            for (args.zone.records.items[0..args.zone.records.len]) |*record| {
                const is_dnskey_data = record.rrtype.eql(.DNSKEY) or record.rrtype.eql(.RRSIG);
                if (!is_dnskey_data) continue;
                const owner_is_apex = std.ascii.eqlIgnoreCase(record.ownerText(), "signed.example.");
                if (!owner_is_apex) continue;
                const wire = dns_record.ResourceRecord{
                    .owner = dns_name.Name.fromText(record.ownerText()) catch return,
                    .rrtype = record.rrtype,
                    .class = .IN,
                    .ttl = record.ttl,
                    .rdata = zimdns.zone_parser.parseRData(record.rrtype, record.rdataText()) catch return,
                };
                message.answers.append(wire) catch return;
            }
        }
        message.header.answer_count = @intCast(message.answers.len);

        var buffer: [4096]u8 = undefined;
        var writer = dns_writer.Writer.init(&buffer);
        message.encode(&writer) catch return;
        args.udp.send(args.io, &incoming.from, writer.written()) catch return;
        args.ok = true;
    }
}

/// A forwarder policy carrying one DNSKEY anchor. The resolver takes ownership
/// of the anchor RDATA and frees it with its own allocator, so the copy is
/// taken here rather than borrowed from a caller's arena.
fn anchoredForwardPolicy(address: std.Io.net.IpAddress, key: *const zimdns.zone_signer.Key) !resolver.Policy {
    const borrowed = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(borrowed);
    const rdata = try std.testing.allocator.dupe(u8, borrowed);
    var policy = resolver.Policy{ .forwarder = .{ .address = address } };
    policy.anchors.items[0] = .{
        .owner = try dns_name.Name.fromText("signed.example."),
        .rrtype = .DNSKEY,
        .rdata = rdata,
    };
    policy.anchors.len = 1;
    return policy;
}

const signed_forward_zone =
    \\$ORIGIN signed.example.
    \\$TTL 3600
    \\@ IN SOA ns1.signed.example. hostmaster.signed.example. 1 3600 900 1209600 3600
    \\@ IN NS ns1.signed.example.
    \\ns1 IN A 192.0.2.53
    \\www IN A 192.0.2.80
    \\
;

// The full operator path: a configured anchor, a forwarded DO=1 query, and
// the AD bit set only because this server verified every RRset itself.
test "validating forwarder sets AD on a verified answer and SERVFAILs with an EDE on a forged one" {
    const io = std.Io.Threaded.global_single_threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const work = arena.allocator();

    var zone_file = try zimdns.zone_parser.ZoneFile.parse(signed_forward_zone);
    defer zone_file.deinit();
    var zone = try zimdns.zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var key = try zimdns.zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    // Fixed window and clock so the signatures are byte-for-byte reproducible.
    try zimdns.zone_signer.signZone(work, &zone, &key, .{ .inception = 1_000_000_000, .expiration = 2_000_000_000 });

    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41099);

    // --- verified answer: AD must be set.
    {
        var args = SignedUpstreamArgs{ .io = io, .udp = &upstream_socket, .zone = &zone, .tamper = false };
        const thread = try std.Thread.spawn(.{}, serveSignedUpstream, .{&args});

        var forwarder = try Resolver.init(std.testing.allocator, io, try anchoredForwardPolicy(upstream_socket.address, &key));
        defer forwarder.deinit();

        var query_buffer: [512]u8 = undefined;
        const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7110, "www.signed.example.", .A, true);
        var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer query_arena.deinit();
        const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
        var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
        const response_bytes = try forwarder.answer(query_bytes, query, &client, &output);
        thread.join();
        try std.testing.expect(args.ok);

        const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
        try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
        // RFC 4035 section 3.2.3: AD because the resolver side vouched for it.
        try std.testing.expect(response.header.authenticated_data);
    }

    // --- forged answer: SERVFAIL carrying the RFC 8914 INFO-CODE.
    {
        var args = SignedUpstreamArgs{ .io = io, .udp = &upstream_socket, .zone = &zone, .tamper = true };
        const thread = try std.Thread.spawn(.{}, serveSignedUpstream, .{&args});

        var forwarder = try Resolver.init(std.testing.allocator, io, try anchoredForwardPolicy(upstream_socket.address, &key));
        defer forwarder.deinit();

        var query_buffer: [512]u8 = undefined;
        const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7111, "www.signed.example.", .A, true);
        var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer query_arena.deinit();
        const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
        var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
        const response_bytes = try forwarder.answer(query_bytes, query, &client, &output);
        thread.join();
        try std.testing.expect(args.ok);

        const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
        // RFC 4035 section 5.5: a response that fails validation is not
        // returned, and the EDE says why in the wire format of RFC 8914.
        try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .servfail), response.header.rcode);
        try std.testing.expect(!response.header.authenticated_data);
        try expectEde(response, resolver.EDE_DNSSEC_BOGUS);
        try std.testing.expectEqualStrings("dnssec bogus", resolver.edeText(resolver.EDE_DNSSEC_BOGUS));
    }
}

// An upstream that sets AD is not evidence: this server did no validation, so
// it must not relay the claim (RFC 4035 section 3.2.3).
test "a forwarder with no configured anchor never relays an upstream AD bit" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var args = AdUpstreamArgs{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveAdUpstream, .{&args});

    const policy = resolver.Policy{ .forwarder = .{ .address = upstream_socket.address } };
    var forwarder = try Resolver.init(std.testing.allocator, io, policy);
    defer forwarder.deinit();

    var query_buffer: [512]u8 = undefined;
    const query_bytes = try cli_query.buildQueryPacket(&query_buffer, 0x7112, "www.example.com.", .A, false);
    var query_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer query_arena.deinit();
    const query = try dns_message.Message.parseQuery(query_arena.allocator(), query_bytes);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41098);
    var output: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const response_bytes = try forwarder.answer(query_bytes, query, &client, &output);
    thread.join();
    try std.testing.expect(args.ok);

    const response = try dns_message.Message.parse(query_arena.allocator(), response_bytes);
    try std.testing.expect(!response.header.authenticated_data);
}

const AdUpstreamArgs = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    ok: bool = false,
};

fn serveAdUpstream(args: *AdUpstreamArgs) void {
    var request_buffer: [resolver.MAX_UPSTREAM_MESSAGE]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, TestTimeout) catch return;
    var valid = makeAResponse(incoming.data, false, false, false);
    // Claim the answer is authentic; the forwarder must not pass that on.
    // AD is 0x0020, which lives in the low flags octet.
    valid.bytes[3] |= 0x20;
    args.udp.send(args.io, &incoming.from, valid.bytes[0..valid.len]) catch return;
    args.ok = true;
}

test "UDP request pipeline ANY answers one synthesized HINFO at the operator TTL" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.minimal_any_ttl = 300;

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    const query = &[_]u8{
        0x42, 0xE3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd',  'n',  's',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',
        'p',  'a',  0x00, 0x00, 0xff, 0x00, 0x01,
    };
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.{ .value = 13 }));
    try std.testing.expectEqual(@as(u32, 300), response.answers.items[0].ttl);
    const hinfo = response.answers.items[0].rdata.HINFO;
    try std.testing.expectEqualStrings("RFC8482", hinfo.cpuText());
    try std.testing.expectEqualStrings("", hinfo.osText());
}
