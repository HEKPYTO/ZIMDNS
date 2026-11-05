/// Contract: the server copies the question name into its answer, so a name
/// the client randomized keeps its case on the wire.
/// Ownership: one arena owns the parsed message of the exchange.
/// Errors: a failed exchange or a mismatched echo fails the test.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const Runtime = zimdns.auth_runtime.Runtime;
const dns_name = zimdns.dns_name;

const zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\www IN A 192.0.2.1
    \\
;

test "the server echoes the 0x20 question name bit for bit" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(zone_text);
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    // The 0x20 mechanism: the first letter of every label carries a random
    // case, the rest of the label keeps the case it was typed with.
    var random_source = std.Random.IoSource{ .io = io };
    const randomized = (try dns_name.Name.fromText("www.home.arpa.")).withRandomizedLabelFirstCase(random_source.interface());

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacketForName(&query_buffer, 0x2020, randomized, .A, .{});
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);

    // RFC 4343 section 4.1: the answer carries the question as it was sent,
    // case and all.
    try std.testing.expectEqualSlices(u8, randomized.asWire(), response.question.?.name.asWire());
}
