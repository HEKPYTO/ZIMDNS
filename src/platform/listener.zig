const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;

pub const Error = error{
    QueryTooLarge,
    ResponseTooLarge,
    BadTcpFrame,
};

pub fn serveUdpOnce(socket: *const std.Io.net.Socket, io: std.Io, runtime: *const Runtime) !void {
    var request_buffer: [512]u8 = undefined;
    const incoming = try socket.receive(io, &request_buffer);
    var response_buffer: [512]u8 = undefined;
    const response = try runtime.answer(incoming.data, &response_buffer);
    try socket.send(io, &incoming.from, response);
}

pub fn serveUdpOnceOnPort(io: std.Io, runtime: *const Runtime, port: u16) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var socket = try std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpOnce(&socket, io, runtime);
}

pub fn serveTcpStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const len_bytes = try reader.interface.takeArray(2);
    const request_len = std.mem.readInt(u16, len_bytes, .big);
    if (request_len == 0 or request_len > 512) return Error.BadTcpFrame;
    const request = try reader.interface.take(request_len);

    var response_buffer: [512]u8 = undefined;
    const response = try runtime.answer(request, &response_buffer);
    if (response.len > 0xffff) return Error.ResponseTooLarge;

    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(response.len), .big);
    try writer.interface.writeAll(&prefix);
    try writer.interface.writeAll(response);
    try writer.interface.flush();
}

pub fn serveTcpOnceOnPort(io: std.Io, runtime: *const Runtime, port: u16) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var server = try std.Io.net.IpAddress.listen(&addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try serveTcpStreamOnce(stream, io, runtime);
}

test "UDP listener serves one authoritative datagram over loopback sockets" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const runtime = try Runtime.fromZoneText(test_zone);
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    try client_socket.send(io, &server_socket.address, simple_a_query);
    try serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(500),
        .clock = .awake,
    } });
    const response = try @import("../dns/message.zig").Message.parse(incoming.data);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP handler serves one length-prefixed DNS query on a stream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const runtime = try Runtime.fromZoneText(test_zone);

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, simple_a_query.len, .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(simple_a_query);
    try client_writer.interface.flush();

    try serveTcpStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const response_len_bytes = try client_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, response_len_bytes, .big);
    const response_bytes = try client_reader.interface.take(response_len);
    const response = try @import("../dns/message.zig").Message.parse(response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

const simple_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
};
