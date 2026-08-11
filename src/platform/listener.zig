/// Contract: Serves bounded DNS UDP/TCP request streams through an authoritative Runtime.
/// Ownership: Runtime is borrowed; socket streams are consumed/closed by the listener; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write and bind failures propagate as I/O errors.
const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const response_mod = @import("../auth/response.zig");

pub const UDP_CLASSIC_MESSAGE_SIZE: usize = response_mod.CLASSIC_UDP_MESSAGE_SIZE;
pub const UDP_REQUEST_BUFFER_SIZE: usize = UDP_CLASSIC_MESSAGE_SIZE;
pub const UDP_RESPONSE_BUFFER_SIZE: usize = std.math.maxInt(u16);
pub const TCP_MAX_FRAME_SIZE: usize = std.math.maxInt(u16);
// ceiling: two sequential frames per connection; raise only with stream deadlines and a reuse contract.
pub const TCP_MAX_MESSAGES_PER_CONNECTION: usize = 2;
// ceiling: UDP has a standard-library deadline; Zig 0.16 Stream has no read/write timeout seam.
pub const UDP_IDLE_TIMEOUT: std.Io.Timeout = .{ .duration = .{
    .raw = .fromSeconds(5),
    .clock = .awake,
} };

pub const Error = error{
    QueryTooLarge,
    ResponseTooLarge,
    BadTcpFrame,
    InvalidTcpMessageCount,
};

pub fn validateTcpFrameLength(length: usize) Error!void {
    if (length == 0 or length > TCP_MAX_FRAME_SIZE) return Error.BadTcpFrame;
}

pub fn readTcpFrame(reader: *std.Io.Reader, frame_buffer: []u8) ![]const u8 {
    const len_bytes = try reader.takeArray(2);
    const request_len = std.mem.readInt(u16, len_bytes, .big);
    try validateTcpFrameLength(request_len);
    if (request_len > frame_buffer.len) return Error.BadTcpFrame;
    try reader.readSliceAll(frame_buffer[0..request_len]);
    return frame_buffer[0..request_len];
}

pub fn serveUdpOnce(socket: *const std.Io.net.Socket, io: std.Io, runtime: *const Runtime) !void {
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, UDP_IDLE_TIMEOUT);
    var response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    var classic_response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    const response_bytes = try runtime.answer(incoming.data, &response_buffer);
    const response_data = try response_mod.truncateClassicUdpResponse(response_bytes, &classic_response_buffer);
    try socket.send(io, &incoming.from, response_data);
}

pub fn serveUdpOnceWithMetrics(socket: *const std.Io.net.Socket, io: std.Io, runtime: *const Runtime, counters: *metrics.Counters) !void {
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, UDP_IDLE_TIMEOUT);
    var response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    var classic_response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    const response_bytes = try runtime.answerWithMetrics(incoming.data, &response_buffer, counters);
    const response_data = try response_mod.truncateClassicUdpResponse(response_bytes, &classic_response_buffer);
    try socket.send(io, &incoming.from, response_data);
}

pub fn serveUdpCount(socket: *const std.Io.net.Socket, io: std.Io, runtime: *const Runtime, count: usize) !void {
    var served: usize = 0;
    while (served < count) : (served += 1) {
        try serveUdpOnce(socket, io, runtime);
    }
}

pub fn serveUdpCountWithMetrics(socket: *const std.Io.net.Socket, io: std.Io, runtime: *const Runtime, count: usize, counters: *metrics.Counters) !void {
    var served: usize = 0;
    while (served < count) : (served += 1) {
        try serveUdpOnceWithMetrics(socket, io, runtime, counters);
    }
}

pub fn serveUdpOnceOnPort(io: std.Io, runtime: *const Runtime, port: u16) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var socket = try std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpOnce(&socket, io, runtime);
}

pub fn serveUdpCountOnPort(io: std.Io, runtime: *const Runtime, port: u16, count: usize) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var socket = try std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpCount(&socket, io, runtime, count);
}

pub fn serveUdpCountOnPortWithMetrics(io: std.Io, runtime: *const Runtime, port: u16, count: usize, counters: *metrics.Counters) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var socket = try std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpCountWithMetrics(&socket, io, runtime, count, counters);
}

pub fn serveTcpStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    return serveTcpStreamCount(stream, io, runtime, 1);
}

pub fn serveTcpStreamOnceWithMetrics(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, counters: *metrics.Counters) !void {
    return serveTcpStreamCountWithMetrics(stream, io, runtime, 1, counters);
}

pub fn serveTcpStreamCount(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, message_count: usize) !void {
    return serveTcpStreamCountWithMetrics(stream, io, runtime, message_count, null);
}

fn serveTcpStreamCountWithMetrics(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, message_count: usize, counters: ?*metrics.Counters) !void {
    if (message_count == 0 or message_count > TCP_MAX_MESSAGES_PER_CONNECTION) {
        return Error.InvalidTcpMessageCount;
    }

    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var request_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;

    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    var served: usize = 0;
    while (served < message_count) : (served += 1) {
        const request = try readTcpFrame(&reader.interface, &request_buffer);
        const response_bytes = if (counters) |value|
            try runtime.answerWithMetrics(request, &response_buffer, value)
        else
            try runtime.answer(request, &response_buffer);
        if (response_bytes.len > TCP_MAX_FRAME_SIZE) return Error.ResponseTooLarge;

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
        try writer.interface.writeAll(&prefix);
        try writer.interface.writeAll(response_bytes);
        try writer.interface.flush();
    }
}

pub fn serveTcpOnceOnPort(io: std.Io, runtime: *const Runtime, port: u16) !void {
    return serveTcpCountOnPort(io, runtime, port, 1);
}

pub fn serveTcpCountOnPort(io: std.Io, runtime: *const Runtime, port: u16, message_count: usize) !void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var server = try std.Io.net.IpAddress.listen(&addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try serveTcpStreamCount(stream, io, runtime, message_count);
}

test "UDP listener serves one authoritative datagram over loopback sockets" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
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
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), incoming.data);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "UDP listener serves a bounded batch of authoritative datagrams" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    try client_socket.send(io, &server_socket.address, simple_a_query);
    try client_socket.send(io, &server_socket.address, simple_a_query);
    try serveUdpCount(&server_socket, io, &runtime, 2);

    var response_buffer: [512]u8 = undefined;
    const first = try client_socket.receiveTimeout(io, &response_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(500),
        .clock = .awake,
    } });
    const first_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), first.data);
    try std.testing.expectEqual(@as(u16, 1), first_response.header.answer_count);

    const second = try client_socket.receiveTimeout(io, &response_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(500),
        .clock = .awake,
    } });
    const second_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), second.data);
    try std.testing.expectEqual(@as(u16, 1), second_response.header.answer_count);
}

test "UDP listener records metrics for a bounded datagram batch" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var counters = metrics.Counters{};
    try client_socket.send(io, &server_socket.address, simple_a_query);
    try serveUdpCountWithMetrics(&server_socket, io, &runtime, 1, &counters);

    try std.testing.expectEqual(@as(u64, 1), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total);
}

test "classic UDP response over 512 bytes sets TC instead of clipping" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.writeAll(
        "$ORIGIN home.arpa.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns1.home.arpa.\n",
    );
    var record_index: usize = 0;
    while (record_index < 40) : (record_index += 1) {
        try zone_text.writer.print("many IN A 192.0.2.{d}\n", .{record_index + 1});
    }

    var runtime = try Runtime.fromZoneText(zone_text.written());
    defer runtime.deinit();
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    try client_socket.send(io, &server_socket.address, large_a_query);
    try serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [UDP_CLASSIC_MESSAGE_SIZE]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, UDP_IDLE_TIMEOUT);
    try std.testing.expect(incoming.data.len <= UDP_CLASSIC_MESSAGE_SIZE);
    const parsed = try @import("../dns/message.zig").Message.parse(arena.allocator(), incoming.data);
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expect(parsed.edns == null);
}

test "TCP handler serves one length-prefixed DNS query on a stream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

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
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP framing accepts the largest u16 length-prefixed frame" {
    const io = std.Io.Threaded.global_single_threaded.io();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var frame = [_]u8{0} ** TCP_MAX_FRAME_SIZE;
    var client_write_buffer: [1024]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(frame.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&frame);
    try client_writer.interface.flush();

    var read_buffer: [1024]u8 = undefined;
    var reader = server_stream.reader(io, &read_buffer);
    var received: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    const payload = try readTcpFrame(&reader.interface, &received);
    try std.testing.expectEqual(TCP_MAX_FRAME_SIZE, payload.len);
}

test "TCP framing rejects zero and over-limit lengths" {
    try std.testing.expectError(Error.BadTcpFrame, validateTcpFrameLength(0));
    try std.testing.expectError(Error.BadTcpFrame, validateTcpFrameLength(TCP_MAX_FRAME_SIZE + 1));
}

test "TCP handler serves two sequential requests on one connection" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

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
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        std.mem.writeInt(u16, &prefix, simple_a_query.len, .big);
        try client_writer.interface.writeAll(&prefix);
        try client_writer.interface.writeAll(simple_a_query);
    }
    try client_writer.interface.flush();

    try serveTcpStreamCount(server_stream, io, &runtime, 2);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    index = 0;
    while (index < 2) : (index += 1) {
        const response_len_bytes = try client_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try client_reader.interface.take(response_len);
        const parsed = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        try std.testing.expect(parsed.header.qr);
        try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    }
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

const large_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    4,    'm',  'a',  'n',  'y',  4,    'h',  'o',  'm',  'e',  4,    'a',
    'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
};
