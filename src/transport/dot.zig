/// Contract: Serves RFC 7858 DNS-over-TLS framing on the post-handshake byte
/// channel. Wire framing is the same two-octet length-prefixed stream as DNS
/// over TCP, so frame bounds, FIFO order, and five-second deadlines are shared
/// with the plaintext TCP listener. TLS termination itself stays behind the
/// fail-closed gate in tls.zig until the reviewed TLS-server dependency lands;
/// these handlers never see handshake bytes.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write and bind failures
/// propagate as I/O errors.
const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("tls.zig");

pub const DOT_ALPN = tls_policy.dot_alpn;
pub const DOT_PORT = tls_policy.dot_port;
pub const MAX_FRAMES_PER_CONNECTION = listener.TCP_MAX_FRAMES_PER_CONNECTION;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
const IO_TIMEOUT = listener.TCP_IO_TIMEOUT;

pub fn serveDotStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    return serveDotStream(stream, io, runtime, null);
}

pub fn serveDotStreamOnceWithMetrics(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    counters: *metrics.Counters,
) !void {
    return serveDotStream(stream, io, runtime, counters);
}

/// RFC 7858 section 3.3 framing loop: two-octet length-prefixed DNS messages
/// with the same bounds as DNS over TCP. Runs on the post-handshake channel;
/// see tls.zig for the handshake gate.
fn serveDotStream(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, counters: ?*metrics.Counters) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    const posix_timeout: std.posix.timeval = .{
        .sec = @intCast(IO_TIMEOUT.seconds),
        .usec = @intCast(IO_TIMEOUT.microseconds),
    };
    const timeout_bytes = std.mem.asBytes(&posix_timeout);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, timeout_bytes);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, timeout_bytes);

    var request_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var frame_count: usize = 0;
    while (frame_count < MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
        const read_deadline = tcp_deadline.deadline(io, IO_TIMEOUT);
        const request = readFrame(stream.socket.handle, io, &request_buffer, read_deadline) catch |err| {
            if (err == error.EndOfStream) {
                if (frame_count == 0) return error.EndOfStream;
                return;
            }
            if (err == error.Truncated) return listener.Error.BadTcpFrame;
            return err;
        };
        if (counters) |value| value.dot_queries_total += 1;
        const response_bytes = if (counters) |value|
            try runtime.answerWithMetrics(request, &response_buffer, value)
        else
            try runtime.answer(request, &response_buffer);
        if (response_bytes.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
        const write_deadline = tcp_deadline.deadline(io, IO_TIMEOUT);
        try tcp_deadline.writeExact(stream.socket.handle, io, &prefix, write_deadline);
        try tcp_deadline.writeExact(stream.socket.handle, io, response_bytes, write_deadline);
    }
}

fn readFrame(fd: std.posix.fd_t, io: std.Io, frame_buffer: []u8, frame_deadline: std.Io.Clock.Timestamp) ![]const u8 {
    var len_bytes: [2]u8 = undefined;
    try tcp_deadline.readExact(fd, io, &len_bytes, frame_deadline);
    const request_len = std.mem.readInt(u16, &len_bytes, .big);
    try listener.validateTcpFrameLength(request_len);
    if (request_len > frame_buffer.len) return listener.Error.BadTcpFrame;
    tcp_deadline.readExact(fd, io, frame_buffer[0..request_len], frame_deadline) catch |err| {
        if (err == error.EndOfStream) return listener.Error.BadTcpFrame;
        return err;
    };
    return frame_buffer[0..request_len];
}

fn serveDotStreamWorker(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) void {
    defer stream.close(io);
    serveDotStreamOnce(stream, io, runtime) catch {};
}

pub fn serveDotLoop(server: anytype, io: std.Io, runtime: *const Runtime, max_requests: ?usize) !void {
    var group: std.Io.Group = .init;
    defer group.await(io) catch unreachable;

    var accepted: usize = 0;
    while (max_requests == null or accepted < max_requests.?) {
        const stream = try server.accept(io);
        accepted += 1;
        group.concurrent(io, serveDotStreamWorker, .{ stream, io, runtime }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => stream.close(io),
        };
    }
}

pub fn serveDotLoopOnAddress(io: std.Io, runtime: *const Runtime, address: *const std.Io.net.IpAddress, max_requests: ?usize) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    try serveDotLoop(&server, io, runtime, max_requests);
}

pub fn serveDotOnceOnAddress(io: std.Io, runtime: *const Runtime, address: *const std.Io.net.IpAddress) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try serveDotStreamOnce(stream, io, runtime);
}

fn streamPair() ![2]std.Io.net.Stream {
    var pair: [2]std.posix.fd_t = undefined;
    const result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    return .{
        .{ .socket = .{ .handle = pair[0], .address = address } },
        .{ .socket = .{ .handle = pair[1], .address = address } },
    };
}

test "DoT channel serves FIFO length-prefixed queries on one stream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    var server_stream = streams[1];
    var server_stream_closed = false;
    defer {
        if (!server_stream_closed) server_stream.close(io);
    }

    var first_query = simple_a_query.*;
    var second_query = simple_a_query.*;
    std.mem.writeInt(u16, first_query[0..2], 0x1234, .big);
    std.mem.writeInt(u16, second_query[0..2], 0x5678, .big);

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(first_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&first_query);
    std.mem.writeInt(u16, &prefix, @intCast(second_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&second_query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try serveDotStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const first_response_len_bytes = try client_reader.interface.takeArray(2);
    const first_response_len = std.mem.readInt(u16, first_response_len_bytes, .big);
    const first_response_bytes = try client_reader.interface.take(first_response_len);
    const first_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), first_response_bytes);
    try std.testing.expect(first_response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x1234), first_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), first_response.header.answer_count);

    const second_response_len_bytes = try client_reader.interface.takeArray(2);
    const second_response_len = std.mem.readInt(u16, second_response_len_bytes, .big);
    const second_response_bytes = try client_reader.interface.take(second_response_len);
    const second_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), second_response_bytes);
    try std.testing.expect(second_response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x5678), second_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), second_response.header.answer_count);

    server_stream.close(io);
    server_stream_closed = true;
}

test "DoT channel rejects a zero length prefix" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [8]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(&.{ 0, 0 });
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try std.testing.expectError(listener.Error.BadTcpFrame, serveDotStreamOnce(server_stream, io, &runtime));
}

test "DoT channel records metrics for served queries" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x9a9a, .big);
    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    var counters = metrics.Counters{};
    // One query then EOF ends the stream; EOF after a served frame is not an error.
    serveDotStreamOnceWithMetrics(server_stream, io, &runtime, &counters) catch |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    };
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 1), counters.dot_queries_total);
}

test "DoT defaults name the RFC 7858 port and ALPN token" {
    try std.testing.expectEqual(@as(u16, 853), DOT_PORT);
    try std.testing.expectEqualStrings("dot", DOT_ALPN);
    try std.testing.expectEqual(listener.TCP_MAX_FRAMES_PER_CONNECTION, MAX_FRAMES_PER_CONNECTION);
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
