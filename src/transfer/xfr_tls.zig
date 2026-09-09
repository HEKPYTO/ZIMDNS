/// Contract: Serves RFC 9103 zone transfers over TLS (strict TLS use): AXFR
/// queries and RFC 1995 IXFR-fallback queries on a TLS channel receive the
/// axfr.zig message sequence, while ordinary queries share runtime.answer.
/// Plaintext channels answer ordinary queries but refuse transfers instead of
/// leaking zone contents. Multi-message TSIG chaining stays deferred per the
/// axfr.zig policy; authentication rides the TLS session.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write and bind failures
/// propagate as I/O errors.
const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const dns_writer = @import("../dns/writer.zig");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("../transport/tls.zig");
const axfr = @import("axfr.zig");

pub const XFR_TLS_PORT = tls_policy.dot_port;
pub const MAX_FRAMES_PER_CONNECTION = listener.TCP_MAX_FRAMES_PER_CONNECTION;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
const IO_TIMEOUT = listener.TCP_IO_TIMEOUT;

pub fn serveXfrStreamOnce(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    channel: tls_policy.Channel,
) !void {
    return serveXfrStream(stream, io, runtime, channel, null);
}

pub fn serveXfrStreamOnceWithMetrics(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    channel: tls_policy.Channel,
    counters: *metrics.Counters,
) !void {
    return serveXfrStream(stream, io, runtime, channel, counters);
}

fn serveXfrStream(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    channel: tls_policy.Channel,
    counters: ?*metrics.Counters,
) !void {
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
        var frame_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer frame_arena.deinit();
        if (axfr.buildTransferResponses(frame_arena.allocator(), request, runtime, channel)) |messages| {
            var answers: usize = 0;
            for (messages) |message| {
                answers += message.answers.len;
                var writer = dns_writer.Writer.init(&response_buffer);
                var mutable = message;
                mutable.encode(&writer) catch return listener.Error.ResponseTooLarge;
                try writeFrame(stream.socket.handle, io, writer.written());
            }
            // Single error messages (REFUSED) carry no answers and are not transfers.
            if (counters) |value| {
                value.queries_total += 1;
                value.responses_total += 1;
                if (answers > 0) value.xfr_transfers_total += 1;
            }
        } else |err| switch (err) {
            error.NotTransferQuery => {
                if (counters) |value| value.dot_queries_total += 1;
                const response_bytes = if (counters) |value|
                    try runtime.answerWithMetrics(request, &response_buffer, value)
                else
                    try runtime.answer(request, &response_buffer);
                if (response_bytes.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;
                try writeFrame(stream.socket.handle, io, response_bytes);
            },
            else => return err,
        }
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

fn writeFrame(fd: std.posix.fd_t, io: std.Io, payload: []const u8) !void {
    if (payload.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(payload.len), .big);
    const write_deadline = tcp_deadline.deadline(io, IO_TIMEOUT);
    try tcp_deadline.writeExact(fd, io, &prefix, write_deadline);
    try tcp_deadline.writeExact(fd, io, payload, write_deadline);
}

fn serveXfrStreamWorker(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, channel: tls_policy.Channel) void {
    defer stream.close(io);
    serveXfrStreamOnce(stream, io, runtime, channel) catch {};
}

pub fn serveXfrLoop(server: anytype, io: std.Io, runtime: *const Runtime, channel: tls_policy.Channel, max_requests: ?usize) !void {
    var group: std.Io.Group = .init;
    defer group.await(io) catch unreachable;

    var accepted: usize = 0;
    while (max_requests == null or accepted < max_requests.?) {
        const stream = try server.accept(io);
        accepted += 1;
        group.concurrent(io, serveXfrStreamWorker, .{ stream, io, runtime, channel }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => stream.close(io),
        };
    }
}

pub fn serveXfrLoopOnAddress(
    io: std.Io,
    runtime: *const Runtime,
    channel: tls_policy.Channel,
    address: *const std.Io.net.IpAddress,
    max_requests: ?usize,
) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    try serveXfrLoop(&server, io, runtime, channel, max_requests);
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

test "XFR-over-TLS serves a full AXFR sequence on a TLS channel" {
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

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(axfr_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(axfr_query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    var counters = metrics.Counters{};
    try serveXfrStreamOnceWithMetrics(server_stream, io, &runtime, .tls, &counters);
    try std.testing.expectEqual(@as(u64, 1), counters.xfr_transfers_total);

    var client_read_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const response_len_bytes = try client_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, response_len_bytes, .big);
    const response_bytes = try client_reader.interface.take(response_len);
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x1234), response.header.id);
    // SOA + NS + A ... + SOA.
    try std.testing.expectEqual(@as(u16, 4), response.header.answer_count);
    try std.testing.expect(response.answers.slice()[0].rrtype.eql(@import("../dns/types.zig").RecordType.SOA));
    try std.testing.expect(response.answers.slice()[3].rrtype.eql(@import("../dns/types.zig").RecordType.SOA));
}

test "XFR-over-TLS answers ordinary queries and refuses plaintext transfers" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    // Ordinary A query on a TLS channel: answered, not counted as transfer.
    {
        const streams = try streamPair();
        var client_stream = streams[0];
        defer client_stream.close(io);
        const server_stream = streams[1];
        defer server_stream.close(io);
        var client_write_buffer: [512]u8 = undefined;
        var client_writer = client_stream.writer(io, &client_write_buffer);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(simple_a_query.len), .big);
        try client_writer.interface.writeAll(&prefix);
        try client_writer.interface.writeAll(simple_a_query);
        try client_writer.interface.flush();
        try client_stream.shutdown(io, .send);

        var counters = metrics.Counters{};
        try serveXfrStreamOnceWithMetrics(server_stream, io, &runtime, .tls, &counters);
        try std.testing.expectEqual(@as(u64, 0), counters.xfr_transfers_total);
        try std.testing.expectEqual(@as(u64, 1), counters.responses_total);

        var client_read_buffer: [512]u8 = undefined;
        var client_reader = client_stream.reader(io, &client_read_buffer);
        const response_len_bytes = try client_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try client_reader.interface.take(response_len);
        const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    }

    // AXFR on a plaintext channel: single REFUSED, never a transfer.
    {
        const streams = try streamPair();
        var client_stream = streams[0];
        defer client_stream.close(io);
        const server_stream = streams[1];
        defer server_stream.close(io);
        var client_write_buffer: [512]u8 = undefined;
        var client_writer = client_stream.writer(io, &client_write_buffer);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(axfr_query.len), .big);
        try client_writer.interface.writeAll(&prefix);
        try client_writer.interface.writeAll(axfr_query);
        try client_writer.interface.flush();
        try client_stream.shutdown(io, .send);

        var counters = metrics.Counters{};
        try serveXfrStreamOnceWithMetrics(server_stream, io, &runtime, .plaintext, &counters);
        try std.testing.expectEqual(@as(u64, 0), counters.xfr_transfers_total);

        var client_read_buffer: [512]u8 = undefined;
        var client_reader = client_stream.reader(io, &client_read_buffer);
        const response_len_bytes = try client_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try client_reader.interface.take(response_len);
        const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, response.header.rcode);
        try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
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

const axfr_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
    0xfc, 0x00, 0x01,
};
