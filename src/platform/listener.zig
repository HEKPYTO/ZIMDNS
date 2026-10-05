/// Contract: Serves bounded DNS UDP/TCP request streams through Runtime; UDP may use
/// its explicit forwarding policy after authoritative selection, while TCP stays authoritative-only.
/// Ownership: Runtime is borrowed; socket streams are consumed/closed by the listener; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write and bind failures propagate as I/O errors.
const std = @import("std");
const builtin = @import("builtin");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const response_mod = @import("../auth/response.zig");
const dns_tsig = @import("../dns/tsig.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_record = @import("../dns/record.zig");
const dns_name = @import("../dns/name.zig");
const dns_writer = @import("../dns/writer.zig");
const transfer_mod = @import("../zone/transfer.zig");
const tcp_deadline = @import("tcp_deadline.zig");

pub const UDP_CLASSIC_MESSAGE_SIZE: usize = response_mod.CLASSIC_UDP_MESSAGE_SIZE;
pub const UDP_REQUEST_BUFFER_SIZE: usize = response_mod.DEFAULT_EDNS_UDP_PAYLOAD_SIZE;
pub const UDP_RESPONSE_BUFFER_SIZE: usize = std.math.maxInt(u16);
pub const TCP_MAX_FRAME_SIZE: usize = std.math.maxInt(u16);
pub const TCP_MAX_FRAMES_PER_CONNECTION: usize = 16;
pub const TCP_MAX_CONNECTION_WORKERS: usize = 8;
pub const UDP_IDLE_TIMEOUT: std.Io.Timeout = .{ .duration = .{
    .raw = .fromSeconds(5),
    .clock = .awake,
} };
const TcpIoTimeout = tcp_deadline.Timeout;
pub const TCP_IO_TIMEOUT = TcpIoTimeout{ .seconds = 5 };
pub const TCP_DEADLINES_SUPPORTED = switch (builtin.os.tag) {
    .linux, .macos => true,
    else => false,
};

pub const Error = error{
    ResponseTooLarge,
    BadTcpFrame,
    UnsupportedPlatform,
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

/// Exact-reads one length-prefixed TCP frame from a socket with a per-frame
/// deadline: the 2-octet prefix and the payload both loop over partial reads
/// via `tcp_deadline.readExact`, so a slow peer cannot stall the connection
/// past the deadline. A prefix-only EOF maps to EndOfStream (clean close);
/// a mid-payload EOF maps to BadTcpFrame.
pub fn readTcpFrameExact(fd: std.posix.fd_t, io: std.Io, frame_buffer: []u8, frame_deadline: std.Io.Clock.Timestamp) ![]const u8 {
    var len_bytes: [2]u8 = undefined;
    try tcp_deadline.readExact(fd, io, &len_bytes, frame_deadline);
    const request_len = std.mem.readInt(u16, &len_bytes, .big);
    try validateTcpFrameLength(request_len);
    if (request_len > frame_buffer.len) return Error.BadTcpFrame;
    tcp_deadline.readExact(fd, io, frame_buffer[0..request_len], frame_deadline) catch |err| {
        if (err == error.EndOfStream or err == error.Truncated) return Error.BadTcpFrame;
        return err;
    };
    return frame_buffer[0..request_len];
}

fn serveUdpOnceWithTimeout(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, timeout: std.Io.Timeout) !void {
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, timeout);
    var response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    var classic_response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    const response_bytes = try runtime.answerFrom(incoming.data, &response_buffer, &incoming.from);
    const response_data = try runtime.truncateUdpResponse(incoming.data, response_bytes, &classic_response_buffer);
    try socket.send(io, &incoming.from, response_data);
}

pub fn serveUdpOnce(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime) !void {
    return serveUdpOnceWithTimeout(socket, io, runtime, UDP_IDLE_TIMEOUT);
}

fn serveUdpOnceWithMetricsTimeout(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, counters: *metrics.Counters, timeout: std.Io.Timeout) !void {
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, timeout);
    var response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    var classic_response_buffer: [UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    const response_bytes = try runtime.answerFromWithMetrics(incoming.data, &response_buffer, &incoming.from, counters);
    const response_data = try runtime.truncateUdpResponse(incoming.data, response_bytes, &classic_response_buffer);
    try socket.send(io, &incoming.from, response_data);
}

pub fn serveUdpOnceWithMetrics(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, counters: *metrics.Counters) !void {
    return serveUdpOnceWithMetricsTimeout(socket, io, runtime, counters, UDP_IDLE_TIMEOUT);
}

pub fn serveUdpCount(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, count: usize) !void {
    var served: usize = 0;
    while (served < count) : (served += 1) {
        try serveUdpOnce(socket, io, runtime);
    }
}

pub fn serveUdpCountWithMetrics(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, count: usize, counters: *metrics.Counters) !void {
    var served: usize = 0;
    while (served < count) : (served += 1) {
        try serveUdpOnceWithMetrics(socket, io, runtime, counters);
    }
}

pub fn serveUdpLoop(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, max_requests: ?usize) !void {
    return serveUdpLoopWithTimeout(socket, io, runtime, max_requests, UDP_IDLE_TIMEOUT);
}

fn serveUdpLoopWithTimeout(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, max_requests: ?usize, timeout: std.Io.Timeout) !void {
    var served: usize = 0;
    while (max_requests == null or served < max_requests.?) {
        serveUdpOnceWithTimeout(socket, io, runtime, timeout) catch |err| {
            if (isRecoverableRequestError(err)) continue;
            return err;
        };
        served += 1;
    }
}

pub fn serveUdpLoopWithMetrics(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, max_requests: ?usize, counters: *metrics.Counters) !void {
    return serveUdpLoopWithMetricsTimeout(socket, io, runtime, max_requests, counters, UDP_IDLE_TIMEOUT);
}

fn serveUdpLoopWithMetricsTimeout(socket: *const std.Io.net.Socket, io: std.Io, runtime: *Runtime, max_requests: ?usize, counters: *metrics.Counters, timeout: std.Io.Timeout) !void {
    var served: usize = 0;
    while (max_requests == null or served < max_requests.?) {
        serveUdpOnceWithMetricsTimeout(socket, io, runtime, counters, timeout) catch |err| {
            if (isRecoverableRequestError(err)) continue;
            return err;
        };
        served += 1;
    }
}

pub fn serveUdpOnceOnAddress(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress) !void {
    var bind_address = address.*;
    var socket = try std.Io.net.IpAddress.bind(&bind_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpOnce(&socket, io, runtime);
}

pub fn serveUdpLoopOnAddress(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress, max_requests: ?usize) !void {
    var bind_address = address.*;
    var socket = try std.Io.net.IpAddress.bind(&bind_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpLoop(&socket, io, runtime, max_requests);
}

pub fn serveUdpCountOnAddress(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress, count: usize) !void {
    var bind_address = address.*;
    var socket = try std.Io.net.IpAddress.bind(&bind_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpCount(&socket, io, runtime, count);
}

pub fn serveUdpCountOnAddressWithMetrics(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress, count: usize, counters: *metrics.Counters) !void {
    var bind_address = address.*;
    var socket = try std.Io.net.IpAddress.bind(&bind_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpCountWithMetrics(&socket, io, runtime, count, counters);
}

pub fn serveUdpLoopOnAddressWithMetrics(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress, max_requests: ?usize, counters: *metrics.Counters) !void {
    var bind_address = address.*;
    var socket = try std.Io.net.IpAddress.bind(&bind_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try serveUdpLoopWithMetrics(&socket, io, runtime, max_requests, counters);
}

pub fn serveTcpStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    return serveTcpStreamOnceWithTimeout(stream, io, runtime, TCP_IO_TIMEOUT, null);
}

pub fn serveTcpStreamOnceWithMetrics(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, counters: *metrics.Counters) !void {
    return serveTcpStreamOnceWithTimeout(stream, io, runtime, TCP_IO_TIMEOUT, counters);
}

fn serveTcpStreamOnceWithTimeout(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, timeout: TcpIoTimeout, counters: ?*metrics.Counters) !void {
    if (comptime !TCP_DEADLINES_SUPPORTED) return Error.UnsupportedPlatform;
    return unix_tcp_deadlines.serve(stream, io, runtime, timeout, counters);
}

pub fn serveTcpLoop(server: anytype, io: std.Io, runtime: *const Runtime, max_requests: ?usize) !void {
    return serveTcpLoopWithTimeout(server, io, runtime, max_requests, TCP_IO_TIMEOUT);
}

fn serveTcpStreamWorker(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, timeout: TcpIoTimeout) void {
    defer stream.close(io);
    serveTcpStreamOnceWithTimeout(stream, io, runtime, timeout, null) catch {};
}

fn serveTcpLoopWithTimeout(server: anytype, io: std.Io, runtime: *const Runtime, max_requests: ?usize, timeout: TcpIoTimeout) !void {
    var group: std.Io.Group = .init;
    defer group.await(io) catch unreachable;

    var accepted: usize = 0;
    while (max_requests == null or accepted < max_requests.?) {
        const stream = try server.accept(io);
        accepted += 1;
        group.concurrent(io, serveTcpStreamWorker, .{ stream, io, runtime, timeout }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => stream.close(io),
        };
    }
}

pub fn serveTcpLoopOnAddress(io: std.Io, runtime: *const Runtime, address: *const std.Io.net.IpAddress, max_requests: ?usize) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    try serveTcpLoop(&server, io, runtime, max_requests);
}

pub fn serveTcpOnceOnAddress(io: std.Io, runtime: *const Runtime, address: *const std.Io.net.IpAddress) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try serveTcpStreamOnce(stream, io, runtime);
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

test "UDP listener accepts a valid EDNS query above the classic limit" {
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

    var query_buffer: [response_mod.DEFAULT_EDNS_UDP_PAYLOAD_SIZE]u8 = undefined;
    const query = try buildLargeEdnsQuery(&query_buffer, 0x6e6e);
    try std.testing.expect(query.len > UDP_CLASSIC_MESSAGE_SIZE);
    try client_socket.send(io, &server_socket.address, query);
    try serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [UDP_CLASSIC_MESSAGE_SIZE]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, UDP_IDLE_TIMEOUT);
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), incoming.data);
    try std.testing.expectEqual(@as(u16, 0x6e6e), response.header.id);
    try std.testing.expect(response.edns != null);
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

test "UDP listener serves a count-bounded continuous loop" {
    const io = std.Io.Threaded.global_single_threaded.io();
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
    try serveUdpLoop(&server_socket, io, &runtime, 2);
}

test "UDP loop ignores malformed and idle datagrams before a valid query" {
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

    try client_socket.send(io, &server_socket.address, &.{ 0x12, 0x34 });
    try client_socket.send(io, &server_socket.address, simple_a_query);
    try serveUdpLoopWithTimeout(&server_socket, io, &runtime, 1, .{ .duration = .{
        .raw = .fromMilliseconds(1),
        .clock = .awake,
    } });

    var response_buffer: [512]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(500),
        .clock = .awake,
    } });
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), incoming.data);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
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

test "classic UDP signed response retains TSIG and verifies after truncation" {
    try expectSignedUdpTruncation(false);
}

test "EDNS UDP signed response drops OPT and retains TSIG after truncation" {
    try expectSignedUdpTruncation(true);
}

fn expectSignedUdpTruncation(include_edns: bool) !void {
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
    while (record_index < 100) : (record_index += 1) {
        try zone_text.writer.print("many IN A 192.0.2.{d}\n", .{record_index + 1});
    }

    var keyring = try @import("../auth/keyring.zig").Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(zone_text.written(), &keyring);
    defer runtime.deinit();
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    const query = try buildSignedListenerQueryWithEdns(now, include_edns);
    try client_socket.send(io, &server_socket.address, query.bytes[0..query.len]);
    try serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [UDP_CLASSIC_MESSAGE_SIZE]u8 = undefined;
    const incoming = try client_socket.receiveTimeout(io, &response_buffer, UDP_IDLE_TIMEOUT);
    const parsed = try @import("../dns/message.zig").Message.parse(arena.allocator(), incoming.data);
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), parsed.additionals.len);
    try std.testing.expect(parsed.edns == null);
    const request_final = (try dns_tsig.parseFinalAdditional(query.bytes[0..query.len])).?;
    const response_final = (try dns_tsig.parseFinalAdditional(incoming.data)).?;
    try std.testing.expectEqual(@as(u16, 0x1234), response_final.tsig.original_id);
    try std.testing.expectEqual(@as(usize, 32), response_final.tsig.macBytes().len);
    _ = try dns_tsig.verify(incoming.data, "01234567890123456789012345678901", request_final.tsig.macBytes(), 32);
}

test "TCP handler serves FIFO length-prefixed DNS queries on one stream" {
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

    var server_stream = try server.accept(io);
    var server_stream_closed = false;
    defer {
        if (!server_stream_closed) server_stream.close(io);
    }

    try serveTcpStreamOnce(server_stream, io, &runtime);

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

test "TCP loop rejects truncated frames before serving the next connection" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var truncated_header_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer truncated_header_client.close(io);
    var truncated_header_buffer: [8]u8 = undefined;
    var truncated_header_writer = truncated_header_client.writer(io, &truncated_header_buffer);
    try truncated_header_writer.interface.writeAll(&.{0});
    try truncated_header_writer.interface.flush();
    try truncated_header_client.shutdown(io, .send);

    var truncated_payload_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer truncated_payload_client.close(io);
    var truncated_payload_buffer: [8]u8 = undefined;
    var truncated_payload_writer = truncated_payload_client.writer(io, &truncated_payload_buffer);
    var length_prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &length_prefix, @intCast(simple_a_query.len), .big);
    try truncated_payload_writer.interface.writeAll(&length_prefix);
    try truncated_payload_writer.interface.writeAll(simple_a_query[0..1]);
    try truncated_payload_writer.interface.flush();
    try truncated_payload_client.shutdown(io, .send);

    var valid_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer valid_client.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6789, "dns.home.arpa.", .A);
    try @import("../cli/query.zig").sendTcpQuery(valid_client, io, query);
    try valid_client.shutdown(io, .send);

    try serveTcpLoopWithTimeout(&server, io, &runtime, 3, .{ .seconds = 0, .microseconds = 100_000 });

    var response_poll_fds = [_]std.posix.pollfd{.{
        .fd = valid_client.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&response_poll_fds, 100));
    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), valid_client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6789), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP loop does not count an empty EOF connection" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var empty_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer empty_client.close(io);
    try empty_client.shutdown(io, .send);

    var valid_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer valid_client.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6790, "dns.home.arpa.", .A);
    try @import("../cli/query.zig").sendTcpQuery(valid_client, io, query);
    try valid_client.shutdown(io, .send);

    try serveTcpLoopWithTimeout(&server, io, &runtime, 2, .{ .seconds = 0, .microseconds = 100_000 });

    var response_poll_fds = [_]std.posix.pollfd{.{
        .fd = valid_client.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&response_poll_fds, 100));
    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), valid_client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6790), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP loop rejects a length prefix without payload" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var prefix_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer prefix_client.close(io);
    var prefix_buffer: [8]u8 = undefined;
    var prefix_writer = prefix_client.writer(io, &prefix_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(simple_a_query.len), .big);
    try prefix_writer.interface.writeAll(&prefix);
    try prefix_writer.interface.flush();
    try prefix_client.shutdown(io, .send);

    var valid_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer valid_client.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6791, "dns.home.arpa.", .A);
    try @import("../cli/query.zig").sendTcpQuery(valid_client, io, query);
    try valid_client.shutdown(io, .send);

    const prefix_server_stream = try server.accept(io);
    defer prefix_server_stream.close(io);
    try std.testing.expectError(Error.BadTcpFrame, serveTcpStreamOnce(prefix_server_stream, io, &runtime));

    try serveTcpLoopWithTimeout(&server, io, &runtime, 1, .{ .seconds = 0, .microseconds = 100_000 });

    var response_poll_fds = [_]std.posix.pollfd{.{
        .fd = valid_client.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&response_poll_fds, 100));
    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), valid_client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6791), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP connection cap serves sixteen frames and closes before the seventeenth" {
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

    const total_frames = TCP_MAX_FRAMES_PER_CONNECTION + 1;
    var queries: [total_frames][simple_a_query.len]u8 = undefined;
    var client_write_buffer: [1024]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    for (&queries, 0..) |*query, index| {
        query.* = simple_a_query.*;
        const id: u16 = @intCast(0x6000 + index);
        std.mem.writeInt(u16, query[0..2], id, .big);
    }
    for (queries) |query| {
        std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
        try client_writer.interface.writeAll(&prefix);
        try client_writer.interface.writeAll(&query);
    }
    try client_writer.interface.flush();

    var server_stream = try server.accept(io);
    var server_stream_closed = false;
    defer {
        if (!server_stream_closed) server_stream.close(io);
    }
    try serveTcpStreamOnce(server_stream, io, &runtime);

    var response_read_buffer: [1024]u8 = undefined;
    var response_reader = client_stream.reader(io, &response_read_buffer);
    for (0..TCP_MAX_FRAMES_PER_CONNECTION) |index| {
        const response_len_bytes = try response_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try response_reader.interface.take(response_len);
        const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        try std.testing.expectEqual(@as(u16, @intCast(0x6000 + index)), response.header.id);
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    }

    server_stream.close(io);
    server_stream_closed = true;

    if (response_reader.interface.takeArray(2)) |_| {
        return error.UnexpectedSeventeenthResponse;
    } else |_| {}
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

test "TCP exact frame read loops over partial writes under a deadline" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var sockets: [2]std.posix.fd_t = undefined;
    const socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(sockets[0]);
    defer _ = std.posix.system.close(sockets[1]);

    const payload = "exact frame payload";
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, payload.len, .big);
    _ = std.posix.system.sendto(sockets[1], prefix[0..].ptr, prefix.len, std.posix.MSG.NOSIGNAL, null, 0);
    _ = std.posix.system.sendto(sockets[1], payload[0..7].ptr, 7, std.posix.MSG.NOSIGNAL, null, 0);
    _ = std.posix.system.sendto(sockets[1], payload[7..].ptr, payload.len - 7, std.posix.MSG.NOSIGNAL, null, 0);

    var frame_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    const frame = try readTcpFrameExact(sockets[0], io, &frame_buffer, tcp_deadline.deadline(io, TCP_IO_TIMEOUT));
    try std.testing.expectEqualSlices(u8, payload, frame);
}

test "TCP exact frame read rejects truncated payloads and reports clean EOF" {
    const io = std.Io.Threaded.global_single_threaded.io();

    var truncated: [2]std.posix.fd_t = undefined;
    var socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &truncated);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(truncated[0]);
    const truncated_prefix = [_]u8{ 0, 8 };
    _ = std.posix.system.sendto(truncated[1], truncated_prefix[0..].ptr, 2, std.posix.MSG.NOSIGNAL, null, 0);
    _ = std.posix.system.sendto(truncated[1], "x", 1, std.posix.MSG.NOSIGNAL, null, 0);
    _ = std.posix.system.close(truncated[1]);

    var frame_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    try std.testing.expectError(
        Error.BadTcpFrame,
        readTcpFrameExact(truncated[0], io, &frame_buffer, tcp_deadline.deadline(io, TCP_IO_TIMEOUT)),
    );

    var clean: [2]std.posix.fd_t = undefined;
    socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &clean);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(clean[0]);
    _ = std.posix.system.close(clean[1]);
    try std.testing.expectError(
        error.EndOfStream,
        readTcpFrameExact(clean[0], io, &frame_buffer, tcp_deadline.deadline(io, TCP_IO_TIMEOUT)),
    );
}

test "TCP framing rejects zero and over-limit lengths" {
    try std.testing.expectError(Error.BadTcpFrame, validateTcpFrameLength(0));
    try std.testing.expectError(Error.BadTcpFrame, validateTcpFrameLength(TCP_MAX_FRAME_SIZE + 1));

    var zero_reader = std.Io.Reader.fixed(&.{ 0, 0 });
    var frame_buffer: [1]u8 = undefined;
    try std.testing.expectError(Error.BadTcpFrame, readTcpFrame(&zero_reader, &frame_buffer));

    var oversized_reader = std.Io.Reader.fixed(&.{ 0, 2 });
    try std.testing.expectError(Error.BadTcpFrame, readTcpFrame(&oversized_reader, &frame_buffer));
}

test "TCP loop ignores malformed and idle connections before a valid query" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var idle_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer idle_client.close(io);
    var malformed_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer malformed_client.close(io);
    var malformed_writer_buffer: [8]u8 = undefined;
    var malformed_writer = malformed_client.writer(io, &malformed_writer_buffer);
    try malformed_writer.interface.writeAll(&.{ 0, 0 });
    try malformed_writer.interface.flush();
    var valid_client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer valid_client.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x3434, "dns.home.arpa.", .A);
    try @import("../cli/query.zig").sendTcpQuery(valid_client, io, query);
    try valid_client.shutdown(io, .send);

    try serveTcpLoopWithTimeout(&server, io, &runtime, 3, .{ .seconds = 0, .microseconds = 1_000 });

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), valid_client, io, &response_buffer, query);
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

fn buildLargeEdnsQuery(buffer: []u8, id: u16) ![]const u8 {
    const base = try @import("../cli/query.zig").buildQueryPacket(buffer, id, "dns.home.arpa.", .A);
    const option_data_len = 480;
    const opt_len = 11 + 4 + option_data_len;
    if (base.len + opt_len > buffer.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, buffer[10..12], 1, .big);

    var offset = base.len;
    buffer[offset] = 0;
    offset += 1;
    std.mem.writeInt(u16, buffer[offset..][0..2], 41, .big);
    offset += 2;
    std.mem.writeInt(u16, buffer[offset..][0..2], response_mod.DEFAULT_EDNS_UDP_PAYLOAD_SIZE, .big);
    offset += 2;
    std.mem.writeInt(u32, buffer[offset..][0..4], 0, .big);
    offset += 4;
    std.mem.writeInt(u16, buffer[offset..][0..2], 4 + option_data_len, .big);
    offset += 2;
    std.mem.writeInt(u16, buffer[offset..][0..2], 65000, .big);
    offset += 2;
    std.mem.writeInt(u16, buffer[offset..][0..2], option_data_len, .big);
    offset += 2;
    @memset(buffer[offset .. offset + option_data_len], 0);
    return buffer[0 .. offset + option_data_len];
}

const SignedListenerQuery = struct {
    bytes: [512]u8,
    len: usize,
};

fn buildSignedListenerQueryWithEdns(time_signed: u64, include_edns: bool) !SignedListenerQuery {
    const algorithm = try dns_name.Name.fromText("hmac-sha256.");
    const owner = try dns_name.Name.fromText("key.");
    const root = dns_name.Name.root();
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    });
    try writer.writeU16(if (include_edns) 2 else 1);
    try writer.writeBytes(&.{
        4,   'm', 'a', 'n',  'y',  4,    'h',  'o', 'm', 'e', 4, 'a', 'r',
        'p', 'a', 0,   0x00, 0x01, 0x00, 0x01,
    });
    if (include_edns) {
        try (dns_record.ResourceRecord{
            .owner = root,
            .rrtype = .OPT,
            .class = @import("../dns/types.zig").Class.fromCode(response_mod.DEFAULT_EDNS_UDP_PAYLOAD_SIZE),
            .ttl = 0,
            .rdata = .{ .OPT = .{} },
        }).encode(&writer);
    }

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
    return .{ .bytes = packet, .len = writer.len() };
}

const unix_tcp_deadlines = if (TCP_DEADLINES_SUPPORTED) struct {
    fn serve(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, timeout: TcpIoTimeout, counters: ?*metrics.Counters) !void {
        tcp_deadline.setSocketTimeout(stream.socket.handle, timeout);

        var request_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
        var response_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
        var frame_count: usize = 0;
        while (frame_count < TCP_MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
            const read_deadline = tcp_deadline.deadline(io, timeout);
            const request = readFrame(stream.socket.handle, io, &request_buffer, read_deadline) catch |err| {
                if (err == error.EndOfStream) {
                    if (frame_count == 0) return error.EndOfStream;
                    return;
                }
                if (err == error.Truncated) return Error.BadTcpFrame;
                return err;
            };
            if (transfer_mod.peekIsTransferRequest(request)) {
                try serveTransfer(request, stream, io, runtime, timeout, counters);
                continue;
            }
            const response_bytes = if (counters) |value|
                try runtime.answerWithMetrics(request, &response_buffer, value)
            else
                try runtime.answer(request, &response_buffer);
            if (response_bytes.len > TCP_MAX_FRAME_SIZE) return Error.ResponseTooLarge;

            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
            const write_deadline = tcp_deadline.deadline(io, timeout);
            try tcp_deadline.writeExact(stream.socket.handle, io, &prefix, write_deadline);
            try tcp_deadline.writeExact(stream.socket.handle, io, response_bytes, write_deadline);
        }
    }

    fn serveTransfer(
        request: []const u8,
        stream: std.Io.net.Stream,
        io: std.Io,
        runtime: *const Runtime,
        timeout: TcpIoTimeout,
        counters: ?*metrics.Counters,
    ) !void {
        if (counters) |value| value.queries_total += 1;
        const blob = try runtime.encodeTransferFrames(std.heap.page_allocator, request);
        defer std.heap.page_allocator.free(blob);
        const write_deadline = tcp_deadline.deadline(io, timeout);
        try tcp_deadline.writeExact(stream.socket.handle, io, blob, write_deadline);
        if (counters) |value| value.responses_total += 1;
    }

    fn readFrame(fd: std.posix.fd_t, io: std.Io, frame_buffer: []u8, frame_deadline: std.Io.Clock.Timestamp) ![]const u8 {
        return readTcpFrameExact(fd, io, frame_buffer, frame_deadline);
    }
} else struct {};

fn isRecoverableRequestError(err: anyerror) bool {
    return switch (err) {
        error.BadQuery,
        error.EncodeFailed,
        error.BadTcpFrame,
        error.ResponseTooLarge,
        error.Timeout,
        error.ReadFailed,
        error.WriteFailed,
        error.EndOfStream,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        error.WouldBlock,
        error.InputOutput,
        => true,
        else => false,
    };
}

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
