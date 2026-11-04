/// Contract: Serves bounded DNS UDP/TCP request streams through Runtime; both transports
/// use the same dispatch, so a forwarding query is answered over either one.
/// Ownership: Runtime is borrowed; socket streams are consumed/closed by the listener; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write and bind failures propagate as I/O errors.
const std = @import("std");
const builtin = @import("builtin");
const auth_runtime = @import("../auth/runtime.zig");
const Runtime = auth_runtime.Runtime;
const metrics = @import("../metrics.zig");
const response_mod = @import("../auth/response.zig");
const config = @import("../config/parser.zig");
const resolver_mod = @import("../resolver.zig");
const dns_message = @import("../dns/message.zig");
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

/// The connection limits the operator configured. One process serves one
/// configuration, so the TCP policy lives here instead of in every listener.
var tcp_limits: config.TcpLimits = .{};

/// Points the TCP listener at the limits the operator configured.
pub fn setTcpLimits(limits: config.TcpLimits) void {
    tcp_limits = limits;
}

/// The limits the TCP listener enforces.
pub fn tcpLimits() config.TcpLimits {
    return tcp_limits;
}

/// RFC 9210 section 4.2: the timeout the server waits for a frame on an idle
/// connection. The operator may set it; without the directive the project's
/// own five seconds apply.
pub fn tcpIdleTimeout() TcpIoTimeout {
    const seconds = tcp_limits.idle_timeout orelse return TCP_IO_TIMEOUT;
    return .{ .seconds = seconds };
}

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
    // A SIGHUP asks for the zone to be re-read. The reload happens here,
    // outside the signal handler. The first check answers an idle server,
    // the second one answers a request that arrived while the flag was set,
    // so the answer that follows a reload always comes from the new zone.
    _ = runtime.reloadZoneIfRequested(io);
    _ = runtime.refreshCatalogIfRequested(io);
    _ = runtime.maybeRefreshSecondaries(@intCast(std.Io.Clock.awake.now(io).nanoseconds), Runtime.fetchSecondaryViaXfr, runtime) catch {};
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, timeout);
    // A NOTIFY handled by the last answer set the catalog flag; its fetch
    // waits for the next iteration, so this answer is already on the wire.
    _ = runtime.reloadZoneIfRequested(io);
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
    // The same reload the plain UDP path performs, so a metrics run reloads
    // its zone on the same trigger.
    _ = runtime.reloadZoneIfRequested(io);
    _ = runtime.refreshCatalogIfRequested(io);
    _ = runtime.maybeRefreshSecondaries(@intCast(std.Io.Clock.awake.now(io).nanoseconds), Runtime.fetchSecondaryViaXfr, runtime) catch {};
    var request_buffer: [UDP_REQUEST_BUFFER_SIZE]u8 = undefined;
    const incoming = try socket.receiveTimeout(io, &request_buffer, timeout);
    // A NOTIFY handled by the last answer set the catalog flag; its fetch
    // waits for the next iteration, so this answer is already on the wire.
    _ = runtime.reloadZoneIfRequested(io);
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

pub fn serveTcpStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime) !void {
    return serveTcpStreamOnceWithTimeout(stream, io, runtime, tcpIdleTimeout(), null);
}

pub fn serveTcpStreamOnceWithMetrics(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, counters: *metrics.Counters) !void {
    return serveTcpStreamOnceWithTimeout(stream, io, runtime, tcpIdleTimeout(), counters);
}

fn serveTcpStreamOnceWithTimeout(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, timeout: TcpIoTimeout, counters: ?*metrics.Counters) !void {
    if (comptime !TCP_DEADLINES_SUPPORTED) return Error.UnsupportedPlatform;
    // A SIGHUP asks for the zone to be re-read. The reload happens here,
    // outside the signal handler, so the answer that follows it comes from
    // the new zone.
    _ = runtime.reloadZoneIfRequested(io);
    _ = runtime.refreshCatalogIfRequested(io);
    _ = runtime.maybeRefreshSecondaries(@intCast(std.Io.Clock.awake.now(io).nanoseconds), Runtime.fetchSecondaryViaXfr, runtime) catch {};
    return unix_tcp_deadlines.serve(stream, io, runtime, timeout, counters);
}

pub fn serveTcpLoop(server: anytype, io: std.Io, runtime: *Runtime, max_requests: ?usize) !void {
    return serveTcpLoopWithTimeout(server, io, runtime, max_requests, tcpIdleTimeout());
}

fn serveTcpStreamWorker(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, timeout: TcpIoTimeout, sources: *SourceCounter) void {
    defer stream.close(io);
    defer sources.release(&stream.socket.address);
    serveTcpStreamOnceWithTimeout(stream, io, runtime, timeout, null) catch {};
}

fn serveTcpLoopWithTimeout(server: anytype, io: std.Io, runtime: *Runtime, max_requests: ?usize, timeout: TcpIoTimeout) !void {
    var group: std.Io.Group = .init;
    defer group.await(io) catch unreachable;

    var sources = SourceCounter{};
    var accepted: usize = 0;
    while (max_requests == null or accepted < max_requests.?) {
        const stream = try server.accept(io);
        accepted += 1;
        // RFC 9210 section 4.2: a source address holds only so many
        // connections at once, and a connection over the limit is closed at
        // once, the way a connection with no worker slot is closed.
        if (!sources.admit(&stream.socket.address)) {
            stream.close(io);
            continue;
        }
        group.concurrent(io, serveTcpStreamWorker, .{ stream, io, runtime, timeout, &sources }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                sources.release(&stream.socket.address);
                stream.close(io);
            },
        };
    }
}

/// The connections one source address holds, so the per-source limit of
/// RFC 9210 section 4.2 is enforced across the workers.
/// The per-source connection counter. RFC 9210 section 4.2: a source address
/// holds only so many connections at once. The cleartext and the encrypted
/// listeners share it, so the same bound applies to both.
pub const SourceCounter = struct {
    const max_sources = 64;

    const Key = struct {
        v6: bool = false,
        bytes: [16]u8 = @splat(0),

        fn eql(a: Key, b: Key) bool {
            return a.v6 == b.v6 and std.mem.eql(u8, &a.bytes, &b.bytes);
        }
    };

    const Entry = struct {
        key: Key = .{},
        count: u32 = 0,
    };

    mutex: std.Io.Mutex = .init,
    entries: [max_sources]Entry = @splat(.{}),
    len: usize = 0,

    /// Takes a slot for the source of a connection, or refuses the
    /// connection when the source already holds as many as the limit allows.
    pub fn admit(self: *SourceCounter, address: *const std.Io.net.IpAddress) bool {
        const limit = tcp_limits.max_connections_per_source orelse return true;
        const key = sourceKey(address);
        self.lock();
        defer self.unlock();
        for (self.entries[0..self.len]) |*entry| {
            if (!entry.key.eql(key)) continue;
            if (entry.count >= limit) return false;
            entry.count += 1;
            return true;
        }
        // A source that cannot be counted is refused rather than served
        // without a count.
        if (self.len >= self.entries.len) return false;
        self.entries[self.len] = .{ .key = key, .count = 1 };
        self.len += 1;
        return true;
    }

    /// Gives the slot back when the connection closes.
    pub fn release(self: *SourceCounter, address: *const std.Io.net.IpAddress) void {
        const key = sourceKey(address);
        self.lock();
        defer self.unlock();
        for (self.entries[0..self.len], 0..) |*entry, index| {
            if (!entry.key.eql(key)) continue;
            entry.count -= 1;
            if (entry.count == 0) {
                self.entries[index] = self.entries[self.len - 1];
                self.len -= 1;
            }
            return;
        }
    }

    fn lock(self: *SourceCounter) void {
        std.Io.Threaded.mutexLockUncancelable(&self.mutex);
    }

    fn unlock(self: *SourceCounter) void {
        std.Io.Threaded.mutexUnlock(&self.mutex);
    }
};

/// The address a connection comes from: its IP address without the port.
fn sourceKey(address: *const std.Io.net.IpAddress) SourceCounter.Key {
    var key = SourceCounter.Key{};
    switch (address.*) {
        .ip4 => |ip4| @memcpy(key.bytes[0..4], &ip4.bytes),
        .ip6 => |ip6| {
            key.v6 = true;
            @memcpy(&key.bytes, &ip6.bytes);
        },
    }
    return key;
}

/// The time one frame may take: the per-frame deadline, shortened to what is
/// left of the connection's lifetime. Null means the connection is over.
pub fn frameTimeout(io: std.Io, connection_deadline: ?std.Io.Clock.Timestamp, timeout: TcpIoTimeout) ?TcpIoTimeout {
    const deadline = connection_deadline orelse return timeout;
    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining <= 0) return null;
    const frame_nanoseconds = @as(i96, timeout.seconds) * std.time.ns_per_s + @as(i96, timeout.microseconds) * std.time.ns_per_us;
    const nanoseconds = @min(frame_nanoseconds, remaining);
    return .{
        .seconds = @intCast(@divTrunc(nanoseconds, std.time.ns_per_s)),
        .microseconds = @intCast(@divTrunc(@rem(nanoseconds, std.time.ns_per_s), std.time.ns_per_us)),
    };
}

pub fn serveTcpLoopOnAddress(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress, max_requests: ?usize) !void {
    var bind_address = address.*;
    var server = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer server.deinit(io);
    try serveTcpLoop(&server, io, runtime, max_requests);
}

pub fn serveTcpOnceOnAddress(io: std.Io, runtime: *Runtime, address: *const std.Io.net.IpAddress) !void {
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

    try std.testing.expectEqual(@as(u64, 1), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total.load(.monotonic));
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

test "EDNS UDP signed response keeps OPT and retains TSIG after truncation" {
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
    try std.testing.expectEqual(@as(usize, if (include_edns) 2 else 1), parsed.additionals.len);
    // RFC 6891 section 6.1.1: a request that carried an OPT record is
    // answered with one, and the truncated reply keeps it.
    try std.testing.expectEqual(include_edns, parsed.edns != null);
    const request_final = (try dns_tsig.parseFinalAdditional(query.bytes[0..query.len])).?;
    const response_final = (try dns_tsig.parseFinalAdditional(incoming.data)).?;
    try std.testing.expectEqual(@as(u16, 0x1234), response_final.tsig.original_id);
    try std.testing.expectEqual(@as(usize, 32), response_final.tsig.macBytes().len);
    _ = try dns_tsig.verify(incoming.data, "01234567890123456789012345678901", request_final.tsig.macBytes());
}

test "TCP handler serves two length-prefixed DNS queries on one stream" {
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
    // RFC 7766 section 7: each response is matched to its query by message
    // ID, because the two answers may leave in completion order.
    var seen_ids: [2]bool = @splat(false);
    var frames: usize = 0;
    while (frames < 2) : (frames += 1) {
        const response_len_bytes = try client_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try client_reader.interface.take(response_len);
        const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        try std.testing.expect(response.header.qr);
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
        const slot: usize = if (response.header.id == 0x1234) 0 else if (response.header.id == 0x5678) 1 else return error.UnexpectedResponseId;
        try std.testing.expect(!seen_ids[slot]);
        seen_ids[slot] = true;
    }

    server_stream.close(io);
    server_stream_closed = true;
}

test "RFC 7828: a TCP client is answered with the keepalive option" {
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

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(keepalive_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(keepalive_query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    var server_stream = try server.accept(io);
    defer server_stream.close(io);

    try serveTcpStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const response_len_bytes = try client_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, response_len_bytes, .big);
    const response_bytes = try client_reader.interface.take(response_len);
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    // RFC 7828 section 3.3.2: the answer carries the idle timeout the server
    // applies to the session, counted in units of 100 milliseconds.
    var keepalive: ?[]const u8 = null;
    for (response.additionals.items[0..response.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        keepalive = dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE);
        break;
    }
    try std.testing.expect(keepalive != null);
    try std.testing.expectEqualSlices(u8, &.{ 0, 50 }, keepalive.?);
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6789, "dns.home.arpa.", .A, false);
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6790, "dns.home.arpa.", .A, false);
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6791, "dns.home.arpa.", .A, false);
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
    // RFC 7766 section 7: responses leave in completion order, so each frame
    // is matched to its query by message ID, and a duplicate or a stranger
    // fails the test.
    var seen: [TCP_MAX_FRAMES_PER_CONNECTION]bool = @splat(false);
    for (0..TCP_MAX_FRAMES_PER_CONNECTION) |_| {
        const response_len_bytes = try response_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, response_len_bytes, .big);
        const response_bytes = try response_reader.interface.take(response_len);
        const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
        const id = response.header.id;
        try std.testing.expect(id >= 0x6000 and id < 0x6000 + TCP_MAX_FRAMES_PER_CONNECTION);
        const index = id - 0x6000;
        try std.testing.expect(!seen[index]);
        seen[index] = true;
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    }
    for (seen) |matched| try std.testing.expect(matched);

    server_stream.close(io);
    server_stream_closed = true;

    if (response_reader.interface.takeArray(2)) |_| {
        return error.UnexpectedSeventeenthResponse;
    } else |_| {}
}

/// Serves the TCP connections of one listener on a thread of its own, so a
/// test can watch the connections while the loop accepts them.
fn serveTcpLoopThread(server: *std.Io.net.Server, io: std.Io, runtime: *Runtime, max_requests: usize) void {
    serveTcpLoopWithTimeout(server, io, runtime, max_requests, tcpIdleTimeout()) catch {};
}

test "TCP loop refuses a connection from a source over the per-source limit" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const previous_limits = tcpLimits();
    defer setTcpLimits(previous_limits);
    // RFC 9210 section 4.2: one source address holds one connection.
    setTcpLimits(.{ .max_connections_per_source = 1 });

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    const server_thread = try std.Thread.spawn(.{}, serveTcpLoopThread, .{ &server, io, &runtime, 2 });
    defer server_thread.join();

    // The first connection holds the only slot of its source.
    var held = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer held.close(io);

    // The second connection of the same source is over the limit and is
    // closed without an answer.
    var refused = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer refused.close(io);
    tcp_deadline.setSocketTimeout(refused.socket.handle, .{ .seconds = 2 });

    var refused_buffer: [64]u8 = undefined;
    var refused_reader = refused.reader(io, &refused_buffer);
    try std.testing.expectError(error.EndOfStream, refused_reader.interface.takeArray(2));

    // A connection from another source address is not over the limit.
    var listen_addr6: std.Io.net.IpAddress = .{ .ip6 = .loopback(0) };
    var server6 = try std.Io.net.IpAddress.listen(&listen_addr6, io, .{ .reuse_address = true });
    defer server6.deinit(io);
    const server6_thread = try std.Thread.spawn(.{}, serveTcpLoopThread, .{ &server6, io, &runtime, 1 });
    defer server6_thread.join();

    var other = try std.Io.net.IpAddress.connect(&server6.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer other.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6801, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(other, io, query);
    try other.shutdown(io, .send);

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), other, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6801), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP connection is closed after the configured connection duration" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const previous_limits = tcpLimits();
    defer setTcpLimits(previous_limits);
    // RFC 9210 section 4.2: one connection lives for a second.
    setTcpLimits(.{ .max_connection_duration = 1 });

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    const started = std.Io.Clock.real.now(io).nanoseconds;
    var client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6802, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client, io, query);

    const server_thread = try std.Thread.spawn(.{}, serveTcpLoopThread, .{ &server, io, &runtime, 1 });
    defer server_thread.join();

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6802), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    // The answer arrived, and the connection behind it is closed when the
    // duration is over, not when the five-second frame deadline is.
    var client_buffer: [64]u8 = undefined;
    var client_reader = client.reader(io, &client_buffer);
    try std.testing.expectError(error.EndOfStream, client_reader.interface.takeArray(2));
    const elapsed = std.Io.Clock.real.now(io).nanoseconds - started;
    try std.testing.expect(elapsed < @as(i96, 4) * std.time.ns_per_s);
}

test "TCP connection is closed after the configured idle timeout" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const previous_limits = tcpLimits();
    defer setTcpLimits(previous_limits);
    // RFC 9210 section 4.2: an idle connection is closed after a second.
    setTcpLimits(.{ .idle_timeout = 1 });

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    const started = std.Io.Clock.real.now(io).nanoseconds;
    var client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x6803, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client, io, query);

    const server_thread = try std.Thread.spawn(.{}, serveTcpLoopThread, .{ &server, io, &runtime, 1 });
    defer server_thread.join();

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x6803), response.header.id);

    // The connection is idle after the answer, and the configured timeout
    // closes it: the project's own five seconds would close it later.
    var client_buffer: [64]u8 = undefined;
    var client_reader = client.reader(io, &client_buffer);
    try std.testing.expectError(error.EndOfStream, client_reader.interface.takeArray(2));
    const elapsed = std.Io.Clock.real.now(io).nanoseconds - started;
    try std.testing.expect(elapsed < @as(i96, 4) * std.time.ns_per_s);
}

test "TCP loop without a configured per-source limit serves two connections of one source" {
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

    var first = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer first.close(io);
    var second = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer second.close(io);

    var first_buffer: [512]u8 = undefined;
    const first_query = try @import("../cli/query.zig").buildQueryPacket(&first_buffer, 0x6803, "dns.home.arpa.", .A, false);
    var second_buffer: [512]u8 = undefined;
    const second_query = try @import("../cli/query.zig").buildQueryPacket(&second_buffer, 0x6804, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(first, io, first_query);
    try first.shutdown(io, .send);
    try @import("../cli/query.zig").sendTcpQuery(second, io, second_query);
    try second.shutdown(io, .send);

    try serveTcpLoop(&server, io, &runtime, 2);

    var response_buffer: [512]u8 = undefined;
    const first_response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), first, io, &response_buffer, first_query);
    try std.testing.expectEqual(@as(u16, 0x6803), first_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), first_response.header.answer_count);
    const second_response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), second, io, &response_buffer, second_query);
    try std.testing.expectEqual(@as(u16, 0x6804), second_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), second_response.header.answer_count);
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

    var frame = @as([TCP_MAX_FRAME_SIZE]u8, @splat(@as(u8, 0)));
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x3434, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(valid_client, io, query);
    try valid_client.shutdown(io, .send);

    try serveTcpLoopWithTimeout(&server, io, &runtime, 3, .{ .seconds = 0, .microseconds = 1_000 });

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), valid_client, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "a forwarding query over the inbound TCP path is answered with the upstream's answer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream = ForwardingUpstream{ .io = io, .udp = &upstream_socket };
    const upstream_thread = try std.Thread.spawn(.{}, serveForwardingUpstream, .{&upstream});

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "127.0.0.0/8"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x7101, "example.com.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    const server_stream = try server.accept(io);
    defer server_stream.close(io);
    // The accepted socket carries the peer's address, so the policy sees the
    // client and not the listener.
    try std.testing.expect(server_stream.socket.address.getPort() != server.socket.address.getPort());
    try serveTcpStreamOnce(server_stream, io, &runtime);
    upstream_thread.join();

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x7101), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 7766 section 7: a pipelined answer is not held behind a slow forwarded one" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(TCP_MAX_CONNECTION_WORKERS),
    });
    defer io_backend.deinit();
    const io = io_backend.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // A real loopback upstream that answers late, so the forwarded query is
    // still pending when the authoritative one is answered.
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream = ForwardingUpstream{ .io = io, .udp = &upstream_socket, .delay_ms = 400 };
    const upstream_thread = try std.Thread.spawn(.{}, serveForwardingUpstream, .{&upstream});

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "127.0.0.0/8"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var slow_query_buffer: [512]u8 = undefined;
    const slow_query = try @import("../cli/query.zig").buildQueryPacket(&slow_query_buffer, 0x7201, "example.com.", .A, false);
    var fast_query_buffer: [512]u8 = undefined;
    const fast_query = try @import("../cli/query.zig").buildQueryPacket(&fast_query_buffer, 0x7202, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, slow_query);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, fast_query);

    const server_stream = try server.accept(io);
    const ServerRunner = struct {
        stream: std.Io.net.Stream,
        io: std.Io,
        runtime: *Runtime,

        fn run(self: @This()) void {
            defer self.stream.close(self.io);
            serveTcpStreamOnce(self.stream, self.io, self.runtime) catch {};
        }
    };
    const server_thread = try std.Thread.spawn(.{}, ServerRunner.run, .{ServerRunner{
        .stream = server_stream,
        .io = io,
        .runtime = &runtime,
    }});

    // Each frame lands in its own buffer: the parser keeps slices of the
    // packet it was given.
    var first_frame: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    var second_frame: [TCP_MAX_FRAME_SIZE]u8 = undefined;
    const first_bytes = try readTcpFrameExact(client_stream.socket.handle, io, &first_frame, tcp_deadline.deadline(io, .{ .seconds = 2 }));
    const second_bytes = try readTcpFrameExact(client_stream.socket.handle, io, &second_frame, tcp_deadline.deadline(io, .{ .seconds = 2 }));
    const first = try dns_message.Message.parse(arena.allocator(), first_bytes);
    const second = try dns_message.Message.parse(arena.allocator(), second_bytes);

    try client_stream.shutdown(io, .send);
    server_thread.join();
    upstream_thread.join();

    // The authoritative answer was prepared while the forwarded one waited,
    // and it reaches the wire first.
    try std.testing.expectEqual(@as(u16, 0x7202), first.header.id);
    try std.testing.expectEqual(@as(u16, 0x7201), second.header.id);
    try std.testing.expectEqual(@as(u16, 1), first.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), second.header.answer_count);
}

test "the same forwarding query over UDP is answered the same way" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    var upstream = ForwardingUpstream{ .io = io, .udp = &upstream_socket };
    const upstream_thread = try std.Thread.spawn(.{}, serveForwardingUpstream, .{&upstream});

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "127.0.0.0/8"));

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x7102, "example.com.", .A, false);
    try client_socket.send(io, &server_socket.address, query);
    try serveUdpOnce(&server_socket, io, &runtime);
    upstream_thread.join();

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try std.testing.expectEqual(@as(u16, 0x7102), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
}

test "an authoritative query over the inbound TCP path is unchanged" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // A forwarder is configured but must never see the zone's own name.
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "127.0.0.0/8"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x7103, "dns.home.arpa.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    const server_stream = try server.accept(io);
    defer server_stream.close(io);
    try serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 0x7103), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &response.answers.items[0].rdata.A);
    try std.testing.expect(response.header.authoritative);
}

test "the recursion ACL refuses a TCP client the UDP path refuses" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "192.0.2.0/24"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x7104, "example.com.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    const server_stream = try server.accept(io);
    defer server_stream.close(io);
    try serveTcpStreamOnce(server_stream, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .refused), response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
}

test "a TCP query whose upstream truncates is retried over TCP upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);
    // The upstream answers the retry over TCP on the port the UDP answer
    // came from.
    var upstream_tcp_addr = upstream_socket.address;
    var upstream_tcp = try std.Io.net.IpAddress.listen(&upstream_tcp_addr, io, .{ .reuse_address = true });
    defer upstream_tcp.deinit(io);
    var upstream = TruncatingUpstream{ .io = io, .udp = &upstream_socket, .tcp = &upstream_tcp };
    const upstream_thread = try std.Thread.spawn(.{}, serveTruncatingUpstream, .{&upstream});

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, try forwarding_policy(upstream_socket.address, "127.0.0.0/8"));

    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x7105, "example.com.", .A, false);
    try @import("../cli/query.zig").sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    const server_stream = try server.accept(io);
    defer server_stream.close(io);
    try serveTcpStreamOnce(server_stream, io, &runtime);
    upstream_thread.join();

    var response_buffer: [512]u8 = undefined;
    const response = try @import("../cli/query.zig").receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[0].rdata.A);
    try std.testing.expect(!response.header.truncated);
    try std.testing.expectEqual(@as(usize, 1), upstream.tcp_requests);
}

/// A forwarding policy that points at the fake upstream and allows the
/// clients of the CIDR the test names.
fn forwarding_policy(upstream: std.Io.net.IpAddress, allowed: []const u8) !resolver_mod.Policy {
    var policy = resolver_mod.Policy{ .forwarder = .{ .address = upstream } };
    policy.recursion_allow[0] = try config.Cidr.parse(allowed);
    policy.recursion_allow_len = 1;
    return policy;
}

/// The fake upstream a forwarding test forwards to. It answers the question
/// it is asked with one A record.
const ForwardingUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    requests: usize = 0,
    /// How long the upstream waits before answering. A pipelining test makes
    /// one forwarded query slower than an authoritative one.
    delay_ms: u64 = 0,
};

const upstream_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromSeconds(2),
    .clock = .awake,
} };

fn serveForwardingUpstream(args: *ForwardingUpstream) void {
    var request_buffer: [512]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, upstream_timeout) catch return;
    args.requests += 1;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
    var response_buffer: [512]u8 = undefined;
    const bytes = buildForwardingAnswer(&response_buffer, query, false) catch return;
    if (args.delay_ms != 0) std.Io.sleep(args.io, .fromMilliseconds(@intCast(args.delay_ms)), .awake) catch {};
    args.udp.send(args.io, &incoming.from, bytes) catch return;
}

/// The fake upstream that truncates its UDP answer and answers the retry
/// over TCP.
const TruncatingUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    tcp: *std.Io.net.Server,
    tcp_requests: usize = 0,
};

fn serveTruncatingUpstream(args: *TruncatingUpstream) void {
    var request_buffer: [512]u8 = undefined;
    const incoming = args.udp.receiveTimeout(args.io, &request_buffer, upstream_timeout) catch return;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
    var response_buffer: [512]u8 = undefined;
    const truncated = buildForwardingAnswer(&response_buffer, query, true) catch return;
    args.udp.send(args.io, &incoming.from, truncated) catch return;

    const stream = args.tcp.accept(args.io) catch return;
    defer stream.close(args.io);
    args.tcp_requests += 1;
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(args.io, &read_buffer);
    const length_bytes = reader.interface.takeArray(2) catch return;
    const length = std.mem.readInt(u16, length_bytes, .big);
    if (length == 0 or length > 512) return;
    var tcp_query: [512]u8 = undefined;
    reader.interface.readSliceAll(tcp_query[0..length]) catch return;
    var tcp_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer tcp_arena.deinit();
    const tcp_message = dns_message.Message.parseQuery(tcp_arena.allocator(), tcp_query[0..length]) catch return;
    var tcp_response_buffer: [512]u8 = undefined;
    const bytes = buildForwardingAnswer(&tcp_response_buffer, tcp_message, false) catch return;
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(args.io, &write_buffer);
    var response_length: [2]u8 = undefined;
    std.mem.writeInt(u16, &response_length, @intCast(bytes.len), .big);
    writer.interface.writeAll(&response_length) catch return;
    writer.interface.writeAll(bytes) catch return;
    writer.interface.flush() catch return;
}

/// The answer the fake upstream sends for the question it was asked. A
/// truncated answer carries the TC bit, so the resolver retries over TCP.
fn buildForwardingAnswer(buffer: []u8, query: dns_message.Message, truncated: bool) ![]const u8 {
    const question = query.question orelse return error.NoQuestion;
    var message = dns_message.Message{
        .allocator = query.allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .truncated = truncated,
            .recursion_desired = true,
            .recursion_available = true,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = question,
    };
    defer message.deinit();
    message.answers = try dns_message.RecordSection.init(query.allocator, 0);
    message.authorities = try dns_message.RecordSection.init(query.allocator, 0);
    message.additionals = try dns_message.RecordSection.init(query.allocator, 0);
    try message.answers.append(.{
        .owner = question.name,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    });
    message.header.answer_count = 1;
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
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
    const base = try @import("../cli/query.zig").buildQueryPacket(buffer, id, "dns.home.arpa.", .A, false);
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

const TCP_MAX_INFLIGHT_PER_CONNECTION: usize = 4;

const unix_tcp_deadlines = if (TCP_DEADLINES_SUPPORTED) struct {
    /// One frame answered on its own task. The request bytes and the response
    /// buffer live in one allocation; the prefix and payload are written under
    /// the connection's write mutex, so frames never interleave.
    const ResponseTask = struct {
        io: std.Io,
        runtime: *Runtime,
        stream: std.Io.net.Stream,
        client: std.Io.net.IpAddress,
        counters: ?*metrics.Counters,
        write_mutex: *std.Io.Mutex,
        state: *ConnectionState,
        buffer: []u8,
        request_len: usize,
        connection_deadline: ?std.Io.Clock.Timestamp,
        timeout: TcpIoTimeout,
    };

    /// The first failure that ends the connection. The failing task shuts the
    /// socket down so the reader stops waiting for frames that can no longer
    /// be answered.
    const ConnectionState = struct {
        mutex: std.Io.Mutex = .init,
        failure: ?anyerror = null,

        fn fail(self: *ConnectionState, io: std.Io, err: anyerror, stream: std.Io.net.Stream) void {
            self.mutex.lockUncancelable(io);
            if (self.failure == null) self.failure = err;
            self.mutex.unlock(io);
            stream.shutdown(io, .both) catch {};
        }

        fn get(self: *ConnectionState, io: std.Io) ?anyerror {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            return self.failure;
        }
    };

    fn respondFrame(task: ResponseTask) void {
        defer std.heap.page_allocator.free(task.buffer);
        // This thread answers one frame and exits, so it frees the scratch
        // buffers it retained instead of leaving them to a dead thread.
        defer auth_runtime.releaseAnswerScratch();
        const request = task.buffer[0..task.request_len];
        const response_buffer = task.buffer[task.request_len..];
        const response_bytes = task.runtime.answerFromTcp(request, response_buffer, &task.client, task.counters) catch |err| {
            task.state.fail(task.io, err, task.stream);
            return;
        };
        writeResponse(task, response_bytes) catch |err| task.state.fail(task.io, err, task.stream);
    }

    fn writeResponse(task: ResponseTask, response_bytes: []const u8) !void {
        if (response_bytes.len > TCP_MAX_FRAME_SIZE) return Error.ResponseTooLarge;
        // The deadline is taken now: a forwarded answer can arrive long after
        // the frame was read.
        const frame_timeout = frameTimeout(task.io, task.connection_deadline, task.timeout) orelse return error.Timeout;
        const write_deadline = tcp_deadline.deadline(task.io, frame_timeout);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
        task.write_mutex.lockUncancelable(task.io);
        defer task.write_mutex.unlock(task.io);
        try tcp_deadline.writeExact(task.stream.socket.handle, task.io, &prefix, write_deadline);
        try tcp_deadline.writeExact(task.stream.socket.handle, task.io, response_bytes, write_deadline);
    }

    /// Answers one frame on the connection's own thread, for the two cases
    /// where a task cannot be used: no task slot and no allocation. The write
    /// still takes the mutex, because earlier frames may be in flight.
    fn serveFrameInline(
        request: []const u8,
        response_buffer: []u8,
        stream: std.Io.net.Stream,
        io: std.Io,
        runtime: *Runtime,
        counters: ?*metrics.Counters,
        write_mutex: *std.Io.Mutex,
        frame_timeout: TcpIoTimeout,
    ) !void {
        const response_bytes = try runtime.answerFromTcp(request, response_buffer, &stream.socket.address, counters);
        if (response_bytes.len > TCP_MAX_FRAME_SIZE) return Error.ResponseTooLarge;
        const write_deadline = tcp_deadline.deadline(io, frame_timeout);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
        write_mutex.lockUncancelable(io);
        defer write_mutex.unlock(io);
        try tcp_deadline.writeExact(stream.socket.handle, io, &prefix, write_deadline);
        try tcp_deadline.writeExact(stream.socket.handle, io, response_bytes, write_deadline);
    }

    /// The answers prepared ahead of the reader. A response runs on its own
    /// thread rather than the io's task pool: a connection worker blocks in a
    /// socket read while it waits for the next frame, and a queued task that
    /// needs the same pool would not run until that read ended.
    const ResponseThreads = struct {
        threads: [TCP_MAX_INFLIGHT_PER_CONNECTION]std.Thread = undefined,
        len: usize = 0,

        fn drain(self: *ResponseThreads, io: std.Io, state: *ConnectionState) ?anyerror {
            for (self.threads[0..self.len]) |thread| thread.join();
            self.len = 0;
            return state.get(io);
        }
    };

    fn serve(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, timeout: TcpIoTimeout, counters: ?*metrics.Counters) !void {
        tcp_deadline.setSocketTimeout(stream.socket.handle, timeout);
        // RFC 9210 section 4.2: the operator may bound the lifetime of one
        // connection, and that deadline covers the whole connection.
        const connection_deadline: ?std.Io.Clock.Timestamp = if (tcp_limits.max_connection_duration) |seconds|
            tcp_deadline.deadline(io, .{ .seconds = seconds })
        else
            null;

        var write_mutex: std.Io.Mutex = .init;
        var state = ConnectionState{};
        var threads = ResponseThreads{};
        // Every exit path joins the threads before the connection's buffers go
        // out of scope.
        defer _ = threads.drain(io, &state);

        var request_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
        var response_buffer: [TCP_MAX_FRAME_SIZE]u8 = undefined;
        var frame_count: usize = 0;
        while (frame_count < TCP_MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
            // A connection that has outlived its duration ends here, whatever
            // the per-frame deadline says.
            const frame_timeout = frameTimeout(io, connection_deadline, timeout) orelse break;
            const read_deadline = tcp_deadline.deadline(io, frame_timeout);
            const request = readFrame(stream.socket.handle, io, &request_buffer, read_deadline) catch |err| {
                if (err == error.EndOfStream) {
                    if (frame_count == 0) return error.EndOfStream;
                    break;
                }
                if (err == error.Truncated) return Error.BadTcpFrame;
                return err;
            };
            if (transfer_mod.peekIsTransferRequest(request)) {
                // A transfer is its own stream, so the answers prepared before
                // it reach the wire before its first frame.
                if (threads.drain(io, &state)) |failure| return failure;
                try serveTransfer(request, stream, io, runtime, frame_timeout, counters);
                continue;
            }
            if (threads.len == TCP_MAX_INFLIGHT_PER_CONNECTION) {
                if (threads.drain(io, &state)) |failure| return failure;
            }
            // RFC 7766 section 7: responses are prepared in parallel and sent
            // in completion order, so a pipelined client is not held behind a
            // slow one.
            const owned = std.heap.page_allocator.alloc(u8, request.len + TCP_MAX_FRAME_SIZE) catch {
                try serveFrameInline(request, &response_buffer, stream, io, runtime, counters, &write_mutex, frame_timeout);
                continue;
            };
            @memcpy(owned[0..request.len], request);
            threads.threads[threads.len] = std.Thread.spawn(.{}, respondFrame, .{ResponseTask{
                .io = io,
                .runtime = runtime,
                .stream = stream,
                .client = stream.socket.address,
                .counters = counters,
                .write_mutex = &write_mutex,
                .state = &state,
                .buffer = owned,
                .request_len = request.len,
                .connection_deadline = connection_deadline,
                .timeout = timeout,
            }}) catch {
                std.heap.page_allocator.free(owned);
                try serveFrameInline(request, &response_buffer, stream, io, runtime, counters, &write_mutex, frame_timeout);
                continue;
            };
            threads.len += 1;
        }
        if (threads.drain(io, &state)) |failure| return failure;
    }

    fn serveTransfer(
        request: []const u8,
        stream: std.Io.net.Stream,
        io: std.Io,
        runtime: *Runtime,
        timeout: TcpIoTimeout,
        counters: ?*metrics.Counters,
    ) !void {
        if (counters) |value| metrics.bump(&value.queries_total);
        const blob = try runtime.encodeTransferFrames(std.heap.page_allocator, request);
        defer std.heap.page_allocator.free(blob);
        const write_deadline = tcp_deadline.deadline(io, timeout);
        try tcp_deadline.writeExact(stream.socket.handle, io, blob, write_deadline);
        if (counters) |value| metrics.bump(&value.responses_total);
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

/// A query whose OPT record carries the empty edns-tcp-keepalive option of
/// RFC 7828 section 3.2.1.
const keepalive_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00,
};
