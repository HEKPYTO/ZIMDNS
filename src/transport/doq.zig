/// Contract: Serves RFC 9250 DNS-over-QUIC on a client-initiated bidirectional
/// stream per query. Message framing is the same two-octet length prefix as
/// DNS/TCP; one query per stream, a second query on one stream (RFC 9250
/// section 4.3) and a zero-length frame (section 4.1) are protocol errors
/// answered with DOQ_PROTOCOL_ERROR (0x2). The answer comes from the same
/// `Runtime.answerFrom` entry point the cleartext paths use, with the real
/// peer address, so recursion ACLs, cookies and ECS see the client. The QUIC
/// server runs on its own thread with its own event loop; this module owns
/// the frame parser, the per-stream state, and the peer-address mapping.
/// Ownership: Runtime is borrowed; stream parsers are allocated per stream and
/// freed when the stream ends; wire buffers are local.
/// Errors: protocol errors reset the stream with 0x2; bind and TLS failures
/// propagate as I/O errors.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const connection_mod = quic.connection;
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const listener = @import("../platform/listener.zig");
const tls_policy = @import("tls.zig");

/// The IANA ALPN protocol ID for DNS-over-QUIC (RFC 9250 section 4.2). The
/// handshake selects exactly this token, so the port never serves another
/// protocol and a client that offers no common token is refused.
pub const DOQ_ALPN = tls_policy.doq_alpn;
/// The IANA-registered DoQ port (UDP 853).
pub const DOQ_PORT = tls_policy.doq_port;
/// The application error code a protocol error closes a stream with
/// (RFC 9250 section 4.8, DOQ_PROTOCOL_ERROR).
pub const DOQ_PROTOCOL_ERROR: u64 = 0x2;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
/// One stream carries at most one frame: a length prefix and one message.
/// The cap is the TCP frame bound the other transports share, so no length
/// from the wire can ever demand more than this buffer.
pub const MAX_STREAM_BUFFER_SIZE: usize = 2 + listener.TCP_MAX_FRAME_SIZE;
/// Concurrent streams across every connection this port serves.
pub const MAX_STREAMS: usize = 64;

/// Counts what `onStreamData` knows about one stream.
const DoqHandler = struct {
    pub const protocol = event_loop.Protocol.quic;

    allocator: std.mem.Allocator,
    runtime: *Runtime,
    io: std.Io,
    counters: ?*metrics.Counters,
    max_requests: ?usize,
    completed: usize = 0,
    parsers: std.AutoHashMapUnmanaged(u64, *StreamParser) = .empty,
    /// The running server, so the handler can stop the loop once the quota
    /// is served. Set before the loop starts and cleared before it ends.
    server: ?*anyopaque = null,
    request_stop: ?*const fn (*anyopaque) void = null,

    fn parserFor(self: *DoqHandler, stream_id: u64) !*StreamParser {
        if (self.parsers.get(stream_id)) |parser| return parser;
        if (self.parsers.count() >= MAX_STREAMS) return error.TooManyStreams;
        const parser = try self.allocator.create(StreamParser);
        errdefer self.allocator.destroy(parser);
        parser.* = .{};
        try self.parsers.put(self.allocator, stream_id, parser);
        return parser;
    }

    fn dropParser(self: *DoqHandler, stream_id: u64) void {
        if (self.parsers.fetchRemove(stream_id)) |kv| self.allocator.destroy(kv.value);
    }

    pub fn onStreamData(self: *DoqHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        // RFC 9250 section 4.1: the query rides a client-initiated
        // bidirectional stream. A client-initiated stream ID has its two low
        // bits clear; anything else is refused as a protocol error.
        if (stream_id & 0x3 != 0) {
            session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        }
        const parser = self.parserFor(stream_id) catch {
            session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        };
        switch (parser.feed(data)) {
            .message => {
                self.answer(session, stream_id, parser);
                // Bytes past the first message in the same chunk are a
                // second query on this stream (RFC 9250 section 4.3).
                if (parser.extra) {
                    session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
                    self.dropParser(stream_id);
                    return;
                }
                self.maybeStop();
            },
            .incomplete => {},
            .protocol_error => {
                session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
                self.dropParser(stream_id);
                return;
            },
        }
        // The client FINs its half of the stream. A complete message was
        // already answered above; an incomplete one is a protocol error.
        if (fin) {
            if (parser.hasMessage()) {
                self.dropParser(stream_id);
            } else {
                session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
                self.dropParser(stream_id);
            }
        }
    }

    fn answer(self: *DoqHandler, session: *event_loop.Session, stream_id: u64, parser: *StreamParser) void {
        const query = parser.takeMessage();
        parser.markAnswered();
        // The managed trust anchors refresh on wall-clock seconds, the same
        // tick the other serve loops run; a DoQ-only server has no other loop
        // to carry it.
        self.runtime.maybeRefreshManagedAnchors(@intCast(std.Io.Clock.real.now(self.io).nanoseconds));
        _ = self.runtime.reloadZoneIfRequested(self.io);
        _ = self.runtime.refreshCatalogIfRequested(self.io);
        const client = peerAddress(session) orelse {
            session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        };
        var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
        const response = self.runtime.answerFrom(query, &response_buffer, &client) catch {
            session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        };
        if (response.len > listener.TCP_MAX_FRAME_SIZE) {
            session.resetQuicStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        }
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response.len), .big);
        session.writeStream(stream_id, &prefix) catch return;
        session.writeStream(stream_id, response) catch return;
        session.closeQuicStream(stream_id);
        if (self.counters) |counters| metrics.bump(&counters.doq_queries_total);
        self.completed += 1;
    }

    fn maybeStop(self: *DoqHandler) void {
        if (self.max_requests) |max| {
            if (self.completed >= max) {
                if (self.server) |srv| {
                    if (self.request_stop) |stop| stop(srv);
                }
            }
        }
    }
};

/// The peer address of a session as the runtime sees it. quic-zig exposes
/// the peer as a `sockaddr.storage` behind `conn.peerAddress()`; the mapping
/// below handles IPv4, IPv6, and v4-mapped IPv6 socket addresses.
pub fn peerAddress(session: *const event_loop.Session) ?std.Io.net.IpAddress {
    return ipAddressFromSockaddr(session.entry.conn.peerAddress());
}

/// Maps a socket address to the runtime's address type. Returns null for an
/// address family the runtime cannot name, which ends that stream as a
/// protocol error rather than answering with a made-up client.
pub fn ipAddressFromSockaddr(addr: *const std.posix.sockaddr.storage) ?std.Io.net.IpAddress {
    if (addr.family == std.posix.AF.INET) {
        const in4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
        return .{ .ip4 = .{ .bytes = @bitCast(in4.addr), .port = std.mem.bigToNative(u16, in4.port) } };
    }
    if (addr.family == std.posix.AF.INET6) {
        const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
        const bytes: [16]u8 = @bitCast(in6.addr);
        const port = std.mem.bigToNative(u16, in6.port);
        if (std.mem.eql(u8, bytes[0..12], &packetMappedPrefix())) {
            var v4: [4]u8 = undefined;
            @memcpy(&v4, bytes[12..16]);
            return .{ .ip4 = .{ .bytes = v4, .port = port } };
        }
        return .{ .ip6 = .{ .bytes = bytes, .port = port } };
    }
    return null;
}

fn packetMappedPrefix() [12]u8 {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
}

/// One stream's RFC 9250 framing state. `feed` chews arbitrary splits of the
/// 2 + message byte sequence; a completed message is held until `takeMessage`
/// hands it over, after which any further bytes are a second query.
pub const StreamParser = struct {
    prefix: [2]u8 = undefined,
    prefix_len: usize = 0,
    msg_len: ?u16 = null,
    payload: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined,
    payload_len: usize = 0,
    ready: ?[]const u8 = null,
    extra: bool = false,
    failed: bool = false,
    taken: bool = false,

    pub const Outcome = enum { incomplete, message, protocol_error };

    pub fn feed(self: *StreamParser, data: []const u8) Outcome {
        if (self.failed) return .protocol_error;
        if (self.answeredOrPending()) {
            if (data.len != 0) {
                self.failed = true;
                return .protocol_error;
            }
            return .incomplete;
        }
        var offset: usize = 0;
        if (self.msg_len == null) {
            while (self.prefix_len < 2 and offset < data.len) : (offset += 1) {
                self.prefix[self.prefix_len] = data[offset];
                self.prefix_len += 1;
            }
            if (self.prefix_len < 2) return .incomplete;
            const len = std.mem.readInt(u16, &self.prefix, .big);
            if (len == 0) {
                self.failed = true;
                return .protocol_error;
            }
            self.msg_len = len;
        }
        const len = self.msg_len.?;
        while (self.payload_len < len and offset < data.len) : (offset += 1) {
            self.payload[self.payload_len] = data[offset];
            self.payload_len += 1;
        }
        if (self.payload_len < len) return .incomplete;
        self.ready = self.payload[0..len];
        // Bytes past the one message in the same chunk are a second query.
        if (offset < data.len) self.extra = true;
        return .message;
    }

    fn answeredOrPending(self: *const StreamParser) bool {
        return self.ready != null or self.extra or self.taken;
    }

    /// True once a message was completed and taken, so the stream is spent.
    pub fn hasMessage(self: *const StreamParser) bool {
        return self.ready != null or self.taken;
    }

    /// True once the handler answered this stream's one message.
    pub fn answered(self: *const StreamParser) bool {
        return self.taken;
    }

    pub fn takeMessage(self: *StreamParser) []const u8 {
        const message = self.ready orelse &.{};
        self.ready = null;
        self.taken = true;
        return message;
    }

    pub fn markAnswered(self: *StreamParser) void {
        self.taken = true;
    }
};

/// Binds the DoQ port and serves DNS-over-QUIC. The handshake selects the
/// `doq` ALPN token (RFC 9250 section 4.2) before any DNS byte is written, so
/// the port never answers cleartext DNS. The server runs on its own thread
/// with its own event loop, joined before this function returns, so the
/// runtime outlives every use of it.
pub fn serveDoqLoopOnAddress(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    cert_path: []const u8,
    key_path: []const u8,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
) !void {
    const allocator = std.heap.page_allocator;
    var address_buf: [64]u8 = undefined;
    const address_text = try addressToString(address, &address_buf);
    var handler = DoqHandler{
        .allocator = allocator,
        .runtime = runtime,
        .io = io,
        .counters = counters,
        .max_requests = max_requests,
    };
    defer handler.parsers.deinit(allocator);
    var server = try event_loop.Server(DoqHandler).init(allocator, &handler, .{
        .address = address_text,
        .port = address.getPort(),
        .cert_path = cert_path,
        .key_path = key_path,
        .alpn = &.{DOQ_ALPN},
        .max_connections = MAX_CONNECTION_WORKERS,
    });
    defer server.deinit();
    handler.server = &server;
    handler.request_stop = requestStopServer;
    var thread = try std.Thread.spawn(.{}, runDoqServer, .{&server});
    // The loop runs on its own thread until the quota is served or the
    // process asks it to stop; joining here is what keeps the runtime alive
    // for every use of it, and the join returns only after the loop stopped.
    thread.join();
}

fn requestStopServer(server: *anyopaque) void {
    const typed: *event_loop.Server(DoqHandler) = @ptrCast(@alignCast(server));
    typed.requestStop();
}

fn runDoqServer(server: *event_loop.Server(DoqHandler)) void {
    // The loop cannot report an I/O failure through the serve signature once
    // it is on its own thread; name it on stderr instead of exiting silently.
    server.run() catch |err| std.debug.print("DoQ server stopped: {s}\n", .{@errorName(err)});
}

/// Renders the bind address for the QUIC config, which takes a host string
/// and a port separately. IPv4 prints dotted; IPv6 prints its compressed
/// form without the port.
pub fn addressToString(address: *const std.Io.net.IpAddress, buf: []u8) ![]const u8 {
    switch (address.*) {
        .ip4 => |ip4| return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3] }),
        .ip6 => |ip6| {
            const unresolved: std.Io.net.Ip6Address.Unresolved = .{ .bytes = ip6.bytes, .interface_name = null };
            return std.fmt.bufPrint(buf, "{f}", .{unresolved});
        },
    }
}

test "a framed message survives a split length prefix" {
    var parser: StreamParser = .{};
    // One byte of a two-octet prefix: nothing complete yet.
    try std.testing.expectEqual(StreamParser.Outcome.incomplete, parser.feed(&.{0x00}));
    // The second prefix octet plus the payload complete the frame.
    const message = [_]u8{ 0x00, 0x02, 0x01, 0x02 };
    try std.testing.expectEqual(StreamParser.Outcome.incomplete, parser.feed(message[1..3]));
    try std.testing.expectEqual(StreamParser.Outcome.message, parser.feed(message[3..]));
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, parser.takeMessage());
}

test "a zero-length frame is a protocol error" {
    var parser: StreamParser = .{};
    try std.testing.expectEqual(StreamParser.Outcome.protocol_error, parser.feed(&.{ 0x00, 0x00 }));
}

test "an oversized stream is rejected without growing the buffer" {
    var parser: StreamParser = .{};
    // A maximum-length frame completes and is held in the fixed buffer.
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, listener.TCP_MAX_FRAME_SIZE, .big);
    try std.testing.expectEqual(StreamParser.Outcome.incomplete, parser.feed(&prefix));
    var body: [listener.TCP_MAX_FRAME_SIZE]u8 = @splat(0xab);
    try std.testing.expectEqual(StreamParser.Outcome.message, parser.feed(&body));
    _ = parser.takeMessage();
    // Any byte past the one message is a second query, not more buffer.
    try std.testing.expectEqual(StreamParser.Outcome.protocol_error, parser.feed(&.{0x00}));
}

test "a second query on one stream is a protocol error" {
    var parser: StreamParser = .{};
    const first = [_]u8{ 0x00, 0x02, 0x01, 0x02 };
    try std.testing.expectEqual(StreamParser.Outcome.message, parser.feed(&first));
    _ = parser.takeMessage();
    parser.markAnswered();
    const second = [_]u8{ 0x00, 0x02, 0x03, 0x04 };
    try std.testing.expectEqual(StreamParser.Outcome.protocol_error, parser.feed(&second));
}

test "an empty final chunk after an answer ends quietly" {
    var parser: StreamParser = .{};
    const framed = [_]u8{ 0x00, 0x01, 0x07 };
    try std.testing.expectEqual(StreamParser.Outcome.message, parser.feed(&framed));
    _ = parser.takeMessage();
    parser.markAnswered();
    // The client's FIN arrives as an empty chunk; the spent parser ignores it.
    try std.testing.expectEqual(StreamParser.Outcome.incomplete, parser.feed(&.{}));
}

test "a peer address maps IPv4, IPv6, and v4-mapped forms" {
    const v4 = ipAddressFromSockaddr(&storageFor(&.{ 127, 0, 0, 1 }, 5347)).?;
    try std.testing.expectEqual(@as([4]u8, .{ 127, 0, 0, 1 }), v4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 5347), v4.ip4.port);

    const v6 = ipAddressFromSockaddr(&storageForText("2001:db8::1", 5353)).?;
    try std.testing.expectEqual(@as([4]u8, .{ 0x20, 0x01, 0x0d, 0xb8 }) ++ @as([12]u8, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }), v6.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 5353), v6.ip6.port);

    const mapped_result = ipAddressFromSockaddr(&storageForText("::ffff:192.0.2.80", 853)).?;
    try std.testing.expectEqual(@as([4]u8, .{ 192, 0, 2, 80 }), mapped_result.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 853), mapped_result.ip4.port);
}

fn storageFor(bytes: *const [4]u8, port: u16) std.posix.sockaddr.storage {
    const address = quic.sockaddr.Address.initIp4(bytes.*, port);
    return connection_mod.sockaddrToStorage(&address.any);
}

fn storageForText(text: []const u8, port: u16) std.posix.sockaddr.storage {
    const address = quic.sockaddr.Address.parseIp(text, port) catch return std.mem.zeroes(std.posix.sockaddr.storage);
    return connection_mod.sockaddrToStorage(&address.any);
}
