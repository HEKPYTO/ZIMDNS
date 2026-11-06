/// Contract: Serves RFC 9250 DNS-over-QUIC on a client-initiated bidirectional
/// stream per query on ngtcp2 + GnuTLS. Message
/// framing is the same two-octet length prefix as DNS/TCP; one query per
/// stream, a second query on one stream (RFC 9250 section 4.3) and a
/// zero-length frame (section 4.1) are protocol errors answered with
/// DOQ_PROTOCOL_ERROR (0x2). The answer comes from the same
/// `Runtime.answerFrom` entry point the cleartext paths use, with the real
/// peer address, so recursion ACLs, cookies and ECS see the client.
/// Ownership: Runtime is borrowed; stream parsers are allocated per stream
/// and freed when the stream ends; wire buffers are local.
/// Errors: protocol errors queue a 0x2 stream reset; bind and TLS failures
/// propagate as I/O errors.
const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;
const abi = @import("ngtcp2_abi.zig");
const metrics = @import("../metrics.zig");
const listener = @import("../platform/listener.zig");
const tls_policy = @import("tls.zig");
const StreamRegistry = @import("stream_registry.zig");
const core = @import("ngtcp2_server.zig");
const gnutls = @import("gnutls_server.zig");
/// The IANA ALPN protocol ID for DNS-over-QUIC (RFC 9250 section 4.2). The
/// handshake selects exactly this token, so the port never serves another
/// protocol and a client that offers no common token is refused.
pub const DOQ_ALPN = tls_policy.doq_alpn;
/// The IANA-registered DoQ port (UDP 853).
pub const DOQ_PORT = tls_policy.doq_port;
/// The application error code a protocol error shuts down a stream with
/// (RFC 9250 section 4.8, DOQ_PROTOCOL_ERROR).
pub const DOQ_PROTOCOL_ERROR: u64 = 0x2;
/// Concurrent streams across every connection this port serves.
pub const MAX_STREAMS: usize = core.Server.MAX_STREAMS_PER_CONN;

/// What the ngtcp2 core hands the DoQ layer for one stream chunk.
const DoqHandler = struct {
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    io: std.Io,
    counters: ?*metrics.Counters,
    max_requests: ?usize,
    completed: usize = 0,
    parsers: StreamRegistry.Registry(StreamParser) = .{ .max_entries = MAX_STREAMS },

    fn destroyParser(allocator: std.mem.Allocator, parser: *StreamParser) void {
        allocator.destroy(parser);
    }

    fn keyFor(conn: *const core.Connection, stream_id: i64) StreamRegistry.Key {
        return .{ .connection = @intFromPtr(conn), .stream = @bitCast(stream_id) };
    }

    /// Ownership: on success the registry owns `parser`; on error the
    /// caller keeps it (single `errdefer` destroy, no destroy in the
    /// catch, so the error path destroys exactly once).
    fn parserFor(self: *DoqHandler, conn: *core.Connection, stream_id: i64) !*StreamParser {
        const key = keyFor(conn, stream_id);
        if (self.parsers.get(key)) |parser| return parser;
        const parser = try self.allocator.create(StreamParser);
        errdefer self.allocator.destroy(parser);
        parser.* = .{};
        try self.parsers.insert(self.allocator, key, parser);
        return parser;
    }

    fn dropParser(self: *DoqHandler, conn: *core.Connection, stream_id: i64) bool {
        const had = self.parsers.get(keyFor(conn, stream_id)) != null;
        self.parsers.removeOne(self.allocator, keyFor(conn, stream_id), destroyParser);
        return had;
    }

    fn onHandshake(ctx: *anyopaque, conn: *core.Connection) void {
        const self: *DoqHandler = @ptrCast(@alignCast(ctx));
        _ = self;
        // Same gate as DoH/3: the core refreshes the mirror from
        // GnuTLS at handshake completion. A mismatch means the client
        // offered no common token, so doom the connection.
        const got = conn.session.alpn[0..conn.session.alpn_len];
        if (!std.mem.eql(u8, got, DOQ_ALPN)) conn.doomed = true;
    }

    fn onClose(ctx: *anyopaque, conn: *core.Connection) void {
        const self: *DoqHandler = @ptrCast(@alignCast(ctx));
        self.parsers.removeConnection(self.allocator, @intFromPtr(conn), destroyParser);
    }
    fn onStream(ctx: *anyopaque, conn: *core.Connection, event: core.StreamEvent) void {
        const self: *DoqHandler = @ptrCast(@alignCast(ctx));
        switch (event) {
            .reset => |r| {
                if (self.dropParser(conn, r.stream_id)) abi.conn_extend_max_streams_bidi(conn.conn, 1);
            },
            .data => |d| self.onStreamData(conn, d.stream_id, d.bytes, d.fin, d.peer),
        }
    }

    fn onStreamData(self: *DoqHandler, conn: *core.Connection, stream_id: i64, data: []const u8, fin: bool, peer: std.Io.net.IpAddress) void {
        // RFC 9250 section 4.1: the query rides a client-initiated
        // bidirectional stream. A client-initiated bidi stream ID has its
        // two low bits clear; anything else is refused as a protocol error.
        if (stream_id < 0 or @as(u64, @bitCast(stream_id)) & 0x3 != 0) {
            conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        }
        if (data.len > 0) {
            _ = abi.conn_extend_max_stream_offset(conn.conn, stream_id, data.len);
            abi.conn_extend_max_offset(conn.conn, data.len);
        }
        const parser = self.parserFor(conn, stream_id) catch {
            conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        };
        const fr = parser.feed(data);
        switch (fr) {
            .message => {
                self.answer(conn, stream_id, parser, peer);
                // Bytes past the first message in the same chunk are a
                // second query on this stream (RFC 9250 section 4.3).
                if (parser.extra) {
                    conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
                    _ = self.dropParser(conn, stream_id);
                    return;
                }
            },
            .incomplete => {},
            .protocol_error => {
                conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
                _ = self.dropParser(conn, stream_id);
                return;
            },
        }
        // The client FINs its half of the stream. A complete message was
        // already answered above; an incomplete one is a protocol error.
        if (fin) {
            if (parser.hasMessage()) {
                if (self.dropParser(conn, stream_id)) abi.conn_extend_max_streams_bidi(conn.conn, 1);
            } else {
                conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
                _ = self.dropParser(conn, stream_id);
            }
        }
    }

    fn answer(self: *DoqHandler, conn: *core.Connection, stream_id: i64, parser: *StreamParser, peer: std.Io.net.IpAddress) void {
        const query = parser.takeMessage();
        parser.markAnswered();
        // The managed trust anchors refresh on wall-clock seconds, the same
        // tick the other serve loops run; a DoQ-only server has no other loop
        // to carry it.
        self.runtime.maybeRefreshManagedAnchors(@intCast(std.Io.Clock.real.now(self.io).nanoseconds));
        _ = self.runtime.reloadZoneIfRequested(self.io);
        _ = self.runtime.refreshCatalogIfRequested(self.io);
        var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
        const response = self.runtime.answerFrom(query, &response_buffer, &peer) catch {
            conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        };
        if (response.len > listener.TCP_MAX_FRAME_SIZE) {
            conn.pending.resetStream(stream_id, DOQ_PROTOCOL_ERROR);
            return;
        }
        var framed: [2 + listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
        std.mem.writeInt(u16, framed[0..2], @intCast(response.len), .big);
        @memcpy(framed[2..][0..response.len], response);
        conn.pending.answer(stream_id, framed[0 .. 2 + response.len], DOQ_PROTOCOL_ERROR);
        if (self.counters) |counters| metrics.bump(&counters.doq_queries_total);
        self.completed += 1;
    }
};

/// Maps a socket address to the runtime's address type. Returns null for an
/// address family the runtime cannot name, which ends that stream as a
/// protocol error rather than answering with a made-up client.
pub fn ipAddressFromSockaddr(addr: *const std.posix.sockaddr.storage) ?std.Io.net.IpAddress {
    return core.ipAddressFromStorage(addr);
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

/// Binds the DoQ port and serves DNS-over-QUIC via ngtcp2 + GnuTLS. The
/// handshake selects the `doq` ALPN token (RFC 9250 section 4.2) before
/// any DNS byte is written, so the port never answers cleartext DNS.
/// Serving ends when `max_requests` queries are answered; the counters
/// move the same `doq_queries_total` the old transport moved.
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
    var creds = gnutls.ServerCredentials.load(cert_path, key_path) catch return error.TlsIdentityFailed;
    defer creds.deinit();
    var handler = DoqHandler{
        .allocator = allocator,
        .runtime = runtime,
        .io = io,
        .counters = counters,
        .max_requests = max_requests,
    };
    defer handler.parsers.deinit(allocator, DoqHandler.destroyParser);
    const core_handler = core.Handler{ .ptr = &handler, .onStream = DoqHandler.onStream, .onHandshake = DoqHandler.onHandshake, .onClose = DoqHandler.onClose };
    const State = struct {
        handler: *DoqHandler,
        fn stop(ctx: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.handler.max_requests) |max| return self.handler.completed >= max;
            return false;
        }
    };
    var state = State{ .handler = &handler };
    _ = listener.UDP_IDLE_TIMEOUT;
    // QUIC max_idle_timeout: 30s, matching the ngtcp2 example. The UDP
    // timeout above is for stateless receives, not connection lifetime.
    try core.serve(allocator, io, address, &creds, core_handler, State.stop, &state, 30 * 1_000_000_000, DOQ_ALPN);
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

test "a bad TLS identity fails the DoQ loop instead of binding" {
    // No socket binds, no holder leaks, error propagates.
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const result = serveDoqLoopOnAddress(std.Io.Threaded.global_single_threaded.io(), &runtime, &address, "/nonexistent/cert.pem", "/nonexistent/key.pem", null, null);
    try std.testing.expectError(error.TlsIdentityFailed, result);
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

test "a peer address maps IPv4, IPv6, and v4-mapped forms" {
    var v4_storage = std.mem.zeroes(std.posix.sockaddr.storage);
    {
        const in: *std.posix.sockaddr.in = @ptrCast(@alignCast(&v4_storage));
        in.family = std.posix.AF.INET;
        in.port = std.mem.nativeToBig(u16, 5347);
        in.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
    }
    const v4 = ipAddressFromSockaddr(&v4_storage).?;
    try std.testing.expectEqual(@as([4]u8, .{ 127, 0, 0, 1 }), v4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 5347), v4.ip4.port);

    const v6_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var v6_storage = std.mem.zeroes(std.posix.sockaddr.storage);
    {
        const in6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&v6_storage));
        in6.family = std.posix.AF.INET6;
        in6.port = std.mem.nativeToBig(u16, 5353);
        @memcpy(@as(*[16]u8, @ptrCast(&in6.addr)), &v6_bytes);
    }
    const v6 = ipAddressFromSockaddr(&v6_storage).?;
    try std.testing.expectEqual(@as([4]u8, .{ 0x20, 0x01, 0x0d, 0xb8 }) ++ @as([12]u8, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }), v6.ip6.bytes);
    try std.testing.expectEqual(@as(u16, 5353), v6.ip6.port);

    const mapped_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 80 };
    var mapped_storage = std.mem.zeroes(std.posix.sockaddr.storage);
    {
        const in6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&mapped_storage));
        in6.family = std.posix.AF.INET6;
        in6.port = std.mem.nativeToBig(u16, 853);
        @memcpy(@as(*[16]u8, @ptrCast(&in6.addr)), &mapped_bytes);
    }
    const mapped_result = ipAddressFromSockaddr(&mapped_storage).?;
    try std.testing.expectEqual(@as([4]u8, .{ 192, 0, 2, 80 }), mapped_result.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 853), mapped_result.ip4.port);
}
