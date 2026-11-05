/// Contract: Speaks DNS over TLS as a client (RFC 7858) for a resolver that
/// forwards instead of iterating. The handshake, ALPN and certificate
/// verification come from OpenSSL 3.x over one SSL object per socket fd (see openssl_tls.zig);
/// this module owns the `dot` ALPN requirement (RFC 8310 section 8.1 asks a
/// client to offer the token), the framing (RFC 7858 section 3.3 reuses the
/// RFC 1035 section 4.2.2 two-octet length prefix) and the refusal of a
/// server that does not present a valid certificate for the name the
/// operator configured.
/// Ownership: The trust context is loaded once and owned here; request and
/// response buffers are the caller's.
/// Errors: A refused handshake, a certificate that does not verify, a
/// mismatched ALPN, and a malformed frame are typed as `Error`.
const std = @import("std");
const ossl = @import("openssl_tls.zig");
const c = @import("openssl_abi.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const dns_message = @import("../dns/message.zig");
const dot_alpn = "dot";

pub const Error = error{
    HandshakeFailed,
    AlpnMismatch,
    FrameTooLarge,
    BadFrame,
    TrustStoreEmpty,
};

/// Largest DNS message a length-prefixed frame can carry (RFC 1035 section
/// 4.2.2: a two-octet length).
pub const max_frame_len: usize = std.math.maxInt(u16);

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    ctx: ?*ossl.Ctx = null,
    ca_path: ?[]const u8 = null,
    roots_loaded: bool = false,

    /// Loads the platform trust store once. RFC 7858 section 4.1 leaves the
    /// trust model to the operator's resolver; this build uses the system
    /// roots and refuses to forward when there are none, so a deployment
    /// cannot silently fall back to an unauthenticated channel.
    pub fn init(self: *Client, allocator: std.mem.Allocator, io: std.Io) !void {
        const ctx = try ossl.clientCtx(.system);
        self.* = .{ .allocator = allocator, .io = io, .ctx = ctx, .roots_loaded = true };
    }

    /// A client whose trust anchors are one certificate file, for a loopback
    /// server in the tests.
    pub fn initFromCertFile(self: *Client, allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
        const owned = try allocator.dupe(u8, path);
        errdefer allocator.free(owned);
        const ctx = try ossl.clientCtx(.{ .ca_file = owned });
        self.* = .{ .allocator = allocator, .io = io, .ctx = ctx, .ca_path = owned, .roots_loaded = true };
    }

    /// A client whose trust anchors are one PEM bundle inside the caller
    /// supplied directory: RFC 9462 DDR trust stores resolve through the
    /// confined configuration directory, never through an absolute path.
    pub fn initFromCaFile(self: *Client, allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
        var abs: [std.fs.max_path_bytes]u8 = undefined;
        const len = try dir.realPathFile(io, path, &abs);
        const owned = try allocator.dupe(u8, abs[0..len]);
        errdefer allocator.free(owned);
        const ctx = try ossl.clientCtx(.{ .ca_file = owned });
        self.* = .{ .allocator = allocator, .io = io, .ctx = ctx, .ca_path = owned, .roots_loaded = true };
    }

    pub fn deinit(self: *Client) void {
        if (self.ctx) |ctx| ossl.freeClientCtx(ctx);
        if (self.ca_path) |p| self.allocator.free(p);
        self.* = undefined;
    }

    /// One query/response exchange over a fresh TLS connection. The caller
    /// dials the stream (so its own source-port policy applies) and this
    /// function owns the handshake and the framing only.
    pub fn exchange(
        self: *Client,
        stream: std.Io.net.Stream,
        host: []const u8,
        request: []const u8,
        response_buffer: []u8,
    ) ![]const u8 {
        return self.exchangeWithVerification(stream, host, host, request, response_buffer);
    }

    /// One exchange whose certificate verification host differs from the SNI
    /// sent on the wire. An empty `sni` sends no SNI at all: that is the RFC
    /// 9462 section 6.3 case, where a resolver verifies an IP SAN without
    /// offering an IP-literal or `resolver.arpa` SNI.
    pub fn exchangeWithVerification(
        self: *Client,
        stream: std.Io.net.Stream,
        verify_host: []const u8,
        sni: []const u8,
        request: []const u8,
        response_buffer: []u8,
    ) ![]const u8 {
        if (!self.roots_loaded) return Error.TrustStoreEmpty;
        if (request.len == 0 or request.len > max_frame_len) return Error.FrameTooLarge;

        // One absolute deadline covers the handshake and the whole
        // exchange: a stalled upstream holds neither. The handshake and
        // framing poll the fd directly against it.
        const deadline = tcp_deadline.deadline(self.io, .{ .seconds = 5 });
        var connection = ossl.clientHandshake(self.ctx.?, stream.socket.handle, self.io, deadline, .{
            .verify = .system,
            .verify_host = verify_host,
            .sni = if (sni.len == 0) @as(?[]const u8, "") else sni,
            .alpn = dot_alpn,
        }) catch |err| return switch (err) {
            error.VerifyFailed, error.HandshakeFailed => Error.HandshakeFailed,
            else => Error.HandshakeFailed,
        };
        connection.deadline = deadline;
        defer connection.close() catch {};
        // RFC 8310 section 8.1 asks a client to offer the "dot" ALPN token,
        // and a server that ignores the extension (Cloudflare's 1.1.1.1:853
        // does) still speaks DoT on the port it was configured for. A server
        // that selects a different token is not that service.
        if (connection.alpnProtocol()) |negotiated| {
            if (!std.mem.eql(u8, negotiated, dot_alpn)) return Error.AlpnMismatch;
        }

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, prefix[0..2], @intCast(request.len), .big);
        connection.writeAll(&prefix) catch return Error.HandshakeFailed;
        connection.writeAll(request) catch return Error.HandshakeFailed;

        // `readAll` returns short on a clean peer close, leaving the
        // remainder uninitialized: require full frames, never slices of
        // half-read bytes.
        if (try connection.readAll(prefix[0..2]) != 2) return Error.BadFrame;
        const response_len = std.mem.readInt(u16, prefix[0..2], .big);
        if (response_len == 0 or response_len > response_buffer.len) return Error.BadFrame;
        if (try connection.readAll(response_buffer[0..response_len]) != response_len) return Error.BadFrame;
        return response_buffer[0..response_len];
    }
};

test "a frame longer than the two-octet length is refused" {
    var client: Client = .{ .allocator = std.testing.allocator, .io = std.Io.Threaded.global_single_threaded.io() };
    client.roots_loaded = true;
    const stream: std.Io.net.Stream = undefined;
    var request: [max_frame_len + 1]u8 = @splat(0);
    var response: [16]u8 = undefined;
    try std.testing.expectError(Error.FrameTooLarge, client.exchange(stream, "localhost", &request, &response));
}

test "a client without trust anchors refuses to exchange" {
    var client: Client = .{ .allocator = std.testing.allocator, .io = std.Io.Threaded.global_single_threaded.io() };
    const stream: std.Io.net.Stream = undefined;
    var request = [_]u8{ 1, 2 };
    var response: [16]u8 = undefined;
    try std.testing.expectError(Error.TrustStoreEmpty, client.exchange(stream, "localhost", &request, &response));
}

const tls_server = @import("tls_server.zig");
const dns_name = @import("../dns/name.zig");
const dns_writer = @import("../dns/writer.zig");

const ServeArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    server: *tls_server.Server,
    answered: bool = false,
};

fn serveOne(args: *ServeArgs) void {
    const stream = args.listener.accept(args.io) catch return;
    defer stream.close(args.io);
    const deadline = tcp_deadline.deadline(args.io, .{ .seconds = 5 });
    var connection = args.server.handshake(stream.socket.handle, args.io, deadline) catch return;
    defer connection.close() catch {};
    var prefix: [2]u8 = undefined;
    _ = connection.readAll(prefix[0..2]) catch return;
    const request_len = std.mem.readInt(u16, prefix[0..2], .big);
    var request: [512]u8 = undefined;
    if (request_len > request.len) return;
    _ = connection.readAll(request[0..request_len]) catch return;
    // Reply with the same message marked as a response, so the test can
    // compare what it sent with what it got back.
    request[2] |= 0x80;
    std.mem.writeInt(u16, prefix[0..2], request_len, .big);
    connection.writeAll(&prefix) catch return;
    connection.writeAll(request[0..request_len]) catch return;
    args.answered = true;
}

test "RFC 7858 section 3.3: a DoT client frames a DNS message over the dot ALPN" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();

    var cert_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path_buffer);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, cert_path_buffer[0..cert_len]);
    defer client.deinit();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    var query: [512]u8 = undefined;
    var question_arena = std.heap.ArenaAllocator.init(allocator);
    defer question_arena.deinit();
    const built = dns_message.Message{
        .allocator = question_arena.allocator(),
        .header = .{ .id = 0x4242, .question_count = 1, .recursion_desired = true },
        .question = .{ .name = try dns_name.Name.fromText("example.com."), .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(question_arena.allocator(), 0),
    };
    var writer = dns_writer.Writer.init(&query);
    try built.encode(&writer);
    const query_bytes = writer.written();

    var response_buffer: [512]u8 = undefined;
    const response_bytes = try client.exchange(stream, "localhost", query_bytes, &response_buffer);
    const response = try dns_message.Message.parse(question_arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 0x4242), response.header.id);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(query_bytes[2] & 0x7f, response_bytes[2] & 0x7f);
    try std.testing.expectEqual(query_bytes[3], response_bytes[3]);
    try std.testing.expectEqualSlices(u8, query_bytes[4..], response_bytes[4..]);
    try std.testing.expect(args.answered);
}

test "RFC 9462 section 6.3: a client verifies an IP SAN without sending SNI" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity_ip.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity_ip.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    var reject_args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();
    const reject_thread = try std.Thread.spawn(.{}, serveOne, .{&reject_args});
    defer reject_thread.join();

    var cert_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path_buffer);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, cert_path_buffer[0..cert_len]);
    defer client.deinit();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    var query: [512]u8 = undefined;
    var question_arena = std.heap.ArenaAllocator.init(allocator);
    defer question_arena.deinit();
    const built = dns_message.Message{
        .allocator = question_arena.allocator(),
        .header = .{ .id = 0x4343, .question_count = 1, .recursion_desired = true },
        .question = .{ .name = try dns_name.Name.fromText("example.com."), .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(question_arena.allocator(), 0),
    };
    var writer = dns_writer.Writer.init(&query);
    try built.encode(&writer);
    const query_bytes = writer.written();

    var response_buffer: [512]u8 = undefined;
    const response_bytes = try client.exchangeWithVerification(stream, "127.0.0.1", "", query_bytes, &response_buffer);
    const response = try dns_message.Message.parse(question_arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 0x4343), response.header.id);
    try std.testing.expect(response.header.qr);
    try std.testing.expect(args.answered);

    var reject_stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer reject_stream.close(io);
    var reject_response: [512]u8 = undefined;
    try std.testing.expectError(Error.HandshakeFailed, client.exchangeWithVerification(reject_stream, "127.0.0.2", "", query_bytes, &reject_response));
}

test "a truncated DoT frame is BadFrame, never a half-read slice" {
    // The server sends one prefix byte (or a short body) then closes: the
    // client must refuse with BadFrame, not return uninitialized tail bytes.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });

    const Case = struct {
        bytes: []const u8,
    };
    const cases = [_]Case{
        .{ .bytes = &[_]u8{0x00} },
        .{ .bytes = &[_]u8{ 0x00, 0x04, 0xAA } },
    };
    for (cases) |case| {
        var server: tls_server.Server = undefined;
        try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
        defer server.deinit();

        var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
        defer listener.deinit(io);
        const bound = listener.socket.address;

        const Serve = struct {
            fn run(listener_ptr: *std.Io.net.Server, io_inner: std.Io, server_ptr: *tls_server.Server, blob: []const u8) void {
                const stream = listener_ptr.accept(io_inner) catch return;
                defer stream.close(io_inner);
                const deadline = tcp_deadline.deadline(io_inner, .{ .seconds = 5 });
                var conn = server_ptr.handshake(stream.socket.handle, io_inner, deadline) catch return;
                defer conn.close() catch {};
                // Drain the query frame first so the client write completes.
                var q: [514]u8 = undefined;
                _ = conn.read(q[0..]) catch {};
                conn.writeAll(blob) catch return;
            }
        };
        const thread = try std.Thread.spawn(.{}, Serve.run, .{ &listener, io, &server, case.bytes });
        defer thread.join();

        var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
        defer stream.close(io);

        var cert_path: [std.fs.max_path_bytes]u8 = undefined;
        const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path);
        var client: Client = undefined;
        try Client.initFromCertFile(&client, allocator, io, cert_path[0..cert_len]);
        defer client.deinit();

        var response_buffer: [512]u8 = undefined;
        try std.testing.expectError(
            Error.BadFrame,
            client.exchangeWithVerification(stream, "localhost", "localhost", &[_]u8{ 0xaa, 0xbb }, &response_buffer),
        );
    }
}

test "a failed verification aborts before any DNS byte is sent" {
    // The client must refuse the channel when the certificate does not
    // verify: no query byte may reach the server, so a forged upstream
    // cannot harvest queries.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    // Trust the IP-SAN fixture while the server presents the
    // localhost-only identity: verification fails for "127.0.0.1".
    var ip_cert: [std.fs.max_path_bytes]u8 = undefined;
    const ip_len = try tmp.dir.realPathFile(io, "cert.pem", &ip_cert);
    _ = ip_len;
    var other = std.testing.tmpDir(.{});
    defer other.cleanup();
    try other.dir.writeFile(io, .{ .sub_path = "ca.pem", .data = tls_server.test_identity_ip.cert_pem });
    var ca_path: [std.fs.max_path_bytes]u8 = undefined;
    const ca_len = try other.dir.realPathFile(io, "ca.pem", &ca_path);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, ca_path[0..ca_len]);
    defer client.deinit();

    var query = [_]u8{ 0xaa, 0xbb };
    var response_buffer: [512]u8 = undefined;
    try std.testing.expectError(Error.HandshakeFailed, client.exchangeWithVerification(stream, "127.0.0.1", "", &query, &response_buffer));
    // Nothing was framed: the server never saw a DNS byte.
    try std.testing.expect(!args.answered);
}

test "an expired certificate fails verification before any DNS byte" {
    // The fixture below is a self-signed localhost certificate valid only
    // in 2019-2020 (minted offline from the loopback key with
    // `openssl req -x509 ... -not_before 20190101000000Z -not_after
    // 20200101000000Z`); trusting it directly still fails the time check,
    // and the server never sees a DNS byte.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = expired_cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    var ca_path: [std.fs.max_path_bytes]u8 = undefined;
    const ca_len = try tmp.dir.realPathFile(io, "cert.pem", &ca_path);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, ca_path[0..ca_len]);
    defer client.deinit();

    var query = [_]u8{ 0xaa, 0xbb };
    var response_buffer: [512]u8 = undefined;
    try std.testing.expectError(Error.HandshakeFailed, client.exchangeWithVerification(stream, "localhost", "", &query, &response_buffer));
    try std.testing.expect(!args.answered);
}

const expired_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBcjCCARigAwIBAgIUKnHGbV6hXzf/2xdlbkdZVjUME74wCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE5MDEwMTAwMDAwMFoXDTIwMDEwMTAw
    \\MDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    \\AQcDQgAE2C1trCFWKYiVdDCQbCkEHio9Pud5AHdyQQ6tn6yWprNOAoeAv7bcylxu
    \\AUzuvfDzvHKRo4korGI7eHoL9oQwoKNIMEYwHQYDVR0OBBYEFNajBTzbqzMcjw7m
    \\eC+spNDH7YaRMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0
    \\MAoGCCqGSM49BAMCA0gAMEUCIQC5s41favjG3TTz7h78NLjVTEeDwDT6NhPF1yzi
    \\pb9X/gIgAW+hxeBwAXxRGQ5/54077Flcg/wtYBAvItD0OWpRtNE=
    \\-----END CERTIFICATE-----
    \\
;

test "an empty verification host is refused, never silently unchecked" {
    // `SSL_set1_host("")` would disable name checks; the wrapper rejects
    // the empty name before connecting. No listener needed: rejection
    // happens before any handshake byte.
    const io = std.Io.Threaded.global_single_threaded.io();
    const ctx = try ossl.clientCtx(.system);
    defer ossl.freeClientCtx(ctx);
    const deadline = tcp_deadline.deadline(io, .{ .seconds = 1 });
    // -1 is never a live socket; the empty-host refusal must fire first.
    try std.testing.expectError(
        ossl.Error.VerifyFailed,
        ossl.clientHandshake(ctx, -1, io, deadline, .{ .verify = .system, .verify_host = "", .sni = @as(?[]const u8, null), .alpn = dot_alpn }),
    );
}

test "empty SNI sends no server_name while verification still uses the host" {
    // DNS verify host + empty public SNI: the ClientHello must carry no
    // server_name extension, and the exchange still verifies "localhost".
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    const Seen = struct {
        var servername_seen: bool = false;
        var answered: bool = false;
    };
    const Serve = struct {
        fn run(listener_ptr: *std.Io.net.Server, io_inner: std.Io, server_ptr: *tls_server.Server) void {
            const stream = listener_ptr.accept(io_inner) catch return;
            defer stream.close(io_inner);
            const deadline = tcp_deadline.deadline(io_inner, .{ .seconds = 5 });
            // Raw handshake without the ALPN gate: no extension means no
            // ALPN either, and this probe is about SNI, not ALPN.
            var conn = ossl.serverHandshake(&server_ptr.inner, stream.socket.handle, io_inner, deadline) catch return;
            defer conn.close() catch {};
            if (c.SSL_get_servername(conn.ssl.?, c.TLSEXT_NAMETYPE_host_name) != null) {
                Seen.servername_seen = true;
            }
            var prefix: [2]u8 = undefined;
            const got_prefix = conn.readAll(prefix[0..2]) catch return;
            if (got_prefix != 2) return;
            const request_len = std.mem.readInt(u16, prefix[0..2], .big);
            if (request_len > 512) return;
            var request: [512]u8 = undefined;
            const got_body = conn.readAll(request[0..request_len]) catch return;
            if (got_body != request_len) return;
            request[2] |= 0x80;
            conn.writeAll(prefix[0..2]) catch return;
            conn.writeAll(request[0..request_len]) catch return;
            Seen.answered = true;
        }
    };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{ &listener, io, &server });
    defer thread.join();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    var ca_path: [std.fs.max_path_bytes]u8 = undefined;
    const ca_len = try tmp.dir.realPathFile(io, "cert.pem", &ca_path);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, ca_path[0..ca_len]);
    defer client.deinit();

    var query: [512]u8 = undefined;
    var question_arena = std.heap.ArenaAllocator.init(allocator);
    defer question_arena.deinit();
    const built = dns_message.Message{
        .allocator = question_arena.allocator(),
        .header = .{ .id = 0x7777, .question_count = 1, .recursion_desired = true },
        .question = .{ .name = try dns_name.Name.fromText("example.com."), .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(question_arena.allocator(), 0),
    };
    var writer = dns_writer.Writer.init(&query);
    try built.encode(&writer);
    const query_bytes = writer.written();

    var response_buffer: [512]u8 = undefined;
    const response_bytes = try client.exchangeWithVerification(stream, "localhost", "", query_bytes, &response_buffer);
    try std.testing.expect(Seen.answered);
    try std.testing.expect(!Seen.servername_seen);
    const response = try dns_message.Message.parse(question_arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 0x7777), response.header.id);
}

test "a TLS 1.2 client is refused by the TLS 1.3-only server" {
    // The server floor is TLS 1.3; a client offering only 1.2 never
    // completes the handshake.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();

    var address = bound;
    var stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    // Cap the floor below 1.3 on a throwaway client context: OpenSSL
    // fails the handshake against the 1.3-only server.
    _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_MIN_PROTO_VERSION, 0x0301, null);
    _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_MAX_PROTO_VERSION, 0x0303, null); // TLS 1.2 cap
    const deadline = tcp_deadline.deadline(io, .{ .seconds = 5 });
    var conn = ossl.clientHandshake(ctx, stream.socket.handle, io, deadline, .{
        .verify = .insecure,
        .verify_host = "",
        .sni = @as(?[]const u8, null),
        .alpn = dot_alpn,
    }) catch |err| {
        try std.testing.expectEqual(ossl.Error.HandshakeFailed, err);
        return;
    };
    defer conn.closeWithoutNotify();
    try std.testing.expect(false); // the 1.2-only offer must not complete
}
