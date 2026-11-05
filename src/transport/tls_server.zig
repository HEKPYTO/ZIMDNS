/// Contract: Loads the operator's TLS identity and terminates the handshake
/// for an encrypted listener. The record layer comes from OpenSSL 3.x, one SSL object per
/// socket fd (see openssl_tls.zig); this module owns the operator's
/// paths, the ALPN token the transport speaks, and the refusal of a
/// connection that did not negotiate it. RFC 7858 section 3.2 leaves the
/// authentication profile to the operator's certificate, and this server
/// never asks for a client certificate: RFC 7858 section 3.1 keeps the
/// port for encrypted traffic only.
/// Ownership: The loaded identity belongs to the Server; the operator's key
/// bytes are never logged and never written anywhere but the file the
/// operator gave.
/// Errors: An unreadable identity, a failed handshake, and a connection that
/// did not negotiate the transport's ALPN are typed errors.
const std = @import("std");
const ossl = @import("openssl_tls.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");

pub const Error = error{
    AlpnMismatch,
};

/// The loaded identity and the handshake it performs.
pub const Server = struct {
    inner: ossl.Server,
    allocator: std.mem.Allocator,
    io: std.Io,
    alpn_protocol: []const u8,

    /// Loads the operator's certificate chain and private key from the two
    /// paths the operator gave. The paths are read from `dir`, so a caller
    /// can load them from the working directory or from a test directory.
    /// The identity is loaded before the port binds (see the main gate), so
    /// an unreadable identity fails closed with no listener.
    pub fn init(
        self: *Server,
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
        alpn_protocol: []const u8,
    ) !void {
        var cert_abs: [std.fs.max_path_bytes]u8 = undefined;
        const cert_len = try dir.realPathFile(io, cert_path, &cert_abs);
        var key_abs: [std.fs.max_path_bytes]u8 = undefined;
        const key_len = try dir.realPathFile(io, key_path, &key_abs);
        self.* = .{
            .inner = try ossl.Server.init(cert_abs[0..cert_len], key_abs[0..key_len], alpn_protocol),
            .allocator = allocator,
            .io = io,
            .alpn_protocol = alpn_protocol,
        };
    }

    pub fn deinit(self: *Server) void {
        self.inner.deinit();
    }

    /// Terminates the handshake on the socket fd and refuses a connection
    /// that did not negotiate this transport's ALPN token: the server never
    /// speaks another protocol on an encrypted port. TLS 1.3 is the floor
    /// RFC 9103 section 7.2 sets for the strict-TLS transfer channel. The
    /// handshake polls the fd against one absolute deadline; expiry is
    /// typed, never a held worker.
    pub fn handshake(self: *Server, fd: std.posix.fd_t, io: std.Io, deadline: std.Io.Clock.Timestamp) !ossl.Connection {
        var connection = try ossl.serverHandshake(&self.inner, fd, io, deadline);
        errdefer connection.closeWithoutNotify();
        const negotiated = connection.alpnProtocol() orelse return Error.AlpnMismatch;
        if (!std.mem.eql(u8, negotiated, self.alpn_protocol)) return Error.AlpnMismatch;
        return connection;
    }
};

test "ALPN survives the handshake return with a poisoned stack" {
    // `Connection` crosses the handshake return by value. If ALPN were a
    // slice captured from the callee frame, the copy below would dangle;
    // poisoning the stack between return and read exposes it. The
    // accessor rebuilds the slice from the by-value storage instead.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = test_identity.key_pem });
    var server: Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", "dot");
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    const Serve = struct {
        fn run(listener_ptr: *std.Io.net.Server, io_inner: std.Io, server_ptr: *Server) void {
            const stream = listener_ptr.accept(io_inner) catch return;
            defer stream.close(io_inner);
            const deadline = tcp_deadline.deadline(io_inner, .{ .seconds = 5 });
            var conn = server_ptr.handshake(stream.socket.handle, io_inner, deadline) catch return;
            defer conn.close() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{ &listener, io, &server });
    defer thread.join();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    const deadline = tcp_deadline.deadline(io, .{ .seconds = 5 });
    var conn = try ossl.clientHandshake(ctx, stream.socket.handle, io, deadline, .{
        .verify = .insecure,
        .verify_host = "",
        .sni = @as(?[]const u8, null),
        .alpn = "dot",
    });
    defer conn.closeWithoutNotify();
    // Poison the stack the callee frame used to occupy.
    var poison: [4096]u8 = undefined;
    @memset(&poison, 0xAA);
    std.mem.doNotOptimizeAway(&poison);
    // The negotiated token must still read back intact.
    const got = conn.alpnProtocol() orelse return error.TestExpectedAlpn;
    try std.testing.expectEqualStrings("dot", got);
}

pub const test_identity = struct {
    pub const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBdDCCARqgAwIBAgIUZoVWbX5A6TJE0Qj6v9p3t9oMh6UwCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTEwNTA2MTUyN1oYDzIxMjYxMDEy
        \\MDYxNTI3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
        \\PQMBBwNCAATYLW2sIVYpiJV0MJBsKQQeKj0+53kAd3JBDq2frJams04Ch4C/ttzK
        \\XG4BTO698PO8cpGjiSisYjt4egv2hDCgo0gwRjAdBgNVHQ4EFgQU1qMFPNurMxyP
        \\DuZ4L6yk0MfthpEwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhv
        \\c3QwCgYIKoZIzj0EAwIDSAAwRQIhANbY8v4TpBDq/M/yTstfqsBLt3vpZeqdBqy/
        \\RY2oSoywAiAeMlwB26farGWvXWCJZMbahVb7jhTJc3QO18HCWQ5ewQ==
        \\-----END CERTIFICATE-----
        \\
    ;
    pub const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglmwDeGezcGGtSzLo
        \\hPuxxG5caYK0IWPTobG8KtdYvxqhRANCAATYLW2sIVYpiJV0MJBsKQQeKj0+53kA
        \\d3JBDq2frJams04Ch4C/ttzKXG4BTO698PO8cpGjiSisYjt4egv2hDCg
        \\-----END PRIVATE KEY-----
        \\
    ;
};

/// A throwaway self-signed identity whose certificate carries an IP SAN
/// for 127.0.0.1 (plus the DNS name localhost), for the split
/// SNI/verification test: a client verifies the IP literal while sending
/// no SNI at all, as RFC 9462 section 6.3 asks.
pub const test_identity_ip = struct {
    pub const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBeDCCAR6gAwIBAgIURYIyIaTkfp/RB3EwNpmMPPVhc68wCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MTEwNTA2MTUzMVoXDTI3MTEwNTA2
        \\MTUzMVowFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0D
        \\AQcDQgAEhgUjXha2/bI5oDWOgXcNzgqAENlyDbdAt44gSwoAD0CYzy2O7KDO/Kxq
        \\kgsaJAXL19oATi9O0+7eHce6So5LJ6NOMEwwHQYDVR0OBBYEFGmNkpwj/eaAE7cc
        \\9r1QtQidYy3OMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYcEfwAAAYIJbG9j
        \\YWxob3N0MAoGCCqGSM49BAMCA0gAMEUCIBrGQsfqDE/qau2yoPnWmv+yJiTVDWDC
        \\pyUoh5IuohDaAiEAyzuj+Yav3coVjOTw90QGQ6Ev2DcYSXW/nbOaxTChcSk=
        \\-----END CERTIFICATE-----
        \\
    ;
    pub const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOLglTyv7BLi6Kayv
        \\4PE+SpnL9EdDPSRm3cl/lZEblvahRANCAASGBSNeFrb9sjmgNY6Bdw3OCoAQ2XIN
        \\t0C3jiBLCgAPQJjPLY7soM78rGqSCxokBcvX2gBOL07T7t4dx7pKjksn
        \\-----END PRIVATE KEY-----
        \\
    ;
};

const tls_server_for_test = @import("tls_server.zig");

const ossl_DribbleArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    server: *Server,
};

/// Serves one handshake and then echoes one framed message back, like the
/// DoT framing loop. The message is larger than `chunk_len`, so both sides
/// exercise partial SSL_read/SSL_write (WANT_READ/WANT_WRITE) paths.
fn ossl_echoOne(args: *ossl_DribbleArgs) void {
    const stream = args.listener.accept(args.io) catch return;
    defer stream.close(args.io);
    const deadline = ossl_tcp_deadline(args.io, 5);
    var conn = args.server.handshake(stream.socket.handle, args.io, deadline) catch return;
    defer conn.close() catch {};
    // Read the whole 20KiB the client wrote (partial SSL_reads under
    // the deadline), then echo the 2-byte marker.
    var got: usize = 0;
    var chunk: [16384]u8 = undefined;
    while (got < 20480) {
        const n = conn.read(chunk[0..@min(chunk.len, 20480 - got)]) catch return;
        if (n == 0) continue;
        got += n;
    }
    conn.writeAll(&ossl_echo_msg_len) catch return;
}

var ossl_echo_msg_len: [2]u8 = .{ 0x50, 0x00 };

fn ossl_tcp_deadline(io: std.Io, seconds: u32) std.Io.Clock.Timestamp {
    return tcp_deadline.deadline(io, .{ .seconds = seconds });
}

test "dribbled reads and short writes complete under one absolute deadline" {
    // A 20KiB echo is larger than `chunk_len`, so the transfer exercises
    // the WANT_READ/WANT_WRITE retry loops on both ends; the single
    // absolute deadline bounds the whole exchange.
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = test_identity.key_pem });
    var tls_srv: Server = undefined;
    try tls_srv.init(allocator, io, tmp.dir, "cert.pem", "key.pem", "dot");
    defer tls_srv.deinit();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    var args = ossl_DribbleArgs{ .io = io, .listener = &listener, .server = &tls_srv };
    const thread = try std.Thread.spawn(.{}, ossl_echoOne, .{&args});
    defer thread.join();
    const stream = try std.Io.net.IpAddress.connect(&listener.socket.address, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);
    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    const deadline = ossl_tcp_deadline(io, 10);
    var conn = try ossl.clientHandshake(ctx, stream.socket.handle, io, deadline, .{
        .verify = .insecure,
        .verify_host = "localhost",
        .sni = "localhost",
        .alpn = "dot",
    });
    defer conn.close() catch {};
    try std.testing.expectEqualStrings("dot", conn.alpnProtocol().?);
    try std.testing.expectEqual(@as(c_int, 0x0304), conn.version());
    // 20KiB > chunk_len: forces partial SSL_write calls.
    var out: [20480]u8 = undefined;
    @memset(&out, 0xAB);
    try conn.writeAll(&out);
    // The server echoes the 2-byte marker once it has read the 20KiB.
    var got: [2]u8 = undefined;
    _ = try conn.readAll(&got);
    try std.testing.expectEqualSlices(u8, &ossl_echo_msg_len, &got);
}

test "an expired absolute deadline fails the handshake typed" {
    // A deadline already in the past fails immediately with
    // DeadlineExceeded instead of hanging on the fd.
    const io = std.Io.Threaded.global_single_threaded.io();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const stream = try std.Io.net.IpAddress.connect(&listener.socket.address, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);
    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    // Already-expired deadline: the first poll fails typed.
    const past = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(-1000), .clock = .awake });
    const err = ossl.clientHandshake(ctx, stream.socket.handle, io, past, .{
        .verify = .insecure,
        .verify_host = "localhost",
        .sni = "localhost",
        .alpn = "dot",
    });
    try std.testing.expectError(ossl.Error.DeadlineExceeded, err);
}
