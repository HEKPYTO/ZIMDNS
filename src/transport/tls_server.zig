/// Contract: Loads the operator's TLS identity and terminates the handshake
/// for an encrypted listener. The handshake comes from the reviewed
/// inic/tls.zig dependency, pinned to one commit in build.zig.zon; this
/// module owns the operator's paths, the ALPN token the transport speaks, and
/// the refusal of a connection that did not negotiate it. RFC 7858 section
/// 3.2 leaves the authentication profile to the operator's certificate, and
/// this server never asks for a client certificate: RFC 7858 section 3.1
/// keeps the port for encrypted traffic only.
/// Ownership: The loaded identity belongs to the Server; the operator's key
/// bytes are never logged and never written anywhere but the file the
/// operator gave.
/// Errors: An unreadable identity, a failed handshake, and a connection that
/// did not negotiate the transport's ALPN are typed errors.
const std = @import("std");
const tls = @import("tls");

pub const Error = error{
    AlpnMismatch,
};

/// The buffer sizes the TLS dependency needs: one ciphertext record fits in
/// the input buffer, and one handshake flight fits in the output buffer.
pub const input_buffer_len = tls.input_buffer_len;
pub const output_buffer_len = tls.output_buffer_len;

/// The loaded identity and the handshake it performs.
pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: tls.config.CertKeyPair,
    alpn_protocol: []const u8,

    /// Loads the operator's certificate chain and private key from the two
    /// paths the operator gave. The paths are read from `dir`, so a caller
    /// can load them from the working directory or from a test directory.
    ///
    /// shortcut: the standard library's DER parser aborts the process on a
    /// length field that runs past the end of the buffer, and the pinned
    /// dependency calls that parser directly, so a certificate whose DER is
    /// truncated ends the run with a stack trace instead of a typed error.
    /// The port is still not bound, so nothing is served in the clear; give
    /// the operator a clean refusal instead when the parser is fixed
    /// upstream.
    pub fn init(
        self: *Server,
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
        alpn_protocol: []const u8,
    ) !void {
        self.* = .{
            .allocator = allocator,
            .io = io,
            .identity = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, cert_path, key_path),
            .alpn_protocol = alpn_protocol,
        };
    }

    pub fn deinit(self: *Server) void {
        self.identity.deinit(self.allocator);
    }

    /// Terminates the handshake and refuses a connection that did not
    /// negotiate this transport's ALPN token: the server never speaks another
    /// protocol on an encrypted port. The dependency's TLS 1.3 cipher suite
    /// default is the floor RFC 9103 section 7.2 sets for the strict-TLS
    /// transfer channel.
    pub fn handshake(self: *Server, reader: *std.Io.Reader, writer: *std.Io.Writer) !tls.Connection {
        var rng_source: std.Random.IoSource = .{ .io = self.io };
        const alpn_protocols = [_][]const u8{self.alpn_protocol};
        const connection = try tls.server(reader, writer, .{
            .rng = rng_source.interface(),
            .auth = &self.identity,
            .alpn_protocols = &alpn_protocols,
            .now = std.Io.Clock.real.now(self.io),
        });
        const negotiated = connection.alpn_protocol orelse return Error.AlpnMismatch;
        if (!std.mem.eql(u8, negotiated, self.alpn_protocol)) return Error.AlpnMismatch;
        return connection;
    }
};

/// A throwaway self-signed identity for the tests: the key is a test
/// fixture, not a secret, and it grants access to nothing.
pub const test_identity = struct {
    pub const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBXjCCAQSgAwIBAgIUTHvx5jGZ+dT5Z0kredJTUq+kEQAwCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAyMTIxNTEzMFoYDzIxMjYwOTI3
        \\MjE1MTMwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
        \\PQMBBwNCAAQdckaGyjxfvpyCLArrINJ787lrhaGmaYqLYebme4j07PY4LPEkk6G1
        \\+llvdA46AKR2oleQPlDhJfoclmOHjA1JozIwMDAdBgNVHQ4EFgQU9sqjIrmFtcFf
        \\GW5BdsuAW+XuSpcwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBM
        \\+awXX6C3DG9MFhSv7RnYoKWgoxXLsgxpgkJosqoCywIhAJUMO0QlFB0X0nSyfeeG
        \\sf1Gdh8w8gh+QMPfx3lh+Rbg
        \\-----END CERTIFICATE-----
        \\
    ;
    pub const key_pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHcCAQEEIGc+zATonj2C+tiBshiTU5v9T3jCo503EHXUX2kD5tRooAoGCCqGSM49
        \\AwEHoUQDQgAEHXJGhso8X76cgiwK6yDSe/O5a4WhpmmKi2Hm5nuI9Oz2OCzxJJOh
        \\tfpZb3QOOgCkdqJXkD5Q4SX6HJZjh4wNSQ==
        \\-----END EC PRIVATE KEY-----
        \\
    ;
};
