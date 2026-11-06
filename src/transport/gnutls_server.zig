/// Contract: Listener-scoped GnuTLS identity for the ngtcp2 DoQ server.
/// One `ServerCredentials` loads the certificate chain once and is shared
/// by every connection; each connection builds its own `gnutls_session_t`
/// bound to an `ngtcp2_crypto_conn_ref` whose `get_conn` returns the
/// ngtcp2 connection. ALPN is mandatory `doq`, so the handshake never
/// serves another protocol.
/// Ownership: the credentials own the loaded chain until `deinit`; each
/// session is owned by its connection and freed with it.
const std = @import("std");
const abi = @import("ngtcp2_abi.zig");

/// The ALPN token selected on every DoQ handshake (RFC 9250 §4.2).
pub const doq_alpn = "doq";

pub const Error = error{
    CredentialsFailed,
    IdentityFailed,
    SessionFailed,
    PriorityFailed,
    AlpnFailed,
    TlsConfigFailed,
};

/// The certificate chain loaded once per listener. `load` fails when the
/// paths do not name a PEM pair GnuTLS can parse, so a bad identity stops
/// the port instead of serving without one.
pub const ServerCredentials = struct {
    creds: abi.gnutls_cert_creds_t,

    pub fn load(cert_path: []const u8, key_path: []const u8) Error!ServerCredentials {
        var creds: abi.gnutls_cert_creds_t = null;
        if (abi.gnutls_certificate_allocate_credentials(&creds) != 0) return Error.CredentialsFailed;
        errdefer abi.gnutls_certificate_free_credentials(creds);
        // C strings live on the page allocator; the listener never frees a
        // path, so a process-lifetime leak here would be the wrong trade.
        const cert_c = toCString(cert_path) catch return Error.IdentityFailed;
        defer std.heap.page_allocator.free(cert_c);
        const key_c = toCString(key_path) catch return Error.IdentityFailed;
        defer std.heap.page_allocator.free(key_c);
        if (abi.gnutls_certificate_set_x509_key_file(creds, cert_c, key_c, abi.GNUTLS_X509_FMT_PEM) != 0) {
            return Error.IdentityFailed;
        }
        return .{ .creds = creds };
    }

    pub fn deinit(self: *ServerCredentials) void {
        abi.gnutls_certificate_free_credentials(self.creds);
        self.creds = null;
    }
};

/// A per-connection TLS session. `init` wires the session to `conn_ref`
/// (which must outlive the session) and configures the ngtcp2 QUIC
/// callbacks; the ngtcp2 connection drives the handshake, never GnuTLS
/// directly.
pub const ServerSession = struct {
    session: abi.gnutls_session_t,
    alpn: [8]u8 = undefined,
    alpn_len: usize = 0,

    pub fn init(creds: *const ServerCredentials, conn_ref: *abi.crypto_conn_ref) Error!ServerSession {
        return initWithAlpn(creds, conn_ref, doq_alpn);
    }

    pub fn initWithAlpn(creds: *const ServerCredentials, conn_ref: *abi.crypto_conn_ref, alpn_token: []const u8) Error!ServerSession {
        var session: abi.gnutls_session_t = null;
        if (abi.gnutls_init(&session, abi.GNUTLS_SERVER) != 0) return Error.SessionFailed;
        errdefer abi.gnutls_deinit(session);
        // Match the ngtcp2 example's cipher/group selection exactly.
        const priority: [*:0]const u8 = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1";
        if (abi.gnutls_priority_set_direct(session, priority, null) != 0) {
            return Error.PriorityFailed;
        }
        if (abi.gnutls_credentials_set(session, abi.GNUTLS_CRD_CERTIFICATE, creds.creds) != 0) {
            return Error.SessionFailed;
        }
        // Exactly one token per listener: a client that offers no
        // common token is refused before any DNS byte is written.
        var alpn_buf: [8]u8 = undefined;
        if (alpn_token.len > alpn_buf.len) return Error.AlpnFailed;
        @memcpy(alpn_buf[0..alpn_token.len], alpn_token);
        var alpn = abi.gnutls_datum_t{ .data = alpn_buf[0..].ptr, .size = @intCast(alpn_token.len) };
        if (abi.gnutls_alpn_set_protocols(session, &alpn, 1, abi.GNUTLS_ALPN_MANDATORY | abi.GNUTLS_ALPN_SERVER_PRECEDENCE) != 0) {
            return Error.AlpnFailed;
        }
        abi.gnutls_session_set_ptr(session, conn_ref);
        if (abi.crypto_gnutls_configure_server_session(session) != 0) {
            return Error.TlsConfigFailed;
        }
        var out: ServerSession = .{ .session = session };
        // Nothing is negotiated yet (the handshake has not run); the
        // core refreshes the mirror from GnuTLS once it completes.
        out.alpn_len = 0;
        return out;
    }

    pub fn deinit(self: *ServerSession) void {
        abi.gnutls_deinit(self.session);
        self.session = null;
    }
};

fn toCString(text: []const u8) ![:0]const u8 {
    const buf = try std.heap.page_allocator.alloc(u8, text.len + 1);
    @memcpy(buf[0..text.len], text);
    buf[text.len] = 0;
    return buf[0..text.len :0];
}

test "alpn token is the IANA doq token" {
    try std.testing.expectEqualStrings("doq", doq_alpn);
}

test "bad identity paths fail instead of serving" {
    const result = ServerCredentials.load("/nonexistent/cert.pem", "/nonexistent/key.pem");
    try std.testing.expectError(Error.IdentityFailed, result);
}
