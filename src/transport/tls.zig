/// Contract: Owns the encrypted-transport policy surface (RFC 7858/8484/9103 substrate).
/// The Zig 0.16 standard library ships a TLS client only, so the record-layer
/// handshake stays behind a fail-closed gate until the reviewed TLS-server
/// dependency lands (see docs/decisions/encrypted-transport.md). All DNS-layer
/// behavior here operates on the post-handshake byte channel; no cipher,
/// certificate-parsing, or key-exchange code lives in this module.
/// Ownership: Config and PEM byte slices are borrowed; nothing is allocated.
/// Errors: Missing/disabled identity and deferred transports are typed; the
/// handshake gate always fails closed.
const std = @import("std");

pub const dot_port: u16 = 853;
pub const doh_port: u16 = 443;
pub const dot_alpn = "dot";
pub const doh_alpn_h2 = "h2";
pub const doh_alpn_http11 = "http/1.1";

pub const Error = error{
    TlsDisabled,
    MissingCertificate,
    MissingKey,
    CertKeySameFile,
    TlsServerUnavailable,
    DoqDeferred,
};

/// Marks whether a byte stream already passed TLS termination. XFR-over-TLS
/// (RFC 9103) requires .tls; plaintext channels must refuse transfers.
pub const Channel = enum {
    tls,
    plaintext,
};

/// Server ALPN preference for one handshake offer list. DoT selects "dot"
/// (RFC 7858 section 3.1); DoH prefers "h2" then "http/1.1" (RFC 8484
/// section 5.2 prefers HTTP/2 while tolerating HTTP/1.1 mappings).
pub fn negotiateAlpn(offered: []const []const u8, want_doh: bool) ?[]const u8 {
    if (want_doh) {
        for (offered) |protocol| {
            if (std.mem.eql(u8, protocol, doh_alpn_h2)) return doh_alpn_h2;
        }
        for (offered) |protocol| {
            if (std.mem.eql(u8, protocol, doh_alpn_http11)) return doh_alpn_http11;
        }
        return null;
    }
    for (offered) |protocol| {
        if (std.mem.eql(u8, protocol, dot_alpn)) return dot_alpn;
    }
    return null;
}

/// Opt-in gate: dot/doh listeners require the explicit encrypted-dns flag.
pub fn requireEnabled(enabled: bool) Error!void {
    if (!enabled) return Error.TlsDisabled;
}

/// Startup-only identity path check: both paths must be set and distinct.
pub fn validatePaths(cert_path: []const u8, key_path: []const u8) Error!void {
    if (cert_path.len == 0) return Error.MissingCertificate;
    if (key_path.len == 0) return Error.MissingKey;
    if (std.mem.eql(u8, cert_path, key_path)) return Error.CertKeySameFile;
}

/// Startup-only PEM sanity check over already-loaded files: the certificate
/// must carry a PEM block header and the key must be nonempty. Full chain
/// validation belongs to the reviewed TLS-server dependency, not here.
pub fn validatePemPair(cert_bytes: []const u8, key_bytes: []const u8) Error!void {
    if (std.mem.indexOf(u8, cert_bytes, "-----BEGIN") == null) return Error.MissingCertificate;
    if (key_bytes.len == 0) return Error.MissingKey;
}

/// Fail-closed handshake gate. Until the G4-reviewed TLS-server dependency
/// lands, no handshake bytes are ever emitted or accepted here; callers must
/// serve only externally terminated channels or return this error.
pub fn acceptHandshake() Error!void {
    return Error.TlsServerUnavailable;
}

/// RFC 9250 DNS over QUIC is deferred: QUIC cannot be approximated by TCP
/// plus TLS, so any DoQ request fails with a typed error instead of a
/// silent fallback.
pub fn dialDoq() Error!void {
    return Error.DoqDeferred;
}

test "ALPN prefers dot for DoT and h2 for DoH" {
    const offered = &.{ "h2", "dot", "http/1.1" };
    try std.testing.expectEqualStrings("dot", negotiateAlpn(offered, false).?);
    try std.testing.expectEqualStrings("h2", negotiateAlpn(offered, true).?);
    try std.testing.expectEqualStrings("http/1.1", negotiateAlpn(&.{"http/1.1"}, true).?);
    try std.testing.expect(negotiateAlpn(&.{"h2"}, false) == null);
    try std.testing.expect(negotiateAlpn(&.{}, true) == null);
}

test "encrypted listeners require the opt-in flag" {
    try requireEnabled(true);
    try std.testing.expectError(Error.TlsDisabled, requireEnabled(false));
}

test "identity paths must be set and distinct" {
    try validatePaths("/etc/zimdns/tls/cert.pem", "/etc/zimdns/tls/key.pem");
    try std.testing.expectError(Error.MissingCertificate, validatePaths("", "/etc/zimdns/tls/key.pem"));
    try std.testing.expectError(Error.MissingKey, validatePaths("/etc/zimdns/tls/cert.pem", ""));
    try std.testing.expectError(Error.CertKeySameFile, validatePaths("/etc/zimdns/tls/same.pem", "/etc/zimdns/tls/same.pem"));
}

test "PEM pair check rejects non-PEM certificates and empty keys" {
    try validatePemPair("-----BEGIN CERTIFICATE-----\nabc\n", "key-bytes");
    try std.testing.expectError(Error.MissingCertificate, validatePemPair("not a pem", "key-bytes"));
    try std.testing.expectError(Error.MissingKey, validatePemPair("-----BEGIN CERTIFICATE-----\nabc\n", ""));
}

test "handshake gate fails closed and DoQ is deferred" {
    try std.testing.expectError(Error.TlsServerUnavailable, acceptHandshake());
    try std.testing.expectError(Error.DoqDeferred, dialDoq());
}
