/// Contract: Owns the encrypted-transport policy surface (RFC 7858/8484/9103
/// substrate). The TLS server comes from the reviewed inic/tls.zig dependency,
/// pinned to one commit in build.zig.zon, so this module owns the policy
/// around it: the ALPN tokens, the opt-in gate, the identity-path checks, the
/// PEM sanity check, and the rule that a transport with no listener refuses
/// to start instead of binding a port. dot.zig serves the DoT port and
/// doh.zig serves the DoH port over that server; the strict-TLS transfer
/// channel has no listener yet and refuses to start.
/// Ownership: Config and PEM byte slices are borrowed; nothing is allocated.
/// Errors: Missing/disabled identity and deferred transports are typed; the
/// startup gate fails closed.
const std = @import("std");

pub const dot_port: u16 = 853;
pub const doh_port: u16 = 443;
pub const dot_alpn = "dot";
pub const doh_alpn_http11 = "http/1.1";

pub const Error = error{
    TlsDisabled,
    MissingCertificate,
    MissingKey,
    CertKeySameFile,
    TransportDeferred,
    DoqDeferred,
};

/// The encrypted transports this build knows.
pub const Transport = enum {
    /// DNS over TLS, served on the dot port.
    dot,
    /// DNS over HTTPS, served on the doh port.
    doh,
    /// The strict-TLS zone transfer channel.
    xfr,
};

/// The ALPN token a transport speaks. DoT selects "dot", the IANA ALPN
/// protocol ID whose registry reference is RFC 7858; RFC 7858 section 3.1
/// fixes the DoT port and never mentions ALPN. RFC 9103 section 7.1
/// additionally requires "dot" for zone transfer over TLS. DoH selects
/// "http/1.1" only, because doh.zig implements the HTTP/1.1 mapping:
/// selecting "h2" would hand the client a protocol this server cannot speak
/// (see src/transport/README.md).
pub fn alpnFor(transport: Transport) []const u8 {
    return switch (transport) {
        .dot, .xfr => dot_alpn,
        .doh => doh_alpn_http11,
    };
}

/// Server ALPN preference for one handshake offer list.
pub fn negotiateAlpn(offered: []const []const u8, transport: Transport) ?[]const u8 {
    const wanted = alpnFor(transport);
    for (offered) |protocol| {
        if (std.mem.eql(u8, protocol, wanted)) return wanted;
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

/// Startup gate for an encrypted listener: only the transports this build
/// serves may start. A transport with no listener refuses here, before a
/// socket is opened, so an encrypted port never answers in cleartext.
pub fn requireListener(transport: Transport) Error!void {
    switch (transport) {
        .dot, .doh => {},
        .xfr => return Error.TransportDeferred,
    }
}

/// RFC 9250 DNS over QUIC is deferred: QUIC cannot be approximated by TCP
/// plus TLS, so any DoQ request fails with a typed error instead of a
/// silent fallback.
pub fn dialDoq() Error!void {
    return Error.DoqDeferred;
}

test "ALPN selects dot for DoT and only http/1.1 for DoH, never unimplemented h2" {
    const offered = &.{ "h2", "dot", "http/1.1" };
    try std.testing.expectEqualStrings("dot", negotiateAlpn(offered, .dot).?);
    try std.testing.expectEqualStrings("http/1.1", negotiateAlpn(offered, .doh).?);
    // doh.zig speaks HTTP/1.1 only, so an h2-only client gets no selection.
    try std.testing.expect(negotiateAlpn(&.{"h2"}, .doh) == null);
    try std.testing.expect(negotiateAlpn(&.{"h2"}, .dot) == null);
    try std.testing.expect(negotiateAlpn(&.{}, .doh) == null);
    // RFC 9103 section 7.1 scopes the "dot" token to transfers as well.
    try std.testing.expectEqualStrings("dot", alpnFor(.xfr));
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

test "encrypted listener startup fails closed and DoQ is deferred" {
    // DoT and DoH have a listener; the strict-TLS transfer channel refuses
    // to start, before a port is bound.
    try requireListener(.dot);
    try requireListener(.doh);
    try std.testing.expectError(Error.TransportDeferred, requireListener(.xfr));
    try std.testing.expectError(Error.DoqDeferred, dialDoq());
}
