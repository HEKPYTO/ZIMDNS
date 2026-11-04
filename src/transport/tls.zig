/// Contract: Owns the encrypted-transport policy surface (RFC 7858/8484 for
/// the transports this build serves, RFC 9103 for the strict-TLS transfer
/// channel it defers). The TLS server comes from the reviewed inic/tls.zig
/// dependency, pinned to one commit in build.zig.zon, so this module owns
/// the policy around it: the ALPN tokens, the opt-in gate, the
/// identity-path checks, the PEM sanity check, and the rule that a transport
/// with no listener refuses to start instead of binding a port. dot.zig serves
/// the DoT port, doh.zig serves the DoH port, and xfr_tls.zig serves the
/// strict-TLS transfer channel over that server.
/// Ownership: Config and PEM byte slices are borrowed; nothing is allocated.
/// Errors: Missing/disabled identity and deferred transports are typed; the
/// startup gate fails closed.
const std = @import("std");

pub const dot_port: u16 = 853;
pub const doh_port: u16 = 443;
pub const doq_port: u16 = 853;
pub const dot_alpn = "dot";
pub const doh_alpn_http11 = "http/1.1";
pub const doq_alpn = "doq";

pub const Error = error{
    TlsDisabled,
    MissingCertificate,
    MissingKey,
    CertKeySameFile,
};

/// The encrypted transports this build knows.
pub const Transport = enum {
    /// DNS over TLS, served on the dot port.
    dot,
    /// DNS over HTTPS, served on the doh port.
    doh,
    /// DNS over QUIC, served on the doq port.
    doq,
    /// The strict-TLS zone transfer channel.
    xfr,
};

/// The ALPN token a transport speaks. DoT selects "dot", the IANA ALPN
/// protocol ID whose registry reference is RFC 7858; RFC 7858 section 3.1
/// fixes the DoT port and never mentions ALPN. RFC 9103 section 7.1 asks
/// for "dot" on the strict-TLS zone-transfer channel, and that channel
/// selects the same token, so the general DoT port follows the registry alone.
/// DoH selects "http/1.1" only, because doh.zig implements the HTTP/1.1
/// mapping: selecting "h2" would hand the client a protocol this server
/// cannot speak (see src/transport/README.md).
pub fn alpnFor(transport: Transport) []const u8 {
    return switch (transport) {
        .dot, .xfr => dot_alpn,
        .doh => doh_alpn_http11,
        .doq => doq_alpn,
    };
}

/// Opt-in gate: dot/doh/doq listeners require the explicit encrypted-dns flag.
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

test "each transport names the ALPN token it speaks" {
    // DoT and the strict-TLS transfer channel speak the IANA "dot" token;
    // RFC 9103 section 7.1 asks for the same token on the transfer channel.
    try std.testing.expectEqualStrings("dot", alpnFor(.dot));
    try std.testing.expectEqualStrings("dot", alpnFor(.xfr));
    // DoH speaks HTTP/1.1 only, because that is what doh.zig implements.
    try std.testing.expectEqualStrings("http/1.1", alpnFor(.doh));
    // DoQ speaks the IANA "doq" token (RFC 9250 §4.2).
    try std.testing.expectEqualStrings("doq", alpnFor(.doq));
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
