/// Contract: Signs one primary zone with a single DNSSEC key -- ECDSA P-256
/// (RFC 6605 algorithm 13), ECDSA P-384 (RFC 6605 algorithm 14), Ed25519
/// (RFC 8080 algorithm 15), or Ed448 (RFC 8080 algorithm 16) -- producing the
/// apex DNSKEY, an NSEC chain of denial, and one RRSIG per RRset
/// (RFC 4034 sections 3.1.8.1 and 5.1.4, RFC 4035 section 2.3).
/// Ownership: every generated zone record, RDATA blob, and byte string is
/// allocated from `allocator`, which the caller keeps alive for as long as it
/// keeps the signed zone. `Key` owns private key material; call `Key.deinit`.
/// Errors: key-file, RDATA, and capacity failures are typed; no file or socket
/// I/O occurs here. This module signs only: validation lives in
/// `src/dns/validate.zig`, served over the forwarding path.
const std = @import("std");
const Name = @import("../dns/name.zig").Name;
const dns_dnssec = @import("../dns/dnssec.zig");
const dns_message = @import("../dns/message.zig");
const dns_types = @import("../dns/types.zig");
const dns_header = @import("../dns/header.zig");
const dns_validate = @import("../dns/validate.zig");
const RecordType = dns_types.RecordType;
const dns_rdata = @import("../dns/rdata.zig");
const dns_writer = @import("../dns/writer.zig");
const zone_parser = @import("parser.zig");
const zone_index = @import("index.zig");
const zonemd = @import("zonemd.zig");

pub const Error = error{
    BadKeyFile,
    BadSecret,
    BadZoneRecord,
    /// The operator's NSEC3 parameters contradict the ones the zone's own
    /// apex NSEC3PARAM states.
    BadChainParameters,
    /// RFC 9276 section 3.1: a published NSEC3 chain uses an iteration count
    /// of 0, so a chain that names another count is refused rather than
    /// published.
    InsecureChainParameters,
    AlreadySigned,
    KeyUsedForAnotherZone,
    SigningFailed,
    OutOfMemory,
};

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const ed448 = @import("../dns/ed448.zig");

/// The signing algorithms this build carries. RFC 5702's RSA/SHA-256 (8) and
/// RSA/SHA-512 (10) are here; RSA/SHA-1 (5) and RSA/SHA-1-NSEC3 (7) are not,
/// because the IANA "DNS Security Algorithm Numbers" registry, as revised by
/// RFC 9904, marks them NOT RECOMMENDED under "Implement for DNSSEC Signing".
/// Ed25519 (RFC 8080 algorithm 15) and Ed448 (RFC 8080 algorithm 16) are here,
/// the latter on the `src/dns/ed448.zig` primitive.
pub const Algorithm = enum(u8) {
    rsa_sha256 = 8,
    rsa_sha512 = 10,
    ecdsa_p256_sha256 = 13,
    ecdsa_p384_sha384 = 14,
    ed25519 = 15,
    ed448 = 16,

    pub fn mnemonic(self: Algorithm) []const u8 {
        return switch (self) {
            .rsa_sha256 => "RSASHA256",
            .rsa_sha512 => "RSASHA512",
            .ecdsa_p256_sha256 => "ECDSAP256SHA256",
            .ecdsa_p384_sha384 => "ECDSAP384SHA384",
            .ed25519 => "ED25519",
            .ed448 => "ED448",
        };
    }
};

/// DS digest types. RFC 4509 section 2 assigns 2 to SHA-256; RFC 6605
/// section 6.2 pairs algorithm 14 with SHA-384 (digest type 4).
const DigestType = enum(u8) {
    sha256 = 2,
    sha384 = 4,

    fn forAlgorithm(algorithm: Algorithm) DigestType {
        return switch (algorithm) {
            .ecdsa_p384_sha384 => .sha384,
            else => .sha256,
        };
    }
};

/// RFC 4034 section 2.1.1: bit 7 (0x0100) is the Zone Key flag and bit 15
/// (0x0001) is the Secure Entry Point flag.
const zone_key_flag: u16 = 0x0100;
const secure_entry_point_flag: u16 = 0x0001;
/// RFC 6781 section 3.2.3: the Secure Entry Point flag belongs on the
/// key-signing key and not on the zone-signing key, and on every key of a
/// single-type signing scheme, which is why every example key file uses 257,
/// the value RFC 8080 section 6.1 publishes.
const dnskey_flags: u16 = zone_key_flag | secure_entry_point_flag;
/// The two DNSKEY forms the signer publishes. A zone signs its data with
/// `zone_key_flags` and its DNSKEY RRset with `key_signing_flags`; the
/// signature's key tag is over the RDATA of the form it names.
pub const zone_key_flags: u16 = zone_key_flag;
pub const key_signing_flags: u16 = dnskey_flags;
/// RFC 5011 section 3: bit 8 of the DNSKEY Flags field is the REVOKE flag.
const revoke_flag: u16 = 0x0080;
/// RFC 4034 section 2.1.2 fixes protocol at 3; other values MUST NOT be used.
const dnskey_protocol: u8 = 3;

/// DNSKEY, RRSIG, and DS RDATA are served opaque and bounded by
/// `max_unknown_len`, so the signer reuses that ceiling instead of inventing a
/// second one.
const max_rdata_len = dns_rdata.max_unknown_len;

/// An RSA private key, big-endian and unnormalized: it is the DNSSEC key,
/// copied by value into `Material` and wiped by `Key.deinit`.
pub const max_rsa_modulus_bytes = 512;
pub const max_rsa_exponent_bytes = 8;
/// RRSIG RDATA is 18 fixed octets, the signer name (at most 255 wire
/// octets), and the signature, whose widest form here is an RSA modulus.
pub const max_rrsig_rdata_local_len = 18 + 255 + max_rsa_modulus_bytes;

pub const RsaKey = struct {
    modulus: [max_rsa_modulus_bytes]u8 = undefined,
    exponent: [max_rsa_exponent_bytes]u8 = undefined,
    private_exponent: [max_rsa_modulus_bytes]u8 = undefined,
    modulus_len: u16 = 0,
    exponent_len: u8 = 0,
    private_len: u16 = 0,

    pub fn modulusBytes(self: *const RsaKey) []const u8 {
        return self.modulus[0..self.modulus_len];
    }

    pub fn exponentBytes(self: *const RsaKey) []const u8 {
        return self.exponent[0..self.exponent_len];
    }

    pub fn privateBytes(self: *const RsaKey) []const u8 {
        return self.private_exponent[0..self.private_len];
    }
};

pub const Material = union(Algorithm) {
    rsa_sha256: RsaKey,
    rsa_sha512: RsaKey,
    ecdsa_p256_sha256: EcdsaP256Sha256.KeyPair,
    ecdsa_p384_sha384: EcdsaP384Sha384.KeyPair,
    ed25519: Ed25519.KeyPair,
    ed448: ed448.SecretKey,
};

pub const Key = struct {
    material: Material,
    /// The zone this key has signed, if any. RFC 8080 section 8: a private key
    /// used for a DNSSEC zone must not be used for any other purpose than for
    /// that zone, so one key signs one zone.
    signed_zone: ?Name = null,
    /// RFC 6781 section 3.1: the key-signing key of a zone that separates the
    /// roles. It signs the DNSKEY RRset and nothing else, and the parent
    /// points its DS at it. Null is the single-type signing scheme, where one
    /// key signs everything.
    ksk: ?Ksk = null,
    /// RFC 6781 section 4.1.2: the second key-signing key of a
    /// Double-Signature rollover. It is published at the apex and signs the
    /// DNSKEY RRset beside the key the parent's DS points at, but that DS
    /// states that one alone. Null when no rollover is in progress.
    published_ksk: ?Ksk = null,

    pub fn algorithm(self: *const Key) Algorithm {
        return self.material;
    }

    /// RFC 6605 section 4 fixes the ECDSA Signature field at the raw `r | s`
    /// concatenation of fixed-width big-endian octets; RFC 8080 section 3 uses
    /// the RFC 8032 `R || S` form. The standard library emits both as
    /// fixed-width big-endian pairs, so `toBytes` is the DNSSEC encoding.
    fn sign(self: *const Key, message: []const u8, out: []u8) Error![]const u8 {
        return signMaterial(&self.material, message, out);
    }

    /// Wipes the private scalar, the Ed25519 seed, the Ed448 secret, and the public key.
    pub fn deinit(self: *Key) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.material));
        if (self.ksk) |*ksk| ksk.deinit();
        if (self.published_ksk) |*ksk| ksk.deinit();
    }

    /// DNSKEY RDATA (RFC 4034 section 5.1.1): flags, protocol, algorithm, then
    /// the public key. ECDSA uses the uncompressed curve point as "x | y"
    /// (RFC 6605 section 4), which is SEC 1's uncompressed form with the
    /// leading 0x04 octet dropped; Ed25519 uses its raw 32 octets, per
    /// RFC 8080 section 3.2, and Ed448 its raw 57 octets, per RFC 8080
    /// section 3. Public because a trust anchor is exactly this
    /// record, and an operator (or a test) cannot write one without it.
    pub fn dnskeyRdata(self: *const Key, allocator: std.mem.Allocator) Error![]const u8 {
        return dnskeyRdataOf(self.material, allocator, dnskey_flags);
    }

    /// The DNSKEY RDATA with the flags the key's role asks for: RFC 4034
    /// section 2.1.1 sets the Zone Key bit on every key, and RFC 6781
    /// section 3.2.3 sets the Secure Entry Point bit on the key a parent
    /// points its DS at and not on the others.
    pub fn dnskeyRdataWithFlags(
        self: *const Key,
        allocator: std.mem.Allocator,
        flags: u16,
    ) Error![]const u8 {
        return dnskeyRdataOf(self.material, allocator, flags);
    }
};

/// RFC 6781 section 3.1: the key-signing key of a zone that separates the
/// roles. It signs the DNSKEY RRset and nothing else, and the DS the parent
/// publishes states it.
pub const Ksk = struct {
    material: Material,
    /// The zone this key has signed, if any (RFC 8080 section 8).
    signed_zone: ?Name = null,
    /// RFC 6781 section 4.1.2.1: the key is the one being removed, so it is
    /// published with the RFC 5011 section 3 REVOKE bit set and it still
    /// signs the DNSKEY RRset that carries it.
    revoked: bool = false,

    pub fn algorithm(self: *const Ksk) Algorithm {
        return self.material;
    }

    pub fn deinit(self: *Ksk) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.material));
    }
};

/// The public key bytes of a key: what the DNSKEY carries after the flags,
/// the protocol, and the algorithm (RFC 4034 section 5.1.1).
fn publicKeyBytes(material: Material, buffer: []u8) []const u8 {
    switch (material) {
        .rsa_sha256, .rsa_sha512 => |key| {
            // RFC 3110 section 2: a one-octet exponent length, or a zero
            // octet and a two-octet length when the exponent is 256 octets or
            // longer, then the exponent and the modulus.
            return rsaPublicKeyBytes(key, buffer);
        },
        .ecdsa_p256_sha256 => |key_pair| {
            const sec1 = EcdsaP256Sha256.PublicKey.toUncompressedSec1(key_pair.public_key);
            @memcpy(buffer[0 .. sec1.len - 1], sec1[1..]);
            return buffer[0 .. sec1.len - 1];
        },
        .ecdsa_p384_sha384 => |key_pair| {
            const sec1 = EcdsaP384Sha384.PublicKey.toUncompressedSec1(key_pair.public_key);
            @memcpy(buffer[0 .. sec1.len - 1], sec1[1..]);
            return buffer[0 .. sec1.len - 1];
        },
        .ed25519 => |key_pair| {
            const public = key_pair.public_key.toBytes();
            @memcpy(buffer[0..public.len], &public);
            return buffer[0..public.len];
        },
        .ed448 => |secret| {
            const public = ed448.derivePublicKey(secret);
            @memcpy(buffer[0..public.len], &public);
            return buffer[0..public.len];
        },
    }
}

/// True when two keys hold the same public key. A zone that published the
/// same key twice would hold the same DNSKEY in its RRset twice, and an
/// RRset with a duplicate RR is not the RRset a signature covers.
pub fn samePublicKey(a: Material, b: Material) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    var a_buffer: [max_rdata_len]u8 = undefined;
    var b_buffer: [max_rdata_len]u8 = undefined;
    return std.mem.eql(u8, publicKeyBytes(a, &a_buffer), publicKeyBytes(b, &b_buffer));
}

/// The DNSKEY RDATA of one key with the flags the key's role asks for
/// (RFC 4034 section 5.1.1).
fn dnskeyRdataOf(material: Material, allocator: std.mem.Allocator, flags: u16) Error![]const u8 {
    var buffer: [max_rdata_len]u8 = undefined;
    std.mem.writeInt(u16, buffer[0..2], flags, .big);
    buffer[2] = dnskey_protocol;
    buffer[3] = @backingInt(material);
    var len: usize = 4;
    switch (material) {
        .rsa_sha256, .rsa_sha512 => |key| {
            const public = rsaPublicKeyBytes(key, buffer[4..]);
            len += public.len;
        },
        .ecdsa_p256_sha256 => |key_pair| {
            const sec1 = EcdsaP256Sha256.PublicKey.toUncompressedSec1(key_pair.public_key);
            @memcpy(buffer[len..][0 .. sec1.len - 1], sec1[1..]);
            len += sec1.len - 1;
        },
        .ecdsa_p384_sha384 => |key_pair| {
            const sec1 = EcdsaP384Sha384.PublicKey.toUncompressedSec1(key_pair.public_key);
            @memcpy(buffer[len..][0 .. sec1.len - 1], sec1[1..]);
            len += sec1.len - 1;
        },
        .ed25519 => |key_pair| {
            const public = key_pair.public_key.toBytes();
            @memcpy(buffer[len..][0..public.len], &public);
            len += public.len;
        },
        .ed448 => |secret| {
            const public = ed448.derivePublicKey(secret);
            @memcpy(buffer[len..][0..public.len], &public);
            len += public.len;
        },
    }
    return allocator.dupe(u8, buffer[0..len]);
}

/// Signs with one key's material.
fn signMaterial(material: *const Material, message: []const u8, out: []u8) Error![]const u8 {
    // The payload is reached through pointers, so the private key is not
    // copied again; the one copy the switch needs is wiped on the way out.
    var copy = material.*;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&copy));
    switch (copy) {
        .rsa_sha256 => |*key| return rsaPkcs1Sign(key, message, out, std.crypto.hash.sha2.Sha256),
        .rsa_sha512 => |*key| return rsaPkcs1Sign(key, message, out, std.crypto.hash.sha2.Sha512),
        .ecdsa_p256_sha256 => |*key_pair| {
            const bytes = (try signEcdsa(EcdsaP256Sha256, key_pair.*, message)).toBytes();
            @memcpy(out[0..bytes.len], &bytes);
            return out[0..bytes.len];
        },
        .ecdsa_p384_sha384 => |*key_pair| {
            const bytes = (try signEcdsa(EcdsaP384Sha384, key_pair.*, message)).toBytes();
            @memcpy(out[0..bytes.len], &bytes);
            return out[0..bytes.len];
        },
        .ed25519 => |*key_pair| {
            const bytes = (key_pair.sign(message, null) catch return Error.SigningFailed).toBytes();
            @memcpy(out[0..bytes.len], &bytes);
            return out[0..bytes.len];
        },
        .ed448 => |*secret| {
            var signature: ed448.Signature = undefined;
            ed448.sign(message, secret.*, ed448.derivePublicKey(secret.*), &signature);
            @memcpy(out[0..signature.len], &signature);
            return out[0..signature.len];
        },
    }
}

/// One `sign` call for both ECDSA schemes. A null noise value derives the nonce
/// deterministically from the message digest and the private scalar, the
/// RFC 6979 construction: two signatures over different data never share a
/// nonce, and the same key and data always reproduce the same signature, which
/// is what makes a signed zone verifiable byte for byte.
fn signEcdsa(
    comptime Scheme: type,
    key_pair: Scheme.KeyPair,
    message: []const u8,
) Error!Scheme.Signature {
    return key_pair.sign(message, null) catch Error.SigningFailed;
}

/// RFC 3110 section 2: the DNSKEY public key of an RSA key.
fn rsaPublicKeyBytes(key: RsaKey, buffer: []u8) []const u8 {
    const exponent = key.exponentBytes();
    const modulus = key.modulusBytes();
    var len: usize = 0;
    if (exponent.len < 256) {
        buffer[0] = @intCast(exponent.len);
        len = 1;
    } else {
        buffer[0] = 0;
        std.mem.writeInt(u16, buffer[1..3], @intCast(exponent.len), .big);
        len = 3;
    }
    @memcpy(buffer[len..][0..exponent.len], exponent);
    len += exponent.len;
    @memcpy(buffer[len..][0..modulus.len], modulus);
    len += modulus.len;
    return buffer[0..len];
}

/// RFC 8017 section 9.2, RSASSA-PKCS1-v1_5 with the DigestInfo the DNS
/// algorithm names (RFC 5702 section 3): EM = 0x00 || 0x01 || PS || 0x00 || T,
/// and the signature is EM^d mod n, encoded in k octets.
fn rsaPkcs1Sign(key: *const RsaKey, message: []const u8, out: []u8, comptime Hash: type) Error![]const u8 {
    const k: usize = key.modulus_len;
    // RFC 5702 sections 2.1 and 2.2: 512 bits is the floor for SHA-256 and
    // 1024 bits for SHA-512.
    const min_modulus: usize = if (Hash == std.crypto.hash.sha2.Sha512) 128 else 64;
    if (k < min_modulus or k > max_rsa_modulus_bytes or out.len < k) return Error.SigningFailed;
    const prefix = digestInfoPrefix(Hash);
    const t_len = prefix.len + Hash.digest_length;
    if (k < t_len + 11) return Error.SigningFailed;
    var em: [max_rsa_modulus_bytes]u8 = @splat(0);
    em[0] = 0x00;
    em[1] = 0x01;
    const padding = k - t_len - 3;
    @memset(em[2..][0..padding], 0xff);
    em[2 + padding] = 0x00;
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &digest, .{});
    @memcpy(em[3 + padding ..][0..prefix.len], prefix);
    @memcpy(em[3 + padding + prefix.len ..][0..digest.len], &digest);

    const Modulus = std.crypto.ff.Modulus(max_rsa_modulus_bytes * 8);
    const modulus = Modulus.fromBytes(key.modulusBytes(), .big) catch return Error.SigningFailed;
    const base = Modulus.Fe.fromBytes(modulus, em[0..k], .big) catch return Error.SigningFailed;
    // The exponent is the private one, so the constant-time path is required.
    const signature = modulus.powWithEncodedExponent(base, key.privateBytes(), .big) catch return Error.SigningFailed;
    signature.toBytes(out[0..k], .big) catch return Error.SigningFailed;
    return out[0..k];
}

fn digestInfoPrefix(comptime Hash: type) []const u8 {
    return switch (Hash) {
        std.crypto.hash.sha2.Sha256 => &[_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
        std.crypto.hash.sha2.Sha512 => &[_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
        else => @compileError("no PKCS#1 DigestInfo for this hash"),
    };
}

/// One DER element: tag and value, with the definite length forms a
/// PKCS#1 RSAPrivateKey uses (RFC 8017 A.1.2).
const DerElement = struct {
    tag: u8,
    value: []const u8,
};

fn derElement(bytes: []const u8, offset: *usize) Error!DerElement {
    if (offset.* + 2 > bytes.len) return Error.BadKeyFile;
    const tag = bytes[offset.*];
    offset.* += 1;
    var len: usize = bytes[offset.*];
    offset.* += 1;
    if (len & 0x80 != 0) {
        const count = len & 0x7f;
        if (count == 0 or count > 2 or offset.* + count > bytes.len) return Error.BadKeyFile;
        len = 0;
        for (bytes[offset.*..][0..count]) |byte| len = (len << 8) | byte;
        offset.* += count;
    }
    if (offset.* + len > bytes.len) return Error.BadKeyFile;
    const value = bytes[offset.*..][0..len];
    offset.* += len;
    return .{ .tag = tag, .value = value };
}

fn stripLeadingZero(bytes: []const u8) []const u8 {
    var index: usize = 0;
    while (index + 1 < bytes.len and bytes[index] == 0) index += 1;
    return bytes[index..];
}

/// RFC 8017 A.1.2: the modulus, the public exponent, and the private exponent
/// of a PKCS#1 RSAPrivateKey. The primes are not needed for a single
/// exponentiation and are skipped.
fn rsaKeyFromDer(der: []const u8) Error!RsaKey {
    var offset: usize = 0;
    const sequence = try derElement(der, &offset);
    if (sequence.tag != 0x30) return Error.BadKeyFile;
    var inner: usize = 0;
    _ = try derElement(sequence.value, &inner); // version
    const modulus_element = try derElement(sequence.value, &inner);
    const exponent_element = try derElement(sequence.value, &inner);
    const private_element = try derElement(sequence.value, &inner);
    if (modulus_element.tag != 0x02 or exponent_element.tag != 0x02 or private_element.tag != 0x02) {
        return Error.BadKeyFile;
    }
    const modulus = stripLeadingZero(modulus_element.value);
    const exponent = stripLeadingZero(exponent_element.value);
    const private_exponent = stripLeadingZero(private_element.value);
    var key = RsaKey{};
    if (modulus.len > key.modulus.len or exponent.len > key.exponent.len or private_exponent.len > key.private_exponent.len) {
        return Error.BadKeyFile;
    }
    if (modulus.len == 0 or exponent.len == 0 or private_exponent.len == 0) return Error.BadKeyFile;
    @memcpy(key.modulus[0..modulus.len], modulus);
    @memcpy(key.exponent[0..exponent.len], exponent);
    @memcpy(key.private_exponent[0..private_exponent.len], private_exponent);
    key.modulus_len = @intCast(modulus.len);
    key.exponent_len = @intCast(exponent.len);
    key.private_len = @intCast(private_exponent.len);
    return key;
}

// ------------------------------------------------------------------ key file

/// Reads the project key file: one whitespace-separated `<algorithm> <secret>`
/// pair per line, the secret being the base64 private scalar (ECDSA), seed
/// (Ed25519), or 57-octet secret (Ed448, RFC 8080 section 3). Blank lines and
/// `#` comments are skipped. The key is not named here: the signer is always
/// told which zone it signs, and a DNSKEY owner is
/// that zone's apex by definition (RFC 4034 section 5.1.1), so a name in the
/// file could only ever be wrong.
pub fn parseKey(text: []const u8) Error!Key {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const hash = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
        const line = std.mem.trim(u8, raw_line[0..hash], " \t\r");
        if (line.len == 0) continue;
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const algorithm_text = tokens.next() orelse return Error.BadKeyFile;
        const secret_text = tokens.next() orelse return Error.BadKeyFile;
        if (tokens.next() != null) return Error.BadKeyFile;
        return keyFromBase64(algorithm_text, secret_text);
    }
    return Error.BadKeyFile;
}

fn keyFromBase64(algorithm_text: []const u8, secret_text: []const u8) Error!Key {
    var decoded: [4096]u8 = undefined;
    const expected = std.base64.standard.Decoder.calcSizeForSlice(secret_text) catch return Error.BadSecret;
    if (expected > decoded.len) return Error.BadSecret;
    std.base64.standard.Decoder.decode(decoded[0..expected], secret_text) catch return Error.BadSecret;
    defer std.crypto.secureZero(u8, &decoded);

    if (std.ascii.eqlIgnoreCase(algorithm_text, "ecdsap256sha256")) {
        if (expected != EcdsaP256Sha256.SecretKey.encoded_length) return Error.BadSecret;
        const scalar: [EcdsaP256Sha256.SecretKey.encoded_length]u8 = decoded[0..EcdsaP256Sha256.SecretKey.encoded_length].*;
        const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch return Error.BadSecret;
        return .{ .material = .{ .ecdsa_p256_sha256 = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return Error.BadSecret } };
    }
    if (std.ascii.eqlIgnoreCase(algorithm_text, "ecdsap384sha384")) {
        if (expected != EcdsaP384Sha384.SecretKey.encoded_length) return Error.BadSecret;
        const scalar: [EcdsaP384Sha384.SecretKey.encoded_length]u8 = decoded[0..EcdsaP384Sha384.SecretKey.encoded_length].*;
        const secret_key = EcdsaP384Sha384.SecretKey.fromBytes(scalar) catch return Error.BadSecret;
        return .{ .material = .{ .ecdsa_p384_sha384 = EcdsaP384Sha384.KeyPair.fromSecretKey(secret_key) catch return Error.BadSecret } };
    }
    if (std.ascii.eqlIgnoreCase(algorithm_text, "rsasha256")) {
        const key = try rsaKeyFromDer(decoded[0..expected]);
        // RFC 5702 section 2.1: RSA/SHA-256 keys are 512 to 4096 bits.
        if (key.modulus_len < 64 or key.modulus_len > 512) return Error.BadSecret;
        return .{ .material = .{ .rsa_sha256 = key } };
    }
    if (std.ascii.eqlIgnoreCase(algorithm_text, "rsasha512")) {
        const key = try rsaKeyFromDer(decoded[0..expected]);
        // RFC 5702 section 2.2: RSA/SHA-512 keys are 1024 to 4096 bits.
        if (key.modulus_len < 128 or key.modulus_len > 512) return Error.BadSecret;
        return .{ .material = .{ .rsa_sha512 = key } };
    }
    if (std.ascii.eqlIgnoreCase(algorithm_text, "ed25519")) {
        if (expected != Ed25519.KeyPair.seed_length) return Error.BadSecret;
        const seed: [Ed25519.KeyPair.seed_length]u8 = decoded[0..Ed25519.KeyPair.seed_length].*;
        return .{ .material = .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch return Error.BadSecret } };
    }
    if (std.ascii.eqlIgnoreCase(algorithm_text, "ed448")) {
        if (expected != @sizeOf(ed448.SecretKey)) return Error.BadSecret;
        const secret: ed448.SecretKey = decoded[0..@sizeOf(ed448.SecretKey)].*;
        return .{ .material = .{ .ed448 = secret } };
    }
    return Error.BadKeyFile;
}

// ---------------------------------------------------------------- zone model

/// One loaded zone record reduced to what signing needs: the owner in canonical
/// wire form and RDATA already canonicalised with no compression.
const Entry = struct {
    owner_wire: []const u8,
    rrtype: u16,
    ttl: u32,
    rdata: []const u8,
};

/// Everything the signer signs: one owner name, one type, and that RRset's
/// RDATA in canonical order (RFC 4034 section 6.3).
const Rrset = struct {
    owner_wire: []const u8,
    rrtype: u16,
    ttl: u32,
    rdata: []const []const u8,
};

/// The signature window the caller picks, in seconds since the epoch
/// (RFC 4034 section 3.1.5). The loader passes wall-clock values; tests pass
/// fixed ones so every produced signature is reproducible.
pub const Options = struct {
    inception: u32,
    expiration: u32,
    /// The chain the operator chose for the signed zones. Null leaves the
    /// zone's own apex NSEC3PARAM in charge, which is what the server did
    /// before the operator could choose.
    chain: ?ChainPolicy = null,
    zonemd: ?zonemd.Hash = null,

    /// The same window counted from `now`: the validity period the server
    /// was configured with, starting at the moment of the signing
    /// (RFC 4034 section 3.1.5). The expiration saturates, because the field
    /// cannot state a date past the range of its 32 bits.
    pub fn fromNow(self: Options, now: u32) Options {
        return .{
            .inception = now,
            .expiration = now +| (self.expiration -| self.inception),
            .chain = self.chain,
            .zonemd = self.zonemd,
        };
    }
};

/// The chain a signed zone publishes: the RFC 4034 section 6.1 NSEC chain or
/// the RFC 5155 section 7.1 NSEC3 chain. The choice is the operator's, not
/// the RFC's: both chains are valid, and the RFCs say how a chain is built
/// once a zone publishes one.
pub const Chain = enum { nsec, nsec3 };

/// The operator's chain, with the parameters of an NSEC3 chain
/// (RFC 5155 section 4.1): the iteration count and the salt. The hash
/// algorithm is SHA-1. The Opt-Out flag is not the operator's to name: the
/// zone's own apex NSEC3PARAM states it (RFC 5155 section 3.1.2.1). RFC 9276
/// section 3.1 says an operator SHOULD NOT use a salt, so a chain that names
/// one is refused.
pub const ChainPolicy = struct {
    chain: Chain,
    iterations: u16 = 0,
    salt: []const u8 = "",
};

/// The signing material the serving path keeps once the zone has been signed:
/// the private key and the window every signature it makes uses. An RRset that
/// is not in the zone file -- the RFC 8482 minimal answer -- can only be
/// signed while the key is still held, so the key outlives the startup
/// signing pass and is wiped when the holder is deinited.
pub const Session = struct {
    key: Key,
    options: Options,

    /// Take over a copy of `key` and the window every signature uses.
    pub fn start(key: *const Key, options: Options) Session {
        return .{ .key = key.*, .options = options };
    }

    /// Wipes the private key.
    pub fn deinit(self: *Session) void {
        self.key.deinit();
    }
};

/// Signs `zone` in place: appends the apex DNSKEY, one NSEC per
/// authoritative owner name, and one RRSIG per RRset. The zone's SOA serial is
/// left alone -- nothing is written back to disk, so the published zone is
/// unchanged and a serial that moved on every restart would only churn
/// secondaries for no content change.
///
/// A key signs one zone only: RFC 8080 section 8 forbids a private key that
/// signs a DNSSEC zone from being used for any other purpose, so a key that
/// has already signed a zone is refused for a second one.
///
/// Only the records handed to the zone outlive the call, and the zone owns
/// them. Everything else -- canonical RDATA, sorted RRsets, preimages -- is
/// built in an arena released here, so a caller that is not itself an arena
/// (the config loader signs from its own allocator) leaks nothing.
pub fn signZone(
    allocator: std.mem.Allocator,
    zone: *zone_index.Zone,
    key: *Key,
    options: Options,
) Error!void {
    if (zone.soa == null) return Error.BadZoneRecord;
    if (alreadySigned(zone)) return Error.AlreadySigned;
    // RFC 6781 section 4.1.2: the second key-signing key signs the DNSKEY
    // RRset beside the first, and the parent DS states the first, so a second key
    // with no first has nothing to sign beside.
    if (key.published_ksk != null and key.ksk == null) return Error.BadKeyFile;

    const origin = Name.fromText(zone.originText()) catch return Error.BadZoneRecord;
    // RFC 8080 section 8: a private key used for a DNSSEC zone must not be
    // used for any other purpose than for that zone, so a key that has signed
    // one zone is refused for a second one. The key-signing key is a key of
    // its own and answers for itself.
    try claimZone(Key, key, origin);
    if (key.ksk) |*ksk| try claimZone(Ksk, ksk, origin);
    if (key.published_ksk) |*ksk| try claimZone(Ksk, ksk, origin);

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

    // The chain the zone publishes is settled before the zone's records are
    // collected: an apex NSEC3PARAM states the parameters of the chain the
    // zone publishes (RFC 5155 section 7.3), so a zone that publishes the
    // NSEC chain must not keep one.
    const chain = try selectChain(work, zone, options.chain);
    if (chain.kind == .nsec) dropApexNsec3Param(zone);

    var entries: std.ArrayList(Entry) = .empty;
    try collectEntries(work, zone, &entries);

    const soa_ttl = try soaMinimum(zone);
    const origin_wire = try work.dupe(u8, origin.asWire());

    var authoritative: std.ArrayList(Entry) = .empty;
    try selectAuthoritative(work, entries.items, origin_wire, &authoritative);

    var rrsets: std.ArrayList(Rrset) = .empty;
    try groupRrsets(work, authoritative.items, &rrsets);

    // The apex key records join before the NSEC chain is built so the apex
    // bitmap names the types the zone really has. Appending them breaks the
    // canonical order `groupRrsets` produced, so it is restored here: the NSEC
    // walk below relies on every owner occupying one contiguous run.
    //
    // RFC 6781 section 3.1: a zone that separates the roles publishes both
    // keys, and the parent DS states the key-signing key, the key the parent points
    // at. A zone with one key publishes that key twice: once with the Zone
    // Key flag alone, which signs the zone data, and once with the Secure
    // Entry Point flag, which signs the DNSKEY RRset and is the key a parent's
    // DS names. External verifiers (BIND `dnssec-verify`) require a ZSK
    // beside the KSK and reject a zone whose only key carries flags 257.
    const zsk_dnskey = try key.dnskeyRdataWithFlags(work, zone_key_flag);
    const ksk_rdata = if (key.ksk) |*ksk|
        try dnskeyRdataOf(ksk.material, work, dnskey_flags)
    else
        try key.dnskeyRdataWithFlags(work, dnskey_flags);
    var key_rdata: [3][]const u8 = undefined;
    key_rdata[0] = zsk_dnskey;
    key_rdata[1] = ksk_rdata;
    var key_count: usize = 2;
    // RFC 6781 section 4.1.2: the second key-signing key of a
    // Double-Signature rollover is published beside the first and signs the
    // DNSKEY RRset with it.
    var published_ksk_tag: u16 = 0;
    if (key.published_ksk) |*ksk| {
        // RFC 6781 section 4.1.2.1: the key being removed is published with
        // the REVOKE bit of RFC 5011 section 3 set, beside the flags every
        // key of the zone carries.
        const flags: u16 = if (ksk.revoked) dnskey_flags | revoke_flag else dnskey_flags;
        key_rdata[key_count] = try dnskeyRdataOf(ksk.material, work, flags);
        published_ksk_tag = dns_dnssec.keyTag(key_rdata[key_count]);
        key_count += 1;
    }
    try appendDnskeys(work, origin_wire, soa_ttl, key_rdata[0..key_count], &rrsets);
    const ksk_tag: u16 = dns_dnssec.keyTag(ksk_rdata);
    // RFC 4035 section 2.2: the DS RRset that authorizes this zone's key
    // lives in the parent zone, not at the child apex. The signer publishes
    // the DNSKEY and leaves the DS to the parent; an apex DS would be data
    // this zone cannot vouch for, and external verifiers reject it.
    std.mem.sort(Rrset, rrsets.items, {}, rrsetLessThan);
    // RFC 8976 ZONEMD publishing: the placeholder RRset is present before the
    // chain is built so the denial bitmap names type 63. Its digest is zero;
    // the real digest and signature are installed after emit, when every
    // other generated record exists. A zone that already carries an apex
    // ZONEMD keeps it, and the loader verifies it.
    var publish_zonemd: ?zonemd.Hash = null;
    var zonemd_serial: u32 = 0;
    if (options.zonemd) |hash| {
        if (!zonemd.hasApexRecord(zone)) {
            publish_zonemd = hash;
            const soa_record = zone.soa orelse return Error.BadZoneRecord;
            const soa_rdata = zone_parser.parseRData(RecordType.SOA, soa_record.rdataText()) catch return Error.BadZoneRecord;
            if (soa_rdata != .SOA) return Error.BadZoneRecord;
            zonemd_serial = soa_rdata.SOA.serial;
            const placeholder = try work.alloc(u8, 6 + hash.digestLen());
            std.mem.writeInt(u32, placeholder[0..4], zonemd_serial, .big);
            placeholder[4] = @backingInt(zonemd.Scheme.simple);
            placeholder[5] = @backingInt(hash);
            @memset(placeholder[6..], 0);
            try appendSingle(work, origin_wire, RecordType.ZONEMD.code(), soa_ttl, placeholder, &rrsets);
            std.mem.sort(Rrset, rrsets.items, {}, rrsetLessThan);
        }
    }

    // An apex NSEC3PARAM is the opt-in: the zone states the parameters of the
    // chain it publishes, and the signer builds that chain (RFC 5155 section
    // 7.1). A zone without one keeps the NSEC chain it always had. The
    // operator's choice, when there is one, replaces that opt-in.
    switch (chain.kind) {
        .nsec => try appendNsecChain(work, &rrsets, soa_ttl),
        .nsec3 => {
            // RFC 5155 section 7.3: the parameters of the chain are stated by
            // the NSEC3PARAM at the zone apex, so a zone that states none gets
            // the one the operator named.
            if (chain.publish_param) {
                try appendSingle(work, origin_wire, RecordType.NSEC3PARAM.code(), soa_ttl, try nsec3paramRdata(work, chain.params), &rrsets);
                std.mem.sort(Rrset, rrsets.items, {}, rrsetLessThan);
            }
            try appendNsec3Chain(work, &rrsets, origin_wire, soa_ttl, chain.params);
        },
    }
    try emit(work, allocator, zone, key, dns_dnssec.keyTag(zsk_dnskey), ksk_tag, published_ksk_tag, options, rrsets.items, chain.publish_param, publish_zonemd != null);
    if (publish_zonemd) |hash| {
        var digest: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
        zonemd.computeDigestServed(zone, hash, allocator, &digest) catch return Error.BadZoneRecord;
        const real_rdata = try work.alloc(u8, 6 + hash.digestLen());
        std.mem.writeInt(u32, real_rdata[0..4], zonemd_serial, .big);
        real_rdata[4] = @backingInt(zonemd.Scheme.simple);
        real_rdata[5] = @backingInt(hash);
        @memcpy(real_rdata[6..], digest[0..hash.digestLen()]);
        const zonemd_record = try genericRecord(allocator, origin_wire, RecordType.ZONEMD.code(), soa_ttl, real_rdata);
        const rrsig_rdata = try signDataRrset(allocator, origin, origin, RecordType.ZONEMD.code(), &.{real_rdata}, soa_ttl, key, options);
        defer allocator.free(rrsig_rdata);
        const rrsig_record = try genericRecord(allocator, origin_wire, RecordType.RRSIG.code(), soa_ttl, rrsig_rdata);
        try appendGenerated(allocator, zone, &.{ zonemd_record, rrsig_record });
    }
    // The signed zone carries the records the signer generated, so the full
    // transfer of the zone is larger than the one the zone file holds.
    zone_index.registerZoneSize(zone);
}

/// Signs `zone` again with the chain `served` publishes, so a zone that is
/// reloaded keeps the chain the validators have already seen. The key is the
/// one the server holds, so the key tag (RFC 4034 section 3.1.6) and the DS
/// that states it (section 5.1.1) do not move.
pub fn resignZone(
    allocator: std.mem.Allocator,
    zone: *zone_index.Zone,
    key: *Key,
    options: Options,
    served: *const zone_index.Zone,
) Error!void {
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var effective = options;
    effective.chain = try chainPolicyOf(scratch.allocator(), served);
    try signZone(allocator, zone, key, effective);
}

/// The chain a signed zone publishes. The NSEC3 parameters come from the apex
/// NSEC3PARAM, the record that states them (RFC 5155 section 4.1).
fn chainPolicyOf(allocator: std.mem.Allocator, served: *const zone_index.Zone) Error!ChainPolicy {
    var has_nsec = false;
    var has_nsec3 = false;
    for (served.records.items[0..served.records.len]) |record| {
        if (record.rrtype.eql(.NSEC)) has_nsec = true;
        if (record.rrtype.eql(.NSEC3)) has_nsec3 = true;
    }
    if (has_nsec3) {
        const params = (try apexNsec3Param(allocator, served)) orelse return Error.BadChainParameters;
        return .{ .chain = .nsec3, .iterations = params.iterations, .salt = params.salt };
    }
    if (has_nsec) return .{ .chain = .nsec };
    return Error.BadChainParameters;
}

/// The chain the zone publishes. Without the operator's choice the zone's own
/// apex NSEC3PARAM is the opt-in, as it always was. With it the operator's
/// chain wins, and an NSEC3 chain takes its parameters from the zone's own
/// NSEC3PARAM when the zone states one, because that record states the
/// parameters of the chain (RFC 5155 section 4.1). The operator's NSEC choice
/// drops the zone's own apex NSEC3PARAM, because that record states the chain
/// the zone publishes (RFC 5155 section 7.3).
fn selectChain(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    policy: ?ChainPolicy,
) Error!ChainChoice {
    const wanted = policy orelse {
        const params = try apexNsec3Param(allocator, zone) orelse return .{ .kind = .nsec };
        try checkPublishable(params);
        return .{ .kind = .nsec3, .params = params };
    };
    if (wanted.chain == .nsec) return .{ .kind = .nsec };
    const params = Nsec3Params{
        .algorithm = 1,
        .flags = 0,
        .iterations = wanted.iterations,
        .salt = wanted.salt,
    };
    try checkPublishable(params);
    const found = try apexNsec3Param(allocator, zone) orelse
        return .{ .kind = .nsec3, .params = params, .publish_param = true };
    // The zone states the parameters of its own chain, so the operator's
    // choice must name the same ones.
    if (found.iterations != params.iterations or !std.mem.eql(u8, found.salt, params.salt)) {
        return Error.BadChainParameters;
    }
    return .{ .kind = .nsec3, .params = found };
}

/// RFC 9276 section 3.1: "If NSEC3 must be used, then an iterations count of
/// 0 MUST be used to alleviate computational burdens" and "Operators SHOULD
/// NOT use a salt by indicating a zero-length salt value instead". A chain
/// above that count is one a validator treats the answer it proves as
/// insecure over (RFC 9276 section 3.2), and a chain with a salt is one the
/// RFC asks the operator not to publish, so the signer refuses to publish
/// either.
fn checkPublishable(params: Nsec3Params) Error!void {
    if (params.iterations != 0) return Error.InsecureChainParameters;
    if (params.salt.len != 0) return Error.InsecureChainParameters;
}

/// The chain the zone publishes, with the parameters of an NSEC3 chain.
const ChainChoice = struct {
    kind: Chain,
    params: Nsec3Params = .{ .algorithm = 1, .flags = 0, .iterations = 0, .salt = "" },
    /// True when the signer publishes the apex NSEC3PARAM itself, because the
    /// zone states none.
    publish_param: bool = false,
};

/// Removes the apex NSEC3PARAM from the zone. The record states the
/// parameters of the chain the zone publishes (RFC 5155 section 7.3), so a
/// zone that publishes the NSEC chain must not carry one: a validator that
/// reads the record looks for NSEC3 records and finds none. The record is
/// dropped before the zone is signed, so it is neither published nor signed.
fn dropApexNsec3Param(zone: *zone_index.Zone) void {
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const record = zone.records.items[index];
        if (!record.rrtype.eql(.NSEC3PARAM)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        std.mem.copyForwards(
            zone_parser.ZoneRecord,
            zone.records.items[index .. zone.records.len - 1],
            zone.records.items[index + 1 .. zone.records.len],
        );
        zone.records.len -= 1;
        return;
    }
}

/// Sign one RRset the caller already holds and return the RRSIG RDATA to
/// publish beside it (RFC 4034 section 3.1). `signZone` deliberately refuses a
/// zone that already carries DNSSEC records, so denial records a zone file
/// supplies itself -- an NSEC3 chain, or the NSEC a parent zone publishes at a
/// delegation -- cannot be signed through it. The validator's tests are the
/// caller that needs this; the serving path does not. `signer` is the zone that
/// makes the signature, which is not always the RRset's owner: the NSEC a
/// parent publishes at a delegation is owned by the child name and signed by
/// the parent.
pub fn signRrset(
    allocator: std.mem.Allocator,
    owner: Name,
    signer: Name,
    rrtype: u16,
    rdatas: []const []const u8,
    ttl: u32,
    key: *const Key,
    options: Options,
) Error![]const u8 {
    return signRrsetWithFlags(allocator, owner, signer, rrtype, rdatas, ttl, key, key_signing_flags, options);
}

/// Signs a data RRset with the zone-signing form, the key the zone publishes
/// over its ordinary records and the tag those RRSIGs name.
pub fn signDataRrset(
    allocator: std.mem.Allocator,
    owner: Name,
    signer: Name,
    rrtype: u16,
    rdatas: []const []const u8,
    ttl: u32,
    key: *const Key,
    options: Options,
) Error![]const u8 {
    return signRrsetWithFlags(allocator, owner, signer, rrtype, rdatas, ttl, key, zone_key_flags, options);
}

fn signRrsetWithFlags(
    allocator: std.mem.Allocator,
    owner: Name,
    signer: Name,
    rrtype: u16,
    rdatas: []const []const u8,
    ttl: u32,
    key: *const Key,
    key_flags: u16,
    options: Options,
) Error![]const u8 {
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

    const order = try work.dupe([]const u8, rdatas);
    const dnskey_rdata = try key.dnskeyRdataWithFlags(work, key_flags);
    const signed = try signedData(
        work,
        .{ .owner_wire = owner.asWire(), .rrtype = rrtype, .ttl = ttl, .rdata = order },
        key.algorithm(),
        dns_dnssec.keyTag(dnskey_rdata),
        signer.asWire(),
        options,
    );
    var rdata_buffer: [max_rrsig_rdata_local_len]u8 = undefined;
    @memcpy(rdata_buffer[0..signed.header_len], signed.bytes[0..signed.header_len]);
    const signature = try key.sign(signed.bytes, rdata_buffer[signed.header_len..]);
    return allocator.dupe(u8, rdata_buffer[0 .. signed.header_len + signature.len]);
}

/// RFC 4034 section 6.3 RDATA octet order, for putting an RRset in the order
/// the signature covers it.
fn rdataLessThan(_: void, left: []const u8, right: []const u8) bool {
    return zonemd.octetOrder(left, right) == .lt;
}

fn soaMinimum(zone: *const zone_index.Zone) Error!u32 {
    const soa_record = zone.soa orelse return Error.BadZoneRecord;
    const rdata = zone_parser.parseRData(RecordType.SOA, soa_record.rdataText()) catch return Error.BadZoneRecord;
    return switch (rdata) {
        .SOA => |soa| soa.minimum,
        else => Error.BadZoneRecord,
    };
}

/// A zone that already carries its own DNSSEC records is left alone: signing it
/// would append a second, conflicting RRSIG and NSEC RRset at every name. The
/// apex NSEC3PARAM is the one exception: it states the parameters of the chain
/// the signer is asked to build (RFC 5155 section 7.1), not a denial of its
/// own.
fn alreadySigned(zone: *const zone_index.Zone) bool {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.RRSIG) or record.rrtype.eql(.NSEC) or
            record.rrtype.eql(.NSEC3) or record.rrtype.eql(.DNSKEY)) return true;
    }
    return false;
}

fn collectEntries(allocator: std.mem.Allocator, zone: *const zone_index.Zone, entries: *std.ArrayList(Entry)) Error!void {
    // A record of a type this server does not implement carries its RDATA
    // whole, so the buffer holds the opaque bound, not the signer's own.
    const buffer = allocator.alloc(u8, dns_rdata.max_opaque_rdata_len) catch return Error.OutOfMemory;
    defer allocator.free(buffer);
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!zone.contains(record.ownerText())) continue;
        const owner = Name.fromText(record.ownerText()) catch return Error.BadZoneRecord;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.BadZoneRecord;
        var writer = dns_writer.Writer.init(buffer);
        rdata.encode(&writer) catch return Error.BadZoneRecord;
        try entries.append(allocator, .{
            .owner_wire = try allocator.dupe(u8, owner.asWire()),
            .rrtype = record.rrtype.code(),
            .ttl = record.ttl,
            .rdata = try allocator.dupe(u8, writer.written()),
        });
    }
}

/// True when `owner` is `ancestor` or sits below it. Both are canonical wire
/// names, so a suffix match on whole labels is exact.
fn withinOrEqual(owner: []const u8, ancestor: []const u8) bool {
    if (owner.len < ancestor.len) return false;
    return std.mem.eql(u8, owner[owner.len - ancestor.len ..], ancestor);
}

/// RFC 4035 section 2.3: NSEC and RRSIG belong to the names the parent zone is
/// authoritative for, and to a delegation point itself with only its NS and DS
/// RRsets. Everything strictly below a delegation point, glue address RRsets
/// included, belongs to the child.
fn selectAuthoritative(
    allocator: std.mem.Allocator,
    entries: []const Entry,
    origin_wire: []const u8,
    out: *std.ArrayList(Entry),
) Error!void {
    // The delegation set is collected once: a zone delegates to as many child
    // zones as it has non-apex NS RRsets, which is a short list, so one pass
    // per entry stays linear in the zone size.
    var delegations: std.ArrayList([]const u8) = .empty;
    defer delegations.deinit(allocator);
    for (entries) |entry| {
        if (entry.rrtype != RecordType.NS.code()) continue;
        if (std.mem.eql(u8, entry.owner_wire, origin_wire)) continue;
        if (delegations.items.len != 0 and std.mem.eql(u8, delegations.items[delegations.items.len - 1], entry.owner_wire)) continue;
        try delegations.append(allocator, entry.owner_wire);
    }

    for (entries) |entry| {
        var below_delegation = false;
        for (delegations.items) |delegation| {
            if (!withinOrEqual(entry.owner_wire, delegation)) continue;
            if (std.mem.eql(u8, entry.owner_wire, delegation)) {
                if (entry.rrtype != RecordType.NS.code() and entry.rrtype != RecordType.DS.code()) continue;
            } else {
                below_delegation = true;
            }
            break;
        }
        if (below_delegation) continue;
        try out.append(allocator, entry);
    }
}

fn entryLessThan(entries: []const Entry, left_index: usize, right_index: usize) bool {
    const left = entries[left_index];
    const right = entries[right_index];
    const name_order = zonemd.canonicalNameOrder(left.owner_wire, right.owner_wire);
    if (name_order != .eq) return name_order == .lt;
    if (left.rrtype != right.rrtype) return left.rrtype < right.rrtype;
    return zonemd.octetOrder(left.rdata, right.rdata) == .lt;
}

/// Owner in canonical order, then ascending RR type: the grouping order the NSEC
/// walk assumes, independent of the zone file's own record order.
fn rrsetLessThan(_: void, left: Rrset, right: Rrset) bool {
    const name_order = zonemd.canonicalNameOrder(left.owner_wire, right.owner_wire);
    if (name_order != .eq) return name_order == .lt;
    return left.rrtype < right.rrtype;
}

/// Groups entries into RRsets in canonical order, each carrying the minimum TTL
/// of its records. An index array is sorted rather than the entries themselves
/// for the same reason [`zonemd.canonicalEntries`] does one: an Entry carries
/// slice headers, and moving values through the sort would copy far more than
/// the comparator reads.
fn groupRrsets(allocator: std.mem.Allocator, entries: []const Entry, rrsets: *std.ArrayList(Rrset)) Error!void {
    const order = try allocator.alloc(usize, entries.len);
    for (order, 0..) |*slot, index| slot.* = index;
    std.mem.sort(usize, order, entries, entryLessThan);

    var start: usize = 0;
    while (start < order.len) {
        const head = entries[order[start]];
        var end = start;
        var ttl = head.ttl;
        while (end < order.len) : (end += 1) {
            const candidate = entries[order[end]];
            if (candidate.rrtype != head.rrtype) break;
            if (!std.mem.eql(u8, candidate.owner_wire, head.owner_wire)) break;
            ttl = @min(ttl, candidate.ttl);
        }
        const rdata = try allocator.alloc([]const u8, end - start);
        for (rdata, start..) |*slot, offset| slot.* = entries[order[offset]].rdata;
        try rrsets.append(allocator, .{
            .owner_wire = head.owner_wire,
            .rrtype = head.rrtype,
            // RFC 4034 section 6.2: the RRset is signed at its minimum TTL.
            .ttl = ttl,
            .rdata = rdata,
        });
        start = end;
    }
}

fn appendSingle(
    allocator: std.mem.Allocator,
    owner_wire: []const u8,
    rrtype: u16,
    ttl: u32,
    rdata: []const u8,
    rrsets: *std.ArrayList(Rrset),
) Error!void {
    const single = try allocator.alloc([]const u8, 1);
    single[0] = rdata;
    try rrsets.append(allocator, .{
        .owner_wire = owner_wire,
        .rrtype = rrtype,
        .ttl = ttl,
        .rdata = single,
    });
}

/// The apex DNSKEY RRset: one RDATA per key the zone publishes, in the
/// canonical order the signature covers them in (RFC 4034 section 6.3).
fn appendDnskeys(
    allocator: std.mem.Allocator,
    owner_wire: []const u8,
    ttl: u32,
    rdata: []const []const u8,
    rrsets: *std.ArrayList(Rrset),
) Error!void {
    const ordered = try allocator.alloc([]const u8, rdata.len);
    @memcpy(ordered, rdata);
    std.mem.sort([]const u8, ordered, {}, rdataLessThan);
    try rrsets.append(allocator, .{
        .owner_wire = owner_wire,
        .rrtype = RecordType.DNSKEY.code(),
        .ttl = ttl,
        .rdata = ordered,
    });
}

/// RFC 8080 section 8: a private key used for a DNSSEC zone must not be used
/// for any other purpose than for that zone, so a key that has signed one
/// zone is refused for a second one.
fn claimZone(comptime T: type, key: *T, origin: Name) Error!void {
    if (key.signed_zone) |signed| {
        if (!std.mem.eql(u8, signed.asWire(), origin.asWire())) return Error.KeyUsedForAnotherZone;
    } else {
        key.signed_zone = origin;
    }
}

/// The DNSKEY RDATA the zone publishes for its zone-signing key: RFC 4034
/// section 2.1.1 sets the Zone Key bit on every key, and RFC 6781 section
/// 3.2.3 sets the Secure Entry Point bit on the key-signing key and not on
/// the zone-signing key.
fn zoneSigningDnskey(key: *const Key, allocator: std.mem.Allocator) Error![]const u8 {
    // A zone with no separate key-signing key publishes this key as a
    // zone-signing key: RFC 4034 section 2.1.1's Secure Entry Point bit says
    // "this key is a key-signing key", and this one signs the zone data.
    // External verifiers (BIND dnssec-verify) require a ZSK for the data
    // RRsets and reject a zone whose only key is flagged as a KSK.
    const flags: u16 = zone_key_flag;
    return key.dnskeyRdataWithFlags(allocator, flags);
}

/// RFC 4034 section 4.1.2 type bitmap: one window per 256 type codes, each
/// holding the window number, an octet count, and the octets through the
/// highest type the owner really has.
fn typeBitmap(allocator: std.mem.Allocator, codes: []u16) Error![]const u8 {
    std.mem.sort(u16, codes, {}, std.sort.asc(u16));
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < codes.len) {
        const window: u8 = @intCast(codes[index] / 256);
        var bits = @as([32]u8, @splat(@as(u8, 0)));
        var last: usize = 0;
        while (index < codes.len and codes[index] / 256 == window) : (index += 1) {
            const bit: u16 = codes[index] % 256;
            bits[bit / 8] |= @as(u8, 0x80) >> @intCast(bit % 8);
            last = @max(last, bit / 8);
        }
        try out.append(allocator, window);
        try out.append(allocator, @intCast(last + 1));
        try out.appendSlice(allocator, bits[0 .. last + 1]);
    }
    return out.toOwnedSlice(allocator);
}

/// RFC 4035 section 2.3: one NSEC at every authoritative owner name, each
/// pointing at the next name in canonical order with the last wrapping to the
/// first. The bitmap always names NSEC and RRSIG alongside the types the owner
/// really has. `rrsets` arrives sorted by owner, so one walk finds every group.
fn appendNsecChain(allocator: std.mem.Allocator, rrsets: *std.ArrayList(Rrset), ttl: u32) Error!void {
    var owners: std.ArrayList([]const u8) = .empty;
    defer owners.deinit(allocator);
    for (rrsets.items) |rrset| {
        if (owners.items.len != 0 and std.mem.eql(u8, owners.items[owners.items.len - 1], rrset.owner_wire)) continue;
        try owners.append(allocator, rrset.owner_wire);
    }

    var codes: std.ArrayList(u16) = .empty;
    defer codes.deinit(allocator);
    var group: usize = 0;
    for (owners.items, 0..) |owner_wire, index| {
        while (group < rrsets.items.len and !std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;
        const start = group;
        while (group < rrsets.items.len and std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;

        codes.clearRetainingCapacity();
        for (rrsets.items[start..group]) |rrset| try codes.append(allocator, rrset.rrtype);
        try codes.append(allocator, RecordType.NSEC.code());
        try codes.append(allocator, RecordType.RRSIG.code());

        const bitmap = try typeBitmap(allocator, codes.items);
        const next = owners.items[(index + 1) % owners.items.len];
        const rdata = try allocator.alloc(u8, next.len + bitmap.len);
        @memcpy(rdata[0..next.len], next);
        @memcpy(rdata[next.len..], bitmap);
        try appendSingle(allocator, owner_wire, RecordType.NSEC.code(), ttl, rdata, rrsets);
    }
}

// ------------------------------------------------------------------- NSEC3

/// RFC 5155 section 4: the parameters the apex NSEC3PARAM states. The chain
/// is built from them, so the record the operator writes is the record the
/// zone publishes.
const Nsec3Params = struct {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
};

/// The apex NSEC3PARAM of the zone, or null when the zone carries none. Only
/// SHA-1 (RFC 5155 section 3.1.1) is implemented, and the only flag a zone
/// may ask for is the Opt-Out one (RFC 5155 section 3.1.2.1), so a record
/// asking for anything else is refused rather than published with parameters
/// this build cannot honour.
fn apexNsec3Param(allocator: std.mem.Allocator, zone: *const zone_index.Zone) Error!?Nsec3Params {
    var found: ?Nsec3Params = null;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC3PARAM)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) return Error.BadZoneRecord;
        const parsed = zone_parser.parseRData(.NSEC3PARAM, record.rdataText()) catch return Error.BadZoneRecord;
        const bytes = switch (parsed) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.BadZoneRecord,
        };
        if (bytes.len < 5) return Error.BadZoneRecord;
        if (bytes[0] != 1) return Error.BadZoneRecord;
        // RFC 5155 section 3.1.2: every flag but the Opt-Out one is reserved
        // and must be zero.
        if (bytes[1] & ~dns_validate.nsec3_opt_out != 0) return Error.BadZoneRecord;
        found = .{
            .algorithm = bytes[0],
            .flags = bytes[1],
            .iterations = std.mem.readInt(u16, bytes[2..4], .big),
            .salt = try allocator.dupe(u8, bytes[5..]),
        };
    }
    return found;
}

/// RFC 5155 section 4.2: the NSEC3PARAM RDATA is the hash algorithm, the
/// flags, the iteration count, the salt length, and the salt.
fn nsec3paramRdata(allocator: std.mem.Allocator, params: Nsec3Params) Error![]const u8 {
    const rdata = try allocator.alloc(u8, 5 + params.salt.len);
    rdata[0] = params.algorithm;
    rdata[1] = params.flags;
    std.mem.writeInt(u16, rdata[2..4], params.iterations, .big);
    rdata[4] = @intCast(params.salt.len);
    @memcpy(rdata[5..], params.salt);
    return rdata;
}

/// RFC 5155 section 5: the hash of the canonical owner name, the same hash
/// the serving path and the validator compute.
fn nsec3HashOf(owner_wire: []const u8, params: Nsec3Params) Error![20]u8 {
    const parsed = Name.parse(owner_wire, 0) catch return Error.BadZoneRecord;
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(parsed.name, params.salt, params.iterations, &out);
    return out;
}

/// The parent of a wire name: the same name with its leftmost label removed.
fn parentWire(wire: []const u8) ?[]const u8 {
    if (wire.len < 2) return null;
    const label_len = wire[0];
    if (label_len == 0 or 1 + label_len >= wire.len) return null;
    return wire[1 + label_len ..];
}

fn ownerNameLessThan(_: void, left: []const u8, right: []const u8) bool {
    return zonemd.canonicalNameOrder(left, right) == .lt;
}

/// True when `name` is one of the zone's owner names, which arrive sorted in
/// canonical order.
fn isOwner(owners: []const []const u8, name: []const u8) bool {
    var low: usize = 0;
    var high: usize = owners.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const order = zonemd.canonicalNameOrder(owners[mid], name);
        if (order == .eq) return true;
        if (order == .lt) low = mid + 1 else high = mid;
    }
    return false;
}

/// One owner name of the chain: the hash it stands for and the types present
/// at the name itself.
const Nsec3Entry = struct {
    hash: [20]u8,
    codes: []u16,
};

fn nsec3EntryLessThan(_: void, left: Nsec3Entry, right: Nsec3Entry) bool {
    return std.mem.order(u8, &left.hash, &right.hash) == .lt;
}

/// RFC 5155 section 7.1: the NSEC3 chain a signed zone publishes. One NSEC3
/// per owner name -- every authoritative owner and every empty non-terminal --
/// sorted into hash order, each naming the next hash with the last wrapping to
/// the first. The type bitmap names the types present at the original owner
/// name, which per the same section never includes the NSEC3 type itself.
fn appendNsec3Chain(
    allocator: std.mem.Allocator,
    rrsets: *std.ArrayList(Rrset),
    origin_wire: []const u8,
    ttl: u32,
    params: Nsec3Params,
) Error!void {
    var owners: std.ArrayList([]const u8) = .empty;
    defer owners.deinit(allocator);
    for (rrsets.items) |rrset| {
        if (owners.items.len != 0 and std.mem.eql(u8, owners.items[owners.items.len - 1], rrset.owner_wire)) continue;
        try owners.append(allocator, rrset.owner_wire);
    }

    // RFC 5155 section 7.1: an empty non-terminal has an NSEC3 too, so the
    // closest encloser of a name below one can be proved.
    var ents: std.ArrayList([]const u8) = .empty;
    defer ents.deinit(allocator);
    for (owners.items) |owner_wire| {
        var parent = parentWire(owner_wire) orelse continue;
        while (parent.len > origin_wire.len) {
            if (isOwner(owners.items, parent)) break;
            try ents.append(allocator, parent);
            parent = parentWire(parent) orelse break;
        }
    }
    std.mem.sort([]const u8, ents.items, {}, ownerNameLessThan);
    var unique: usize = 0;
    for (ents.items) |name| {
        if (unique != 0 and std.mem.eql(u8, ents.items[unique - 1], name)) continue;
        ents.items[unique] = name;
        unique += 1;
    }
    ents.items.len = unique;

    var entries: std.ArrayList(Nsec3Entry) = .empty;
    defer entries.deinit(allocator);
    var codes: std.ArrayList(u16) = .empty;
    defer codes.deinit(allocator);
    const opt_out = (params.flags & dns_validate.nsec3_opt_out) != 0;
    var group: usize = 0;
    for (owners.items) |owner_wire| {
        while (group < rrsets.items.len and !std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;
        const start = group;
        while (group < rrsets.items.len and std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;
        codes.clearRetainingCapacity();
        var has_ns = false;
        var has_ds = false;
        for (rrsets.items[start..group]) |rrset| {
            try codes.append(allocator, rrset.rrtype);
            if (rrset.rrtype == RecordType.NS.code()) has_ns = true;
            if (rrset.rrtype == RecordType.DS.code()) has_ds = true;
        }
        // RFC 5155 section 7.1: an Opt-Out chain leaves the owner name of an
        // unsigned delegation out, and the record that covers its hash
        // carries the Opt-Out bit instead. The apex is not a delegation even
        // though it carries NS, and it keeps its NSEC3.
        if (opt_out and has_ns and !has_ds and !std.mem.eql(u8, owner_wire, origin_wire)) continue;
        // The RRSIG over every RRset at the name is a type present at the
        // name. A delegation whose NS RRset is left unsigned (RFC 4035
        // section 2.2) carries no signature at that owner, so its NSEC3
        // names NS alone; the RRSIG over the NSEC3 lives at the hashed
        // owner, which RFC 5155 section 7.1 excludes.
        const unsigned_delegation = has_ns and !has_ds and !std.mem.eql(u8, owner_wire, origin_wire);
        if (!unsigned_delegation) try codes.append(allocator, RecordType.RRSIG.code());
        try entries.append(allocator, .{
            .hash = try nsec3HashOf(owner_wire, params),
            .codes = try allocator.dupe(u16, codes.items),
        });
    }
    for (ents.items) |name| {
        try entries.append(allocator, .{
            .hash = try nsec3HashOf(name, params),
            .codes = try allocator.alloc(u16, 0),
        });
    }

    // RFC 5155 section 7.1: two owner names with one hash share one NSEC3
    // whose bitmap names the types of both.
    std.mem.sort(Nsec3Entry, entries.items, {}, nsec3EntryLessThan);
    var merged: std.ArrayList(Nsec3Entry) = .empty;
    defer merged.deinit(allocator);
    for (entries.items) |entry| {
        if (merged.items.len != 0 and std.mem.eql(u8, &merged.items[merged.items.len - 1].hash, &entry.hash)) {
            const last = &merged.items[merged.items.len - 1];
            const parts = [_][]const u16{ last.codes, entry.codes };
            last.codes = try std.mem.concat(allocator, u16, &parts);
            continue;
        }
        try merged.append(allocator, entry);
    }

    for (merged.items, 0..) |entry, index| {
        const next = merged.items[(index + 1) % merged.items.len];
        var label: [32]u8 = undefined;
        dns_dnssec.base32Hex(entry.hash, &label);
        const owner_wire = try allocator.alloc(u8, 1 + label.len + origin_wire.len);
        owner_wire[0] = @intCast(label.len);
        @memcpy(owner_wire[1..][0..label.len], &label);
        @memcpy(owner_wire[1 + label.len ..], origin_wire);

        const bitmap = try typeBitmap(allocator, entry.codes);
        const rdata = try allocator.alloc(u8, 6 + params.salt.len + 20 + bitmap.len);
        rdata[0] = params.algorithm;
        rdata[1] = params.flags;
        std.mem.writeInt(u16, rdata[2..4], params.iterations, .big);
        rdata[4] = @intCast(params.salt.len);
        @memcpy(rdata[5..][0..params.salt.len], params.salt);
        rdata[5 + params.salt.len] = 20;
        @memcpy(rdata[6 + params.salt.len ..][0..20], &next.hash);
        @memcpy(rdata[6 + params.salt.len + 20 ..], bitmap);

        const single = try allocator.alloc([]const u8, 1);
        single[0] = rdata;
        try rrsets.append(allocator, .{
            .owner_wire = owner_wire,
            .rrtype = RecordType.NSEC3.code(),
            .ttl = ttl,
            .rdata = single,
        });
    }
}

// ------------------------------------------------------------------ emission

/// The Labels field counts neither the root label nor a wildcard label
/// (RFC 4034 section 3.1.3): "www.example.com." is 3 and "*.example.com." is
/// 2, while the wildcard label stays part of the owner name the signature
/// covers. RFC 4035 section 5.3.2 is the validator's side of the same rule.
fn labelCount(owner_wire: []const u8) u8 {
    var count: u8 = 0;
    var index: usize = 0;
    while (index < owner_wire.len and owner_wire[index] != 0) : (count += 1) {
        index += 1 + owner_wire[index];
    }
    if (count != 0 and owner_wire[0] == 1 and owner_wire[1] == '*') count -= 1;
    return count;
}

/// RRSIG RDATA with the Signature field left out
/// (RFC 4034 section 3.1, sections 3.1.2 through 3.1.7): Type Covered,
/// Algorithm, Labels, Original TTL, Signature Expiration, Signature Inception,
/// Key Tag, and the Signer's Name in canonical form.
fn rrsigHeader(
    rrset: Rrset,
    algorithm: Algorithm,
    key_tag: u16,
    signer_wire: []const u8,
    options: Options,
    out: []u8,
) Error!usize {
    std.mem.writeInt(u16, out[0..2], rrset.rrtype, .big);
    out[2] = @backingInt(algorithm);
    out[3] = labelCount(rrset.owner_wire);
    std.mem.writeInt(u32, out[4..8], rrset.ttl, .big);
    std.mem.writeInt(u32, out[8..12], options.expiration, .big);
    std.mem.writeInt(u32, out[12..16], options.inception, .big);
    std.mem.writeInt(u16, out[16..18], key_tag, .big);
    @memcpy(out[18..][0..signer_wire.len], signer_wire);
    return 18 + signer_wire.len;
}

/// RFC 4034 section 3.1.8.1:
///   signed_data = RRSIG_RDATA (Signature excluded)
///                  | RR(1) | RR(2) | ...
///   RR(i) = owner | type | class | Original TTL | RDLENGTH | RDATA
/// Every RR carries the RRSIG owner, class, type, and Original TTL, and the
/// RRset is in canonical order. `header_len` is returned because only the
/// header goes into the RRSIG RDATA; the RRs that follow are signed and
/// discarded, never published.
const SignedData = struct {
    bytes: []const u8,
    header_len: usize,
};

fn signedData(
    allocator: std.mem.Allocator,
    rrset: Rrset,
    algorithm: Algorithm,
    key_tag: u16,
    signer_wire: []const u8,
    options: Options,
) Error!SignedData {
    var header: [18 + 255]u8 = undefined;
    const header_len = try rrsigHeader(rrset, algorithm, key_tag, signer_wire, options, &header);

    // RFC 4034 section 6.2: the signature covers the RDATA in its canonical
    // form, and RFC 4034 section 6.3 puts the RRset in the order of that
    // form. The rule lives in `dnssec`, so the signer signs exactly what the
    // validator verifies.
    var rdata: std.ArrayList([]const u8) = .empty;
    for (rrset.rdata) |bytes| {
        const canonical = dns_dnssec.canonicalRdata(allocator, rrset.rrtype, bytes) catch return Error.OutOfMemory;
        try rdata.append(allocator, canonical);
    }
    std.mem.sort([]const u8, rdata.items, {}, rdataLessThan);

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, header[0..header_len]);
    for (rdata.items) |bytes| {
        try out.appendSlice(allocator, rrset.owner_wire);
        const rr_header = zonemd.rrHeader(rrset.rrtype, dns_types.Class.IN.code(), rrset.ttl, bytes.len);
        try out.appendSlice(allocator, &rr_header);
        try out.appendSlice(allocator, bytes);
    }
    return .{ .bytes = try out.toOwnedSlice(allocator), .header_len = header_len };
}

/// One signing key and the key tag its signatures carry
/// (RFC 4034 section 3.1.6).
const SigningKey = struct {
    material: Material,
    tag: u16,
};

/// Signs every RRset and installs the generated records on the zone. The NSEC
/// chain and the apex key records are written out as records in their own
/// right; the zone's own RRsets are already in `zone.records` and are only
/// signed. Each generated record uses the RFC 3597 generic presentation form,
/// which the zone parser decodes back to exactly the bytes written here, so no
/// wire value is ever re-derived from text.
///
/// `scratch` is released when `signZone` returns; `records` outlives the call
/// because the zone owns every generated record until it is deinited.
fn emit(
    scratch: std.mem.Allocator,
    records: std.mem.Allocator,
    zone: *zone_index.Zone,
    key: *const Key,
    key_tag: u16,
    ksk_tag: u16,
    published_ksk_tag: u16,
    options: Options,
    rrsets: []const Rrset,
    publish_param: bool,
    skip_zonemd: bool,
) Error!void {
    const signer_wire = try scratch.dupe(u8, (Name.fromText(zone.originText()) catch return Error.BadZoneRecord).asWire());

    var generated: std.ArrayList(zone_parser.ZoneRecord) = .empty;
    defer generated.deinit(scratch);
    try generated.ensureTotalCapacity(scratch, rrsets.len + 1);

    for (rrsets) |rrset| {
        switch (rrset.rrtype) {
            // The RRsets the signer itself generated. Anything else came from
            // the zone file and is already published there.
            RecordType.NSEC.code(), RecordType.NSEC3.code(), RecordType.DNSKEY.code(), RecordType.DS.code() => for (rrset.rdata) |rdata| {
                try generated.append(scratch, try genericRecord(records, rrset.owner_wire, rrset.rrtype, rrset.ttl, rdata));
            },
            // The apex NSEC3PARAM the signer publishes states the chain's
            // parameters; a zone that states one of its own keeps it.
            RecordType.NSEC3PARAM.code() => if (publish_param) {
                for (rrset.rdata) |rdata| {
                    try generated.append(scratch, try genericRecord(records, rrset.owner_wire, rrset.rrtype, rrset.ttl, rdata));
                }
            },
            else => {},
        }
        if (skip_zonemd and rrset.rrtype == RecordType.ZONEMD.code()) continue;
        // RFC 4035 section 2.2: a delegation's NS RRset is not signed by the
        // parent. It is still published and transferred, but it carries no
        // RRSIG, and external verifiers reject one that does.
        if (rrset.rrtype == RecordType.NS.code() and !std.mem.eql(u8, rrset.owner_wire, signer_wire)) continue;

        // RFC 6781 section 3.1: the key-signing key signs the DNSKEY RRset
        // and nothing else; the zone-signing key signs every other RRset. A
        // zone with one key signs the DNSKEY RRset with that key. RFC 6781
        // section 4.1.2: a Double-Signature rollover signs the DNSKEY RRset
        // once per key-signing key.
        const ksk: ?*const Ksk = if (key.ksk) |*candidate| candidate else null;
        const published_ksk: ?*const Ksk = if (key.published_ksk) |*candidate| candidate else null;
        var signers: [2]SigningKey = undefined;
        var signer_count: usize = 1;
        // The copied private material lives on this stack frame; wipe it when
        // the RRset is done.
        defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(signers[0..signer_count]));
        signers[0] = .{ .material = key.material, .tag = key_tag };
        // The parent DS states this zone's own key-signing key, so it is key
        // material rather than ordinary zone data and is signed by that key.
        const own_ds = rrset.rrtype == RecordType.DS.code() and std.mem.eql(u8, rrset.owner_wire, signer_wire);
        if ((rrset.rrtype == RecordType.DNSKEY.code() or own_ds) and ksk_tag != 0) {
            signers[0] = .{ .material = if (ksk) |value| value.material else key.material, .tag = ksk_tag };
            if (published_ksk) |second| {
                signers[1] = .{ .material = second.material, .tag = published_ksk_tag };
                signer_count = 2;
            }
        }
        for (signers[0..signer_count]) |*signing_key| {
            const signed = try signedData(scratch, rrset, signing_key.material, signing_key.tag, signer_wire, options);
            // RRSIG RDATA is the RRSIG header followed by the Signature field. The
            // RRs that were signed go in neither: they are already published from
            // the zone file.
            var rdata_buffer: [max_rrsig_rdata_local_len]u8 = undefined;
            @memcpy(rdata_buffer[0..signed.header_len], signed.bytes[0..signed.header_len]);
            const signature = try signMaterial(&signing_key.material, signed.bytes, rdata_buffer[signed.header_len..]);
            try generated.append(scratch, try genericRecord(
                records,
                rrset.owner_wire,
                RecordType.RRSIG.code(),
                rrset.ttl,
                rdata_buffer[0 .. signed.header_len + signature.len],
            ));
        }
    }

    try install(records, zone, generated.items);
}

fn genericRecord(
    allocator: std.mem.Allocator,
    owner_wire: []const u8,
    rrtype: u16,
    ttl: u32,
    rdata: []const u8,
) Error!zone_parser.ZoneRecord {
    var text_buffer: [3 + 2 * max_rdata_len]u8 = undefined;
    text_buffer[0] = '\\';
    text_buffer[1] = '#';
    text_buffer[2] = ' ';
    for (rdata, 0..) |byte, index| {
        const nibbles = [_]u8{ "0123456789abcdef"[byte >> 4], "0123456789abcdef"[byte & 0x0f] };
        text_buffer[3 + 2 * index] = nibbles[0];
        text_buffer[4 + 2 * index] = nibbles[1];
    }

    const owner_name = (Name.parse(owner_wire, 0) catch return Error.BadZoneRecord).name;
    var owner_buffer: [256]u8 = undefined;
    const owner_text = owner_name.toText(&owner_buffer) catch return Error.BadZoneRecord;
    return .{
        .owner = try allocator.dupe(u8, owner_text),
        .ttl = ttl,
        .rrtype = RecordType.fromCode(rrtype),
        .rdata = try allocator.dupe(u8, text_buffer[0 .. 3 + 2 * rdata.len]),
    };
}

/// Replaces the zone's record slice with one that keeps every loaded record
/// and appends the generated ones. The list is rebuilt rather than appended to
/// because the loaded array belongs to the zone file's fixed buffer, and
/// reallocating across two allocators would be undefined. The generated half is
/// handed to the zone so `Zone.deinit` frees it with this allocator instead of
/// leaking every DNSKEY, DS, RRSIG, and NSEC record.
fn install(allocator: std.mem.Allocator, zone: *zone_index.Zone, generated: []const zone_parser.ZoneRecord) Error!void {
    const original_len = zone.records.len;
    const combined = try allocator.alloc(zone_parser.ZoneRecord, original_len + generated.len);
    @memcpy(combined[0..original_len], zone.records.items[0..original_len]);
    @memcpy(combined[original_len..], generated);
    zone.records = .{ .items = combined, .len = original_len + generated.len };
    zone.generated = combined[original_len..];
    zone.generated_allocation = combined;
    zone.generated_allocator = allocator;
}

/// Appends records to an already-signed zone, keeping the split between the
/// loaded records and the generated tail. The old combined array is freed;
/// the per-record strings keep their owner and move with the structs.
fn appendGenerated(allocator: std.mem.Allocator, zone: *zone_index.Zone, extra: []const zone_parser.ZoneRecord) Error!void {
    const original_len = zone.records.len - zone.generated.len;
    const old = zone.generated_allocation;
    const combined = try allocator.alloc(zone_parser.ZoneRecord, zone.records.len + extra.len);
    @memcpy(combined[0..zone.records.len], zone.records.items[0..zone.records.len]);
    @memcpy(combined[zone.records.len..], extra);
    allocator.free(old);
    zone.records = .{ .items = combined, .len = combined.len };
    zone.generated = combined[original_len..];
    zone.generated_allocation = combined;
    zone.generated_allocator = allocator;
}

// ------------------------------------------------------------------- vectors
//
// Nothing here compares the signer against itself. Three sources pin it, and
// each constant below states which one it came from.
//
// 1. RFC 8080 section 6.1 gives the Ed25519 private key, the DNSKEY it derives,
//    its key tag (35217), and its SHA-256 DS digest. All three are reproduced
//    here and were independently confirmed with dnspython 2.8.0.
//
// 2. RFC 6605 sections 6.1 and 6.2 give the ECDSA DNSKEY encodings, key tags
//    (55648 and 10771), and SHA-256 / SHA-384 DS digests. All are reproduced
//    here and were independently confirmed with dnspython 2.8.0.
//
// 3. The RRSIG bytes below come from dnspython 2.8.0 plus `cryptography`,
//    signing the RFC 8080 RRset and window with the RFC 8080 key. Ed25519 is
//    deterministic (RFC 8032), so equality of the signature is equality of the
//    whole signed-data preimage: one wrong octet in the RRSIG header, the
//    canonical RR serialisation, or the owner handling fails this test.
//
// The signatures printed in RFC 6605 and RFC 8080 are NOT used. Both were
// checked against their own published DNSKEYs over their own published
// RRsets and neither verifies, so this module makes no claim about them.
// RFC 8080 additionally prints `RRSIG MX 3 3600`, which omits the Algorithm
// field the RFC 4034 section 3.2 presentation format requires, and dnspython
// computes Labels = 2 for `example.com.` where the RFC prints 3. RFC 4034
// section 3.1.3 is unambiguous ("*.example.com." has a Labels value of 2), so
// the RFC's printed 3 is an error.

const rfc8080_ed25519_key = "ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n";
const rfc8080_ed25519_dnskey = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";
const rfc8080_ed25519_key_tag: u16 = 35217;
/// RFC 8032 section 7.4 blank-message secret, base64-encoded so the key file
/// can carry it. It is a test secret, not a published DNSSEC vector.
const ed448_key = "ed448 bIKlYsuAjRDWMr6JyFE+v2ySnzTd+oyfY8mWDvbjSKNSjIo/zC8ETjmj/FuUSS+PAy51SaIAmPlb\n";
const rfc8080_mx_rrsig_hex =
    "000f0f0200000e1055d4fc6055b94ce08991076578616d706c6503636f6d00" ++
    "cd74346e4620413105c9f2f28bd428898e83f19758a38c32521562a1865715d4f" ++
    "8d7440f4484d04aa2529f34284a6e69a09ee00fb0104743bb2ae239936a5c06";

const rfc6605_p256_key = "ecdsap256sha256 GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n";
const rfc6605_p256_dnskey = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
const rfc6605_p256_key_tag: u16 = 55648;

const rfc6605_p384_key = "ecdsap384sha384 WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR\n";
const rfc6605_p384_dnskey = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
const rfc6605_p384_key_tag: u16 = 10771;

const rfc5702_zone =
    \\$ORIGIN example.net.
    \\$TTL 3600
    \\@ IN SOA ns1.example.net. hostmaster.example.net. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.net.
    \\www IN A 192.0.2.91
;

/// RFC 5702 section 6.1: a 512-bit RSA/SHA-256 key (BIND private-key-format
/// components) and the signature it produces over the example RRset.
const rfc5702_sha256_modulus = "wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==";
const rfc5702_sha256_private = "UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ==";
const rfc5702_sha256_exponent = "AQAB";
const rfc5702_sha256_dnskey = "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=";
const rfc5702_sha256_key_tag: u16 = 9033;
const rfc5702_sha256_signature = "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==";
const rfc5702_sha256_window = Options{ .inception = 946684800, .expiration = 1893456000 };

/// RFC 5702 section 6.2: the 1024-bit RSA/SHA-512 example.
const rfc5702_sha512_modulus = "0eg1M5b563zoq4k5ZEOnWmd2/BvpjzedJVdfIsDcMuuhE5SQ3pfQ7qmdaeMlC6Nf8DKGoUPGPXe06cP27/WRODtxXquSUytkO0kJDk8KX8PtA0+yBWwy7UnZDyCkynO00Uuk8HPVtZeMO1pHtlAGVnc8VjXZlNKdyit99waaE4s=";
const rfc5702_sha512_private = "rFS1IPbJllFFgFc33B5DDlC1egO8e81P4fFadODbp56V7sphKa6AZQCx8NYAew6VXFFPAKTw41QdHnK5kIYOwxvfFDjDcUGza88qbjyrDPSJenkeZbISMUSSqy7AMFzEolkk6WSn6k3thUVRgSlqDoOV3SEIAsrB043XzGrKIVE=";
const rfc5702_sha512_dnskey = "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL";
const rfc5702_sha512_key_tag: u16 = 3740;
const rfc5702_sha512_signature = "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=";

/// A PKCS#1 RSAPrivateKey built from the RFC's components, in the key file
/// form the signer reads: `<algorithm> <base64 DER>`.
fn rsaKeyFile(
    allocator: std.mem.Allocator,
    algorithm: []const u8,
    modulus_b64: []const u8,
    exponent_b64: []const u8,
    private_b64: []const u8,
) ![]u8 {
    const modulus = try decodeBase64Dynamic(allocator, modulus_b64);
    const exponent = try decodeBase64Dynamic(allocator, exponent_b64);
    const private = try decodeBase64Dynamic(allocator, private_b64);
    const version = try derInteger(allocator, &.{0});
    const n = try derInteger(allocator, modulus);
    const e = try derInteger(allocator, exponent);
    const d = try derInteger(allocator, private);
    const body = try std.mem.concat(allocator, u8, &.{ version, n, e, d });
    var sequence = std.ArrayList(u8).empty;
    try sequence.append(allocator, 0x30);
    if (body.len < 128) {
        try sequence.append(allocator, @intCast(body.len));
    } else if (body.len < 256) {
        try sequence.append(allocator, 0x81);
        try sequence.append(allocator, @intCast(body.len));
    } else {
        try sequence.append(allocator, 0x82);
        try sequence.append(allocator, @intCast(body.len >> 8));
        try sequence.append(allocator, @intCast(body.len & 0xff));
    }
    try sequence.appendSlice(allocator, body);
    const encoded = try encodeBase64(allocator, sequence.items);
    return std.fmt.allocPrint(allocator, "{s} {s}\n", .{ algorithm, encoded });
}

fn decodeBase64Dynamic(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(text));
    try std.base64.standard.Decoder.decode(out, text);
    return out;
}

fn derInteger(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const pad: usize = if (bytes.len == 0 or (bytes[0] & 0x80) != 0) 1 else 0;
    const value_len = pad + bytes.len;
    const header_len: usize = if (value_len < 128) 2 else if (value_len < 256) 3 else 4;
    const out = try allocator.alloc(u8, header_len + value_len);
    out[0] = 0x02;
    var offset: usize = 1;
    if (value_len < 128) {
        out[1] = @intCast(value_len);
        offset = 2;
    } else if (value_len < 256) {
        out[1] = 0x81;
        out[2] = @intCast(value_len);
        offset = 3;
    } else {
        out[1] = 0x82;
        std.mem.writeInt(u16, out[2..4], @intCast(value_len), .big);
        offset = 4;
    }
    if (pad == 1) {
        out[offset] = 0;
        offset += 1;
    }
    @memcpy(out[offset..], bytes);
    return out;
}

test "RFC 5702 section 6.1: the RSA/SHA-256 DNSKEY, key tag, and signature match the published vector" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const key_file = try rsaKeyFile(allocator, "RSASHA256", rfc5702_sha256_modulus, rfc5702_sha256_exponent, rfc5702_sha256_private);
    var key = try parseKey(key_file);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.rsa_sha256, key.algorithm());

    // The RFC's example key carries flags 256 (no Secure Entry Point bit), so
    // the vector is compared against that form of the DNSKEY.
    const dnskey = try key.dnskeyRdataWithFlags(allocator, 0x0100);
    try std.testing.expectEqual(@as(u8, 8), dnskey[3]);
    try std.testing.expectEqualStrings(rfc5702_sha256_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc5702_sha256_key_tag, dns_dnssec.keyTag(dnskey));

    const data = try signedData(allocator, .{
        .owner_wire = (try Name.fromText("www.example.net.")).asWire(),
        .rrtype = RecordType.A.code(),
        .ttl = 3600,
        .rdata = try oneRdata(allocator, &.{ 192, 0, 2, 91 }),
    }, .rsa_sha256, rfc5702_sha256_key_tag, (try Name.fromText("example.net.")).asWire(), rfc5702_sha256_window);

    var signature_buffer: [512]u8 = undefined;
    const signature = try key.sign(data.bytes, &signature_buffer);
    try std.testing.expectEqualStrings(rfc5702_sha256_signature, try encodeBase64(allocator, signature));
}

test "RFC 5702 section 6.2: the RSA/SHA-512 DNSKEY, key tag, and signature match the published vector" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const key_file = try rsaKeyFile(allocator, "RSASHA512", rfc5702_sha512_modulus, rfc5702_sha256_exponent, rfc5702_sha512_private);
    var key = try parseKey(key_file);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.rsa_sha512, key.algorithm());

    const dnskey = try key.dnskeyRdataWithFlags(allocator, 0x0100);
    try std.testing.expectEqual(@as(u8, 10), dnskey[3]);
    try std.testing.expectEqualStrings(rfc5702_sha512_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc5702_sha512_key_tag, dns_dnssec.keyTag(dnskey));

    const data = try signedData(allocator, .{
        .owner_wire = (try Name.fromText("www.example.net.")).asWire(),
        .rrtype = RecordType.A.code(),
        .ttl = 3600,
        .rdata = try oneRdata(allocator, &.{ 192, 0, 2, 91 }),
    }, .rsa_sha512, rfc5702_sha512_key_tag, (try Name.fromText("example.net.")).asWire(), rfc5702_sha256_window);

    var signature_buffer: [512]u8 = undefined;
    const signature = try key.sign(data.bytes, &signature_buffer);
    try std.testing.expectEqualStrings(rfc5702_sha512_signature, try encodeBase64(allocator, signature));
}

test "a zone signed with an RSA/SHA-256 key validates against its own DNSKEY" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const key_file = try rsaKeyFile(allocator, "RSASHA256", rfc5702_sha256_modulus, rfc5702_sha256_exponent, rfc5702_sha256_private);
    var key = try parseKey(key_file);
    defer key.deinit();

    var zone = try loadZone(rfc5702_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc5702_sha256_window);

    const dnskey = try publishedKey(allocator, &zone, 8);
    try expectSignedBy(allocator, &zone, dnskey, dns_dnssec.keyTag(dnskey));
}

const rfc8080_zone =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\@ IN MX 10 mail.example.com.
    \\ns1 IN A 192.0.2.1
    \\mail IN A 192.0.2.2
;

const rfc8080_window = Options{ .inception = 1438207200, .expiration = 1440021600 };

fn decodeBase64(comptime length: usize, text: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    try std.base64.standard.Decoder.decode(&out, text);
    return out;
}

fn encodeBase64(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    _ = std.base64.standard.Encoder.encode(out, bytes);
    return out;
}

/// Compares `bytes` against a lowercase hex literal without allocating.
fn hexEquals(expected_hex: []const u8, bytes: []const u8) bool {
    if (expected_hex.len != 2 * bytes.len) return false;
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        if (expected_hex[2 * index] != alphabet[byte >> 4]) return false;
        if (expected_hex[2 * index + 1] != alphabet[byte & 0x0f]) return false;
    }
    return true;
}

fn loadZone(text: []const u8) !zone_index.Zone {
    var zone_file = try zone_parser.ZoneFile.parse(text);
    defer zone_file.deinit();
    return zone_index.Zone.fromZoneFile(&zone_file);
}

fn hasRecord(zone: *const zone_index.Zone, owner_text: []const u8, rrtype: RecordType) bool {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.code() != rrtype.code()) continue;
        if (std.ascii.eqlIgnoreCase(record.ownerText(), owner_text)) return true;
    }
    return false;
}

/// Opaque RDATA of the first `rrtype` record at `owner_text` whose RDATA
/// begins with `type_covered`, so an RRSIG is picked by what it covers rather
/// than by its position in the generated list.
fn findOpaque(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    owner_text: []const u8,
    rrtype: RecordType,
    type_covered: ?u16,
) !?[]const u8 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.code() != rrtype.code()) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner_text)) continue;
        var rdata = try zone_parser.parseRData(rrtype, record.rdataText());
        switch (rdata) {
            .Unknown => |*unknown| {
                const bytes = unknown.bytes();
                if (type_covered) |covered| {
                    if (bytes.len < 2 or std.mem.readInt(u16, bytes[0..2], .big) != covered) continue;
                }
                return try allocator.dupe(u8, bytes);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    return null;
}

fn oneRdata(allocator: std.mem.Allocator, blob: []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, 1);
    out[0] = blob;
    return out;
}

/// The DNSKEY RDATA of every key the zone publishes at the apex.
fn apexDnskeys(allocator: std.mem.Allocator, zone: *const zone_index.Zone) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.DNSKEY)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        const rdata = try zone_parser.parseRData(.DNSKEY, record.rdataText());
        switch (rdata) {
            .Unknown => |*unknown| try out.append(allocator, try allocator.dupe(u8, unknown.bytes())),
            else => return error.TestUnexpectedResult,
        }
    }
    return out.toOwnedSlice(allocator);
}

/// The RRSIG RDATA of every signature that covers `type_covered` at
/// `owner_text`.
fn rrsigsCovering(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    owner_text: []const u8,
    type_covered: u16,
) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner_text)) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        if (bytes.len < 18) continue;
        if (std.mem.readInt(u16, bytes[0..2], .big) != type_covered) continue;
        try out.append(allocator, try allocator.dupe(u8, bytes));
    }
    return out.toOwnedSlice(allocator);
}

/// The DNSKEY the zone publishes for the key of `algorithm`. A single-key
/// zone publishes the key twice, 256 and 257; the chain anchor is the 257
/// form, so that one is preferred.
fn publishedKey(allocator: std.mem.Allocator, zone: *const zone_index.Zone, algorithm: u8) ![]const u8 {
    const keys = try apexDnskeys(allocator, zone);
    for (keys) |rdata| {
        if (rdata[3] == algorithm and std.mem.readInt(u16, rdata[0..2], .big) & 0x0001 != 0) return rdata;
    }
    for (keys) |rdata| {
        if (rdata[3] == algorithm) return rdata;
    }
    return error.TestUnexpectedResult;
}

/// The apex DNSKEY RRset carrying only the signature whose key tag is
/// `key_tag`, validated with `anchor_rdata` as the one trust anchor. A
/// secure verdict says that the signature verifies with that key and with
/// no other.
fn expectSignedBy(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    anchor_rdata: []const u8,
    key_tag: u16,
) !void {
    const apex = try Name.fromText(zone.originText());
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{ .owner = apex, .rrtype = .DNSKEY, .rdata = try allocator.dupe(u8, anchor_rdata) };
    anchors.len = 1;

    var response = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4410, .qr = true, .rcode = .no_error },
        .question = .{ .name = apex, .qtype = .DNSKEY, .qclass = dns_types.Class.IN },
    };
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.DNSKEY)) {
            try response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
            continue;
        }
        if (!record.rrtype.eql(.RRSIG)) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        if (bytes.len < 18) continue;
        if (std.mem.readInt(u16, bytes[0..2], .big) != RecordType.DNSKEY.code()) continue;
        if (std.mem.readInt(u16, bytes[16..18], .big) != key_tag) continue;
        try response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
    }
    response.header.answer_count = @intCast(response.answers.len);
    const request = try doBitQuery(allocator, zone.originText(), .DNSKEY);
    const result = try dns_validate.validate(allocator, &anchors, request, response, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);
}

/// The zone a key-signing key and a zone-signing key sign together.
const ksk_zsk_zone =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
;

test "RFC 6781 section 3.1: a zone that separates the roles publishes both keys and signs each with its own" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The key-signing key is the Ed25519 key of RFC 8080 section 6.1 and the
    // zone-signing key is the ECDSA P-256 key of RFC 6605 section 6.1, so the
    // two roles are told apart by more than their key tag.
    var ksk = try parseKey(rfc8080_ed25519_key);
    defer ksk.deinit();
    var zsk = try parseKey(rfc6605_p256_key);
    defer zsk.deinit();
    zsk.ksk = .{ .material = ksk.material };

    var zone = try loadZone(ksk_zsk_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &zsk, rfc8080_window);

    // The zone publishes both keys: the key-signing key with the Secure
    // Entry Point flag, the zone-signing key with the Zone Key flag alone.
    const keys = try apexDnskeys(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    var saw_ksk = false;
    var saw_zsk = false;
    for (keys) |rdata| {
        const flags = std.mem.readInt(u16, rdata[0..2], .big);
        if (rdata[3] == 15) {
            try std.testing.expectEqual(@as(u16, 257), flags);
            saw_ksk = true;
        } else {
            try std.testing.expectEqual(@as(u16, 256), flags);
            saw_zsk = true;
        }
    }
    try std.testing.expect(saw_ksk);
    try std.testing.expect(saw_zsk);

    // RFC 4035 section 2.2: the DS lives in the parent zone, so the child
    // publishes its DNSKEY and no DS of its own.
    try std.testing.expect((try findOpaque(allocator, &zone, "example.com.", .DS, null)) == null);

    // The DNSKEY RRset is signed by the key-signing key, and every other
    // RRset by the zone-signing key (RFC 6781 section 3.1).
    const dnskey_rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.DNSKEY.code())).?;
    try std.testing.expectEqual(@as(u8, 15), dnskey_rrsig[2]);
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, std.mem.readInt(u16, dnskey_rrsig[16..18], .big));
    const soa_rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.SOA.code())).?;
    try std.testing.expectEqual(@as(u8, 13), soa_rrsig[2]);
    const zsk_tag = dns_dnssec.keyTag(keys[if (keys[0][3] == 13) 0 else 1]);
    try std.testing.expectEqual(zsk_tag, std.mem.readInt(u16, soa_rrsig[16..18], .big));
}

test "RFC 6781 section 4.1.2: a double-signature KSK rollover publishes both key-signing keys and signs the DNSKEY RRset with both" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Three distinct keys, so the two key-signing keys are told apart by
    // their algorithm and their key tag: the Ed25519 key of RFC 8080
    // section 6.1 is the key the parent's DS points at, the ECDSA P-384 key
    // of RFC 6605 section 6.2 is the second key-signing key, and the ECDSA
    // P-256 key of RFC 6605 section 6.1 signs every other RRset.
    var ksk = try parseKey(rfc8080_ed25519_key);
    defer ksk.deinit();
    var new_ksk = try parseKey(rfc6605_p384_key);
    defer new_ksk.deinit();
    var zsk = try parseKey(rfc6605_p256_key);
    defer zsk.deinit();
    zsk.ksk = .{ .material = ksk.material };
    zsk.published_ksk = .{ .material = new_ksk.material };

    var zone = try loadZone(ksk_zsk_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &zsk, rfc8080_window);

    // The zone publishes three keys: the zone-signing key with the Zone Key
    // flag alone, and the two key-signing keys with the Secure Entry Point
    // flag (RFC 4034 section 2.1.1).
    const keys = try apexDnskeys(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 3), keys.len);
    var zone_key_count: usize = 0;
    var secure_entry_point_count: usize = 0;
    for (keys) |rdata| {
        const flags = std.mem.readInt(u16, rdata[0..2], .big);
        if (flags == 256) {
            zone_key_count += 1;
            try std.testing.expectEqual(@as(u8, 13), rdata[3]);
        } else if (flags == 257) {
            secure_entry_point_count += 1;
        } else return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(@as(usize, 1), zone_key_count);
    try std.testing.expectEqual(@as(usize, 2), secure_entry_point_count);

    // The DNSKEY RRset carries one signature per key-signing key, each with
    // that key's own key tag (RFC 6781 section 4.1.2).
    const dnskey_sigs = try rrsigsCovering(allocator, &zone, "example.com.", RecordType.DNSKEY.code());
    try std.testing.expectEqual(@as(usize, 2), dnskey_sigs.len);
    var saw_ksk_tag = false;
    var saw_new_ksk_tag = false;
    for (dnskey_sigs) |sig| {
        const tag = std.mem.readInt(u16, sig[16..18], .big);
        if (tag == rfc8080_ed25519_key_tag) saw_ksk_tag = true;
        if (tag == rfc6605_p384_key_tag) saw_new_ksk_tag = true;
    }
    try std.testing.expect(saw_ksk_tag);
    try std.testing.expect(saw_new_ksk_tag);

    // Each signature verifies with its own key: a validator that trusts one
    // key-signing key alone accepts the RRset signed by that key alone.
    const ksk_dnskey = try publishedKey(allocator, &zone, 15);
    const new_ksk_dnskey = try publishedKey(allocator, &zone, 14);
    try expectSignedBy(allocator, &zone, ksk_dnskey, rfc8080_ed25519_key_tag);
    try expectSignedBy(allocator, &zone, new_ksk_dnskey, rfc6605_p384_key_tag);

    // RFC 4035 section 2.2: the DS lives in the parent zone, so the child
    // publishes no DS and the rollover does not move one.
    try std.testing.expect((try findOpaque(allocator, &zone, "example.com.", .DS, null)) == null);

    // Every other RRset is still signed by the zone-signing key alone.
    const zsk_dnskey = try publishedKey(allocator, &zone, 13);
    const soa_sigs = try rrsigsCovering(allocator, &zone, "example.com.", RecordType.SOA.code());
    try std.testing.expectEqual(@as(usize, 1), soa_sigs.len);
    try std.testing.expectEqual(@as(u8, 13), soa_sigs[0][2]);
    try std.testing.expectEqual(dns_dnssec.keyTag(zsk_dnskey), std.mem.readInt(u16, soa_sigs[0][16..18], .big));

    // The project's own validator accepts the zone: each key-signing key
    // authenticates the DNSKEY RRset with its own signature, and the
    // zone-signing key signs the rest of the zone.
    const apex = try Name.fromText("example.com.");
    try expectSignedBy(allocator, &zone, ksk_dnskey, rfc8080_ed25519_key_tag);
    try expectSignedBy(allocator, &zone, new_ksk_dnskey, rfc6605_p384_key_tag);

    var zsk_anchors = dns_validate.Anchors{};
    zsk_anchors.items[0] = .{ .owner = apex, .rrtype = .DNSKEY, .rdata = try allocator.dupe(u8, try publishedKey(allocator, &zone, 13)) };
    zsk_anchors.len = 1;
    var soa_response = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4412, .qr = true, .rcode = .no_error },
        .question = .{ .name = apex, .qtype = .SOA, .qclass = dns_types.Class.IN },
    };
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.SOA)) {
            try soa_response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
            continue;
        }
        if (!record.rrtype.eql(.RRSIG)) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        if (bytes.len < 2 or std.mem.readInt(u16, bytes[0..2], .big) != RecordType.SOA.code()) continue;
        try soa_response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
    }
    soa_response.header.answer_count = @intCast(soa_response.answers.len);
    const soa_request = try doBitQuery(allocator, "example.com.", .SOA);
    const soa_result = try dns_validate.validate(allocator, &zsk_anchors, soa_request, soa_response, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, soa_result.status);
}

test "RFC 6781 section 4.1.2.1: a revoked key-signing key is published with the REVOKE bit and still signs the DNSKEY RRset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The revoke phase of the rollover: the key the parent's DS points at is
    // the one `dnssec-ksk-file` names, and the key being removed is the
    // second one, the one the directive marks `revoked`.
    var ksk = try parseKey(rfc8080_ed25519_key);
    defer ksk.deinit();
    var revoked_ksk = try parseKey(rfc6605_p384_key);
    defer revoked_ksk.deinit();
    var zsk = try parseKey(rfc6605_p256_key);
    defer zsk.deinit();
    zsk.ksk = .{ .material = ksk.material };
    zsk.published_ksk = .{ .material = revoked_ksk.material, .revoked = true };

    var zone = try loadZone(ksk_zsk_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &zsk, rfc8080_window);

    // The zone publishes three keys, and only the revoked one carries the
    // REVOKE bit of RFC 5011 section 3: flags 385, and not 256 or 257.
    const keys = try apexDnskeys(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 3), keys.len);
    var revoked_count: usize = 0;
    for (keys) |rdata| {
        const flags = std.mem.readInt(u16, rdata[0..2], .big);
        if (flags == 385) {
            revoked_count += 1;
            try std.testing.expectEqual(@as(u8, 14), rdata[3]);
        } else {
            try std.testing.expect(flags == 256 or flags == 257);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), revoked_count);

    // The revoked key still signs the DNSKEY RRset that carries it, so the
    // RRset is covered by one signature per key-signing key, each with its
    // own key's tag. The revoked key's tag is the tag of the DNSKEY it
    // publishes, the one with the REVOKE bit set.
    const revoked_dnskey = try publishedKey(allocator, &zone, 14);
    const revoked_tag = dns_dnssec.keyTag(revoked_dnskey);
    const ksk_dnskey = try publishedKey(allocator, &zone, 15);
    const ksk_tag = dns_dnssec.keyTag(ksk_dnskey);
    const dnskey_sigs = try rrsigsCovering(allocator, &zone, "example.com.", RecordType.DNSKEY.code());
    try std.testing.expectEqual(@as(usize, 2), dnskey_sigs.len);
    var saw_revoked_tag = false;
    var saw_ksk_tag = false;
    for (dnskey_sigs) |sig| {
        const tag = std.mem.readInt(u16, sig[16..18], .big);
        if (tag == revoked_tag) saw_revoked_tag = true;
        if (tag == ksk_tag) saw_ksk_tag = true;
    }
    try std.testing.expect(saw_revoked_tag);
    try std.testing.expect(saw_ksk_tag);

    // RFC 4035 section 2.2: the DS lives in the parent zone. The revoked
    // key's presence in the RRset does not break the chain a validator
    // builds from the key-signing key itself.
    try std.testing.expect((try findOpaque(allocator, &zone, "example.com.", .DS, null)) == null);
    try expectSignedBy(allocator, &zone, ksk_dnskey, ksk_tag);
}

test "a zone with one key publishes the key as a 256/257 pair and signs data with the 256 form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // One key is the single-type signing scheme (RFC 6781 section 3.1): the
    // key is published twice, with the Zone Key flag alone for the zone data
    // and with the Secure Entry Point flag for the DNSKEY RRset. External
    // verifiers require a ZSK beside the KSK. No DS: it belongs to the parent
    // (RFC 4035 section 2.2).
    const keys = try apexDnskeys(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqual(@as(u16, 256), std.mem.readInt(u16, keys[0][0..2], .big));
    try std.testing.expectEqual(@as(u16, 257), std.mem.readInt(u16, keys[1][0..2], .big));
    try std.testing.expectEqualSlices(u8, keys[0][4..], keys[1][4..]);
    try std.testing.expect((try findOpaque(allocator, &zone, "example.com.", .DS, null)) == null);

    // The bytes are the ones the RFC 8080 section 6.1 vector pins.
    try std.testing.expectEqualStrings(rfc8080_ed25519_dnskey, try encodeBase64(allocator, keys[1][4..]));
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, dns_dnssec.keyTag(keys[1]));

    // Zone data is signed with the 256 key and the DNSKEY RRset with 257.
    const rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.MX.code())).?;
    try std.testing.expectEqual(dns_dnssec.keyTag(keys[0]), std.mem.readInt(u16, rrsig[16..18], .big));
    const dnskey_rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.DNSKEY.code())).?;
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, std.mem.readInt(u16, dnskey_rrsig[16..18], .big));
}

test "the project's own validator accepts the DNSKEY RRset through the key-signing key and the zone's RRsets through the zone-signing key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ksk = try parseKey(rfc8080_ed25519_key);
    defer ksk.deinit();
    var zsk = try parseKey(rfc6605_p256_key);
    defer zsk.deinit();
    zsk.ksk = .{ .material = ksk.material };

    var zone = try loadZone(ksk_zsk_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &zsk, rfc8080_window);

    const apex = try Name.fromText("example.com.");
    const keys = try apexDnskeys(allocator, &zone);
    const ksk_dnskey = keys[if (keys[0][3] == 15) 0 else 1];
    const zsk_dnskey = keys[if (keys[0][3] == 13) 0 else 1];

    // The key-signing key signed the DNSKEY RRset that holds the
    // zone-signing key: that is the chain of RFC 4035 section 5.2.
    try expectSignedBy(allocator, &zone, ksk_dnskey, dns_dnssec.keyTag(ksk_dnskey));

    // The zone-signing key the DNSKEY RRset carries signs the zone, and a
    // validator that trusts that key accepts the zone's own RRsets.
    var zsk_anchors = dns_validate.Anchors{};
    zsk_anchors.items[0] = .{ .owner = apex, .rrtype = .DNSKEY, .rdata = try allocator.dupe(u8, zsk_dnskey) };
    zsk_anchors.len = 1;

    var soa_response = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4407, .qr = true, .rcode = .no_error },
        .question = .{ .name = apex, .qtype = .SOA, .qclass = dns_types.Class.IN },
    };
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.SOA)) {
            try soa_response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
            continue;
        }
        if (!record.rrtype.eql(.RRSIG)) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        if (bytes.len < 2 or std.mem.readInt(u16, bytes[0..2], .big) != RecordType.SOA.code()) continue;
        try soa_response.answers.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
    }
    soa_response.header.answer_count = @intCast(soa_response.answers.len);
    const soa_request = try doBitQuery(allocator, "example.com.", .SOA);
    const soa_result = try dns_validate.validate(allocator, &zsk_anchors, soa_request, soa_response, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, soa_result.status);
}

test "RFC 8080 section 6.1: the signed Ed25519 zone matches the published vector byte for byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The 257 DNSKEY is the RFC 8080 vector, in the served RRset.
    const dnskey = try publishedKey(allocator, &zone, 15);
    try std.testing.expectEqualStrings(rfc8080_ed25519_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, dns_dnssec.keyTag(dnskey));

    // The vector's RRSIG is the key-signing form over the MX RRset. The zone
    // now signs data with the 256 form, so the fixed-RRset primitive is what
    // reproduces the published bytes.
    const mx_rdata = [_]u8{ 0, 10, 4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const rrsig = try signRrset(
        allocator,
        try Name.fromText("example.com."),
        try Name.fromText("example.com."),
        RecordType.MX.code(),
        &.{&mx_rdata},
        3600,
        &key,
        rfc8080_window,
    );
    if (!hexEquals(rfc8080_mx_rrsig_hex, rrsig)) {
        std.debug.print("produced {x}\n", .{rrsig});
        return error.TestExpectedEqual;
    }
}

test "RFC 4034 section 2.1.1: the DNSKEY the signer emits carries the Zone Key flag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The RRset carries the key twice: the Zone Key bit (0x0100) alone marks
    // the key that signs the zone data, and the Secure Entry Point bit
    // (0x0001) marks the key that signs the DNSKEY RRset (RFC 6781 section
    // 3.2.3). RFC 8080 section 6.1 publishes exactly the 257 form.
    const keys = try apexDnskeys(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    for (keys) |dnskey| {
        const flags = std.mem.readInt(u16, dnskey[0..2], .big);
        try std.testing.expect(flags & 0x0100 != 0);
        try std.testing.expectEqual(@as(u8, 3), dnskey[2]);
        try std.testing.expectEqual(@as(u8, 15), dnskey[3]);
    }
    try std.testing.expectEqual(@as(u16, 256), std.mem.readInt(u16, keys[0][0..2], .big));
    try std.testing.expectEqual(@as(u16, 257), std.mem.readInt(u16, keys[1][0..2], .big));
}

const second_zone =
    \\$ORIGIN other.example.
    \\$TTL 3600
    \\@ IN SOA ns1.other.example. hostmaster.other.example. 1 3600 900 1209600 3600
    \\@ IN NS ns1.other.example.
    \\ns1 IN A 192.0.2.3
;

test "RFC 8080 section 8: a key that has signed one zone is refused for a second one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var first = try loadZone(rfc8080_zone);
    defer first.deinit();
    try signZone(allocator, &first, &key, rfc8080_window);

    var second = try loadZone(second_zone);
    defer second.deinit();
    try std.testing.expectError(Error.KeyUsedForAnotherZone, signZone(allocator, &second, &key, rfc8080_window));
    // The refused zone carries no DNSKEY, DS, or RRSIG: the refusal comes
    // before the zone is touched.
    try std.testing.expect(!hasRecord(&second, "other.example.", .DNSKEY));
    try std.testing.expect(!hasRecord(&second, "other.example.", .DS));
}

test "RFC 8080 section 8: one key signs one zone, and that zone is signed as before" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The published DNSKEY pair and the signatures over the zone are the
    // shape this zone gets: the 257 form is the RFC 8080 vector and the 256
    // form signs the data.
    const dnskey = try publishedKey(allocator, &zone, 15);
    try std.testing.expectEqualStrings(rfc8080_ed25519_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, dns_dnssec.keyTag(dnskey));
    const rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.MX.code())).?;
    try std.testing.expectEqual(@as(u8, 15), rrsig[2]);
    try std.testing.expect(dns_dnssec.keyTag(dnskey) != std.mem.readInt(u16, rrsig[16..18], .big));

    // The same zone signed again is the old refusal, not the new one.
    try std.testing.expectError(Error.AlreadySigned, signZone(allocator, &zone, &key, rfc8080_window));
}

test "RFC 6605 section 6.1: the P-256 DNSKEY and key tag match the published vector" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc6605_p256_key);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.ecdsa_p256_sha256, key.algorithm());

    // RFC 6605 section 4: the key is the uncompressed point as "x | y", with
    // no SEC 1 0x04 octet. A DNSKEY that carried the prefix would hash to a
    // different DS digest and no validator would accept the signature.
    const dnskey = try key.dnskeyRdata(allocator);
    try std.testing.expectEqual(@as(usize, 68), dnskey.len);
    try std.testing.expectEqualStrings(rfc6605_p256_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc6605_p256_key_tag, dns_dnssec.keyTag(dnskey));
}

test "RFC 6605 section 6.2: the P-384 DNSKEY and key tag match the published vector" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc6605_p384_key);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.ecdsa_p384_sha384, key.algorithm());

    const dnskey = try key.dnskeyRdata(allocator);
    try std.testing.expectEqual(@as(usize, 100), dnskey.len);
    try std.testing.expectEqualStrings(rfc6605_p384_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc6605_p384_key_tag, dns_dnssec.keyTag(dnskey));
}

test "a P-256 signature over a fixed RRset verifies against the key the DNSKEY publishes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc6605_p256_key);
    defer key.deinit();

    const data = try signedData(allocator, .{
        .owner_wire = (try Name.fromText("www.example.net.")).asWire(),
        .rrtype = RecordType.A.code(),
        .ttl = 3600,
        .rdata = try oneRdata(allocator, &.{ 192, 0, 2, 1 }),
    }, .ecdsa_p256_sha256, rfc6605_p256_key_tag, (try Name.fromText("example.net.")).asWire(), .{
        .inception = 1281607479,
        .expiration = 1284026679,
    });

    var signature_buffer: [64]u8 = undefined;
    const signature = try key.sign(data.bytes, &signature_buffer);
    try EcdsaP256Sha256.Signature.fromBytes(signature_buffer).verify(data.bytes, key.material.ecdsa_p256_sha256.public_key);

    // A one-octet change to the signed data must not verify, so the test is
    // checking the signature rather than a signature-shaped constant.
    const tampered = try allocator.dupe(u8, data.bytes);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        EcdsaP256Sha256.Signature.fromBytes(signature_buffer).verify(tampered, key.material.ecdsa_p256_sha256.public_key),
    );
    try std.testing.expectEqual(@as(usize, 64), signature.len);
}

const wildcard_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2026053001 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\ns1 IN A 192.168.1.1
    \\* IN A 192.168.1.99
;

test "RFC 4034 section 3.1.3: a wildcard RRSIG counts no wildcard label and still covers the wildcard owner" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(wildcard_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    const rrsig = (try findOpaque(allocator, &zone, "*.home.arpa.", .RRSIG, RecordType.A.code())).?;
    // Labels excludes the `*`, so "*.home.arpa." is 2 (arpa, home) ...
    try std.testing.expectEqual(@as(u8, 2), rrsig[3]);
    try std.testing.expectEqual(RecordType.A.code(), std.mem.readInt(u16, rrsig[0..2], .big));
    try std.testing.expectEqual(@as(u8, 15), rrsig[2]);
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, rrsig[4..8], .big));
    try std.testing.expectEqual(rfc8080_window.expiration, std.mem.readInt(u32, rrsig[8..12], .big));
    try std.testing.expectEqual(rfc8080_window.inception, std.mem.readInt(u32, rrsig[12..16], .big));
    // The key tag is over DNSKEY RDATA alone, so it does not move with the
    // zone: the data signature names the 256 form the signer publishes.
    const keys = try apexDnskeys(allocator, &zone);
    const data_key = keys[if (std.mem.readInt(u16, keys[0][0..2], .big) == zone_key_flags) 0 else 1];
    try std.testing.expectEqual(dns_dnssec.keyTag(data_key), std.mem.readInt(u16, rrsig[16..18], .big));
    try std.testing.expect(dns_dnssec.keyTag(data_key) != rfc8080_ed25519_key_tag);

    const signer = try Name.fromText("home.arpa.");
    try std.testing.expectEqualSlices(u8, signer.asWire(), rrsig[18 .. 18 + signer.asWire().len]);

    // The wildcard owner is authoritative, so it joins the NSEC chain and a
    // validator expanding a name below it can find the proof.
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .NSEC));
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .RRSIG));
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .A));
}

/// The wildcard RRSIG for `wildcard_zone` under `rfc8080_window`, signed by
/// the RFC 8080 section 6.1 Ed25519 key with the 257 form the fixed-RRset
/// primitive uses. Ed25519 is deterministic (RFC 8032), so these bytes are
/// reproducible; dnspython 2.8.0 accepted this exact signature over
/// `*.home.arpa. IN A 192.168.1.99` when it was produced, and a one-octet
/// change to the preimage does not verify.
const wildcard_rrsig_hex =
    "00010f0200000e1055d4fc6055b94ce0899104686f6d65046172706100686e" ++
    "127d52eb25af24f97369a2f7e990b74aebb703b4d0940f8b7a7624fa30f36ac34" ++
    "8147d427539df830d439fe536885881b8b1796eef010bdcaf3d376a5e04";

test "the wildcard RRSIG is one dnspython 2.8.0 accepted over the wildcard RRset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    const address = [_]u8{ 192, 168, 1, 99 };
    const rrsig = try signRrset(
        allocator,
        try Name.fromText("*.home.arpa."),
        try Name.fromText("home.arpa."),
        RecordType.A.code(),
        &.{&address},
        3600,
        &key,
        rfc8080_window,
    );
    if (!hexEquals(wildcard_rrsig_hex, rrsig)) {
        std.debug.print("produced {x}\n", .{rrsig});
        return error.TestExpectedEqual;
    }
}

test "the NSEC chain links every authoritative owner in canonical order and wraps the last to the first" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // example.com sorts before mail.example.com, which sorts before
    // ns1.example.com, so the chain is apex -> mail -> ns1 -> apex.
    const apex_next = (try Name.fromText("mail.example.com.")).asWire();
    const apex_nsec = (try findOpaque(allocator, &zone, "example.com.", .NSEC, null)).?;
    try std.testing.expectEqualSlices(u8, apex_next, apex_nsec[0..apex_next.len]);

    const mail_next = (try Name.fromText("ns1.example.com.")).asWire();
    const mail_nsec = (try findOpaque(allocator, &zone, "mail.example.com.", .NSEC, null)).?;
    try std.testing.expectEqualSlices(u8, mail_next, mail_nsec[0..mail_next.len]);

    const apex = (try Name.fromText("example.com.")).asWire();
    const last_nsec = (try findOpaque(allocator, &zone, "ns1.example.com.", .NSEC, null)).?;
    try std.testing.expectEqualSlices(u8, apex, last_nsec[0..apex.len]);

    // Every bitmap names NSEC and RRSIG (RFC 4035 section 2.3). The next-owner
    // name's length differs per record, so each bitmap starts where its own
    // next-owner name ends.
    var checked: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC)) continue;
        const rdata = try zone_parser.parseRData(.NSEC, record.rdataText());
        var rdata_bytes = switch (rdata) {
            .Unknown => |unknown| unknown,
            else => return error.TestUnexpectedResult,
        };
        const bitmap = rdata_bytes.bytes()[(try Name.parse(rdata_bytes.bytes(), 0)).next_offset..];
        try std.testing.expect(dns_dnssec.nsecBitmapHasType(bitmap, RecordType.NSEC.code()));
        try std.testing.expect(dns_dnssec.nsecBitmapHasType(bitmap, RecordType.RRSIG.code()));
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), checked);
}

test "a delegation keeps NS and DS and drops the child subtree from the signed zone" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(
        \\$ORIGIN example.com.
        \\$TTL 3600
        \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
        \\@ IN NS ns1.example.com.
        \\ns1 IN A 192.0.2.1
        \\child IN NS ns.child.example.com.
        \\ns.child IN A 192.0.2.53
        \\host.child IN A 192.0.2.54
        \\
    );
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The parent is authoritative for the delegation itself, so it is in the
    // chain with an NSEC; RFC 4035 section 2.2 makes the delegation's NS
    // RRset unsigned data of neither side.
    try std.testing.expect(hasRecord(&zone, "child.example.com.", .NSEC));
    try std.testing.expect((try findOpaque(allocator, &zone, "child.example.com.", .RRSIG, RecordType.NS.code())) == null);

    // Everything strictly below the cut belongs to the child, so the parent
    // signs none of it and puts no NSEC at any of its names.
    try std.testing.expect(!hasRecord(&zone, "ns.child.example.com.", .NSEC));
    try std.testing.expect(!hasRecord(&zone, "host.child.example.com.", .NSEC));
    try std.testing.expect(!hasRecord(&zone, "ns.child.example.com.", .RRSIG));
}

test "a zone that already carries DNSSEC records is refused rather than signed twice" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(
        \\$ORIGIN example.com.
        \\$TTL 3600
        \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
        \\@ IN NS ns1.example.com.
        \\@ IN DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
        \\
    );
    defer zone.deinit();
    try std.testing.expectError(Error.AlreadySigned, signZone(arena.allocator(), &zone, &key, rfc8080_window));
}

test "the signing session wipes the private key when it is deinitialized" {
    var key = try parseKey(rfc8080_ed25519_key);
    var session = Session.start(&key, rfc8080_window);
    const material = &session.key.material;
    // The key is still there before the session is dropped.
    try std.testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(material), 0));
    session.deinit();
    for (std.mem.asBytes(material)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "a window counted from now keeps the validity period it was given" {
    const window = Options{ .inception = 1_000_000_000, .expiration = 1_000_000_000 + 30 * 24 * 60 * 60 };
    const refreshed = window.fromNow(2_000_000_000);
    try std.testing.expectEqual(@as(u32, 2_000_000_000), refreshed.inception);
    try std.testing.expectEqual(
        window.expiration - window.inception,
        refreshed.expiration - refreshed.inception,
    );
}

test "RFC 8080: an Ed448-signed zone carries a 114-octet signature that verifies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(ed448_key);
    defer key.deinit();
    try std.testing.expectEqual(Algorithm.ed448, key.algorithm());

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    const dnskey = (try findOpaque(allocator, &zone, "example.com.", .DNSKEY, null)).?;
    try std.testing.expectEqual(@as(u8, 16), dnskey[3]);
    try std.testing.expectEqual(@as(usize, 57), dnskey.len - 4);
    const rrsig = (try findOpaque(allocator, &zone, "example.com.", .RRSIG, RecordType.MX.code())).?;
    try std.testing.expectEqual(@as(u8, 16), rrsig[2]);

    // Rebuild the canonical signed data for the MX RRset the same way the
    // signer built it, then check the signature over it.
    const apex = try Name.fromText("example.com.");
    const exchange = try Name.fromText("mail.example.com.");
    var mx: [2 + 255]u8 = undefined;
    std.mem.writeInt(u16, mx[0..2], 10, .big);
    @memcpy(mx[2..][0..exchange.asWire().len], exchange.asWire());
    const rrset = Rrset{
        .owner_wire = apex.asWire(),
        .rrtype = RecordType.MX.code(),
        .ttl = 3600,
        .rdata = &[_][]const u8{mx[0 .. 2 + exchange.asWire().len]},
    };
    const signed = try signedData(allocator, rrset, .ed448, dns_dnssec.keyTag(dnskey), apex.asWire(), rfc8080_window);
    try std.testing.expectEqualSlices(u8, signed.bytes[0..signed.header_len], rrsig[0..signed.header_len]);
    const signature = rrsig[signed.header_len..];
    try std.testing.expectEqual(@as(usize, 114), signature.len);
    try std.testing.expect(ed448.verify(
        signed.bytes,
        signature[0..@sizeOf(ed448.Signature)].*,
        dnskey[4..][0..@sizeOf(ed448.PublicKey)].*,
    ));
}

test "an RSA-3072 signature fills 384 octets and validates against its own DNSKEY" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const key_file = try rsaKeyFile(allocator, "RSASHA256", rsa3072_modulus, rsa3072_exponent, rsa3072_private);
    var key = try parseKey(key_file);
    defer key.deinit();

    const signer = try Name.fromText("example.com.");
    const rrsig = try signRrset(allocator, try Name.fromText("www.example.com."), signer, RecordType.A.code(), try oneRdata(allocator, &.{ 192, 0, 2, 1 }), 3600, &key, rfc5702_sha256_window);
    const signature = rrsig[18 + signer.asWire().len ..];
    // The old 128-octet tail could never hold this; the buffer was the bug.
    try std.testing.expectEqual(@as(usize, 384), signature.len);
    try std.testing.expect(signature.len > 128);
    try std.testing.expectEqual(@as(usize, 18 + signer.asWire().len + 384), rrsig.len);

    var zone = try loadZone(rsa_large_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc5702_sha256_window);
    const dnskey = try publishedKey(allocator, &zone, 8);
    try expectSignedBy(allocator, &zone, dnskey, dns_dnssec.keyTag(dnskey));
}

test "an RSA-4096 signature fills 512 octets and validates against its own DNSKEY" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const key_file = try rsaKeyFile(allocator, "RSASHA512", rsa4096_modulus, rsa4096_exponent, rsa4096_private);
    var key = try parseKey(key_file);
    defer key.deinit();

    const signer = try Name.fromText("example.com.");
    const rrsig = try signRrset(allocator, try Name.fromText("www.example.com."), signer, RecordType.A.code(), try oneRdata(allocator, &.{ 192, 0, 2, 1 }), 3600, &key, rfc5702_sha512_window);
    const signature = rrsig[18 + signer.asWire().len ..];
    try std.testing.expectEqual(@as(usize, 512), signature.len);
    try std.testing.expectEqual(@as(usize, 18 + signer.asWire().len + 512), rrsig.len);

    var zone = try loadZone(rsa_large_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc5702_sha512_window);
    const dnskey = try publishedKey(allocator, &zone, 10);
    try expectSignedBy(allocator, &zone, dnskey, dns_dnssec.keyTag(dnskey));
}

const rsa_large_zone =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
;

const rfc5702_sha512_window = Options{ .inception = 946684800, .expiration = 1893456000 };
const rsa3072_exponent = "AQAB";
const rsa3072_modulus = "pFcya5+2nEuBWvguun+YpfZpALwdwy7K+7UPZWzp6cAVnFZSAohTxSsjXz0zor62yk/kpmMHiQRQvkxrJMZEfFerT1pk8fOIxBUsUh6HY59+V0kM1jXjXqNYFrvX/+UOVXlZO1o7GBw6R//9mChvbKXICVklMG2mDmjpNa7z/Y5IgFEtd3SMHfaf9Ahikp8GIW7wG9LKFbD3ht04c6U5chdqLd9jczGUxjR8zhwHGJPNQRW3mKA/C9BKpsO9g2/8fv1G5hOnkPAcUkQxvEBs+wh7FlRVWeme74FlKrRBpK4TctTCKshzrT9A+DSR6SGoyWHhM2r57sKvVG56DFWRpHdFK02I8E5jpm/MpBu7bBG5U9DAWumOD6musRIXxj7VvUKvXK3r6Y8f5Ix5eNoMWEoa7W4S0Qe0DSMvnRRtDUTlSxm+8Jvdbh+v6Erk5EjmxJ6t/nq2mZN0reTCRPIT/aPSQuW5Nj96Sntf2hiHHzFHvoiCQIPuJdW9FPyrMqTh";
const rsa3072_private = "GedMoT4pcHVOTGJ2KxtVmkM+xcjhABTuFcKyTJBgRmHqhhvtDU0jtx5Xkvl4nBxnf3gcWEWfuG8fsv8knEVMIjVHYVikNKboVc/ojoEVYhSPu35eMZ2I2y/wAJVXNJSML9jSwdI1IlXAsfydolAtT/jJkP+mJv4BgJ/0smuDNeIpd2BURFHwjACFsddogifitX5hBmGxTL36Jh3UehX++gbKy7Q8Xrnf82XujiZI0Azr+2hK6hnIFjqcqbCMvJz39KQK0uuT5d7uiQ5rKu2LnsTtPx7NWumMDQ+07l+z/KC3nfG97QB8HI/FPTd+1mF5cGj8viX0Ks3MBzLj/O4enc0CLt3dqAA4anAN/LdM5R+rlx6Gj+3aE6F78YQFhXdd4a+A2alSbZIIJBfjkeJ5xe5YYsnFiYbDCYh8INfAcFVIbMUMY5QOIoPdrO5bziePd0pXeSlrwi1pprfvx9dKBbP8I+gMf2I6nd5im048XbPecrVyRB6WLR3SOcGQg5bh";
const rsa4096_exponent = "AQAB";
const rsa4096_modulus = "30RU9zC9HWYGwHeaNOKEiuqru2gDNNW41tyOjBvPgHs3YiE7Meys2WLBrRf4D1F6p5iZthBfhRn4dJdfRMVAx9s9BTyE6hCNRZH54kxjPKLzP0KN6k+ADkLcuf3ov91yWzUEiko6T75kobcNno3B96t4S0QVIBeDbrTSbO4BabYoPg7vp/nB3weK+HEMNr4URrC4IhBHEJrKxP+rndrmldVi5GLY19qV9aGDY7CL/RGycr996mzBtBDoSHAV+Ihm27L6bz6oGdjoxMVIq7ObxgIdiNOk+BLrx8jvCHOvPS6bXTZbOygAYgyyEwd5XH4u3qsATSvJ71BBUTbRwLxinC+j1lC1Iz8MJTT2Yjql/FiX+dAYNRnyenhzZlIVUjCzpUELWs5a/L2YApUi/AXZ9xEn5OjOvm3FGZ4Xgh953qRW/zve+jF53Ctw07ZOxzy9DLgGCcFaHLSx3ZBtAmRVwxCAk/ep+ORkpYLG0uuluZutbS9jZIJHUHTEIN3DA1b1DFIPDpmAV0IRn/RPeB3VzQt7Z3AmLaTpE1uw9lQ8cb3ce8GQ99dWx1i7NMDWSerEMbj3FyZ41DbBqrty68aRJR1pAZan9xtHPTGGkMNGpLWMY2NWyRaLdbCfvf1pJWlRTZEncpzywD2gjQHEUCjK4ICRAurMBzXQPzVlj0o23J8=";
const rsa4096_private = "F8IvwHZBSaWXxldz43jPXfEHAVRaMv8jQkoKKUK0XBnAlQKwR+nFowRtU7wfO5ISGU+V29f2MjXHSLDrBGhxMlNUNQBxrG7CecrE6p3yWXuFow+0BmEbYWkgD/LDF9e62ZXUu9qWRfIex06xdlPjdjWbAXdnQBkAdYFsewcAw30M3z27pwZe6RrmYPW2tQSZJ8Sac5WD2nJ+bWQ/oPawXvVsJp2WMbIjDxZ24t7gpreBY9CY159nJYA/F6ZF0ELDn1F2cOwb+1QnwPi1eQAN7Y5AElVjUrrAuGvbc+zLkxkok0y7fJoPIF/1eyzqbztGRY+w4oVsYbkKmlfZDkd9vqo0f1JyFFj6CWjZsYOWMfB4oH1pxbsuFNiigiQLE3x2slsiT3Tv3vhFcZISv4IadzcMTpm0siKHqDU1sPip+irqZ65In6WqBzWxQU1Z2zCVmNv10EnYJsgB0E6L6B2vOSrSxVl7bTSrtC/DWtQiaBi3T491juXoiZGi5XZSVj7VqYCFIE0hx8MaChIA0VkrVXnOW5GriGzcXku1y+hjs5h9taIc7Twu0tgiAWxWLKR2zYKetsIjkmw1ZuolSwlx2qjMslG4VCi1yw4Vqo+irkEkB5TlyVdjWyaU/4ah6QUYl17HKKcySMsztOFc5MXtkVlb0KpfKPISMmJ7CzfLxKE=";
test "the key file accepts only one known algorithm and a correctly sized secret" {
    try std.testing.expectError(Error.BadKeyFile, parseKey("rsa-sha256 AAAA\n"));
    try std.testing.expectError(Error.BadSecret, parseKey("ed448 AAAA\n"));
    try std.testing.expectError(Error.BadSecret, parseKey("ed25519 QUJD\n"));
    try std.testing.expectError(Error.BadKeyFile, parseKey("# only a comment\n"));
    try std.testing.expectError(Error.BadKeyFile, parseKey("ed25519 AAAA BBBB\n"));
    try std.testing.expectError(Error.BadSecret, parseKey("ed25519 !!!!\n"));
    try std.testing.expectError(Error.BadKeyFile, parseKey("\n\n   \n"));
}

test "RFC 4034 Appendix B: an odd-length DNSKEY RDATA pads its last octet on the right" {
    // Three octets 0x01 0x02 0x03 sum as 0x0102 + 0x0300.
    try std.testing.expectEqual(@as(u16, 0x0402), dns_dnssec.keyTag(&.{ 1, 2, 3 }));
    try std.testing.expectEqual(@as(u16, 0x0102), dns_dnssec.keyTag(&.{ 1, 2 }));
}

// ------------------------------------------------------------------- NSEC3

/// A zone that asks for an NSEC3 chain: the apex NSEC3PARAM states the
/// parameters of the chain, and the signer builds that chain
/// (RFC 5155 section 7.1).
const nsec3_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 0 -
    \\www IN A 192.0.2.1
    \\
;

/// The same zone with a salt in its apex NSEC3PARAM: RFC 9276 section 3.1
/// says an operator SHOULD NOT use a salt, so the signer refuses the zone.
const nsec3_salt_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 0 73616c74
    \\www IN A 192.0.2.1
    \\
;

/// A zone whose own apex NSEC3PARAM asks for an iteration count above 0
/// (RFC 9276 section 3.1): the signer refuses it rather than publish it.
const nsec3_iterations_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 2 -
    \\www IN A 192.0.2.1
    \\
;

/// The same zone without the NSEC3PARAM: it keeps the NSEC chain.
const nsec_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\
;

/// The NSEC3 hashes of that zone, as the python hashlib oracle computed them:
/// the SHA-1 of the canonical wire name, with no salt and no extra iteration.
const nsec3_apex_hash = [_]u8{ 0x1d, 0xb8, 0xef, 0xa7, 0xdc, 0xb3, 0x48, 0xbd, 0xa7, 0x89, 0x3f, 0xca, 0x1d, 0x8b, 0xad, 0xfd, 0xb6, 0x99, 0x6b, 0x01 };
const nsec3_www_hash = [_]u8{ 0x4d, 0x35, 0x7d, 0xe6, 0xee, 0xa6, 0x6a, 0xb6, 0x74, 0x56, 0x1d, 0x13, 0x38, 0x8d, 0x95, 0x9f, 0xe5, 0x8a, 0x09, 0x65 };

/// One NSEC3 record of a signed zone, as the zone holds it.
const Nsec3Record = struct {
    owner_text: []const u8,
    flags: u8,
    next_hash: []const u8,
    bitmap: []const u8,
};

/// The NSEC3 records of a zone, in the order the zone holds them.
fn nsec3Records(allocator: std.mem.Allocator, zone: *const zone_index.Zone) ![]Nsec3Record {
    var out: std.ArrayList(Nsec3Record) = .empty;
    errdefer out.deinit(allocator);
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC3)) continue;
        const parsed = try zone_parser.parseRData(.NSEC3, record.rdataText());
        const bytes = switch (parsed) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return error.TestUnexpectedResult,
        };
        // The parsed RDATA is a local, so the decoded fields are copied out of
        // it before it goes out of scope.
        const raw = try allocator.dupe(u8, bytes);
        const decoded = dns_validate.parseNsec3Rdata(raw) orelse return error.TestUnexpectedResult;
        try out.append(allocator, .{
            .owner_text = record.ownerText(),
            .flags = decoded.flags,
            .next_hash = decoded.next_hash,
            .bitmap = decoded.bitmap,
        });
    }
    return out.toOwnedSlice(allocator);
}

/// The zone-signing DNSKEY of a signed zone, as a trust anchor for the
/// validator. Zone data is signed with this key; the DNSKEY RRset is signed
/// with the key-signing form, which such a test response does not carry.
fn dnskeyAnchor(allocator: std.mem.Allocator, key: *const Key) ![]const u8 {
    const rdata = try key.dnskeyRdataWithFlags(allocator, zone_key_flag);
    const encoded = try encodeBase64(allocator, rdata[4..]);
    return std.fmt.allocPrint(allocator, "example. DNSKEY 256 3 15 {s}\n", .{encoded});
}

/// A DO-bit query, so the answer carries the RRSIGs that cover it.
fn doBitQuery(allocator: std.mem.Allocator, name_text: []const u8, qtype: dns_types.RecordType) !dns_message.Message {
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4406 },
        .question = .{
            .name = try Name.fromText(name_text),
            .qtype = qtype,
            .qclass = dns_types.Class.IN,
        },
    };
    message.edns = .{
        .udp_payload_size = 1232,
        .extended_rcode = 0,
        .version = 0,
        .dnssec_ok = true,
    };
    try message.additionals.append(.{
        .owner = Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0x8000,
        .rdata = .{ .OPT = .{} },
    });
    message.header.additional_count = 1;
    return message;
}

test "an apex NSEC3PARAM makes the signer publish the NSEC3 chain (RFC 5155 7.1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    // The chain is in hash order: the hash of the apex sorts before the hash
    // of "www.example.".
    try std.testing.expectEqualStrings("3msev9usmd4br9s97v51r2tdvmr9iqo1.example.", records[0].owner_text);
    try std.testing.expectEqualStrings("9kqnrpnekplbct2m3k9jh3cljviok2b5.example.", records[1].owner_text);
    // Each record names the next hash, and the last wraps to the first.
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, records[0].next_hash);
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, records[1].next_hash);
    // The zone publishes the NSEC3 chain, not an NSEC one.
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC));
    try std.testing.expect(!hasRecord(&zone, "www.example.", .NSEC));
    // The apex keeps the NSEC3PARAM it was signed with.
    try std.testing.expect(hasRecord(&zone, "example.", .NSEC3PARAM));
}

test "an empty non-terminal has an NSEC3 of its own (RFC 5155 7.1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\@ IN NSEC3PARAM 1 0 0 -
        \\a.b IN A 192.0.2.1
        \\
    );
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // "b.example." holds no RRset, but it is an owner name of the zone, so it
    // has an NSEC3 like any other.
    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 3), records.len);
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try Name.fromText("b.example."), "", 0, &out);
    var found = false;
    for (records) |record| {
        const owner = try Name.fromText(record.owner_text);
        const hash = dns_validate.nsec3OwnerHash(owner) orelse return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, &hash, &out)) continue;
        found = true;
        // The name holds no type, so its bitmap is empty.
        try std.testing.expectEqual(@as(usize, 0), record.bitmap.len);
    }
    try std.testing.expect(found);
}

test "the NSEC3 chain carries the hashes the hashlib oracle computed (RFC 5155 5)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The owner label of an NSEC3 decodes back to the hash of the name it
    // was built from. The chain is in hash order, so the two names are
    // looked up by their hash and not by their place in it.
    const records = try nsec3Records(allocator, &zone);
    var saw_apex = false;
    var saw_www = false;
    for (records) |record| {
        const owner = try Name.fromText(record.owner_text);
        const hash = dns_validate.nsec3OwnerHash(owner).?;
        if (std.mem.eql(u8, &hash, &nsec3_apex_hash)) saw_apex = true;
        if (std.mem.eql(u8, &hash, &nsec3_www_hash)) saw_www = true;
    }
    try std.testing.expect(saw_apex);
    try std.testing.expect(saw_www);

    // The project's own hash function computes the same two values, so the
    // signer and the serving path agree on every hash.
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try Name.fromText("www.example."), "", 0, &out);
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, &out);
    dns_dnssec.nsec3Hash(try Name.fromText("example."), "", 0, &out);
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, &out);
}

test "the NSEC3 chain is signed, and the project's own validator accepts it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // Every NSEC3 of the chain carries the RRSIG that covers it.
    const records = try nsec3Records(allocator, &zone);
    for (records) |record| {
        const rrsig = (try findOpaque(allocator, &zone, record.owner_text, .RRSIG, RecordType.NSEC3.code())).?;
        // RFC 4034 section 3.1.3: the label count is the one of the RRSIG's
        // own owner name, which for an NSEC3 is the hashed name.
        try std.testing.expectEqual(@as(u8, 2), rrsig[3]);
    }

    // The served denial is proved by the generated chain.
    const request = try doBitQuery(allocator, "missing.example.", .A);
    const response = try (@import("../auth/response.zig")).buildResponse(request, &zone);
    // The closest encloser proof (RFC 5155 section 7.2.2) and the apex
    // NSEC3PARAM ride along, and no NSEC proof does.
    var nsec3_count: usize = 0;
    var param_count: usize = 0;
    for (response.authorities.items) |record| {
        if (record.rrtype.eql(.NSEC3)) nsec3_count += 1;
        if (record.rrtype.eql(.NSEC3PARAM)) param_count += 1;
        try std.testing.expect(!record.rrtype.eql(.NSEC));
    }
    try std.testing.expect(nsec3_count >= 1);
    try std.testing.expectEqual(@as(usize, 1), param_count);
}

test "the project's own validator accepts the signatures over the NSEC3 chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The chain as the zone holds it, with the RRSIG that covers every record
    // of it, is a response the validator accepts.
    var response = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4406, .qr = true, .rcode = .nxdomain },
        .question = .{
            .name = try Name.fromText("missing.example."),
            .qtype = .A,
            .qclass = dns_types.Class.IN,
        },
    };
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC3) and !record.rrtype.eql(.RRSIG)) continue;
        if (record.rrtype.eql(.RRSIG)) {
            const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
            const bytes = switch (rdata) {
                .Unknown => |*unknown| unknown.bytes(),
                else => continue,
            };
            if (bytes.len < 2 or std.mem.readInt(u16, bytes[0..2], .big) != RecordType.NSEC3.code()) continue;
        }
        try response.authorities.append(try (@import("../auth/response.zig")).zoneRecordToResourceRecord(record, null));
    }
    response.header.authority_count = @intCast(response.authorities.len);
    try std.testing.expectEqual(@as(usize, 4), response.authorities.len);

    // The DNSKEY the zone publishes is the trust anchor, so the chain needs
    // no DNSKEY of its own to verify.
    var anchors = try dns_validate.Anchors.parse(allocator, try dnskeyAnchor(allocator, &key));
    defer anchors.deinit(allocator);
    const request = try doBitQuery(allocator, "missing.example.", .A);
    const result = try dns_validate.validate(allocator, &anchors, request, response, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);
}

test "a zone without an apex NSEC3PARAM keeps exactly its NSEC chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The NSEC chain of the zone is unchanged: one NSEC per owner, in
    // canonical order, and no NSEC3 record at all.
    const apex = (try findOpaque(allocator, &zone, "example.", .NSEC, null)).?;
    const next = try Name.fromText("www.example.");
    try std.testing.expectEqualSlices(u8, next.asWire(), apex[0..next.asWire().len]);
    // The bitmap names SOA, NS, DNSKEY, NSEC, and RRSIG; the DS belongs to
    // the parent (RFC 4035 section 2.2).
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x07, 0x22, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80 }, apex[next.asWire().len..]);
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC3));
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC3PARAM));
}

/// The first record of a type at an owner name.
fn findZoneRecord(zone: *const zone_index.Zone, owner_text: []const u8, rrtype: RecordType) !?zone_parser.ZoneRecord {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.code() != rrtype.code()) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner_text)) continue;
        return record;
    }
    return null;
}

test "the operator's NSEC choice drops the zone's own NSEC3PARAM" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_sign_zone);
    defer zone.deinit();
    var options = rfc8080_window;
    options.chain = .{ .chain = .nsec };
    try signZone(allocator, &zone, &key, options);

    // The zone publishes the RFC 4034 chain, one NSEC per owner, and no NSEC3
    // record at all.
    try std.testing.expect(hasRecord(&zone, "example.", .NSEC));
    try std.testing.expect(hasRecord(&zone, "www.example.", .NSEC));
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC3));
    try std.testing.expect(!hasRecord(&zone, "www.example.", .NSEC3));
    const apex = (try findOpaque(allocator, &zone, "example.", .NSEC, null)).?;
    const next = try Name.fromText("www.example.");
    try std.testing.expectEqualSlices(u8, next.asWire(), apex[0..next.asWire().len]);
    // RFC 5155 section 7.3: the apex NSEC3PARAM states the parameters of the
    // chain the zone publishes, so a zone that publishes the NSEC chain does
    // not carry one. It is dropped before the zone is signed, so no
    // signature covers it either.
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC3PARAM));
}

test "a zone that is signed again keeps the chain the served zone publishes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    // The served zone publishes the NSEC3 chain, because its own apex
    // NSEC3PARAM states the parameters of that chain.
    var served = try loadZone(nsec3_sign_zone);
    defer served.deinit();
    try signZone(allocator, &served, &key, rfc8080_window);
    const served_dnskey = (try findOpaque(allocator, &served, "example.", .DNSKEY, null)).?;

    var zone = try loadZone(nsec_sign_zone);
    defer zone.deinit();
    try resignZone(allocator, &zone, &key, rfc8080_window, &served);

    // The key is the one the server holds, so the key tag does not move with
    // the zone, and no apex DS is published either way.
    const dnskey = (try findOpaque(allocator, &zone, "example.", .DNSKEY, null)).?;
    try std.testing.expectEqualSlices(u8, served_dnskey, dnskey);
    try std.testing.expect((try findOpaque(allocator, &zone, "example.", .DS, null)) == null);

    // The chain is the one the served zone publishes: NSEC3, with the
    // parameters its NSEC3PARAM states.
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC));
    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    const param = (try findOpaque(allocator, &zone, "example.", .NSEC3PARAM, null)).?;
    try std.testing.expectEqual(@as(u8, 1), param[0]);
    try std.testing.expectEqual(@as(u8, 0), param[1]);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, param[2..4], .big));
    // RFC 9276 section 3.1: the chain the zone publishes carries no salt.
    try std.testing.expectEqual(@as(u8, 0), param[4]);

    // A served zone that publishes the NSEC chain is signed again with it.
    var nsec_served = try loadZone(nsec_sign_zone);
    defer nsec_served.deinit();
    try signZone(allocator, &nsec_served, &key, rfc8080_window);

    var nsec_zone = try loadZone(nsec3_sign_zone);
    defer nsec_zone.deinit();
    try resignZone(allocator, &nsec_zone, &key, rfc8080_window, &nsec_served);

    try std.testing.expect(hasRecord(&nsec_zone, "example.", .NSEC));
    try std.testing.expect(hasRecord(&nsec_zone, "www.example.", .NSEC));
    try std.testing.expect(!hasRecord(&nsec_zone, "example.", .NSEC3));
    // RFC 5155 section 7.3: a zone that publishes the NSEC chain carries no
    // NSEC3PARAM, so the record the file states is dropped.
    try std.testing.expect(!hasRecord(&nsec_zone, "example.", .NSEC3PARAM));
}

test "the operator's NSEC3 choice builds the chain in a zone that states no NSEC3PARAM" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec_sign_zone);
    defer zone.deinit();
    var options = rfc8080_window;
    options.chain = .{ .chain = .nsec3, .iterations = 0, .salt = "" };
    try signZone(allocator, &zone, &key, options);

    // The zone publishes the NSEC3 chain and no NSEC record at all.
    try std.testing.expect(!hasRecord(&zone, "example.", .NSEC));
    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), records.len);

    // RFC 5155 section 7.3: the parameters of the chain are stated by the
    // NSEC3PARAM at the zone apex, which the signer publishes for a zone
    // that states none.
    const param = (try findOpaque(allocator, &zone, "example.", .NSEC3PARAM, null)).?;
    try std.testing.expectEqual(@as(u8, 1), param[0]);
    try std.testing.expectEqual(@as(u8, 0), param[1]);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, param[2..4], .big));
    try std.testing.expectEqual(@as(u8, 0), param[4]);

    // The chain is built with the parameters the operator named: the
    // unsalted hash of the apex name is one of its owner names.
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try Name.fromText("example."), "", 0, &out);
    var found = false;
    for (records) |record| {
        const owner = try Name.fromText(record.owner_text);
        const hash = dns_validate.nsec3OwnerHash(owner) orelse return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, &hash, &out)) continue;
        found = true;
    }
    try std.testing.expect(found);
}

test "RFC 9276 section 3.1: the signer refuses an NSEC3 chain whose iteration count is not 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    // A zone whose own apex NSEC3PARAM asks for an iteration count above 0:
    // the chain it would publish is one a validator treats the answer it
    // proves as insecure over, so the zone is refused.
    var zone = try loadZone(nsec3_iterations_sign_zone);
    defer zone.deinit();
    try std.testing.expectError(error.InsecureChainParameters, signZone(allocator, &zone, &key, rfc8080_window));

    // The operator's directive asking for one is refused the same way.
    var directed = try loadZone(nsec_sign_zone);
    defer directed.deinit();
    var options = rfc8080_window;
    options.chain = .{ .chain = .nsec3, .iterations = 2, .salt = "" };
    try std.testing.expectError(error.InsecureChainParameters, signZone(allocator, &directed, &key, options));
}

test "RFC 9276 section 3.1: the signer refuses an NSEC3 chain that states a salt" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    // A zone whose own apex NSEC3PARAM asks for a salt: RFC 9276 section 3.1
    // says an operator SHOULD NOT use one, so the zone is refused rather
    // than published as a salted chain.
    var zone = try loadZone(nsec3_salt_sign_zone);
    defer zone.deinit();
    try std.testing.expectError(error.InsecureChainParameters, signZone(allocator, &zone, &key, rfc8080_window));

    // The same zone with an empty salt signs as it always did, and the apex
    // NSEC3PARAM it publishes states the empty salt.
    var unsalted = try loadZone(nsec3_sign_zone);
    defer unsalted.deinit();
    try signZone(allocator, &unsalted, &key, rfc8080_window);
    const param = (try findOpaque(allocator, &unsalted, "example.", .NSEC3PARAM, null)).?;
    try std.testing.expectEqual(@as(u8, 1), param[0]);
    try std.testing.expectEqual(@as(u8, 0), param[1]);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, param[2..4], .big));
    try std.testing.expectEqual(@as(u8, 0), param[4]);
}

/// A zone with an unsigned delegation whose apex NSEC3PARAM asks for the
/// Opt-Out flag (RFC 5155 section 3.1.2.1): the chain leaves the delegation
/// out and the record that covers it carries the flag.
const nsec3_optout_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 1 0 -
    \\www IN A 192.0.2.1
    \\unsigned-sub IN NS ns.unsigned-sub.example.
    \\
;

/// The same zone with the flag clear: the delegation keeps its NSEC3, and no
/// record of the chain covers an unsigned delegation.
const nsec3_optout_clear_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 0 -
    \\www IN A 192.0.2.1
    \\unsigned-sub IN NS ns.unsigned-sub.example.
    \\
;

/// The hash of the unsigned delegation of that zone, as the hashlib oracle
/// computed it with no salt and no extra iteration.
const nsec3_unsigned_sub_hash = [_]u8{ 0x3f, 0xa6, 0xb7, 0x73, 0xa5, 0x32, 0x32, 0x67, 0x4a, 0xfa, 0x0f, 0x56, 0x92, 0xfc, 0xef, 0x27, 0xc7, 0xa7, 0x92, 0x3d };

test "a zone with an unsigned delegation and an Opt-Out NSEC3PARAM is signed with an Opt-Out chain (RFC 5155 7.1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_optout_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // RFC 5155 section 7.1: the owner name of an unsigned delegation is left
    // out of an Opt-Out chain, so the chain holds the apex and "www" only.
    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 2), records.len);

    var matched = false;
    var covered = false;
    for (records) |record| {
        // RFC 5155 section 7.1: every record of an Opt-Out chain carries the
        // flag, so the record that covers the delegation does too.
        try std.testing.expect(record.flags & dns_validate.nsec3_opt_out != 0);
        const owner = try Name.fromText(record.owner_text);
        const owner_hash = dns_validate.nsec3OwnerHash(owner) orelse return error.TestUnexpectedResult;
        if (std.mem.eql(u8, &owner_hash, &nsec3_unsigned_sub_hash)) matched = true;
        if (record.next_hash.len != 20) return error.TestUnexpectedResult;
        if (!dns_validate.nsec3Covers(owner_hash, record.next_hash[0..20].*, nsec3_unsigned_sub_hash)) continue;
        covered = true;
    }
    // The chain never claims the delegation itself exists.
    try std.testing.expect(!matched);
    // The delegation's next closer name is covered by a record of the chain.
    try std.testing.expect(covered);
}

test "the same zone without the Opt-Out flag keeps every record and carries no flag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_optout_clear_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The chain is the one it always was: every owner name keeps its NSEC3,
    // the delegation among them.
    const records = try nsec3Records(allocator, &zone);
    try std.testing.expectEqual(@as(usize, 3), records.len);

    var matched = false;
    for (records) |record| {
        // RFC 5155 section 3.1.2.1: a record that is not Opt-Out covers no
        // unsigned delegation.
        try std.testing.expectEqual(@as(u8, 0), record.flags & dns_validate.nsec3_opt_out);
        const owner = try Name.fromText(record.owner_text);
        const owner_hash = dns_validate.nsec3OwnerHash(owner) orelse return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, &owner_hash, &nsec3_unsigned_sub_hash)) continue;
        matched = true;
        // The NS RRset at an insecure delegation is left unsigned (RFC 4035
        // section 2.2), and the RRSIG over the NSEC3 is at the hashed owner,
        // so the bitmap names NS alone (RFC 5155 section 7.1).
        try std.testing.expect(dns_dnssec.nsecBitmapHasType(record.bitmap, RecordType.NS.code()));
        try std.testing.expect(!dns_dnssec.nsecBitmapHasType(record.bitmap, RecordType.RRSIG.code()));
        try std.testing.expect(!dns_dnssec.nsecBitmapHasType(record.bitmap, RecordType.DS.code()));
    }
    try std.testing.expect(matched);
}

test "the referral to an unsigned delegation under an Opt-Out chain is proved (RFC 5155 7.2.7, 8.9)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(nsec3_optout_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The delegation is unsigned and the chain holds no NSEC3 for it, so the
    // answer is a referral with the closest provable encloser proof of
    // section 7.2.7.
    const request = try doBitQuery(allocator, "unsigned-sub.example.", .A);
    const response = try (@import("../auth/response.zig")).buildResponse(request, &zone);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(!response.header.authoritative);

    // The proof carries the NSEC3 that covers the next closer name of the
    // delegation, and that record carries the Opt-Out flag.
    var covered = false;
    for (response.authorities.items) |record| {
        if (!record.rrtype.eql(.NSEC3)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const rdata = dns_validate.parseNsec3Rdata(raw) orelse return error.TestUnexpectedResult;
        if (rdata.next_hash.len != 20) return error.TestUnexpectedResult;
        const owner_hash = dns_validate.nsec3OwnerHash(record.owner) orelse return error.TestUnexpectedResult;
        if (!dns_validate.nsec3Covers(owner_hash, rdata.next_hash[0..20].*, nsec3_unsigned_sub_hash)) continue;
        covered = true;
        try std.testing.expect(rdata.flags & dns_validate.nsec3_opt_out != 0);
    }
    try std.testing.expect(covered);

    // The project's own validator accepts the answer: the delegation is proved
    // unsigned (RFC 5155 section 8.9).
    var anchors = dns_validate.Anchors{};
    const result = try dns_validate.validate(allocator, &anchors, request, response, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.insecure, result.status);
}

/// A zone whose owner names and whose RDATA names are written in upper case.
const mixed_case_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\WWW IN CNAME Target.Example.
    \\Target IN A 192.0.2.1
    \\
;

/// The same zone written in lower case: the twin the canonical form of the
/// zone above must match.
const lower_case_sign_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN CNAME target.example.
    \\target IN A 192.0.2.1
    \\
;

test "RFC 4034 6.2: the signature is over the canonical form and the served name is not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(mixed_case_sign_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    // The answer the server serves carries the case the zone wrote: the
    // owner of the CNAME and the name inside its RDATA.
    const request = try doBitQuery(allocator, "www.example.", .A);
    const response = try (@import("../auth/response.zig")).buildResponse(request, &zone);
    try std.testing.expectEqual(@as(usize, 4), response.answers.len);
    var text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("WWW.example.", try response.answers.items[0].owner.toText(&text));
    try std.testing.expectEqualStrings("Target.Example.", try response.answers.items[0].rdata.CNAME.toText(&text));

    // The validator reads the answer off the wire, where the case is the one
    // the zone wrote, and rebuilds the canonical form from it (RFC 4034
    // section 6.2), so the signature the signer made still verifies.
    var encoded: [2048]u8 = undefined;
    var writer = dns_writer.Writer.init(&encoded);
    try response.encode(&writer);
    const wire = try dns_message.Message.parse(allocator, writer.written());
    var anchors = try dns_validate.Anchors.parse(allocator, try dnskeyAnchor(allocator, &key));
    defer anchors.deinit(allocator);
    const result = try dns_validate.validate(allocator, &anchors, request, wire, &.{}, rfc8080_window.inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);
}

test "RFC 8976: the ZONEMD digest of a mixed-case zone is the digest of its lower-case twin" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var mixed = try loadZone(mixed_case_sign_zone);
    defer mixed.deinit();
    var lower = try loadZone(lower_case_sign_zone);
    defer lower.deinit();

    // RFC 4034 section 6.2: the digest covers the canonical form, in which
    // every name is lowercase, so the two zones digest the same.
    var mixed_digest: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
    var lower_digest: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
    try zonemd.computeDigest(&mixed, .sha384, allocator, &mixed_digest);
    try zonemd.computeDigest(&lower, .sha384, allocator, &lower_digest);
    try std.testing.expectEqualSlices(u8, lower_digest[0..48], mixed_digest[0..48]);
}
