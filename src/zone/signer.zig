/// Contract: Signs one primary zone with a single DNSSEC key -- ECDSA P-256
/// (RFC 6605 algorithm 13), ECDSA P-384 (RFC 6605 algorithm 14), or Ed25519
/// (RFC 8080 algorithm 15) -- producing the apex DNSKEY and DS, an NSEC chain
/// of denial, and one RRSIG per RRset (RFC 4034 sections 3.1.8.1 and 5.1.4,
/// RFC 4035 section 2.3).
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
    AlreadySigned,
    KeyUsedForAnotherZone,
    SigningFailed,
    OutOfMemory,
};

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

/// The signing algorithms this build carries. RSA (IANA algorithms 5, 7, 8,
/// 10) and Ed448 (RFC 8080 algorithm 16) are absent: the standard library has
/// no primitive for either, and adding one is out of scope.
pub const Algorithm = enum(u8) {
    ecdsa_p256_sha256 = 13,
    ecdsa_p384_sha384 = 14,
    ed25519 = 15,

    pub fn mnemonic(self: Algorithm) []const u8 {
        return switch (self) {
            .ecdsa_p256_sha256 => "ECDSAP256SHA256",
            .ecdsa_p384_sha384 => "ECDSAP384SHA384",
            .ed25519 => "ED25519",
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

/// RFC 4034 section 2.1.1: bit 7 (0x0100) marks a zone-signing key and bit 15
/// (0x0001) marks a key a parent publishes as a trust anchor. One key does both
/// here, which is why every example key file uses 257, the value RFC 8080
/// section 6.1 publishes; RFC 6781 section 3.2.3 asks a single-type signing
/// scheme to set the Secure Entry Point bit on every key, which is this one.
const dnskey_flags: u16 = 257;
/// RFC 4034 section 2.1.2 fixes protocol at 3; other values MUST NOT be used.
const dnskey_protocol: u8 = 3;

/// DNSKEY, RRSIG, and DS RDATA are served opaque and bounded by
/// `max_unknown_len`, so the signer reuses that ceiling instead of inventing a
/// second one.
const max_rdata_len = dns_rdata.max_unknown_len;

const Material = union(Algorithm) {
    ecdsa_p256_sha256: EcdsaP256Sha256.KeyPair,
    ecdsa_p384_sha384: EcdsaP384Sha384.KeyPair,
    ed25519: Ed25519.KeyPair,
};

pub const Key = struct {
    material: Material,
    /// The zone this key has signed, if any. RFC 8080 section 8: a private key
    /// used for a DNSSEC zone must not be used for any other purpose than for
    /// that zone, so one key signs one zone.
    signed_zone: ?Name = null,

    pub fn algorithm(self: *const Key) Algorithm {
        return self.material;
    }

    /// RFC 6605 section 4 fixes the ECDSA Signature field at the raw `r | s`
    /// concatenation of fixed-width big-endian octets; RFC 8080 section 3 uses
    /// the RFC 8032 `R || S` form. The standard library emits both as
    /// fixed-width big-endian pairs, so `toBytes` is the DNSSEC encoding.
    fn sign(self: *const Key, message: []const u8, out: []u8) Error![]const u8 {
        switch (self.material) {
            .ecdsa_p256_sha256 => |key_pair| {
                const bytes = (try signEcdsa(EcdsaP256Sha256, key_pair, message)).toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return out[0..bytes.len];
            },
            .ecdsa_p384_sha384 => |key_pair| {
                const bytes = (try signEcdsa(EcdsaP384Sha384, key_pair, message)).toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return out[0..bytes.len];
            },
            .ed25519 => |key_pair| {
                const bytes = (key_pair.sign(message, null) catch return Error.SigningFailed).toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return out[0..bytes.len];
            },
        }
    }

    /// Wipes the private scalar, the Ed25519 seed, and the public key.
    pub fn deinit(self: *Key) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.material));
    }

    /// DNSKEY RDATA (RFC 4034 section 5.1.1): flags, protocol, algorithm, then
    /// the public key. ECDSA uses the uncompressed curve point as "x | y"
    /// (RFC 6605 section 4), which is SEC 1's uncompressed form with the
    /// leading 0x04 octet dropped; Ed25519 uses its raw 32 octets, per
    /// RFC 8080 section 3.2. Public because a trust anchor is exactly this
    /// record, and an operator (or a test) cannot write one without it.
    pub fn dnskeyRdata(self: *const Key, allocator: std.mem.Allocator) Error![]const u8 {
        var buffer: [max_rdata_len]u8 = undefined;
        std.mem.writeInt(u16, buffer[0..2], dnskey_flags, .big);
        buffer[2] = dnskey_protocol;
        buffer[3] = @backingInt(self.algorithm());
        var len: usize = 4;
        switch (self.material) {
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
        }
        return allocator.dupe(u8, buffer[0..len]);
    }

    /// RFC 4034 section 5.1.4:
    ///   digest = digest_algorithm( DNSKEY owner name in canonical form
    ///                              | DNSKEY RDATA )
    /// The owner arrives as a parameter so this stays a function of its
    /// arguments, and the key tag in the DS RDATA is computed over the same
    /// DNSKEY RDATA (RFC 4034 Appendix B).
    fn dsRdata(
        self: *const Key,
        allocator: std.mem.Allocator,
        owner_wire: []const u8,
        dnskey_rdata: []const u8,
    ) Error![]const u8 {
        var digest: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
        var digest_len: usize = undefined;
        switch (DigestType.forAlgorithm(self.algorithm())) {
            .sha256 => {
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(owner_wire);
                hasher.update(dnskey_rdata);
                hasher.final(digest[0..std.crypto.hash.sha2.Sha256.digest_length]);
                digest_len = std.crypto.hash.sha2.Sha256.digest_length;
            },
            .sha384 => {
                var hasher = std.crypto.hash.sha2.Sha384.init(.{});
                hasher.update(owner_wire);
                hasher.update(dnskey_rdata);
                hasher.final(&digest);
                digest_len = std.crypto.hash.sha2.Sha384.digest_length;
            },
        }

        var buffer: [4 + digest.len]u8 = undefined;
        std.mem.writeInt(u16, buffer[0..2], dns_dnssec.keyTag(dnskey_rdata), .big);
        buffer[2] = @backingInt(self.algorithm());
        buffer[3] = @backingInt(DigestType.forAlgorithm(self.algorithm()));
        @memcpy(buffer[4..][0..digest_len], digest[0..digest_len]);
        return allocator.dupe(u8, buffer[0 .. 4 + digest_len]);
    }
};

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

// ------------------------------------------------------------------ key file

/// Reads the project key file: one whitespace-separated `<algorithm> <secret>`
/// pair per line, the secret being the base64 private scalar (ECDSA) or seed
/// (Ed25519). Blank lines and `#` comments are skipped. The key is not named
/// here: the signer is always told which zone it signs, and a DNSKEY owner is
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
    var decoded: [128]u8 = undefined;
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
    if (std.ascii.eqlIgnoreCase(algorithm_text, "ed25519")) {
        if (expected != Ed25519.KeyPair.seed_length) return Error.BadSecret;
        const seed: [Ed25519.KeyPair.seed_length]u8 = decoded[0..Ed25519.KeyPair.seed_length].*;
        return .{ .material = .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch return Error.BadSecret } };
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
};

/// The chain a signed zone publishes: the RFC 4034 section 6.1 NSEC chain or
/// the RFC 5155 section 7.1 NSEC3 chain. The choice is the operator's, not
/// the RFC's: both chains are valid, and the RFCs say how a chain is built
/// once a zone publishes one.
pub const Chain = enum { nsec, nsec3 };

/// The operator's chain, with the parameters of an NSEC3 chain
/// (RFC 5155 section 4.1): the iteration count and the salt. The hash
/// algorithm is SHA-1 and the Opt-Out flag is clear, the only ones this build
/// implements.
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

/// Signs `zone` in place: appends the apex DNSKEY and DS, one NSEC per
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

    const origin = Name.fromText(zone.originText()) catch return Error.BadZoneRecord;
    // RFC 8080 section 8: a private key used for a DNSSEC zone must not be
    // used for any other purpose than for that zone, so a key that has signed
    // one zone is refused for a second one.
    if (key.signed_zone) |signed| {
        if (!std.mem.eql(u8, signed.asWire(), origin.asWire())) return Error.KeyUsedForAnotherZone;
    } else {
        key.signed_zone = origin;
    }

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

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
    const dnskey_rdata = try key.dnskeyRdata(work);
    try appendSingle(work, origin_wire, RecordType.DNSKEY.code(), soa_ttl, dnskey_rdata, &rrsets);
    try appendSingle(work, origin_wire, RecordType.DS.code(), soa_ttl, try key.dsRdata(work, origin_wire, dnskey_rdata), &rrsets);
    std.mem.sort(Rrset, rrsets.items, {}, rrsetLessThan);

    // An apex NSEC3PARAM is the opt-in: the zone states the parameters of the
    // chain it publishes, and the signer builds that chain (RFC 5155 section
    // 7.1). A zone without one keeps the NSEC chain it always had. The
    // operator's choice, when there is one, replaces that opt-in.
    const chain = try selectChain(work, zone, options.chain);
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
    try emit(work, allocator, zone, key, dns_dnssec.keyTag(dnskey_rdata), options, rrsets.items, chain.publish_param);
}

/// The chain the zone publishes. Without the operator's choice the zone's own
/// apex NSEC3PARAM is the opt-in, as it always was. With it the operator's
/// chain wins, and an NSEC3 chain takes its parameters from the zone's own
/// NSEC3PARAM when the zone states one, because that record states the
/// parameters of the chain (RFC 5155 section 4.1).
fn selectChain(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    policy: ?ChainPolicy,
) Error!ChainChoice {
    const wanted = policy orelse {
        const params = try apexNsec3Param(allocator, zone) orelse return .{ .kind = .nsec };
        return .{ .kind = .nsec3, .params = params };
    };
    if (wanted.chain == .nsec) return .{ .kind = .nsec };
    const params = Nsec3Params{
        .algorithm = 1,
        .flags = 0,
        .iterations = wanted.iterations,
        .salt = wanted.salt,
    };
    const found = try apexNsec3Param(allocator, zone) orelse
        return .{ .kind = .nsec3, .params = params, .publish_param = true };
    // The zone states the parameters of its own chain, so the operator's
    // choice must name the same ones.
    if (found.iterations != params.iterations or !std.mem.eql(u8, found.salt, params.salt)) {
        return Error.BadChainParameters;
    }
    return .{ .kind = .nsec3, .params = found };
}

/// The chain the zone publishes, with the parameters of an NSEC3 chain.
const ChainChoice = struct {
    kind: Chain,
    params: Nsec3Params = .{ .algorithm = 1, .flags = 0, .iterations = 0, .salt = "" },
    /// True when the signer publishes the apex NSEC3PARAM itself, because the
    /// zone states none.
    publish_param: bool = false,
};

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
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

    const order = try work.dupe([]const u8, rdatas);
    std.mem.sort([]const u8, order, {}, rdataLessThan);
    const dnskey_rdata = try key.dnskeyRdata(work);
    const signed = try signedData(
        work,
        .{ .owner_wire = owner.asWire(), .rrtype = rrtype, .ttl = ttl, .rdata = order },
        key.algorithm(),
        dns_dnssec.keyTag(dnskey_rdata),
        signer.asWire(),
        options,
    );
    var rdata_buffer: [18 + 255 + 128]u8 = undefined;
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
/// SHA-1 (RFC 5155 section 3.1.1) and the Opt-Out flag clear are implemented,
/// so a record asking for anything else is refused rather than published with
/// parameters this build cannot honour.
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
        if (bytes[0] != 1 or bytes[1] != 0) return Error.BadZoneRecord;
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

/// RFC 5155 section 3: the owner name of an NSEC3 is the SHA-1 hash of the
/// original owner name in unpadded base32hex (RFC 4648 section 7), so 20
/// octets are exactly 32 characters.
fn base32HexLabel(hash: [20]u8, out: *[32]u8) void {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    var written: usize = 0;
    var index: usize = 0;
    while (index < hash.len) : (index += 5) {
        // Five octets are forty bits, which is exactly eight characters.
        var chunk: u64 = 0;
        for (hash[index..][0..5]) |byte| chunk = (chunk << 8) | byte;
        var shift: u6 = 35;
        while (true) {
            out[written] = alphabet[@intCast((chunk >> shift) & 0x1f)];
            written += 1;
            if (shift == 0) break;
            shift -= 5;
        }
    }
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
    var group: usize = 0;
    for (owners.items) |owner_wire| {
        while (group < rrsets.items.len and !std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;
        const start = group;
        while (group < rrsets.items.len and std.mem.eql(u8, rrsets.items[group].owner_wire, owner_wire)) group += 1;
        codes.clearRetainingCapacity();
        for (rrsets.items[start..group]) |rrset| try codes.append(allocator, rrset.rrtype);
        // The RRSIG over every RRset at the name is a type present at the name.
        try codes.append(allocator, RecordType.RRSIG.code());
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
        base32HexLabel(entry.hash, &label);
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

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, header[0..header_len]);
    for (rrset.rdata) |rdata| {
        try out.appendSlice(allocator, rrset.owner_wire);
        const rr_header = zonemd.rrHeader(rrset.rrtype, dns_types.Class.IN.code(), rrset.ttl, rdata.len);
        try out.appendSlice(allocator, &rr_header);
        try out.appendSlice(allocator, rdata);
    }
    return .{ .bytes = try out.toOwnedSlice(allocator), .header_len = header_len };
}

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
    options: Options,
    rrsets: []const Rrset,
    publish_param: bool,
) Error!void {
    const algorithm = key.algorithm();
    const signer_wire = try scratch.dupe(u8, (Name.fromText(zone.originText()) catch return Error.BadZoneRecord).asWire());

    var generated: std.ArrayList(zone_parser.ZoneRecord) = .empty;
    defer generated.deinit(scratch);
    try generated.ensureTotalCapacity(scratch, rrsets.len);

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

        const signed = try signedData(scratch, rrset, algorithm, key_tag, signer_wire, options);
        // RRSIG RDATA is the RRSIG header followed by the Signature field. The
        // RRs that were signed go in neither: they are already published from
        // the zone file. The widest signature this build produces is 96 octets.
        var rdata_buffer: [18 + 255 + 128]u8 = undefined;
        @memcpy(rdata_buffer[0..signed.header_len], signed.bytes[0..signed.header_len]);
        const signature = try key.sign(signed.bytes, rdata_buffer[signed.header_len..]);
        try generated.append(scratch, try genericRecord(
            records,
            rrset.owner_wire,
            RecordType.RRSIG.code(),
            rrset.ttl,
            rdata_buffer[0 .. signed.header_len + signature.len],
        ));
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
const rfc8080_ed25519_ds = "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c";
const rfc8080_ed25519_key_tag: u16 = 35217;
const rfc8080_mx_rrsig_hex =
    "000f0f0200000e1055d4fc6055b94ce08991076578616d706c6503636f6d00" ++
    "cd74346e4620413105c9f2f28bd428898e83f19758a38c32521562a1865715d4f" ++
    "8d7440f4484d04aa2529f34284a6e69a09ee00fb0104743bb2ae239936a5c06";

const rfc6605_p256_key = "ecdsap256sha256 GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n";
const rfc6605_p256_dnskey = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
const rfc6605_p256_ds = "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17";
const rfc6605_p256_key_tag: u16 = 55648;

const rfc6605_p384_key = "ecdsap384sha384 WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR\n";
const rfc6605_p384_dnskey = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
const rfc6605_p384_ds = "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6";
const rfc6605_p384_key_tag: u16 = 10771;

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
                return bytes;
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

test "RFC 8080 section 6.1: the signed Ed25519 zone matches the published vector byte for byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key = try parseKey(rfc8080_ed25519_key);
    defer key.deinit();

    var zone = try loadZone(rfc8080_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    const dnskey = (try findOpaque(&zone, "example.com.", .DNSKEY, null)).?;
    try std.testing.expectEqualStrings(rfc8080_ed25519_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, dns_dnssec.keyTag(dnskey));

    const ds = (try findOpaque(&zone, "example.com.", .DS, null)).?;
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, std.mem.readInt(u16, ds[0..2], .big));
    try std.testing.expectEqual(@as(u8, 15), ds[2]);
    try std.testing.expectEqual(@as(u8, 2), ds[3]);
    try std.testing.expect(hexEquals(rfc8080_ed25519_ds, ds[4..]));

    const rrsig = (try findOpaque(&zone, "example.com.", .RRSIG, RecordType.MX.code())).?;
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

    const dnskey = (try findOpaque(&zone, "example.com.", .DNSKEY, null)).?;
    const flags = std.mem.readInt(u16, dnskey[0..2], .big);
    // The Zone Key bit (0x0100) marks a key that signs a zone; the Secure
    // Entry Point bit (0x0001) is the hint RFC 6781 section 3.2.3 asks a
    // single-type signing scheme to set on every key. RFC 8080 section 6.1
    // publishes exactly this pair.
    try std.testing.expect(flags & 0x0100 != 0);
    try std.testing.expectEqual(@as(u16, 257), flags);
    try std.testing.expectEqual(@as(u8, 3), dnskey[2]);
    try std.testing.expectEqual(@as(u8, 15), dnskey[3]);
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

    // The DNSKEY, the DS, and the RRSIGs are the ones this zone always got.
    const dnskey = (try findOpaque(&zone, "example.com.", .DNSKEY, null)).?;
    try std.testing.expectEqualStrings(rfc8080_ed25519_dnskey, try encodeBase64(allocator, dnskey[4..]));
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, dns_dnssec.keyTag(dnskey));
    const ds = (try findOpaque(&zone, "example.com.", .DS, null)).?;
    try std.testing.expect(hexEquals(rfc8080_ed25519_ds, ds[4..]));
    const rrsig = (try findOpaque(&zone, "example.com.", .RRSIG, RecordType.MX.code())).?;
    try std.testing.expect(hexEquals(rfc8080_mx_rrsig_hex, rrsig));

    // The same zone signed again is the old refusal, not the new one.
    try std.testing.expectError(Error.AlreadySigned, signZone(allocator, &zone, &key, rfc8080_window));
}

test "RFC 6605 section 6.1: the P-256 DNSKEY, key tag, and DS digest match the published vector" {
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

    const owner = try Name.fromText("example.net.");
    const ds = try key.dsRdata(allocator, owner.asWire(), dnskey);
    try std.testing.expectEqual(@as(u8, 13), ds[2]);
    try std.testing.expectEqual(@as(u8, 2), ds[3]);
    try std.testing.expect(hexEquals(rfc6605_p256_ds, ds[4..]));
}

test "RFC 6605 section 6.2: the P-384 DNSKEY, key tag, and SHA-384 DS digest match the published vector" {
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

    const owner = try Name.fromText("example.net.");
    const ds = try key.dsRdata(allocator, owner.asWire(), dnskey);
    try std.testing.expectEqual(@as(u8, 14), ds[2]);
    try std.testing.expectEqual(@as(u8, 4), ds[3]);
    try std.testing.expect(hexEquals(rfc6605_p384_ds, ds[4..]));
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

    const rrsig = (try findOpaque(&zone, "*.home.arpa.", .RRSIG, RecordType.A.code())).?;
    // Labels excludes the `*`, so "*.home.arpa." is 2 (arpa, home) ...
    try std.testing.expectEqual(@as(u8, 2), rrsig[3]);
    try std.testing.expectEqual(RecordType.A.code(), std.mem.readInt(u16, rrsig[0..2], .big));
    try std.testing.expectEqual(@as(u8, 15), rrsig[2]);
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, rrsig[4..8], .big));
    try std.testing.expectEqual(rfc8080_window.expiration, std.mem.readInt(u32, rrsig[8..12], .big));
    try std.testing.expectEqual(rfc8080_window.inception, std.mem.readInt(u32, rrsig[12..16], .big));
    // The key tag is over DNSKEY RDATA alone, so it does not move with the zone.
    try std.testing.expectEqual(rfc8080_ed25519_key_tag, std.mem.readInt(u16, rrsig[16..18], .big));

    const signer = try Name.fromText("home.arpa.");
    try std.testing.expectEqualSlices(u8, signer.asWire(), rrsig[18 .. 18 + signer.asWire().len]);

    // The wildcard owner is authoritative, so it joins the NSEC chain and a
    // validator expanding a name below it can find the proof.
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .NSEC));
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .RRSIG));
    try std.testing.expect(hasRecord(&zone, "*.home.arpa.", .A));
}

/// The wildcard RRSIG for `wildcard_zone` under `rfc8080_window`, signed by
/// the RFC 8080 section 6.1 Ed25519 key. Ed25519 is deterministic
/// (RFC 8032), so these bytes are reproducible; dnspython 2.8.0 accepted this
/// exact signature over `*.home.arpa. IN A 192.168.1.99` when it was produced,
/// and a one-octet change to the preimage does not verify.
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

    var zone = try loadZone(wildcard_zone);
    defer zone.deinit();
    try signZone(allocator, &zone, &key, rfc8080_window);

    const rrsig = (try findOpaque(&zone, "*.home.arpa.", .RRSIG, RecordType.A.code())).?;
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
    const apex_nsec = (try findOpaque(&zone, "example.com.", .NSEC, null)).?;
    try std.testing.expectEqualSlices(u8, apex_next, apex_nsec[0..apex_next.len]);

    const mail_next = (try Name.fromText("ns1.example.com.")).asWire();
    const mail_nsec = (try findOpaque(&zone, "mail.example.com.", .NSEC, null)).?;
    try std.testing.expectEqualSlices(u8, mail_next, mail_nsec[0..mail_next.len]);

    const apex = (try Name.fromText("example.com.")).asWire();
    const last_nsec = (try findOpaque(&zone, "ns1.example.com.", .NSEC, null)).?;
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
    // chain with an NSEC and an RRSIG over its NS RRset.
    try std.testing.expect(hasRecord(&zone, "child.example.com.", .NSEC));
    try std.testing.expect((try findOpaque(&zone, "child.example.com.", .RRSIG, RecordType.NS.code())) != null);

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

test "the key file accepts only one known algorithm and a correctly sized secret" {
    try std.testing.expectError(Error.BadKeyFile, parseKey("rsa-sha256 AAAA\n"));
    try std.testing.expectError(Error.BadKeyFile, parseKey("ed448 AAAA\n"));
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
    \\@ IN NSEC3PARAM 1 0 2 73616c74
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
/// the iterated salted SHA-1 of the canonical wire name, with the salt "salt"
/// and 2 iterations.
const nsec3_apex_hash = [_]u8{ 0x76, 0xed, 0x9c, 0x9f, 0x42, 0xb4, 0xc9, 0x12, 0x2a, 0xcf, 0xc7, 0x5d, 0x39, 0xd9, 0x6e, 0x8d, 0x56, 0x6a, 0x14, 0xd0 };
const nsec3_www_hash = [_]u8{ 0x31, 0x5f, 0x4a, 0x7c, 0xa2, 0xfc, 0xd7, 0xfe, 0x22, 0xd3, 0x10, 0x9d, 0x2e, 0x0e, 0xba, 0x23, 0xaf, 0x9b, 0xe5, 0x8f };

/// One NSEC3 record of a signed zone, as the zone holds it.
const Nsec3Record = struct {
    owner_text: []const u8,
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
            .next_hash = decoded.next_hash,
            .bitmap = decoded.bitmap,
        });
    }
    return out.toOwnedSlice(allocator);
}

/// The DNSKEY of a signed zone, as a trust anchor for the validator.
fn dnskeyAnchor(allocator: std.mem.Allocator, key: *const Key) ![]const u8 {
    const rdata = try key.dnskeyRdata(allocator);
    const encoded = try encodeBase64(allocator, rdata[4..]);
    return std.fmt.allocPrint(allocator, "example. DNSKEY 257 3 15 {s}\n", .{encoded});
}

/// A DO-bit query for a name the zone does not have, so the answer is a denial.
fn denialQuery(allocator: std.mem.Allocator, name_text: []const u8, qtype: dns_types.RecordType) !dns_message.Message {
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
    // The chain is in hash order: the hash of "www.example." sorts before the
    // hash of the apex.
    try std.testing.expectEqualStrings("65fkkv52vjbvs8mj22eis3lq4enpnpcf.example.", records[0].owner_text);
    try std.testing.expectEqualStrings("ermpp7q2mj4h4amfotejjmbehlb6k56g.example.", records[1].owner_text);
    // Each record names the next hash, and the last wraps to the first.
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, records[0].next_hash);
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, records[1].next_hash);
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
    // was built from.
    const records = try nsec3Records(allocator, &zone);
    const www = try Name.fromText(records[0].owner_text);
    const apex = try Name.fromText(records[1].owner_text);
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, &dns_validate.nsec3OwnerHash(www).?);
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, &dns_validate.nsec3OwnerHash(apex).?);

    // The project's own hash function computes the same two values, so the
    // signer and the serving path agree on every hash.
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try Name.fromText("www.example."), "salt", 2, &out);
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, &out);
    dns_dnssec.nsec3Hash(try Name.fromText("example."), "salt", 2, &out);
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
        const rrsig = (try findOpaque(&zone, record.owner_text, .RRSIG, RecordType.NSEC3.code())).?;
        // RFC 4034 section 3.1.3: the label count is the one of the RRSIG's
        // own owner name, which for an NSEC3 is the hashed name.
        try std.testing.expectEqual(@as(u8, 2), rrsig[3]);
    }

    // The served denial is proved by the generated chain.
    const request = try denialQuery(allocator, "missing.example.", .A);
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
    const request = try denialQuery(allocator, "missing.example.", .A);
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
    const apex = (try findOpaque(&zone, "example.", .NSEC, null)).?;
    const next = try Name.fromText("www.example.");
    try std.testing.expectEqualSlices(u8, next.asWire(), apex[0..next.asWire().len]);
    // The bitmap names SOA, NS, DNSKEY, DS, NSEC, and RRSIG.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x07, 0x22, 0x00, 0x00, 0x00, 0x00, 0x13, 0x80 }, apex[next.asWire().len..]);
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

test "the operator's NSEC choice publishes the NSEC chain in a zone that states an NSEC3PARAM" {
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
    const apex = (try findOpaque(&zone, "example.", .NSEC, null)).?;
    const next = try Name.fromText("www.example.");
    try std.testing.expectEqualSlices(u8, next.asWire(), apex[0..next.asWire().len]);
    // The zone's own apex NSEC3PARAM stays published: it is zone data, and the
    // ZONEMD digest of RFC 8976 section 3.3.1 covers it.
    try std.testing.expect(hasRecord(&zone, "example.", .NSEC3PARAM));
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
    const param = (try findOpaque(&zone, "example.", .NSEC3PARAM, null)).?;
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
