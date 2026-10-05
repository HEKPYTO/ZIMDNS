/// Contract: Signs one primary zone with a single DNSSEC key -- ECDSA P-256
/// (RFC 6605 algorithm 13), ECDSA P-384 (RFC 6605 algorithm 14), or Ed25519
/// (RFC 8080 algorithm 15) -- producing the apex DNSKEY and DS, an NSEC chain
/// of denial, and one RRSIG per RRset (RFC 4034 sections 3.1.8.1 and 5.1.4,
/// RFC 4035 section 2.3).
/// Ownership: every generated zone record, RDATA blob, and byte string is
/// allocated from `allocator`, which the caller keeps alive for as long as it
/// keeps the signed zone. `Key` owns private key material; call `Key.deinit`.
/// Errors: key-file, RDATA, and capacity failures are typed; no file or socket
/// I/O occurs here. This module signs only: validation, chain building, and
/// trust anchors stay deferred per docs/decisions/dnssec-deferral.md.
const std = @import("std");
const Name = @import("../dns/name.zig").Name;
const dns_dnssec = @import("../dns/dnssec.zig");
const dns_types = @import("../dns/types.zig");
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
    AlreadySigned,
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

/// RFC 4034 section 2.1.1: bit 7 marks a zone-signing key and bit 8 marks a
/// key a parent publishes as a trust anchor. One key does both here, which is
/// why every example key file uses 257.
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
        buffer[3] = @intFromEnum(self.algorithm());
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
        buffer[2] = @intFromEnum(self.algorithm());
        buffer[3] = @intFromEnum(DigestType.forAlgorithm(self.algorithm()));
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
};

/// Signs `zone` in place: appends the apex DNSKEY and DS, one NSEC per
/// authoritative owner name, and one RRSIG per RRset. The zone's SOA serial is
/// left alone -- nothing is written back to disk, so the published zone is
/// unchanged and a serial that moved on every restart would only churn
/// secondaries for no content change.
///
/// Only the records handed to the zone outlive the call, and the zone owns
/// them. Everything else -- canonical RDATA, sorted RRsets, preimages -- is
/// built in an arena released here, so a caller that is not itself an arena
/// (the config loader signs from its own allocator) leaks nothing.
pub fn signZone(
    allocator: std.mem.Allocator,
    zone: *zone_index.Zone,
    key: *const Key,
    options: Options,
) Error!void {
    if (zone.soa == null) return Error.BadZoneRecord;
    if (alreadySigned(zone)) return Error.AlreadySigned;

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

    var entries: std.ArrayList(Entry) = .empty;
    try collectEntries(work, zone, &entries);

    const soa_ttl = try soaMinimum(zone);
    const origin = Name.fromText(zone.originText()) catch return Error.BadZoneRecord;
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

    try appendNsecChain(work, &rrsets, soa_ttl);
    try emit(work, allocator, zone, key, dns_dnssec.keyTag(dnskey_rdata), options, rrsets.items);
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
/// would append a second, conflicting RRSIG and NSEC RRset at every name.
fn alreadySigned(zone: *const zone_index.Zone) bool {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.RRSIG) or record.rrtype.eql(.NSEC) or
            record.rrtype.eql(.NSEC3) or record.rrtype.eql(.NSEC3PARAM) or
            record.rrtype.eql(.DNSKEY)) return true;
    }
    return false;
}

fn collectEntries(allocator: std.mem.Allocator, zone: *const zone_index.Zone, entries: *std.ArrayList(Entry)) Error!void {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!zone.contains(record.ownerText())) continue;
        const owner = Name.fromText(record.ownerText()) catch return Error.BadZoneRecord;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.BadZoneRecord;
        var buffer: [max_rdata_len]u8 = undefined;
        var writer = dns_writer.Writer.init(&buffer);
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
        var bits = [_]u8{0} ** 32;
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
    out[2] = @intFromEnum(algorithm);
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
            RecordType.NSEC.code(), RecordType.DNSKEY.code(), RecordType.DS.code() => for (rrset.rdata) |rdata| {
                try generated.append(scratch, try genericRecord(records, rrset.owner_wire, rrset.rrtype, rrset.ttl, rdata));
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
