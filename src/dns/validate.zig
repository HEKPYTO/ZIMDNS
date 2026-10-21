/// Contract: Validates one DNSSEC response against a static trust-anchor store:
/// a DS or DNSKEY anchor authenticates a child apex DNSKEY RRset
/// (RFC 4035 section 5.2), that key authenticates every signed RRset, and a
/// negative answer is checked against the RFC 6840 sections 4.1, 4.3 and 4.4
/// spoof rules and the RFC 5155 section 8 NSEC3 proofs.
/// What this module does: DS and DNSKEY anchors, RFC 4034 section 6 canonical
/// signed-data assembly, ECDSA P-256/P-384 and Ed25519 verification, NSEC
/// NXDOMAIN and NODATA proofs, NSEC3 closest-encloser and opt-out proofs, and
/// the secure/insecure/bogus outcome with an RFC 8914 INFO-CODE for a bogus
/// answer and for an answer the server returns without a signed verification.
/// The NSEC3 RDATA decoder and the hash span test are shared with the
/// authoritative path, which picks the NSEC3 denial proofs a zone serves.
/// `zoneSignedToAnchor` answers the same question for a loaded zone: do the
/// RRsets named at its apex carry valid signatures chaining up to a
/// configured anchor (RFC 8976 section 4 step 3).
/// What this module does NOT do: iterative resolution, chasing a delegation
/// chain across several zones, RFC 5011 anchor rollover, NSEC3 generation, and
/// RSA or Ed448, for which the standard library carries no primitive.
/// Ownership: `validate` runs on one arena and frees it before returning.
/// `Anchors` owns its parsed RDATA until `deinit`.
/// Errors: a malformed anchor file or opaque RDATA is a typed error. A failed
/// validation is a `Status` in `Result`, never an error, so a caller maps one
/// outcome to SERVFAIL and the other two to the relayed answer.
const std = @import("std");
const Name = @import("name.zig").Name;
const Class = @import("types.zig").Class;
const RecordType = @import("types.zig").RecordType;
const dns_record = @import("record.zig");
const dns_message = @import("message.zig");
const dns_rdata = @import("rdata.zig");
const dns_writer = @import("writer.zig");
const dnssec = @import("dnssec.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    BadAnchorFile,
    TooManyAnchors,
    MalformedRrsig,
    MalformedDnskey,
    MalformedRdata,
    /// The response carried more records than one answer may be validated over.
    TooManyRecords,
    SignatureInvalid,
    KeyMismatch,
    UnsupportedAlgorithm,
    OutOfMemory,
};

/// RFC 4035 section 5.5 names three outcomes: a validated RRset is `secure`,
/// one outside the trust domain is `insecure`, and one that should have
/// validated but did not is `bogus`. Only `secure` may set the AD bit.
pub const Status = enum {
    secure,
    insecure,
    bogus,
};

pub const Result = struct {
    status: Status,
    /// RFC 8914 INFO-CODE to relay, or 0. A bogus status carries the code of
    /// the failure; an insecure status carries the code that says why the
    /// answer could not be signed-verified, and rides on the answer the
    /// client still gets (RFC 4035 section 5.2).
    ede: u16 = 0,
};

/// Bounds on one answer's validation work. RFC 4035 section 5.4 requires a
/// validator to bound the work it puts into answering a query, and an
/// oversize response is a reason to stop, not a reason to allocate.
const max_records = 256;
const max_rrsets = 64;
const max_proofs = 32;
const max_chains = 8;
/// Bounds the CNAME walk in `terminalName` and the closest-encloser walk.
const max_labels = 128;

// ------------------------------------------------------------------ anchors

pub const max_anchors = 16;

/// One configured trust anchor: a DS or DNSKEY held in wire RDATA. The owner is
/// the zone the anchor speaks for, and for a DNSKEY it is that zone's apex.
pub const Anchor = struct {
    owner: Name,
    rrtype: RecordType,
    rdata: []const u8,
};

/// A static trust-anchor store. This is the whole of Stage 3's anchor
/// management: an operator names a file, the file names zones and holds DS or
/// DNSKEY records, and nothing here rolls a key over (RFC 5011 is Stage 4).
pub const Anchors = struct {
    items: [max_anchors]Anchor = undefined,
    len: usize = 0,

    /// Parse the project anchor file. One record per line, blank lines and
    /// `#` comments skipped:
    ///
    ///     <owner> [ttl] [IN] DS <keytag> <algorithm> <digest-type> <hex-digest>
    ///     <owner> [ttl] [IN] DNSKEY <flags> <protocol> <algorithm> <base64-key>
    ///
    /// The owner is a presentation name (`example.com.` or `.` for the root).
    /// The TTL and the class are optional and ignored: an anchor is
    /// configuration, not zone data, so it has no lifetime here.
    pub fn parse(allocator: std.mem.Allocator, text: []const u8) Error!Anchors {
        var anchors = Anchors{};
        errdefer anchors.deinit(allocator);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const hash = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
            const line = std.mem.trim(u8, raw_line[0..hash], " \t\r");
            if (line.len == 0) continue;
            var tokens = std.mem.tokenizeAny(u8, line, " \t");
            const owner = Name.fromText(tokens.next() orelse return Error.BadAnchorFile) catch return Error.BadAnchorFile;
            // An optional TTL and class may sit between the owner and the type.
            var token = tokens.next() orelse return Error.BadAnchorFile;
            if (isDecimal(token)) token = tokens.next() orelse return Error.BadAnchorFile;
            if (isClass(token)) token = tokens.next() orelse return Error.BadAnchorFile;
            if (anchors.len >= max_anchors) return Error.TooManyAnchors;
            anchors.items[anchors.len] = if (std.ascii.eqlIgnoreCase(token, "DS"))
                .{ .owner = owner, .rrtype = .DS, .rdata = try parseDsRdata(allocator, &tokens) }
            else if (std.ascii.eqlIgnoreCase(token, "DNSKEY"))
                .{ .owner = owner, .rrtype = .DNSKEY, .rdata = try parseDnskeyRdata(allocator, &tokens) }
            else
                return Error.BadAnchorFile;
            // Counted before the trailing-token check: `deinit` frees items
            // below `len`, so a record stored and then rejected on its last
            // token would otherwise never be freed.
            anchors.len += 1;
            // A trailing token means the line was not the record it claimed.
            if (tokens.next() != null) return Error.BadAnchorFile;
        }
        return anchors;
    }

    pub fn deinit(self: *Anchors, allocator: std.mem.Allocator) void {
        for (self.items[0..self.len]) |anchor| allocator.free(anchor.rdata);
        self.len = 0;
    }

    /// True when a configured anchor speaks for `name` or a zone above it.
    /// This is the test for "should this name have been signed": an unsigned
    /// answer inside the trust domain is bogus, not insecure.
    pub fn covers(self: *const Anchors, name: Name) bool {
        for (self.items[0..self.len]) |anchor| {
            if (isSuffix(anchor.owner, name)) return true;
        }
        return false;
    }

    /// True when a configured anchor names `name` itself. RFC 8976 section 4
    /// step 1 asks whether a zone is expected to carry DNSSEC records: an
    /// anchor for the zone says yes, an anchor for a zone above it does not,
    /// because a delegation without a DS is insecure (RFC 4035 section 5.2)
    /// and the parent side of that chain is not reachable from a zone file.
    pub fn anchorsZone(self: *const Anchors, name: Name) bool {
        for (self.items[0..self.len]) |anchor| {
            if (anchor.owner.eql(&name)) return true;
        }
        return false;
    }

    /// Writes the 16-bit Key Tag of every anchor that speaks for `name` into
    /// `out` and returns how many. RFC 8145 section 4.2 needs one tag per trust
    /// anchor the querier will use to validate a DNSKEY answer for that name:
    /// a DS carries its tag in the RDATA Key Tag field (RFC 4034 section
    /// 5.1.4) and a DNSKEY's is the RFC 4034 Appendix B checksum of its RDATA.
    pub fn keyTags(self: *const Anchors, name: Name, out: []u8) usize {
        var count: usize = 0;
        for (self.items[0..self.len]) |anchor| {
            if (!isSuffix(anchor.owner, name)) continue;
            const tag = if (anchor.rrtype.eql(.DS))
                std.mem.readInt(u16, anchor.rdata[0..2], .big)
            else
                dnssec.keyTag(anchor.rdata);
            std.mem.writeInt(u16, out[count * 2 ..][0..2], tag, .big);
            count += 1;
        }
        return count;
    }
};

/// DS RDATA (RFC 4034 section 5.1.4): key tag, algorithm, digest type, digest.
fn parseDsRdata(allocator: std.mem.Allocator, tokens: *std.mem.TokenIterator(u8, .any)) Error![]const u8 {
    const key_tag = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    const algorithm = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    const digest_type = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    const digest_text = tokens.next() orelse return Error.BadAnchorFile;
    if (digest_text.len == 0 or digest_text.len % 2 != 0 or digest_text.len > 2 * std.crypto.hash.sha2.Sha384.digest_length) return Error.BadAnchorFile;
    const rdata = try allocator.alloc(u8, 4 + digest_text.len / 2);
    errdefer allocator.free(rdata);
    std.mem.writeInt(u16, rdata[0..2], key_tag, .big);
    rdata[2] = algorithm;
    rdata[3] = digest_type;
    _ = std.fmt.hexToBytes(rdata[4..], digest_text) catch return Error.BadAnchorFile;
    return rdata;
}

/// DNSKEY RDATA (RFC 4034 section 5.1.1): flags, protocol, algorithm, key.
/// RFC 4034 section 2.1.2 fixes the protocol at 3, so any other value in a
/// configuration file is an operator error rather than a key we could skip.
fn parseDnskeyRdata(allocator: std.mem.Allocator, tokens: *std.mem.TokenIterator(u8, .any)) Error![]const u8 {
    const flags = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    const protocol = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    if (protocol != 3) return Error.BadAnchorFile;
    const algorithm = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadAnchorFile, 10) catch return Error.BadAnchorFile;
    const key_text = tokens.next() orelse return Error.BadAnchorFile;
    const expected = std.base64.standard.Decoder.calcSizeForSlice(key_text) catch return Error.BadAnchorFile;
    if (expected == 0 or expected > dns_rdata.max_unknown_len - 4) return Error.BadAnchorFile;
    const rdata = try allocator.alloc(u8, 4 + expected);
    errdefer allocator.free(rdata);
    std.mem.writeInt(u16, rdata[0..2], flags, .big);
    rdata[2] = protocol;
    rdata[3] = algorithm;
    std.base64.standard.Decoder.decode(rdata[4..], key_text) catch return Error.BadAnchorFile;
    return rdata;
}

fn isDecimal(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn isClass(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "IN") or
        std.ascii.eqlIgnoreCase(token, "CH") or
        std.ascii.eqlIgnoreCase(token, "HS");
}

// ------------------------------------------------------------------ RRSIG

/// The RRSIG fields the validator reads (RFC 4034 section 3.1). RRSIG is
/// carried opaquely, so the fixed fields sit at fixed offsets and the Signer's
/// Name starts at 18.
const Rrsig = struct {
    owner: Name,
    raw: []const u8,
    covered: u16,
    algorithm: u8,
    labels: u8,
    orig_ttl: u32,
    key_tag: u16,
    signer: Name,
    signature: []const u8,
    /// Length of the RRSIG RDATA with the Signature field excluded: the exact
    /// prefix that opens RFC 4035 section 5.3.1's signed data.
    header_len: usize,

    fn at(raw: []const u8, owner: Name) Error!Rrsig {
        if (raw.len < 18) return Error.MalformedRrsig;
        const parsed = Name.parse(raw, 18) catch return Error.MalformedRrsig;
        if (parsed.next_offset >= raw.len) return Error.MalformedRrsig;
        return .{
            .owner = owner,
            .raw = raw,
            .covered = dnssec.rrsigCovers(raw) catch return Error.MalformedRrsig,
            .algorithm = raw[2],
            .labels = raw[3],
            .orig_ttl = std.mem.readInt(u32, raw[4..8], .big),
            .key_tag = std.mem.readInt(u16, raw[16..18], .big),
            .signer = parsed.name,
            .signature = raw[parsed.next_offset..],
            .header_len = parsed.next_offset,
        };
    }
};

// ------------------------------------------------------- canonical form

/// Number of labels in a canonical wire name, excluding the root label.
fn labelCount(wire: []const u8) u8 {
    var count: u8 = 0;
    var index: usize = 0;
    while (index < wire.len and wire[index] != 0) : (count += 1) {
        index += 1 + wire[index];
    }
    return count;
}

/// Parent name with the leftmost label stripped; null at the root.
fn parentName(name: Name) ?Name {
    const wire = name.asWire();
    if (wire.len < 2) return null;
    const len = wire[0];
    if (len == 0 or (len & 0xc0) != 0 or len > 63) return null;
    const rest = wire[1 + @as(usize, len) ..];
    if (rest.len == 0 or rest[rest.len - 1] != 0) return null;
    var out = Name{};
    @memcpy(out.wire[0..rest.len], rest);
    out.wire_len = @intCast(rest.len);
    return out;
}

/// Wildcard at the closest encloser: "*." prepended to the encloser name.
fn wildcardName(encloser: Name) Error!Name {
    const wire = encloser.asWire();
    var out = Name{};
    if (wire.len + 2 > out.wire.len) return Error.MalformedRrsig;
    out.wire[0] = 1;
    out.wire[1] = '*';
    @memcpy(out.wire[2..][0..wire.len], wire);
    out.wire_len = @intCast(wire.len + 2);
    return out;
}

/// True when `name` is `ancestor` or sits below it. A canonical wire name ends
/// at the root label, so a suffix match on whole labels is exact: `example.`
/// is never a suffix-match of `notexample.com.`. The comparison ignores case
/// (RFC 1035 section 2.3.2), so a name that arrived in upper case still
/// matches the zone it sits under.
fn isSuffix(ancestor: Name, name: Name) bool {
    const outer = ancestor.asWire();
    const inner = name.asWire();
    if (outer.len > inner.len) return false;
    return std.ascii.eqlIgnoreCase(inner[inner.len - outer.len ..], outer);
}

/// RFC 4034 section 6.3: RDATA compares as left-justified unsigned octet
/// sequences in which the absence of an octet sorts before a zero octet.
fn octetOrder(a: []const u8, b: []const u8) std.math.Order {
    const common = @min(a.len, b.len);
    const order = std.mem.order(u8, a[0..common], b[0..common]);
    if (order != .eq) return order;
    return std.math.order(a.len, b.len);
}

/// The owner name the signature actually covers (RFC 4034 section 6.2,
/// RFC 4035 section 5.3.2). When the RRSIG Labels field is below the owner
/// name's own label count, the RRset was signed under a wildcard, so the
/// signed owner is "*." plus the last `labels` labels of the name the response
/// carried. `Name` already lowercases, which is what section 6.2 requires.
/// The name is taken by pointer because the returned slice borrows its wire
/// form: a by-value parameter's buffer does not outlive the call.
fn signedOwner(allocator: std.mem.Allocator, owner: *const Name, labels: u8) Error![]const u8 {
    const wire = owner.asWire();
    const total = labelCount(wire);
    if (total <= labels) return wire;
    var remaining = total - labels;
    var index: usize = 0;
    while (index < wire.len and remaining > 0) : (remaining -= 1) {
        index += 1 + wire[index];
    }
    const suffix = wire[index..];
    if (suffix.len + 2 > 255) return Error.MalformedRrsig;
    const out = try allocator.alloc(u8, suffix.len + 2);
    out[0] = 1;
    out[1] = '*';
    @memcpy(out[2..], suffix);
    return out;
}

/// RDATA in canonical form. Every typed RDATA re-encodes its embedded names as
/// fully qualified lowercase wire names with no compression, which is exactly
/// RFC 4034 section 6.2's requirement, so one path covers the whole union; an
/// opaque RDATA re-encodes to the octets it arrived as, and RFC 3597 forbids
/// compression inside a type this build does not model.
fn encodeRdata(allocator: std.mem.Allocator, rdata: dns_rdata.RData) Error![]const u8 {
    var buffer: [dns_rdata.max_unknown_len]u8 = undefined;
    var writer = dns_writer.Writer.init(&buffer);
    rdata.encode(&writer) catch return Error.MalformedRdata;
    return allocator.dupe(u8, writer.written());
}

/// RR(i) = owner | type | class | Original TTL | RDLENGTH | RDATA
/// (RFC 4034 section 6.1). The TTL is the RRSIG's Original TTL, not the TTL the
/// response happened to carry, and the owner is the signed owner.
fn rrHeader(rrtype: u16, class: u16, ttl: u32, rdata_len: usize) [10]u8 {
    var header: [10]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], rrtype, .big);
    std.mem.writeInt(u16, header[2..4], class, .big);
    std.mem.writeInt(u32, header[4..8], ttl, .big);
    std.mem.writeInt(u16, header[8..10], @intCast(rdata_len), .big);
    return header;
}

const CanonicalRr = struct {
    rdata: []const u8,
    index: usize,
};

fn canonicalLessThan(entries: []const CanonicalRr, left: usize, right: usize) bool {
    return octetOrder(entries[left].rdata, entries[right].rdata) == .lt;
}

/// RFC 4035 section 5.3.1:
///     signed_data = RRSIG_RDATA (Signature excluded) | RR(1) | RR(2) | ...
/// over the RRset in canonical order. Only the RRSIG prefix is ever published;
/// the RRs that follow are the ones the response already carried.
fn signedData(
    allocator: std.mem.Allocator,
    records: []const *const dns_record.ResourceRecord,
    rrsig: Rrsig,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, rrsig.raw[0..rrsig.header_len]);
    const owner = try signedOwner(allocator, &rrsig.owner, rrsig.labels);

    const entries = try allocator.alloc(CanonicalRr, records.len);
    var unique: usize = 0;
    for (records, 0..) |record, index| {
        const rdata = try encodeRdata(allocator, record.rdata);
        // An RRset is a set, so a repeated RR counts once (RFC 4034 section
        // 6.3). A response can carry the same record twice, and the signature
        // covers the deduplicated RRset, so keeping both would fail a
        // signature that is in fact valid.
        var repeated = false;
        for (entries[0..unique]) |*entry| {
            if (std.mem.eql(u8, entry.rdata, rdata)) repeated = true;
        }
        if (repeated) continue;
        entries[unique] = .{ .rdata = rdata, .index = index };
        unique += 1;
    }
    const order = try allocator.alloc(usize, unique);
    for (order, 0..) |*slot, index| slot.* = index;
    std.mem.sort(usize, order, entries, canonicalLessThan);

    for (order) |slot| {
        const record = records[entries[slot].index];
        try out.appendSlice(allocator, owner);
        try out.appendSlice(allocator, &rrHeader(record.rrtype.code(), record.class.code(), rrsig.orig_ttl, entries[slot].rdata.len));
        try out.appendSlice(allocator, entries[slot].rdata);
    }
    return out.toOwnedSlice(allocator);
}

// ------------------------------------------------------------ cryptography

/// One ECDSA scheme's verify, shared by algorithm 13 and 14. RFC 6605
/// section 4 fixes the DNSKEY public key at the raw `x | y` pair, which is
/// SEC 1's uncompressed point with its leading 0x04 tag removed, and the
/// signature at a fixed-width big-endian `r | s`.
fn verifyEcdsa(comptime Scheme: type, key: []const u8, signature: []const u8, data: []const u8) Error!void {
    const field_len = Scheme.PublicKey.compressed_sec1_encoded_length - 1;
    if (key.len != 2 * field_len or signature.len != Scheme.Signature.encoded_length) return Error.MalformedDnskey;
    var sec1: [1 + 2 * field_len]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..], key);
    const public_key = Scheme.PublicKey.fromSec1(&sec1) catch return Error.MalformedDnskey;
    const raw: [Scheme.Signature.encoded_length]u8 = signature[0..Scheme.Signature.encoded_length].*;
    Scheme.Signature.fromBytes(raw).verify(data, public_key) catch return Error.SignatureInvalid;
}

/// RFC 8080 section 3.1 fixes the key at the raw 32 octets and the signature at
/// the RFC 8032 form. Verification is cofactorless, so a malleated
/// non-canonical S cannot be used to replay a signature over different data.
fn verifyEd25519(key: []const u8, signature: []const u8, data: []const u8) Error!void {
    if (key.len != Ed25519.PublicKey.encoded_length or signature.len != Ed25519.Signature.encoded_length) return Error.MalformedDnskey;
    const public_key = Ed25519.PublicKey.fromBytes(key[0..Ed25519.PublicKey.encoded_length].*) catch return Error.MalformedDnskey;
    const raw: [Ed25519.Signature.encoded_length]u8 = signature[0..Ed25519.Signature.encoded_length].*;
    Ed25519.Signature.fromBytes(raw).verifyStrict(data, public_key) catch return Error.SignatureInvalid;
}

/// The DNSSEC algorithms this build verifies: 13 and 14 (RFC 6605) and 15
/// (RFC 8080). A DNSKEY RRset of any other algorithm is the case RFC 8914
/// section 4.2 names; a DS RRset of them is the case RFC 4035 section 5.2
/// names. Either way the zone has no supported authentication path.
fn algorithmSupported(number: u8) bool {
    return switch (number) {
        13, 14, 15 => true,
        else => false,
    };
}

/// RFC 4034 section 2.1.1: bit 7 of the DNSKEY Flags field is the Zone Key
/// flag, and a DNSKEY without it must not be used to verify an RRset. Bit 7
/// is the low bit of the first flags octet (0x0100); bit 15, the Secure
/// Entry Point flag, is the low bit of the second (0x0001).
fn dnskeyZoneKeyBit(raw: []const u8) bool {
    return raw.len >= 4 and (raw[0] & 0x01) != 0;
}

/// The DS digest types this build computes: 1 (SHA-1), 2 (SHA-256), and 4
/// (SHA-384). RFC 6840 section 5.2 names an unknown digest type a deliberate
/// downgrade signal.
fn dsDigestTypeSupported(ds_rdata: []const u8) bool {
    if (ds_rdata.len < 5) return false;
    return switch (ds_rdata[3]) {
        1, 2, 4 => true,
        else => false,
    };
}

/// Check one RRSIG over `data` against one DNSKEY. The key tag and algorithm
/// are matched first so a key that cannot possibly have made the signature is
/// never handed to the curve arithmetic.
fn verifyWithKey(dnskey_rdata: []const u8, rrsig: Rrsig, data: []const u8) Error!void {
    if (dnskey_rdata.len < 4 or dnskey_rdata[2] != 3) return Error.MalformedDnskey;
    if (dnssec.keyTag(dnskey_rdata) != rrsig.key_tag) return Error.KeyMismatch;
    if (dnskey_rdata[3] != rrsig.algorithm) return Error.KeyMismatch;
    const key = dnskey_rdata[4..];
    switch (rrsig.algorithm) {
        13 => try verifyEcdsa(EcdsaP256Sha256, key, rrsig.signature, data),
        14 => try verifyEcdsa(EcdsaP384Sha384, key, rrsig.signature, data),
        15 => try verifyEd25519(key, rrsig.signature, data),
        // RFC 4035 section 5.2: an unsupported algorithm leaves the zone with
        // no authentication path, which the caller reports as insecure.
        else => return Error.UnsupportedAlgorithm,
    }
}

/// RFC 4034 section 5.1.4:
///     digest = digest_algorithm( DNSKEY owner name in canonical form
///                                | DNSKEY RDATA )
/// The DS's key tag and algorithm must match the DNSKEY first, so a digest
/// that happens to collide across algorithms still cannot match.
fn dsMatches(ds_rdata: []const u8, owner: Name, dnskey_rdata: []const u8) bool {
    if (ds_rdata.len < 5 or dnskey_rdata.len < 4) return false;
    if (std.mem.readInt(u16, ds_rdata[0..2], .big) != dnssec.keyTag(dnskey_rdata)) return false;
    if (ds_rdata[2] != dnskey_rdata[3]) return false;
    if (!dsDigestTypeSupported(ds_rdata)) return false;
    const digest = ds_rdata[4..];
    var computed: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
    switch (ds_rdata[3]) {
        1 => {
            if (digest.len != std.crypto.hash.Sha1.digest_length) return false;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(owner.asWire());
            hasher.update(dnskey_rdata);
            hasher.final(computed[0..std.crypto.hash.Sha1.digest_length]);
        },
        2 => {
            if (digest.len != std.crypto.hash.sha2.Sha256.digest_length) return false;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(owner.asWire());
            hasher.update(dnskey_rdata);
            hasher.final(computed[0..std.crypto.hash.sha2.Sha256.digest_length]);
        },
        4 => {
            if (digest.len != std.crypto.hash.sha2.Sha384.digest_length) return false;
            var hasher = std.crypto.hash.sha2.Sha384.init(.{});
            hasher.update(owner.asWire());
            hasher.update(dnskey_rdata);
            hasher.final(&computed);
        },
        // RFC 6840 section 5.2: an unknown DS digest algorithm is a deliberate
        // downgrade signal. Treating it as "no match" is what makes the child
        // insecure instead of trusted by accident.
        else => return false,
    }
    return std.mem.eql(u8, digest, computed[0..digest.len]);
}

// ------------------------------------------------------------- RFC 6840

/// RFC 6840 section 4.1: an "ancestor delegation" NSEC or NSEC3 carries the NS
/// bit, leaves the SOA bit clear, and is signed by a zone shorter than its own
/// owner name. It lives in the parent of the cut and MUST NOT prove the
/// nonexistence of anything at or below that owner name. Without this check a
/// validator reads a parent's delegation NSEC as proof that a name in the
/// child does not exist.
fn isAncestorDelegation(bitmap: []const u8, owner_labels: u8, signer_labels: u8) bool {
    if (!dnssec.nsecBitmapHasType(bitmap, RecordType.NS.code())) return false;
    if (dnssec.nsecBitmapHasType(bitmap, RecordType.SOA.code())) return false;
    return signer_labels < owner_labels;
}

/// RFC 6840 section 4.1, second paragraph: an NSEC or NSEC3 with the DNAME bit
/// set must not be used to prove the nonexistence of a name beneath its own
/// owner name, because a DNAME redirects that whole subtree elsewhere.
fn deniesSubdomain(bitmap: []const u8, owner: Name, target: Name) bool {
    if (!dnssec.nsecBitmapHasType(bitmap, RecordType.DNAME.code())) return false;
    if (owner.eql(&target)) return false;
    return isSuffix(owner, target);
}

/// RFC 4035 section 5.4: when the covering RRSIG's Labels field equals the NSEC
/// owner's own label count, the NSEC proves wildcard expansion could not have
/// matched the request. A lower count means the NSEC sat at a wildcard, so it
/// cannot deny a name the wildcard could have produced.
fn deniesWildcard(labels: u8, owner: Name) bool {
    return labels == labelCount(owner.asWire());
}

/// NSEC3 span test (RFC 5155 section 7.1): the target hash falls strictly
/// between the owner hash and the next hash, wrapping past the end of the hash
/// space when the next hash sorts before the owner hash. A validator uses it
/// to find the NSEC3 that covers a name (RFC 5155 section 8.3); an
/// authoritative server uses the same test to pick the record it serves
/// (RFC 5155 section 7.2.1).
pub fn nsec3Covers(owner: [20]u8, next: [20]u8, target: [20]u8) bool {
    const span = octetOrder(&owner, &next);
    // A zone whose last NSEC3 points back at its own owner hash has one hash
    // in the chain, and that single span wraps the whole space.
    if (span == .eq) return !std.mem.eql(u8, &owner, &target);
    if (span == .lt) {
        return octetOrder(&owner, &target) == .lt and octetOrder(&target, &next) == .lt;
    }
    return octetOrder(&owner, &target) == .lt or octetOrder(&target, &next) == .lt;
}

/// RFC 5155 section 3: an NSEC3 owner label is the SHA-1 hash in unpadded
/// base32hex (RFC 4648 section 7), so 20 octets are exactly 32 characters and
/// decode as a straight five-bit regrouping. The standard library carries no
/// base32 alphabet, so the mapping is spelled out here rather than pulled in.
fn base32hexLabel(label: []const u8, out: *[20]u8) bool {
    if (label.len != 32) return false;
    var accumulator: u64 = 0;
    var bits: u6 = 0;
    var written: usize = 0;
    for (label) |byte| {
        const upper = std.ascii.toUpper(byte);
        const value: u6 = switch (upper) {
            '0'...'9' => @truncate(upper - '0'),
            'A'...'V' => @truncate(upper - 'A' + 10),
            else => return false,
        };
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if (bits < 8) continue;
        bits -= 8;
        if (written == out.len) return false;
        out[written] = @truncate(accumulator >> bits);
        written += 1;
    }
    return written == out.len;
}

/// The NSEC3 RDATA fields (RFC 5155 section 3.1) as the wire carries them.
pub const Nsec3Rdata = struct {
    flags: u8,
    iterations: u16,
    salt: []const u8,
    next_hash: []const u8,
    bitmap: []const u8,
};

/// Decode NSEC3 RDATA (RFC 5155 section 3.2): hash algorithm, flags,
/// iterations, salt, hash length, next hashed owner name, type bitmap. The
/// hash algorithm must be 1 (RFC 5155 section 3.1.1 fixes SHA-1) and the hash
/// length 20 (RFC 5155 section 3.1.6), the only pair this build computes.
pub fn parseNsec3Rdata(raw: []const u8) ?Nsec3Rdata {
    if (raw.len < 6 or raw[0] != 1) return null;
    const salt_len = raw[4];
    if (6 + salt_len > raw.len) return null;
    const hash_len = raw[5 + salt_len];
    if (hash_len != 20) return null;
    if (6 + salt_len + hash_len > raw.len) return null;
    return .{
        .flags = raw[1],
        .iterations = std.mem.readInt(u16, raw[2..4], .big),
        .salt = raw[5 .. 5 + salt_len],
        .next_hash = raw[6 + salt_len ..][0..hash_len],
        .bitmap = raw[6 + salt_len + hash_len ..],
    };
}

/// The NSEC3 parameters a chain is built with (RFC 5155 section 7.1): the
/// hash algorithm, the iteration count, and the salt.
const Nsec3Params = struct {
    hash_algorithm: u8,
    iterations: u16,
    salt: []const u8,
};

/// The parameters the zone's apex NSEC3PARAM states (RFC 5155 section 3.2):
/// hash algorithm, flags, iterations, salt length, and salt. Null when the
/// record's RDATA is not a well-formed NSEC3PARAM.
fn zoneNsec3Param(record: zone_parser.ZoneRecord) ?Nsec3Params {
    const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return null;
    const bytes = switch (rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return null,
    };
    if (bytes.len < 5) return null;
    const salt_len = bytes[4];
    if (5 + salt_len > bytes.len) return null;
    return .{
        .hash_algorithm = bytes[0],
        .iterations = std.mem.readInt(u16, bytes[2..4], .big),
        .salt = bytes[5 .. 5 + salt_len],
    };
}

/// The hash an NSEC3 owner name carries (RFC 5155 section 3): the first label
/// of the owner name is the unpadded base32hex encoding of the 20-octet hash
/// of the original owner name.
pub fn nsec3OwnerHash(owner: Name) ?[20]u8 {
    const wire = owner.asWire();
    if (wire.len < 34 or wire[0] != 32) return null;
    var out: [20]u8 = undefined;
    if (!base32hexLabel(wire[1..33], &out)) return null;
    return out;
}

// ----------------------------------------------------------------- proofs

/// One RRset as it arrived, with every record a signature could cover.
const Rrset = struct {
    owner: Name,
    rrtype: u16,
    records: std.ArrayList(*const dns_record.ResourceRecord) = .empty,
};

/// An NSEC denial proof plus the two facts RFC 6840 needs about the RRSIG that
/// covered it: who signed it, and how many labels that signature claims.
const Nsec = struct {
    owner: Name,
    next: Name,
    bitmap: []const u8,
    signer: Name,
    labels: u8,
};

/// An NSEC3 denial proof. `owner_labels` is the label count of the name the
/// NSEC3 was generated for, which RFC 4034 section 3.1.3 puts in the covering
/// RRSIG's Labels field: the owner name is the hash label in front of the
/// signing zone, and RFC 6840 section 4.1 compares the signer against that
/// original name rather than against the hashed owner.
const Nsec3 = struct {
    owner_hash: [20]u8,
    next_hash: [20]u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    bitmap: []const u8,
    signer: Name,
    owner_labels: u8,
};

/// A proven closest encloser: the name itself, plus the NSEC3 that matched it.
/// The name is carried separately because the NSEC3 owner is the name's hash,
/// and the wildcard at the encloser has to be built from the real name.
const Encloser = struct {
    name: Name,
    proof: Nsec3,
};

const Outcome = enum { secure, insecure, bogus };

const KeySet = struct {
    signer: Name,
    keys: []const []const u8,
};

/// One response's validation state. Every buffer is arena-owned by `validate`.
const Validator = struct {
    allocator: std.mem.Allocator,
    anchors: *const Anchors,
    now: u32,
    rrsigs: std.ArrayList(Rrsig) = .empty,
    rrsets: std.ArrayList(Rrset) = .empty,
    nsecs: std.ArrayList(Nsec) = .empty,
    nsec3s: std.ArrayList(Nsec3) = .empty,
    chains: std.ArrayList(KeySet) = .empty,
    seen: usize = 0,
    secure: usize = 0,
    insecure: usize = 0,
    ede: u16 = 0,
    /// The RFC 8914 INFO-CODE that explains an insecure answer. RFC 4035
    /// section 5.2 keeps these answers insecure, so the code rides on the
    /// answer the client still gets.
    insecure_ede: u16 = 0,

    fn count(self: *Validator, outcome: Outcome) void {
        switch (outcome) {
            .secure => self.secure += 1,
            .insecure => self.insecure += 1,
            .bogus => {},
        }
    }

    fn fail(self: *Validator, code: u16) Outcome {
        if (self.ede == 0) self.ede = code;
        return .bogus;
    }

    fn noteInsecure(self: *Validator, code: u16) void {
        if (self.insecure_ede == 0) self.insecure_ede = code;
    }

    // ------------------------------------------------------------ indexing

    fn addRecord(self: *Validator, record: *const dns_record.ResourceRecord) Error!void {
        self.seen += 1;
        if (self.seen > max_records) return Error.TooManyRecords;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => null,
        };
        // RRSIGs were indexed by `addSignature`; they are not RRsets of their
        // own and never take part in the Answer-section decision.
        if (record.rrtype.eql(.RRSIG)) return;
        if (raw) |bytes| {
            if (record.rrtype.eql(.NSEC)) return self.addNsec(record, bytes);
            if (record.rrtype.eql(.NSEC3)) return self.addNsec3(record, bytes);
        }
        for (self.rrsets.items) |*rrset| {
            if (rrset.rrtype != record.rrtype.code() or !rrset.owner.eql(&record.owner)) continue;
            try rrset.records.append(self.allocator, record);
            return;
        }
        if (self.rrsets.items.len >= max_rrsets) return Error.TooManyRecords;
        var rrset = Rrset{ .owner = record.owner, .rrtype = record.rrtype.code() };
        try rrset.records.append(self.allocator, record);
        try self.rrsets.append(self.allocator, rrset);
    }

    /// An NSEC or NSEC3 is collected only once its covering RRSIG is known
    /// (RFC 4035 section 5.4: the proof RRsets must themselves be
    /// authenticated), so signatures are indexed in a pass of their own before
    /// any proof is read. Doing it in one pass made collection depend on the
    /// order the records arrived in, and an attacker chooses that order: an
    /// NSEC placed ahead of its RRSIG would have been dropped as unsigned,
    /// turning a real denial into a validation failure.
    fn addSignature(self: *Validator, record: *const dns_record.ResourceRecord) Error!void {
        if (!record.rrtype.eql(.RRSIG)) return;
        if (self.rrsigs.items.len >= max_records) return Error.TooManyRecords;
        const bytes = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.MalformedRrsig,
        };
        try self.rrsigs.append(self.allocator, try Rrsig.at(bytes, record.owner));
    }

    /// An NSEC with no covering RRSIG proves nothing (RFC 4035 section 5.4:
    /// the proof RRsets must themselves be authenticated), so it is dropped
    /// rather than collected.
    fn addNsec(self: *Validator, record: *const dns_record.ResourceRecord, raw: []const u8) Error!void {
        if (self.nsecs.items.len >= max_proofs) return Error.TooManyRecords;
        const rrsig = self.coveringRrsig(record.owner, RecordType.NSEC.code()) orelse return;
        const next = Name.parse(raw, 0) catch return Error.MalformedRdata;
        try self.nsecs.append(self.allocator, .{
            .owner = record.owner,
            .next = next.name,
            .bitmap = raw[next.next_offset..],
            .signer = rrsig.signer,
            .labels = rrsig.labels,
        });
    }

    fn addNsec3(self: *Validator, record: *const dns_record.ResourceRecord, raw: []const u8) Error!void {
        if (self.nsec3s.items.len >= max_proofs) return Error.TooManyRecords;
        const rdata = parseNsec3Rdata(raw) orelse return Error.MalformedRdata;
        const rrsig = self.coveringRrsig(record.owner, RecordType.NSEC3.code()) orelse return;
        // The hashed name's label must sit at the front of the owner name, and
        // the RRSIG's signer must be the zone the rest of it names.
        const owner_wire = record.owner.asWire();
        if (owner_wire[0] != 32 or !isSuffix(rrsig.signer, record.owner)) return Error.MalformedRdata;
        const owner_hash = nsec3OwnerHash(record.owner) orelse return Error.MalformedRdata;
        try self.nsec3s.append(self.allocator, .{
            .owner_hash = owner_hash,
            .next_hash = rdata.next_hash[0..20].*,
            .flags = rdata.flags,
            .iterations = rdata.iterations,
            .salt = rdata.salt,
            .bitmap = rdata.bitmap,
            .signer = rrsig.signer,
            .owner_labels = rrsig.labels,
        });
    }

    fn coveringRrsig(self: *Validator, owner: Name, covered: u16) ?Rrsig {
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered == covered and rrsig.owner.eql(&owner)) return rrsig;
        }
        return null;
    }

    // --------------------------------------------------------------- chain

    /// DNSKEY RDATA trusted for `signer` (RFC 4035 section 5.2). A configured
    /// DNSKEY is its own trust anchor. Otherwise a DS authenticates the child
    /// apex DNSKEY RRset, which must then be self-signed by a key the DS
    /// matched and which carries the Zone flag. An empty result means no
    /// configured anchor reaches this zone: the RRset is insecure, not bogus.
    fn keySet(self: *Validator, signer: Name) Error![]const []const u8 {
        for (self.chains.items) |cached| {
            if (cached.signer.eql(&signer)) return cached.keys;
        }
        if (self.chains.items.len >= max_chains) return Error.TooManyRecords;
        var keys: std.ArrayList([]const u8) = .empty;
        for (self.anchors.items[0..self.anchors.len]) |anchor| {
            if (!anchor.rrtype.eql(.DNSKEY) or !anchor.owner.eql(&signer)) continue;
            // RFC 4034 section 2.1.1: a key without the Zone Key flag must
            // not verify an RRset, and RFC 4035 section 5.2 leaves a zone
            // whose algorithm this build cannot verify unsigned.
            if (!dnskeyZoneKeyBit(anchor.rdata)) continue;
            if (!algorithmSupported(anchor.rdata[3])) continue;
            try keys.append(self.allocator, anchor.rdata);
        }
        if (keys.items.len == 0) try self.keysFromDs(&keys, signer);
        if (keys.items.len == 0) {
            // No chain to the zone: the reason the answer is insecure is
            // worth reporting (RFC 8914 sections 4.2, 4.3, 4.6 and 4.12).
            if (self.chainReason(signer)) |code| self.noteInsecure(code);
        }
        try self.chains.append(self.allocator, .{ .signer = signer, .keys = keys.items });
        return keys.items;
    }

    fn dsAnchorFor(self: *const Validator, signer: Name) bool {
        var index: usize = 0;
        while (index < self.anchors.len) : (index += 1) {
            const anchor = &self.anchors.items[index];
            if (!anchor.rrtype.eql(.DS)) continue;
            if (!anchor.owner.eql(&signer)) continue;
            return true;
        }
        return false;
    }

    /// Why the chain to `signer` could not be built, as an RFC 8914
    /// INFO-CODE. RFC 4035 section 5.2 keeps the answer insecure in each of
    /// these cases, so the code explains an answer the client still gets
    /// instead of failing it. Null when no anchor speaks for the zone: a
    /// zone outside the trust domain is honestly unsigned.
    fn chainReason(self: *Validator, signer: Name) ?u16 {
        var speaks_for_zone = false;
        for (self.anchors.items[0..self.anchors.len]) |anchor| {
            if (!anchor.owner.eql(&signer)) continue;
            if (anchor.rrtype.eql(.DS) or anchor.rrtype.eql(.DNSKEY)) speaks_for_zone = true;
        }
        if (!speaks_for_zone) return null;

        // The keys the zone publishes: the DNSKEY RRset the response carried
        // for the apex, and the configured DNSKEY anchor that stands for it.
        var saw_key = false;
        var saw_zone_key = false;
        var saw_supported_algorithm = false;
        for (self.anchors.items[0..self.anchors.len]) |anchor| {
            if (!anchor.rrtype.eql(.DNSKEY) or !anchor.owner.eql(&signer)) continue;
            if (anchor.rdata.len < 4) continue;
            saw_key = true;
            if (dnskeyZoneKeyBit(anchor.rdata)) saw_zone_key = true;
            if (algorithmSupported(anchor.rdata[3])) saw_supported_algorithm = true;
        }
        for (self.rrsets.items) |*rrset| {
            if (rrset.rrtype != RecordType.DNSKEY.code() or !rrset.owner.eql(&signer)) continue;
            for (rrset.records.items) |record| {
                const raw = encodeRdata(self.allocator, record.rdata) catch continue;
                if (raw.len < 4) continue;
                saw_key = true;
                if (dnskeyZoneKeyBit(raw)) saw_zone_key = true;
                if (algorithmSupported(raw[3])) saw_supported_algorithm = true;
            }
        }
        // RFC 8914 section 4.12: no DNSKEY of the zone carried the Zone Key
        // flag, so no key could sign the zone.
        if (saw_key and !saw_zone_key) return dnssec.EDE_NO_ZONE_KEY_BIT;
        // RFC 8914 section 4.2: the DNSKEY RRset held only algorithms this
        // build cannot verify with.
        if (saw_key and !saw_supported_algorithm) return dnssec.EDE_UNSUPPORTED_DNSKEY_ALGORITHM;

        // The DS the parent published for the zone.
        var saw_ds = false;
        var saw_supported_digest = false;
        var saw_supported_ds_algorithm = false;
        for (self.anchors.items[0..self.anchors.len]) |anchor| {
            if (!anchor.rrtype.eql(.DS) or !anchor.owner.eql(&signer)) continue;
            saw_ds = true;
            if (dsDigestTypeSupported(anchor.rdata)) saw_supported_digest = true;
            if (anchor.rdata.len >= 3 and algorithmSupported(anchor.rdata[2])) saw_supported_ds_algorithm = true;
        }
        // RFC 8914 section 4.3: the DS RRset held only digest types this
        // build cannot compute.
        if (saw_ds and !saw_supported_digest) return dnssec.EDE_UNSUPPORTED_DS_DIGEST_TYPE;
        // The DS names a (key tag, algorithm) pair no DNSKEY of the zone
        // carries, and that algorithm is one this build cannot verify with.
        if (saw_ds and !saw_supported_ds_algorithm) return dnssec.EDE_UNSUPPORTED_DNSKEY_ALGORITHM;
        // The anchor speaks for the zone, so the answer should be signed, but
        // no chain to a verdict exists: RFC 4035 section 4.3 calls that
        // state Indeterminate.
        return dnssec.EDE_DNSSEC_INDETERMINATE;
    }

    // Called only when keySet found zero keys, which already covers every
    // DNSKEY anchor for the signer — so only the response RRsets are live.
    fn hasDnskey(self: *const Validator, signer: Name) bool {
        for (self.rrsets.items) |*rrset| {
            if (rrset.rrtype != RecordType.DNSKEY.code()) continue;
            if (rrset.owner.eql(&signer)) return true;
        }
        return false;
    }

    fn keysFromDs(self: *Validator, keys: *std.ArrayList([]const u8), signer: Name) Error!void {
        for (self.anchors.items[0..self.anchors.len]) |anchor| {
            if (!anchor.rrtype.eql(.DS) or !anchor.owner.eql(&signer)) continue;
            for (self.rrsets.items) |*rrset| {
                if (rrset.rrtype != RecordType.DNSKEY.code() or !rrset.owner.eql(&signer)) continue;
                for (rrset.records.items) |record| {
                    const raw = try encodeRdata(self.allocator, record.rdata);
                    // RFC 4035 section 5.2 names the Zone Flag as one of the
                    // three conditions; a bare key could sign the apex RRset
                    // without being authoritative for the zone.
                    if (!dnskeyZoneKeyBit(raw)) continue;
                    // A key this build cannot verify with is no key at all:
                    // RFC 4035 section 5.2 leaves the zone unsigned.
                    if (!algorithmSupported(raw[3])) continue;
                    if (!dsMatches(anchor.rdata, signer, raw)) continue;
                    try keys.append(self.allocator, raw);
                }
            }
        }
        if (keys.items.len == 0) return;
        // The matched DNSKEY must have signed the apex DNSKEY RRset itself.
        var rrset: ?*const Rrset = null;
        for (self.rrsets.items) |*candidate| {
            if (candidate.rrtype == RecordType.DNSKEY.code() and candidate.owner.eql(&signer)) {
                rrset = candidate;
                break;
            }
        }
        const apex = rrset orelse return keys.clearRetainingCapacity();
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != RecordType.DNSKEY.code() or !rrsig.owner.eql(&signer)) continue;
            const data = try signedData(self.allocator, apex.records.items, rrsig);
            for (keys.items) |key| {
                verifyWithKey(key, rrsig, data) catch continue;
                return;
            }
        }
        keys.clearRetainingCapacity();
    }

    // ------------------------------------------------------------ RRsets

    /// Validate one signed RRset (RFC 4035 section 5.3). Every RRSIG that
    /// covers it is tried: a zone with two keys publishes two signatures and
    /// one of them failing says nothing about the other.
    fn checkRrset(self: *Validator, rrset: *const Rrset) Error!Outcome {
        var saw_signature = false;
        var has_keys = false;
        var unsupported_algorithm = false;
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != rrset.rrtype or !rrsig.owner.eql(&rrset.owner)) continue;
            saw_signature = true;
            // RFC 4035 section 5.5: a signer that is not a suffix of the owner
            // name vouched for nothing here, whatever the signature says.
            if (!isSuffix(rrsig.signer, rrset.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            const keys = try self.keySet(rrsig.signer);
            if (keys.len == 0) {
                // RFC 8914 section 4.10: a DS existed at a parent, but no
                // supported matching DNSKEY could be found for the child.
                if (self.dsAnchorFor(rrsig.signer) and !self.hasDnskey(rrsig.signer)) {
                    return self.fail(dnssec.EDE_DNSKEY_MISSING);
                }
                continue;
            }
            has_keys = true;
            // RFC 4035 section 5.2: a signature this build cannot verify
            // leaves the zone with no supported authentication path, so the
            // answer is insecure rather than bogus.
            if (!algorithmSupported(rrsig.algorithm)) {
                unsupported_algorithm = true;
                continue;
            }
            const status = dnssec.rrsigTimeStatus(rrsig.raw, self.now) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (status != .valid) return self.fail(dnssec.rrsigTimeEde(status).?);
            const data = try signedData(self.allocator, rrset.records.items, rrsig);
            for (keys) |key| {
                verifyWithKey(key, rrsig, data) catch continue;
                return .secure;
            }
        }
        if (!saw_signature) {
            // An NS RRset at a zone cut belongs to neither side: the parent
            // does not sign it and the child has not been reached, so its
            // absence of a signature says nothing about the trust domain.
            if (rrset.rrtype == RecordType.NS.code()) return .insecure;
            // Any other RRset in a zone the operator anchored must carry a
            // signature; its absence is bogus, not merely unsigned.
            if (self.anchors.covers(rrset.owner)) return self.fail(dnssec.EDE_RRSIGS_MISSING);
            return .insecure;
        }
        if (!has_keys) return .insecure;
        if (unsupported_algorithm) {
            self.noteInsecure(dnssec.EDE_UNSUPPORTED_DNSKEY_ALGORITHM);
            return .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    // ------------------------------------------------------------ NSEC

    /// RFC 4035 section 5.4 with RFC 6840 sections 4.1, 4.3 and 4.4.
    fn checkNsecDenial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        // RFC 6840 section 4.1 exempts DS from the ancestor-delegation ban:
        // "all RRs at that (original) owner name other than DS RRs". The NSEC a
        // parent publishes at a delegation is therefore the legitimate proof
        // for a DS query, and section 4.4 says what it has to show.
        if (delegation and qtype == RecordType.DS.code()) return self.nsecUnsignedDelegation(name);
        for (self.nsecs.items) |*proof| {
            if (proof.owner.eql(&name)) return self.nsecNoData(proof, qtype);
        }
        if (!nxdomain) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        return self.nsecNxDomain(name);
    }

    /// RFC 6840 section 4.4: an insecure delegation needs the NS bit to show
    /// there really is a delegation, and DS and SOA both clear to show no DS
    /// RRset exists for it. Reusing an NSEC at a non-delegation name would let
    /// an attacker claim an existing signed RRset sits below an unsigned cut.
    fn nsecUnsignedDelegation(self: *Validator, name: Name) Error!Outcome {
        for (self.nsecs.items) |*proof| {
            if (!proof.owner.eql(&name)) continue;
            if (!dnssec.nsecBitmapHasType(proof.bitmap, RecordType.NS.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.DS.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.SOA.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            // The delegation itself is proven; nothing below the cut is.
            return .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// The exact-owner case. The bitmap must be strictly well-formed and must
    /// deny both the QTYPE and CNAME; the NSEC must not be an ancestor
    /// delegation; and the covering RRSIG must claim the owner's own label
    /// count, or the denial only proves that a wildcard could not have
    /// answered.
    fn nsecNoData(self: *Validator, proof: *const Nsec, qtype: u16) Error!Outcome {
        if (isAncestorDelegation(proof.bitmap, labelCount(proof.owner.asWire()), labelCount(proof.signer.asWire()))) {
            return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        }
        if (!deniesWildcard(proof.labels, proof.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const denies = dnssec.bitmapDeniesTypeAndCname(proof.bitmap, qtype) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        if (!denies) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        return if (try self.anchored(proof.signer)) .secure else .insecure;
    }

    /// Three proofs are needed: the closest encloser must exist, one NSEC must
    /// cover the next closer name, and one must cover the wildcard at the
    /// closest encloser. A wildcard that exists is what a positive answer
    /// would have come from, so it must be denied too.
    fn nsecNxDomain(self: *Validator, name: Name) Error!Outcome {
        var next_closer = name;
        var ancestor = parentName(name);
        var steps: usize = 0;
        while (ancestor) |encloser| : (steps += 1) {
            if (steps >= max_labels) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            for (self.nsecs.items) |*proof| {
                if (!proof.owner.eql(&encloser)) continue;
                return self.nsecEncloser(proof, next_closer);
            }
            next_closer = encloser;
            ancestor = parentName(encloser);
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    fn nsecEncloser(self: *Validator, proof: *const Nsec, next_closer: Name) Error!Outcome {
        if (isAncestorDelegation(proof.bitmap, labelCount(proof.owner.asWire()), labelCount(proof.signer.asWire()))) {
            return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        }
        if (!deniesWildcard(proof.labels, proof.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const wildcard = wildcardName(proof.owner) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        for ([_]Name{ next_closer, wildcard }) |target| {
            for (self.nsecs.items) |*candidate| {
                if (!dnssec.nsecCovers(candidate.owner, candidate.next, target)) continue;
                // An ancestor delegation proves nothing below the cut, and a
                // DNAME redirects the subtree it would have denied.
                if (isAncestorDelegation(candidate.bitmap, labelCount(candidate.owner.asWire()), labelCount(candidate.signer.asWire()))) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
                if (deniesSubdomain(candidate.bitmap, candidate.owner, target)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            }
        }
        return if (try self.anchored(proof.signer)) .secure else .insecure;
    }

    // ----------------------------------------------------------- NSEC3

    /// RFC 5155 section 8.3. The flag is not per-iteration: step 1 clears it
    /// once, and each pass then applies "no match clears it, a covering NSEC3
    /// sets it". So the flag a name inherits is what a *longer* name proved,
    /// which is exactly how a name below a known encloser is shown not to
    /// exist. Requiring the match and the cover in the same pass would find
    /// no encloser at all, because an encloser's own hash is a span endpoint
    /// and is therefore never covered.
    fn nsec3ClosestEncloser(self: *Validator, name: Name) Error!?Encloser {
        var covered = false;
        var candidate = name;
        var steps: usize = 0;
        while (steps < max_labels) : (steps += 1) {
            const digest = self.hash(candidate);
            var matched: ?Nsec3 = null;
            var spans = false;
            for (self.nsec3s.items) |proof| {
                if (std.mem.eql(u8, &proof.owner_hash, &digest)) matched = proof;
                if (nsec3Covers(proof.owner_hash, proof.next_hash, digest)) spans = true;
            }
            if (matched == null) covered = false;
            if (spans) covered = true;
            if (matched) |proof| {
                // A matching NSEC3 with the flag clear is the RFC's "response
                // is bogus" case, not an incomplete proof.
                if (!covered) return null;
                // The encloser's NSEC3 must come from the zone that holds the
                // encloser: no DNAME, and NS only alongside SOA.
                if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.DNAME.code())) return null;
                if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.NS.code()) and
                    !dnssec.nsecBitmapHasType(proof.bitmap, RecordType.SOA.code())) return null;
                return .{ .name = candidate, .proof = proof };
            }
            candidate = parentName(candidate) orelse return null;
        }
        return null;
    }

    /// NSEC3 iterated hashing uses the parameters the proofs themselves carry
    /// (RFC 5155 section 7.1). A response mixing two parameter sets cannot be
    /// one consistent proof, so the first record's parameters are the ones
    /// used and any other set is rejected outright.
    fn hash(self: *Validator, name: Name) [20]u8 {
        const proof = self.nsec3s.items[0];
        var out: [20]u8 = undefined;
        dnssec.nsec3Hash(name, proof.salt, proof.iterations, &out);
        return out;
    }

    fn nsec3ParamsConsistent(self: *Validator) bool {
        const first = self.nsec3s.items[0];
        for (self.nsec3s.items[1..]) |proof| {
            if (proof.iterations != first.iterations) return false;
            if (!std.mem.eql(u8, proof.salt, first.salt)) return false;
        }
        return true;
    }

    /// RFC 5155 sections 8.4 to 8.7, dispatched on what the response claims.
    fn checkNsec3Denial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        if (!self.nsec3ParamsConsistent()) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const outcome = try self.nsec3Denial(name, qtype, delegation, nxdomain);
        // RFC 9276 section 3.2: a validator that processes NSEC3 records with
        // an iteration count above 0 answers insecure, not secure, and says
        // so with the EDE the RFC assigns to that answer.
        if (self.nsec3s.items[0].iterations > 0) {
            self.noteInsecure(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS);
            if (outcome == .secure) return .insecure;
        }
        return outcome;
    }

    fn nsec3Denial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        if (delegation) return self.nsec3UnsignedReferral(name);
        const digest = self.hash(name);
        for (self.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            return self.nsec3NoData(proof, qtype);
        }
        if (nxdomain) return self.nsec3NxDomain(name);
        // RFC 5155 section 8.6: a DS NODATA with no matching NSEC3 is proved by
        // an opt-out closest-encloser proof rather than an exact match.
        if (qtype == RecordType.DS.code()) return self.nsec3OptOutCover(name);
        return self.nsec3WildcardNoData(name, qtype);
    }

    /// RFC 5155 sections 8.5 and 8.6: the matching NSEC3's bitmap must leave
    /// the QTYPE and CNAME bits clear. Leaving CNAME set is what tells a
    /// stripped CNAME response apart from a real NODATA (RFC 6840 section 4.3).
    fn nsec3NoData(self: *Validator, proof: *const Nsec3, qtype: u16) Error!Outcome {
        const denies = dnssec.bitmapDeniesTypeAndCname(proof.bitmap, qtype) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        if (!denies) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        return if (try self.anchored(proof.signer)) .secure else .insecure;
    }

    /// RFC 5155 section 8.4: a closest encloser proof for the name, plus an
    /// NSEC3 covering the wildcard at that encloser.
    fn nsec3NxDomain(self: *Validator, name: Name) Error!Outcome {
        const encloser = (try self.nsec3ClosestEncloser(name)) orelse return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const wildcard = wildcardName(encloser.name) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const digest = self.hash(wildcard);
        for (self.nsec3s.items) |proof| {
            if (!nsec3Covers(proof.owner_hash, proof.next_hash, digest)) continue;
            return if (try self.anchored(encloser.proof.signer)) .secure else .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// RFC 5155 section 8.7: the response denies a name the wildcard at the
    /// closest encloser would have answered, so that wildcard needs an exact
    /// match with the QTYPE and CNAME bits clear.
    fn nsec3WildcardNoData(self: *Validator, name: Name, qtype: u16) Error!Outcome {
        const encloser = (try self.nsec3ClosestEncloser(name)) orelse return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const wildcard = wildcardName(encloser.name) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const digest = self.hash(wildcard);
        for (self.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            const denies = dnssec.bitmapDeniesTypeAndCname(proof.bitmap, qtype) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (!denies) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            return if (try self.anchored(proof.signer)) .secure else .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// RFC 5155 section 8.9 with RFC 6840 section 4.4: an unsigned delegation
    /// is proved either by an NSEC3 matching the delegation name with NS set,
    /// DS and SOA clear, or by a closest-encloser proof whose covering NSEC3
    /// carries Opt-Out. Without one of those an attacker could reuse an NSEC3
    /// for a non-delegation name to spoof an unsigned delegation, claiming an
    /// existing signed RRset sits below an unsigned delegation.
    fn nsec3UnsignedReferral(self: *Validator, name: Name) Error!Outcome {
        const digest = self.hash(name);
        for (self.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            if (!dnssec.nsecBitmapHasType(proof.bitmap, RecordType.NS.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.DS.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (dnssec.nsecBitmapHasType(proof.bitmap, RecordType.SOA.code())) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            // The delegation is proven, but nothing below the cut is signed.
            return .insecure;
        }
        return self.nsec3OptOutCover(name);
    }

    /// A closest-encloser proof for `name` whose covering NSEC3 carries
    /// Opt-Out: the zone may hold names under the cut that it never signed.
    fn nsec3OptOutCover(self: *Validator, name: Name) Error!Outcome {
        const encloser = (try self.nsec3ClosestEncloser(name)) orelse return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        var next_closer = name;
        var steps: usize = 0;
        while (steps < max_labels) : (steps += 1) {
            const parent = parentName(next_closer) orelse break;
            if (parent.eql(&encloser.name)) {
                const digest = self.hash(next_closer);
                for (self.nsec3s.items) |proof| {
                    if (!nsec3Covers(proof.owner_hash, proof.next_hash, digest)) continue;
                    if (proof.flags & nsec3_opt_out == 0) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
                    // The opt-out proof is what is authenticated here; either
                    // way nothing below the cut can be vouched for.
                    return .insecure;
                }
                return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            }
            next_closer = parent;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    fn anchored(self: *Validator, signer: Name) Error!bool {
        return (try self.keySet(signer)).len != 0;
    }
};

/// RFC 5155 section 3, Flags: the Opt-Out bit on an NSEC3 RR.
pub const nsec3_opt_out: u8 = 0x01;

/// True when the Authority section holds a delegation: an NS RRset with no
/// SOA, which is what distinguishes a referral from a name error.
fn isReferral(records: []const dns_record.ResourceRecord) bool {
    var saw_ns = false;
    for (records) |record| {
        if (record.rrtype.eql(.NS)) saw_ns = true;
        if (record.rrtype.eql(.SOA)) return false;
    }
    return saw_ns;
}

/// Validate one response against the configured anchors and return its
/// security status. `extra` carries DNSKEY records the caller fetched out of
/// band (a supplementary DNSKEY query), which is how a DS-only anchor reaches
/// a child apex DNSKEY RRset on a forwarder that returns only the answer.
/// `now` is unix seconds and must come from the caller's clock, never from
/// inside this function, so a test can pin the validity window.
pub fn validate(
    allocator: std.mem.Allocator,
    anchors: *const Anchors,
    query: dns_message.Message,
    response: dns_message.Message,
    extra: []const dns_record.ResourceRecord,
    now: u32,
) Error!Result {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var self = Validator{ .allocator = arena.allocator(), .anchors = anchors, .now = now };
    const sections = [_][]const dns_record.ResourceRecord{
        response.answers.slice(),
        response.authorities.slice(),
        extra,
    };
    for (sections) |section| {
        for (section) |*record| try self.addSignature(record);
    }
    for (sections) |section| {
        for (section) |*record| try self.addRecord(record);
    }

    // No signature arrived at all. A name inside the trust domain must be
    // signed, so an unsigned answer there is bogus (RFC 4035 section 5.5);
    // everywhere else it is honestly insecure.
    if (self.rrsigs.items.len == 0) {
        const question = query.question orelse return .{ .status = .insecure };
        if (anchors.covers(question.name)) return .{ .status = .bogus, .ede = dnssec.EDE_RRSIGS_MISSING };
        return .{ .status = .insecure };
    }

    for (self.rrsets.items) |*rrset| self.count(try self.checkRrset(rrset));

    // RFC 4035 section 3.2.3: the AD bit covers the Answer section and the
    // negative response RRs in Authority, so the denial proof is part of the
    // same decision, not a later one.
    if (response.answers.len == 0) {
        const question = query.question orelse return .{ .status = .insecure };
        const nxdomain = response.header.rcode == .nxdomain;
        const delegation = isReferral(response.authorities.slice());
        const outcome = if (self.nsec3s.items.len != 0)
            try self.checkNsec3Denial(question.name, question.qtype.code(), delegation, nxdomain)
        else if (self.nsecs.items.len != 0)
            try self.checkNsecDenial(question.name, question.qtype.code(), delegation, nxdomain)
        else
            self.fail(dnssec.EDE_DNSSEC_BOGUS);
        self.count(outcome);
    }

    if (self.ede != 0) return .{ .status = .bogus, .ede = self.ede };
    if (self.secure == 0) return .{ .status = .insecure, .ede = self.insecure_ede };
    // AD covers every RRset in the answer, so one unanchored RRset in the mix
    // is enough to withhold it.
    if (self.insecure != 0) return .{ .status = .insecure, .ede = self.insecure_ede };
    return .{ .status = .secure };
}

/// RFC 8976 section 4 step 3: the RRsets named by `types` must carry valid
/// signatures that chain up to a configured trust anchor. `zone` is the
/// loaded zone, and only its apex records take part, because the SOA and the
/// ZONEMD live there. A zone that no configured anchor names needs no chain,
/// and is reported as signed.
pub fn zoneSignedToAnchor(
    allocator: std.mem.Allocator,
    anchors: *const Anchors,
    zone: *const zone_index.Zone,
    types: []const u16,
    now: u32,
) Error!bool {
    const apex = Name.fromText(zone.originText()) catch return Error.MalformedRdata;
    if (!anchors.anchorsZone(apex)) return true;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var validator = Validator{ .allocator = scratch, .anchors = anchors, .now = now };
    const records = try apexRecords(scratch, zone, apex);
    for (records) |record| {
        if (record.rrtype.eql(.RRSIG)) {
            try validator.addSignature(record);
        } else {
            try validator.addRecord(record);
        }
    }
    for (types) |rrtype| {
        const rrset = findRrset(&validator, apex, rrtype) orelse return false;
        if (try validator.checkRrset(rrset) != .secure) return false;
    }
    return true;
}

/// RFC 8976 section 4 step 2: what the zone's own DNSSEC records say about the
/// apex ZONEMD RRset of a zone that publishes no ZONEMD record.
pub const ZonemdAbsence = enum {
    /// The zone's own NSEC or NSEC3 records deny the ZONEMD type at the apex,
    /// so the zone publishes no ZONEMD. RFC 8976 section 4 step 2 says digest
    /// verification cannot occur, which is an answer and not a failure.
    proven,
    /// No configured anchor names the zone, so RFC 8976 section 4 step 1 does
    /// not expect DNSSEC records and the absence needs no proof.
    not_expected,
    /// An anchor names the zone, but no record of the zone denies the ZONEMD
    /// type at the apex: absent and unknown cannot be told apart, so the
    /// caller must fail closed.
    unknown,
};

/// One zone record a denial proof rests on, with the owner and the type the
/// signature over it must carry.
const Denial = struct {
    owner: Name,
    rrtype: RecordType,
    record: dns_record.ResourceRecord,
};

/// RFC 8976 section 4 step 2: the existence of the apex ZONEMD record must be
/// validated for a zone where signatures are expected. The zone's own DNSSEC
/// records carry the proof: the NSEC at the apex, or the NSEC3 whose owner
/// hash matches the apex, must deny the ZONEMD type. The denial is the one the
/// validator already applies to a response, so a zone cannot prove an absence
/// it could not have proved over the wire.
pub fn zoneZonemdAbsence(
    allocator: std.mem.Allocator,
    anchors: *const Anchors,
    zone: *const zone_index.Zone,
    now: u32,
) Error!ZonemdAbsence {
    const apex = Name.fromText(zone.originText()) catch return Error.MalformedRdata;
    // RFC 8976 section 4 step 1: an anchor for the zone says DNSSEC records
    // are expected, an anchor for a zone above it does not.
    if (!anchors.anchorsZone(apex)) return .not_expected;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var validator = Validator{ .allocator = scratch, .anchors = anchors, .now = now };

    // RFC 5155 section 7.1: the apex NSEC3PARAM states the hash algorithm,
    // the flags, the iteration count, and the salt that govern the chain, so
    // the parameters come from there and not from an arbitrary record of the
    // chain. A zone that carries a second NSEC3PARAM, as a rollover does,
    // cannot say which chain it publishes, and a chain that names a hash
    // algorithm this build does not compute can never be proven; both leave
    // the absence unproven.
    var salt: [255]u8 = undefined;
    var salt_len: usize = 0;
    var iterations: u16 = 0;
    var has_chain = false;
    var declares_params = false;
    var unproven_chain = false;
    var param_count: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC3PARAM)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        param_count += 1;
        if (param_count > 1) {
            unproven_chain = true;
            break;
        }
        declares_params = true;
        const params = zoneNsec3Param(record) orelse {
            unproven_chain = true;
            break;
        };
        // RFC 5155 section 3.1.1: this build computes SHA-1 only.
        if (params.hash_algorithm != 1) {
            unproven_chain = true;
            break;
        }
        salt_len = params.salt.len;
        @memcpy(salt[0..salt_len], params.salt);
        iterations = params.iterations;
        has_chain = true;
    }
    if (unproven_chain) return .unknown;
    if (!declares_params) {
        // The zone states no parameters of its own, so the chain's own
        // records are the only source; RFC 5155 section 7.2 requires every
        // record of a chain to use the same salt and iteration count.
        for (zone.records.items[0..zone.records.len]) |record| {
            if (!record.rrtype.eql(.NSEC3)) continue;
            const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch continue;
            const bytes = switch (rdata) {
                .Unknown => |*unknown| unknown.bytes(),
                else => continue,
            };
            const parsed = parseNsec3Rdata(bytes) orelse continue;
            salt_len = parsed.salt.len;
            @memcpy(salt[0..salt_len], parsed.salt);
            iterations = parsed.iterations;
            has_chain = true;
            break;
        }
    }

    // The hash of the apex, which the NSEC3 that matches it carries as its
    // owner name.
    var digest: [20]u8 = undefined;
    if (has_chain) dnssec.nsec3Hash(apex, salt[0..salt_len], iterations, &digest);

    // The records that can prove the absence: the NSEC at the apex, the NSEC3
    // that matches the apex, and the apex DNSKEY RRset a DS anchor needs to
    // reach the zone's own key.
    var proofs: std.ArrayList(Denial) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.NSEC) and !record.rrtype.eql(.NSEC3) and !record.rrtype.eql(.DNSKEY)) continue;
        const owner = Name.fromText(record.ownerText()) catch continue;
        if (record.rrtype.eql(.NSEC)) {
            if (!owner.eql(&apex)) continue;
        } else if (record.rrtype.eql(.NSEC3)) {
            if (!has_chain) continue;
            const owner_hash = nsec3OwnerHash(owner) orelse continue;
            if (!std.mem.eql(u8, &owner_hash, &digest)) continue;
        } else if (!owner.eql(&apex)) continue;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch continue;
        try proofs.append(scratch, .{
            .owner = owner,
            .rrtype = record.rrtype,
            .record = .{
                .owner = owner,
                .rrtype = record.rrtype,
                .class = Class.IN,
                .ttl = record.ttl,
                .rdata = rdata,
            },
        });
    }

    // A proof is worthless without the signature that covers it (RFC 4035
    // section 5.4), so the RRSIG over each proof is collected with it.
    var signatures: std.ArrayList(dns_record.ResourceRecord) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        const owner = Name.fromText(record.ownerText()) catch continue;
        var wanted = false;
        for (proofs.items) |proof| {
            if (proof.owner.eql(&owner)) wanted = true;
        }
        if (!wanted) continue;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch continue;
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const covered = dnssec.rrsigCovers(bytes) catch continue;
        var covers_proof = false;
        for (proofs.items) |proof| {
            if (proof.rrtype.code() == covered and proof.owner.eql(&owner)) covers_proof = true;
        }
        if (!covers_proof) continue;
        try signatures.append(scratch, .{
            .owner = owner,
            .rrtype = .RRSIG,
            .class = Class.IN,
            .ttl = record.ttl,
            .rdata = rdata,
        });
    }

    // The signatures are indexed first: a proof is read only once the
    // signature that covers it is known.
    for (signatures.items) |*record| try validator.addSignature(record);
    for (proofs.items) |*proof| try validator.addRecord(&proof.record);

    // RFC 4035 section 3.1.3 and RFC 5155 section 8.6: the record at the name
    // must deny the type, and the denial must reach the trust anchor.
    for (validator.nsecs.items) |*proof| {
        if (!proof.owner.eql(&apex)) continue;
        if (try validator.nsecNoData(proof, RecordType.ZONEMD.code()) == .secure) return .proven;
    }
    if (has_chain) {
        for (validator.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            if (try validator.nsec3NoData(proof, RecordType.ZONEMD.code()) == .secure) return .proven;
        }
    }
    return .unknown;
}

/// The apex records the chain check reads, in the wire form the validator
/// signs over: the SOA, the ZONEMD, the DNSKEY RRset, and every RRSIG at the
/// apex. Nothing below the apex can authenticate it, and the set is small
/// enough to bound the work. Every record is class IN, which is the only
/// class the zone parser reads.
fn apexRecords(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    apex: Name,
) Error![]*const dns_record.ResourceRecord {
    var list: std.ArrayList(dns_record.ResourceRecord) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        if (!record.rrtype.eql(.SOA) and !record.rrtype.eql(.ZONEMD) and
            !record.rrtype.eql(.DNSKEY) and !record.rrtype.eql(.RRSIG)) continue;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.MalformedRdata;
        try list.append(allocator, .{
            .owner = apex,
            .rrtype = record.rrtype,
            .class = Class.IN,
            .ttl = record.ttl,
            .rdata = rdata,
        });
    }
    const pointers = try allocator.alloc(*const dns_record.ResourceRecord, list.items.len);
    for (list.items, 0..) |*record, index| pointers[index] = record;
    return pointers;
}

/// The RRset the validator grouped for one owner and one type.
fn findRrset(validator: *const Validator, owner: Name, rrtype: u16) ?*const Rrset {
    for (validator.rrsets.items) |*rrset| {
        if (rrset.rrtype != rrtype) continue;
        if (!rrset.owner.eql(&owner)) continue;
        return rrset;
    }
    return null;
}

// ------------------------------------------------------------------- tests

const dns_header = @import("header.zig");
const dns_question = @import("question.zig");
const zone_signer = @import("../zone/signer.zig");

/// The RFC 6605 and RFC 8080 test keys the signer already uses. A validator
/// that could only check keys it generated itself would prove nothing, so the
/// same published keys drive both sides.
const ed25519_secret = "ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n";
const p256_secret = "ecdsap256sha256 GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n";
/// A fixed window and a fixed clock. Nothing here reads a wall clock, so every
/// signature is byte-for-byte reproducible and no test can pass by accident on
/// a slow machine.
const window = zone_signer.Options{ .inception = 1_000_000_000, .expiration = 2_000_000_000 };
const now_seconds: u32 = 1_500_000_000;

const child_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\@ IN MX 10 mail.example.com.
    \\ns1 IN A 192.0.2.1
    \\www IN A 192.0.2.2
    \\mail IN A 192.0.2.3
    \\alias IN CNAME www.example.com.
    \\sub IN NS ns.sub.example.com.
;

/// The same child zone with a DS at the delegation, so the NSEC the signer
/// writes there carries the DS bit and the insecure-delegation proof fails.
const child_ds_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
    \\sub IN NS ns.sub.example.com.
    \\sub IN DS 1234 13 2 0000000000000000000000000000000000000000000000000000000000000000
;

/// A parent zone. Signing it produces the NSEC a parent publishes at a
/// delegation: NS set, SOA clear, and a signer name shorter than the NSEC's own
/// owner. That record is the whole of the RFC 6840 section 4.1 attack.
const parent_zone_text =
    \\$ORIGIN com.
    \\$TTL 3600
    \\@ IN SOA ns.com. hostmaster.com. 1 3600 900 1209600 3600
    \\@ IN NS ns.com.
    \\ns IN A 192.0.2.10
    \\example.com. IN NS ns1.example.com.
;

const SignedZone = struct {
    zone: zone_index.Zone,
    key: zone_signer.Key,
    /// The public record an operator writes as a trust anchor.
    dnskey: []const u8,

    fn deinit(self: *SignedZone, allocator: std.mem.Allocator) void {
        self.zone.deinit();
        self.key.deinit();
        allocator.free(self.dnskey);
    }
};

fn signZoneText(allocator: std.mem.Allocator, text: []const u8, key_text: []const u8) !SignedZone {
    var zone_file = try zone_parser.ZoneFile.parse(text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    errdefer zone.deinit();
    var key = try zone_signer.parseKey(key_text);
    errdefer key.deinit();
    try zone_signer.signZone(allocator, &zone, &key, window);
    return .{
        .zone = zone,
        .key = key,
        .dnskey = try key.dnskeyRdata(allocator),
    };
}

const Exchange = struct {
    query: dns_message.Message,
    response: dns_message.Message,
};

fn emptyMessage(allocator: std.mem.Allocator, header: dns_header.Header, question: dns_question.Question) !dns_message.Message {
    return .{
        .allocator = allocator,
        .header = header,
        .question = question,
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
        .edns = .{
            .udp_payload_size = dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE,
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = true,
        },
    };
}

/// Send a message out over the wire and read it back, so every test sees the
/// octets a client would receive rather than records this file assembled.
fn roundTrip(allocator: std.mem.Allocator, message: dns_message.Message) !dns_message.Message {
    var buffer: [64 * 1024]u8 = undefined;
    var writer = dns_writer.Writer.init(&buffer);
    try message.encode(&writer);
    return dns_message.Message.parse(allocator, writer.written());
}

/// Build the query and the response a server would publish for it, from a zone
/// the signer has just signed. Records for `answer_owner` land in the Answer
/// section; `include` narrows Authority to the named owners, or takes every
/// owner when it is null.
fn exchange(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    qname: []const u8,
    qtype: RecordType,
    rcode: dns_header.Rcode,
    answer_owner: []const u8,
    include: ?[]const []const u8,
) !Exchange {
    const question = dns_question.Question{ .name = try Name.fromText(qname), .qtype = qtype, .qclass = .IN };
    var query = try emptyMessage(allocator, .{ .id = 0x1234, .recursion_desired = true, .question_count = 1 }, question);
    defer query.deinit();
    var response = try emptyMessage(allocator, .{
        .id = 0x1234,
        .qr = true,
        .recursion_desired = true,
        .recursion_available = true,
        .question_count = 1,
        .rcode = rcode,
    }, question);
    defer response.deinit();

    for (zone.records.items[0..zone.records.len]) |*record| {
        if (record.rrtype.eql(.OPT)) continue;
        const answered = std.ascii.eqlIgnoreCase(record.ownerText(), answer_owner);
        // `include` narrows Authority only: the Answer section is whatever the
        // question named, which is the one thing a filter must not remove.
        if (!answered) {
            if (include) |owners| {
                var listed = false;
                for (owners) |owner| {
                    if (std.ascii.eqlIgnoreCase(record.ownerText(), owner)) listed = true;
                }
                if (!listed) continue;
            }
        }
        const wire_record = dns_record.ResourceRecord{
            .owner = try Name.fromText(record.ownerText()),
            .rrtype = record.rrtype,
            .class = .IN,
            .ttl = record.ttl,
            .rdata = try zone_parser.parseRData(record.rrtype, record.rdataText()),
        };
        if (answered) {
            try response.answers.append(wire_record);
        } else {
            try response.authorities.append(wire_record);
        }
    }
    response.header.answer_count = @intCast(response.answers.len);
    response.header.authority_count = @intCast(response.authorities.len);

    var parsed_query = try roundTrip(allocator, query);
    errdefer parsed_query.deinit();
    const parsed_response = try roundTrip(allocator, response);
    return .{ .query = parsed_query, .response = parsed_response };
}

/// A trust-anchor store holding one DNSKEY: the shape an operator writes for a
/// zone this server is the authority for.
fn dnskeyAnchor(allocator: std.mem.Allocator, owner_text: []const u8, dnskey_rdata: []const u8) !Anchors {
    var anchors = Anchors{};
    anchors.items[0] = .{
        .owner = try Name.fromText(owner_text),
        .rrtype = .DNSKEY,
        .rdata = try allocator.dupe(u8, dnskey_rdata),
    };
    anchors.len = 1;
    return anchors;
}

/// A DS for `dnskey_rdata`, so a test can exercise the RFC 4035 section 5.2
/// chain without reaching for a published parent. Digest type 2 is SHA-256.
fn dsAnchor(allocator: std.mem.Allocator, owner_text: []const u8, dnskey_rdata: []const u8, corrupt: bool) !Anchors {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update((try Name.fromText(owner_text)).asWire());
    hasher.update(dnskey_rdata);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    if (corrupt) digest[0] ^= 0xff;
    var rdata: [4 + std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u16, rdata[0..2], dnssec.keyTag(dnskey_rdata), .big);
    rdata[2] = dnskey_rdata[3];
    rdata[3] = 2;
    @memcpy(rdata[4..], &digest);
    var anchors = Anchors{};
    anchors.items[0] = .{
        .owner = try Name.fromText(owner_text),
        .rrtype = .DS,
        .rdata = try allocator.dupe(u8, &rdata),
    };
    anchors.len = 1;
    return anchors;
}

/// A DS for `dnskey_rdata` whose digest type this build cannot compute
/// (RFC 6840 section 5.2 names an unknown digest type a downgrade signal).
fn dsAnchorWithDigestType(allocator: std.mem.Allocator, owner_text: []const u8, dnskey_rdata: []const u8, digest_type: u8) !Anchors {
    var rdata: [4 + std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u16, rdata[0..2], dnssec.keyTag(dnskey_rdata), .big);
    rdata[2] = dnskey_rdata[3];
    rdata[3] = digest_type;
    @memset(rdata[4..], 0);
    var anchors = Anchors{};
    anchors.items[0] = .{
        .owner = try Name.fromText(owner_text),
        .rrtype = .DS,
        .rdata = try allocator.dupe(u8, &rdata),
    };
    anchors.len = 1;
    return anchors;
}

/// A DNSKEY RDATA (RFC 4034 section 2.1.1) with the given flags and
/// algorithm, carrying a key body no signature of this build made.
fn dnskeyRdata(flags: u16, algorithm: u8) [8]u8 {
    var rdata: [8]u8 = undefined;
    std.mem.writeInt(u16, rdata[0..2], flags, .big);
    rdata[2] = 3;
    rdata[3] = algorithm;
    @memset(rdata[4..], 0);
    return rdata;
}

/// Put `rdata` in place of every DNSKEY the response carried for the zone
/// apex, so a test can state the key material the zone publishes.
fn setApexDnskey(response: *dns_message.Message, rdata: []const u8) !void {
    var kept: usize = 0;
    for (response.authorities.items) |record| {
        if (record.rrtype.eql(.DNSKEY)) continue;
        response.authorities.items[kept] = record;
        kept += 1;
    }
    response.authorities.len = kept;
    try response.authorities.append(.{
        .owner = try Name.fromText("example.com."),
        .rrtype = .DNSKEY,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .Unknown = .{ .len = @intCast(rdata.len), .borrowed = rdata } },
    });
    response.header.authority_count = @intCast(response.authorities.len);
}

/// Reduce a response's Authority section to the denial proof an attacker can
/// lift from a public zone: the NSEC RRsets and the RRSIGs that cover them.
/// Everything else (the delegation NS, the SOA) is what a real server would
/// also send, and leaving it in would make the forged response below look
/// like a referral rather than the name error it claims to be.
fn keepNsecProofs(section: *dns_message.RecordSection) void {
    var kept: usize = 0;
    for (section.items[0..section.len]) |record| {
        const is_proof = record.rrtype.eql(.NSEC) or
            (record.rrtype.eql(.RRSIG) and rrsigCoversType(record, RecordType.NSEC));
        if (!is_proof) continue;
        // Copied by value first: `section.items` is one allocation, so writing
        // the kept record back in place would overwrite an entry the loop has
        // not reached yet.
        const copy = record;
        section.items[kept] = copy;
        kept += 1;
    }
    section.len = kept;
}

/// True when an RRSIG's Type Covered field is `expected`. A malformed RRSIG
/// covers nothing, so it is never a proof for anything.
fn rrsigCoversType(record: dns_record.ResourceRecord, expected: RecordType) bool {
    const raw = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return false,
    };
    const covered = dnssec.rrsigCovers(raw) catch return false;
    return covered == expected.code();
}

fn expectStatus(expected: Status, actual: Result) !void {
    try std.testing.expectEqual(expected, actual.status);
}

// ------------------------------------------------------------ positive path

test "a signed answer validates secure against a configured DNSKEY anchor" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "a DS anchor authenticates the child DNSKEY RRset and then the answer" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
}

test "a DS whose digest does not match the DNSKEY leaves the answer insecure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, true);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // Not bogus: RFC 4035 section 5.2 makes a DS that matches no DNSKEY an
    // absent authentication path, which is insecure, not a forged answer.
    try expectStatus(.insecure, try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds));
}

test "a DS anchor whose child publishes no DNSKEY is bogus with the DNSKEY Missing EDE (RFC 8914 4.10)" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    // The answer still carries the A RRset and its RRSIG, but the authority
    // section (and the answer) contain no DNSKEY RRset for the apex, mirroring
    // a forwarder that returns the answer alone: a DS anchor names the signer
    // and no matching key material is reachable.
    var empty_owners: [0][]const u8 = .{};
    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", empty_owners[0..]);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSKEY_MISSING, result.ede);
}

test "a DNSKEY RRset with only an unsupported algorithm leaves the answer insecure with the Unsupported DNSKEY Algorithm EDE (RFC 8914 4.2)" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);

    // The zone publishes one DNSKEY, whose algorithm this build cannot
    // verify with, and the DS at the parent names it.
    const key = dnskeyRdata(256, 8);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", &key, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();
    try setApexDnskey(&pair.response, &key);

    // RFC 4035 section 5.2: an unsupported algorithm leaves the zone with no
    // authentication path, so the answer is insecure and the client still
    // gets it -- not a SERVFAIL.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_DNSKEY_ALGORITHM, result.ede);
}

test "a DS whose digest type this build cannot compute leaves the answer insecure with the Unsupported DS Digest Type EDE (RFC 8914 4.3)" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);

    // Digest type 3 is not one this build computes, so the DS matches no
    // DNSKEY the zone publishes.
    var anchors = try dsAnchorWithDigestType(std.testing.allocator, "example.com.", signed.dnskey, 3);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The answer stays insecure rather than bogus, and the reason rides on
    // the answer the client still gets.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_DS_DIGEST_TYPE, result.ede);
}

test "a DNSKEY without the Zone Key flag leaves the answer insecure with the No Zone Key Bit Set EDE (RFC 8914 4.12)" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);

    // RFC 4034 section 2.1.1: a key without the Zone Key flag must not
    // verify an RRset, so the zone has no authentication path.
    const key = dnskeyRdata(0, 13);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", &key, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();
    try setApexDnskey(&pair.response, &key);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_NO_ZONE_KEY_BIT, result.ede);
}

test "a DS that matches no DNSKEY leaves the status indeterminate with the DNSSEC Indeterminate EDE (RFC 8914 4.6)" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);

    // The DS names a digest the zone's key does not produce, so no chain to
    // the zone exists and the security status cannot be determined.
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, true);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_INDETERMINATE, result.ede);
}

test "a chain that validates cleanly carries no EDE" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "a DNSKEY fetched out of band authenticates the answer as a DS chain does" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, p256_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    // A forwarder only sees the answer, so the apex DNSKEY RRset and its
    // signature come from a second upstream query rather than the response.
    const apex_owners = [_][]const u8{"example.com."};
    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", &apex_owners);
    defer pair.query.deinit();
    defer pair.response.deinit();

    var apex = try exchange(std.testing.allocator, &signed.zone, "example.com.", .DNSKEY, .no_error, "example.com.", &apex_owners);
    defer apex.query.deinit();
    defer apex.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, apex.response.answers.slice(), now_seconds);
    try expectStatus(.secure, result);
}

// ------------------------------------------------------------- negative path

test "a one-octet change to a signed answer is bogus, not secure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    for (pair.response.answers.items[0..pair.response.answers.len]) |*record| {
        if (!record.rrtype.eql(.A)) continue;
        record.rdata.A[3] ^= 0xff;
    }
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "a signature past its expiration is bogus with the expired EDE" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, window.expiration + 1);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_SIGNATURE_EXPIRED, result.ede);
}

test "a signature before its inception is bogus with the not-yet-valid EDE" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, window.inception - 1);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_SIGNATURE_NOT_YET_VALID, result.ede);
}

test "an unsigned answer is insecure outside the trust domain and bogus inside it" {
    var zone_file = try zone_parser.ZoneFile.parse(child_zone_text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var empty = try dnskeyAnchor(std.testing.allocator, "other.test.", "unused");
    defer empty.deinit(std.testing.allocator);
    var matching = try dnskeyAnchor(std.testing.allocator, "example.com.", "unused");
    defer matching.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // No anchor reaches www.example.com., so unsigned data is honestly insecure.
    try expectStatus(.insecure, try validate(std.testing.allocator, &empty, pair.query, pair.response, &.{}, now_seconds));
    // An anchor does reach it, so the same bytes are now a missing signature.
    const result = try validate(std.testing.allocator, &matching, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_RRSIGS_MISSING, result.ede);
}

// -------------------------------------------------- RFC 6840 ancestor NSEC

test "RFC 6840 section 4.1: a parent delegation NSEC cannot prove a name below the cut" {
    var signed = try signZoneText(std.testing.allocator, parent_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    // The attacker owns nothing. Every byte below is copied verbatim from the
    // public parent zone: the NSEC the parent publishes at its delegation to
    // example.com. (NS set, SOA clear, signer `com.` one label shorter than
    // the owner) and the RRSIG the parent made over it. That is the whole
    // attack, and every byte verifies against the parent's key.
    var pair = try exchange(std.testing.allocator, &signed.zone, "foo.example.com.", .A, .nxdomain, "nothing.example.com.", &.{"example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();
    keepNsecProofs(&pair.response.authorities);

    // The record is authentic and the parent that signed it is anchored, so
    // every other check passes. Only RFC 6840 section 4.1 stands between this
    // response and a forged NXDOMAIN for a name in the child zone: an ancestor
    // delegation NSEC "MUST NOT be used to prove the nonexistence of all RRs
    // at that owner name" or of anything below the cut.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

// ------------------------------------------------------------------- NSEC3

/// RFC 5155 Appendix A's NSEC3 parameters: SHA-1, salt `aabbccdd`, 12
/// iterations. Every hash label below is the RFC's own published value, so a
/// test that fails here is a disagreement with the RFC and not with itself.
const nsec3_salt = "\xaa\xbb\xcc\xdd";
const nsec3_iterations: u16 = 12;
const h_example = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
const h_ns1 = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
const h_ns2 = "q04jkcevqvmu85r014c7dkba38o0ji5r";
const h_w = "k8udemvp1j2f7eg6jebps17vp3n8i58h";

/// RFC 4034 section 4.1.2 type bitmap over a fixed list of type codes. Every
/// code these tests use is below 256, so one window covers them all.
/// The apex bitmap carries NS alongside SOA, which is what distinguishes a
/// real owner from a delegation (RFC 5155 section 8.9): the pairing matters,
/// not just the presence of the bit.
fn typeBitmap(codes: []const RecordType) [2 + 32]u8 {
    var bitmap = @as([(2 + 32)]u8, @splat(@as(u8, 0)));
    bitmap[0] = 0;
    bitmap[1] = 32;
    for (codes) |code| {
        const value = code.code();
        const bit = value % 256;
        if (bit / 8 >= 32) continue;
        bitmap[2 + bit / 8] |= @as(u8, 0x80) >> @as(u3, @intCast(bit % 8));
    }
    return bitmap;
}

/// NSEC3 RDATA (RFC 5155 section 3): hash algorithm, flags, iterations, salt,
/// next hashed owner name, and the type bitmap. `next_label` is the RFC 4648
/// section 7 base32hex form the published vectors use.
fn nsec3Rdata(next_label: []const u8, flags: u8, bitmap: []const u8) dns_rdata.Unknown {
    var next: [20]u8 = undefined;
    std.debug.assert(base32hexLabel(next_label, &next));
    var raw = dns_rdata.Unknown{};
    raw.data[0] = 1; // SHA-1 (RFC 5155 section 3)
    raw.data[1] = flags;
    std.mem.writeInt(u16, raw.data[2..4], nsec3_iterations, .big);
    raw.data[4] = @intCast(nsec3_salt.len);
    @memcpy(raw.data[5..][0..nsec3_salt.len], nsec3_salt);
    raw.data[5 + nsec3_salt.len] = 20;
    @memcpy(raw.data[6 + nsec3_salt.len ..][0..20], &next);
    const at = 26 + nsec3_salt.len;
    @memcpy(raw.data[at..][0..bitmap.len], bitmap);
    raw.len = @intCast(at + bitmap.len);
    return raw;
}

/// One NSEC3 RRset signed by the zone key: the record plus the RRSIG over it
/// (`signZone` refuses a zone that already carries DNSSEC records, and a zone
/// file cannot publish an NSEC3 chain this signer did not generate).
fn signedNsec3(
    allocator: std.mem.Allocator,
    key: *const zone_signer.Key,
    hash_label: []const u8,
    rdata: dns_rdata.Unknown,
    ttl: u32,
) ![2]dns_record.ResourceRecord {
    var owner_text: [64]u8 = undefined;
    const owner = try Name.fromText(try std.fmt.bufPrint(&owner_text, "{s}.example.", .{hash_label}));
    const signer = try Name.fromText("example.");
    const bytes = rdata.data[0..rdata.len];
    const rdata_list = [_][]const u8{bytes};
    const rrsig_rdata = try zone_signer.signRrset(allocator, owner, signer, RecordType.NSEC3.code(), &rdata_list, ttl, key, window);
    defer allocator.free(rrsig_rdata);
    var signature = dns_rdata.Unknown{};
    @memcpy(signature.data[0..rrsig_rdata.len], rrsig_rdata);
    signature.len = @intCast(rrsig_rdata.len);
    return .{
        .{
            .owner = owner,
            .rrtype = .NSEC3,
            .class = .IN,
            .ttl = ttl,
            .rdata = .{ .Unknown = rdata },
        },
        .{
            .owner = owner,
            .rrtype = .RRSIG,
            .class = .IN,
            .ttl = ttl,
            .rdata = .{ .Unknown = signature },
        },
    };
}

/// A negative response whose Authority section holds exactly the NSEC3
/// RRsets a test names, in order. RFC 4035 section 5.4 admits only the
/// RRsets the response carried, so an NSEC3 record whose RRSIG is missing must
/// not be able to borrow one from elsewhere.
fn nsec3Exchange(
    allocator: std.mem.Allocator,
    key: *const zone_signer.Key,
    qname: []const u8,
    qtype: RecordType,
    rcode: dns_header.Rcode,
    labels: []const []const u8,
    flags: []const u8,
    next_labels: []const []const u8,
    bitmaps: []const []const u8,
) !Exchange {
    const question = dns_question.Question{ .name = try Name.fromText(qname), .qtype = qtype, .qclass = .IN };
    var query = try emptyMessage(allocator, .{ .id = 0x1234, .recursion_desired = true, .question_count = 1 }, question);
    defer query.deinit();
    var response = try emptyMessage(allocator, .{
        .id = 0x1234,
        .qr = true,
        .recursion_desired = true,
        .recursion_available = true,
        .question_count = 1,
        .rcode = rcode,
    }, question);
    defer response.deinit();

    for (labels, 0..) |label, index| {
        const pair = try signedNsec3(allocator, key, label, nsec3Rdata(next_labels[index], flags[index], bitmaps[index]), 3600);
        try response.authorities.append(pair[0]);
        try response.authorities.append(pair[1]);
    }
    response.header.authority_count = @intCast(response.authorities.len);

    var parsed_query = try roundTrip(allocator, query);
    errdefer parsed_query.deinit();
    const parsed_response = try roundTrip(allocator, response);
    return .{ .query = parsed_query, .response = parsed_response };
}

test "RFC 5155 section 8.4: a closest-encloser proof is required, not just a covering NSEC3" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The apex NSEC3 matches `example.`, so it is the closest encloser. The
    // zero-hash record spans the whole hash space except the zero hash itself,
    // so it covers both the next closer `w.example.` and the wildcard
    // `*.example.` the section 8.4 proof needs.
    const apex_bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC3, .DNSKEY });
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const zero_hash = "00000000000000000000000000000000";
    const max_hash = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";

    // Control: apex plus the covering record is a complete proof, so it must
    // validate as one. Without this, a negative test below would pass for the
    // wrong reason (a validator that rejects everything). The chain of this
    // exchange carries the iteration count of RFC 5155 Appendix A, which is
    // above 0, so RFC 9276 section 3.2 leaves the answer insecure.
    const complete = [_][]const u8{ h_example, zero_hash };
    const two_flags = [_]u8{ 0, 0 };
    const two_next = [_][]const u8{ h_ns1, max_hash };
    const two_bitmaps = [_][]const u8{ &apex_bitmap, &covering_bitmap };
    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &complete, &two_flags, &two_next, &two_bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();
    try expectStatus(.insecure, try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds));

    // Drop the apex NSEC3 and keep only the covering record. That is exactly
    // the section 8.4 attack: a span that covers the name but shows no
    // encloser, so an attacker could deny any name at all. RFC 5155 section
    // 8.4 requires a closest encloser proof, so this must be bogus.
    const one = [_][]const u8{zero_hash};
    const one_flag = [_]u8{0};
    const one_next = [_][]const u8{max_hash};
    const one_bitmap = [_][]const u8{&covering_bitmap};
    var incomplete = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &one, &one_flag, &one_next, &one_bitmap);
    defer incomplete.query.deinit();
    defer incomplete.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, incomplete.query, incomplete.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "RFC 9276 section 3.2: an answer proven by an NSEC3 chain with an iteration count above 0 is insecure" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The chain of this exchange is the one RFC 5155 Appendix A publishes:
    // 12 iterations, above the count of 0 RFC 9276 section 3.1 asks a
    // publisher to use. The proof itself is complete, so the answer is not
    // bogus, but it is not secure either: a validator that processes NSEC3
    // records with an iteration count above 0 treats the zone as insecure and
    // says so with the EDE the RFC assigns to that answer.
    const apex_bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC3, .DNSKEY });
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const labels = [_][]const u8{ h_example, "00000000000000000000000000000000" };
    const flags = [_]u8{ 0, 0 };
    const next_labels = [_][]const u8{ h_ns1, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" };
    const bitmaps = [_][]const u8{ &apex_bitmap, &covering_bitmap };
    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &labels, &flags, &next_labels, &bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS, result.ede);
}

test "RFC 5155 section 8.6: a DS NODATA needs the Opt-Out bit or it is bogus" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    const apex_bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC3, .DNSKEY });
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const zero_hash = "00000000000000000000000000000000";
    const max_hash = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";
    const labels = [_][]const u8{ h_example, zero_hash };
    const next_labels = [_][]const u8{ h_ns1, max_hash };
    const bitmaps = [_][]const u8{ &apex_bitmap, &covering_bitmap };

    // A DS query at `ns2.example.` with no matching NSEC3: section 8.6 falls
    // back to a closest-encloser proof whose covering record carries Opt-Out.
    // That proves the unsigned delegation and nothing below the cut, which is
    // `insecure` and must not set AD (RFC 5155 section 9.2).
    const opt_out_flags = [_]u8{ 0, 1 };
    var opted_out = try nsec3Exchange(std.testing.allocator, &key, "ns2.example.", .DS, .no_error, &labels, &opt_out_flags, &next_labels, &bitmaps);
    defer opted_out.query.deinit();
    defer opted_out.response.deinit();
    try expectStatus(.insecure, try validate(std.testing.allocator, &anchors, opted_out.query, opted_out.response, &.{}, now_seconds));

    // Clear the bit and the very same records stop proving anything. Without
    // Opt-Out the zone is saying the span is closed, so a delegation inside it
    // that carries no DS is a lie rather than a declared gap.
    const closed_flags = [_]u8{ 0, 0 };
    var closed = try nsec3Exchange(std.testing.allocator, &key, "ns2.example.", .DS, .no_error, &labels, &closed_flags, &next_labels, &bitmaps);
    defer closed.query.deinit();
    defer closed.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, closed.query, closed.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

// ------------------------------------------------------------ anchor file

test "RFC 1035 2.3.2: a trust anchor covers a name that arrived in upper case" {
    var anchors = try Anchors.parse(std.testing.allocator,
        \\example.com. 3600 IN DS 35217 15 2 401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c
        \\
    );
    defer anchors.deinit(std.testing.allocator);

    const mixed = (try Name.parsePreservingCase(
        &.{ 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0 },
        0,
    )).name;
    try std.testing.expect(anchors.covers(mixed));

    var tags: [2]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), anchors.keyTags(mixed, &tags));
    try std.testing.expectEqual(@as(u16, 35217), std.mem.readInt(u16, tags[0..2], .big));
}

test "the anchor file takes DS and DNSKEY lines and rejects every other shape" {
    // RFC 8080 section 6.1's published Ed25519 DNSKEY and its SHA-256 DS, so
    // the parser is exercised on the same records the signer tests use.
    var anchors = try Anchors.parse(std.testing.allocator,
        \\# A comment, then a DS and a DNSKEY.
        \\example.com. 3600 IN DS 35217 15 2 401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c
        \\. IN DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
        \\
    );
    defer anchors.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), anchors.len);
    try std.testing.expect(anchors.items[0].rrtype.eql(.DS));
    try std.testing.expectEqual(@as(u16, 35217), std.mem.readInt(u16, anchors.items[0].rdata[0..2], .big));
    try std.testing.expectEqual(@as(usize, 4 + 32), anchors.items[0].rdata.len);
    try std.testing.expect(anchors.items[1].rrtype.eql(.DNSKEY));
    try std.testing.expect(anchors.covers(try Name.fromText("www.example.com.")));
    // The root anchor covers everything, so the DS-only line is what reaches
    // example.com. and the root DNSKEY alone would not.
    try std.testing.expect(!std.mem.eql(u8, anchors.items[0].owner.asWire(), anchors.items[1].owner.asWire()));

    // RFC 4034 section 2.1.2 fixes the DNSKEY protocol at 3.
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. DNSKEY 257 4 15 AAAA\n"));
    // A line that is not a DS or a DNSKEY, an odd-length digest, a trailing
    // token, a truncated record, and a digest longer than SHA-384. A short but
    // well-formed digest is deliberately NOT one of these: it simply fails to
    // match any DNSKEY, which is an insecure answer rather than a bad file.
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. A 192.0.2.1\n"));
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. DS 1 15 2 aabbc\n"));
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. DS 1 15 2 aabb extra\n"));
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. DNSKEY 257 3\n"));
    try std.testing.expectError(Error.BadAnchorFile, Anchors.parse(std.testing.allocator, "example. DS 1 15 2 " ++ "ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab" ++ "\n"));
}

test "the anchor file is bounded and an empty file is an empty store" {
    var empty = try Anchors.parse(std.testing.allocator, "# nothing here\n\n");
    defer empty.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try std.testing.expect(!empty.covers(try Name.fromText("www.example.com.")));

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(std.testing.allocator);
    for (0..max_anchors + 1) |index| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "z{0}. DS 1 15 2 aabbccdd\n", .{index});
        defer std.testing.allocator.free(line);
        try text.appendSlice(std.testing.allocator, line);
    }
    try std.testing.expectError(Error.TooManyAnchors, Anchors.parse(std.testing.allocator, text.items));
}

/// A zone with an apex ZONEMD, so the RFC 8976 section 4 step 3 chain over
/// the SOA and the ZONEMD RRsets can be checked. The digest is a placeholder:
/// that chain is about the signatures, not about the digest.
const zonemd_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\@ IN ZONEMD 1 1 1 0000000000000000000000000000000000000000000000000000000000000000
    \\ns1 IN A 192.0.2.1
;

/// The RRsets RFC 8976 section 4 step 3 names: the SOA and the ZONEMD.
const zonemd_chain_types = [_]u16{ RecordType.SOA.code(), RecordType.ZONEMD.code() };

/// The trust anchor an operator writes for a zone's own key: the DNSKEY in
/// the anchor file's presentation form (RFC 4034 section 5.1.1).
fn dnskeyAnchorText(allocator: std.mem.Allocator, owner: []const u8, dnskey_rdata: []const u8) ![]u8 {
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(dnskey_rdata.len - 4));
    _ = std.base64.standard.Encoder.encode(encoded, dnskey_rdata[4..]);
    return std.fmt.allocPrint(allocator, "{s} DNSKEY {d} 3 {d} {s}\n", .{
        owner,
        std.mem.readInt(u16, dnskey_rdata[0..2], .big),
        dnskey_rdata[3],
        encoded,
    });
}

test "RFC 8976 section 4 step 3: the apex SOA and ZONEMD RRsets chain to a DNSKEY anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    try std.testing.expect(try zoneSignedToAnchor(allocator, &anchors, &signed.zone, &zonemd_chain_types, now_seconds));
}

test "RFC 8976 section 4 step 3: a DS anchor reaches the zone's own DNSKEY RRset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    // The RFC 8080 section 6.1 DS for the Ed25519 key the zone is signed
    // with: the chain runs through the zone's DNSKEY RRset and the signature
    // that RRset carries.
    var anchors = try Anchors.parse(allocator,
        \\example.com. DS 35217 15 2 401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c
        \\
    );
    defer anchors.deinit(allocator);

    try std.testing.expect(try zoneSignedToAnchor(allocator, &anchors, &signed.zone, &zonemd_chain_types, now_seconds));
}

test "RFC 8976 section 4 step 3: a zone signed by another key does not chain to the anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    // The anchor holds the RFC 6605 section 6.1 P-256 key, and the zone is
    // signed with the Ed25519 one: no signature over the apex RRsets can be
    // made by the anchored key.
    var other = try zone_signer.parseKey(p256_secret);
    defer other.deinit();
    const other_dnskey = try other.dnskeyRdata(allocator);
    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", other_dnskey));
    defer anchors.deinit(allocator);

    try std.testing.expect(!try zoneSignedToAnchor(allocator, &anchors, &signed.zone, &zonemd_chain_types, now_seconds));
}

test "RFC 8976 section 4 step 3: an unsigned zone does not chain to the anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var zone_file = try zone_parser.ZoneFile.parse(zonemd_zone_text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var anchors = try Anchors.parse(allocator,
        \\example.com. DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
        \\
    );
    defer anchors.deinit(allocator);

    try std.testing.expect(!try zoneSignedToAnchor(allocator, &anchors, &zone, &zonemd_chain_types, now_seconds));
}

test "RFC 8976 section 4 step 1: a zone no anchor names is not checked" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    // An anchor for a zone above says nothing about this one: a delegation
    // without a DS is insecure, and the parent's side of that chain is not
    // reachable from a zone file.
    var anchors = try Anchors.parse(allocator,
        \\. DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
        \\
    );
    defer anchors.deinit(allocator);

    try std.testing.expect(try zoneSignedToAnchor(allocator, &anchors, &signed.zone, &zonemd_chain_types, now_seconds));
}

/// The apex RRSIGs of a signed zone in the RFC 4034 section 3.2 presentation
/// form, so a zone file that carries the publisher's own signatures can be
/// loaded and checked the way a zone this server signed is.
fn rrsigPresentationLines(allocator: std.mem.Allocator, zone: *const zone_index.Zone) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return error.TestUnexpectedResult,
        };
        const parsed = try Name.parse(bytes, 18);
        var signer_buffer: [256]u8 = undefined;
        const signer = try parsed.name.toText(&signer_buffer);
        const signature = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len - parsed.next_offset));
        _ = std.base64.standard.Encoder.encode(signature, bytes[parsed.next_offset..]);
        // RFC 4034 section 3.2 lets an unknown type mnemonic be written as
        // TYPE followed by its number, which is what the zone parser reads.
        try out.print(allocator, "@ IN RRSIG TYPE{d} {d} {d} {d} {d} {d} {d} {s} {s}\n", .{
            std.mem.readInt(u16, bytes[0..2], .big),
            bytes[2],
            bytes[3],
            std.mem.readInt(u32, bytes[4..8], .big),
            std.mem.readInt(u32, bytes[8..12], .big),
            std.mem.readInt(u32, bytes[12..16], .big),
            std.mem.readInt(u16, bytes[16..18], .big),
            signer,
            signature,
        });
    }
    return out.toOwnedSlice(allocator);
}

test "RFC 8976 section 4 step 3: a zone file carrying the publisher's own signatures chains to the anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    // The zone file the publisher would ship: the same zone with its
    // signatures in the RFC 4034 section 3.2 presentation form.
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(allocator, zonemd_zone_text);
    try text.append(allocator, '\n');
    try text.appendSlice(allocator, try rrsigPresentationLines(allocator, &signed.zone));

    var zone_file = try zone_parser.ZoneFile.parse(text.items);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    try std.testing.expect(try zoneSignedToAnchor(allocator, &anchors, &zone, &zonemd_chain_types, now_seconds));
}

/// A zone that publishes no ZONEMD record, so the absence of the RRset is
/// what RFC 8976 section 4 step 2 has to resolve.
const zonemd_absent_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
;

/// The same zone with an apex NSEC3PARAM, which is the opt-in that makes the
/// signer publish an NSEC3 chain instead of an NSEC chain (RFC 5155
/// section 4).
const nsec3_zonemd_absent_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\@ IN NSEC3PARAM 1 0 0 73616c74
    \\ns1 IN A 192.0.2.1
;

test "RFC 8976 section 4 step 2: the zone's own NSEC proves the apex ZONEMD RRset does not exist" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_absent_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    // The NSEC the signer writes at the apex denies the ZONEMD type, so the
    // absence is proven and the zone publishes no ZONEMD.
    try std.testing.expectEqual(
        ZonemdAbsence.proven,
        try zoneZonemdAbsence(allocator, &anchors, &signed.zone, now_seconds),
    );
}

test "RFC 8976 section 4 step 2: the zone's own NSEC3 proves the apex ZONEMD RRset does not exist" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, nsec3_zonemd_absent_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    // The NSEC3 whose owner hash matches the apex denies the ZONEMD type, so
    // the absence is proven the same way the NSEC chain proves it.
    try std.testing.expectEqual(
        ZonemdAbsence.proven,
        try zoneZonemdAbsence(allocator, &anchors, &signed.zone, now_seconds),
    );
}

/// The same zone with a second apex NSEC3PARAM, as a rollover carries, so
/// the zone states two sets of parameters and cannot say which chain it
/// publishes.
const nsec3_rollover_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\@ IN NSEC3PARAM 1 0 0 73616c74
    \\@ IN NSEC3PARAM 1 0 0 aabbccdd
    \\ns1 IN A 192.0.2.1
;

test "RFC 5155 section 7.1: a zone with a second apex NSEC3PARAM leaves the absence unproven" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, nsec3_rollover_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    // Two apex NSEC3PARAM records leave the chain unproven, so the absence
    // of the ZONEMD RRset cannot be shown and the caller fails closed.
    try std.testing.expectEqual(
        ZonemdAbsence.unknown,
        try zoneZonemdAbsence(allocator, &anchors, &signed.zone, now_seconds),
    );
}

test "RFC 8976 section 4 step 2: a zone that holds no proof leaves the absence unknown" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_absent_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    var anchors = try Anchors.parse(allocator, try dnskeyAnchorText(allocator, "example.com.", signed.dnskey));
    defer anchors.deinit(allocator);

    // The same zone without the records the signer adds: the anchor names the
    // zone, so DNSSEC records are expected, but nothing proves the absence.
    var zone_file = try zone_parser.ZoneFile.parse(zonemd_absent_zone_text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    try std.testing.expectEqual(
        ZonemdAbsence.unknown,
        try zoneZonemdAbsence(allocator, &anchors, &zone, now_seconds),
    );
}

test "RFC 8976 section 4 step 2: a zone no anchor names needs no proof of the absence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var signed = try signZoneText(allocator, zonemd_absent_zone_text, ed25519_secret);
    defer signed.deinit(allocator);

    // An anchor for a zone above says nothing about this one, so RFC 8976
    // section 4 step 1 does not expect DNSSEC records here.
    var anchors = try Anchors.parse(allocator,
        \\. DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
        \\
    );
    defer anchors.deinit(allocator);

    try std.testing.expectEqual(
        ZonemdAbsence.not_expected,
        try zoneZonemdAbsence(allocator, &anchors, &signed.zone, now_seconds),
    );
}
