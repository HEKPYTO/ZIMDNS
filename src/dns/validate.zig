/// Contract: Validates one DNSSEC response against a static trust-anchor store:
/// a DS or DNSKEY anchor authenticates a child apex DNSKEY RRset
/// (RFC 4035 section 5.2), that key authenticates every signed RRset, and a
/// negative answer is checked against the RFC 6840 sections 4.1, 4.3 and 4.4
/// spoof rules and the RFC 5155 section 8 NSEC3 proofs.
/// What this module does: DS and DNSKEY anchors, RFC 4034 section 6 canonical
/// signed-data assembly, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/P-384, and
/// Ed25519 verification, the
/// RFC 5011 section 3 REVOKE bit that keeps a revoked key out of the trusted
/// set, NSEC NXDOMAIN and NODATA proofs, NSEC3 closest-encloser and opt-out
/// proofs, and the secure/insecure/bogus outcome with an RFC 8914 INFO-CODE
/// for a bogus answer and for an answer the server returns without a signed
/// verification.
/// The NSEC3 RDATA decoder and the hash span test are shared with the
/// authoritative path, which picks the NSEC3 denial proofs a zone serves.
/// `zoneSignedToAnchor` answers the same question for a loaded zone: do the
/// RRsets named at its apex carry valid signatures chaining up to a
/// configured anchor (RFC 8976 section 4 step 3).
/// What this module does NOT do: iterative resolution, chasing a delegation
/// chain across several zones, the RFC 5011 anchor rollover beyond the REVOKE
/// bit, NSEC3 generation, RSA/SHA-1 (5 and 7, which RFC 8624 section 3.1
/// says a validator SHOULD NOT use), and Ed448, for which the standard
/// library carries no primitive.
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
/// RFC 5155 section 10.3: the most iterations this validator will hash.
const max_nsec3_iterations: u16 = 150;
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

/// The octets the RRSIG RDATA holds before the Signer's Name (RFC 4034
/// section 3.1): type covered, algorithm, labels, original TTL, expiration,
/// inception, and key tag.
const rrsig_fixed_len = 18;

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
    /// Length of the RRSIG RDATA with the Signature field excluded: the RRSIG
    /// prefix that opens RFC 4035 section 5.3.1's signed data, followed by the
    /// Signer's Name. Only the tests that rebuild a signature over the
    /// published octets read it.
    header_len: usize,

    fn at(raw: []const u8, owner: Name) Error!Rrsig {
        if (raw.len < rrsig_fixed_len) return Error.MalformedRrsig;
        const parsed = Name.parse(raw, rrsig_fixed_len) catch return Error.MalformedRrsig;
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

/// RFC 4034 section 3.1.3: the Labels field of an RRSIG does not count the
/// wildcard label, so "*.example.com." has a Labels field of 2. The label
/// counts an RRSIG is compared by are that one.
fn labelsCount(wire: []const u8) u8 {
    var count = labelCount(wire);
    if (count != 0 and wire[0] == 1 and wire[1] == '*') count -= 1;
    return count;
}

/// Parent name with the leftmost label stripped; null at the root.
/// True when `ancestor` is a strict ancestor of `name`.
fn isStrictAncestor(ancestor: *const Name, name: *const Name) bool {
    const parent = ancestor.asWire();
    const child = name.asWire();
    if (parent.len >= child.len) return false;
    return std.mem.eql(u8, child[child.len - parent.len ..], parent);
}

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
/// opaque RDATA re-encodes to the octets it arrived as with the names it
/// holds folded to lowercase (RFC 4034 section 6.2 rule 3), and RFC 3597
/// forbids compression inside a type this build does not model. The rule
/// itself lives in `dnssec`, so the signer signs what the validator verifies.
fn encodeRdata(allocator: std.mem.Allocator, rrtype: u16, rdata: dns_rdata.RData) Error![]const u8 {
    var buffer: [dns_rdata.max_unknown_len]u8 = undefined;
    var writer = dns_writer.Writer.init(&buffer);
    rdata.encode(&writer) catch return Error.MalformedRdata;
    return dnssec.canonicalRdata(allocator, rrtype, writer.written()) catch return Error.OutOfMemory;
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
    // RFC 4035 section 5.3.2: the RRSIG RDATA opens the signed data with
    // the Signer's Name in canonical form.
    try out.appendSlice(allocator, rrsig.raw[0..rrsig_fixed_len]);
    try out.appendSlice(allocator, rrsig.signer.asWire());
    const owner = try signedOwner(allocator, &rrsig.owner, rrsig.labels);

    const entries = try allocator.alloc(CanonicalRr, records.len);
    var unique: usize = 0;
    for (records, 0..) |record, index| {
        const rdata = try encodeRdata(allocator, record.rrtype.code(), record.rdata);
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

/// The DNSSEC algorithms this build verifies: 8 and 10 (RFC 5702), 13 and 14
/// (RFC 6605), and 15 (RFC 8080). A DNSKEY RRset of any other algorithm is
/// the case RFC 8914 section 4.2 names; a DS RRset of them is the case
/// RFC 4035 section 5.2 names. Either way the zone has no supported
/// authentication path. RSA/SHA-1 (5 and 7) is not here: RFC 8624 section 3.1
/// says a signer MUST NOT use it and a validator SHOULD NOT, and this build
/// treats it as unsupported rather than insecure-by-silence.
fn algorithmSupported(number: u8) bool {
    return switch (number) {
        8, 10, 13, 14, 15 => true,
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

/// The revoked-key policy of this validator, in one place.
/// RFC 5011 section 2.1: "Once the resolver sees the REVOKE bit, it MUST NOT
/// use this key as a trust anchor." Section 3 says when the resolver sees it:
/// the bit counts only "AND the resolver sees an RRSIG(DNSKEY) signed by the
/// associated key", so the signature the key made over the DNSKEY RRset is
/// what proves a revocation and the bit alone proves nothing.
/// The proof depends on where the key comes from:
/// - A key the zone published in its own DNSKEY RRset: the proof is the
///   RRSIG that key made over that RRset, which `selfRevoked` looks for.
/// - A configured DNSKEY anchor: the anchor file holds no RRset and so has
///   no signature to see. The operator's file is the proof there, and an
///   operator who writes a revoked key into the anchor file has revoked it.
/// RFC 5011 section 3: bit 8 of the DNSKEY Flags field is the REVOKE flag.
/// The flags are a 16-bit field, so bit 8 is the high bit of the second
/// octet (0x0080).
fn revokedKey(raw: []const u8) bool {
    return raw.len >= 4 and (raw[1] & 0x80) != 0;
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
        8 => try verifyRsa(key, rrsig.signature, data, std.crypto.hash.sha2.Sha256),
        10 => try verifyRsa(key, rrsig.signature, data, std.crypto.hash.sha2.Sha512),
        13 => try verifyEcdsa(EcdsaP256Sha256, key, rrsig.signature, data),
        14 => try verifyEcdsa(EcdsaP384Sha384, key, rrsig.signature, data),
        15 => try verifyEd25519(key, rrsig.signature, data),
        // RFC 4035 section 5.2: an unsupported algorithm leaves the zone with
        // no authentication path, which the caller reports as insecure.
        else => return Error.UnsupportedAlgorithm,
    }
}

/// RFC 3110 section 2: the DNSKEY public key of an RSA key, one-octet or
/// three-octet exponent length, exponent, modulus.
fn rsaPublicKeyParts(key: []const u8) ?struct { exponent: []const u8, modulus: []const u8 } {
    if (key.len < 3) return null;
    var exponent_len: usize = key[0];
    var offset: usize = 1;
    if (exponent_len == 0) {
        exponent_len = std.mem.readInt(u16, key[1..3], .big);
        offset = 3;
    }
    if (exponent_len == 0 or offset + exponent_len >= key.len) return null;
    return .{ .exponent = key[offset..][0..exponent_len], .modulus = key[offset + exponent_len ..] };
}

/// RFC 5702 section 3: RSASSA-PKCS1-v1_5 over the RRSIG RDATA and the
/// canonical RRset, with the hash the algorithm names.
fn verifyRsa(key: []const u8, signature: []const u8, data: []const u8, comptime Hash: type) Error!void {
    const parts = rsaPublicKeyParts(key) orelse return Error.MalformedDnskey;
    const modulus_len = parts.modulus.len;
    // RFC 5702 sections 2.1 and 2.2: 512 bits is the floor for SHA-256 and
    // 1024 bits for SHA-512; 4096 bits is the ceiling for both.
    const min_modulus: usize = if (Hash == std.crypto.hash.sha2.Sha512) 128 else 64;
    if (modulus_len < min_modulus or modulus_len > 512) return Error.UnsupportedAlgorithm;
    if (signature.len != modulus_len) return Error.SignatureInvalid;
    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch
        return Error.MalformedDnskey;
    // The verifier's modulus length is comptime, so the standard key sizes are
    // the sizes this build accepts (512 to 4096 bits in 8-bit steps).
    const modulus_sizes = .{ 64, 96, 128, 160, 192, 224, 256, 320, 384, 448, 512 };
    inline for (modulus_sizes) |len| {
        // RFC 8017 section 9.2 needs k >= tLen + 11; a smaller field would
        // underflow inside the standard verifier at compile time.
        if (comptime len >= Hash.digest_length + 30) {
            if (modulus_len == len) {
                const sig: *const [len]u8 = @ptrCast(signature.ptr);
                std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(len, sig, data, public_key, Hash) catch
                    return Error.SignatureInvalid;
                return;
            }
        }
    }
    return Error.UnsupportedAlgorithm;
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
///
/// RFC 4034 section 3.1.3: the Labels field does not count the wildcard label,
/// so the zone's own record at "*.example.com." is signed with a Labels field
/// of 2. A record that came from a deeper wildcard claims fewer labels still,
/// so it is not the zone's own record at the wildcard's name.
fn deniesWildcard(labels: u8, owner: Name) bool {
    return labels == labelsCount(owner.asWire());
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
    /// The denial used this record, so RFC 4035 section 5.4 asks for its
    /// signature to be verified. A record the response carries beside the
    /// proof is not judged.
    used: bool = false,
};

/// An NSEC3 denial proof. `owner_labels` is the label count of the name the
/// NSEC3 was generated for, which RFC 4034 section 3.1.3 puts in the covering
/// RRSIG's Labels field: the owner name is the hash label in front of the
/// signing zone, and RFC 6840 section 4.1 compares the signer against that
/// original name rather than against the hashed owner.
const Nsec3 = struct {
    owner: Name,
    owner_hash: [20]u8,
    next_hash: [20]u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    bitmap: []const u8,
    signer: Name,
    owner_labels: u8,
    /// The denial used this record, so RFC 4035 section 5.4 asks for its
    /// signature to be verified. A record the response carries beside the
    /// proof is not judged.
    used: bool = false,
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
            // RFC 4035 section 5.4: the RRsets that make up a denial proof
            // must themselves be authenticated, so a proof is collected as an
            // RRset as well, and the denial path checks the signature over
            // it with the signer's trusted key set.
            if (record.rrtype.eql(.NSEC)) try self.addNsec(record, bytes);
            if (record.rrtype.eql(.NSEC3)) try self.addNsec3(record, bytes);
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
            .owner = record.owner,
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
    /// matched and which carries the Zone flag. An authenticated RRset lends
    /// its other zone keys to the set (RFC 6781 section 3.1). An empty result
    /// means no configured anchor reaches this zone: the RRset is insecure,
    /// not bogus.
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
            // RFC 5011 section 2.1: "Once the resolver sees the REVOKE bit, it
            // MUST NOT use this key as a trust anchor". The anchor file holds
            // no RRset and so no self-signature to see, and the operator's
            // file is the proof there: an operator who writes a revoked key
            // into the anchor file has revoked it.
            if (revokedKey(anchor.rdata)) continue;
            try keys.append(self.allocator, anchor.rdata);
        }
        if (keys.items.len == 0) try self.keysFromDs(&keys, signer);
        if (keys.items.len == 0) try self.keysFromParentDs(&keys, signer);
        // RFC 4035 section 5.2: the anchor key authenticates the apex DNSKEY
        // RRset, and every zone key in that authenticated set is then
        // trusted. A KSK anchor and a ZSK signature are the normal pairing,
        // so the DNSKEY RRset, when the caller supplied it, adds its keys.
        if (keys.items.len != 0) try self.adoptZoneKeys(&keys, signer);
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
                const raw = encodeRdata(self.allocator, record.rrtype.code(), record.rdata) catch continue;
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
                    const raw = try encodeRdata(self.allocator, record.rrtype.code(), record.rdata);
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
        try self.confirmDsMatchedKeys(keys, signer);
    }

    /// Adds the zone keys of an apex DNSKEY RRset that one of `keys` signed.
    fn adoptZoneKeys(self: *Validator, keys: *std.ArrayList([]const u8), signer: Name) Error!void {
        var rrset: ?*const Rrset = null;
        for (self.rrsets.items) |*candidate| {
            if (candidate.rrtype == RecordType.DNSKEY.code() and candidate.owner.eql(&signer)) {
                rrset = candidate;
                break;
            }
        }
        const apex = rrset orelse return;
        var authenticated = false;
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != RecordType.DNSKEY.code() or !rrsig.owner.eql(&signer)) continue;
            const data = try signedData(self.allocator, apex.records.items, rrsig);
            for (keys.items) |key| {
                verifyWithKey(key, rrsig, data) catch continue;
                authenticated = true;
                break;
            }
            if (authenticated) break;
        }
        if (!authenticated) return;
        try self.addZoneKeys(keys, apex);
    }

    /// The DS that reached this zone is authenticated: the matched DNSKEY
    /// must have signed the apex DNSKEY RRset itself, and a revoked key
    /// leaves the trusted set (RFC 5011 section 2.1).
    fn confirmDsMatchedKeys(self: *Validator, keys: *std.ArrayList([]const u8), signer: Name) Error!void {
        // The matched DNSKEY must have signed the apex DNSKEY RRset itself.
        var rrset: ?*const Rrset = null;
        for (self.rrsets.items) |*candidate| {
            if (candidate.rrtype == RecordType.DNSKEY.code() and candidate.owner.eql(&signer)) {
                rrset = candidate;
                break;
            }
        }
        const apex = rrset orelse return keys.clearRetainingCapacity();
        var authenticated = false;
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != RecordType.DNSKEY.code() or !rrsig.owner.eql(&signer)) continue;
            const data = try signedData(self.allocator, apex.records.items, rrsig);
            for (keys.items) |key| {
                verifyWithKey(key, rrsig, data) catch continue;
                // The key signed the apex DNSKEY RRset it belongs to, so the
                // proof RFC 5011 section 3 names is in hand: a key that
                // carries the REVOKE bit is revoked, and a revoked key is
                // invalid for every purpose except validating the revocation.
                if (revokedKey(key)) continue;
                authenticated = true;
                break;
            }
            if (authenticated) break;
        }
        if (!authenticated) return keys.clearRetainingCapacity();
        // RFC 5011 section 2.1: a revoked key must not be used as a trust
        // anchor, so it leaves the trusted set even when another key
        // authenticated the RRset.
        var kept: usize = 0;
        for (keys.items) |key| {
            if (try self.selfRevoked(apex, key)) continue;
            keys.items[kept] = key;
            kept += 1;
        }
        keys.items.len = kept;
        try self.addZoneKeys(keys, apex);
    }

    /// RFC 4035 section 5.2: a zone that no configured anchor names is
    /// reached through the DS RRset its parent publishes. The parent signs
    /// that DS RRset with its own key, so the walk continues at the parent
    /// until an anchor speaks for a zone. Every record the walk needs is in
    /// the signed material the caller supplied: the DS RRset with its RRSIG,
    /// and the child's DNSKEY RRset.
    fn keysFromParentDs(self: *Validator, keys: *std.ArrayList([]const u8), signer: Name) Error!void {
        var ds: ?*const Rrset = null;
        for (self.rrsets.items) |*candidate| {
            if (candidate.rrtype != RecordType.DS.code()) continue;
            if (!candidate.owner.eql(&signer)) continue;
            ds = candidate;
            break;
        }
        const ds_set = ds orelse return;
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != RecordType.DS.code()) continue;
            if (!rrsig.owner.eql(&signer)) continue;
            // The DS is signed by the parent zone. A signer that is not a
            // strict ancestor would leave the tree the DS names.
            if (!isStrictAncestor(&rrsig.signer, &signer)) continue;
            const parent_keys = try self.keySet(rrsig.signer);
            if (parent_keys.len == 0) continue;
            const data = try signedData(self.allocator, ds_set.records.items, rrsig);
            var parent_verified = false;
            for (parent_keys) |key| {
                verifyWithKey(key, rrsig, data) catch continue;
                parent_verified = true;
                break;
            }
            if (!parent_verified) continue;
            for (self.rrsets.items) |*candidate| {
                if (candidate.rrtype != RecordType.DNSKEY.code() or !candidate.owner.eql(&signer)) continue;
                for (candidate.records.items) |record| {
                    const raw = try encodeRdata(self.allocator, record.rrtype.code(), record.rdata);
                    if (!dnskeyZoneKeyBit(raw)) continue;
                    if (!algorithmSupported(raw[3])) continue;
                    for (ds_set.records.items) |ds_record| {
                        const ds_raw = try encodeRdata(self.allocator, ds_record.rrtype.code(), ds_record.rdata);
                        if (!dsMatches(ds_raw, signer, raw)) continue;
                        try keys.append(self.allocator, raw);
                    }
                }
            }
            if (keys.items.len == 0) continue;
            try self.confirmDsMatchedKeys(keys, signer);
            return;
        }
    }

    /// Whether the key signed the apex DNSKEY RRset it belongs to, which is
    /// the proof RFC 5011 section 3 names for a revocation: the signature the
    /// key made over that RRset, and not the bit alone. `revokedKey` states
    /// the policy both trust paths follow.
    fn selfRevoked(self: *Validator, apex: *const Rrset, key_rdata: []const u8) Error!bool {
        if (!revokedKey(key_rdata)) return false;
        for (self.rrsigs.items) |rrsig| {
            if (rrsig.covered != RecordType.DNSKEY.code() or !rrsig.owner.eql(&apex.owner)) continue;
            const data = try signedData(self.allocator, apex.records.items, rrsig);
            verifyWithKey(key_rdata, rrsig, data) catch continue;
            return true;
        }
        return false;
    }

    /// The rest of the keys of an authenticated apex DNSKEY RRset. RFC 6781
    /// section 3.1: once the key-signing key has signed the RRset, every key
    /// in it can sign the zone's other RRsets, so the zone-signing key's
    /// signatures count. RFC 4034 section 2.1.1 keeps a key without the Zone
    /// Key flag out, and a key this build cannot verify with is no key at all.
    /// RFC 5011 section 2.1 keeps a revoked key out as well (`revokedKey`):
    /// it is invalid for every purpose except validating the revocation.
    fn addZoneKeys(self: *Validator, keys: *std.ArrayList([]const u8), apex: *const Rrset) Error!void {
        for (apex.records.items) |record| {
            const raw = try encodeRdata(self.allocator, record.rrtype.code(), record.rdata);
            if (!dnskeyZoneKeyBit(raw)) continue;
            if (!algorithmSupported(raw[3])) continue;
            if (try self.selfRevoked(apex, raw)) continue;
            var known = false;
            for (keys.items) |key| {
                if (std.mem.eql(u8, key, raw)) {
                    known = true;
                    break;
                }
            }
            if (known) continue;
            try keys.append(self.allocator, raw);
        }
    }

    // ------------------------------------------------------------ RRsets

    /// Validate one signed RRset (RFC 4035 section 5.3). Every RRSIG that
    /// covers it is tried: a zone with two keys publishes two signatures and
    /// one of them failing says nothing about the other.
    fn checkRrset(self: *Validator, rrset: *const Rrset) Error!Outcome {
        var saw_signature = false;
        var has_keys = false;
        var unsupported_algorithm = false;
        // RFC 4035 section 5.3.3: a validator tries every RRSIG that covers
        // the RRset, so one expired or not-yet-valid signature beside a good
        // one does not make the answer bogus.
        var time_failure: ?u16 = null;
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
            // answer is insecure rather than bogus (the states of section
            // 4.3).
            if (!algorithmSupported(rrsig.algorithm)) {
                unsupported_algorithm = true;
                continue;
            }
            const status = dnssec.rrsigTimeStatus(rrsig.raw, self.now) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (status != .valid) {
                time_failure = dnssec.rrsigTimeEde(status).?;
                continue;
            }
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
        if (time_failure) |ede| return self.fail(ede);
        if (!has_keys) return .insecure;
        if (unsupported_algorithm) {
            self.noteInsecure(dnssec.EDE_UNSUPPORTED_DNSKEY_ALGORITHM);
            return .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// The verdict on one denial proof: its signature verifies with the
    /// signer's trusted key set, this build cannot authenticate it, or the
    /// signature does not verify.
    fn checkProof(self: *Validator, owner: Name, rrtype: u16) Error!Outcome {
        const rrset = findRrset(self, owner, rrtype) orelse return .insecure;
        return self.checkRrset(rrset);
    }

    /// RFC 4035 section 5.4: the RRsets that make up a denial proof must
    /// themselves be authenticated (section 5.3), so the signature over every
    /// proof the denial used is checked with the signer's trusted key set
    /// before the proof may support an answer. A proof whose signature does
    /// not verify makes the response bad (section 5.5); a proof this build
    /// cannot authenticate leaves the answer insecure (the state of section
    /// 4.3). A record
    /// the response carries beside the proof is not part of it and is not
    /// judged.
    fn checkProofs(self: *Validator) Error!Outcome {
        var authenticated = true;
        for (self.nsecs.items) |*proof| {
            if (!proof.used) continue;
            switch (try self.checkProof(proof.owner, RecordType.NSEC.code())) {
                .bogus => return .bogus,
                .insecure => authenticated = false,
                .secure => {},
            }
        }
        for (self.nsec3s.items) |*proof| {
            if (!proof.used) continue;
            switch (try self.checkProof(proof.owner, RecordType.NSEC3.code())) {
                .bogus => return .bogus,
                .insecure => authenticated = false,
                .secure => {},
            }
        }
        return if (authenticated) .secure else .insecure;
    }

    // ------------------------------------------------------------ NSEC

    /// RFC 4035 section 5.4 with RFC 6840 sections 4.1, 4.3 and 4.4.
    fn checkNsecDenial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        const outcome = try self.nsecDenial(name, qtype, delegation, nxdomain);
        if (outcome == .bogus) return .bogus;
        // RFC 4035 section 5.4: the proof must be authenticated before it may
        // support an answer.
        const proofs = try self.checkProofs();
        if (proofs == .bogus) return .bogus;
        // A proof this build cannot authenticate cannot make the answer
        // secure, so the answer stays insecure.
        if (outcome == .secure and proofs == .insecure) return .insecure;
        return outcome;
    }

    fn nsecDenial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        // RFC 6840 section 4.1 exempts DS from the ancestor-delegation ban:
        // "all RRs at that (original) owner name other than DS RRs". The NSEC a
        // parent publishes at a delegation is therefore the legitimate proof
        // for a DS query, and section 4.4 says what it has to show.
        if (delegation and qtype == RecordType.DS.code()) return self.nsecUnsignedDelegation(name);
        for (self.nsecs.items) |*proof| {
            if (!proof.owner.eql(&name)) continue;
            proof.used = true;
            return self.nsecNoData(proof, qtype);
        }
        if (!nxdomain) return self.nsecWildcardNoData(name, qtype);
        return self.nsecNxDomain(name);
    }

    /// RFC 4035 section 3.1.3.4: a NODATA answer may rest on the NSEC at
    /// the wildcard owner name that matched the name. The wildcard is the one
    /// at the closest encloser, so it covers the name only when the name is
    /// one label below that encloser, and the encloser must exist.
    fn nsecWildcardNoData(self: *Validator, name: Name, qtype: u16) Error!Outcome {
        const encloser = parentName(name) orelse return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        for (self.nsecs.items) |*proof| {
            if (!proof.owner.eql(&encloser)) continue;
            proof.used = true;
            return self.nsecWildcardEncloser(proof, name, qtype);
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// The proof a wildcard NODATA rests on: the closest encloser exists, the
    /// name itself does not, and the wildcard at the encloser holds neither
    /// the QTYPE nor CNAME.
    fn nsecWildcardEncloser(self: *Validator, proof: *const Nsec, name: Name, qtype: u16) Error!Outcome {
        if (isAncestorDelegation(proof.bitmap, labelsCount(proof.owner.asWire()), labelsCount(proof.signer.asWire()))) {
            return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        }
        if (!deniesWildcard(proof.labels, proof.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        // A name that exists holds its own types, so the name itself must be
        // covered by an NSEC that proves it does not exist.
        var covered = false;
        for (self.nsecs.items) |*candidate| {
            if (!dnssec.nsecCovers(candidate.owner, candidate.next, name)) continue;
            // The NSEC that covers the name is part of the proof.
            candidate.used = true;
            covered = true;
            if (isAncestorDelegation(candidate.bitmap, labelsCount(candidate.owner.asWire()), labelsCount(candidate.signer.asWire()))) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (deniesSubdomain(candidate.bitmap, candidate.owner, name)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        }
        if (!covered) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        // The record at the wildcard's own name shows the types the wildcard
        // holds, so a type it does not hold is proved absent (RFC 4035
        // section 3.1.3.4, and RFC 6840 section 4.3 for the CNAME bit).
        const wildcard = wildcardName(proof.owner) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        for (self.nsecs.items) |*candidate| {
            if (!candidate.owner.eql(&wildcard)) continue;
            candidate.used = true;
            if (isAncestorDelegation(candidate.bitmap, labelsCount(candidate.owner.asWire()), labelsCount(candidate.signer.asWire()))) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (!deniesWildcard(candidate.labels, candidate.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            const denies = dnssec.bitmapDeniesTypeAndCname(candidate.bitmap, qtype) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            if (!denies) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
            return if (try self.anchored(proof.signer)) .secure else .insecure;
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    /// RFC 6840 section 4.4: an insecure delegation needs the NS bit to show
    /// there really is a delegation, and DS and SOA both clear to show no DS
    /// RRset exists for it. Reusing an NSEC at a non-delegation name would let
    /// an attacker claim an existing signed RRset sits below an unsigned cut.
    fn nsecUnsignedDelegation(self: *Validator, name: Name) Error!Outcome {
        for (self.nsecs.items) |*proof| {
            if (!proof.owner.eql(&name)) continue;
            proof.used = true;
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
        if (isAncestorDelegation(proof.bitmap, labelsCount(proof.owner.asWire()), labelsCount(proof.signer.asWire()))) {
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
                proof.used = true;
                return self.nsecEncloser(proof, next_closer);
            }
            next_closer = encloser;
            ancestor = parentName(encloser);
        }
        return self.fail(dnssec.EDE_DNSSEC_BOGUS);
    }

    fn nsecEncloser(self: *Validator, proof: *const Nsec, next_closer: Name) Error!Outcome {
        if (isAncestorDelegation(proof.bitmap, labelsCount(proof.owner.asWire()), labelsCount(proof.signer.asWire()))) {
            return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        }
        if (!deniesWildcard(proof.labels, proof.owner)) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        const wildcard = wildcardName(proof.owner) catch return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        // RFC 4035 section 5.4: the proof is complete only when an NSEC
        // covers the next closer name and another covers the wildcard at
        // the closest encloser. A response that carries only the encloser's
        // own NSEC proves neither.
        if (try self.nsecCoversName(next_closer) != .covered) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        if (try self.nsecCoversName(wildcard) != .covered) return self.fail(dnssec.EDE_DNSSEC_BOGUS);
        return if (try self.anchored(proof.signer)) .secure else .insecure;
    }

    const Covers = enum { covered, uncovered, bogus };

    /// Whether some NSEC in the response covers `target`; the NSEC used is
    /// marked as part of the proof. A covering delegation or DNAME makes the
    /// denial bogus, not merely incomplete.
    fn nsecCoversName(self: *Validator, target: Name) Error!Covers {
        var covered = false;
        for (self.nsecs.items) |*candidate| {
            if (!dnssec.nsecCovers(candidate.owner, candidate.next, target)) continue;
            candidate.used = true;
            covered = true;
            // An ancestor delegation proves nothing below the cut, and a
            // DNAME redirects the subtree it would have denied.
            if (isAncestorDelegation(candidate.bitmap, labelsCount(candidate.owner.asWire()), labelsCount(candidate.signer.asWire()))) {
                _ = self.fail(dnssec.EDE_DNSSEC_BOGUS);
                return .bogus;
            }
            if (deniesSubdomain(candidate.bitmap, candidate.owner, target)) {
                _ = self.fail(dnssec.EDE_DNSSEC_BOGUS);
                return .bogus;
            }
        }
        return if (covered) .covered else .uncovered;
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
            for (self.nsec3s.items) |*proof| {
                if (std.mem.eql(u8, &proof.owner_hash, &digest)) {
                    // The closest encloser's own NSEC3 is part of the proof.
                    proof.used = true;
                    matched = proof.*;
                }
                if (nsec3Covers(proof.owner_hash, proof.next_hash, digest)) {
                    // The NSEC3 that covers the name is part of the proof too.
                    proof.used = true;
                    spans = true;
                }
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
        // RFC 5155 section 10.3: the iteration count drives the validator's
        // work and comes from the response, so a count above this ceiling is
        // not hashed at all. RFC 9276 section 3.1 asks publishers for zero;
        // this is the validator's own bound.
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
        // RFC 5155 section 10.3: bound the work a proof can demand. A chain
        // this far above the recommendation cannot be authenticated here, so
        // the answer is insecure rather than an expensive denial.
        if (self.nsec3s.items[0].iterations > max_nsec3_iterations) {
            self.noteInsecure(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS);
            return .insecure;
        }
        const outcome = try self.nsec3Denial(name, qtype, delegation, nxdomain);
        if (outcome == .bogus) return .bogus;
        // RFC 4035 section 5.4: the proof must be authenticated before it may
        // support an answer, and RFC 9276 section 3.2 asks the same of a
        // validator that answers insecure over a chain with iterations.
        const proofs = try self.checkProofs();
        if (proofs == .bogus) return .bogus;
        // RFC 9276 section 3.2: a validator that processes NSEC3 records with
        // an iteration count above 0 answers insecure, not secure, and says
        // so with the EDE the RFC assigns to that answer.
        if (self.nsec3s.items[0].iterations > 0) {
            self.noteInsecure(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS);
            if (outcome == .secure) return .insecure;
        }
        // A proof this build cannot authenticate cannot make the answer
        // secure, so the answer stays insecure.
        if (outcome == .secure and proofs == .insecure) return .insecure;
        return outcome;
    }

    fn nsec3Denial(self: *Validator, name: Name, qtype: u16, delegation: bool, nxdomain: bool) Error!Outcome {
        if (delegation) return self.nsec3UnsignedReferral(name);
        const digest = self.hash(name);
        for (self.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            proof.used = true;
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
        for (self.nsec3s.items) |*proof| {
            if (!nsec3Covers(proof.owner_hash, proof.next_hash, digest)) continue;
            // The NSEC3 that covers the wildcard is part of the proof.
            proof.used = true;
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
            proof.used = true;
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
            proof.used = true;
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
                for (self.nsec3s.items) |*proof| {
                    if (!nsec3Covers(proof.owner_hash, proof.next_hash, digest)) continue;
                    proof.used = true;
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

/// True when the Answer section holds an RRset whose owner is the QNAME and
/// whose class is the query class. RFC 6840 section 4.2: the RRsets a
/// response to QTYPE=* carries at the QNAME are the ones that must be
/// validated, and a response that carries none of them must prove the
/// absence instead. The DNSSEC bookkeeping records are not data of the name.
fn answerHoldsQname(response: dns_message.Message, name: Name, class: Class) bool {
    for (response.answers.slice()) |record| {
        if (record.rrtype.eql(.RRSIG) or record.rrtype.eql(.NSEC) or record.rrtype.eql(.NSEC3)) continue;
        if (!record.class.eql(class)) continue;
        if (record.owner.eql(&name)) return true;
        // RFC 6672 section 3.1: a DNAME above the QNAME redirects the query,
        // so the answer is that DNAME and not a denial of the QNAME. The
        // answer holds no RRset at the QNAME, and the NSEC that could prove
        // its absence carries the DNAME bit, which RFC 6840 section 4.1 bars
        // from proving anything below that owner.
        if (record.rrtype.eql(.DNAME) and isSuffix(record.owner, name)) return true;
    }
    return false;
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

    for (self.rrsets.items) |*rrset| {
        // The NSEC and NSEC3 proof records are checked with the denial proof
        // they belong to (RFC 4035 section 5.4), not on their own.
        if (rrset.rrtype == RecordType.NSEC.code()) continue;
        if (rrset.rrtype == RecordType.NSEC3.code()) continue;
        self.count(try self.checkRrset(rrset));
    }

    // RFC 4035 section 3.2.3: the AD bit covers the Answer section and the
    // negative response RRs in Authority, so the denial proof is part of the
    // same decision, not a later one.
    //
    // RFC 6840 section 4.2: a response to QTYPE=* carries a subset of the
    // RRsets at the QNAME, so the validator must not expect all of them.
    // When the answer holds no RRset at the QNAME in the query class, that
    // absence must be proved with the rules of RFC 4035 section 5.4, so the
    // denial path runs on the content of the answer and not on its length.
    const question = query.question orelse return .{ .status = .insecure };
    if (!answerHoldsQname(response, question.name, question.qclass)) {
        const nxdomain = response.header.rcode == .nxdomain;
        const delegation = isReferral(response.authorities.slice());
        const outcome = if (self.nsec3s.items.len != 0)
            try self.checkNsec3Denial(question.name, question.qtype.code(), delegation, nxdomain)
        else if (self.nsecs.items.len != 0)
            try self.checkNsecDenial(question.name, question.qtype.code(), delegation, nxdomain)
        else if (anchors.covers(question.name))
            // RFC 4035 section 5.4: a signed zone must prove the absence.
            self.fail(dnssec.EDE_DNSSEC_BOGUS)
        else
            // Nothing was expected to be signed, so the absence needs no
            // proof and the answer is insecure, not bogus.
            .insecure;
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

    // RFC 4035 section 5.4: the proof is worthless without a signature over
    // it that verifies, so the absence is proven only by an authenticated
    // NSEC or NSEC3.
    //
    // RFC 4035 section 3.1.3 and RFC 5155 section 8.6: the record at the name
    // must deny the type, and the denial must reach the trust anchor.
    for (validator.nsecs.items) |*proof| {
        if (!proof.owner.eql(&apex)) continue;
        if (try validator.checkProof(proof.owner, RecordType.NSEC.code()) != .secure) return .unknown;
        if (try validator.nsecNoData(proof, RecordType.ZONEMD.code()) == .secure) return .proven;
    }
    if (has_chain) {
        for (validator.nsec3s.items) |*proof| {
            if (!std.mem.eql(u8, &proof.owner_hash, &digest)) continue;
            if (try validator.checkProof(proof.owner, RecordType.NSEC3.code()) != .secure) return .unknown;
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

/// A zone whose owner holds two RRsets, so an answer to QTYPE=* at that owner
/// carries two RRsets at the QNAME (RFC 6840 section 4.2), and a name that
/// holds a CNAME, so such an answer can be stripped of it.
const any_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
    \\both IN A 192.0.2.2
    \\both IN MX 10 mail.example.com.
    \\mail IN A 192.0.2.3
    \\alias IN CNAME both.example.com.
;

/// A zone with a DNAME above a name, so a query for a name below it is
/// answered with the DNAME and not with a denial of the name (RFC 6672
/// section 3.1).
const dname_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
    \\redirect IN DNAME target.example.net.
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

/// A zone whose roles are separated (RFC 6781 section 3.1): the key-signing
/// key signs the apex DNSKEY RRset and the DS states it, the zone-signing key
/// signs every other RRset.
const SplitZone = struct {
    zone: zone_index.Zone,
    /// The zone-signing key, with the key-signing key attached to it.
    key: zone_signer.Key,
    /// The key-signing key on its own: the DS at the parent states it.
    ksk: zone_signer.Key,
    /// The DNSKEY the DS states.
    ksk_dnskey: []const u8,

    fn deinit(self: *SplitZone, allocator: std.mem.Allocator) void {
        self.zone.deinit();
        self.key.deinit();
        self.ksk.deinit();
        allocator.free(self.ksk_dnskey);
    }
};

fn signSplitZoneText(
    allocator: std.mem.Allocator,
    text: []const u8,
    zsk_text: []const u8,
    ksk_text: []const u8,
) !SplitZone {
    var zone_file = try zone_parser.ZoneFile.parse(text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    errdefer zone.deinit();
    var key = try zone_signer.parseKey(zsk_text);
    errdefer key.deinit();
    var ksk = try zone_signer.parseKey(ksk_text);
    errdefer ksk.deinit();
    key.ksk = .{ .material = ksk.material };
    try zone_signer.signZone(allocator, &zone, &key, window);
    var ksk_dnskey: []const u8 = undefined;
    ksk_dnskey = try ksk.dnskeyRdata(allocator);
    return .{ .zone = zone, .key = key, .ksk = ksk, .ksk_dnskey = ksk_dnskey };
}

/// The DNSKEY RDATA of an Ed25519 key with the flags a test gives it. The
/// project signer always publishes a key with the Zone Key flag, so a DNSKEY
/// without it can only be built here.
fn ed25519DnskeyRdata(allocator: std.mem.Allocator, flags: u16, pair: Ed25519.KeyPair) ![]const u8 {
    var rdata: [4 + Ed25519.PublicKey.encoded_length]u8 = undefined;
    std.mem.writeInt(u16, rdata[0..2], flags, .big);
    rdata[2] = 3;
    rdata[3] = 15;
    const public = pair.public_key.toBytes();
    @memcpy(rdata[4..], &public);
    return allocator.dupe(u8, &rdata);
}

/// An RRSIG over `records` made by `pair`, for the test that needs a signature
/// from a key the validator must not trust. The RRSIG RDATA is built here
/// (RFC 4034 section 3.1) because the project signer signs with a key's own
/// published DNSKEY, and a key without the Zone Key flag has none.
fn forgeRrsig(
    allocator: std.mem.Allocator,
    owner: Name,
    signer: Name,
    covered: u16,
    records: []const *const dns_record.ResourceRecord,
    key_rdata: []const u8,
    pair: Ed25519.KeyPair,
) ![]const u8 {
    var header: [18 + 255]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], covered, .big);
    header[2] = key_rdata[3];
    header[3] = labelCount(owner.asWire());
    std.mem.writeInt(u32, header[4..8], records[0].ttl, .big);
    std.mem.writeInt(u32, header[8..12], window.expiration, .big);
    std.mem.writeInt(u32, header[12..16], window.inception, .big);
    std.mem.writeInt(u16, header[16..18], dnssec.keyTag(key_rdata), .big);
    const signer_wire = signer.asWire();
    @memcpy(header[18..][0..signer_wire.len], signer_wire);
    const header_len = 18 + signer_wire.len;

    const raw = try allocator.alloc(u8, header_len + Ed25519.Signature.encoded_length);
    @memcpy(raw[0..header_len], header[0..header_len]);
    @memset(raw[header_len..], 0);
    // The signed data is the RRSIG RDATA without the signature, then the
    // covered RRset in canonical order (RFC 4035 section 5.3.1).
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const data = try signedData(scratch.allocator(), records, try Rrsig.at(raw, owner));
    const signature = try pair.sign(data, null);
    const bytes = signature.toBytes();
    @memcpy(raw[header_len..][0..bytes.len], &bytes);
    return raw;
}

/// The RRSIG in `section` that covers `covered`, replaced by `rdata`. The
/// record keeps its place in the section, so the rest of the response is
/// untouched.
fn replaceRrsig(
    section: *dns_message.RecordSection,
    covered: RecordType,
    rdata: []const u8,
) !void {
    for (section.items[0..section.len]) |*record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!rrsigCoversType(record.*, covered)) continue;
        record.rdata = .{ .Unknown = .{ .len = @intCast(rdata.len), .borrowed = rdata } };
        return;
    }
    return Error.MalformedRdata;
}

/// The RRSIG in `section` that covers `covered`, with its signature broken:
/// the answer then rests on a signature that cannot verify. The copy is
/// returned so the caller can free it.
fn breakRrsig(
    allocator: std.mem.Allocator,
    section: *dns_message.RecordSection,
    covered: RecordType,
) ![]const u8 {
    for (section.items[0..section.len]) |*record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!rrsigCoversType(record.*, covered)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.MalformedRdata,
        };
        const copy = try allocator.dupe(u8, raw);
        copy[copy.len - 1] ^= 0xff;
        record.rdata = .{ .Unknown = .{ .len = @intCast(copy.len), .borrowed = copy } };
        return copy;
    }
    return Error.MalformedRdata;
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

/// Reduce a response's Authority section to the apex DNSKEY RRset and the
/// signature over it, so a test that swaps the zone's key sees nothing else
/// the old key signed.
fn keepApexDnskey(section: *dns_message.RecordSection) void {
    var kept: usize = 0;
    for (section.items) |record| {
        const is_key = record.rrtype.eql(.DNSKEY);
        const is_key_signature = record.rrtype.eql(.RRSIG) and rrsigCoversType(record, RecordType.DNSKEY);
        if (!is_key and !is_key_signature) continue;
        // Copied by value first: `section.items` is one allocation, so writing
        // the kept record back in place would overwrite an entry the loop has
        // not reached yet.
        const copy = record;
        section.items[kept] = copy;
        kept += 1;
    }
    section.len = kept;
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

/// Drop the RRSIG over the NSEC, so the proof the answer rests on is
/// unsigned: RFC 4035 section 5.4 says an NSEC with no signature over it
/// proves nothing.
fn dropNsecSignature(section: *dns_message.RecordSection) void {
    var kept: usize = 0;
    for (section.items) |record| {
        const is_signature = record.rrtype.eql(.RRSIG) and rrsigCoversType(record, RecordType.NSEC);
        if (is_signature) continue;
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

/// Drop the denial proofs and the RRSIGs that cover them, so the response
/// carries no proof of an absence at all.
fn dropNsecProofs(section: *dns_message.RecordSection) void {
    var kept: usize = 0;
    for (section.items) |record| {
        const is_proof = record.rrtype.eql(.NSEC) or record.rrtype.eql(.NSEC3);
        const is_proof_signature = record.rrtype.eql(.RRSIG) and
            (rrsigCoversType(record, RecordType.NSEC) or rrsigCoversType(record, RecordType.NSEC3));
        if (is_proof or is_proof_signature) continue;
        // Copied by value first: `section.items` is one allocation, so writing
        // the kept record back in place would overwrite an entry the loop has
        // not reached yet.
        const copy = record;
        section.items[kept] = copy;
        kept += 1;
    }
    section.len = kept;
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

test "RFC 6781 section 3.1: a separated zone validates secure through the DS of its key-signing key" {
    var signed = try signSplitZoneText(std.testing.allocator, child_zone_text, p256_secret, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.ksk_dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The DS names the key-signing key, which signed the DNSKEY RRset, so
    // the zone-signing key's signature over the answer carries the zone: the
    // answer is secure and the AD bit may be set.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "a separated zone whose DNSKEY RRset signature is broken stays insecure" {
    var signed = try signSplitZoneText(std.testing.allocator, child_zone_text, p256_secret, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.ksk_dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The key-signing key's signature over the DNSKEY RRset is what
    // authenticates the set, so breaking it leaves the zone with no
    // authentication path (RFC 4035 section 5.2): insecure, not bogus, and
    // the zone-signing key's signature buys the answer nothing.
    const broken = try breakRrsig(std.testing.allocator, &pair.response.authorities, RecordType.DNSKEY);
    defer std.testing.allocator.free(broken);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
}

test "a DNSKEY without the Zone Key flag is not trusted" {
    const allocator = std.testing.allocator;
    var signed = try signSplitZoneText(allocator, child_zone_text, p256_secret, ed25519_secret);
    defer signed.deinit(allocator);
    var anchors = try dsAnchor(allocator, "example.com.", signed.ksk_dnskey, false);
    defer anchors.deinit(allocator);

    var pair = try exchange(allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // A third key, published without the Zone Key flag: RFC 4034 section
    // 2.1.1 says such a key must not verify an RRset, so the answer it
    // signed is bogus.
    const bare_pair = try Ed25519.KeyPair.generateDeterministic(@splat(0x33));
    const bare_dnskey = try ed25519DnskeyRdata(allocator, 0x0001, bare_pair);
    defer allocator.free(bare_dnskey);
    try pair.response.authorities.append(.{
        .owner = try Name.fromText("example.com."),
        .rrtype = .DNSKEY,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .Unknown = .{ .len = @intCast(bare_dnskey.len), .borrowed = bare_dnskey } },
    });
    pair.response.header.authority_count = @intCast(pair.response.authorities.len);

    // The DNSKEY RRset now holds three keys, so the key-signing key signs it
    // again over the three.
    const zsk_dnskey = try signed.key.dnskeyRdataWithFlags(allocator, 0x0100);
    defer allocator.free(zsk_dnskey);
    const rdatas = [_][]const u8{ zsk_dnskey, signed.ksk_dnskey, bare_dnskey };
    const apex = try Name.fromText("example.com.");
    const dnskey_rrsig = try zone_signer.signRrset(allocator, apex, apex, RecordType.DNSKEY.code(), &rdatas, 3600, &signed.ksk, window);
    defer allocator.free(dnskey_rrsig);
    try replaceRrsig(&pair.response.authorities, RecordType.DNSKEY, dnskey_rrsig);

    // The answer carries the signature of the key without the Zone Key flag.
    const answer = &pair.response.answers.items[0];
    const records = [_]*const dns_record.ResourceRecord{answer};
    const owner = try Name.fromText("www.example.com.");
    const bare_rrsig = try forgeRrsig(allocator, owner, apex, RecordType.A.code(), &records, bare_dnskey, bare_pair);
    defer allocator.free(bare_rrsig);
    try replaceRrsig(&pair.response.answers, RecordType.A, bare_rrsig);

    const result = try validate(allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
}

test "RFC 5011 section 2.1: a revoked key in a self-signed DNSKEY RRset is not used to verify the zone" {
    const allocator = std.testing.allocator;
    var signed = try signZoneText(allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(allocator);
    var pair = try exchange(allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The key the zone publishes with the REVOKE bit set, and the only key
    // of its DNSKEY RRset. The zone's other RRsets go with it: the revoked
    // key is then the only key that could verify anything in the response.
    const revoked_pair = try Ed25519.KeyPair.generateDeterministic(@splat(0x52));
    const revoked_dnskey = try ed25519DnskeyRdata(allocator, 0x0180, revoked_pair);
    defer allocator.free(revoked_dnskey);
    try setApexDnskey(&pair.response, revoked_dnskey);
    keepApexDnskey(&pair.response.authorities);

    // The self-signature over the apex DNSKEY RRset: the resolver sees the
    // key in a self-signed RRset, and that is what proves the revocation
    // (RFC 5011 sections 2.1 and 3).
    const apex = try Name.fromText("example.com.");
    var dnskey_record: ?*const dns_record.ResourceRecord = null;
    for (pair.response.authorities.items) |*record| {
        if (!record.rrtype.eql(.DNSKEY)) continue;
        dnskey_record = record;
        break;
    }
    const dnskey_records = [_]*const dns_record.ResourceRecord{dnskey_record.?};
    const self_signature = try forgeRrsig(allocator, apex, apex, RecordType.DNSKEY.code(), &dnskey_records, revoked_dnskey, revoked_pair);
    defer allocator.free(self_signature);
    try replaceRrsig(&pair.response.authorities, RecordType.DNSKEY, self_signature);

    // The answer carries the revoked key's signature as well, so nothing but
    // the revocation stands between it and a secure answer.
    const answer = &pair.response.answers.items[0];
    const answer_records = [_]*const dns_record.ResourceRecord{answer};
    const owner = try Name.fromText("www.example.com.");
    const answer_signature = try forgeRrsig(allocator, owner, apex, RecordType.A.code(), &answer_records, revoked_dnskey, revoked_pair);
    defer allocator.free(answer_signature);
    try replaceRrsig(&pair.response.answers, RecordType.A, answer_signature);

    // The DS at the parent names the revoked key.
    var anchors = try dsAnchor(allocator, "example.com.", revoked_dnskey, false);
    defer anchors.deinit(allocator);

    // RFC 5011 section 2.1: a revoked key must not be used as a trust anchor,
    // so the DS matches no usable key and the zone has no chain of trust.
    // RFC 4035 section 5.2 makes that insecure, not bogus.
    try expectStatus(.insecure, try validate(allocator, &anchors, pair.query, pair.response, &.{}, now_seconds));
}

test "RFC 5011 section 3: a key that carries the REVOKE bit but did not sign the DNSKEY RRset is not revoked" {
    const allocator = std.testing.allocator;
    var signed = try signZoneText(allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(allocator);
    var pair = try exchange(allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // Two keys in the apex DNSKEY RRset: the one the DS names, and one that
    // carries the REVOKE bit.
    const ksk_pair = try Ed25519.KeyPair.generateDeterministic(@splat(0x53));
    const ksk_dnskey = try ed25519DnskeyRdata(allocator, 0x0100, ksk_pair);
    defer allocator.free(ksk_dnskey);
    const revoked_pair = try Ed25519.KeyPair.generateDeterministic(@splat(0x54));
    const revoked_dnskey = try ed25519DnskeyRdata(allocator, 0x0180, revoked_pair);
    defer allocator.free(revoked_dnskey);

    // The zone publishes both keys, and only the first signs the DNSKEY
    // RRset. The REVOKE bit of the second is there, but the proof RFC 5011
    // section 3 names -- that key's own signature over the RRset -- is not.
    try setApexDnskey(&pair.response, ksk_dnskey);
    try pair.response.authorities.append(.{
        .owner = try Name.fromText("example.com."),
        .rrtype = .DNSKEY,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .Unknown = .{ .len = @intCast(revoked_dnskey.len), .borrowed = revoked_dnskey } },
    });
    keepApexDnskey(&pair.response.authorities);

    const apex = try Name.fromText("example.com.");
    var dnskey_records: [2]*const dns_record.ResourceRecord = undefined;
    var found: usize = 0;
    for (pair.response.authorities.items[0..pair.response.authorities.len]) |*record| {
        if (!record.rrtype.eql(.DNSKEY)) continue;
        dnskey_records[found] = record;
        found += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), found);
    const self_signature = try forgeRrsig(allocator, apex, apex, RecordType.DNSKEY.code(), &dnskey_records, ksk_dnskey, ksk_pair);
    defer allocator.free(self_signature);
    try replaceRrsig(&pair.response.authorities, RecordType.DNSKEY, self_signature);

    // The answer is signed by the key that carries the REVOKE bit and did
    // not sign the DNSKEY RRset, so nothing but the policy decides whether
    // that key is trusted.
    const answer = &pair.response.answers.items[0];
    const answer_records = [_]*const dns_record.ResourceRecord{answer};
    const owner = try Name.fromText("www.example.com.");
    const answer_signature = try forgeRrsig(allocator, owner, apex, RecordType.A.code(), &answer_records, revoked_dnskey, revoked_pair);
    defer allocator.free(answer_signature);
    try replaceRrsig(&pair.response.answers, RecordType.A, answer_signature);

    // The DS at the parent names the key that signed the DNSKEY RRset.
    var anchors = try dsAnchor(allocator, "example.com.", ksk_dnskey, false);
    defer anchors.deinit(allocator);

    // RFC 5011 section 3: the bit counts only where the resolver saw the key
    // sign the DNSKEY RRset, and this key did not, so it is not revoked and
    // it stays in the trusted set. RFC 4035 section 5.3.1 trusts every key
    // of an authenticated DNSKEY RRset, so the answer validates secure.
    const result = try validate(allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 5011 section 2.1: a configured DNSKEY anchor that carries the REVOKE bit is not a trust anchor" {
    const allocator = std.testing.allocator;
    var signed = try signZoneText(allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(allocator);
    var pair = try exchange(allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The anchor an operator wrote carries the REVOKE bit. The anchor file
    // holds no RRset and so has no self-signature to see: the operator's
    // file is the proof that the key is revoked.
    const revoked = try allocator.dupe(u8, signed.dnskey);
    defer allocator.free(revoked);
    revoked[1] |= 0x80;
    var anchors = try dnskeyAnchor(allocator, "example.com.", revoked);
    defer anchors.deinit(allocator);

    // RFC 5011 section 2.1: a revoked key is not a trust anchor, so the zone
    // has no chain of trust and RFC 4035 section 5.2 leaves the answer
    // insecure rather than bogus. RFC 8914 has no code that names a revoked
    // key, so the client is told the status is indeterminate.
    const result = try validate(allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_INDETERMINATE, result.ede);
}

test "a zone with one key still validates secure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // One key, one signed RRset: the outcome is the one it always was.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "the apex DNSKEY RRset is authenticated by the DS and not by the zone-signing key" {
    var signed = try signSplitZoneText(std.testing.allocator, child_zone_text, p256_secret, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dsAnchor(std.testing.allocator, "example.com.", signed.ksk_dnskey, false);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .A, .no_error, "www.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The DNSKEY RRset signed by the zone-signing key alone. The DS names the
    // key-signing key, and only that key authenticates the RRset (RFC 4035
    // sections 5.2 and 5.3.1), so the zone keeps no authentication path.
    const zsk_dnskey = try signed.key.dnskeyRdataWithFlags(std.testing.allocator, 0x0100);
    defer std.testing.allocator.free(zsk_dnskey);
    const rdatas = [_][]const u8{ zsk_dnskey, signed.ksk_dnskey };
    const apex = try Name.fromText("example.com.");
    const dnskey_rrsig = try zone_signer.signRrset(std.testing.allocator, apex, apex, RecordType.DNSKEY.code(), &rdatas, 3600, &signed.key, window);
    defer std.testing.allocator.free(dnskey_rrsig);
    try replaceRrsig(&pair.response.authorities, RecordType.DNSKEY, dnskey_rrsig);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
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
    const key = dnskeyRdata(256, 16);
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

// ------------------------------------------------- RFC 6840 ANY responses

test "RFC 6840 section 4.2: an ANY answer with two RRsets at the QNAME is bogus when one of them does not verify" {
    var signed = try signZoneText(std.testing.allocator, any_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "both.example.com.", .ANY, .no_error, "both.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The answer carries two RRsets at the QNAME and the MX one rests on a
    // signature that does not verify, so the answer is bogus even though the
    // A RRset beside it verifies.
    const broken = try breakRrsig(std.testing.allocator, &pair.response.answers, RecordType.MX);
    defer std.testing.allocator.free(broken);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "RFC 6840 section 4.2: an ANY answer with two RRsets at the QNAME is secure when both of them verify" {
    var signed = try signZoneText(std.testing.allocator, any_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "both.example.com.", .ANY, .no_error, "both.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The same two RRsets, both of them signed by the zone's own key: the
    // answer is secure and the AD bit may be set.
    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 6840 section 4.2: an ANY answer with no RRset at the QNAME is judged by the NODATA proof" {
    var signed = try signZoneText(std.testing.allocator, any_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);
    var outside = try dnskeyAnchor(std.testing.allocator, "other.test.", signed.dnskey);
    defer outside.deinit(std.testing.allocator);

    // The answer holds the RRsets of the CNAME's target and not the CNAME at
    // the QNAME, so it carries no RRset at the QNAME at all. The NSEC at the
    // QNAME still names the CNAME type (RFC 6840 section 4.3), so the absence
    // is not proved and the answer is bogus.
    var stripped = try exchange(std.testing.allocator, &signed.zone, "alias.example.com.", .ANY, .no_error, "both.example.com.", null);
    defer stripped.query.deinit();
    defer stripped.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, stripped.query, stripped.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);

    // The same answer without any denial proof: inside the trust domain the
    // absence must be proved (RFC 4035 section 5.4), so the answer is bogus.
    var unproved = try exchange(std.testing.allocator, &signed.zone, "alias.example.com.", .ANY, .no_error, "both.example.com.", null);
    defer unproved.query.deinit();
    defer unproved.response.deinit();
    dropNsecProofs(&unproved.response.answers);
    dropNsecProofs(&unproved.response.authorities);

    const unproved_result = try validate(std.testing.allocator, &anchors, unproved.query, unproved.response, &.{}, now_seconds);
    try expectStatus(.bogus, unproved_result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, unproved_result.ede);

    // The same answer outside the trust domain: nothing was expected to be
    // signed, so the absence needs no proof and the answer is insecure.
    var unsigned = try exchange(std.testing.allocator, &signed.zone, "alias.example.com.", .ANY, .no_error, "both.example.com.", null);
    defer unsigned.query.deinit();
    defer unsigned.response.deinit();
    dropNsecProofs(&unsigned.response.answers);
    dropNsecProofs(&unsigned.response.authorities);

    try expectStatus(.insecure, try validate(std.testing.allocator, &outside, unsigned.query, unsigned.response, &.{}, now_seconds));
}

test "RFC 6672 section 3.1: a DNAME above the QNAME answers the query, it does not deny it" {
    var signed = try signZoneText(std.testing.allocator, dname_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    // The answer holds the DNAME and the signature over it, and no RRset at
    // the QNAME: the DNAME redirects the query, so the absence of the QNAME
    // needs no proof. The only NSEC that could cover the name is the one the
    // DNAME's own owner published, and RFC 6840 section 4.1 bars it from
    // proving anything below that owner.
    var pair = try exchange(std.testing.allocator, &signed.zone, "host.redirect.example.com.", .A, .no_error, "redirect.example.com.", null);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

// ----------------------------------------- RFC 4035 section 5.4 proofs

test "RFC 4035 section 5.4: an NSEC proof that verifies leaves the answer secure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    // The answer holds no RRset at the QNAME, so the absence of an MX record
    // at www.example.com. must be proved with the NSEC the zone published
    // there. The zone signed that proof with its own key, so the answer is
    // secure and the AD bit may be set.
    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4035 section 5.4: an NSEC proof whose signature does not verify is bogus" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The signature over the NSEC is broken, so the proof cannot be
    // authenticated: the absence it supports is not proved and the answer is
    // bogus, not secure.
    const broken = try breakRrsig(std.testing.allocator, &pair.response.authorities, RecordType.NSEC);
    defer std.testing.allocator.free(broken);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "RFC 4035 section 5.4: an NSEC proof with no signature over it is refused" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The NSEC without the RRSIG over it proves nothing (RFC 4035 section
    // 5.4), so the absence is not proved and the answer is bogus.
    dropNsecSignature(&pair.response.authorities);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

/// An extra NSEC in the authority section, under a name of its own, with the
/// RRSIG the response already carried: the signature was made over the proof
/// the response carried, so it does not verify over the copy. RFC 4035
/// section 5.4 asks for the RRsets that comprise the proof, and this one is
/// not one of them.
fn appendExtraNsec(section: *dns_message.RecordSection, owner_text: []const u8) !void {
    var nsec: ?dns_record.ResourceRecord = null;
    var signature: ?dns_record.ResourceRecord = null;
    for (section.items[0..section.len]) |record| {
        if (record.rrtype.eql(.NSEC)) nsec = record;
        if (record.rrtype.eql(.RRSIG) and rrsigCoversType(record, RecordType.NSEC)) signature = record;
    }
    const nsec_record = nsec orelse return Error.MalformedRdata;
    const rrsig_record = signature orelse return Error.MalformedRdata;
    const owner = try Name.fromText(owner_text);
    try section.append(.{ .owner = owner, .rrtype = nsec_record.rrtype, .class = nsec_record.class, .ttl = nsec_record.ttl, .rdata = nsec_record.rdata });
    try section.append(.{ .owner = owner, .rrtype = rrsig_record.rrtype, .class = rrsig_record.class, .ttl = rrsig_record.ttl, .rdata = rrsig_record.rdata });
}

/// An extra NSEC in the authority section with an RRSIG over it made by a
/// signer no anchor names: the validator cannot authenticate the proof, so it
/// must not be able to say anything about the answer. The RRSIG RDATA is
/// returned so the caller can free it.
fn appendUnauthenticatedNsec(
    allocator: std.mem.Allocator,
    section: *dns_message.RecordSection,
    owner_text: []const u8,
    signer_text: []const u8,
    key_rdata: []const u8,
    pair: Ed25519.KeyPair,
) ![]const u8 {
    var nsec: ?dns_record.ResourceRecord = null;
    for (section.items[0..section.len]) |record| {
        if (record.rrtype.eql(.NSEC)) nsec = record;
    }
    const nsec_record = nsec orelse return Error.MalformedRdata;
    const owner = try Name.fromText(owner_text);
    const signer = try Name.fromText(signer_text);
    const extra = dns_record.ResourceRecord{ .owner = owner, .rrtype = nsec_record.rrtype, .class = nsec_record.class, .ttl = nsec_record.ttl, .rdata = nsec_record.rdata };
    const records = [_]*const dns_record.ResourceRecord{&extra};
    const rrsig_rdata = try forgeRrsig(allocator, owner, signer, RecordType.NSEC.code(), &records, key_rdata, pair);
    try section.append(extra);
    try section.append(.{
        .owner = owner,
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = extra.ttl,
        .rdata = .{ .Unknown = .{ .len = @intCast(rrsig_rdata.len), .borrowed = rrsig_rdata } },
    });
    return rrsig_rdata;
}

test "RFC 4035 section 5.4: an extra NSEC with a broken signature does not judge the denial" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The response carries an NSEC the denial does not use, and the signature
    // over it does not verify. RFC 4035 section 5.4 asks for the RRsets that
    // comprise the proof, so the extra record is not judged.
    try appendExtraNsec(&pair.response.authorities, "extra.example.com.");

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4035 section 5.4: an extra NSEC the validator cannot authenticate does not judge the denial" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The extra NSEC is signed by a zone no anchor names, so the validator
    // cannot authenticate it. It is not part of the proof, so it cannot take
    // the secure answer down to insecure either.
    const rrsig = try appendUnauthenticatedNsec(
        std.testing.allocator,
        &pair.response.authorities,
        "extra.other.example.",
        "other.example.",
        signed.dnskey,
        try ed25519TestPair(),
    );
    defer std.testing.allocator.free(rrsig);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

// ------------------------------------- RFC 4034 section 6.2 rule 3 folding
/// The case a publisher wrote the NSEC's next domain name in.
const NsecCase = enum { upper, mixed };

/// The NSEC's next domain name, published in the given case: the octets the
/// publisher put on the wire, with the name's letters in that case and the
/// type bitmap left as it was.
fn republishNsecNext(
    allocator: std.mem.Allocator,
    section: *dns_message.RecordSection,
    mode: NsecCase,
) Error![]const u8 {
    for (section.items[0..section.len]) |*record| {
        if (!record.rrtype.eql(.NSEC)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const next = Name.parse(raw, 0) catch return Error.MalformedRdata;
        const copy = try allocator.dupe(u8, raw);
        const name = copy[0..next.next_offset];
        switch (mode) {
            .upper => {
                for (name) |*byte| byte.* = std.ascii.toUpper(byte.*);
            },
            .mixed => {
                var index: usize = 0;
                while (index < name.len) {
                    const len = name[index];
                    if (len == 0) break;
                    name[index + 1] = std.ascii.toUpper(name[index + 1]);
                    for (name[index + 2 .. index + 1 + len]) |*byte| byte.* = std.ascii.toLower(byte.*);
                    index += 1 + len;
                }
            },
        }
        record.rdata = .{ .Unknown = .{ .len = @intCast(copy.len), .borrowed = copy } };
        return copy;
    }
    return Error.MalformedRdata;
}

/// The signed data a publisher that signed the octets it published would have
/// built: the RRSIG prefix, then the owner, the header and the published RDATA
/// as they are (RFC 4034 section 5.3.1). The NSEC's next domain name is not
/// folded (RFC 6840 section 5.1), so the preimage carries the published
/// octets unchanged.
fn publishedPreimage(allocator: std.mem.Allocator, response: *const dns_message.Message) Error![]u8 {
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var nsec: ?*const dns_record.ResourceRecord = null;
    var signature: ?*const dns_record.ResourceRecord = null;
    for (response.authorities.items[0..response.authorities.len]) |*record| {
        if (record.rrtype.eql(.NSEC)) nsec = record;
        if (record.rrtype.eql(.RRSIG) and rrsigCoversType(record.*, RecordType.NSEC)) signature = record;
    }
    const nsec_record = nsec orelse return Error.MalformedRdata;
    const rrsig_record = signature orelse return Error.MalformedRdata;
    const rrsig_raw = switch (rrsig_record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return Error.MalformedRdata,
    };
    const rdata = switch (nsec_record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return Error.MalformedRdata,
    };
    const rrsig = try Rrsig.at(rrsig_raw, rrsig_record.owner);
    const owner = try signedOwner(scratch.allocator(), &rrsig.owner, rrsig.labels);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, rrsig.raw[0..rrsig_fixed_len]);
    try out.appendSlice(allocator, rrsig.signer.asWire());
    try out.appendSlice(allocator, owner);
    const header = rrHeader(nsec_record.rrtype.code(), nsec_record.class.code(), rrsig.orig_ttl, rdata.len);
    try out.appendSlice(allocator, &header);
    try out.appendSlice(allocator, rdata);
    return out.toOwnedSlice(allocator);
}

/// The RRSIG over the NSEC, with its signature made over `data`: the proof a
/// publisher that signed the octets it published would have sent.
fn forgeNsecSignature(
    allocator: std.mem.Allocator,
    response: *dns_message.Message,
    data: []const u8,
    pair: Ed25519.KeyPair,
) Error![]const u8 {
    for (response.authorities.items[0..response.authorities.len]) |*record| {
        if (!record.rrtype.eql(.RRSIG) or !rrsigCoversType(record.*, RecordType.NSEC)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.MalformedRdata,
        };
        const rrsig = try Rrsig.at(raw, record.owner);
        const signature = pair.sign(data, null) catch return Error.SignatureInvalid;
        const bytes = signature.toBytes();
        if (rrsig.signature.len != bytes.len) return Error.MalformedRdata;
        const forged = try allocator.dupe(u8, raw);
        @memcpy(forged[rrsig.header_len..], &bytes);
        record.rdata = .{ .Unknown = .{ .len = @intCast(forged.len), .borrowed = forged } };
        return forged;
    }
    return Error.MalformedRdata;
}

/// The Ed25519 key the test zones are signed with, taken from the seed the
/// signer reads, so a test can sign a proof the zone itself did not.
fn ed25519TestPair() Error!Ed25519.KeyPair {
    const secret = "DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=";
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(secret) catch return Error.MalformedRdata;
    if (size != seed.len) return Error.MalformedRdata;
    std.base64.standard.Decoder.decode(seed[0..], secret) catch return Error.MalformedRdata;
    return Ed25519.KeyPair.generateDeterministic(seed) catch return Error.MalformedRdata;
}

test "RFC 6840 section 5.1: the NSEC's next domain name is not folded" {
    const allocator = std.testing.allocator;
    // The name inside the RDATA keeps the case it arrived in, and so does the
    // type bitmap, whose octets happen to be letters too.
    const rdata = [_]u8{ 3, 'W', 'W', 'W', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0, 0, 6, 0x41 };
    const canonical = try dnssec.canonicalRdata(allocator, RecordType.NSEC.code(), &rdata);
    defer allocator.free(canonical);
    try std.testing.expectEqualSlices(u8, &rdata, canonical);
}

test "RFC 4034 section 6.2 rule 3: the names inside the RDATA of a rule-3 type are folded" {
    const allocator = std.testing.allocator;
    // An MD record holds one name and nothing else, so the name is the whole
    // of its RDATA and it is signed in lowercase.
    const md = [_]u8{ 6, 'T', 'A', 'R', 'G', 'E', 'T', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0 };
    const folded_md = try dnssec.canonicalRdata(allocator, 3, &md);
    defer allocator.free(folded_md);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 6, 't', 'a', 'r', 'g', 'e', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        folded_md,
    );
}

test "the signer and the validator agree on the canonical form of a rule-3 type" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", dnskey);
    defer anchors.deinit(std.testing.allocator);

    // RFC 4034 section 6.2 rule 3: the name inside the RDATA of an MD record
    // is signed in lowercase. The signer folds it and the validator folds it,
    // so the signature the project made over the published octets verifies.
    var md = dns_rdata.Unknown{};
    md.data[0] = 6;
    @memcpy(md.data[1..7], "TARGET");
    md.data[7] = 7;
    @memcpy(md.data[8..15], "EXAMPLE");
    md.data[15] = 0;
    md.len = 16;

    const question = dns_question.Question{ .name = try Name.fromText("www.example.com."), .qtype = .fromCode(3), .qclass = .IN };
    var query = try emptyMessage(std.testing.allocator, .{ .id = 0x1234, .recursion_desired = true, .question_count = 1 }, question);
    defer query.deinit();
    var response = try emptyMessage(std.testing.allocator, .{
        .id = 0x1234,
        .qr = true,
        .recursion_desired = true,
        .recursion_available = true,
        .question_count = 1,
    }, question);
    defer response.deinit();

    const owner = try Name.fromText("www.example.com.");
    const signer = try Name.fromText("example.com.");
    const rdata_list = [_][]const u8{md.bytes()};
    const rrsig_rdata = try zone_signer.signRrset(std.testing.allocator, owner, signer, 3, &rdata_list, 3600, &key, window);
    defer std.testing.allocator.free(rrsig_rdata);
    var signature = dns_rdata.Unknown{};
    @memcpy(signature.data[0..rrsig_rdata.len], rrsig_rdata);
    signature.len = @intCast(rrsig_rdata.len);

    try response.answers.append(.{
        .owner = owner,
        .rrtype = .fromCode(3),
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .Unknown = md },
    });
    try response.answers.append(.{
        .owner = owner,
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .Unknown = signature },
    });
    response.header.answer_count = @intCast(response.answers.len);

    var parsed_query = try roundTrip(std.testing.allocator, query);
    defer parsed_query.deinit();
    var parsed_response = try roundTrip(std.testing.allocator, response);
    defer parsed_response.deinit();

    const result = try validate(std.testing.allocator, &anchors, parsed_query, parsed_response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4034 section 6.2 rule 3: a type outside the list keeps its RDATA as it arrived" {
    const allocator = std.testing.allocator;
    // A DNSKEY and a DS carry no name and an NSEC3 carries a hash, so none of
    // them is in the list and none of them changes.
    const dnskey = [_]u8{ 0x25, 0x03, 0x03, 0x0f, 'A', 'B', 'C' };
    const folded_dnskey = try dnssec.canonicalRdata(allocator, RecordType.DNSKEY.code(), &dnskey);
    defer allocator.free(folded_dnskey);
    try std.testing.expectEqualSlices(u8, &dnskey, folded_dnskey);

    const ds = [_]u8{ 0x12, 0x34, 0x03, 0x02, 'A' };
    const folded_ds = try dnssec.canonicalRdata(allocator, RecordType.DS.code(), &ds);
    defer allocator.free(folded_ds);
    try std.testing.expectEqualSlices(u8, &ds, folded_ds);

    const nsec3 = [_]u8{ 1, 0, 12, 'A', 'B' };
    const folded_nsec3 = try dnssec.canonicalRdata(allocator, RecordType.NSEC3.code(), &nsec3);
    defer allocator.free(folded_nsec3);
    try std.testing.expectEqualSlices(u8, &nsec3, folded_nsec3);
}

test "RFC 6840 section 5.1: an NSEC proof published in upper case and signed over those octets is secure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The publisher wrote the next name in upper case and signed the octets
    // it published, so the proof authenticates the absence (RFC 6840
    // section 5.1).
    const published = try republishNsecNext(std.testing.allocator, &pair.response.authorities, .upper);
    defer std.testing.allocator.free(published);
    const preimage = try publishedPreimage(std.testing.allocator, &pair.response);
    defer std.testing.allocator.free(preimage);
    const forged = try forgeNsecSignature(std.testing.allocator, &pair.response, preimage, try ed25519TestPair());
    defer std.testing.allocator.free(forged);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 6840 section 5.1: an NSEC proof whose next name is published in mixed case and signed over those octets is secure" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    const published = try republishNsecNext(std.testing.allocator, &pair.response.authorities, .mixed);
    defer std.testing.allocator.free(published);
    const preimage = try publishedPreimage(std.testing.allocator, &pair.response);
    defer std.testing.allocator.free(preimage);
    const forged = try forgeNsecSignature(std.testing.allocator, &pair.response, preimage, try ed25519TestPair());
    defer std.testing.allocator.free(forged);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 6840 section 5.1: an NSEC proof published in upper case but signed over the lowercase octets is bogus" {
    var signed = try signZoneText(std.testing.allocator, child_zone_text, ed25519_secret);
    defer signed.deinit(std.testing.allocator);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", signed.dnskey);
    defer anchors.deinit(std.testing.allocator);

    var pair = try exchange(std.testing.allocator, &signed.zone, "www.example.com.", .MX, .no_error, "nothing.example.com.", &.{"www.example.com."});
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The signature was made over other octets than the proof published, so
    // the proof authenticates nothing and the absence it supports is not
    // proved.
    const published = try republishNsecNext(std.testing.allocator, &pair.response.authorities, .upper);
    defer std.testing.allocator.free(published);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

// ------------------------------------------- RFC 4035 section 3.1.3.4

/// One NSEC RRset signed by the zone key: the record and the RRSIG over it
/// (RFC 4034 section 3.2).
fn signedNsec(
    allocator: std.mem.Allocator,
    key: *const zone_signer.Key,
    owner_text: []const u8,
    next_text: []const u8,
    bitmap: []const u8,
    ttl: u32,
) ![2]dns_record.ResourceRecord {
    const owner = try Name.fromText(owner_text);
    const next = (try Name.fromText(next_text)).asWire();
    var raw = dns_rdata.Unknown{};
    @memcpy(raw.data[0..next.len], next);
    @memcpy(raw.data[next.len..][0..bitmap.len], bitmap);
    raw.len = @intCast(next.len + bitmap.len);
    const signer = try Name.fromText("example.com.");
    const rrsig = try zone_signer.signRrset(allocator, owner, signer, RecordType.NSEC.code(), &.{raw.data[0..raw.len]}, ttl, key, window);
    defer allocator.free(rrsig);
    var signature = dns_rdata.Unknown{};
    @memcpy(signature.data[0..rrsig.len], rrsig);
    signature.len = @intCast(rrsig.len);
    return .{
        .{
            .owner = owner,
            .rrtype = .NSEC,
            .class = .IN,
            .ttl = ttl,
            .rdata = .{ .Unknown = raw },
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

/// A negative response whose Authority section holds exactly the NSEC
/// RRsets a test names, in order, each with the signature that covers it.
fn nsecExchange(
    allocator: std.mem.Allocator,
    key: *const zone_signer.Key,
    qname: []const u8,
    qtype: RecordType,
    rcode: dns_header.Rcode,
    owners: []const []const u8,
    nexts: []const []const u8,
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

    for (owners, 0..) |owner, index| {
        const pair = try signedNsec(allocator, key, owner, nexts[index], bitmaps[index], 3600);
        try response.authorities.append(pair[0]);
        try response.authorities.append(pair[1]);
    }
    response.header.authority_count = @intCast(response.authorities.len);

    var parsed_query = try roundTrip(allocator, query);
    errdefer parsed_query.deinit();
    const parsed_response = try roundTrip(allocator, response);
    return .{ .query = parsed_query, .response = parsed_response };
}

test "RFC 4035 section 3.1.3.4: the NSEC at the wildcard owner name proves the NODATA" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The closest encloser of nx.example.com. is example.com., the NSEC at
    // mail.example.com. covers the name, and the NSEC at the wildcard's own
    // name shows that the wildcard holds neither AAAA nor CNAME.
    const bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC });
    const owners = [_][]const u8{ "example.com.", "mail.example.com.", "*.example.com." };
    const nexts = [_][]const u8{ "mail.example.com.", "www.example.com.", "mail.example.com." };
    const bitmaps = [_][]const u8{ &bitmap, &bitmap, &bitmap };
    var pair = try nsecExchange(std.testing.allocator, &key, "nx.example.com.", .AAAA, .no_error, &owners, &nexts, &bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4035 section 5.4: an NXDOMAIN proven only by the encloser's NSEC is bogus" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The answer carries the apex NSEC and nothing else. It names the
    // closest encloser, but no NSEC covers nx.example.com. or
    // *.example.com., so the name's absence is not proved.
    const bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC });
    const owners = [_][]const u8{"example.com."};
    const nexts = [_][]const u8{"mail.example.com."};
    const bitmaps = [_][]const u8{&bitmap};
    var pair = try nsecExchange(std.testing.allocator, &key, "nx.example.com.", .A, .nxdomain, &owners, &nexts, &bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "RFC 4035 section 3.1.3.4: an NSEC that does not cover the query proves nothing" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The wildcard that matches nx.example.com. is *.example.com. The NSEC
    // that shows the types it holds sits at *.other.example.com., which does
    // not cover the query, so the absence is not proved.
    const bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC });
    const owners = [_][]const u8{ "example.com.", "mail.example.com.", "*.other.example.com." };
    const nexts = [_][]const u8{ "mail.example.com.", "www.example.com.", "mail.example.com." };
    const bitmaps = [_][]const u8{ &bitmap, &bitmap, &bitmap };
    var pair = try nsecExchange(std.testing.allocator, &key, "nx.example.com.", .AAAA, .no_error, &owners, &nexts, &bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
}

test "RFC 4035 section 5.4: the NSEC at the queried name still proves the NODATA" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.com.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The ordinary NODATA proof: the NSEC at the name the query named, with
    // the QTYPE and the CNAME bit clear.
    const bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC });
    const owners = [_][]const u8{"nx.example.com."};
    const nexts = [_][]const u8{"mail.example.com."};
    const bitmaps = [_][]const u8{&bitmap};
    var pair = try nsecExchange(std.testing.allocator, &key, "nx.example.com.", .AAAA, .no_error, &owners, &nexts, &bitmaps);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
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
fn nsec3Rdata(next_label: []const u8, flags: u8, bitmap: []const u8, iterations: u16) dns_rdata.Unknown {
    var next: [20]u8 = undefined;
    std.debug.assert(base32hexLabel(next_label, &next));
    var raw = dns_rdata.Unknown{};
    raw.data[0] = 1; // SHA-1 (RFC 5155 section 3)
    raw.data[1] = flags;
    std.mem.writeInt(u16, raw.data[2..4], iterations, .big);
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
    iterations: u16,
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
        const pair = try signedNsec3(allocator, key, label, nsec3Rdata(next_labels[index], flags[index], bitmaps[index], iterations), 3600);
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
    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &complete, &two_flags, &two_next, &two_bitmaps, nsec3_iterations);
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
    var incomplete = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &one, &one_flag, &one_next, &one_bitmap, nsec3_iterations);
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
    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &labels, &flags, &next_labels, &bitmaps, nsec3_iterations);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS, result.ede);
}

test "RFC 5155 section 10.3: an iteration count above the validator ceiling is not hashed" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    const apex_bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC3, .DNSKEY });
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const labels = [_][]const u8{ h_example, "00000000000000000000000000000000" };
    const flags = [_]u8{ 0, 0 };
    const next_labels = [_][]const u8{ h_ns1, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" };
    const bitmaps = [_][]const u8{ &apex_bitmap, &covering_bitmap };
    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &labels, &flags, &next_labels, &bitmaps, 65535);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS, result.ede);
}

test "RFC 9276 section 3.2: an insecure answer over an NSEC3 chain still verifies the signature over the NSEC3" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The chain of RFC 5155 Appendix A: 12 iterations, above the count of 0
    // RFC 9276 section 3.1 asks a publisher to use. The proof is complete, so
    // the answer is insecure and carries the EDE the RFC assigns to it.
    const apex_bitmap = typeBitmap(&.{ .SOA, .NS, .RRSIG, .NSEC3, .DNSKEY });
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const labels = [_][]const u8{ h_example, "00000000000000000000000000000000" };
    const flags = [_]u8{ 0, 0 };
    const next_labels = [_][]const u8{ h_ns1, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" };
    const bitmaps = [_][]const u8{ &apex_bitmap, &covering_bitmap };

    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &labels, &flags, &next_labels, &bitmaps, nsec3_iterations);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.insecure, result);
    try std.testing.expectEqual(dnssec.EDE_UNSUPPORTED_NSEC3_ITERATIONS, result.ede);

    // The same proof with a broken signature over the NSEC3 record. The
    // iteration count a validator answers insecure on must be the one the
    // zone published, so the signature over the record decides: an answer
    // that rests on a signature which does not verify is bogus.
    var broken_pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .nxdomain, &labels, &flags, &next_labels, &bitmaps, nsec3_iterations);
    defer broken_pair.query.deinit();
    defer broken_pair.response.deinit();
    const broken = try breakRrsig(std.testing.allocator, &broken_pair.response.authorities, RecordType.NSEC3);
    defer std.testing.allocator.free(broken);

    const broken_result = try validate(std.testing.allocator, &anchors, broken_pair.query, broken_pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, broken_result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, broken_result.ede);
}

test "RFC 4035 section 5.4: an NSEC3 proof that verifies leaves the answer secure" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    // The NSEC3 that matches the QNAME, over a chain that counts no
    // iterations: RFC 9276 section 3.2 does not hold the answer insecure, so
    // the answer is secure once the proof verifies.
    var digest: [20]u8 = undefined;
    dnssec.nsec3Hash(try Name.fromText("w.example."), nsec3_salt, 0, &digest);
    var label: [32]u8 = undefined;
    dnssec.base32Hex(digest, &label);
    const labels = [_][]const u8{&label};
    const flags = [_]u8{0};
    const next_labels = [_][]const u8{"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"};
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const bitmaps = [_][]const u8{&covering_bitmap};

    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .no_error, &labels, &flags, &next_labels, &bitmaps, 0);
    defer pair.query.deinit();
    defer pair.response.deinit();

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4035 section 5.4: an NSEC3 proof whose signature does not verify is bogus" {
    var key = try zone_signer.parseKey(ed25519_secret);
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(std.testing.allocator);
    defer std.testing.allocator.free(dnskey_rdata);
    var anchors = try dnskeyAnchor(std.testing.allocator, "example.", dnskey_rdata);
    defer anchors.deinit(std.testing.allocator);

    var digest: [20]u8 = undefined;
    dnssec.nsec3Hash(try Name.fromText("w.example."), nsec3_salt, 0, &digest);
    var label: [32]u8 = undefined;
    dnssec.base32Hex(digest, &label);
    const labels = [_][]const u8{&label};
    const flags = [_]u8{0};
    const next_labels = [_][]const u8{"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"};
    const covering_bitmap = typeBitmap(&.{ .RRSIG, .NSEC3 });
    const bitmaps = [_][]const u8{&covering_bitmap};

    var pair = try nsec3Exchange(std.testing.allocator, &key, "w.example.", .A, .no_error, &labels, &flags, &next_labels, &bitmaps, 0);
    defer pair.query.deinit();
    defer pair.response.deinit();

    // The signature over the NSEC3 is broken, so the proof cannot be
    // authenticated: the absence it supports is not proved and the answer is
    // bogus, not secure.
    const broken = try breakRrsig(std.testing.allocator, &pair.response.authorities, RecordType.NSEC3);
    defer std.testing.allocator.free(broken);

    const result = try validate(std.testing.allocator, &anchors, pair.query, pair.response, &.{}, now_seconds);
    try expectStatus(.bogus, result);
    try std.testing.expectEqual(dnssec.EDE_DNSSEC_BOGUS, result.ede);
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
    var opted_out = try nsec3Exchange(std.testing.allocator, &key, "ns2.example.", .DS, .no_error, &labels, &opt_out_flags, &next_labels, &bitmaps, nsec3_iterations);
    defer opted_out.query.deinit();
    defer opted_out.response.deinit();
    try expectStatus(.insecure, try validate(std.testing.allocator, &anchors, opted_out.query, opted_out.response, &.{}, now_seconds));

    // Clear the bit and the very same records stop proving anything. Without
    // Opt-Out the zone is saying the span is closed, so a delegation inside it
    // that carries no DS is a lie rather than a declared gap.
    const closed_flags = [_]u8{ 0, 0 };
    var closed = try nsec3Exchange(std.testing.allocator, &key, "ns2.example.", .DS, .no_error, &labels, &closed_flags, &next_labels, &bitmaps, nsec3_iterations);
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
    \\@ IN NSEC3PARAM 1 0 0 -
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
    \\@ IN NSEC3PARAM 1 0 0 -
    \\@ IN NSEC3PARAM 1 1 0 -
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

fn rrsigRecord(owner: Name, rrsig: []const u8, ttl: u32) dns_record.ResourceRecord {
    var raw = dns_rdata.Unknown{};
    @memcpy(raw.data[0..rrsig.len], rrsig);
    raw.len = @intCast(rrsig.len);
    return .{ .owner = owner, .rrtype = .RRSIG, .class = .IN, .ttl = ttl, .rdata = .{ .Unknown = raw } };
}

fn unknownFrom(bytes: []const u8) dns_rdata.Unknown {
    var raw = dns_rdata.Unknown{};
    @memcpy(raw.data[0..bytes.len], bytes);
    raw.len = @intCast(bytes.len);
    return raw;
}

test "RFC 4035 section 5.2: a zone reached through its parent's signed DS validates secure" {
    const allocator = std.testing.allocator;
    var root_key = try zone_signer.parseKey(ed25519_secret);
    defer root_key.deinit();
    var child_key = try zone_signer.parseKey(p256_secret);
    defer child_key.deinit();

    const root_dnskey = try root_key.dnskeyRdata(allocator);
    defer allocator.free(root_dnskey);
    const child_dnskey = try child_key.dnskeyRdata(allocator);
    defer allocator.free(child_dnskey);

    const child_owner = try Name.fromText("example.com.");
    const root_name = try Name.fromText(".");

    // The DS the parent publishes for the child: key tag, algorithm, digest
    // type 2, and the SHA-256 of the child owner's wire form and DNSKEY.
    var ds_raw: [4 + std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u16, ds_raw[0..2], dnssec.keyTag(child_dnskey), .big);
    ds_raw[2] = child_dnskey[3];
    ds_raw[3] = 2;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(child_owner.asWire());
    hasher.update(child_dnskey);
    hasher.final(ds_raw[4..]);

    const ds_rrsig = try zone_signer.signRrset(allocator, child_owner, root_name, RecordType.DS.code(), &.{ds_raw[0..]}, 3600, &root_key, window);
    defer allocator.free(ds_rrsig);
    const key_rrsig = try zone_signer.signRrset(allocator, child_owner, child_owner, RecordType.DNSKEY.code(), &.{child_dnskey}, 3600, &child_key, window);
    defer allocator.free(key_rrsig);

    const answer_address = [4]u8{ 192, 0, 2, 1 };
    const www = try Name.fromText("www.example.com.");
    const a_rrsig = try zone_signer.signRrset(allocator, www, child_owner, RecordType.A.code(), &.{answer_address[0..]}, 3600, &child_key, window);
    defer allocator.free(a_rrsig);

    const question = dns_question.Question{ .name = www, .qtype = .A, .qclass = .IN };
    var query = try emptyMessage(allocator, .{ .id = 0x1234, .recursion_desired = true, .question_count = 1 }, question);
    defer query.deinit();
    var response = try emptyMessage(allocator, .{ .id = 0x1234, .qr = true, .question_count = 1, .answer_count = 2 }, question);
    defer response.deinit();
    try response.answers.append(.{ .owner = www, .rrtype = .A, .class = .IN, .ttl = 3600, .rdata = .{ .A = answer_address } });
    try response.answers.append(rrsigRecord(www, a_rrsig, 3600));

    // The chain the iterative resolver fetched: the parent's DS RRset and the
    // child's DNSKEY RRset, each with the signature that covers it.
    const extra = [_]dns_record.ResourceRecord{
        .{ .owner = child_owner, .rrtype = .DS, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(ds_raw[0..]) } },
        rrsigRecord(child_owner, ds_rrsig, 3600),
        .{ .owner = child_owner, .rrtype = .DNSKEY, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(child_dnskey) } },
        rrsigRecord(child_owner, key_rrsig, 3600),
    };

    // The operator configured only the root key. The child's key is reached
    // from the root through the DS the root signed.
    var anchors = try dnskeyAnchor(allocator, ".", root_dnskey);
    defer anchors.deinit(allocator);

    const result = try validate(allocator, &anchors, query, response, &extra, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}

test "RFC 4035 section 5.2: a KSK anchor trusts the ZSK that signed the parent's DS" {
    const allocator = std.testing.allocator;
    // The operator anchors the root KSK. The root signs its children's DS
    // RRsets with the ZSK, which the anchored DNSKEY RRset authenticates.
    var root_ksk = try zone_signer.parseKey(ed25519_secret);
    defer root_ksk.deinit();
    var root_zsk = try zone_signer.parseKey(p256_secret);
    defer root_zsk.deinit();
    var child_key = try zone_signer.parseKey("ed25519 AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n");
    defer child_key.deinit();

    const root_ksk_dnskey = try root_ksk.dnskeyRdata(allocator);
    defer allocator.free(root_ksk_dnskey);
    const root_zsk_dnskey = try root_zsk.dnskeyRdata(allocator);
    defer allocator.free(root_zsk_dnskey);
    const child_dnskey = try child_key.dnskeyRdata(allocator);
    defer allocator.free(child_dnskey);

    const child_owner = try Name.fromText("example.com.");
    const root_name = try Name.fromText(".");

    // The root DNSKEY RRset, signed by the KSK, is what makes the ZSK a
    // trusted zone key.
    const root_rrsig = try zone_signer.signRrset(allocator, root_name, root_name, RecordType.DNSKEY.code(), &.{ root_ksk_dnskey, root_zsk_dnskey }, 3600, &root_ksk, window);
    defer allocator.free(root_rrsig);

    // The DS the root publishes for the child is signed by the root ZSK.
    var ds_raw: [4 + std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u16, ds_raw[0..2], dnssec.keyTag(child_dnskey), .big);
    ds_raw[2] = child_dnskey[3];
    ds_raw[3] = 2;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(child_owner.asWire());
    hasher.update(child_dnskey);
    hasher.final(ds_raw[4..]);
    const ds_rrsig = try zone_signer.signRrset(allocator, child_owner, root_name, RecordType.DS.code(), &.{ds_raw[0..]}, 3600, &root_zsk, window);
    defer allocator.free(ds_rrsig);
    const child_rrsig = try zone_signer.signRrset(allocator, child_owner, child_owner, RecordType.DNSKEY.code(), &.{child_dnskey}, 3600, &child_key, window);
    defer allocator.free(child_rrsig);

    const answer_address = [4]u8{ 192, 0, 2, 1 };
    const www = try Name.fromText("www.example.com.");
    const a_rrsig = try zone_signer.signRrset(allocator, www, child_owner, RecordType.A.code(), &.{answer_address[0..]}, 3600, &child_key, window);
    defer allocator.free(a_rrsig);

    const question = dns_question.Question{ .name = www, .qtype = .A, .qclass = .IN };
    var query = try emptyMessage(allocator, .{ .id = 0x1234, .recursion_desired = true, .question_count = 1 }, question);
    defer query.deinit();
    var response = try emptyMessage(allocator, .{ .id = 0x1234, .qr = true, .question_count = 1 }, question);
    defer response.deinit();
    try response.answers.append(.{ .owner = www, .rrtype = .A, .class = .IN, .ttl = 3600, .rdata = .{ .A = answer_address } });
    try response.answers.append(rrsigRecord(www, a_rrsig, 3600));

    const extra = [_]dns_record.ResourceRecord{
        .{ .owner = root_name, .rrtype = .DNSKEY, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(root_ksk_dnskey) } },
        .{ .owner = root_name, .rrtype = .DNSKEY, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(root_zsk_dnskey) } },
        rrsigRecord(root_name, root_rrsig, 3600),
        .{ .owner = child_owner, .rrtype = .DS, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(ds_raw[0..]) } },
        rrsigRecord(child_owner, ds_rrsig, 3600),
        .{ .owner = child_owner, .rrtype = .DNSKEY, .class = .IN, .ttl = 3600, .rdata = .{ .Unknown = unknownFrom(child_dnskey) } },
        rrsigRecord(child_owner, child_rrsig, 3600),
    };

    var anchors = try dnskeyAnchor(allocator, ".", root_ksk_dnskey);
    defer anchors.deinit(allocator);

    const result = try validate(allocator, &anchors, query, response, &extra, now_seconds);
    try expectStatus(.secure, result);
    try std.testing.expectEqual(@as(u16, 0), result.ede);
}
