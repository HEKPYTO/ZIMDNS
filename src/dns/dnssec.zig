/// Contract: DNSSEC serve+validate minimum (RFC 4034/4035/5155/8198/8914).
/// What this module does:
/// - DO-bit helpers and DNSSEC RRset inclusion rules for authoritative answers.
/// - Opaque-wire helpers: RRSIG validity-window check, NSEC type-bitmap denial,
///   NSEC3 (SHA-1, RFC 5155) hash and denial.
/// - A bounded aggressive cache of NSEC and NSEC3 proofs (RFC 8198
///   sections 4-5) for validators.
/// - EDE INFO-CODEs (RFC 8914): the DNSSEC-bogus codes 6-10 and the codes
///   that explain an answer the server returns without a signed verification.
/// What this module does NOT do: zone signing, cryptographic validation (no
/// RSA/ECDSA chain building and no trust-anchor management). A full-validating
/// resolver MUST NOT claim `secure` from this module alone. Presence,
/// time-window, and denial checks report `bogus`/`insecure` only; `secure`
/// requires an external cryptographic verifier over the same opaque RDATA.
/// Ownership: All values are inline or borrow caller storage; no allocation.
/// Errors: Malformed opaque RDATA is reported as typed errors; no I/O.
const std = @import("std");
const RecordType = @import("types.zig").RecordType;
const Name = @import("name.zig").Name;
const dns_message = @import("message.zig");
const dns_writer = @import("writer.zig");
const record_mod = @import("record.zig");
const rdata_mod = @import("rdata.zig");

pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_SIGNATURE_EXPIRED: u16 = 7;
pub const EDE_SIGNATURE_NOT_YET_VALID: u16 = 8;
pub const EDE_DNSKEY_MISSING: u16 = 9;
pub const EDE_RRSIGS_MISSING: u16 = 10;
/// RFC 8914 section 4.2: the zone's DNSKEY RRset held only algorithms this
/// server cannot verify with.
pub const EDE_UNSUPPORTED_DNSKEY_ALGORITHM: u16 = 1;
/// RFC 8914 section 4.3: the zone's DS RRset held only digest types this
/// server cannot compute.
pub const EDE_UNSUPPORTED_DS_DIGEST_TYPE: u16 = 2;
/// RFC 8914 section 4.6: the security status of the answer could not be
/// determined.
pub const EDE_DNSSEC_INDETERMINATE: u16 = 5;
/// RFC 8914 section 4.12: no DNSKEY of the zone carried the Zone Key flag.
pub const EDE_NO_ZONE_KEY_BIT: u16 = 11;
/// RFC 9276 section 6: the NSEC3 chain carries an iteration count this build
/// does not treat the answer it proves as secure over.
pub const EDE_UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;

/// RFC 8914 EXTRA-TEXT purpose strings for the INFO-CODEs above.
pub fn edeText(code: u16) []const u8 {
    return switch (code) {
        EDE_DNSSEC_BOGUS => "dnssec bogus",
        EDE_SIGNATURE_EXPIRED => "signature expired",
        EDE_SIGNATURE_NOT_YET_VALID => "signature not yet valid",
        EDE_DNSKEY_MISSING => "dnskey missing",
        EDE_RRSIGS_MISSING => "rrsigs missing",
        EDE_UNSUPPORTED_DNSKEY_ALGORITHM => "unsupported dnskey algorithm",
        EDE_UNSUPPORTED_DS_DIGEST_TYPE => "unsupported ds digest type",
        EDE_DNSSEC_INDETERMINATE => "dnssec indeterminate",
        EDE_NO_ZONE_KEY_BIT => "no zone key bit set",
        EDE_UNSUPPORTED_NSEC3_ITERATIONS => "unsupported nsec3 iterations",
        else => "",
    };
}

pub const Error = error{
    MalformedRrsig,
    MalformedNsec,
    MalformedNsec3,
    NameTooLong,
};

/// True for the proof/key RRsets this minimum serves (RFC 4034 + RFC 5155).
pub fn isDnssecType(rrtype: RecordType) bool {
    const code = rrtype.code();
    return code == RecordType.DS.code() or
        code == RecordType.RRSIG.code() or
        code == RecordType.NSEC.code() or
        code == RecordType.DNSKEY.code() or
        code == RecordType.NSEC3.code() or
        code == RecordType.NSEC3PARAM.code();
}

/// Proof RRsets (signatures and denial records) are only useful to a validator
/// that set DO=1. Key/data RRsets (DNSKEY/DS) are ordinary answer data and are
/// always eligible. An explicit query for a proof type is always answered.
pub fn shouldInclude(rrtype: RecordType, qtype: RecordType, dnssec_ok: bool) bool {
    if (rrtype.eql(qtype)) return true;
    if (dnssec_ok) return true;
    const code = rrtype.code();
    return code != RecordType.RRSIG.code() and
        code != RecordType.NSEC.code() and
        code != RecordType.NSEC3.code() and
        code != RecordType.NSEC3PARAM.code();
}
/// Drop proof RRsets (RRSIG/NSEC/NSEC3/NSEC3PARAM) from every section unless
/// the QTYPE named them explicitly, updating the section counts. DNSKEY/DS
/// answers are ordinary data and are always kept. Shared by the authoritative
/// builder (RFC 3597) and the validating forwarder (RFC 3225 section 3): a
/// query with the DO bit clear must not be answered with security RRs.
pub fn stripProofRecords(message: *dns_message.Message, qtype: RecordType) void {
    stripProofSection(&message.answers, qtype);
    stripProofSection(&message.authorities, qtype);
    stripProofSection(&message.additionals, qtype);
    message.header.answer_count = @intCast(message.answers.len);
    message.header.authority_count = @intCast(message.authorities.len);
    message.header.additional_count = @intCast(message.additionals.len);
}

fn stripProofSection(section: *dns_message.RecordSection, qtype: RecordType) void {
    var write_index: usize = 0;
    var read_index: usize = 0;
    while (read_index < section.len) : (read_index += 1) {
        const record = section.items[read_index];
        if (!shouldInclude(record.rrtype, qtype, false)) continue;
        section.items[write_index] = record;
        write_index += 1;
    }
    section.len = write_index;
}

pub const RrsigTimeStatus = enum {
    valid,
    expired,
    not_yet_valid,
};

/// Check the RRSIG validity window (RFC 4035 section 5.3.1) from opaque wire
/// RDATA. Fixed offsets: expiration at [8..12], inception at [12..16].
/// This checks freshness only, never the cryptographic signature.
pub fn rrsigTimeStatus(rrsig_rdata: []const u8, now_seconds: u32) Error!RrsigTimeStatus {
    if (rrsig_rdata.len < 18) return Error.MalformedRrsig;
    const expiration = std.mem.readInt(u32, rrsig_rdata[8..][0..4], .big);
    const inception = std.mem.readInt(u32, rrsig_rdata[12..][0..4], .big);
    // Serial-arithmetic comparison per RFC 4034 section 5.3.1.
    if (now_seconds != expiration and now_seconds != inception) {
        const expired = @as(i32, @bitCast(now_seconds -% expiration)) > 0;
        const premature = @as(i32, @bitCast(inception -% now_seconds)) > 0;
        if (expired) return .expired;
        if (premature) return .not_yet_valid;
    }
    return .valid;
}

pub fn rrsigTimeEde(status: RrsigTimeStatus) ?u16 {
    return switch (status) {
        .valid => null,
        .expired => EDE_SIGNATURE_EXPIRED,
        .not_yet_valid => EDE_SIGNATURE_NOT_YET_VALID,
    };
}

/// Type-covered field (RFC 4034 section 3.1) from opaque RRSIG RDATA.
pub fn rrsigCovers(rrsig_rdata: []const u8) Error!u16 {
    if (rrsig_rdata.len < 18) return Error.MalformedRrsig;
    return std.mem.readInt(u16, rrsig_rdata[0..2], .big);
}

// ------------------------------------------------------- canonical form

/// The names an opaque RDATA of a rule-3 type holds: the octets before the
/// first name and how many names follow.
const OpaqueNames = struct {
    prefix: usize,
    count: usize,
};

/// RFC 4034 section 6.2 rule 3: the names inside the RDATA of these types are
/// signed in lowercase. RFC 6840 section 5.1 corrects the list: the NSEC's
/// next domain name is not folded, and HINFO holds no name at all.
fn opaqueNames(code: u16, raw: []const u8) ?OpaqueNames {
    return switch (code) {
        3, 4, 7, 8, 9 => .{ .prefix = 0, .count = 1 }, // MD MF MB MG MR
        14 => .{ .prefix = 0, .count = 2 }, // MINFO
        24 => .{ .prefix = 18, .count = 1 }, // SIG
        26 => .{ .prefix = 2, .count = 2 }, // PX
        30 => .{ .prefix = 0, .count = 1 }, // NXT
        36 => .{ .prefix = 2, .count = 1 }, // KX
        38 => a6Names(raw), // A6
        else => null,
    };
}

/// RFC 2874 section 3.1.1: the A6 RDATA is the prefix length, the address
/// suffix the prefix length leaves over, and the prefix name. The name is
/// absent when the prefix length is zero or 128.
fn a6Names(raw: []const u8) ?OpaqueNames {
    if (raw.len < 1) return null;
    const length = raw[0];
    if (length > 128) return null;
    const suffix: usize = if (length == 128) 0 else (128 - length + 7) / 8;
    const count: usize = if (length == 0 or length == 128) 0 else 1;
    return .{ .prefix = 1 + suffix, .count = count };
}

/// The canonical RDATA of a record: the names it holds are folded to
/// lowercase (RFC 4034 section 6.2 rule 3) and every other octet is left as
/// it arrived. The NSEC's next domain name is the one exception: RFC 6840
/// section 5.1 keeps it as the publisher wrote it, because the proof is
/// authenticated over the octets it published. A name the RDATA does not hold
/// where the type's RFC puts it is left alone, and the signature over it then
/// fails to verify.
pub fn canonicalRdata(allocator: std.mem.Allocator, rrtype: u16, rdata: []const u8) std.mem.Allocator.Error![]const u8 {
    const layout = opaqueNames(rrtype, rdata) orelse return allocator.dupe(u8, rdata);
    const out = try allocator.dupe(u8, rdata);
    var offset = layout.prefix;
    var index: usize = 0;
    while (index < layout.count) : (index += 1) {
        if (offset > out.len) break;
        const parsed = Name.parse(out, offset) catch break;
        // A compressed name is not the canonical form, so it is left as it is.
        if (parsed.name.asWire().len != parsed.next_offset - offset) break;
        @memcpy(out[offset..parsed.next_offset], parsed.name.asWire());
        offset = parsed.next_offset;
    }
    return out;
}

const NsecBitmap = struct {
    windows: []const u8,
};

/// Split opaque NSEC RDATA into the next-owner wire name and the type bitmap.
/// The next name is scanned as bare wire labels (no compression on the wire).
fn splitNsec(rrdata: []const u8) Error!struct { next_len: usize, bitmap: []const u8 } {
    var cursor: usize = 0;
    while (cursor < rrdata.len) {
        const len = rrdata[cursor];
        if (len == 0) {
            cursor += 1;
            break;
        }
        if ((len & 0xc0) != 0 or len > 63 or cursor + 1 + len > rrdata.len) return Error.MalformedNsec;
        cursor += 1 + len;
    } else return Error.MalformedNsec;
    return .{ .next_len = cursor, .bitmap = rrdata[cursor..] };
}

/// True when the NSEC type bitmap (RFC 4034 section 4.1.2) lists `qtype`.
pub fn nsecBitmapHasType(bitmap: []const u8, qtype: u16) bool {
    var offset: usize = 0;
    while (offset + 2 <= bitmap.len) {
        const window = bitmap[offset];
        const window_len = bitmap[offset + 1];
        offset += 2;
        if (window_len == 0 or window_len > 32 or offset + window_len > bitmap.len) return false;
        if (window == qtype / 256) {
            const bit = qtype % 256;
            if (bit / 8 >= window_len) return false;
            return (bitmap[offset + bit / 8] & (@as(u8, 0x80) >> @intCast(bit % 8))) != 0;
        }
        offset += window_len;
    }
    return false;
}

/// True when opaque NSEC RDATA denies `qtype` at an exact owner match: the
/// bitmap must be strictly well-formed, must NOT list the QTYPE, and must
/// list NSEC (RFC 4035 section 3.1). Any malformed bitmap (bad window
/// length, truncated window, trailing garbage) is Error.MalformedNsec,
/// never a denial: the lenient lookup below reports malformed input as
/// absent, which would otherwise synthesize a false denial here.
pub fn nsecDeniesType(nsec_rdata: []const u8, qtype: u16) Error!bool {
    const split = try splitNsec(nsec_rdata);
    try nsecBitmapValidate(split.bitmap);
    if (!nsecBitmapHasType(split.bitmap, RecordType.NSEC.code())) return Error.MalformedNsec;
    return !nsecBitmapHasType(split.bitmap, qtype);
}

/// Strict validation for a cached NSEC type bitmap (RFC 4034 section 4.1.2):
/// every window header must fit, lengths must be 1..32, and no trailing
/// bytes may remain. `nsecBitmapHasType` reports malformed input as false,
/// which is safe for presence checks but would synthesize a false denial on
/// the exact path below, so the deny path validates first and fails closed.
fn nsecBitmapValidate(bitmap: []const u8) Error!void {
    if (bitmap.len == 0) return Error.MalformedNsec;
    var offset: usize = 0;
    while (offset + 2 <= bitmap.len) {
        const window_len = bitmap[offset + 1];
        if (window_len == 0 or window_len > 32) return Error.MalformedNsec;
        offset += 2;
        if (offset + window_len > bitmap.len) return Error.MalformedNsec;
        offset += window_len;
    }
    if (offset != bitmap.len) return Error.MalformedNsec;
}

/// Exact-owner denial over a cached bitmap: the bitmap must be well-formed
/// and list NSEC (RFC 4035 section 3.1); denial holds when it lacks `qtype`.
fn nsecBitmapDeniesType(bitmap: []const u8, qtype: u16) Error!bool {
    try nsecBitmapValidate(bitmap);
    if (!nsecBitmapHasType(bitmap, RecordType.NSEC.code())) return Error.MalformedNsec;
    return !nsecBitmapHasType(bitmap, qtype);
}

/// RFC 6840 section 4.3: a NODATA proof needs the QTYPE bit clear AND the CNAME
/// bit clear in the same type bitmap. Without the second test an attacker can
/// strip the CNAME RRset out of a positive response and the stripped response
/// then reads as a valid NODATA, which is the whole attack. The bitmap is
/// validated first: malformed input is an error, never a denial.
pub fn bitmapDeniesTypeAndCname(bitmap: []const u8, qtype: u16) Error!bool {
    try nsecBitmapValidate(bitmap);
    return !nsecBitmapHasType(bitmap, qtype) and !nsecBitmapHasType(bitmap, RecordType.CNAME.code());
}

/// RFC 4034 Appendix B: the DNSKEY RDATA summed as big-endian 16-bit groups,
/// with the carry folded back in once before the result is truncated. The fold
/// is not decoration -- the sum exceeds 16 bits for any real DNSKEY, and
/// leaving it out yields a tag lower than the RFC's by the carry count. An
/// odd-length RDATA pads the final octet on the right, so that octet
/// contributes its high byte only.
pub fn keyTag(dnskey_rdata: []const u8) u16 {
    var sum: u64 = 0;
    var index: usize = 0;
    while (index + 1 < dnskey_rdata.len) : (index += 2) {
        sum += std.mem.readInt(u16, dnskey_rdata[index..][0..2], .big);
    }
    if (dnskey_rdata.len % 2 != 0) sum += @as(u64, dnskey_rdata[dnskey_rdata.len - 1]) << 8;
    return @truncate((sum + ((sum >> 16) & 0xffff)) & 0xffff);
}

/// Canonical DNS name order (RFC 4034 section 6.1): compare labels from the
/// root, case-insensitively. Returns <0, 0, >0 like mem.order.
pub fn compareNames(a: Name, b: Name) i8 {
    const a_wire = a.asWire();
    const b_wire = b.asWire();
    // A 255-octet wire name holds at most 127 single-octet labels plus the
    // root, so 128 slots compare every valid name without truncation.
    var a_labels: [128][]const u8 = undefined;
    var b_labels: [128][]const u8 = undefined;
    const a_count = splitLabelsBuf(a_wire, &a_labels);
    const b_count = splitLabelsBuf(b_wire, &b_labels);
    var depth: usize = 1;
    while (true) {
        const a_label: ?[]const u8 = if (depth <= a_count) a_labels[a_count - depth] else null;
        const b_label: ?[]const u8 = if (depth <= b_count) b_labels[b_count - depth] else null;
        if (a_label == null and b_label == null) return 0;
        if (a_label == null) return -1;
        if (b_label == null) return 1;
        const order = orderLabel(a_label.?, b_label.?);
        if (order != 0) return order;
        depth += 1;
    }
}

fn splitLabelsBuf(wire: []const u8, out: *[128][]const u8) usize {
    var count: usize = 0;
    var cursor: usize = 0;
    while (cursor < wire.len and count < out.len) {
        const len = wire[cursor];
        if (len == 0) break;
        if ((len & 0xc0) != 0 or len > 63 or cursor + 1 + len > wire.len) break;
        out[count] = wire[cursor + 1 .. cursor + 1 + len];
        count += 1;
        cursor += 1 + len;
    }
    return count;
}

fn orderLabel(a: []const u8, b: []const u8) i8 {
    const min = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min) : (i += 1) {
        const x = std.ascii.toLower(a[i]);
        const y = std.ascii.toLower(b[i]);
        if (x < y) return -1;
        if (x > y) return 1;
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// True when `qname` falls strictly inside the NSEC span (owner, next):
/// owner < qname < next in canonical order, the RFC 4035 denial condition.
pub fn nsecCovers(owner: Name, next: Name, qname: Name) bool {
    return compareNames(owner, qname) < 0 and compareNames(qname, next) < 0;
}

/// NSEC3 hash (RFC 5155 section 5): iterated salted SHA-1 over the
/// canonical owner wire name. `out` must be 20 bytes (SHA-1).
pub fn nsec3Hash(owner: Name, salt: []const u8, iterations: u16, out: *[20]u8) void {
    var digest: [20]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    // RFC 5155 section 5 hashes the canonical owner name, so the case the
    // name arrived with never reaches the digest.
    const canonical = owner.folded();
    hasher.update(canonical.asWire());
    hasher.update(salt);
    hasher.final(&digest);
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(&digest);
        hasher.update(salt);
        hasher.final(&digest);
    }
    @memcpy(out, &digest);
}

/// base32hex (RFC 4648 section 7) of a hash, the form an NSEC3 owner name
/// takes (RFC 5155 section 3). The canonical form is lowercase, so the label
/// is written that way.
pub fn base32Hex(hash: [20]u8, out: *[32]u8) void {
    const alphabet = "0123456789abcdefghijklmnopqrstuv";
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

pub const Denial = enum {
    nxdomain,
    nodata,
};

/// The number of records a cached wildcard RRset holds. The RRSIG covers the
/// whole RRset (RFC 4035 section 5.3.2), so a wildcard the cache cannot hold
/// whole is not cached at all and the resolver falls back upstream
/// (RFC 8198 section 5.3).
pub const max_wildcard_records = 4;

/// The wire length of the longest record the cache holds: an owner name, the
/// record's own fields, and an RDATA of the largest inline type.
const max_cached_record_wire_len = 255 + 10 + rdata_mod.max_unknown_len;

/// The bound on the RDATA of a proof record a cut answer carries. It holds
/// an RRSIG with an RSA-2048 signature and a full-length signer name.
pub const max_proof_rdata_len: usize = 640;
/// The wire form of a proof record: the owner name, the type, the class,
/// the TTL, and the RDATA.
pub const max_proof_wire_len: usize = 255 + 10 + max_proof_rdata_len;

/// A proof record on the wire, so a cut answer carries the bytes the
/// upstream answer published and not a rebuilt copy.
pub const ProofRecord = struct {
    wire: [max_proof_wire_len]u8 = @as([max_proof_wire_len]u8, @splat(@as(u8, 0))),
    len: u16 = 0,

    pub fn bytes(self: *const ProofRecord) []const u8 {
        return self.wire[0..self.len];
    }
};

/// The proof a cut answer carries (RFC 8020 section 2): the NSEC records the
/// denial rests on, each with the RRSIG that covers it.
pub const Proof = struct {
    records: [6]ProofRecord = @splat(ProofRecord{}),
    len: u8 = 0,

    /// Add a proof record, skipping an empty one and a record that is
    /// already there: RFC 4035 section 3.1.3.2 wants a record that proves
    /// two points included once.
    fn add(self: *Proof, record: ProofRecord) void {
        if (record.len == 0) return;
        for (self.records[0..self.len]) |existing| {
            if (std.mem.eql(u8, existing.bytes(), record.bytes())) return;
        }
        if (self.len >= self.records.len) return;
        self.records[self.len] = record;
        self.len += 1;
    }
};

/// The proof record an upstream answer carried with a proving NSEC or NSEC3:
/// the record itself and the RRSIG that covers it (RFC 4035 section 3.1.3).
pub const SignedProof = struct {
    record: ?record_mod.ResourceRecord = null,
    rrsig: ?record_mod.ResourceRecord = null,
};

/// The NSEC3 chain a cached proof belongs to (RFC 5155 section 7.1): the
/// zone it covers, the iteration count, and the salt. The hash algorithm is
/// always SHA-1 here.
pub const Nsec3Chain = struct {
    zone: Name = Name.root(),
    iterations: u16 = 0,
    salt: [255]u8 = @as([255]u8, @splat(@as(u8, 0))),
    salt_len: u8 = 0,
};

/// RFC 5155 section 7.1: the NSEC3 span test. The chain is ordered by the
/// hash read as an unsigned octet sequence, and the last NSEC3 of a chain
/// points back at the first, so the span wraps.
pub fn nsec3Covers(owner: [20]u8, next: [20]u8, target: [20]u8) bool {
    const order = std.mem.order(u8, &owner, &next);
    if (order == .eq) return !std.mem.eql(u8, &owner, &target);
    if (order == .lt) {
        return std.mem.order(u8, &owner, &target) == .lt and std.mem.order(u8, &target, &next) == .lt;
    }
    return std.mem.order(u8, &owner, &target) == .lt or std.mem.order(u8, &target, &next) == .lt;
}

/// A denial a cached proof gives, with the zone SOA that arrived with the
/// proof (RFC 2308 section 3). The SOA is null when the proof was cached
/// without one, and such a denial must not be cached (RFC 2308 section 5).
/// The proof is null when the upstream answer carried no proof that can be
/// returned, and the denial is served all the same.
pub const ProvenDenial = struct {
    denial: Denial,
    soa: ?record_mod.ResourceRecord,
    proof: ?Proof = null,
};

/// The answer a cached wildcard proof gives (RFC 8198 section 5.3). The
/// records are the wildcard's own records; the owner name they are sent
/// under is the queried name, not the wildcard's (RFC 4035 section 5.3.2).
pub const WildcardAnswer = struct {
    /// The wildcard the records come from, e.g. "*.example.".
    wildcard: Name,
    /// The zone the wildcard belongs to: the signer name of the signature
    /// that covers it (RFC 4035 section 5.3.1).
    zone: Name,
    /// The wildcard's records, of the queried type.
    records: [max_wildcard_records]record_mod.ResourceRecord = undefined,
    len: u8 = 0,
    /// The proof the answer rests on (RFC 8020 section 2).
    proof: ?Proof = null,
    /// The RRSIG that covers the wildcard RRset (RFC 4035 section 5.3.2).
    rrsig: ?ProofRecord = null,
    /// The TTL the answer carries: the TTL of the wildcard's records, held
    /// down to the life of the proof (RFC 8198 section 4).
    ttl: u32,
};

/// Keep a proof record as the upstream answer published it, when it can be
/// carried in another message unchanged. Every name in its RDATA must be
/// written out in full: a compression pointer names a place in the message
/// it came from and would name another place here.
fn keepProof(out: *ProofRecord, record: record_mod.ResourceRecord) void {
    const rdata = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return,
    };
    if (rdata.len > max_proof_rdata_len) return;
    if (!proofNamesUncompressed(record.rrtype, rdata)) return;
    var writer = dns_writer.Writer.init(&out.wire);
    record.encode(&writer) catch return;
    out.len = @intCast(writer.written().len);
}

/// True when every name in the RDATA of a proof record is written out in
/// full. The NSEC RDATA starts with the next owner name (RFC 4034 section
/// 4.1.2) and the RRSIG RDATA carries the signer's name after its
/// 18-octet header (RFC 4034 section 3.2). The NSEC3 RDATA carries the
/// next hashed owner name in binary form (RFC 5155 section 3.1.7), so it
/// holds no name at all.
fn proofNamesUncompressed(rrtype: RecordType, rdata: []const u8) bool {
    const code = rrtype.code();
    const offset: usize = if (code == RecordType.NSEC.code())
        0
    else if (code == RecordType.RRSIG.code())
        18
    else if (code == RecordType.NSEC3.code())
        return true
    else
        return false;
    if (rdata.len <= offset) return false;
    var index = offset;
    while (index < rdata.len) {
        const len = rdata[index];
        if (len == 0) return true;
        if ((len & 0xc0) != 0 or len > 63) return false;
        index += 1 + len;
    }
    return false;
}

/// True when a proof record is malformed because a name in its RDATA was
/// compressed. RFC 4034 section 4.1.1 says a sender MUST NOT compress the
/// NSEC next domain name, and RFC 3597 section 4 forbids compression in the
/// RDATA of a type that is not well known, so such a record cannot be used
/// as a proof.
pub fn proofMalformed(record: record_mod.ResourceRecord) bool {
    switch (record.rrtype.code()) {
        RecordType.NSEC.code(), RecordType.RRSIG.code(), RecordType.NSEC3.code() => {},
        else => return false,
    }
    const rdata = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return false,
    };
    return !proofNamesUncompressed(record.rrtype, rdata);
}

/// Parent name with the leftmost label stripped; null for the root and for
/// malformed wire input. Used to walk the ancestor chain toward the closest
/// encloser on the RFC 8198 section 5 path.
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

/// The signer's name of an RRSIG RDATA (RFC 4034 section 3.2): the zone
/// the signature was made in, which is the zone the covered RRset
/// belongs to (RFC 4035 section 5.3.1). Null when the name is compressed,
/// which RFC 4034 section 3.2 forbids.
pub fn rrsigSigner(rrsig_rdata: []const u8) ?Name {
    if (!proofNamesUncompressed(.RRSIG, rrsig_rdata)) return null;
    const parsed = Name.parse(rrsig_rdata, 18) catch return null;
    return parsed.name;
}

/// The Labels field of an RRSIG RDATA (RFC 4034 section 3.2.5): the label
/// count of the original owner name, the wildcard label not counted.
pub fn rrsigLabels(rrsig_rdata: []const u8) ?u8 {
    if (rrsig_rdata.len < 4) return null;
    return rrsig_rdata[3];
}

/// The label count of a name, the root label not counted.
pub fn labelCount(name: Name) u8 {
    const wire = name.asWire();
    var count: u8 = 0;
    var index: usize = 0;
    while (index < wire.len and wire[index] != 0) : (count += 1) {
        if (wire[index] > 63) break;
        index += 1 + wire[index];
    }
    return count;
}

/// The wildcard owner name an RRSIG's Labels field names: "*." followed by
/// the rightmost labels of the queried name (RFC 4035 section 5.3.2). Null
/// when the name would exceed the 255-octet wire limit.
pub fn wildcardFromLabels(qname: Name, labels: u8) ?Name {
    const wire = qname.asWire();
    var offsets: [128]usize = undefined;
    var count: usize = 0;
    var index: usize = 0;
    while (index < wire.len and wire[index] != 0) {
        if (wire[index] > 63 or count >= offsets.len) return null;
        offsets[count] = index;
        count += 1;
        index += 1 + wire[index];
    }
    if (labels == 0 or labels > count) return null;
    const tail = wire[offsets[count - labels]..];
    if (tail.len + 2 > 255) return null;
    var out = Name{};
    out.wire[0] = 1;
    out.wire[1] = '*';
    @memcpy(out.wire[2..][0..tail.len], tail);
    out.wire_len = @intCast(tail.len + 2);
    return out;
}

/// Wire name for the wildcard at the closest encloser ("*." + encloser);
/// null when it would exceed the 255-octet wire limit.
fn wildcardName(closest_encloser: Name) ?Name {
    const wire = closest_encloser.asWire();
    if (wire.len + 2 > 255) return null;
    var out = Name{};
    out.wire[0] = 1;
    out.wire[1] = '*';
    @memcpy(out.wire[2..][0..wire.len], wire);
    out.wire_len = @intCast(wire.len + 2);
    return out;
}

/// True when two NSEC3 chains are the same chain: the same zone, the same
/// iteration count, and the same salt (RFC 5155 section 7.1).
fn sameChain(a: Nsec3Chain, b: Nsec3Chain) bool {
    if (!a.zone.eql(&b.zone)) return false;
    if (a.iterations != b.iterations) return false;
    return std.mem.eql(u8, a.salt[0..a.salt_len], b.salt[0..b.salt_len]);
}

/// The hash a name has in an NSEC3 chain (RFC 5155 section 5).
fn nsec3HashIn(chain: Nsec3Chain, name: Name) [20]u8 {
    var out: [20]u8 = undefined;
    nsec3Hash(name, chain.salt[0..chain.salt_len], chain.iterations, &out);
    return out;
}

/// True when `zone` is an ancestor of `name`, or the name itself.
fn isWithin(name: Name, zone: Name) bool {
    var current = name;
    while (true) {
        if (current.eql(&zone)) return true;
        current = parentName(current) orelse return false;
    }
}

/// Bounded aggressive cache of NSEC and NSEC3 proofs (RFC 8198 sections
/// 4-5). Stores proving NSEC and NSEC3 RRs; `deny` synthesizes
/// NXDOMAIN/NODATA without an upstream query.
pub const AggressiveCache = struct {
    pub const capacity = 16;

    /// Upper bound on entry lifetime in seconds. RFC 8198 section 4 bounds
    /// aggressive use by the proving NSEC RRset TTL; the cap additionally
    /// bounds how stale a proof can get under an outsized zone TTL.
    pub const max_entry_ttl_seconds: i64 = 24 * 60 * 60;

    const Entry = struct {
        valid: bool = false,
        owner: Name = Name.root(),
        next: Name = Name.root(),
        bitmap: [64]u8 = @as([64]u8, @as([64]u8, @splat(@as(u8, 0)))),
        bitmap_len: u8 = 0,
        hashed_owner: [20]u8 = @as([20]u8, @as([20]u8, @splat(@as(u8, 0)))),
        is_nsec3: bool = false,
        /// The NSEC3 chain this entry belongs to (RFC 5155 section 7.1).
        nsec3_chain: Nsec3Chain = .{},
        /// The next hashed owner name of the NSEC3 record (RFC 5155
        /// section 3.1.7): the hash the chain is ordered by.
        nsec3_next: [20]u8 = @as([20]u8, @as([20]u8, @splat(@as(u8, 0)))),
        /// The Opt-Out flag of the NSEC3 record (RFC 5155 section 3.1.2.1).
        nsec3_opt_out: bool = false,
        /// The zone SOA that arrived with this proof. A negative answer must
        /// carry it (RFC 2308 section 3), and a denial without one must not
        /// be cached (RFC 2308 section 5).
        soa: ?record_mod.ResourceRecord = null,
        /// The proof record as the upstream answer published it and the
        /// RRSIG that covers it. RFC 8020 section 2 returns them with a cut
        /// answer.
        proof_record: ProofRecord = .{},
        proof_rrsig: ProofRecord = .{},
        /// Unix seconds after which the proof must no longer deny (RFC 8198
        /// section 4). Always derived as now + min(ttl, cap) at insert.
        expires_at: i64 = 0,
    };

    /// A wildcard RRset the cache holds (RFC 8198 section 5.3). The records
    /// are the wildcard's own, and the answer sends them under the queried
    /// name (RFC 4035 section 5.3.2).
    const WildcardEntry = struct {
        valid: bool = false,
        name: Name = Name.root(),
        /// The zone the wildcard belongs to (RFC 4035 section 5.3.1).
        zone: Name = Name.root(),
        records: [max_wildcard_records]record_mod.ResourceRecord = undefined,
        len: u8 = 0,
        /// The RRSIG that covers the wildcard RRset (RFC 4035 section 5.3.2).
        rrsig: ProofRecord = .{},
        expires_at: i64 = 0,
    };

    entries: [capacity]Entry = @splat(Entry{}),
    next_slot: usize = 0,

    /// The wildcard RRsets the cache holds. RFC 8198 section 5.3 lets a
    /// resolver answer from the wildcard it has, and requires it to fall
    /// back to the authoritative servers when the wildcard is not there.
    wildcards: [4]WildcardEntry = @splat(WildcardEntry{}),
    next_wildcard: usize = 0,

    /// Cache a proving NSEC RRset. The proof records the upstream answer
    /// published are kept with it, so a cut answer can return them
    /// (RFC 8020 section 2).
    pub fn insertNsec(self: *AggressiveCache, owner: Name, next: Name, bitmap: []const u8, now: i64, ttl: u32, soa: ?record_mod.ResourceRecord, proof: SignedProof) void {
        const slot = &self.entries[self.next_slot];
        self.next_slot = (self.next_slot + 1) % capacity;
        slot.* = .{};
        slot.valid = true;
        slot.owner = owner;
        slot.next = next;
        const len = @min(bitmap.len, slot.bitmap.len);
        @memcpy(slot.bitmap[0..len], bitmap[0..len]);
        slot.bitmap_len = @intCast(len);
        slot.soa = soa;
        slot.expires_at = now +| @min(@as(i64, ttl), max_entry_ttl_seconds);
        // A proof that names another owner is not this entry's proof.
        if (proof.record) |record| {
            if (record.owner.eql(&owner)) {
                keepProof(&slot.proof_record, record);
                if (proof.rrsig) |rrsig| keepProof(&slot.proof_rrsig, rrsig);
            }
        }
    }

    /// Cache a proving NSEC3 record (RFC 5155 section 3). The chain it
    /// belongs to, its next hashed owner name, and its type bitmap are kept,
    /// so a later query the record covers can be denied from it.
    pub fn insertNsec3(self: *AggressiveCache, owner: Name, owner_hash: [20]u8, next_hash: [20]u8, opt_out: bool, iterations: u16, salt: []const u8, bitmap: []const u8, now: i64, ttl: u32, soa: ?record_mod.ResourceRecord, proof: SignedProof) void {
        const slot = &self.entries[self.next_slot];
        self.next_slot = (self.next_slot + 1) % capacity;
        slot.* = .{};
        slot.valid = true;
        slot.is_nsec3 = true;
        slot.owner = owner;
        slot.hashed_owner = owner_hash;
        slot.nsec3_next = next_hash;
        slot.nsec3_opt_out = opt_out;
        const salt_len = @min(salt.len, slot.nsec3_chain.salt.len);
        slot.nsec3_chain = .{
            .zone = parentName(owner) orelse Name.root(),
            .iterations = iterations,
            .salt_len = @intCast(salt_len),
        };
        @memcpy(slot.nsec3_chain.salt[0..salt_len], salt[0..salt_len]);
        const len = @min(bitmap.len, slot.bitmap.len);
        @memcpy(slot.bitmap[0..len], bitmap[0..len]);
        slot.bitmap_len = @intCast(len);
        slot.soa = soa;
        slot.expires_at = now +| @min(@as(i64, ttl), max_entry_ttl_seconds);
        if (proof.record) |record| {
            if (record.owner.eql(&owner)) {
                keepProof(&slot.proof_record, record);
                if (proof.rrsig) |rrsig| keepProof(&slot.proof_rrsig, rrsig);
            }
        }
    }

    /// Drop proofs past their expiry. Lazy eviction on every deny path, so
    /// no timer is needed; re-inserting a proof refreshes its expiry. A
    /// zero TTL therefore denies nothing: the entry expires immediately.
    fn evictExpired(self: *AggressiveCache, now: i64) void {
        for (&self.entries) |*entry| {
            if (entry.valid and now >= entry.expires_at) entry.valid = false;
        }
        for (&self.wildcards) |*entry| {
            if (entry.valid and now >= entry.expires_at) entry.valid = false;
        }
    }

    /// RFC 8198 section 5.3: cache the wildcard RRset an upstream answer
    /// carried, so a later query the wildcard covers is answered from it.
    /// The records are the wildcard's own, and the answer sends them under
    /// the queried name (RFC 4035 section 5.3.2).
    pub fn insertWildcard(self: *AggressiveCache, name: Name, zone: Name, records: []const record_mod.ResourceRecord, rrsig: ?record_mod.ResourceRecord, now: i64, ttl: u32) void {
        if (records.len == 0) return;
        // Every record is tested before the slot is written, so a slot that
        // is reused never keeps the records of the wildcard it held.
        for (records) |record| {
            // A record whose RDATA borrows the message it came from cannot
            // outlive that message in the cache.
            switch (record.rdata) {
                .Unknown => return,
                else => {},
            }
        }
        // The answer is only served to a client that asked for the proofs,
        // and such a client needs the signature that covers the wildcard
        // RRset (RFC 4035 section 5.3.2).
        const sig = rrsig orelse return;
        var sig_wire = ProofRecord{};
        keepProof(&sig_wire, sig);
        if (sig_wire.len == 0) return;
        // The signature covers the whole RRset, so a wildcard the cache
        // cannot hold whole is not cached at all: a partial RRset under that
        // signature cannot verify (RFC 4035 section 5.3.2), and the resolver
        // falls back upstream instead (RFC 8198 section 5.3).
        if (records.len > max_wildcard_records) return;
        // The answer carries the records and the signature that covers them
        // in one message, so their wire size must fit what a message can
        // carry (RFC 1035 section 4.2.2).
        var wire_len: usize = sig_wire.len;
        var scratch: [max_cached_record_wire_len]u8 = undefined;
        for (records) |record| {
            var writer = dns_writer.Writer.init(&scratch);
            record.encode(&writer) catch return;
            wire_len += writer.written().len;
        }
        if (wire_len > rdata_mod.max_message_rdata_len) return;
        const slot = &self.wildcards[self.next_wildcard];
        self.next_wildcard = (self.next_wildcard + 1) % self.wildcards.len;
        slot.* = .{};
        slot.valid = true;
        slot.name = name;
        slot.zone = zone;
        for (records, 0..) |record, index| {
            var copy = record;
            copy.owner = name;
            slot.records[index] = copy;
        }
        slot.len = @intCast(records.len);
        slot.rrsig = sig_wire;
        slot.expires_at = now +| @min(@as(i64, ttl), max_entry_ttl_seconds);
    }

    /// The proof a wildcard answer rests on: the closest encloser (the
    /// wildcard's own parent) must exist and the queried name must not
    /// (RFC 4035 section 5.4, RFC 5155 section 8.8).
    const WildcardProof = struct {
        records: ?Proof = null,
        expires_at: i64 = 0,
    };

    /// The zone a cached proof belongs to: the apex of the zone that
    /// published it. A proof of another zone proves nothing here.
    fn entryZone(entry: *const Entry) ?Name {
        if (entry.is_nsec3) return entry.nsec3_chain.zone;
        const soa = entry.soa orelse return null;
        return soa.owner;
    }

    fn wildcardProof(self: *const AggressiveCache, qname: Name, encloser: Name, zone: Name) ?WildcardProof {
        if (self.nsecWildcardProof(qname, encloser, zone)) |proof| return proof;
        return self.nsec3WildcardProof(qname, encloser, zone);
    }

    /// RFC 4035 section 5.4: the closest encloser must exist and the
    /// queried name must not, both in the zone the wildcard belongs to.
    fn nsecWildcardProof(self: *const AggressiveCache, qname: Name, encloser: Name, zone: Name) ?WildcardProof {
        const ce = self.findNsecOwner(encloser, zone) orelse return null;
        const cover = self.findCovering(qname, zone) orelse return null;
        var proof = Proof{};
        var complete = true;
        for ([_]*const Entry{ ce, cover }) |entry| {
            if (entry.proof_record.len == 0 or entry.proof_rrsig.len == 0) {
                complete = false;
                break;
            }
            proof.add(entry.proof_record);
            proof.add(entry.proof_rrsig);
        }
        return .{
            .records = if (complete and proof.len != 0) proof else null,
            .expires_at = @min(ce.expires_at, cover.expires_at),
        };
    }

    /// RFC 5155 section 8.8: an NSEC3 that matches the closest encloser
    /// and one that covers the next closer name, in the zone the wildcard
    /// belongs to.
    fn nsec3WildcardProof(self: *const AggressiveCache, qname: Name, encloser: Name, zone: Name) ?WildcardProof {
        var index: usize = 0;
        while (index < self.entries.len) : (index += 1) {
            const head = &self.entries[index];
            if (!head.valid or !head.is_nsec3) continue;
            // One chain at a time: a record of another chain cannot prove
            // this one (RFC 5155 section 8.2).
            if (self.chainSeen(head, index)) continue;
            const chain = head.nsec3_chain;
            if (!chain.zone.eql(&zone)) continue;
            if (!isWithin(qname, chain.zone)) continue;
            const cover = self.findNsec3Cover(&chain, nsec3HashIn(chain, qname)) orelse continue;
            // RFC 8198 section 5.2: a covering NSEC3 with the Opt-Out flag
            // set does not prove the non-existence of the name.
            if (cover.nsec3_opt_out) continue;
            const ce = self.findNsec3Match(&chain, nsec3HashIn(chain, encloser)) orelse continue;
            var proof = Proof{};
            var complete = true;
            for ([_]*const Entry{ ce, cover }) |entry| {
                if (entry.proof_record.len == 0 or entry.proof_rrsig.len == 0) {
                    complete = false;
                    break;
                }
                proof.add(entry.proof_record);
                proof.add(entry.proof_rrsig);
            }
            return .{
                .records = if (complete and proof.len != 0) proof else null,
                .expires_at = @min(ce.expires_at, cover.expires_at),
            };
        }
        return null;
    }

    /// RFC 8198 section 5.3: the answer a cached wildcard proof gives, or
    /// null when the cache holds no wildcard the queried name falls under
    /// or no proof that the name does not exist.
    ///
    /// The wildcard covers a name one label below its own parent, so the
    /// queried name is the next closer name of the closest encloser and
    /// the proof that the name does not exist is the one that covers it
    /// (RFC 4035 section 5.4, RFC 5155 section 8.8).
    pub fn wildcardAnswer(self: *AggressiveCache, qname: Name, qtype: RecordType, now: i64) ?WildcardAnswer {
        self.evictExpired(now);
        const encloser = parentName(qname) orelse return null;
        for (&self.wildcards) |*entry| {
            if (!entry.valid) continue;
            const wildcard_parent = parentName(entry.name) orelse continue;
            if (!wildcard_parent.eql(&encloser)) continue;
            var found = false;
            for (entry.records[0..entry.len]) |record| {
                if (record.rrtype.eql(qtype)) found = true;
            }
            if (!found) continue;
            const proof = self.wildcardProof(qname, encloser, entry.zone) orelse continue;
            const remaining = @min(entry.expires_at, proof.expires_at) - now;
            if (remaining <= 0) continue;
            var answer = WildcardAnswer{
                .wildcard = entry.name,
                .zone = entry.zone,
                .records = undefined,
                .proof = proof.records,
                .rrsig = if (entry.rrsig.len == 0) null else entry.rrsig,
                .ttl = @min(@as(u32, @intCast(remaining)), entry.records[0].ttl),
            };
            @memcpy(answer.records[0..entry.len], entry.records[0..entry.len]);
            answer.len = entry.len;
            return answer;
        }
        return null;
    }

    /// The cached NSEC whose owner is the name. The zone is the one the
    /// proof must be of: a proof of another zone proves nothing here, and
    /// the search looks on for one that does. Null asks for any zone.
    fn findNsecOwner(self: *const AggressiveCache, owner: Name, zone: ?Name) ?*const Entry {
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (!entry.owner.eql(&owner)) continue;
            if (zone) |wanted| {
                const entry_zone = entryZone(entry) orelse continue;
                if (!entry_zone.eql(&wanted)) continue;
            }
            return entry;
        }
        return null;
    }

    /// The cached NSEC whose span covers the name, which is the proof that
    /// the name does not exist. The zone is the one the proof must be of: a
    /// proof of another zone proves nothing here, and the search looks on for
    /// one that does. Null asks for any zone.
    fn findCovering(self: *const AggressiveCache, name: Name, zone: ?Name) ?*const Entry {
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (zone) |wanted| {
                const entry_zone = entryZone(entry) orelse continue;
                if (!entry_zone.eql(&wanted)) continue;
            }
            if (nsecCovers(entry.owner, entry.next, name)) return entry;
        }
        return null;
    }

    /// RFC 8198 sections 5.1 and 5.2 aggressive use of cached NSEC and
    /// NSEC3 proofs. The NSEC proof is tried first: a zone is signed with
    /// one scheme or the other, so the two never answer the same name.
    ///
    /// Expired proofs are evicted first and never deny (RFC 8198 section 4);
    /// `now` is unix seconds on the same clock the insert TTLs were stored
    /// against.
    pub fn deny(self: *AggressiveCache, qname: Name, qtype: RecordType, now: i64) Error!?ProvenDenial {
        self.evictExpired(now);
        if (try self.denyNsec(qname, qtype)) |denial| return denial;
        return try self.denyNsec3(qname, qtype);
    }

    /// RFC 8198 section 5.1 aggressive use of cached NSEC proofs.
    ///
    /// Exact path (section 4 NODATA): the QNAME must exactly match a cached
    /// NSEC owner whose bitmap is well-formed, lists NSEC (RFC 4035 section
    /// 3.1), and lacks the QTYPE. A malformed bitmap or a missing NSEC bit
    /// is Error.MalformedNsec, never a denial: the old bitmap lookup
    /// returned false on malformed input and synthesized a false NODATA.
    ///
    /// NXDOMAIN path (section 5): a lone covering span never suffices. Two
    /// proofs are required: the closest encloser (longest cached NSEC owner
    /// that is a strict ancestor of the QNAME) must exist, one cached NSEC
    /// must cover the next-closer name (the chain node one label below the
    /// closest encloser), and one cached NSEC must cover the wildcard at
    /// the closest encloser. An exact wildcard match proves the wildcard
    /// exists, so NXDOMAIN is refused. Anything less returns null and the
    /// caller falls through to the normal lookup path.
    ///
    /// The denial carries the zone SOA that arrived with the proof that
    /// gave it (RFC 2308 section 3), and null when the proof was cached
    /// without one. It carries the proof records the denial rests on
    /// (RFC 8020 section 2) when every one of them came with the RRSIG
    /// that covers it, and no proof at all otherwise.
    pub fn denyNsec(self: *AggressiveCache, qname: Name, qtype: RecordType) Error!?ProvenDenial {
        var exact_seen = false;
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (entry.owner.eql(&qname)) {
                exact_seen = true;
                if (try nsecBitmapDeniesType(entry.bitmap[0..entry.bitmap_len], qtype.code())) {
                    var proof = Proof{};
                    if (entry.proof_record.len != 0 and entry.proof_rrsig.len != 0) {
                        proof.add(entry.proof_record);
                        proof.add(entry.proof_rrsig);
                    }
                    return .{
                        .denial = .nodata,
                        .soa = entry.soa,
                        .proof = if (proof.len == 0) null else proof,
                    };
                }
            }
        }
        if (exact_seen) return null;
        var next_closer = qname;
        var ancestor = parentName(qname);
        while (ancestor) |closest_encloser| {
            if (self.findNsecOwner(closest_encloser, null)) |encloser| {
                const wildcard = wildcardName(closest_encloser) orelse return null;
                if (self.findNsecOwner(wildcard, null) != null) return null;
                const next_cover = self.findCovering(next_closer, null) orelse return null;
                const wildcard_cover = self.findCovering(wildcard, null) orelse return null;
                var proof = Proof{};
                var complete = true;
                for ([_]*const Entry{ encloser, next_cover, wildcard_cover }) |entry| {
                    if (entry.proof_record.len == 0 or entry.proof_rrsig.len == 0) {
                        complete = false;
                        break;
                    }
                    proof.add(entry.proof_record);
                    proof.add(entry.proof_rrsig);
                }
                return .{
                    .denial = .nxdomain,
                    .soa = encloser.soa,
                    .proof = if (complete and proof.len != 0) proof else null,
                };
            }
            next_closer = closest_encloser;
            ancestor = parentName(closest_encloser);
        }
        return null;
    }

    /// RFC 8198 section 5.2 aggressive use of cached NSEC3 records.
    ///
    /// The proof follows RFC 5155 sections 8.3 to 8.6. A NODATA needs an
    /// NSEC3 that matches the QNAME whose bitmap leaves the QTYPE and the
    /// CNAME bit clear (section 8.5, and section 8.6 for a DS query). An
    /// NXDOMAIN needs a closest encloser proof: the longest ancestor of the
    /// QNAME that an NSEC3 matches, the next closer name covered by an
    /// NSEC3, and an NSEC3 that covers the wildcard at the closest encloser
    /// (section 8.4). A covering NSEC3 with the Opt-Out flag set proves
    /// nothing (RFC 8198 section 5.2), and neither does a closest encloser
    /// whose NSEC3 carries the DNAME bit (RFC 5155 section 8.3).
    pub fn denyNsec3(self: *AggressiveCache, qname: Name, qtype: RecordType) Error!?ProvenDenial {
        var index: usize = 0;
        while (index < self.entries.len) : (index += 1) {
            const head = &self.entries[index];
            if (!head.valid or !head.is_nsec3) continue;
            // One chain at a time: a record of another chain cannot prove
            // this one (RFC 5155 section 8.2).
            if (self.chainSeen(head, index)) continue;
            if (try self.denyNsec3Chain(head, qname, qtype)) |denial| return denial;
        }
        return null;
    }

    /// True when an earlier entry belongs to the same NSEC3 chain.
    fn chainSeen(self: *const AggressiveCache, head: *const Entry, index: usize) bool {
        var earlier: usize = 0;
        while (earlier < index) : (earlier += 1) {
            const other = &self.entries[earlier];
            if (!other.valid or !other.is_nsec3) continue;
            if (sameChain(other.nsec3_chain, head.nsec3_chain)) return true;
        }
        return false;
    }

    /// The denial one NSEC3 chain proves, or null when it proves none.
    fn denyNsec3Chain(self: *AggressiveCache, head: *const Entry, qname: Name, qtype: RecordType) Error!?ProvenDenial {
        const chain = head.nsec3_chain;
        // A chain speaks only for the names inside its zone (RFC 5155
        // section 7.1): the hash of a name outside the zone proves nothing.
        if (!isWithin(qname, chain.zone)) return null;

        // RFC 5155 section 8.5: a NODATA needs an NSEC3 that matches the
        // QNAME, with the QTYPE and the CNAME bit clear.
        if (self.findNsec3Match(&chain, nsec3HashIn(chain, qname))) |entry| {
            const denies = try bitmapDeniesTypeAndCname(entry.bitmap[0..entry.bitmap_len], qtype.code());
            if (!denies) return null;
            return .{
                .denial = .nodata,
                .soa = entry.soa,
                .proof = self.proofOf(entry),
            };
        }

        // RFC 5155 section 8.4: an NXDOMAIN needs a closest encloser proof
        // and an NSEC3 that covers the wildcard at that encloser.
        var closest: ?*const Entry = null;
        var closest_name: Name = Name.root();
        var next_closer: ?*const Entry = null;
        var candidate = qname;
        var child_cover: ?*const Entry = null;
        while (true) {
            const digest = nsec3HashIn(chain, candidate);
            if (self.findNsec3Match(&chain, digest)) |entry| {
                // The QNAME itself exists, so it is never denied.
                if (candidate.eql(&qname)) return null;
                closest = entry;
                closest_name = candidate;
                next_closer = child_cover;
                break;
            }
            child_cover = self.findNsec3Cover(&chain, digest);
            // The apex of the zone is the last ancestor the chain covers.
            if (candidate.eql(&chain.zone)) return null;
            candidate = parentName(candidate) orelse return null;
        }
        const encloser = closest orelse return null;
        const cover = next_closer orelse return null;
        // RFC 8198 section 5.2: a covering NSEC3 with the Opt-Out flag set
        // does not prove the non-existence of the name.
        if (cover.nsec3_opt_out) return null;
        // RFC 5155 section 8.3: the encloser's NSEC3 must not carry the
        // DNAME bit, and the NS bit only alongside the SOA bit.
        const encloser_bitmap = encloser.bitmap[0..encloser.bitmap_len];
        try nsecBitmapValidate(encloser_bitmap);
        if (nsecBitmapHasType(encloser_bitmap, RecordType.DNAME.code())) return null;
        if (nsecBitmapHasType(encloser_bitmap, RecordType.NS.code()) and
            !nsecBitmapHasType(encloser_bitmap, RecordType.SOA.code())) return null;
        const wildcard = wildcardName(closest_name) orelse return null;
        const wildcard_cover = self.findNsec3Cover(&chain, nsec3HashIn(chain, wildcard)) orelse return null;
        if (wildcard_cover.nsec3_opt_out) return null;
        var proof = Proof{};
        var complete = true;
        for ([_]*const Entry{ encloser, cover, wildcard_cover }) |entry| {
            if (entry.proof_record.len == 0 or entry.proof_rrsig.len == 0) {
                complete = false;
                break;
            }
            proof.add(entry.proof_record);
            proof.add(entry.proof_rrsig);
        }
        return .{
            .denial = .nxdomain,
            .soa = encloser.soa,
            .proof = if (complete and proof.len != 0) proof else null,
        };
    }

    /// The cached NSEC3 of the chain whose hashed owner is the digest.
    fn findNsec3Match(self: *const AggressiveCache, chain: *const Nsec3Chain, digest: [20]u8) ?*const Entry {
        for (&self.entries) |*entry| {
            if (!entry.valid or !entry.is_nsec3) continue;
            if (!sameChain(entry.nsec3_chain, chain.*)) continue;
            if (!std.mem.eql(u8, &entry.hashed_owner, &digest)) continue;
            return entry;
        }
        return null;
    }

    /// The cached NSEC3 of the chain whose span covers the digest.
    fn findNsec3Cover(self: *const AggressiveCache, chain: *const Nsec3Chain, digest: [20]u8) ?*const Entry {
        for (&self.entries) |*entry| {
            if (!entry.valid or !entry.is_nsec3) continue;
            if (!sameChain(entry.nsec3_chain, chain.*)) continue;
            if (nsec3Covers(entry.hashed_owner, entry.nsec3_next, digest)) return entry;
        }
        return null;
    }

    /// The proof records a denial rests on, when the entry kept both.
    fn proofOf(self: *const AggressiveCache, entry: *const Entry) ?Proof {
        _ = self;
        if (entry.proof_record.len == 0 or entry.proof_rrsig.len == 0) return null;
        var proof = Proof{};
        proof.add(entry.proof_record);
        proof.add(entry.proof_rrsig);
        return if (proof.len == 0) null else proof;
    }
};

test "EDE DNSSEC-bogus codes use RFC 8914 INFO-CODEs 6 through 10" {
    try std.testing.expectEqual(@as(u16, 6), EDE_DNSSEC_BOGUS);
    try std.testing.expectEqual(@as(u16, 7), EDE_SIGNATURE_EXPIRED);
    try std.testing.expectEqual(@as(u16, 8), EDE_SIGNATURE_NOT_YET_VALID);
    try std.testing.expectEqual(@as(u16, 9), EDE_DNSKEY_MISSING);
    try std.testing.expectEqual(@as(u16, 10), EDE_RRSIGS_MISSING);
    try std.testing.expectEqualStrings("dnssec bogus", edeText(6));
    try std.testing.expectEqualStrings("signature expired", edeText(7));
    try std.testing.expectEqualStrings("rrsigs missing", edeText(10));
    try std.testing.expectEqualStrings("", edeText(99));
}

test "EDE codes for an insecure answer use RFC 8914 INFO-CODEs 1, 2, 5 and 11" {
    try std.testing.expectEqual(@as(u16, 1), EDE_UNSUPPORTED_DNSKEY_ALGORITHM);
    try std.testing.expectEqual(@as(u16, 2), EDE_UNSUPPORTED_DS_DIGEST_TYPE);
    try std.testing.expectEqual(@as(u16, 5), EDE_DNSSEC_INDETERMINATE);
    try std.testing.expectEqual(@as(u16, 11), EDE_NO_ZONE_KEY_BIT);
    try std.testing.expectEqualStrings("unsupported dnskey algorithm", edeText(1));
    try std.testing.expectEqualStrings("unsupported ds digest type", edeText(2));
    try std.testing.expectEqualStrings("dnssec indeterminate", edeText(5));
    try std.testing.expectEqualStrings("no zone key bit set", edeText(11));
}

test "DO-bit inclusion keeps explicit queries and gates proof RRsets" {
    try std.testing.expect(shouldInclude(.RRSIG, .RRSIG, false));
    try std.testing.expect(shouldInclude(.NSEC, .NSEC, false));
    try std.testing.expect(shouldInclude(.RRSIG, .A, true));
    try std.testing.expect(shouldInclude(.DNSKEY, .DNSKEY, false));
    try std.testing.expect(shouldInclude(.DS, .DS, false));
    try std.testing.expect(shouldInclude(.DNSKEY, .A, false));
    try std.testing.expect(!shouldInclude(.RRSIG, .A, false));
    try std.testing.expect(!shouldInclude(.NSEC, .AAAA, false));
    try std.testing.expect(!shouldInclude(.NSEC3, .MX, false));
    try std.testing.expect(!shouldInclude(.NSEC3PARAM, .MX, false));
}

test "RRSIG validity window reports expired and not-yet-valid (RFC 4035 5.3.1)" {
    // type-covered A(1), alg 8, labels 3, orig-ttl 3600,
    // expiration 2000000000, inception 1000000000, key tag 1234.
    var rrsig = [_]u8{
        0x00, 0x01, 0x08, 0x03, 0x00, 0x00, 0x0e, 0x10,
        0x77, 0x35, 0x94, 0x00, 0x3b, 0x9a, 0xca, 0x00,
        0x04, 0xd2, 0x07, 'e',  'x',  'a',  'm',  'p',
        'l',  'e',  0x00,
    };
    try std.testing.expectEqual(RrsigTimeStatus.valid, try rrsigTimeStatus(&rrsig, 1500000000));
    try std.testing.expectEqual(RrsigTimeStatus.expired, try rrsigTimeStatus(&rrsig, 2000000001));
    try std.testing.expectEqual(RrsigTimeStatus.not_yet_valid, try rrsigTimeStatus(&rrsig, 999999999));
    try std.testing.expectEqual(@as(u16, 1), try rrsigCovers(&rrsig));
    try std.testing.expectEqual(@as(?u16, null), rrsigTimeEde(.valid));
    try std.testing.expectEqual(@as(?u16, 7), rrsigTimeEde(.expired));
    try std.testing.expectEqual(@as(?u16, 8), rrsigTimeEde(.not_yet_valid));
    try std.testing.expectError(Error.MalformedRrsig, rrsigTimeStatus(rrsig[0..10], 1500000000));
}

test "NSEC bitmap denies missing types (RFC 4034 4.1.2)" {
    // next = ns.example. (wire), bitmap: window 0, len 7, bits for A(1),
    // RRSIG(46), NSEC(47), DNSKEY(48). Byte i covers types 8i..8i+7 with
    // mask 0x80 >> (type % 8).
    var nsec = [_]u8{
        0x02, 'n',  's',  0x07, 'e',  'x',  'a',  'm',  'p',  'l', 'e', 0x00,
        0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80,
    };
    try std.testing.expect(try nsecDeniesType(&nsec, 16)); // TXT denied
    try std.testing.expect(!(try nsecDeniesType(&nsec, 1))); // A present
    try std.testing.expectError(Error.MalformedNsec, nsecDeniesType(nsec[0..4], 1));
}

test "canonical name order compares from the root (RFC 4034 6.1)" {
    const a = try Name.fromText("a.example.");
    const b = try Name.fromText("b.example.");
    const parent = try Name.fromText("example.");
    try std.testing.expectEqual(@as(i8, -1), compareNames(a, b));
    try std.testing.expectEqual(@as(i8, 1), compareNames(b, a));
    try std.testing.expectEqual(@as(i8, 0), compareNames(a, a));
    try std.testing.expect(compareNames(parent, a) < 0);
    const upper = try Name.fromText("A.EXAMPLE.");
    try std.testing.expectEqual(@as(i8, 0), compareNames(a, upper));
}

test "canonical name order sees labels past the old 64-label cap" {
    var x_text: [256]u8 = undefined;
    var y_text: [256]u8 = undefined;
    @memcpy(x_text[0..2], "x.");
    @memcpy(y_text[0..2], "y.");
    var i: usize = 0;
    while (i < 69) : (i += 1) {
        @memcpy(x_text[2 + i * 2 .. 4 + i * 2], "a.");
        @memcpy(y_text[2 + i * 2 .. 4 + i * 2], "a.");
    }
    const x = try Name.fromText(x_text[0 .. 2 + 69 * 2]);
    const y = try Name.fromText(y_text[0 .. 2 + 69 * 2]);
    try std.testing.expect(compareNames(x, y) < 0);
    try std.testing.expect(compareNames(y, x) > 0);
    try std.testing.expectEqual(@as(i8, 0), compareNames(x, x));
}

test "canonical name order tolerates malformed wire without panicking" {
    var bad = Name{ .wire_len = 3 };
    bad.wire[0] = 3;
    bad.wire[1] = 'a';
    bad.wire[2] = 'b';
    const good = try Name.fromText("ab.");
    _ = compareNames(bad, good);
    _ = compareNames(good, bad);
}

test "aggressive NSEC cache synthesizes NODATA on exact match (RFC 8198 4)" {
    const now: i64 = 1_000_000;
    var cache = AggressiveCache{};
    // Window 0 bitmap with A(1) and NSEC(47): byte 5 carries 47 % 8.
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    cache.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), &bitmap, now, 3600, null, .{});
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(try Name.fromText("www.example."), .{ .value = 16 }, now)).?.denial);
    try std.testing.expect((try cache.deny(try Name.fromText("www.example."), .A, now)) == null);
    try std.testing.expect((try cache.deny(try Name.fromText("www.example."), .NSEC, now)) == null);
    // No exact owner and no closest-encloser proof: a lone span never denies.
    try std.testing.expect((try cache.deny(try Name.fromText("x.example."), .A, now)) == null);
    try std.testing.expect((try cache.deny(try Name.fromText("other.test."), .A, now)) == null);
}

test "aggressive NXDOMAIN needs closest-encloser and wildcard proofs (RFC 8198 5)" {
    // example. < *.example. < mail.example. < nx.example. < www.example.:
    // the (example., mail.example.) span covers the wildcard while the
    // (mail.example., www.example.) span covers the next-closer name.
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = 1_000_000;
    var cache = AggressiveCache{};
    cache.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600, null, .{});
    cache.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, null, .{});
    const qnx = try Name.fromText("nx.example.");
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(qnx, .A, now)).?.denial);
    // Names below the next-closer name share its denial.
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(try Name.fromText("deep.nx.example."), .A, now)).?.denial);
    // An existing name with the QTYPE is never denied, even with full proofs.
    try std.testing.expect((try cache.deny(try Name.fromText("mail.example."), .A, now)) == null);
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(try Name.fromText("mail.example."), .{ .value = 16 }, now)).?.denial);

    // Lone covering span without the closest-encloser proof denies nothing.
    var lone = AggressiveCache{};
    lone.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, null, .{});
    try std.testing.expect((try lone.deny(qnx, .A, now)) == null);

    // Closest encloser without a wildcard cover denies nothing: the empty
    // (example., *.example.) span covers no name, so the wildcard proof is
    // missing even though the next-closer name stays covered.
    var no_wild = AggressiveCache{};
    no_wild.insertNsec(try Name.fromText("example."), try Name.fromText("*.example."), &bitmap, now, 3600, null, .{});
    no_wild.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, null, .{});
    try std.testing.expect((try no_wild.deny(qnx, .A, now)) == null);

    // Closest encloser without a next-closer cover denies nothing.
    var no_closer = AggressiveCache{};
    no_closer.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600, null, .{});
    no_closer.insertNsec(try Name.fromText("a.example."), try Name.fromText("b.example."), &bitmap, now, 3600, null, .{});
    try std.testing.expect((try no_closer.deny(qnx, .A, now)) == null);

    // An existing wildcard at the closest encloser refuses NXDOMAIN.
    var wild = AggressiveCache{};
    wild.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600, null, .{});
    wild.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, null, .{});
    wild.insertNsec(try Name.fromText("*.example."), try Name.fromText("mail.example."), &bitmap, now, 3600, null, .{});
    try std.testing.expect((try wild.deny(qnx, .A, now)) == null);
}

/// The zone SOA a proof arrives with (RFC 2308 section 3).
fn testProofSoa(zone: Name) record_mod.ResourceRecord {
    return .{
        .owner = zone,
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = zone,
            .rname = zone,
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
}

/// The RRSIG that covers a wildcard RRset (RFC 4034 section 3.2): the type
/// it covers, the label count of the wildcard, and the zone that signed it.
fn testWildcardRrsig(covered: RecordType, labels: u8, zone: Name) record_mod.ResourceRecord {
    var rdata: rdata_mod.Unknown = .{};
    std.mem.writeInt(u16, rdata.data[0..2], covered.code(), .big);
    rdata.data[2] = 8; // algorithm
    rdata.data[3] = labels;
    const signer = zone.asWire();
    @memcpy(rdata.data[18..][0..signer.len], signer);
    rdata.len = @intCast(18 + signer.len);
    return .{
        .owner = Name.root(),
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .Unknown = rdata },
    };
}

test "aggressive cache answers the name a cached wildcard proof covers (RFC 8198 5.3)" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.");
    var cache = AggressiveCache{};
    // The closest encloser of nx.example. is example., and it exists.
    cache.insertNsec(zone, try Name.fromText("mail.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    // The (mail.example., www.example.) span covers nx.example.
    cache.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    const wildcard = try Name.fromText("*.example.");
    cache.insertWildcard(wildcard, zone, &.{.{
        .owner = wildcard,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    }}, testWildcardRrsig(.A, 1, zone), now, 300);

    const answer = cache.wildcardAnswer(try Name.fromText("nx.example."), .A, now).?;
    try std.testing.expectEqual(@as(u8, 1), answer.len);
    try std.testing.expectEqual(@as(u32, 300), answer.ttl);
    try std.testing.expect(answer.wildcard.eql(&wildcard));
    try std.testing.expect(answer.zone.eql(&zone));
    try std.testing.expectEqual(@as(u8, 192), answer.records[0].rdata.A[0]);
    // The answer carries the signature that covers the wildcard RRset.
    try std.testing.expect(answer.rrsig != null);

    // A name the wildcard does not cover is not answered from the cache.
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("deep.nx.example."), .A, now) == null);
    // A name with no proof that it does not exist is not answered either.
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("zzz.example."), .A, now) == null);
    // A type the wildcard does not hold is not answered from the cache.
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("nx.example."), .AAAA, now) == null);
}

test "a wildcard answers only with a proof of its own zone (RFC 4035 5.3.1)" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.");
    const other = try Name.fromText("other.");
    var cache = AggressiveCache{};
    // The proof is of the zone other.: the closest encloser exists there
    // and the span covers the name below it.
    cache.insertNsec(other, try Name.fromText("zz.other."), &bitmap, now, 3600, testProofSoa(other), .{});
    // The wildcard belongs to the zone example., which the proof is not of.
    const wildcard = try Name.fromText("*.other.");
    cache.insertWildcard(wildcard, zone, &.{.{
        .owner = wildcard,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    }}, testWildcardRrsig(.A, 1, zone), now, 300);
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("x.other."), .A, now) == null);
}

test "a wildcard answers only where the closest encloser is proven (RFC 5155 8.8)" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.");
    var cache = AggressiveCache{};
    // The name does not exist, but the closest encloser is not proven.
    cache.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    const wildcard = try Name.fromText("*.example.");
    cache.insertWildcard(wildcard, zone, &.{.{
        .owner = wildcard,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    }}, testWildcardRrsig(.A, 1, zone), now, 300);
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("nx.example."), .A, now) == null);
}

test "a reused wildcard slot does not serve the wildcard it held" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.");
    var cache = AggressiveCache{};
    // The closest encloser c.example. exists and its span covers the name
    // below it, and the same for e.example.
    cache.insertNsec(try Name.fromText("c.example."), try Name.fromText("d.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    cache.insertNsec(try Name.fromText("e.example."), try Name.fromText("f.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    // Every slot of the cache holds a wildcard of its own.
    for ([_][]const u8{ "*.a.example.", "*.b.example.", "*.c.example.", "*.d.example." }) |text| {
        const wildcard = try Name.fromText(text);
        cache.insertWildcard(wildcard, zone, &.{.{
            .owner = wildcard,
            .rrtype = .A,
            .class = .IN,
            .ttl = 300,
            .rdata = .{ .A = .{ 192, 0, 2, 1 } },
        }}, testWildcardRrsig(.A, 1, zone), now, 300);
    }
    // The next wildcard holds a record that borrows the message it came
    // from, so it cannot be cached and the slot it would take keeps the
    // wildcard it held.
    const fifth = try Name.fromText("*.e.example.");
    const raw = [_]u8{ 192, 0, 2, 9 };
    cache.insertWildcard(fifth, zone, &.{.{
        .owner = fifth,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .Unknown = .{ .len = 4, .borrowed = raw[0..] } },
    }}, testWildcardRrsig(.A, 1, zone), now, 300);
    // The name the refused wildcard covers is not answered from the cache.
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("x.e.example."), .A, now) == null);
    // The slot still holds the wildcard it had, with its own records.
    const held = try Name.fromText("*.a.example.");
    try std.testing.expect(cache.wildcards[0].name.eql(&held));
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("x.c.example."), .A, now) != null);
}

test "a wildcard RRset the cache cannot hold whole is not cached (RFC 4035 5.3.2)" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.");
    var cache = AggressiveCache{};
    // The closest encloser of nx.example. is example., and it exists.
    cache.insertNsec(zone, try Name.fromText("mail.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    // The (mail.example., www.example.) span covers nx.example.
    cache.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600, testProofSoa(zone), .{});
    const wildcard = try Name.fromText("*.example.");
    // Five records of the queried type: the signature covers the whole
    // RRset, so a cache that kept four of them would publish an RRset the
    // signature cannot verify (RFC 4035 section 5.3.2).
    var records: [5]record_mod.ResourceRecord = undefined;
    for (&records, 0..) |*record, index| {
        record.* = .{
            .owner = wildcard,
            .rrtype = .A,
            .class = .IN,
            .ttl = 300,
            .rdata = .{ .A = .{ 192, 0, 2, @intCast(index + 1) } },
        };
    }
    cache.insertWildcard(wildcard, zone, &records, testWildcardRrsig(.A, 1, zone), now, 300);
    // The name the wildcard covers is not answered from the cache.
    try std.testing.expect(cache.wildcardAnswer(try Name.fromText("nx.example."), .A, now) == null);
}

test "a wildcard is answered from a cache that holds another zone's proofs too" {
    const now: i64 = 1_000_000;
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const zone = try Name.fromText("example.com.");
    const parent = try Name.fromText("com.");
    var cache = AggressiveCache{};
    // The parent zone's proof comes first: it names the same owner and
    // covers the same name, and it proves nothing about the child zone.
    cache.insertNsec(try Name.fromText("example.com."), try Name.fromText("zzz.com."), &bitmap, now, 3600, testProofSoa(parent), .{});
    // The child zone's own proofs: the closest encloser exists and the span
    // covers the name below it.
    cache.insertNsec(try Name.fromText("example.com."), try Name.fromText("*.example.com."), &bitmap, now, 3600, testProofSoa(zone), .{});
    cache.insertNsec(try Name.fromText("mail.example.com."), try Name.fromText("www.example.com."), &bitmap, now, 3600, testProofSoa(zone), .{});
    const wildcard = try Name.fromText("*.example.com.");
    cache.insertWildcard(wildcard, zone, &.{.{
        .owner = wildcard,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    }}, testWildcardRrsig(.A, 2, zone), now, 300);
    // The proof of the zone the wildcard belongs to is found, so the name
    // it covers is answered.
    const answer = cache.wildcardAnswer(try Name.fromText("nx.example.com."), .A, now).?;
    try std.testing.expectEqual(@as(u8, 1), answer.len);
}

test "a record type the RFCs do not forbid is not malformed" {
    const raw = [_]u8{ 192, 0, 2, 1 };
    const record = record_mod.ResourceRecord{
        .owner = try Name.fromText("example."),
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .Unknown = .{ .len = 4, .borrowed = raw[0..] } },
    };
    // An A record carries no name in its RDATA, so no name rule applies.
    try std.testing.expect(!proofMalformed(record));

    // An NSEC whose next domain name is compressed cannot be a proof.
    const compressed = [_]u8{ 0xc0, 0x0c };
    const nsec = record_mod.ResourceRecord{
        .owner = try Name.fromText("example."),
        .rrtype = .NSEC,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .Unknown = .{ .len = 2, .borrowed = compressed[0..] } },
    };
    try std.testing.expect(proofMalformed(nsec));
}

test "aggressive cache answers a wildcard an NSEC3 proof covers (RFC 8198 5.3)" {
    const now: i64 = 1_000_000;
    const zone = try Name.fromText("example.");
    const qname = try Name.fromText("nx.example.");
    const wildcard = try Name.fromText("*.example.");
    const bitmap = [_]u8{ 0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x02, 0xa0, 0x00 };
    const qname_hash = testChainHash(qname);
    const wildcard_record = record_mod.ResourceRecord{
        .owner = wildcard,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    };
    var cache = AggressiveCache{};
    // The NSEC3 that covers the hash of the queried name (RFC 5155 section 8.8).
    cache.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(qname_hash, false), testHashNeighbour(qname_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    // The NSEC3 that matches the closest encloser, the zone apex.
    cache.insertNsec3(try testChainOwner(3, zone), testChainHash(zone), testHashNeighbour(testChainHash(zone), true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    cache.insertWildcard(wildcard, zone, &.{wildcard_record}, testWildcardRrsig(.A, 1, zone), now, 300);

    const answer = cache.wildcardAnswer(qname, .A, now).?;
    try std.testing.expectEqual(@as(u8, 1), answer.len);
    try std.testing.expectEqual(@as(u32, 300), answer.ttl);
    try std.testing.expectEqual(@as(u8, 192), answer.records[0].rdata.A[0]);

    // A covering NSEC3 with the Opt-Out flag set proves no non-existence
    // (RFC 8198 section 5.2), so the wildcard answers nothing.
    var opt_out = AggressiveCache{};
    opt_out.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(qname_hash, false), testHashNeighbour(qname_hash, true), true, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    opt_out.insertNsec3(try testChainOwner(3, zone), testChainHash(zone), testHashNeighbour(testChainHash(zone), true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    opt_out.insertWildcard(wildcard, zone, &.{wildcard_record}, testWildcardRrsig(.A, 1, zone), now, 300);
    try std.testing.expect(opt_out.wildcardAnswer(qname, .A, now) == null);
}

test "exact deny requires the NSEC bit and a well-formed bitmap" {
    const now: i64 = 1_000_000;
    // Well-formed window 0 bitmap with A(1) only: no NSEC bit, so the proof
    // is malformed and must error rather than deny TXT.
    var cache = AggressiveCache{};
    const bare = [_]u8{ 0x00, 0x01, 0x40 };
    cache.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), &bare, now, 3600, null, .{});
    try std.testing.expectError(Error.MalformedNsec, cache.deny(try Name.fromText("www.example."), .{ .value = 16 }, now));

    // Each malformed shape errors instead of synthesizing a false NODATA.
    const malformed = [_][]const u8{
        &[_]u8{},
        &[_]u8{ 0x00, 0x02, 0x40 },
        &[_]u8{ 0x00, 0x00 },
        &[_]u8{ 0x00, 0x21, 0x40 },
        &[_]u8{ 0x00, 0x01, 0x40, 0xff },
        &[_]u8{0x00},
    };
    for (malformed) |bitmap| {
        var bad = AggressiveCache{};
        bad.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), bitmap, now, 3600, null, .{});
        try std.testing.expectError(Error.MalformedNsec, bad.deny(try Name.fromText("www.example."), .{ .value = 16 }, now));
    }

    // A malformed bitmap on an unrelated owner is not consulted: no proof,
    // no error, fall through to the normal lookup path.
    var unrelated = AggressiveCache{};
    unrelated.insertNsec(try Name.fromText("other.example."), try Name.fromText("zzz.example."), &[_]u8{ 0x00, 0x02, 0x40 }, now, 3600, null, .{});
    try std.testing.expect((try unrelated.deny(try Name.fromText("www.example."), .{ .value = 16 }, now)) == null);
}

/// The NSEC3 chain the aggressive-cache tests use: the salt "salt" and two
/// iterations, so every hash in the test is a real one (RFC 5155 section 5).
const test_chain_salt = [_]u8{ 0x73, 0x61, 0x6c, 0x74 };
const test_chain_iterations: u16 = 2;

/// The hash a name has in the test chain.
fn testChainHash(name: Name) [20]u8 {
    var out: [20]u8 = undefined;
    nsec3Hash(name, &test_chain_salt, test_chain_iterations, &out);
    return out;
}

/// The hash just above or below the given one, so a test span covers the
/// hash it is built around and nothing else.
fn testHashNeighbour(hash: [20]u8, up: bool) [20]u8 {
    var out = hash;
    var index: usize = out.len;
    while (index > 0) {
        index -= 1;
        if (up) {
            if (out[index] != 0xff) {
                out[index] += 1;
                break;
            }
            out[index] = 0;
        } else {
            if (out[index] != 0x00) {
                out[index] -= 1;
                break;
            }
            out[index] = 0xff;
        }
    }
    return out;
}

/// The owner name an NSEC3 record of the test chain carries: a 32-character
/// base32hex hash label over the zone (RFC 5155 section 3.1).
fn testChainOwner(index: u8, zone: Name) !Name {
    var label: [32]u8 = @splat('a');
    label[31] = '0' + index;
    var zone_text: [256]u8 = undefined;
    const zone_wire = try zone.toText(&zone_text);
    var text: [300]u8 = undefined;
    const written = try std.fmt.bufPrint(&text, "{s}.{s}", .{ label, zone_wire });
    return Name.fromText(written);
}

test "aggressive NSEC3 cache denies from a closest encloser proof (RFC 8198 5.2)" {
    const now: i64 = 1_000_000;
    const zone = try Name.fromText("example.");
    const encloser = try Name.fromText("example.");
    const next_closer = try Name.fromText("nx.example.");
    const wildcard = try Name.fromText("*.example.");
    const encloser_hash = testChainHash(encloser);
    const next_closer_hash = testChainHash(next_closer);
    const wildcard_hash = testChainHash(wildcard);
    // The type bitmap of an apex: A(1), RRSIG(46), DNSKEY(48), NSEC3(50).
    const bitmap = [_]u8{ 0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x02, 0xa0, 0x00 };
    var cache = AggressiveCache{};
    // The encloser's own NSEC3 matches it and covers nothing else.
    cache.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    // The next closer name and the wildcard are covered by their own NSEC3.
    cache.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(next_closer_hash, false), testHashNeighbour(next_closer_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    cache.insertNsec3(try testChainOwner(3, zone), testHashNeighbour(wildcard_hash, false), testHashNeighbour(wildcard_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});

    // The name the next closer name covers does not exist: NXDOMAIN.
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(try Name.fromText("nx.example."), .A, now)).?.denial);
    // A name below it shares the denial.
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(try Name.fromText("deep.nx.example."), .A, now)).?.denial);
    // The encloser exists, so a type it does not hold is a NODATA.
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(encloser, .{ .value = 16 }, now)).?.denial);
    // The type it does hold is never denied.
    try std.testing.expect((try cache.deny(encloser, .A, now)) == null);
    // A name the proof does not cover is not denied.
    try std.testing.expect((try cache.deny(try Name.fromText("other.example."), .A, now)) == null);
    // A name outside the zone the chain covers is not denied either.
    try std.testing.expect((try cache.deny(try Name.fromText("nx.other.example."), .A, now)) == null);
}

test "an NSEC3 proof that does not establish the denial is not used (RFC 8198 5.2)" {
    const now: i64 = 1_000_000;
    const zone = try Name.fromText("example.");
    const encloser = try Name.fromText("example.");
    const next_closer = try Name.fromText("nx.example.");
    const wildcard = try Name.fromText("*.example.");
    const encloser_hash = testChainHash(encloser);
    const next_closer_hash = testChainHash(next_closer);
    const wildcard_hash = testChainHash(wildcard);
    const bitmap = [_]u8{ 0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x02, 0xa0, 0x00 };
    // The type bitmap of a name that carries a DNAME: DNAME(39).
    const dname_bitmap = [_]u8{ 0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20 };

    // A covering NSEC3 with the Opt-Out flag set proves no non-existence
    // (RFC 8198 section 5.2), so the denial is refused.
    var opt_out = AggressiveCache{};
    opt_out.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    opt_out.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(next_closer_hash, false), testHashNeighbour(next_closer_hash, true), true, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    opt_out.insertNsec3(try testChainOwner(3, zone), testHashNeighbour(wildcard_hash, false), testHashNeighbour(wildcard_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    try std.testing.expect((try opt_out.deny(try Name.fromText("nx.example."), .A, now)) == null);

    // Without the NSEC3 that covers the wildcard at the encloser, the
    // closest encloser proof is incomplete (RFC 5155 section 8.4).
    var no_wildcard = AggressiveCache{};
    no_wildcard.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    no_wildcard.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(next_closer_hash, false), testHashNeighbour(next_closer_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    try std.testing.expect((try no_wildcard.deny(try Name.fromText("nx.example."), .A, now)) == null);

    // Without the NSEC3 that covers the next closer name, the proof is
    // incomplete as well.
    var no_next_closer = AggressiveCache{};
    no_next_closer.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    no_next_closer.insertNsec3(try testChainOwner(3, zone), testHashNeighbour(wildcard_hash, false), testHashNeighbour(wildcard_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    try std.testing.expect((try no_next_closer.deny(try Name.fromText("nx.example."), .A, now)) == null);

    // An encloser whose NSEC3 carries the DNAME bit is not an encloser
    // (RFC 5155 section 8.3).
    var dname = AggressiveCache{};
    dname.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &dname_bitmap, now, 3600, null, .{});
    dname.insertNsec3(try testChainOwner(2, zone), testHashNeighbour(next_closer_hash, false), testHashNeighbour(next_closer_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    dname.insertNsec3(try testChainOwner(3, zone), testHashNeighbour(wildcard_hash, false), testHashNeighbour(wildcard_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, now, 3600, null, .{});
    try std.testing.expect((try dname.deny(try Name.fromText("nx.example."), .A, now)) == null);
}

test "an NSEC3 proof with a malformed bitmap denies nothing" {
    const now: i64 = 1_000_000;
    const zone = try Name.fromText("example.");
    const encloser = try Name.fromText("example.");
    const encloser_hash = testChainHash(encloser);
    var cache = AggressiveCache{};
    // An empty bitmap on a matching hash is no proof, so it errors rather
    // than deny.
    cache.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &[_]u8{}, now, 3600, null, .{});
    try std.testing.expectError(Error.MalformedNsec, cache.deny(encloser, .{ .value = 16 }, now));
    // A hash the chain does not hold proves nothing either way.
    try std.testing.expect((try cache.deny(try Name.fromText("nx.example."), .A, now)) == null);
}

test "NSEC3 hash matches an independent SHA-1 recomputation (RFC 5155 5)" {
    const owner = try Name.fromText("example.");
    const salt = [_]u8{ 0x73, 0x61, 0x6c, 0x74 }; // "salt"
    var hashed: [20]u8 = undefined;
    nsec3Hash(owner, &salt, 2, &hashed);
    // Independent oracle: same algorithm written inline against std SHA-1.
    var expected: [20]u8 = undefined;
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(owner.asWire());
    h.update(&salt);
    h.final(&expected);
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        h = std.crypto.hash.Sha1.init(.{});
        h.update(&expected);
        h.update(&salt);
        h.final(&expected);
    }
    try std.testing.expectEqualSlices(u8, &expected, &hashed);
    var different: [20]u8 = undefined;
    nsec3Hash(owner, &[_]u8{}, 0, &different);
    try std.testing.expect(!std.mem.eql(u8, &hashed, &different));
}

test "RFC 5155 5: the NSEC3 hash covers the canonical owner name, not the case it arrived in" {
    const mixed = (try Name.parsePreservingCase(&.{ 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, 0)).name;
    const canonical = (try Name.parse(&.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, 0)).name;
    var mixed_hash: [20]u8 = undefined;
    var canonical_hash: [20]u8 = undefined;
    nsec3Hash(mixed, &.{}, 0, &mixed_hash);
    nsec3Hash(canonical, &.{}, 0, &canonical_hash);
    try std.testing.expectEqualSlices(u8, &canonical_hash, &mixed_hash);
}

test "NSEC3 hash matches external RFC 5155 vectors (python hashlib oracle)" {
    // Oracle: python3 hashlib, iterated salted SHA-1 over the canonical wire
    // name (see task report for the exact script). Full cryptographic
    // validation is still out of scope; this pins the hash construction.
    const vectors = [_]struct {
        name: []const u8,
        salt: []const u8,
        iterations: u16,
        expected: [20]u8,
    }{
        .{
            .name = "example.",
            .salt = &[_]u8{ 0x73, 0x61, 0x6c, 0x74 },
            .iterations = 2,
            .expected = [_]u8{
                0x76, 0xed, 0x9c, 0x9f, 0x42, 0xb4, 0xc9, 0x12, 0x2a, 0xcf,
                0xc7, 0x5d, 0x39, 0xd9, 0x6e, 0x8d, 0x56, 0x6a, 0x14, 0xd0,
            },
        },
        .{
            .name = "example.",
            .salt = &[_]u8{},
            .iterations = 0,
            .expected = [_]u8{
                0x1d, 0xb8, 0xef, 0xa7, 0xdc, 0xb3, 0x48, 0xbd, 0xa7, 0x89,
                0x3f, 0xca, 0x1d, 0x8b, 0xad, 0xfd, 0xb6, 0x99, 0x6b, 0x01,
            },
        },
        .{
            .name = "www.example.",
            .salt = &[_]u8{0xaa},
            .iterations = 1,
            .expected = [_]u8{
                0x8a, 0x85, 0x4c, 0x07, 0xf2, 0x24, 0x2e, 0x7c, 0x6c, 0xc5,
                0x56, 0xa4, 0xfa, 0x83, 0xd3, 0xc9, 0xc6, 0x8d, 0x69, 0x03,
            },
        },
    };
    for (vectors) |vector| {
        const owner = try Name.fromText(vector.name);
        var hashed: [20]u8 = undefined;
        nsec3Hash(owner, vector.salt, vector.iterations, &hashed);
        try std.testing.expectEqualSlices(u8, &vector.expected, &hashed);
    }
}

test "nsecDeniesType fails closed on trailing garbage (no false denial)" {
    // next = ns.example. (wire) + window 0 bitmap listing A/RRSIG/NSEC/DNSKEY.
    const head = [_]u8{
        0x02, 'n',  's',  0x07, 'e',  'x',  'a',  'm',  'p',  'l', 'e', 0x00,
        0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80,
    };
    try std.testing.expect(try nsecDeniesType(&head, 16));
    // One stray byte after a valid bitmap: error, never a denial.
    const trailing = head ++ [_]u8{0x00};
    try std.testing.expectError(Error.MalformedNsec, nsecDeniesType(&trailing, 16));
    // Truncated window (header claims 7 bytes, only 6 present): error.
    try std.testing.expectError(Error.MalformedNsec, nsecDeniesType(head[0 .. head.len - 1], 16));
    // Zero window length: error.
    var zero_len = head;
    zero_len[13] = 0x00;
    try std.testing.expectError(Error.MalformedNsec, nsecDeniesType(&zero_len, 16));
    // Severely truncated window (header claims 7 bytes, 1 present): error.
    var short = head;
    short[14] = 0x00;
    try std.testing.expectError(Error.MalformedNsec, nsecDeniesType(short[0..15], 16));
}

test "aggressive NSEC3 cache proofs expire like the NSEC ones (RFC 8198 4)" {
    const zone = try Name.fromText("example.");
    const encloser = try Name.fromText("example.");
    const encloser_hash = testChainHash(encloser);
    const bitmap = [_]u8{ 0x00, 0x07, 0x40, 0x00, 0x00, 0x00, 0x02, 0xa0, 0x00 };
    var cache = AggressiveCache{};
    cache.insertNsec3(try testChainOwner(1, zone), encloser_hash, testHashNeighbour(encloser_hash, true), false, test_chain_iterations, &test_chain_salt, &bitmap, 1_000, 60, null, .{});
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(encloser, .{ .value = 16 }, 1_059)).?.denial);
    // At and past the TTL the proof is evicted: no denial, no error.
    try std.testing.expect((try cache.deny(encloser, .{ .value = 16 }, 1_060)) == null);
    try std.testing.expect((try cache.deny(encloser, .{ .value = 16 }, 9_999)) == null);
}

test "aggressive cache proofs expire, cap, and refresh (RFC 8198 4)" {
    // Window 0 bitmap with A(1) and NSEC(47).
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const owner = try Name.fromText("www.example.");
    const next = try Name.fromText("zzz.example.");
    const qtxt = RecordType{ .value = 16 };

    var cache = AggressiveCache{};
    cache.insertNsec(owner, next, &bitmap, 1_000, 60, null, .{});
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(owner, qtxt, 1_059)).?.denial);
    // At and past now+ttl the proof is evicted: no denial, no error.
    try std.testing.expect((try cache.deny(owner, qtxt, 1_060)) == null);
    try std.testing.expect((try cache.deny(owner, qtxt, 9_999)) == null);

    // A zero TTL denies nothing, even immediately.
    var zero = AggressiveCache{};
    zero.insertNsec(owner, next, &bitmap, 1_000, 0, null, .{});
    try std.testing.expect((try zero.deny(owner, qtxt, 1_000)) == null);

    // Outsized TTLs are capped: usable just before the cap, gone at it.
    var capped = AggressiveCache{};
    capped.insertNsec(owner, next, &bitmap, 0, std.math.maxInt(u32), null, .{});
    try std.testing.expectEqual(
        Denial.nodata,
        (try capped.deny(owner, qtxt, AggressiveCache.max_entry_ttl_seconds - 1)).?.denial,
    );
    try std.testing.expect((try capped.deny(owner, qtxt, AggressiveCache.max_entry_ttl_seconds)) == null);

    // Re-inserting after expiry refreshes the proof.
    cache.insertNsec(owner, next, &bitmap, 2_000, 60, null, .{});
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(owner, qtxt, 2_059)).?.denial);
}
