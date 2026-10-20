/// Contract: DNSSEC serve+validate minimum (RFC 4034/4035/5155/8198/8914).
/// What this module does:
/// - DO-bit helpers and DNSSEC RRset inclusion rules for authoritative answers.
/// - Opaque-wire helpers: RRSIG validity-window check, NSEC type-bitmap denial,
///   NSEC3 (SHA-1, RFC 5155) hash and denial.
/// - A bounded aggressive-NSEC cache (RFC 8198 sections 4-5) for validators.
/// - EDE DNSSEC-bogus INFO-CODEs (RFC 8914 codes 6-10) for validation failures.
/// What this module does NOT do: zone signing, cryptographic validation (no
/// RSA/ECDSA chain building and no trust-anchor management), and
/// authoritative NSEC3 denial serving with closest-encloser/opt-out proofs
/// (deferred behind the typed error below). A full-validating
/// resolver MUST NOT claim `secure` from this module alone. Presence,
/// time-window, and denial checks report `bogus`/`insecure` only; `secure`
/// requires an external cryptographic verifier over the same opaque RDATA.
/// Ownership: All values are inline or borrow caller storage; no allocation.
/// Errors: Malformed opaque RDATA is reported as typed errors; no I/O.
const std = @import("std");
const RecordType = @import("types.zig").RecordType;
const Name = @import("name.zig").Name;
const dns_message = @import("message.zig");

pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_SIGNATURE_EXPIRED: u16 = 7;
pub const EDE_SIGNATURE_NOT_YET_VALID: u16 = 8;
pub const EDE_DNSKEY_MISSING: u16 = 9;
pub const EDE_RRSIGS_MISSING: u16 = 10;

/// RFC 8914 EXTRA-TEXT purpose strings for the DNSSEC-bogus INFO-CODEs above.
pub fn edeText(code: u16) []const u8 {
    return switch (code) {
        EDE_DNSSEC_BOGUS => "dnssec bogus",
        EDE_SIGNATURE_EXPIRED => "signature expired",
        EDE_SIGNATURE_NOT_YET_VALID => "signature not yet valid",
        EDE_DNSKEY_MISSING => "dnskey missing",
        EDE_RRSIGS_MISSING => "rrsigs missing",
        else => "",
    };
}

pub const Error = error{
    MalformedRrsig,
    MalformedNsec,
    MalformedNsec3,
    NameTooLong,
    /// Authoritative NSEC3 denial serving is deferred: no closest-encloser or
    /// opt-out proofs are synthesized for authoritative answers.
    Nsec3DenialDeferred,
};

/// Authoritative NSEC3 denial serving is deferred; the aggressive cache below
/// consumes NSEC proofs only and never synthesizes an NSEC3 denial. Fails with
/// its typed error instead of a silent fallback or an unsigned answer.
pub fn serveNsec3DenialDeferred() Error!void {
    return Error.Nsec3DenialDeferred;
}

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

pub const Denial = enum {
    nxdomain,
    nodata,
};

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

/// Bounded aggressive-NSEC cache (RFC 8198 sections 4-5). Stores proving NSEC
/// RRs; `deny` synthesizes NXDOMAIN/NODATA without an upstream query. NSEC3
/// entries are matched on exact hashed-owner plus a type-bitmap miss in this
/// minimum; anything more complex (closest-encloser proofs, opt-out) returns
/// null so the caller falls through to the normal lookup path.
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
        /// Unix seconds after which the proof must no longer deny (RFC 8198
        /// section 4). Always derived as now + min(ttl, cap) at insert.
        expires_at: i64 = 0,
    };

    entries: [capacity]Entry = @splat(Entry{}),
    next_slot: usize = 0,

    pub fn insertNsec(self: *AggressiveCache, owner: Name, next: Name, bitmap: []const u8, now: i64, ttl: u32) void {
        const slot = &self.entries[self.next_slot];
        self.next_slot = (self.next_slot + 1) % capacity;
        slot.* = .{};
        slot.valid = true;
        slot.owner = owner;
        slot.next = next;
        const len = @min(bitmap.len, slot.bitmap.len);
        @memcpy(slot.bitmap[0..len], bitmap[0..len]);
        slot.bitmap_len = @intCast(len);
        slot.expires_at = now +| @min(@as(i64, ttl), max_entry_ttl_seconds);
    }

    pub fn insertNsec3Hash(self: *AggressiveCache, hashed_owner: [20]u8, bitmap: []const u8, now: i64, ttl: u32) void {
        const slot = &self.entries[self.next_slot];
        self.next_slot = (self.next_slot + 1) % capacity;
        slot.* = .{};
        slot.valid = true;
        slot.is_nsec3 = true;
        slot.hashed_owner = hashed_owner;
        const len = @min(bitmap.len, slot.bitmap.len);
        @memcpy(slot.bitmap[0..len], bitmap[0..len]);
        slot.bitmap_len = @intCast(len);
        slot.expires_at = now +| @min(@as(i64, ttl), max_entry_ttl_seconds);
    }

    /// Drop proofs past their expiry. Lazy eviction on every deny path, so
    /// no timer is needed; re-inserting a proof refreshes its expiry. A
    /// zero TTL therefore denies nothing: the entry expires immediately.
    fn evictExpired(self: *AggressiveCache, now: i64) void {
        for (&self.entries) |*entry| {
            if (entry.valid and now >= entry.expires_at) entry.valid = false;
        }
    }

    fn hasNsecOwner(self: *const AggressiveCache, owner: Name) bool {
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (entry.owner.eql(&owner)) return true;
        }
        return false;
    }

    fn spanCovers(self: *const AggressiveCache, name: Name) bool {
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (nsecCovers(entry.owner, entry.next, name)) return true;
        }
        return false;
    }

    /// RFC 8198 sections 4-5 aggressive use of cached NSEC proofs.
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
    /// Expired proofs are evicted first and never deny (RFC 8198 section 4);
    /// `now` is unix seconds on the same clock the insert TTLs were stored
    /// against.
    pub fn deny(self: *AggressiveCache, qname: Name, qtype: RecordType, now: i64) Error!?Denial {
        self.evictExpired(now);
        var exact_seen = false;
        for (&self.entries) |*entry| {
            if (!entry.valid or entry.is_nsec3) continue;
            if (entry.owner.eql(&qname)) {
                exact_seen = true;
                if (try nsecBitmapDeniesType(entry.bitmap[0..entry.bitmap_len], qtype.code())) return .nodata;
            }
        }
        if (exact_seen) return null;
        var next_closer = qname;
        var ancestor = parentName(qname);
        while (ancestor) |closest_encloser| {
            if (self.hasNsecOwner(closest_encloser)) {
                const wildcard = wildcardName(closest_encloser) orelse return null;
                if (self.hasNsecOwner(wildcard)) return null;
                if (self.spanCovers(next_closer) and self.spanCovers(wildcard)) return .nxdomain;
                return null;
            }
            next_closer = closest_encloser;
            ancestor = parentName(closest_encloser);
        }
        return null;
    }

    /// NSEC3 exact-match denial only: the hashed qname must equal a cached
    /// hashed owner whose strictly well-formed bitmap lacks the QTYPE. Span
    /// proofs need the closest-encloser NSEC3 set, which this minimum does
    /// not synthesize. A matching entry with an empty or malformed bitmap
    /// is Error.MalformedNsec, never a denial: the lenient lookup below
    /// reports malformed input as absent, which would otherwise deny on
    /// zero proof. Unknown hashes return null (no proof either way).
    pub fn denyNsec3(self: *AggressiveCache, hashed_qname: [20]u8, qtype_code: u16, now: i64) Error!?Denial {
        self.evictExpired(now);
        for (&self.entries) |*entry| {
            if (!entry.valid or !entry.is_nsec3) continue;
            if (!std.mem.eql(u8, &entry.hashed_owner, &hashed_qname)) continue;
            const bitmap = entry.bitmap[0..entry.bitmap_len];
            try nsecBitmapValidate(bitmap);
            if (!nsecBitmapHasType(bitmap, qtype_code)) return .nodata;
            return null;
        }
        return null;
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

test "deferred NSEC3 denial fails with a typed error" {
    try std.testing.expectError(Error.Nsec3DenialDeferred, serveNsec3DenialDeferred());
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
    cache.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), &bitmap, now, 3600);
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(try Name.fromText("www.example."), .{ .value = 16 }, now)).?);
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
    cache.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600);
    cache.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600);
    const qnx = try Name.fromText("nx.example.");
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(qnx, .A, now)).?);
    // Names below the next-closer name share its denial.
    try std.testing.expectEqual(Denial.nxdomain, (try cache.deny(try Name.fromText("deep.nx.example."), .A, now)).?);
    // An existing name with the QTYPE is never denied, even with full proofs.
    try std.testing.expect((try cache.deny(try Name.fromText("mail.example."), .A, now)) == null);
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(try Name.fromText("mail.example."), .{ .value = 16 }, now)).?);

    // Lone covering span without the closest-encloser proof denies nothing.
    var lone = AggressiveCache{};
    lone.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600);
    try std.testing.expect((try lone.deny(qnx, .A, now)) == null);

    // Closest encloser without a wildcard cover denies nothing: the empty
    // (example., *.example.) span covers no name, so the wildcard proof is
    // missing even though the next-closer name stays covered.
    var no_wild = AggressiveCache{};
    no_wild.insertNsec(try Name.fromText("example."), try Name.fromText("*.example."), &bitmap, now, 3600);
    no_wild.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600);
    try std.testing.expect((try no_wild.deny(qnx, .A, now)) == null);

    // Closest encloser without a next-closer cover denies nothing.
    var no_closer = AggressiveCache{};
    no_closer.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600);
    no_closer.insertNsec(try Name.fromText("a.example."), try Name.fromText("b.example."), &bitmap, now, 3600);
    try std.testing.expect((try no_closer.deny(qnx, .A, now)) == null);

    // An existing wildcard at the closest encloser refuses NXDOMAIN.
    var wild = AggressiveCache{};
    wild.insertNsec(try Name.fromText("example."), try Name.fromText("mail.example."), &bitmap, now, 3600);
    wild.insertNsec(try Name.fromText("mail.example."), try Name.fromText("www.example."), &bitmap, now, 3600);
    wild.insertNsec(try Name.fromText("*.example."), try Name.fromText("mail.example."), &bitmap, now, 3600);
    try std.testing.expect((try wild.deny(qnx, .A, now)) == null);
}

test "exact deny requires the NSEC bit and a well-formed bitmap" {
    const now: i64 = 1_000_000;
    // Well-formed window 0 bitmap with A(1) only: no NSEC bit, so the proof
    // is malformed and must error rather than deny TXT.
    var cache = AggressiveCache{};
    const bare = [_]u8{ 0x00, 0x01, 0x40 };
    cache.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), &bare, now, 3600);
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
        bad.insertNsec(try Name.fromText("www.example."), try Name.fromText("zzz.example."), bitmap, now, 3600);
        try std.testing.expectError(Error.MalformedNsec, bad.deny(try Name.fromText("www.example."), .{ .value = 16 }, now));
    }

    // A malformed bitmap on an unrelated owner is not consulted: no proof,
    // no error, fall through to the normal lookup path.
    var unrelated = AggressiveCache{};
    unrelated.insertNsec(try Name.fromText("other.example."), try Name.fromText("zzz.example."), &[_]u8{ 0x00, 0x02, 0x40 }, now, 3600);
    try std.testing.expect((try unrelated.deny(try Name.fromText("www.example."), .{ .value = 16 }, now)) == null);
}

test "aggressive NSEC3 cache denies only types missing from the bitmap" {
    const now: i64 = 1_000_000;
    var cache = AggressiveCache{};
    const hashed = @as([20]u8, @splat(@as(u8, 0xab)));
    // Window 0 bitmap with A(1) only.
    cache.insertNsec3Hash(hashed, &[_]u8{ 0x00, 0x01, 0x40 }, now, 3600);
    try std.testing.expectEqual(Denial.nodata, (try cache.denyNsec3(hashed, 16, now)).?);
    try std.testing.expect((try cache.denyNsec3(hashed, 1, now)) == null);
    try std.testing.expect((try cache.denyNsec3(@as([20]u8, @splat(@as(u8, 0xcd))), 16, now)) == null);
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

test "denyNsec3 fails closed without a well-formed bitmap proof" {
    const now: i64 = 1_000_000;
    const hashed = @as([20]u8, @splat(@as(u8, 0xab)));
    // Empty bitmap on a matching hash: no proof, so error (never NODATA).
    var empty = AggressiveCache{};
    empty.insertNsec3Hash(hashed, &[_]u8{}, now, 3600);
    try std.testing.expectError(Error.MalformedNsec, empty.denyNsec3(hashed, 16, now));
    // Truncated window and trailing garbage likewise error on a match.
    const malformed = [_][]const u8{
        &[_]u8{ 0x00, 0x02, 0x40 },
        &[_]u8{ 0x00, 0x01, 0x40, 0xff },
        &[_]u8{0x00},
    };
    for (malformed) |bitmap| {
        var bad = AggressiveCache{};
        bad.insertNsec3Hash(hashed, bitmap, now, 3600);
        try std.testing.expectError(Error.MalformedNsec, bad.denyNsec3(hashed, 16, now));
        // Unknown hashes still prove nothing either way: null, not error.
        try std.testing.expect((try bad.denyNsec3(@as([20]u8, @splat(@as(u8, 0xcd))), 16, now)) == null);
    }
}

test "aggressive cache proofs expire, cap, and refresh (RFC 8198 4)" {
    // Window 0 bitmap with A(1) and NSEC(47).
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const owner = try Name.fromText("www.example.");
    const next = try Name.fromText("zzz.example.");
    const qtxt = RecordType{ .value = 16 };

    var cache = AggressiveCache{};
    cache.insertNsec(owner, next, &bitmap, 1_000, 60);
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(owner, qtxt, 1_059)).?);
    // At and past now+ttl the proof is evicted: no denial, no error.
    try std.testing.expect((try cache.deny(owner, qtxt, 1_060)) == null);
    try std.testing.expect((try cache.deny(owner, qtxt, 9_999)) == null);

    // A zero TTL denies nothing, even immediately.
    var zero = AggressiveCache{};
    zero.insertNsec(owner, next, &bitmap, 1_000, 0);
    try std.testing.expect((try zero.deny(owner, qtxt, 1_000)) == null);

    // Outsized TTLs are capped: usable just before the cap, gone at it.
    var capped = AggressiveCache{};
    capped.insertNsec(owner, next, &bitmap, 0, std.math.maxInt(u32));
    try std.testing.expectEqual(
        Denial.nodata,
        (try capped.deny(owner, qtxt, AggressiveCache.max_entry_ttl_seconds - 1)).?,
    );
    try std.testing.expect((try capped.deny(owner, qtxt, AggressiveCache.max_entry_ttl_seconds)) == null);

    // Re-inserting after expiry refreshes the proof.
    cache.insertNsec(owner, next, &bitmap, 2_000, 60);
    try std.testing.expectEqual(Denial.nodata, (try cache.deny(owner, qtxt, 2_059)).?);

    // NSEC3 proofs expire the same way: evicted entries return null.
    var nsec3 = AggressiveCache{};
    const hashed = @as([20]u8, @splat(@as(u8, 0xab)));
    nsec3.insertNsec3Hash(hashed, &[_]u8{ 0x00, 0x01, 0x40 }, 1_000, 60);
    try std.testing.expectEqual(Denial.nodata, (try nsec3.denyNsec3(hashed, 16, 1_059)).?);
    try std.testing.expect((try nsec3.denyNsec3(hashed, 16, 1_060)) == null);
}
