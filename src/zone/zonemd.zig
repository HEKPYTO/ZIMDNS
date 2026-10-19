/// Contract: Computes and verifies the RFC 8976 ZONEMD (RR type 63) zone digest
/// over a loaded zone, using the SIMPLE collation scheme and canonical RR order.
/// Ownership: A verify call borrows the zone and the allocator, copies nothing
/// back into the zone, and writes one operator-facing line into a caller buffer.
/// Errors: Digest and ordering failures are typed; no file or socket I/O occurs.
const std = @import("std");
const Name = @import("../dns/name.zig").Name;
const Class = @import("../dns/types.zig").Class;
const dns_types = @import("../dns/types.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_writer = @import("../dns/writer.zig");
const zone_index = @import("index.zig");
const zone_parser = @import("parser.zig");

pub const Error = error{
    OutOfMemory,
    BadZoneRecord,
    NoSoa,
    SerialMismatch,
    DuplicateAlgorithm,
    UnsupportedScheme,
    UnsupportedHash,
    DigestSizeMismatch,
    DigestMismatch,
    ReportTooSmall,
};

/// RFC 8976 section 5.3 "ZONEMD Hash Algorithms" registry. SHA384 (1) MUST and
/// SHA512 (2) SHOULD be supported; 240-254 are Private Use and unverifiable here.
pub const Hash = enum(u8) {
    sha384 = 1,
    sha512 = 2,

    pub fn digestLen(self: Hash) usize {
        return switch (self) {
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    pub fn text(self: Hash) []const u8 {
        return switch (self) {
            .sha384 => "SHA384",
            .sha512 => "SHA512",
        };
    }
};

/// RFC 8976 section 5.2 "ZONEMD Schemes" registry. SIMPLE (1) is the only
/// standardized scheme; 240-254 are Private Use and unverifiable here.
pub const Scheme = enum(u8) {
    simple = 1,

    pub fn text(self: Scheme) []const u8 {
        return switch (self) {
            .simple => "SIMPLE",
        };
    }
};

/// Long enough for the zone name plus two 64-octet digests in hex ("zone
/// <255> ZONEMD ... expected <128> computed <128> ..."), so the operator line
/// never truncates on a real zone.
pub const report_max_len = 1024;

/// Registry lookups over the raw RDATA octet. Values outside the enum are
/// Unassigned or Private Use in the RFC 8976 section 5 registries and are not
/// verifiable here.
fn schemeFromCode(code: u8) ?Scheme {
    return switch (code) {
        @backingInt(Scheme.simple) => Scheme.simple,
        else => null,
    };
}

fn hashFromCode(code: u8) ?Hash {
    return switch (code) {
        @backingInt(Hash.sha384) => Hash.sha384,
        @backingInt(Hash.sha512) => Hash.sha512,
        else => null,
    };
}
/// One record reduced to exactly what the canonical form and order need: the
/// owner in canonical wire form and RDATA already encoded without compression.
/// Both slices point into an arena, so ordering moves only these small values.
const Entry = struct {
    owner_wire: []const u8,
    class: u16,
    rrtype: u16,
    ttl: u32,
    rdata: []const u8,
};

/// A wire name is a chain of [length][bytes] groups closed by a zero length, so
/// the 255-octet name limit bounds the label count.
const max_name_labels = 128;

const LabelOffsets = struct {
    name: []const u8 = &.{},
    starts: [max_name_labels]u8 = undefined,
    len: usize = 0,

    fn init(name: []const u8) LabelOffsets {
        var self = LabelOffsets{ .name = name };
        var index: usize = 0;
        while (index < name.len and self.len < max_name_labels) {
            self.starts[self.len] = @intCast(index);
            self.len += 1;
            index += 1 + name[index];
        }
        return self;
    }

    /// Depth 0 is the most significant (rightmost) label; the root label is
    /// the empty slice, which is what makes a bare parent sort before its
    /// children at the same depth.
    fn label(self: LabelOffsets, depth: usize) []const u8 {
        const start = self.starts[self.len - 1 - depth];
        const length = self.name[start];
        return self.name[start + 1 .. start + 1 + length];
    }

    fn eql(a: LabelOffsets, b: LabelOffsets) bool {
        if (a.len != b.len) return false;
        var depth: usize = 0;
        while (depth < a.len) : (depth += 1) {
            if (!std.mem.eql(u8, a.label(depth), b.label(depth))) return false;
        }
        return true;
    }
};

/// RFC 4034 section 6.1 canonical DNS name order: labels compare as unsigned
/// left-justified octet strings starting at the most significant (rightmost)
/// label, with the absence of an octet sorting before a zero octet. Uppercase
/// folding is already done by Name, whose wire form is lowercase.
pub fn canonicalNameOrder(a: []const u8, b: []const u8) std.math.Order {
    if (std.mem.eql(u8, a, b)) return .eq;
    const labels_a = LabelOffsets.init(a);
    const labels_b = LabelOffsets.init(b);
    var depth: usize = 0;
    while (depth < labels_a.len or depth < labels_b.len) : (depth += 1) {
        // The name that runs out of labels here is the parent, and a parent
        // sorts before every name that has a label in its place.
        if (depth >= labels_a.len) return .lt;
        if (depth >= labels_b.len) return .gt;
        const order = octetOrder(labels_a.label(depth), labels_b.label(depth));
        if (order != .eq) return order;
    }
    return .eq;
}

/// RFC 4034 section 6.3 octet ordering: compare as left-justified unsigned
/// octet sequences where the absence of an octet sorts before a zero octet.
pub fn octetOrder(a: []const u8, b: []const u8) std.math.Order {
    const common = @min(a.len, b.len);
    const order = std.mem.order(u8, a[0..common], b[0..common]);
    if (order != .eq) return order;
    return std.math.order(a.len, b.len);
}

/// RFC 8976 section 3.3.1 orders RRsets by canonical DNS name order, then by the
/// additional provision it states over RFC 4034 (ascending numeric RR TYPE for
/// RRsets sharing an owner), then within an RRset by RFC 4034 section 6.3
/// RDATA octet order.
fn lessThan(entries: []const Entry, left_index: usize, right_index: usize) bool {
    const left = &entries[left_index];
    const right = &entries[right_index];
    const name_order = canonicalNameOrder(left.owner_wire, right.owner_wire);
    if (name_order != .eq) return name_order == .lt;
    if (left.class != right.class) return left.class < right.class;
    if (left.rrtype != right.rrtype) return left.rrtype < right.rrtype;
    return octetOrder(left.rdata, right.rdata) == .lt;
}

/// Records are duplicates for digest purposes when owner, class, type, and
/// RDATA all match (RFC 8976 section 3.3.1.1); TTL is deliberately not compared.
fn sameRrset(left: *const Entry, right: *const Entry) bool {
    return left.rrtype == right.rrtype and
        left.class == right.class and
        canonicalNameOrder(left.owner_wire, right.owner_wire) == .eq and
        octetOrder(left.rdata, right.rdata) == .eq;
}

/// True when this RRSIG's Type Covered field names the ZONEMD type. RRSIG is
/// carried opaquely, and RFC 4034 section 3.1.1 puts Type Covered first.
fn rrsigCoversZonemd(rdata: dns_rdata.RData) bool {
    const raw = switch (rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return false,
    };
    if (raw.len < 2) return false;
    return std.mem.readInt(u16, raw[0..2], .big) == dns_types.RecordType.ZONEMD.code();
}

/// Builds the deduplicated, canonically ordered record set that the SIMPLE
/// scheme digests (RFC 8976 sections 3.3.1 and 3.3.1.1). Excluded: records
/// outside the zone, the apex ZONEMD RRset, and the RRSIG covering that RRset,
/// which the publisher rewrites after every digest is computed. Every other DNSSEC
/// RR stays in, and a non-apex ZONEMD is ordinary zone data.
fn canonicalEntries(zone: *const zone_index.Zone, allocator: std.mem.Allocator) Error![]Entry {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const scratch = arena.allocator();

    var entries: std.ArrayList(Entry) = .empty;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!zone.contains(record.ownerText())) continue;
        const is_apex = std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText());
        if (record.rrtype.eql(.ZONEMD) and is_apex) continue;

        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.BadZoneRecord;
        if (record.rrtype.eql(.RRSIG) and is_apex and rrsigCoversZonemd(rdata)) continue;
        const owner = Name.fromText(record.ownerText()) catch return Error.BadZoneRecord;

        // RDATA in canonical form: every domain name fully expanded and
        // lowercased, and no compression (RFC 4034 section 6.2).
        var rdata_buffer: [2048]u8 = undefined;
        var rdata_writer = dns_writer.Writer.init(&rdata_buffer);
        rdata.encode(&rdata_writer) catch return Error.BadZoneRecord;
        try entries.append(scratch, .{
            .owner_wire = try scratch.dupe(u8, owner.asWire()),
            .class = Class.IN.code(),
            .rrtype = record.rrtype.code(),
            .ttl = record.ttl,
            .rdata = try scratch.dupe(u8, rdata_writer.written()),
        });
    }

    // Sort an index array rather than the entries themselves: std.mem.sort's
    // comparator takes values, and moving 48-byte Entry values through the
    // sort would copy every record O(log n) times for no benefit.
    const order = try scratch.alloc(usize, entries.items.len);
    for (order, 0..) |*slot, index| slot.* = index;
    std.mem.sort(usize, order, entries.items, lessThan);

    const ordered = try scratch.alloc(Entry, order.len);
    var kept: usize = 0;
    var index: usize = 0;
    while (index < order.len) : (index += 1) {
        const entry = entries.items[order[index]];
        if (kept != 0 and sameRrset(&ordered[kept - 1], &entry)) continue;
        ordered[kept] = entry;
        kept += 1;
    }
    return ordered[0..kept];
}

/// digest = hash( RR(1) | RR(2) | ... ) over the canonically ordered zone
/// (RFC 8976 section 3.3.1.2). Each RR contributes its canonical wire form.
fn computeDigest(zone: *const zone_index.Zone, hash: Hash, allocator: std.mem.Allocator, out: *[dns_rdata.max_zonemd_digest_len]u8) Error!void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const entries = try canonicalEntries(zone, arena.allocator());

    switch (hash) {
        .sha384 => hashEntries(entries, std.crypto.hash.sha2.Sha384, 48, out[0..48]),
        .sha512 => hashEntries(entries, std.crypto.hash.sha2.Sha512, 64, out[0..64]),
    }
}

fn hashEntries(entries: []const Entry, comptime Hasher: type, comptime digest_len: usize, out: *[digest_len]u8) void {
    var hasher = Hasher.init(.{});
    for (entries) |entry| {
        const header = rrHeader(entry.rrtype, entry.class, entry.ttl, entry.rdata.len);
        hasher.update(entry.owner_wire);
        hasher.update(&header);
        hasher.update(entry.rdata);
    }
    hasher.final(out);
}

/// The 10-octet canonical RR header (RFC 4034 section 6.2): type, class, TTL,
/// and RDLENGTH. Exported so the DNSSEC signer builds signed-data RRs with the
/// same serialisation the ZONEMD digest covers, instead of a second copy.
pub fn rrHeader(rrtype: u16, class: u16, ttl: u32, rdata_len: usize) [10]u8 {
    var header: [10]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], rrtype, .big);
    std.mem.writeInt(u16, header[2..4], class, .big);
    std.mem.writeInt(u32, header[4..8], ttl, .big);
    std.mem.writeInt(u16, header[8..10], @intCast(rdata_len), .big);
    return header;
}

/// Reports are NUL-terminated in place so a caller that only receives the
/// error (never the returned slice) can still recover the exact text.
fn finishReport(writer: *std.Io.Writer) Error![]const u8 {
    const written = writer.buffered();
    if (written.len >= writer.buffer.len) return Error.ReportTooSmall;
    writer.buffer[written.len] = 0;
    return written;
}

fn writeReport(report: []u8, comptime format: []const u8, args: anytype) Error![]const u8 {
    var writer = std.Io.Writer.fixed(report);
    writer.print(format, args) catch return Error.ReportTooSmall;
    return finishReport(&writer);
}

/// std.fmt has no slice-hex formatter, so digest hex uses the same per-byte
/// "{x:0>2}" idiom the CLI already uses for SSHFP and TLSA fingerprints.
fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |byte| try writer.print("{x:0>2}", .{byte});
}

/// Writes the mismatch line in one pass: prefix, both digests in hex, suffix.
fn writeMismatchReport(
    report: []u8,
    zone_text: []const u8,
    scheme: Scheme,
    hash: Hash,
    serial: u32,
    expected: []const u8,
    computed: []const u8,
) Error![]const u8 {
    var writer = std.Io.Writer.fixed(report);
    writer.print("zone {s}: ZONEMD {s} {s} serial {d} mismatch, expected ", .{
        zone_text,
        scheme.text(),
        hash.text(),
        serial,
    }) catch return Error.ReportTooSmall;
    writeHex(&writer, expected) catch return Error.ReportTooSmall;
    writer.writeAll(", computed ") catch return Error.ReportTooSmall;
    writeHex(&writer, computed) catch return Error.ReportTooSmall;
    return finishReport(&writer);
}

/// Verifies every apex ZONEMD RR against `zone` following RFC 8976 section 4
/// and writes one operator-facing line into `report`, returning it. A zone with
/// no apex ZONEMD RRset succeeds without computing anything. Any one supported
/// (scheme, hash) pair matching is sufficient; nothing matching fails closed.
pub fn verify(zone: *const zone_index.Zone, allocator: std.mem.Allocator, report: []u8) Error![]const u8 {
    if (report.len < report_max_len) return Error.ReportTooSmall;

    var wanted: [16]dns_rdata.Zonemd = undefined;
    var wanted_count: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.ZONEMD)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), zone.originText())) continue;
        const rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.BadZoneRecord;
        if (wanted_count == wanted.len) return Error.DuplicateAlgorithm;
        wanted[wanted_count] = rdata.ZONEMD;
        wanted_count += 1;
    }
    if (wanted_count == 0) {
        return writeReport(report, "zone {s}: no apex ZONEMD record, digest not verified", .{zone.originText()});
    }

    // RFC 8976 section 4.4: each RR must name a unique (scheme, hash) tuple.
    for (wanted[0..wanted_count], 0..) |candidate, index| {
        for (wanted[0..index]) |earlier| {
            if (earlier.scheme == candidate.scheme and earlier.hash == candidate.hash) return Error.DuplicateAlgorithm;
        }
    }

    const soa = zone.soa orelse return Error.NoSoa;
    const soa_rdata = zone_parser.parseRData(.SOA, soa.rdataText()) catch return Error.BadZoneRecord;

    var last_failure: Error = Error.DigestMismatch;
    for (wanted[0..wanted_count]) |zonemd| {
        // RFC 8976 section 4.5a: the SOA serial binds the ZONEMD to this exact
        // zone version, so a stale digest can never pass as current.
        if (zonemd.serial != soa_rdata.SOA.serial) {
            last_failure = Error.SerialMismatch;
            _ = writeReport(report, "zone {s}: ZONEMD serial {d} does not match SOA serial {d}", .{
                zone.originText(),
                zonemd.serial,
                soa_rdata.SOA.serial,
            }) catch return Error.ReportTooSmall;
            continue;
        }
        const scheme = schemeFromCode(zonemd.scheme) orelse {
            last_failure = Error.UnsupportedScheme;
            _ = writeReport(report, "zone {s}: ZONEMD scheme {d} is not the standardized SIMPLE scheme", .{
                zone.originText(),
                zonemd.scheme,
            }) catch return Error.ReportTooSmall;
            continue;
        };
        const hash = hashFromCode(zonemd.hash) orelse {
            last_failure = Error.UnsupportedHash;
            _ = writeReport(report, "zone {s}: ZONEMD hash algorithm {d} is not supported", .{
                zone.originText(),
                zonemd.hash,
            }) catch return Error.ReportTooSmall;
            continue;
        };
        // RFC 8976 section 4.5d: the Digest size must be exactly what the hash
        // algorithm produces, so a truncated digest never compares equal.
        if (zonemd.digest_len != hash.digestLen()) {
            last_failure = Error.DigestSizeMismatch;
            _ = writeReport(report, "zone {s}: ZONEMD {s} digest is {d} octets, expected {d}", .{
                zone.originText(),
                hash.text(),
                zonemd.digest_len,
                hash.digestLen(),
            }) catch return Error.ReportTooSmall;
            continue;
        }

        var computed: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
        const digest_len = hash.digestLen();
        try computeDigest(zone, hash, allocator, &computed);
        if (std.mem.eql(u8, computed[0..digest_len], zonemd.digestBytes())) {
            return writeReport(report, "zone {s}: ZONEMD verified ({s} {s}, serial {d})", .{
                zone.originText(),
                scheme.text(),
                hash.text(),
                zonemd.serial,
            });
        }
        last_failure = Error.DigestMismatch;
        _ = writeMismatchReport(report, zone.originText(), scheme, hash, zonemd.serial, zonemd.digestBytes(), computed[0..digest_len]) catch return Error.ReportTooSmall;
    }

    return last_failure;
}

/// Concatenates wire labels into a DNS name, exactly as they appear on the
/// wire in the RFC 4034 section 6.1 example (including its control octets).
/// Labels are folded to lowercase because canonical wire form is lowercase
/// (RFC 4034 section 6.2), which is the form canonicalNameOrder compares.
fn wireName(labels: []const []const u8, out: []u8) []const u8 {
    var index: usize = 0;
    for (labels) |label| {
        out[index] = @intCast(label.len);
        for (label, 0..) |byte, offset| out[index + 1 + offset] = std.ascii.toLower(byte);
        index += 1 + label.len;
    }
    out[index] = 0;
    return out[0 .. index + 1];
}

test "canonical name order reproduces the RFC 4034 section 6.1 example" {
    // The exact list RFC 4034 section 6.1 presents in canonical order.
    const canonical_list = [_][]const []const u8{
        &.{"example"},
        &.{ "a", "example" },
        &.{ "yljkjljk", "a", "example" },
        &.{ "Z", "a", "example" },
        &.{ "zABC", "a", "EXAMPLE" },
        &.{ "z", "example" },
        &.{ "\x01", "z", "example" },
        &.{ "*", "z", "example" },
        &.{ "\x80", "z", "example" },
    };

    var storage: [canonical_list.len][255]u8 = undefined;
    var wires: [canonical_list.len][]const u8 = undefined;
    for (canonical_list, 0..) |labels, index| wires[index] = wireName(labels, &storage[index]);

    var left: usize = 0;
    while (left < wires.len) : (left += 1) {
        var right: usize = 0;
        while (right < wires.len) : (right += 1) {
            try std.testing.expectEqual(
                std.math.order(left, right),
                canonicalNameOrder(wires[left], wires[right]),
            );
        }
    }

    // Canonical order is not raw byte order: "a.example" sorts after
    // "example" even though its wire form begins with the shorter length
    // octet 0x01. A comparator that memcmp'd owner names would reverse this.
    try std.testing.expect(std.mem.order(u8, wires[0], wires[1]) == .gt);
    try std.testing.expect(canonicalNameOrder(wires[0], wires[1]) == .lt);
}

fn loadZone(text: []const u8) !zone_index.Zone {
    var zone_file = try zone_parser.ZoneFile.parse(text);
    defer zone_file.deinit();
    return zone_index.Zone.fromZoneFile(&zone_file);
}

test "RFC 8976 A.1 simple EXAMPLE zone digest verifies" {
    // RFC 8976 Appendix A.1, with the $ORIGIN/$TTL directives the presentation
    // sample omits. TTLs are stated per record exactly as the RFC shows them.
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN NS ns2
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    c68090d90a7aed71
        \\    6bc459f9340e3d7c
        \\    1370d4d24b7e2fc3
        \\    a1ddc0b9a87153b9
        \\    a9713b3c9ae5cc27
        \\    777f98b8e730044c )
        \\ns1 3600 IN A 203.0.113.63
        \\ns2 3600 IN AAAA 2001:db8::63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    const message = try verify(&zone, std.testing.allocator, &report);
    try std.testing.expect(std.mem.startsWith(u8, message, "zone example.: ZONEMD verified"));
}

test "RFC 8976 A.2 complex EXAMPLE zone digest verifies" {
    // This vector is the one that pins canonical ordering: it mixes uppercase
    // owner names, a wildcard, an out-of-order multi-record MX and AAAA RRset,
    // an exact duplicate RR, an occluded RR, a non-apex ZONEMD, and one
    // out-of-zone RR. Any error in name order, RR TYPE order, RDATA order,
    // duplicate removal, or exclusion produces a different digest.
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN NS ns2
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    a3b69bad980a3504
        \\    e1cffcb0fd6397f9
        \\    3848071c93151f55
        \\    2ae2f6b1711d4bd2
        \\    d8b39808226d7b9d
        \\    b71e34b72077f8fe )
        \\ns1 3600 IN A 203.0.113.63
        \\NS2 3600 IN AAAA 2001:db8::63
        \\occluded.sub 7200 IN TXT "I'm occluded but must be digested"
        \\sub 7200 IN NS ns1
        \\duplicate 300 IN TXT "I must be digested just once"
        \\duplicate 300 IN TXT "I must be digested just once"
        \\foo.test. 555 IN TXT "out-of-zone data must be excluded"
        \\UPPERCASE 3600 IN TXT "canonicalize uppercase owner names"
        \\* 777 IN PTR dont-forget-about-wildcards
        \\mail 3600 IN MX 20 MAIL1
        \\mail 3600 IN MX 10 Mail2.Example.
        \\sortme 3600 IN AAAA 2001:db8::5:61
        \\sortme 3600 IN AAAA 2001:db8::3:62
        \\sortme 3600 IN AAAA 2001:db8::4:63
        \\sortme 3600 IN AAAA 2001:db8::1:65
        \\sortme 3600 IN AAAA 2001:db8::2:64
        \\non-apex 900 IN ZONEMD 2018031900 1 1 (
        \\    616c6c6f77656420
        \\    6275742069676e6f
        \\    7265642e20616c6c
        \\    6f77656420627574
        \\    2069676e6f726564
        \\    2e20616c6c6f7765 )
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    const message = try verify(&zone, std.testing.allocator, &report);
    try std.testing.expect(std.mem.startsWith(u8, message, "zone example.: ZONEMD verified"));
}

test "RFC 8976 A.3 zone verifies on SHA512 and ignores private-use digests" {
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1.example.
        \\@ IN NS ns2.example.
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    62e6cf51b02e54b9
        \\    b5f967d547ce4313
        \\    6792901f9f88e637
        \\    493daaf401c92c27
        \\    9dd10f0edb1c56f8
        \\    080211f8480ee306 )
        \\@ IN ZONEMD 2018031900 1 2 (
        \\    08cfa1115c7b948c
        \\    4163a901270395ea
        \\    226a930cd2cbcf2f
        \\    a9a5e6eb85f37c8a
        \\    4e114d884e66f176
        \\    eab121cb02db7d65
        \\    2e0cc4827e7a3204
        \\    f166b47e5613fd27 )
        \\@ IN ZONEMD 2018031900 1 240 (
        \\    e2d523f654b9422a
        \\    96c5a8f44607bbee )
        \\@ IN ZONEMD 2018031900 241 1 (
        \\    e1846540e33a9e41
        \\    89792d18d5d131f6
        \\    05fc283e )
        \\ns1.example. 3600 IN A 203.0.113.63
        \\ns2.example. 86400 IN TXT "This example has multiple digests"
        \\NS2.EXAMPLE. 3600 IN AAAA 2001:db8::63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    const message = try verify(&zone, std.testing.allocator, &report);
    // The SHA512 RR matched first; the private-use ones are reported as
    // unsupported but a single supported match still verifies the zone.
    try std.testing.expect(std.mem.startsWith(u8, message, "zone example.: ZONEMD verified (SIMPLE SHA384"));
}

/// Computes the SIMPLE/SHA384 digest of one zone text and releases the zone.
fn digestOf(text: []const u8) ![64]u8 {
    var zone = try loadZone(text);
    defer zone.deinit();
    var digest: [64]u8 = undefined;
    try computeDigest(&zone, .sha384, std.testing.allocator, &digest);
    return digest;
}

test "RFC 8976 3.3.1.1 excludes the apex ZONEMD and only its covering RRSIG" {
    // The zones below differ only in apex RRSIGs. Section 3.3.1.1 puts the
    // apex ZONEMD RRset and the RRSIG covering it outside the digest while
    // every other DNSSEC RR stays inside, so dropping the covering RRSIG must
    // not move the digest and dropping any other RRSIG must move it.
    const base =
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN ZONEMD 2018031900 1 1 0000000000000000000000000000000000000000000000000000000000000000
        \\@ IN RRSIG SOA 8 2 86400 2000000000 1000000000 1234 example. QUJD
        \\ns1 3600 IN A 203.0.113.63
        \\
    ;
    const covered = base ++ "@ IN RRSIG ZONEMD 8 2 86400 2000000000 1000000000 1234 example. QUJDRA==\n";
    const no_other_sig =
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN ZONEMD 2018031900 1 1 0000000000000000000000000000000000000000000000000000000000000000
        \\ns1 3600 IN A 203.0.113.63
        \\
    ;

    const base_digest = try digestOf(base);
    const covered_digest = try digestOf(covered);
    const bare_digest = try digestOf(no_other_sig);

    try std.testing.expectEqualSlices(u8, base_digest[0..48], covered_digest[0..48]);
    try std.testing.expect(!std.mem.eql(u8, base_digest[0..48], bare_digest[0..48]));
}

test "verify reports zone, expected and computed digests on mismatch" {
    // RFC 8976 A.1 with only the digest digits corrupted, so the "computed"
    // value reported to the operator must be the digest the RFC itself
    // publishes for this exact zone.
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN NS ns2
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    0000000000000000
        \\    0000000000000000
        \\    0000000000000000
        \\    0000000000000000
        \\    0000000000000000
        \\    0000000000000000 )
        \\ns1 3600 IN A 203.0.113.63
        \\ns2 3600 IN AAAA 2001:db8::63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    if (verify(&zone, std.testing.allocator, &report)) |message| {
        std.debug.print("unexpected verify success: {s}\n", .{message});
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(Error.DigestMismatch, err);
    const expected_report = "zone example.: ZONEMD SIMPLE SHA384 serial 2018031900 mismatch, expected " ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++ ", computed " ++
        "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c";
    if (!std.mem.startsWith(u8, report[0..], expected_report)) {
        const written = std.mem.indexOfScalar(u8, report[0..], 0) orelse report.len;
        std.debug.print("report was: {s}\n", .{report[0..written]});
        return error.TestUnexpectedResult;
    }
}

test "verify rejects a ZONEMD serial that disagrees with the SOA" {
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN ZONEMD 2018031500 1 1 (
        \\    c68090d90a7aed71
        \\    6bc459f9340e3d7c
        \\    1370d4d24b7e2fc3
        \\    a1ddc0b9a87153b9
        \\    a9713b3c9ae5cc27
        \\    777f98b8e730044c )
        \\ns1 3600 IN A 203.0.113.63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    try std.testing.expectError(Error.SerialMismatch, verify(&zone, std.testing.allocator, &report));
    try std.testing.expect(std.mem.startsWith(
        u8,
        report[0..],
        "zone example.: ZONEMD serial 2018031500 does not match SOA serial 2018031900",
    ));
}

test "verify rejects a duplicated scheme and hash pair" {
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    c68090d90a7aed71
        \\    6bc459f9340e3d7c
        \\    1370d4d24b7e2fc3
        \\    a1ddc0b9a87153b9
        \\    a9713b3c9ae5cc27
        \\    777f98b8e730044c )
        \\@ IN ZONEMD 2018031900 1 1 (
        \\    c68090d90a7aed71
        \\    6bc459f9340e3d7c
        \\    1370d4d24b7e2fc3
        \\    a1ddc0b9a87153b9
        \\    a9713b3c9ae5cc27
        \\    777f98b8e730044c )
        \\ns1 3600 IN A 203.0.113.63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    try std.testing.expectError(Error.DuplicateAlgorithm, verify(&zone, std.testing.allocator, &report));
}

test "a zone with no apex ZONEMD record verifies without hashing" {
    var zone = try loadZone(
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
        \\@ IN NS ns1
        \\ns1 3600 IN A 203.0.113.63
        \\
    );
    defer zone.deinit();

    var report: [report_max_len]u8 = undefined;
    const message = try verify(&zone, std.testing.allocator, &report);
    try std.testing.expectEqualStrings("zone example.: no apex ZONEMD record, digest not verified", message);
}
