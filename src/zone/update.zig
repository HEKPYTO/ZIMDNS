/// Contract: Applies an RFC 2136 prerequisite and update section to a zone and
/// renders the resulting zone text; nothing here touches the network or a file.
/// Ownership: the returned text is allocated with the caller's allocator and is
/// the caller's to free; zone records are never mutated.
/// Errors: OutOfMemory only; the RFC's own refusals travel in Outcome.rcode.
const std = @import("std");
const header = @import("../dns/header.zig");
const dns_name = @import("../dns/name.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_record = @import("../dns/record.zig");
const RecordType = @import("../dns/types.zig").RecordType;
const dns_writer = @import("../dns/writer.zig");
const dnssec = @import("../dns/dnssec.zig");
const parser = @import("parser.zig");
const Zone = @import("index.zig").Zone;
const zonemd = @import("zonemd.zig");

pub const Error = error{OutOfMemory};

pub const Outcome = union(enum) {
    zone_text: []u8,
    rcode: header.Rcode,
};

const CLASS_ANY: u16 = 255;
const CLASS_NONE: u16 = 254;
const CLASS_IN: u16 = 1;
const MAX_RDATA: usize = 65535;
const TEXT_BUFFER: usize = 512;

const Expected = struct {
    name: []const u8,
    rrtype: RecordType,
    members: std.ArrayList([]const u8) = .empty,
};

/// Applies one RFC 2136 transaction. `domain` is the zone apex in text form;
/// `prerequisites` is the message's answer section and `updates` its authority
/// section. Returns the new zone text, SOA serial raised when the update did not
/// carry a newer one, or the rcode the RFC names for the first refusal.
pub fn apply(
    allocator: std.mem.Allocator,
    zone: *const Zone,
    domain: []const u8,
    prerequisites: []const dns_record.ResourceRecord,
    updates: []const dns_record.ResourceRecord,
) Error!Outcome {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encode_buffer = try arena.alloc(u8, MAX_RDATA);

    // The served zone of a signed apex carries the signer's generated tail
    // (DNSKEY/RRSIG/NSEC...). Prerequisite checks (§3.2) run against the
    // full served data, but mutations apply to the loaded records only: the
    // signing pass regenerates the tail, and a user-authored delegation DS
    // is loaded data, not generated, so it stays.
    const loaded_len = zone.records.len -| zone.generated.len;
    const served = zone.records.items[0..zone.records.len];
    var records: std.ArrayList(parser.ZoneRecord) = .empty;
    defer records.deinit(allocator);
    try records.appendSlice(allocator, zone.records.items[0..loaded_len]);

    // RFC 2136 section 3.2: the prerequisite section first.
    var expected: std.ArrayList(Expected) = .empty;
    defer {
        for (expected.items) |*entry| entry.members.deinit(allocator);
        expected.deinit(allocator);
    }
    for (prerequisites) |rr| {
        if (rr.ttl != 0) return .{ .rcode = .formerr };
        var name_buffer: [TEXT_BUFFER]u8 = undefined;
        const name = rr.owner.toText(&name_buffer) catch return .{ .rcode = .formerr };
        if (!isAtOrBelow(name, domain)) return .{ .rcode = .notzone };
        const class = rr.class.code();
        if (class == CLASS_ANY) {
            if (encodedLen(rr) != 0) return .{ .rcode = .formerr };
            if (rr.rrtype.eql(.ANY)) {
                if (!nameInUse(served, name)) return .{ .rcode = .nxdomain };
            } else if (!rrsetExists(served, name, rr.rrtype)) {
                return .{ .rcode = .nxrrset };
            }
        } else if (class == CLASS_NONE) {
            if (encodedLen(rr) != 0) return .{ .rcode = .formerr };
            if (rr.rrtype.eql(.ANY)) {
                if (nameInUse(served, name)) return .{ .rcode = .yxdomain };
            } else if (rrsetExists(served, name, rr.rrtype)) {
                return .{ .rcode = .yxrrset };
            }
        } else if (class == CLASS_IN) {
            const rdata = encodeUpdateRdata(rr, encode_buffer) catch return .{ .rcode = .formerr };
            var found: ?*Expected = null;
            for (expected.items) |*entry| {
                if (entry.rrtype.eql(rr.rrtype) and std.ascii.eqlIgnoreCase(entry.name, name)) {
                    found = entry;
                    break;
                }
            }
            if (found) |entry| {
                try entry.members.append(allocator, try arena.dupe(u8, rdata));
            } else {
                var entry = Expected{ .name = try arena.dupe(u8, name), .rrtype = rr.rrtype };
                try entry.members.append(allocator, try arena.dupe(u8, rdata));
                try expected.append(allocator, entry);
            }
        } else {
            return .{ .rcode = .formerr };
        }
    }
    // RFC 2136 section 3.2.3: a value-dependent prerequisite must match the
    // zone RRset exactly, member for member.
    for (expected.items) |entry| {
        var zone_members: usize = 0;
        for (served) |record| {
            if (!record.rrtype.eql(entry.rrtype)) continue;
            if (!std.ascii.eqlIgnoreCase(record.ownerText(), entry.name)) continue;
            zone_members += 1;
            const bytes = zoneRdataBytes(record, encode_buffer) orelse return .{ .rcode = .formerr };
            // RFC 2136 section 1.1 with RFC 4034 section 6.2: names inside
            // RDATA compare case-insensitively, every other octet exactly.
            const canonical = try dnssec.canonicalRdata(arena, entry.rrtype.code(), bytes);
            const matched = try containsMember(arena, entry.members.items, entry.rrtype.code(), canonical);
            if (!matched) return .{ .rcode = .nxrrset };
        }
        if (zone_members != entry.members.items.len) return .{ .rcode = .nxrrset };
    }

    // RFC 2136 section 3.4.1: the update section prescan.
    const signed = zone.generated.len != 0;
    for (updates) |rr| {
        var name_buffer: [TEXT_BUFFER]u8 = undefined;
        const name = rr.owner.toText(&name_buffer) catch return .{ .rcode = .formerr };
        if (!isAtOrBelow(name, domain)) return .{ .rcode = .notzone };
        const class = rr.class.code();
        if (class == CLASS_IN) {
            if (isQueryMetaType(rr.rrtype)) return .{ .rcode = .formerr };
            // A bogus ZONEMD add reseals to null and bricks the next load, so refuse it here.
            if (rr.rrtype.eql(.ZONEMD)) {
                if (!std.ascii.eqlIgnoreCase(name, domain)) return .{ .rcode = .refused };
                const value = switch (rr.rdata) {
                    .ZONEMD => |v| v,
                    else => return .{ .rcode = .formerr },
                };
                if (zonemd.schemeFromCode(value.scheme) == null or zonemd.hashFromCode(value.hash) == null) return .{ .rcode = .refused };
            }
            // The signer owns these types on a signed apex: persisting one
            // would poison the file and refuse the next load, so the update
            // is refused before anything is written. A delegation DS is not
            // generated, so it stays updatable.
            if (signed and isSignerOwnedType(rr.rrtype)) return .{ .rcode = .refused };
        } else if (class == CLASS_ANY) {
            if (rr.ttl != 0 or encodedLen(rr) != 0) return .{ .rcode = .formerr };
            if (!rr.rrtype.eql(.ANY) and isQueryMetaType(rr.rrtype)) return .{ .rcode = .formerr };
        } else if (class == CLASS_NONE) {
            if (rr.ttl != 0 or isQueryMetaType(rr.rrtype)) return .{ .rcode = .formerr };
        } else {
            return .{ .rcode = .formerr };
        }
    }

    // RFC 2136 section 3.4.2: apply in order.
    var soa_replaced = false;
    for (updates) |rr| {
        var name_buffer: [TEXT_BUFFER]u8 = undefined;
        const name = rr.owner.toText(&name_buffer) catch return .{ .rcode = .formerr };
        const class = rr.class.code();
        if (class == CLASS_IN) {
            try applyAdd(allocator, arena, &records, name, rr, encode_buffer, &soa_replaced);
        } else if (class == CLASS_ANY) {
            applyDeleteAny(&records, name, domain, rr.rrtype);
        } else if (class == CLASS_NONE) {
            try applyDeleteOne(&records, name, rr, encode_buffer);
        }
    }

    // The caller's swap rejects an equal or older serial, so an update that
    // carried no newer SOA raises the serial by one here.
    try raiseSerial(arena, &records, domain, soa_replaced);

    return .{ .zone_text = try renderZoneText(allocator, domain, records.items) };
}

fn applyAdd(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    records: *std.ArrayList(parser.ZoneRecord),
    name: []const u8,
    rr: dns_record.ResourceRecord,
    encode_buffer: []u8,
    soa_replaced: *bool,
) Error!void {
    // The shared encode buffer is reused by the zone lookups below, so the
    // update's own bytes are copied before anything else can touch it.
    const rdata = try arena.dupe(u8, encodeUpdateRdata(rr, encode_buffer) catch return);
    const is_cname = rr.rrtype.eql(.CNAME);
    var saw_cname = false;
    var saw_other = false;
    for (records.items) |record| {
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) continue;
        if (record.rrtype.eql(.CNAME)) saw_cname = true else saw_other = true;
    }
    // RFC 2136 section 3.4.2.2: a CNAME never shares a name with other data.
    if (is_cname and saw_other) return;
    if (!is_cname and saw_cname) return;
    // RFC 2181 section 10.1: a name holds exactly one CNAME. An add matches
    // the existing record by type, because a second CNAME is never a valid
    // outcome.
    if (is_cname and saw_cname) return;

    if (rr.rrtype.eql(.SOA)) {
        if (rr.rdata != .SOA) return;
        var current: ?u32 = null;
        for (records.items) |record| {
            if (!record.rrtype.eql(.SOA)) continue;
            if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) continue;
            const parsed = parser.parseRData(.SOA, record.rdataText()) catch return;
            if (parsed != .SOA) return;
            current = parsed.SOA.serial;
        }
        const existing_serial = current orelse return;
        // RFC 2136 section 3.4.2.2: a lower or equal serial is ignored.
        if (!serialGreaterThan(rr.rdata.SOA.serial, existing_serial)) return;
        for (records.items) |*record| {
            if (!record.rrtype.eql(.SOA)) continue;
            if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) continue;
            record.ttl = rr.ttl;
            record.rdata = try genericRdataText(arena, rdata);
        }
        soa_replaced.* = true;
        return;
    }

    var index: usize = 0;
    while (index < records.items.len) : (index += 1) {
        const record = records.items[index];
        if (!record.rrtype.eql(rr.rrtype)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) continue;
        const existing = zoneRdataBytes(record, encode_buffer) orelse continue;
        if (!std.mem.eql(u8, existing, rdata)) continue;
        records.items[index].ttl = rr.ttl;
        records.items[index].rdata = try genericRdataText(arena, rdata);
        return;
    }
    try records.append(allocator, .{
        .owner = try arena.dupe(u8, name),
        .ttl = rr.ttl,
        .rrtype = rr.rrtype,
        .rdata = try genericRdataText(arena, rdata),
    });
}

fn applyDeleteAny(records: *std.ArrayList(parser.ZoneRecord), name: []const u8, domain: []const u8, rrtype: RecordType) void {
    const at_apex = std.ascii.eqlIgnoreCase(name, domain);
    const all_types = rrtype.eql(.ANY);
    var index: usize = 0;
    while (index < records.items.len) {
        const record = records.items[index];
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) {
            index += 1;
            continue;
        }
        const protected_apex = at_apex and (record.rrtype.eql(.SOA) or record.rrtype.eql(.NS));
        const delete = if (all_types) !protected_apex else !protected_apex and record.rrtype.eql(rrtype);
        if (delete) {
            _ = records.orderedRemove(index);
        } else {
            index += 1;
        }
    }
}

fn applyDeleteOne(records: *std.ArrayList(parser.ZoneRecord), name: []const u8, rr: dns_record.ResourceRecord, encode_buffer: []u8) Error!void {
    if (rr.rrtype.eql(.SOA)) return;
    const wanted = encodeUpdateRdata(rr, encode_buffer) catch return;
    var ns_count: usize = 0;
    if (rr.rrtype.eql(.NS)) {
        for (records.items) |record| {
            if (record.rrtype.eql(.NS) and std.ascii.eqlIgnoreCase(record.ownerText(), name)) ns_count += 1;
        }
    }
    var index: usize = 0;
    while (index < records.items.len) : (index += 1) {
        const record = records.items[index];
        if (!record.rrtype.eql(rr.rrtype)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), name)) continue;
        const existing = zoneRdataBytes(record, encode_buffer) orelse continue;
        if (!std.mem.eql(u8, existing, wanted)) continue;
        // RFC 2136 section 3.4.2.4: the last NS of an apex RRset stays.
        if (rr.rrtype.eql(.NS) and ns_count <= 1) return;
        _ = records.orderedRemove(index);
        return;
    }
}

fn raiseSerial(arena: std.mem.Allocator, records: *std.ArrayList(parser.ZoneRecord), domain: []const u8, soa_replaced: bool) Error!void {
    for (records.items) |*record| {
        if (!record.rrtype.eql(.SOA)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), domain)) continue;
        const parsed = parser.parseRData(.SOA, record.rdataText()) catch return;
        if (parsed != .SOA) return;
        if (soa_replaced) return;
        var soa = parsed.SOA;
        soa.serial +%= 1;
        var mname_buffer: [TEXT_BUFFER]u8 = undefined;
        var rname_buffer: [TEXT_BUFFER]u8 = undefined;
        const mname = soa.mname.toText(&mname_buffer) catch return;
        const rname = soa.rname.toText(&rname_buffer) catch return;
        record.rdata = try std.fmt.allocPrint(arena, "{s} {s} {d} {d} {d} {d} {d}", .{ mname, rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum });
        return;
    }
}

pub fn renderZoneText(allocator: std.mem.Allocator, domain: []const u8, records: []const parser.ZoneRecord) Error![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    // Every rendered record carries its own TTL; the directive is only the
    // parser's requirement for one.
    output.writer.print("$ORIGIN {s}\n$TTL 1\n", .{domain}) catch return Error.OutOfMemory;
    for (records) |record| {
        if (!record.rrtype.eql(.SOA)) continue;
        try writeRecord(&output.writer, record);
    }
    for (records) |record| {
        if (record.rrtype.eql(.SOA)) continue;
        try writeRecord(&output.writer, record);
    }
    var list = output.toArrayList();
    const text = list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
    // RFC 8976 section 3.4: a zone that publishes a ZONEMD publishes the
    // digest of the data it now serves, with the serial the update produced.
    if (try resealZonemdText(allocator, text)) |sealed| {
        allocator.free(text);
        return sealed;
    }
    return text;
}

/// Rewrites every apex ZONEMD record in a rendered zone text with the digest
/// of the new data (RFC 8976 section 3.4). The digest covers neither the apex
/// ZONEMD RRset nor its RRSIG (section 3.3.1.1), so one pass is enough. Null
/// when the zone carries no apex ZONEMD.
fn resealZonemdText(allocator: std.mem.Allocator, text: []const u8) Error!?[]u8 {
    var zone_file = parser.ZoneFile.parse(text) catch return null;
    defer zone_file.deinit();
    var zone = Zone.fromZoneFile(&zone_file) catch return null;
    defer zone.deinit();
    if (!zonemd.hasApexRecord(&zone)) return null;
    const serial = zone.soaSerial() orelse return null;

    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    var rewrote = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        const fields = blk: {
            const owner = tokens.next() orelse break :blk null;
            const ttl_text = tokens.next() orelse break :blk null;
            const class_text = tokens.next() orelse break :blk null;
            const type_text = tokens.next() orelse break :blk null;
            break :blk .{ owner, ttl_text, class_text, type_text };
        };
        const parsed_fields = fields orelse {
            output.writer.print("{s}\n", .{line}) catch return Error.OutOfMemory;
            continue;
        };
        const owner = parsed_fields[0];
        const ttl_text = parsed_fields[1];
        const class_text = parsed_fields[2];
        const type_text = parsed_fields[3];
        if (!std.ascii.eqlIgnoreCase(owner, zone.originText()) or !std.mem.eql(u8, type_text, "ZONEMD")) {
            output.writer.print("{s}\n", .{line}) catch return Error.OutOfMemory;
            continue;
        }
        const rdata_text = tokens.rest();
        const parsed = parser.parseRData(.ZONEMD, rdata_text) catch return null;
        const hash = zonemd.hashFromCode(parsed.ZONEMD.hash) orelse return null;
        var digest: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
        zonemd.computeDigest(&zone, hash, allocator, &digest) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            else => return null,
        };
        output.writer.print("{s} {s} {s} ZONEMD {d} {d} {d} ", .{
            owner,
            ttl_text,
            class_text,
            serial,
            parsed.ZONEMD.scheme,
            parsed.ZONEMD.hash,
        }) catch return Error.OutOfMemory;
        for (digest[0..hash.digestLen()]) |byte| output.writer.print("{x:0>2}", .{byte}) catch return Error.OutOfMemory;
        output.writer.writeByte('\n') catch return Error.OutOfMemory;
        rewrote = true;
    }
    if (!rewrote) {
        output.deinit();
        return null;
    }
    var list = output.toArrayList();
    return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
}

fn writeRecord(writer: *std.Io.Writer, record: parser.ZoneRecord) Error!void {
    if (recordTypeText(record.rrtype)) |mnemonic| {
        writer.print("{s} {d} IN {s} {s}\n", .{ record.ownerText(), record.ttl, mnemonic, record.rdataText() }) catch return Error.OutOfMemory;
    } else {
        writer.print("{s} {d} IN TYPE{d} {s}\n", .{ record.ownerText(), record.ttl, record.rrtype.code(), record.rdataText() }) catch return Error.OutOfMemory;
    }
}

fn recordTypeText(rrtype: RecordType) ?[]const u8 {
    if (rrtype.eql(.A)) return "A";
    if (rrtype.eql(.AAAA)) return "AAAA";
    if (rrtype.eql(.NS)) return "NS";
    if (rrtype.eql(.SOA)) return "SOA";
    if (rrtype.eql(.CNAME)) return "CNAME";
    if (rrtype.eql(.DNAME)) return "DNAME";
    if (rrtype.eql(.PTR)) return "PTR";
    if (rrtype.eql(.MX)) return "MX";
    if (rrtype.eql(.RT)) return "RT";
    if (rrtype.eql(.RP)) return "RP";
    if (rrtype.eql(.AFSDB)) return "AFSDB";
    if (rrtype.eql(.X25)) return "X25";
    if (rrtype.eql(.ISDN)) return "ISDN";
    if (rrtype.eql(.HINFO)) return "HINFO";
    if (rrtype.eql(.TXT)) return "TXT";
    if (rrtype.eql(.SRV)) return "SRV";
    if (rrtype.eql(.NAPTR)) return "NAPTR";
    if (rrtype.eql(.CAA)) return "CAA";
    if (rrtype.eql(.SSHFP)) return "SSHFP";
    if (rrtype.eql(.TLSA)) return "TLSA";
    if (rrtype.eql(.URI)) return "URI";
    if (rrtype.eql(.APL)) return "APL";
    if (rrtype.eql(.SVCB)) return "SVCB";
    if (rrtype.eql(.HTTPS)) return "HTTPS";
    if (rrtype.eql(.DS)) return "DS";
    if (rrtype.eql(.RRSIG)) return "RRSIG";
    if (rrtype.eql(.NSEC)) return "NSEC";
    if (rrtype.eql(.DNSKEY)) return "DNSKEY";
    if (rrtype.eql(.NSEC3)) return "NSEC3";
    if (rrtype.eql(.NSEC3PARAM)) return "NSEC3PARAM";
    if (rrtype.eql(.ZONEMD)) return "ZONEMD";
    return null;
}

fn genericRdataText(arena: std.mem.Allocator, bytes: []const u8) Error![]u8 {
    const hex = try arena.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        hex[index * 2] = digits[byte >> 4];
        hex[index * 2 + 1] = digits[byte & 0x0f];
    }
    return std.fmt.allocPrint(arena, "\\# {d} {s}", .{ bytes.len, hex }) catch return Error.OutOfMemory;
}

fn encodeUpdateRdata(rr: dns_record.ResourceRecord, buffer: []u8) Error![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    rr.rdata.encode(&writer) catch return Error.OutOfMemory;
    return writer.written();
}

fn encodedLen(rr: dns_record.ResourceRecord) usize {
    var buffer: [MAX_RDATA]u8 = undefined;
    const bytes = encodeUpdateRdata(rr, &buffer) catch return 0;
    return bytes.len;
}

fn zoneRdataBytes(record: parser.ZoneRecord, buffer: []u8) ?[]const u8 {
    const parsed = parser.parseRData(record.rrtype, record.rdataText()) catch return null;
    var writer = dns_writer.Writer.init(buffer);
    parsed.encode(&writer) catch return null;
    return writer.written();
}

fn containsMember(allocator: std.mem.Allocator, members: []const []const u8, rrtype: u16, bytes: []const u8) Error!bool {
    for (members) |member| {
        const canonical = try dnssec.canonicalRdata(allocator, rrtype, member);
        if (std.mem.eql(u8, canonical, bytes)) return true;
    }
    return false;
}

fn nameInUse(records: []const parser.ZoneRecord, name: []const u8) bool {
    for (records) |record| {
        if (std.ascii.eqlIgnoreCase(record.ownerText(), name)) return true;
    }
    return false;
}

fn rrsetExists(records: []const parser.ZoneRecord, name: []const u8, rrtype: RecordType) bool {
    for (records) |record| {
        if (!record.rrtype.eql(rrtype)) continue;
        if (std.ascii.eqlIgnoreCase(record.ownerText(), name)) return true;
    }
    return false;
}

fn isAtOrBelow(name: []const u8, parent: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, parent)) return true;
    if (name.len <= parent.len) return false;
    const offset = name.len - parent.len;
    if (!std.ascii.eqlIgnoreCase(name[offset..], parent)) return false;
    return name[offset - 1] == '.';
}

pub fn serialGreaterThan(candidate: u32, current: u32) bool {
    return @as(i32, @bitCast(candidate -% current)) > 0;
}

/// RFC 2136 section 3.4.1.2: the types that name a query, a transfer, or a
/// channel record rather than zone data. None of them may be added or
/// deleted by an update.
fn isQueryMetaType(rrtype: RecordType) bool {
    const code = rrtype.code();
    return code == 255 // ANY
    or code == 252 // AXFR
    or code == 251 // IXFR
    or code == 253 // MAILB
    or code == 254 // MAILA
    or code == 250 // TSIG
    or code == 41; // OPT
}

/// The types the signer generates for a signed apex, mirroring its
/// `alreadySigned` refusal set. An UPDATE that adds one while the zone is
/// signed would persist signer output as zone data and poison the next load,
/// so it is refused in the prescan. A delegation DS is never generated, so
/// it is not in this set and stays updatable.
fn isSignerOwnedType(rrtype: RecordType) bool {
    return rrtype.eql(.DNSKEY) or rrtype.eql(.RRSIG) or rrtype.eql(.NSEC) or rrtype.eql(.NSEC3) or rrtype.eql(.NSEC3PARAM);
}

const test_zone_text =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns1.example.com. hostmaster.example.com. 7 3600 900 1209600 3600
    \\@ IN NS ns1.example.com.
    \\ns1 IN A 192.0.2.1
    \\www IN A 192.0.2.10
    \\www IN TXT "hello"
;

fn buildZone(text: []const u8) !Zone {
    var file = parser.ZoneFile.parse(text) catch unreachable;
    errdefer file.deinit();
    return Zone.fromZoneFile(&file);
}

fn makeName(text: []const u8) dns_name.Name {
    return dns_name.Name.fromText(text) catch unreachable;
}

fn emptyRdata() dns_rdata.RData {
    return .{ .Unknown = .{} };
}

fn makeRecord(owner: []const u8, rrtype: RecordType, class: u16, ttl: u32, rdata: dns_rdata.RData) dns_record.ResourceRecord {
    return .{ .owner = makeName(owner), .rrtype = rrtype, .class = .{ .value = class }, .ttl = ttl, .rdata = rdata };
}

fn aRecord(owner: []const u8, address: [4]u8, ttl: u32) dns_record.ResourceRecord {
    return makeRecord(owner, .A, CLASS_IN, ttl, .{ .A = address });
}

fn zoneRcode(outcome: Outcome) header.Rcode {
    return switch (outcome) {
        .rcode => |rcode| rcode,
        .zone_text => unreachable,
    };
}

fn zoneText(outcome: Outcome) []u8 {
    return switch (outcome) {
        .zone_text => |text| text,
        .rcode => unreachable,
    };
}

test "an update adds an A record and raises the serial" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{aRecord("new.example.com.", .{ 192, 0, 2, 20 }, 60)};
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    var lookup = rebuilt.lookup(std.testing.allocator, "new.example.com.", .A);
    defer lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(.answer, lookup.kind);
    try std.testing.expectEqual(@as(u32, 8), rebuilt.soaSerial().?);
}

test "an update reseals a published ZONEMD" {
    // RFC 8976 section 3.4: the digest follows the data and the serial the
    // update produced. The placeholder digest is the right length and wrong
    // value, so the old record cannot pass by accident.
    const sealed_zone_text =
        \\$ORIGIN example.com.
        \\$TTL 3600
        \\@ IN SOA ns1.example.com. hostmaster.example.com. 7 3600 900 1209600 3600
        \\@ IN NS ns1.example.com.
        \\@ IN ZONEMD 7 1 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        \\ns1 IN A 192.0.2.1
        \\
    ;
    var zone = try buildZone(sealed_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{aRecord("new.example.com.", .{ 192, 0, 2, 20 }, 60)};
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);

    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    try std.testing.expectEqual(@as(u32, 8), rebuilt.soaSerial().?);
    var report: [1024]u8 = undefined;
    const message = try zonemd.verify(&rebuilt, std.testing.allocator, &report);
    try std.testing.expect(std.mem.startsWith(u8, message, "zone example.com.: ZONEMD verified"));
    try std.testing.expect(std.mem.indexOf(u8, text, "ZONEMD 8 1 1 0000000000") == null);
}
test "an update refuses an unverifiable ZONEMD" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    const before = try renderZoneText(std.testing.allocator, "example.com.", zone.records.items);
    defer std.testing.allocator.free(before);
    var bad = [_]dns_record.ResourceRecord{makeRecord("example.com.", .ZONEMD, CLASS_IN, 3600, .{ .ZONEMD = .{ .serial = 7, .scheme = 1, .hash = 99 } })};
    try std.testing.expectEqual(header.Rcode.refused, zoneRcode(try apply(std.testing.allocator, &zone, "example.com.", &.{}, &bad)));
    var off = [_]dns_record.ResourceRecord{makeRecord("sub.example.com.", .ZONEMD, CLASS_IN, 3600, .{ .ZONEMD = .{ .serial = 7, .scheme = 1, .hash = 1 } })};
    try std.testing.expectEqual(header.Rcode.refused, zoneRcode(try apply(std.testing.allocator, &zone, "example.com.", &.{}, &off)));
    const after = try renderZoneText(std.testing.allocator, "example.com.", zone.records.items);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);
}

test "a duplicate add replaces the record's TTL" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{aRecord("www.example.com.", .{ 192, 0, 2, 10 }, 30)};
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    var lookup = rebuilt.lookup(std.testing.allocator, "www.example.com.", .A);
    defer lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(.answer, lookup.kind);
    try std.testing.expectEqual(@as(usize, 1), lookup.records.len);
    try std.testing.expectEqual(@as(u32, 30), lookup.records.items[0].ttl);
}

test "delete one RR removes only the matching RDATA" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{
        makeRecord("www.example.com.", .A, CLASS_NONE, 0, .{ .A = .{ 192, 0, 2, 10 } }),
        makeRecord("www.example.com.", .A, CLASS_NONE, 0, .{ .A = .{ 192, 0, 2, 99 } }),
    };
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    var lookup = rebuilt.lookup(std.testing.allocator, "www.example.com.", .A);
    defer lookup.deinit(std.testing.allocator);
    // The name still holds its TXT record, so the type is a NODATA answer.
    try std.testing.expectEqual(.nodata, lookup.kind);
}

test "delete an RRset removes the type and keeps the rest" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{
        makeRecord("www.example.com.", .A, CLASS_ANY, 0, emptyRdata()),
    };
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    var a_lookup = rebuilt.lookup(std.testing.allocator, "www.example.com.", .A);
    defer a_lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(.nodata, a_lookup.kind);
    var txt_lookup = rebuilt.lookup(std.testing.allocator, "www.example.com.", .TXT);
    defer txt_lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(.answer, txt_lookup.kind);
}

test "delete every RRset at an apex name keeps the SOA and the NS" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{
        makeRecord("example.com.", .ANY, CLASS_ANY, 0, emptyRdata()),
    };
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    try std.testing.expect(rebuilt.soaSerial() != null);
    var ns_lookup = rebuilt.lookup(std.testing.allocator, "example.com.", .NS);
    defer ns_lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(.answer, ns_lookup.kind);
}

test "RFC 2181 section 10.1: an add never creates a second CNAME" {
    const cname_zone =
        \\$ORIGIN example.com.
        \\$TTL 3600
        \\@ IN SOA ns1.example.com. hostmaster.example.com. 7 3600 900 1209600 3600
        \\@ IN NS ns1.example.com.
        \\alias IN CNAME first.example.com.
        \\
    ;
    var zone = try buildZone(cname_zone);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{makeRecord("alias.example.com.", .CNAME, CLASS_IN, 60, .{ .CNAME = makeName("second.example.com.") })};
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    var count: usize = 0;
    for (rebuilt.records.items[0..rebuilt.records.len]) |record| {
        if (!record.rrtype.eql(.CNAME)) continue;
        count += 1;
        try std.testing.expectEqualStrings("first.example.com.", record.rdataText());
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "RFC 2136 section 3.4.1.2: a meta type cannot be added by an update" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    const maila = RecordType{ .value = 254 };
    const ixfr = RecordType{ .value = 251 };
    const cases = [_]struct { rr: dns_record.ResourceRecord, class: u16 }{
        .{ .rr = makeRecord("www.example.com.", maila, CLASS_IN, 60, emptyRdata()), .class = CLASS_IN },
        .{ .rr = makeRecord("www.example.com.", ixfr, CLASS_IN, 60, emptyRdata()), .class = CLASS_IN },
        .{ .rr = makeRecord("www.example.com.", .OPT, CLASS_IN, 0, emptyRdata()), .class = CLASS_IN },
        .{ .rr = makeRecord("www.example.com.", ixfr, CLASS_ANY, 0, emptyRdata()), .class = CLASS_ANY },
    };
    for (cases) |case| {
        var updates = [_]dns_record.ResourceRecord{case.rr};
        const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
        try std.testing.expectEqual(header.Rcode.formerr, zoneRcode(outcome));
    }
}

test "an update cannot add a signer-owned type to a signed zone" {
    // The served zone carries the signer's generated tail: any class-IN add
    // of a signer-owned type is refused in the prescan, before anything is
    // persisted, so the file never carries one and the next load never trips
    // the signer's AlreadySigned refusal.
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var tail = [_]parser.ZoneRecord{.{
        .owner = "example.com.",
        .ttl = 3600,
        .rrtype = .RRSIG,
        .rdata = "bogus",
    }};
    var served = try std.testing.allocator.alloc(parser.ZoneRecord, zone.records.len + tail.len);
    defer std.testing.allocator.free(served);
    @memcpy(served[0..zone.records.len], zone.records.items[0..zone.records.len]);
    @memcpy(served[zone.records.len..], tail[0..]);
    zone.records.items = served;
    zone.records.len = served.len;
    zone.generated = served[served.len - tail.len ..];
    const types = [_]RecordType{ .DNSKEY, .RRSIG, .NSEC, .NSEC3, .NSEC3PARAM };
    for (types) |rrtype| {
        const update = makeRecord("example.com.", rrtype, CLASS_IN, 3600, emptyRdata());
        var updates = [_]dns_record.ResourceRecord{update};
        const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
        try std.testing.expectEqual(header.Rcode.refused, zoneRcode(outcome));
    }
    // A delegation DS is not generated, so adding one is still accepted.
    const ds = makeRecord("child.example.com.", .DS, CLASS_IN, 3600, emptyRdata());
    var ds_updates = [_]dns_record.ResourceRecord{ds};
    const ds_outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &ds_updates);
    std.testing.allocator.free(zoneText(ds_outcome));
    zone.generated = &.{};
}

test "prerequisites still see the generated RRsets of a signed zone" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var tail = [_]parser.ZoneRecord{.{
        .owner = "example.com.",
        .ttl = 3600,
        .rrtype = .DNSKEY,
        .rdata = "256 3 15 AQID",
    }};
    var served = try std.testing.allocator.alloc(parser.ZoneRecord, zone.records.len + tail.len);
    defer std.testing.allocator.free(served);
    @memcpy(served[0..zone.records.len], zone.records.items[0..zone.records.len]);
    @memcpy(served[zone.records.len..], tail[0..]);
    zone.records.items = served;
    zone.records.len = served.len;
    zone.generated = served[served.len - tail.len ..];
    // A prerequisite for the generated DNSKEY RRset must match: the §3.2
    // check runs against the served data, not just the loaded records.
    const exists = makeRecord("example.com.", .DNSKEY, CLASS_ANY, 0, emptyRdata());
    var prerequisites = [_]dns_record.ResourceRecord{exists};
    const matched = try apply(std.testing.allocator, &zone, "example.com.", &prerequisites, &.{});
    std.testing.allocator.free(zoneText(matched));
    // And a value-dependent prerequisite on it is honored too.
    const missing = makeRecord("example.com.", .RRSIG, CLASS_ANY, 0, emptyRdata());
    var missing_prerequisites = [_]dns_record.ResourceRecord{missing};
    const refused = try apply(std.testing.allocator, &zone, "example.com.", &missing_prerequisites, &.{});
    try std.testing.expectEqual(header.Rcode.nxrrset, zoneRcode(refused));
    zone.generated = &.{};
}

test "prerequisites refuse with the RFC rcode" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    const cases = [_]struct { rr: dns_record.ResourceRecord, rcode: header.Rcode }{
        .{ .rr = makeRecord("absent.example.com.", .ANY, CLASS_ANY, 0, emptyRdata()), .rcode = .nxdomain },
        .{ .rr = makeRecord("absent.example.com.", .A, CLASS_ANY, 0, emptyRdata()), .rcode = .nxrrset },
        .{ .rr = makeRecord("www.example.com.", .ANY, CLASS_NONE, 0, emptyRdata()), .rcode = .yxdomain },
        .{ .rr = makeRecord("www.example.com.", .A, CLASS_NONE, 0, emptyRdata()), .rcode = .yxrrset },
        .{ .rr = makeRecord("www.example.com.", .A, CLASS_ANY, 60, emptyRdata()), .rcode = .formerr },
        .{ .rr = makeRecord("elsewhere.test.", .A, CLASS_ANY, 0, emptyRdata()), .rcode = .notzone },
    };
    for (cases) |case| {
        var prerequisites = [_]dns_record.ResourceRecord{case.rr};
        const outcome = try apply(std.testing.allocator, &zone, "example.com.", &prerequisites, &.{});
        try std.testing.expectEqual(case.rcode, zoneRcode(outcome));
    }
}

test "a value-dependent prerequisite must match the RRset exactly" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var matching = [_]dns_record.ResourceRecord{
        makeRecord("www.example.com.", .A, CLASS_IN, 0, .{ .A = .{ 192, 0, 2, 10 } }),
    };
    var updates = [_]dns_record.ResourceRecord{aRecord("www.example.com.", .{ 192, 0, 2, 11 }, 60)};
    const accepted = try apply(std.testing.allocator, &zone, "example.com.", &matching, &updates);
    std.testing.allocator.free(zoneText(accepted));

    var wrong = [_]dns_record.ResourceRecord{
        makeRecord("www.example.com.", .A, CLASS_IN, 0, .{ .A = .{ 192, 0, 2, 11 } }),
    };
    const refused = try apply(std.testing.allocator, &zone, "example.com.", &wrong, &updates);
    try std.testing.expectEqual(header.Rcode.nxrrset, zoneRcode(refused));
}

test "RFC 2136 section 1.1: a prerequisite name compares case-insensitively" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    // The zone publishes `example.com. NS ns1.example.com.`. The
    // prerequisite states the same target in another case: RFC 2136
    // section 1.1 makes the domain names in RDATA case-insensitive, so the
    // RRset matches member for member.
    var matching = [_]dns_record.ResourceRecord{
        makeRecord("example.com.", .NS, CLASS_IN, 0, .{ .NS = makeName("NS1.Example.COM.") }),
    };
    var updates = [_]dns_record.ResourceRecord{aRecord("www.example.com.", .{ 192, 0, 2, 31 }, 60)};
    const accepted = try apply(std.testing.allocator, &zone, "example.com.", &matching, &updates);
    std.testing.allocator.free(zoneText(accepted));

    var different = [_]dns_record.ResourceRecord{
        makeRecord("example.com.", .NS, CLASS_IN, 0, .{ .NS = makeName("ns2.example.com.") }),
    };
    const refused = try apply(std.testing.allocator, &zone, "example.com.", &different, &updates);
    try std.testing.expectEqual(header.Rcode.nxrrset, zoneRcode(refused));
}

test "an update outside the zone is NOTZONE" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    var updates = [_]dns_record.ResourceRecord{aRecord("elsewhere.test.", .{ 192, 0, 2, 20 }, 60)};
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    try std.testing.expectEqual(header.Rcode.notzone, zoneRcode(outcome));
}

test "an SOA update with a greater serial is kept" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    const soa = dns_rdata.Soa{
        .mname = makeName("ns1.example.com."),
        .rname = makeName("hostmaster.example.com."),
        .serial = 42,
        .refresh = 3600,
        .retry = 900,
        .expire = 1209600,
        .minimum = 3600,
    };
    var updates = [_]dns_record.ResourceRecord{
        makeRecord("example.com.", .SOA, CLASS_IN, 3600, .{ .SOA = soa }),
    };
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    try std.testing.expectEqual(@as(u32, 42), rebuilt.soaSerial().?);
}

test "an SOA update with a stale serial is ignored and the serial still rises" {
    var zone = try buildZone(test_zone_text);
    defer zone.deinit();
    const soa = dns_rdata.Soa{
        .mname = makeName("ns1.example.com."),
        .rname = makeName("hostmaster.example.com."),
        .serial = 3,
        .refresh = 3600,
        .retry = 900,
        .expire = 1209600,
        .minimum = 3600,
    };
    var updates = [_]dns_record.ResourceRecord{
        makeRecord("example.com.", .SOA, CLASS_IN, 3600, .{ .SOA = soa }),
        aRecord("new.example.com.", .{ 192, 0, 2, 20 }, 60),
    };
    const outcome = try apply(std.testing.allocator, &zone, "example.com.", &.{}, &updates);
    const text = zoneText(outcome);
    defer std.testing.allocator.free(text);
    var rebuilt = try buildZone(text);
    defer rebuilt.deinit();
    try std.testing.expectEqual(@as(u32, 8), rebuilt.soaSerial().?);
}
