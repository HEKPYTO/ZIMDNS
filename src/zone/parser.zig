/// Contract: Parses authoritative zone text into validated zone records.
/// Ownership: ZoneFile owns its exact retained backing and records; call ZoneFile.deinit; input text is borrowed.
/// Errors: Zone syntax and allocation limits are typed parser errors; file I/O belongs to callers.
const std = @import("std");
const RecordType = @import("../dns/types.zig").RecordType;
const dns_name = @import("../dns/name.zig");
const dns_rdata = @import("../dns/rdata.zig");

/// Maximum temporary parser-owned backing used while loading one zone.
pub const max_zone_allocation_bytes: usize = 16 * 1024 * 1024;

/// RFC 2181 section 8: a TTL is an unsigned value of at most 2^31-1, so a
/// larger value has no legal wire encoding and is refused.
const max_ttl: u32 = 0x7fff_ffff;

pub const Error = error{
    MissingOrigin,
    MissingTtl,
    MissingSoa,
    MissingApexNs,
    MultipleApexSoa,
    SoaNotAtApex,
    CnameConflict,
    AllocationBudgetExceeded,
    BadDirective,
    BadRecord,
    BadTtl,
    BadName,
};

pub const ZoneRecord = struct {
    owner: []const u8 = &.{},
    ttl: u32,
    rrtype: RecordType,
    rdata: []const u8 = &.{},

    pub fn ownerText(self: *const ZoneRecord) []const u8 {
        return self.owner;
    }

    pub fn rdataText(self: *const ZoneRecord) []const u8 {
        return self.rdata;
    }
};

pub const RecordList = struct {
    items: []ZoneRecord = &.{},
    len: usize = 0,

    pub fn append(self: *RecordList, allocator: std.mem.Allocator, record: ZoneRecord) !void {
        if (self.len == self.items.len) {
            const new_capacity = if (self.items.len == 0) 1 else std.math.mul(usize, self.items.len, 2) catch {
                return error.OutOfMemory;
            };
            self.items = if (self.items.len == 0)
                try allocator.alloc(ZoneRecord, new_capacity)
            else
                try allocator.realloc(self.items, new_capacity);
        }
        self.items[self.len] = record;
        self.len += 1;
    }
};

pub const ZoneFile = struct {
    backing: []u8,
    storage: std.heap.FixedBufferAllocator,
    origin: []const u8 = &.{},
    default_ttl: u32 = 0,
    records: RecordList = .{},

    /// The ZoneFile owns every returned origin, record, and RDATA slice through
    /// its exact retained backing allocation. Call deinit when it is no longer used.
    pub fn parse(text: []const u8) !ZoneFile {
        return parseWithBudget(text, max_zone_allocation_bytes);
    }

    fn parseWithBudget(text: []const u8, allocation_budget: usize) !ZoneFile {
        const retained_size = blk: {
            const probe_backing = try std.heap.page_allocator.alloc(u8, allocation_budget);
            defer std.heap.page_allocator.free(probe_backing);

            var probe = ZoneFile{
                .backing = probe_backing,
                .storage = std.heap.FixedBufferAllocator.init(probe_backing),
            };
            parseWithAllocator(&probe, probe.storage.allocator(), text, allocation_budget) catch |err| switch (err) {
                error.OutOfMemory => return Error.AllocationBudgetExceeded,
                else => return err,
            };
            break :blk probe.storage.end_index;
        };
        const backing = try std.heap.page_allocator.alloc(u8, retained_size);
        var zone = ZoneFile{
            .backing = backing,
            .storage = std.heap.FixedBufferAllocator.init(backing),
        };
        errdefer zone.deinit();
        parseWithAllocator(&zone, zone.storage.allocator(), text, retained_size) catch |err| switch (err) {
            error.OutOfMemory => return Error.AllocationBudgetExceeded,
            else => return err,
        };
        return zone;
    }

    fn parseWithAllocator(zone: *ZoneFile, storage_allocator: std.mem.Allocator, text: []const u8, allocation_budget: usize) !void {
        var saw_apex_soa = false;
        var saw_apex_ns = false;

        var logical_buffer: std.ArrayList(u8) = .empty;
        defer logical_buffer.deinit(storage_allocator);
        var paren_depth: usize = 0;

        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const stripped = stripComment(raw_line);
            const trimmed = std.mem.trim(u8, stripped, " \t\r");
            if (trimmed.len == 0) continue;

            const separator_len: usize = if (logical_buffer.items.len == 0) 0 else 1;
            const base_len = std.math.add(usize, logical_buffer.items.len, separator_len) catch {
                return Error.AllocationBudgetExceeded;
            };
            const required_len = std.math.add(usize, base_len, trimmed.len) catch {
                return Error.AllocationBudgetExceeded;
            };
            if (required_len > allocation_budget) return Error.AllocationBudgetExceeded;
            if (logical_buffer.capacity < required_len) {
                try logical_buffer.ensureTotalCapacityPrecise(storage_allocator, required_len);
            }
            if (separator_len != 0) try logical_buffer.append(storage_allocator, ' ');
            try logical_buffer.appendSlice(storage_allocator, trimmed);
            paren_depth = updateParenDepth(paren_depth, trimmed);
            if (paren_depth != 0) continue;

            const logical = logical_buffer.items;
            try zone.parseLogicalLine(storage_allocator, logical, &saw_apex_soa, &saw_apex_ns);
            logical_buffer.clearRetainingCapacity();
        }

        if (logical_buffer.items.len != 0) return Error.BadRecord;
        if (zone.origin.len == 0) return Error.MissingOrigin;
        if (zone.default_ttl == 0) return Error.MissingTtl;
        if (!saw_apex_soa) return Error.MissingSoa;
        if (!saw_apex_ns) return Error.MissingApexNs;
    }

    pub fn deinit(self: *ZoneFile) void {
        std.heap.page_allocator.free(self.backing);
        self.backing = &.{};
        self.storage = std.heap.FixedBufferAllocator.init(self.backing);
        self.records = .{};
        self.origin = &.{};
        self.default_ttl = 0;
    }

    pub fn originText(self: *const ZoneFile) []const u8 {
        return self.origin;
    }

    fn parseLogicalLine(self: *ZoneFile, allocator: std.mem.Allocator, line: []const u8, saw_apex_soa: *bool, saw_apex_ns: *bool) !void {
        var tokens = Tokenizer.init(line);
        const first = tokens.next() orelse return;

        if (std.mem.eql(u8, first, "$ORIGIN")) {
            const origin = tokens.next() orelse return Error.BadDirective;
            if (tokens.next() != null) return Error.BadDirective;
            const origin_text = try ensureTrailingDot(allocator, origin);
            try validateName(origin_text);
            if (self.records.len != 0 and !std.ascii.eqlIgnoreCase(self.originText(), origin_text)) return Error.BadDirective;
            const copied_origin = try copyText(allocator, origin_text);
            self.origin = copied_origin;
            return;
        }

        if (std.mem.eql(u8, first, "$TTL")) {
            const ttl_text = tokens.next() orelse return Error.BadDirective;
            if (tokens.next() != null) return Error.BadDirective;
            const parsed_default_ttl = std.fmt.parseInt(u32, ttl_text, 10) catch return Error.BadTtl;
            if (parsed_default_ttl > max_ttl) return Error.BadTtl;
            self.default_ttl = parsed_default_ttl;
            return;
        }

        if (self.origin.len == 0) return Error.MissingOrigin;
        if (self.default_ttl == 0) return Error.MissingTtl;

        var ttl = self.default_ttl;
        var rrtype: ?RecordType = null;
        const owner_token = first;

        var token = tokens.next() orelse return Error.BadRecord;
        if (parseOptionalTtl(token)) |parsed_ttl| {
            if (parsed_ttl > max_ttl) return Error.BadTtl;
            ttl = parsed_ttl;
            token = tokens.next() orelse return Error.BadRecord;
        }
        if (std.mem.eql(u8, token, "IN")) {
            token = tokens.next() orelse return Error.BadRecord;
        }
        rrtype = parseRecordType(token);
        if (rrtype == null) return Error.BadRecord;
        var record = ZoneRecord{
            .ttl = ttl,
            .rrtype = rrtype.?,
        };
        try self.expandOwner(allocator, owner_token, &record);
        errdefer allocator.free(record.owner);
        record.rdata = try normalizeRData(allocator, record.rrtype, self.originText(), tokens.rest());
        errdefer allocator.free(record.rdata);
        _ = try parseRData(record.rrtype, record.rdataText());

        for (self.records.items[0..self.records.len]) |existing| {
            if (!std.ascii.eqlIgnoreCase(existing.ownerText(), record.ownerText())) continue;
            if (existing.rrtype.eql(.CNAME) or record.rrtype.eql(.CNAME)) return Error.CnameConflict;
        }

        if (record.rrtype.eql(.SOA)) {
            if (!std.ascii.eqlIgnoreCase(record.ownerText(), self.originText())) return Error.SoaNotAtApex;
            if (saw_apex_soa.*) return Error.MultipleApexSoa;
            saw_apex_soa.* = true;
        }

        try self.records.append(allocator, record);

        // RFC 2181 section 5.2: all RRs in an RRSet share one TTL, so
        // same-owner, same-type records normalize to the lowest TTL listed.
        // RRSIG records are exempt (RFC 4034 section 2.3: an RRSIG's TTL is
        // the TTL of the RRSet it covers).
        if (!record.rrtype.eql(.RRSIG)) {
            var lowest = record.ttl;
            for (self.records.items[0..self.records.len]) |existing| {
                if (!std.ascii.eqlIgnoreCase(existing.ownerText(), record.ownerText())) continue;
                if (!existing.rrtype.eql(record.rrtype)) continue;
                lowest = @min(lowest, existing.ttl);
            }
            for (self.records.items[0..self.records.len]) |*existing| {
                if (!std.ascii.eqlIgnoreCase(existing.ownerText(), record.ownerText())) continue;
                if (!existing.rrtype.eql(record.rrtype)) continue;
                existing.ttl = lowest;
            }
        }

        if (record.rrtype.eql(.NS) and std.ascii.eqlIgnoreCase(record.ownerText(), self.originText())) saw_apex_ns.* = true;
    }

    fn expandOwner(self: *ZoneFile, allocator: std.mem.Allocator, owner: []const u8, record: *ZoneRecord) !void {
        if (std.mem.eql(u8, owner, "@")) {
            record.owner = try copyText(allocator, self.originText());
        } else if (std.mem.endsWith(u8, owner, ".")) {
            record.owner = try copyText(allocator, owner);
        } else {
            const owner_len = std.math.add(usize, owner.len, 1) catch return error.OutOfMemory;
            const expanded_len = std.math.add(usize, owner_len, self.origin.len) catch return error.OutOfMemory;
            const expanded = try allocator.alloc(u8, expanded_len);
            @memcpy(expanded[0..owner.len], owner);
            expanded[owner.len] = '.';
            @memcpy(expanded[owner.len + 1 ..], self.originText());
            record.owner = expanded;
        }
        errdefer allocator.free(record.owner);
        try validateName(record.ownerText());
    }

    fn copyText(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
        const copy = try allocator.alloc(u8, text.len);
        @memcpy(copy, text);
        return copy;
    }
};

const Tokenizer = struct {
    line: []const u8,
    index: usize = 0,

    fn init(line: []const u8) Tokenizer {
        return .{ .line = line };
    }

    fn next(self: *Tokenizer) ?[]const u8 {
        while (self.index < self.line.len and std.ascii.isWhitespace(self.line[self.index])) self.index += 1;
        if (self.index >= self.line.len) return null;
        if (self.line[self.index] == '"') {
            const start = self.index + 1;
            self.index += 1;
            while (self.index < self.line.len and self.line[self.index] != '"') self.index += 1;
            const end = self.index;
            if (self.index < self.line.len) self.index += 1;
            return self.line[start..end];
        }
        const start = self.index;
        while (self.index < self.line.len and !std.ascii.isWhitespace(self.line[self.index])) self.index += 1;
        return self.line[start..self.index];
    }

    fn rest(self: *Tokenizer) []const u8 {
        const start = self.index;
        return std.mem.trim(u8, self.line[start..], " \t\r()");
    }
};

fn stripComment(line: []const u8) []const u8 {
    var in_quote = false;
    var index: usize = 0;
    while (index < line.len) : (index += 1) {
        const byte = line[index];
        if (in_quote and byte == '\\' and index + 1 < line.len) {
            index += 1;
            continue;
        }
        if (byte == '"') in_quote = !in_quote;
        if (byte == ';' and !in_quote) return line[0..index];
    }
    return line;
}

fn updateParenDepth(start_depth: usize, line: []const u8) usize {
    var depth = start_depth;
    var in_quote = false;
    var index: usize = 0;
    while (index < line.len) : (index += 1) {
        const byte = line[index];
        if (in_quote and byte == '\\' and index + 1 < line.len) {
            index += 1;
            continue;
        }
        if (byte == '"') in_quote = !in_quote;
        if (in_quote) continue;
        if (byte == '(') depth += 1;
        if (byte == ')' and depth > 0) depth -= 1;
    }
    return depth;
}

fn parseOptionalTtl(text: []const u8) ?u32 {
    return std.fmt.parseInt(u32, text, 10) catch null;
}

fn parseRecordType(text: []const u8) ?RecordType {
    if (std.mem.eql(u8, text, "A")) return .A;
    if (std.mem.eql(u8, text, "AAAA")) return .AAAA;
    if (std.mem.eql(u8, text, "NS")) return .NS;
    if (std.mem.eql(u8, text, "SOA")) return .SOA;
    if (std.mem.eql(u8, text, "CNAME")) return .CNAME;
    if (std.mem.eql(u8, text, "DNAME")) return .DNAME;
    if (std.mem.eql(u8, text, "PTR")) return .PTR;
    if (std.mem.eql(u8, text, "MX")) return .MX;
    if (std.mem.eql(u8, text, "RT")) return .RT;
    if (std.mem.eql(u8, text, "RP")) return .RP;
    if (std.mem.eql(u8, text, "AFSDB")) return .AFSDB;
    if (std.mem.eql(u8, text, "X25")) return .X25;
    if (std.mem.eql(u8, text, "ISDN")) return .ISDN;
    if (std.mem.eql(u8, text, "HINFO")) return .HINFO;
    if (std.mem.eql(u8, text, "TXT")) return .TXT;
    if (std.mem.eql(u8, text, "SRV")) return .SRV;
    if (std.mem.eql(u8, text, "NAPTR")) return .NAPTR;
    if (std.mem.eql(u8, text, "CAA")) return .CAA;
    if (std.mem.eql(u8, text, "SSHFP")) return .SSHFP;
    if (std.mem.eql(u8, text, "TLSA")) return .TLSA;
    if (std.mem.eql(u8, text, "URI")) return .URI;
    if (std.mem.eql(u8, text, "APL")) return .APL;
    if (std.mem.eql(u8, text, "SVCB")) return .SVCB;
    if (std.mem.eql(u8, text, "HTTPS")) return .HTTPS;
    if (std.mem.eql(u8, text, "DS")) return .DS;
    if (std.mem.eql(u8, text, "RRSIG")) return .RRSIG;
    if (std.mem.eql(u8, text, "NSEC")) return .NSEC;
    if (std.mem.eql(u8, text, "DNSKEY")) return .DNSKEY;
    if (std.mem.eql(u8, text, "NSEC3")) return .NSEC3;
    if (std.mem.eql(u8, text, "NSEC3PARAM")) return .NSEC3PARAM;
    if (std.mem.eql(u8, text, "ZONEMD")) return .ZONEMD;
    if (text.len > 4 and std.ascii.eqlIgnoreCase(text[0..4], "TYPE")) {
        const code = std.fmt.parseInt(u16, text[4..], 10) catch return null;
        return RecordType.fromCode(code);
    }
    return null;
}

fn validateName(text: []const u8) Error!void {
    _ = dns_name.Name.fromText(text) catch return Error.BadName;
}

/// Parses one supported zone-text RDATA value. Zone loading calls this before
/// retaining a record; responses reuse it as a defensive conversion step.
pub fn parseRData(rrtype: RecordType, text: []const u8) Error!dns_rdata.RData {
    if (rrtype.eql(.A)) return .{ .A = try parseIpv4(text) };
    if (rrtype.eql(.AAAA)) return .{ .AAAA = try parseIpv6(text) };
    if (rrtype.eql(.NS)) return .{ .NS = try parseRdataName(text) };
    if (rrtype.eql(.CNAME)) return .{ .CNAME = try parseRdataName(text) };
    if (rrtype.eql(.DNAME)) return .{ .DNAME = try parseRdataName(text) };
    if (rrtype.eql(.PTR)) return .{ .PTR = try parseRdataName(text) };
    if (rrtype.eql(.SOA)) return .{ .SOA = try parseSoa(text) };
    if (rrtype.eql(.MX)) return .{ .MX = try parseMx(text) };
    if (rrtype.eql(.RT)) return .{ .RT = try parseMx(text) };
    if (rrtype.eql(.RP)) return .{ .RP = try parseRp(text) };
    if (rrtype.eql(.AFSDB)) return .{ .AFSDB = try parseAfsdb(text) };
    if (rrtype.eql(.X25)) return .{ .X25 = try parseX25(text) };
    if (rrtype.eql(.ISDN)) return .{ .ISDN = try parseIsdn(text) };
    if (rrtype.eql(.HINFO)) return .{ .HINFO = try parseHinfo(text) };
    if (rrtype.eql(.TXT)) return .{ .TXT = try parseTxt(text) };
    if (rrtype.eql(.SRV)) return .{ .SRV = try parseSrv(text) };
    if (rrtype.eql(.NAPTR)) return .{ .NAPTR = try parseNaptr(text) };
    if (rrtype.eql(.CAA)) return .{ .CAA = try parseCaa(text) };
    if (rrtype.eql(.SSHFP)) return .{ .SSHFP = try parseSshfp(text) };
    if (rrtype.eql(.TLSA)) return .{ .TLSA = try parseTlsa(text) };
    if (rrtype.eql(.URI)) return .{ .URI = try parseUri(text) };
    if (rrtype.eql(.APL)) return .{ .APL = try parseApl(text) };
    if (rrtype.eql(.SVCB)) return .{ .SVCB = try parseSvcb(text) };
    if (rrtype.eql(.HTTPS)) return .{ .HTTPS = try parseSvcb(text) };
    if (rrtype.eql(.DNSKEY)) return .{ .Unknown = try parseDnskey(text) };
    if (rrtype.eql(.DS)) return .{ .Unknown = try parseDs(text) };
    if (rrtype.eql(.RRSIG)) return .{ .Unknown = try parseRrsig(text) };
    if (rrtype.eql(.NSEC)) return .{ .Unknown = try parseNsec(text) };
    if (rrtype.eql(.NSEC3)) return .{ .Unknown = try parseNsec3(text) };
    if (rrtype.eql(.NSEC3PARAM)) return .{ .Unknown = try parseNsec3Param(text) };
    if (rrtype.eql(.ZONEMD)) return .{ .ZONEMD = try parseZonemd(text) };
    return Error.BadRecord;
}

/// DNSSEC zone RDATA is served opaque (RFC 4034/5155 wire bytes in an Unknown
/// slot). Every parser below also accepts the RFC 3597 generic form
/// `\# <hex>` so operators can paste wire bytes directly.
fn parseDnssecGeneric(text: []const u8) ?dns_rdata.Unknown {
    const input = std.mem.trim(u8, text, " \t\r\n");
    if (input.len < 2 or input[0] != '\\' or input[1] != '#') return null;
    const hex = std.mem.trim(u8, input[2..], " \t\r\n");
    return decodeHexBlob(hex) catch null;
}

fn decodeHexBlob(hex: []const u8) Error!dns_rdata.Unknown {
    var compact: [4096]u8 = undefined;
    var compact_len: usize = 0;
    for (hex) |byte| {
        // Presentation hex blobs allow embedded whitespace and the zone-file
        // grammar wraps long values in parentheses, which survive mid-string
        // because Tokenizer.rest only trims them at the ends.
        if (std.ascii.isWhitespace(byte) or byte == '(' or byte == ')') continue;
        if (compact_len >= compact.len) return Error.BadRecord;
        compact[compact_len] = byte;
        compact_len += 1;
    }
    if (compact_len % 2 != 0 or compact_len / 2 > 2048) return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    var i: usize = 0;
    while (i < compact_len) : (i += 2) {
        const high = parseHexDigit(compact[i]) orelse return Error.BadRecord;
        const low = parseHexDigit(compact[i + 1]) orelse return Error.BadRecord;
        out.data[out.len] = (high << 4) | low;
        out.len += 1;
    }
    return out;
}

/// Decode RFC 4648 base32hex (0-9A-V, case-insensitive) as used for the
/// NSEC3 next-hashed-owner field (RFC 5155). Presentation has no whitespace;
/// optional trailing `=` padding is accepted.
fn decodeBase32Hex(text: []const u8, out: []u8) Error!usize {
    if (text.len == 0 or text.len % 8 == 1) return Error.BadRecord;
    var padded: usize = 0;
    while (padded < text.len and text[text.len - 1 - padded] == '=') padded += 1;
    if (padded > 6) return Error.BadRecord;
    const data_len = text.len - padded;
    if (data_len % 8 == 1 or data_len % 8 == 3 or data_len % 8 == 6) return Error.BadRecord;
    if (padded != 0 and data_len + padded != ((data_len + 7) / 8) * 8) return Error.BadRecord;
    const decoded_len = data_len * 5 / 8;
    if (decoded_len == 0 or decoded_len > out.len) return Error.BadRecord;
    var values: [8]u5 = undefined;
    var written: usize = 0;
    var index: usize = 0;
    while (index < data_len) {
        const width: usize = @min(8, data_len - index);
        for (values[0..width], 0..) |*value, offset| {
            value.* = base32HexValue(text[index + offset]) orelse return Error.BadRecord;
        }
        var quantum: u64 = 0;
        for (values[0..width]) |value| quantum = (quantum << 5) | value;
        const pad_bits: u6 = @intCast((8 - width) * 5);
        quantum <<= pad_bits;
        if (width != 8 and (quantum & (((@as(u64, 1) << pad_bits) - 1))) != 0) {
            // Non-zero trailing pad bits are a malformed encoding.
            return Error.BadRecord;
        }
        const out_bytes = width * 5 / 8;
        var byte_index: usize = 0;
        while (byte_index < out_bytes) : (byte_index += 1) {
            if (written >= out.len) return Error.BadRecord;
            out[written] = @intCast((quantum >> @intCast(32 - byte_index * 8)) & 0xff);
            written += 1;
        }
        index += width;
    }
    return written;
}

fn base32HexValue(byte: u8) ?u5 {
    return switch (byte) {
        '0'...'9' => @intCast(byte - '0'),
        'A'...'V' => @intCast(byte - 'A' + 10),
        'a'...'v' => @intCast(byte - 'a' + 10),
        else => null,
    };
}

fn decodeBase64Blob(text: []const u8, out: []u8) Error!usize {
    var compact: [4096]u8 = undefined;
    var compact_len: usize = 0;
    for (text) |byte| {
        if (std.ascii.isWhitespace(byte)) continue;
        if (compact_len >= compact.len) return Error.BadRecord;
        compact[compact_len] = byte;
        compact_len += 1;
    }
    if (compact_len == 0) return Error.BadRecord;
    const decoder = std.base64.standard.Decoder;
    const exact = decoder.calcSizeForSlice(compact[0..compact_len]) catch return Error.BadRecord;
    if (exact > out.len) return Error.BadRecord;
    decoder.decode(out[0..exact], compact[0..compact_len]) catch return Error.BadRecord;
    return exact;
}

fn parseDnskey(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const flags = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const protocol = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const key_text = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    std.mem.writeInt(u16, out.data[0..2], flags, .big);
    out.data[2] = protocol;
    out.data[3] = algorithm;
    out.len = 4;
    const key_len = try decodeBase64Blob(key_text, out.data[4..]);
    out.len += @intCast(key_len);
    return out;
}

fn parseDs(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const key_tag = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const digest_type = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const digest_text = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    var digest = try decodeHexBlob(digest_text);
    var out = dns_rdata.Unknown{};
    if (4 + digest.len > out.data.len) return Error.BadRecord;
    std.mem.writeInt(u16, out.data[0..2], key_tag, .big);
    out.data[2] = algorithm;
    out.data[3] = digest_type;
    @memcpy(out.data[4 .. 4 + digest.len], digest.bytes());
    out.len = @intCast(4 + digest.len);
    return out;
}

fn parseTypeCovered(text: []const u8) Error!u16 {
    if (parseRecordType(text)) |rrtype| return rrtype.code();
    return Error.BadRecord;
}

/// RFC 8976 section 2.3 presentation format: serial, scheme, and hash are
/// unsigned decimal integers; the digest is case-insensitive hexadecimal
/// whose whitespace the zone parser has already folded out of parenthetical
/// continuations. decodeHexBlob accepts the embedded whitespace as well.
fn parseZonemd(text: []const u8) Error!dns_rdata.Zonemd {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const serial = parseStrictDecimal(u32, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const scheme = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const hash = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const digest = try decodeHexBlob(tokens.rest());
    const bytes = digest.bytes();
    if (bytes.len < dns_rdata.min_zonemd_digest_len or bytes.len > dns_rdata.max_zonemd_digest_len) return Error.BadRecord;
    var zonemd = dns_rdata.Zonemd{
        .serial = serial,
        .scheme = scheme,
        .hash = hash,
        .digest_len = @intCast(bytes.len),
    };
    @memcpy(zonemd.digest[0..bytes.len], bytes);
    return zonemd;
}

fn parseRrsig(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const covered = try parseTypeCovered(tokens.next() orelse return Error.BadRecord);
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const labels = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const orig_ttl = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const expiration = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const inception = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const key_tag = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const signer_text = tokens.next() orelse return Error.BadRecord;
    const signer = dns_name.Name.fromText(signer_text) catch return Error.BadRecord;
    const sig_text = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    const header_len = 18 + signer.asWire().len;
    if (header_len > out.data.len) return Error.BadRecord;
    std.mem.writeInt(u16, out.data[0..2], covered, .big);
    out.data[2] = algorithm;
    out.data[3] = labels;
    std.mem.writeInt(u32, out.data[4..8], orig_ttl, .big);
    std.mem.writeInt(u32, out.data[8..12], expiration, .big);
    std.mem.writeInt(u32, out.data[12..16], inception, .big);
    std.mem.writeInt(u16, out.data[16..18], key_tag, .big);
    @memcpy(out.data[18..header_len], signer.asWire());
    out.len = @intCast(header_len);
    const sig_len = try decodeBase64Blob(sig_text, out.data[header_len..]);
    out.len += @intCast(sig_len);
    return out;
}

/// Build a windowed type bitmap (RFC 4034 section 4.1.2) from presentation
/// type mnemonics. Supports windows 0-255; at most 64 types per NSEC.
fn buildTypeBitmap(tokens: *std.mem.TokenIterator(u8, .any), out: []u8) Error!usize {
    var codes: [64]u16 = undefined;
    var count: usize = 0;
    while (tokens.next()) |token| {
        if (count >= codes.len) return Error.BadRecord;
        codes[count] = try parseTypeCovered(token);
        count += 1;
    }
    if (count == 0) return Error.BadRecord;
    std.mem.sort(u16, codes[0..count], {}, std.sort.asc(u16));
    var prev: ?u16 = null;
    for (codes[0..count]) |code| {
        if (prev != null and prev.? == code) return Error.BadRecord;
        prev = code;
    }
    var len: usize = 0;
    var index: usize = 0;
    while (index < count) {
        const window: u8 = @intCast(codes[index] / 256);
        var bits: [32]u8 = @as([32]u8, @as([32]u8, @splat(@as(u8, 0))));
        var max_byte: usize = 0;
        while (index < count and codes[index] / 256 == window) : (index += 1) {
            const bit: u16 = codes[index] % 256;
            bits[bit / 8] |= @as(u8, 0x80) >> @intCast(bit % 8);
            max_byte = @max(max_byte, bit / 8);
        }
        if (len + 2 + max_byte + 1 > out.len) return Error.BadRecord;
        out[len] = window;
        out[len + 1] = @intCast(max_byte + 1);
        @memcpy(out[len + 2 .. len + 3 + max_byte], bits[0 .. max_byte + 1]);
        len += 3 + max_byte;
    }
    return len;
}

fn parseNsec(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const next_text = tokens.next() orelse return Error.BadRecord;
    const next = dns_name.Name.fromText(next_text) catch return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    if (next.asWire().len > out.data.len) return Error.BadRecord;
    @memcpy(out.data[0..next.asWire().len], next.asWire());
    out.len = @intCast(next.asWire().len);
    const bitmap_len = try buildTypeBitmap(&tokens, out.data[out.len..]);
    out.len += @intCast(bitmap_len);
    return out;
}

fn parseHexOrDash(text: []const u8, out: []u8) Error!usize {
    if (std.mem.eql(u8, text, "-")) return 0;
    if (text.len % 2 != 0) return Error.BadRecord;
    if (text.len / 2 > out.len) return Error.BadRecord;
    var i: usize = 0;
    while (i < text.len) : (i += 2) {
        const high = parseHexDigit(text[i]) orelse return Error.BadRecord;
        const low = parseHexDigit(text[i + 1]) orelse return Error.BadRecord;
        out[i / 2] = (high << 4) | low;
    }
    return text.len / 2;
}

fn parseNsec3Param(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const flags = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const iterations = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const salt_text = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    out.data[0] = algorithm;
    out.data[1] = flags;
    std.mem.writeInt(u16, out.data[2..4], iterations, .big);
    const salt_len = try parseHexOrDash(salt_text, out.data[5..]);
    if (salt_len > 255) return Error.BadRecord;
    out.data[4] = @intCast(salt_len);
    out.len = @intCast(5 + salt_len);
    return out;
}

fn parseNsec3(text: []const u8) Error!dns_rdata.Unknown {
    if (parseDnssecGeneric(text)) |generic| return generic;
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const flags = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const iterations = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const salt_text = tokens.next() orelse return Error.BadRecord;
    const next_text = tokens.next() orelse return Error.BadRecord;
    var out = dns_rdata.Unknown{};
    out.data[0] = algorithm;
    out.data[1] = flags;
    std.mem.writeInt(u16, out.data[2..4], iterations, .big);
    const salt_len = try parseHexOrDash(salt_text, out.data[5..]);
    if (salt_len > 255) return Error.BadRecord;
    out.data[4] = @intCast(salt_len);
    var cursor: usize = 5 + salt_len;
    var next_hash: [64]u8 = undefined;
    const next_len = try decodeBase32Hex(next_text, &next_hash);
    if (next_len == 0 or next_len > 255 or cursor + 1 + next_len > out.data.len) return Error.BadRecord;
    out.data[cursor] = @intCast(next_len);
    cursor += 1;
    @memcpy(out.data[cursor .. cursor + next_len], next_hash[0..next_len]);
    cursor += next_len;
    const bitmap_len = try buildTypeBitmap(&tokens, out.data[cursor..]);
    cursor += bitmap_len;
    out.len = @intCast(cursor);
    return out;
}

fn parseIpv4(text: []const u8) Error![4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var out: [4]u8 = undefined;
    var index: usize = 0;
    while (parts.next()) |part| {
        if (index >= out.len) return Error.BadRecord;
        out[index] = std.fmt.parseInt(u8, part, 10) catch return Error.BadRecord;
        index += 1;
    }
    if (index != out.len) return Error.BadRecord;
    return out;
}

fn parseIpv6(text: []const u8) Error![16]u8 {
    const address = std.Io.net.Ip6Address.parse(text, 0) catch return Error.BadRecord;
    return address.bytes;
}

fn parseApl(text: []const u8) Error!dns_rdata.Unknown {
    var apl = dns_rdata.Unknown{};
    var output_len: usize = 0;
    var items = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (items.next()) |item| {
        var negated = false;
        var value = item;
        if (value[0] == '!') {
            negated = true;
            value = value[1..];
        }
        if (value.len == 0) return Error.BadRecord;

        const colon = std.mem.indexOfScalar(u8, value, ':') orelse return Error.BadRecord;
        const afi = parseStrictDecimal(u16, value[0..colon]) orelse return Error.BadRecord;
        if (afi != 1 and afi != 2) return Error.BadRecord;

        const address_and_prefix = value[colon + 1 ..];
        const slash = std.mem.indexOfScalar(u8, address_and_prefix, '/') orelse return Error.BadRecord;
        const address_text = address_and_prefix[0..slash];
        const prefix = parseStrictDecimal(u8, address_and_prefix[slash + 1 ..]) orelse return Error.BadRecord;

        var address: [16]u8 = undefined;
        const address_len: usize = switch (afi) {
            1 => blk: {
                if (prefix > 32) return Error.BadRecord;
                const parsed = try parseIpv4(address_text);
                @memcpy(address[0..4], &parsed);
                break :blk 4;
            },
            2 => blk: {
                if (prefix > 128) return Error.BadRecord;
                const parsed = try parseIpv6(address_text);
                @memcpy(&address, &parsed);
                break :blk 16;
            },
            else => unreachable,
        };
        maskAplAddress(address[0..address_len], prefix);

        var afd_len = address_len;
        while (afd_len != 0 and address[afd_len - 1] == 0) afd_len -= 1;
        if (output_len + 4 + afd_len > apl.data.len) return Error.BadRecord;

        std.mem.writeInt(u16, apl.data[output_len..][0..2], afi, .big);
        apl.data[output_len + 2] = prefix;
        const negation_bit: u8 = if (negated) 0x80 else 0;
        apl.data[output_len + 3] = @as(u8, @intCast(afd_len)) | negation_bit;
        @memcpy(apl.data[output_len + 4 ..][0..afd_len], address[0..afd_len]);
        output_len += 4 + afd_len;
    }
    apl.len = @intCast(output_len);
    return apl;
}

fn maskAplAddress(address: []u8, prefix: u8) void {
    const full_bytes = @as(usize, prefix) / 8;
    const remaining_bits = prefix % 8;
    if (remaining_bits != 0) address[full_bytes] &= @as(u8, 0xff) << @intCast(8 - remaining_bits);
    const first_zero = full_bytes + @intFromBool(remaining_bits != 0);
    if (first_zero < address.len) @memset(address[first_zero..], 0);
}

fn parseRdataName(text: []const u8) Error!dns_name.Name {
    return dns_name.Name.fromText(text) catch Error.BadRecord;
}

fn parseMx(text: []const u8) Error!dns_rdata.Mx {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const preference = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const exchange = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .preference = preference,
        .exchange = try parseRdataName(exchange),
    };
}

fn parseAfsdb(text: []const u8) Error!dns_rdata.Mx {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const subtype = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const hostname = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .preference = subtype,
        .exchange = try parseRdataName(hostname),
    };
}

fn parseRp(text: []const u8) Error!dns_rdata.Rp {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const mbox = tokens.next() orelse return Error.BadRecord;
    const txt = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .mbox = try parseRdataName(mbox),
        .txt = try parseRdataName(txt),
    };
}

fn parseTxt(text: []const u8) Error!dns_rdata.Txt {
    const value = if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') text[1 .. text.len - 1] else text;
    if (value.len > 255) return Error.BadRecord;
    var txt = dns_rdata.Txt{ .len = @intCast(value.len) };
    @memcpy(txt.data[0..value.len], value);
    return txt;
}

fn parseX25(text: []const u8) Error!dns_rdata.Txt {
    const input = std.mem.trim(u8, text, " \t\r\n");
    if (input.len == 0) return Error.BadRecord;

    const value = if (input[0] == '"') blk: {
        if (input.len < 2 or input[input.len - 1] != '"') return Error.BadRecord;
        break :blk input[1 .. input.len - 1];
    } else blk: {
        for (input) |byte| {
            if (std.ascii.isWhitespace(byte)) return Error.BadRecord;
        }
        break :blk input;
    };
    if (!dns_rdata.validX25(value)) return Error.BadRecord;

    var x25 = dns_rdata.Txt{ .len = @intCast(value.len) };
    @memcpy(x25.data[0..value.len], value);
    return x25;
}

fn parseIsdn(text: []const u8) Error!dns_rdata.Isdn {
    const input = std.mem.trim(u8, text, " \t\r\n");
    if (input.len == 0) return Error.BadRecord;

    var index: usize = 0;
    const address = try parseIsdnField(input, &index);
    if (!dns_rdata.validIsdnAddress(address)) return Error.BadRecord;

    if (index == input.len) return dns_rdata.Isdn.init(address, null) catch Error.BadRecord;
    if (!std.ascii.isWhitespace(input[index])) return Error.BadRecord;
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index == input.len) return Error.BadRecord;

    const subaddress = try parseIsdnField(input, &index);
    if (!dns_rdata.validIsdnSubaddress(subaddress)) return Error.BadRecord;
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index != input.len) return Error.BadRecord;
    return dns_rdata.Isdn.init(address, subaddress) catch Error.BadRecord;
}

fn parseIsdnField(input: []const u8, index: *usize) Error![]const u8 {
    if (index.* >= input.len) return Error.BadRecord;
    if (input[index.*] == '"') {
        index.* += 1;
        const start = index.*;
        while (index.* < input.len and input[index.*] != '"') {
            if (input[index.*] == '\\' or std.ascii.isWhitespace(input[index.*])) return Error.BadRecord;
            index.* += 1;
        }
        if (index.* == input.len) return Error.BadRecord;
        const value = input[start..index.*];
        index.* += 1;
        return value;
    }

    const start = index.*;
    while (index.* < input.len and !std.ascii.isWhitespace(input[index.*])) {
        if (input[index.*] == '"' or input[index.*] == '\\') return Error.BadRecord;
        index.* += 1;
    }
    return input[start..index.*];
}

/// RFC 1035 section 5.1 character-string: a quoted string whose escapes are
/// resolved, or a bare run of characters without interior spaces.
fn parseCharacterString(input: []const u8, index: *usize, output: []u8) Error!usize {
    if (index.* >= input.len) return Error.BadRecord;
    if (input[index.*] == '"') return parseQuotedString(input, index, output);

    const start = index.*;
    while (index.* < input.len and !std.ascii.isWhitespace(input[index.*])) index.* += 1;
    const bare = input[start..index.*];
    if (bare.len == 0 or bare.len > output.len) return Error.BadRecord;
    for (bare) |byte| {
        if (byte == '"' or byte == '\\') return Error.BadRecord;
    }
    @memcpy(output[0..bare.len], bare);
    return bare.len;
}

/// RFC 1035 section 3.3.2 HINFO zone text: a CPU character-string followed by
/// an OS character-string.
fn parseHinfo(text: []const u8) Error!dns_rdata.Hinfo {
    const input = std.mem.trim(u8, text, " \t\r\n");
    if (input.len == 0) return Error.BadRecord;

    var index: usize = 0;
    var cpu_buffer: [255]u8 = undefined;
    const cpu_len = try parseCharacterString(input, &index, &cpu_buffer);
    if (index == input.len or !std.ascii.isWhitespace(input[index])) return Error.BadRecord;
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;

    var os_buffer: [255]u8 = undefined;
    const os_len = try parseCharacterString(input, &index, &os_buffer);
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index != input.len) return Error.BadRecord;

    return dns_rdata.Hinfo.init(cpu_buffer[0..cpu_len], os_buffer[0..os_len]) catch Error.BadRecord;
}

fn parseSrv(text: []const u8) Error!dns_rdata.Srv {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const priority = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const weight = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const port = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const target = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .priority = priority,
        .weight = weight,
        .port = port,
        .target = try parseRdataName(target),
    };
}

fn parseCaa(text: []const u8) Error!dns_rdata.Caa {
    const input = std.mem.trim(u8, text, " \t\r\n");
    var index: usize = 0;

    const flags_start = index;
    while (index < input.len and !std.ascii.isWhitespace(input[index])) index += 1;
    if (index == flags_start) return Error.BadRecord;
    const flags_text = input[flags_start..index];
    const flags = parseStrictDecimal(u8, flags_text) orelse return Error.BadRecord;
    if ((flags != 0 and flags != 128) or
        (!std.mem.eql(u8, flags_text, "0") and !std.mem.eql(u8, flags_text, "128")))
    {
        return Error.BadRecord;
    }

    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    const tag_start = index;
    while (index < input.len and !std.ascii.isWhitespace(input[index])) index += 1;
    if (index == tag_start) return Error.BadRecord;
    const tag = input[tag_start..index];
    if (tag.len > std.math.maxInt(u8)) return Error.BadRecord;
    for (tag) |byte| {
        if (!((byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9'))) return Error.BadRecord;
    }

    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index == input.len) return Error.BadRecord;

    var value: [509]u8 = undefined;
    const value_len: usize = if (input[index] == '"') blk: {
        const decoded_len = try parseQuotedString(input, &index, value[0..]);
        while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
        if (index != input.len) return Error.BadRecord;
        break :blk decoded_len;
    } else blk: {
        const value_start = index;
        while (index < input.len and !std.ascii.isWhitespace(input[index])) index += 1;
        const unquoted = input[value_start..index];
        if (unquoted.len > value.len) return Error.BadRecord;
        for (unquoted) |byte| {
            if (byte == '"' or byte == '\\') return Error.BadRecord;
        }
        @memcpy(value[0..unquoted.len], unquoted);
        while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
        if (index != input.len) return Error.BadRecord;
        break :blk unquoted.len;
    };

    return dns_rdata.Caa.init(flags, tag, value[0..value_len]) catch Error.BadRecord;
}

/// Decode one RFC 1035 section 5.1 quoted string: a backslash quotes a
/// non-digit character and three decimal digits are a decimal octet.
fn parseQuotedString(input: []const u8, index: *usize, output: []u8) Error!usize {
    if (index.* >= input.len or input[index.*] != '"') return Error.BadRecord;
    index.* += 1;
    var length: usize = 0;
    while (index.* < input.len) {
        const byte = input[index.*];
        index.* += 1;
        if (byte == '"') return length;
        if (length >= output.len) return Error.BadRecord;
        if (byte != '\\') {
            output[length] = byte;
            length += 1;
            continue;
        }

        if (index.* >= input.len) return Error.BadRecord;
        const escaped = input[index.*];
        if (escaped >= '0' and escaped <= '9') {
            if (index.* + 3 > input.len) return Error.BadRecord;
            const digits = input[index.* .. index.* + 3];
            if (digits[1] < '0' or digits[1] > '9' or digits[2] < '0' or digits[2] > '9') {
                return Error.BadRecord;
            }
            output[length] = parseStrictDecimal(u8, digits) orelse return Error.BadRecord;
            length += 1;
            index.* += 3;
        } else {
            output[length] = escaped;
            length += 1;
            index.* += 1;
        }
    }
    return Error.BadRecord;
}

fn parseHexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'A'...'F' => byte - 'A' + 10,
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

fn parseStrictDecimal(comptime T: type, text: []const u8) ?T {
    if (text.len == 0) return null;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(T, text, 10) catch null;
}

fn parseSshfp(text: []const u8) Error!dns_rdata.Sshfp {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const algorithm = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const fingerprint_type = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const fingerprint_text = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;

    if (fingerprint_text.len % 2 != 0) return Error.BadRecord;
    const fingerprint_len = fingerprint_text.len / 2;
    if (!dns_rdata.validSshfp(algorithm, fingerprint_type, fingerprint_len)) return Error.BadRecord;

    var sshfp = dns_rdata.Sshfp{
        .algorithm = algorithm,
        .fingerprint_type = fingerprint_type,
        .fingerprint_len = @intCast(fingerprint_len),
    };
    for (sshfp.fingerprint[0..fingerprint_len], 0..) |*byte, index| {
        const high = parseHexDigit(fingerprint_text[index * 2]) orelse return Error.BadRecord;
        const low = parseHexDigit(fingerprint_text[index * 2 + 1]) orelse return Error.BadRecord;
        byte.* = (high << 4) | low;
    }
    return sshfp;
}

fn parseTlsa(text: []const u8) Error!dns_rdata.Tlsa {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const usage = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const selector = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const matching_type = parseStrictDecimal(u8, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;

    var tlsa = dns_rdata.Tlsa{
        .usage = usage,
        .selector = selector,
        .matching_type = matching_type,
    };
    var output_index: usize = 0;
    var pending_nibble: ?u8 = null;
    while (tokens.next()) |chunk| {
        for (chunk) |byte| {
            const nibble = parseHexDigit(byte) orelse return Error.BadRecord;
            if (pending_nibble) |high| {
                if (output_index >= tlsa.association.len) return Error.BadRecord;
                tlsa.association[output_index] = (high << 4) | nibble;
                output_index += 1;
                pending_nibble = null;
            } else {
                pending_nibble = nibble;
            }
        }
    }
    if (pending_nibble != null) return Error.BadRecord;
    if (!dns_rdata.validTlsa(usage, selector, matching_type, output_index)) return Error.BadRecord;
    tlsa.association_len = @intCast(output_index);
    return tlsa;
}

fn parseUri(text: []const u8) Error!dns_rdata.Uri {
    var tokens = std.mem.tokenizeAny(u8, text, &std.ascii.whitespace);
    const priority = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const weight = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const input = tokens.rest();

    var index: usize = 0;
    if (index >= input.len or input[index] != '"') return Error.BadRecord;
    index += 1;

    var uri = dns_rdata.Uri{
        .priority = priority,
        .weight = weight,
    };
    var closed_quote = false;
    while (index < input.len) {
        if (input[index] == '"') {
            index += 1;
            closed_quote = true;
            break;
        }
        if (uri.target_len >= uri.target.len) return Error.BadRecord;
        if (input[index] != '\\') {
            uri.target[uri.target_len] = input[index];
            uri.target_len += 1;
            index += 1;
            continue;
        }

        index += 1;
        if (index >= input.len) return Error.BadRecord;
        if (input[index] >= '0' and input[index] <= '9') {
            if (index + 3 > input.len or
                input[index + 1] < '0' or input[index + 1] > '9' or
                input[index + 2] < '0' or input[index + 2] > '9')
            {
                return Error.BadRecord;
            }
            uri.target[uri.target_len] = parseStrictDecimal(u8, input[index .. index + 3]) orelse return Error.BadRecord;
            uri.target_len += 1;
            index += 3;
        } else {
            uri.target[uri.target_len] = input[index];
            uri.target_len += 1;
            index += 1;
        }
    }
    if (!closed_quote or uri.target_len == 0) return Error.BadRecord;
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index != input.len) return Error.BadRecord;
    return uri;
}

/// Parse RFC 9460 SVCB/HTTPS presentation text:
/// `priority target [key=value ...]`, with a bare `no-default-alpn` for the
/// zero-length flag. Keys must appear in increasing numeric order; generic
/// keys use `keyNNNN=<hex>`, and `ech` uses standard base64.
fn parseSvcb(text: []const u8) Error!dns_rdata.Svcb {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const priority = parseStrictDecimal(u16, tokens.next() orelse return Error.BadRecord) orelse return Error.BadRecord;
    const target = try parseRdataName(tokens.next() orelse return Error.BadRecord);

    var params: [dns_rdata.max_svcb_params_len]u8 = undefined;
    var params_len: usize = 0;
    var prev_key: ?u16 = null;
    var seen: [128]u16 = undefined;
    var seen_count: usize = 0;
    var mandatory: [128]u16 = undefined;
    var mandatory_count: ?usize = null;

    while (tokens.next()) |token| {
        const eq = std.mem.indexOfScalar(u8, token, '=');
        const key_text = if (eq) |index| token[0..index] else token;
        const value_text = if (eq) |index| token[index + 1 ..] else "";
        const key = svcbKeyFromName(key_text) orelse return Error.BadRecord;
        if (prev_key != null and key <= prev_key.?) return Error.BadRecord;
        prev_key = key;
        if (seen_count >= seen.len) return Error.BadRecord;
        seen[seen_count] = key;
        seen_count += 1;

        var value: [dns_rdata.max_svcb_params_len]u8 = undefined;
        const value_len = try encodeSvcbParamValue(key, value_text, &value);
        if (key == dns_rdata.SVCB_MANDATORY_KEY) {
            if (value_len == 0 or value_len % 2 != 0) return Error.BadRecord;
            if (value_len / 2 > mandatory.len) return Error.BadRecord;
            mandatory_count = value_len / 2;
            var index: usize = 0;
            while (index < value_len) : (index += 2) {
                mandatory[index / 2] = std.mem.readInt(u16, value[index..][0..2], .big);
            }
        }
        if (params_len + 4 + value_len > params.len) return Error.BadRecord;
        std.mem.writeInt(u16, params[params_len..][0..2], key, .big);
        std.mem.writeInt(u16, params[params_len + 2 ..][0..2], @intCast(value_len), .big);
        @memcpy(params[params_len + 4 ..][0..value_len], value[0..value_len]);
        params_len += 4 + value_len;
    }

    if (mandatory_count) |count| {
        for (mandatory[0..count]) |required| {
            if (required == dns_rdata.SVCB_MANDATORY_KEY) return Error.BadRecord;
            var covered = false;
            for (seen[0..seen_count]) |present| {
                if (present == required) {
                    covered = true;
                    break;
                }
            }
            if (!covered) return Error.BadRecord;
        }
    }

    return dns_rdata.Svcb.init(priority, target, params[0..params_len]) catch Error.BadRecord;
}

fn svcbKeyFromName(text: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(text, "mandatory")) return dns_rdata.SVCB_MANDATORY_KEY;
    if (std.ascii.eqlIgnoreCase(text, "alpn")) return dns_rdata.SVCB_ALPN_KEY;
    if (std.ascii.eqlIgnoreCase(text, "no-default-alpn")) return dns_rdata.SVCB_NO_DEFAULT_ALPN_KEY;
    if (std.ascii.eqlIgnoreCase(text, "port")) return dns_rdata.SVCB_PORT_KEY;
    if (std.ascii.eqlIgnoreCase(text, "ipv4hint")) return dns_rdata.SVCB_IPV4HINT_KEY;
    if (std.ascii.eqlIgnoreCase(text, "ech")) return dns_rdata.SVCB_ECH_KEY;
    if (std.ascii.eqlIgnoreCase(text, "ipv6hint")) return dns_rdata.SVCB_IPV6HINT_KEY;
    if (std.ascii.eqlIgnoreCase(text, "dohpath")) return dns_rdata.SVCB_DOHPATH_KEY;
    if (text.len > 3 and std.ascii.eqlIgnoreCase(text[0..3], "key")) {
        return parseStrictDecimal(u16, text[3..]);
    }
    return null;
}

fn encodeSvcbParamValue(key: u16, value_text: []const u8, out: []u8) Error!usize {
    switch (key) {
        dns_rdata.SVCB_MANDATORY_KEY => {
            if (value_text.len == 0) return Error.BadRecord;
            var length: usize = 0;
            var items = std.mem.splitScalar(u8, value_text, ',');
            while (items.next()) |item| {
                const entry = svcbKeyFromName(item) orelse return Error.BadRecord;
                if (entry == dns_rdata.SVCB_MANDATORY_KEY) return Error.BadRecord;
                if (length + 2 > out.len) return Error.BadRecord;
                std.mem.writeInt(u16, out[length..][0..2], entry, .big);
                length += 2;
            }
            return length;
        },
        dns_rdata.SVCB_ALPN_KEY => {
            var decoded: [dns_rdata.max_svcb_params_len]u8 = undefined;
            const decoded_len = try decodeSvcbString(value_text, &decoded);
            if (decoded_len == 0) return Error.BadRecord;
            var length: usize = 0;
            var items = std.mem.splitScalar(u8, decoded[0..decoded_len], ',');
            while (items.next()) |item| {
                if (item.len == 0 or item.len > 255 or length + 1 + item.len > out.len) return Error.BadRecord;
                out[length] = @intCast(item.len);
                @memcpy(out[length + 1 ..][0..item.len], item);
                length += 1 + item.len;
            }
            return length;
        },
        dns_rdata.SVCB_NO_DEFAULT_ALPN_KEY => {
            if (value_text.len != 0) return Error.BadRecord;
            return 0;
        },
        dns_rdata.SVCB_PORT_KEY => {
            const port = parseStrictDecimal(u16, value_text) orelse return Error.BadRecord;
            if (out.len < 2) return Error.BadRecord;
            std.mem.writeInt(u16, out[0..2], port, .big);
            return 2;
        },
        dns_rdata.SVCB_IPV4HINT_KEY => {
            if (value_text.len == 0) return Error.BadRecord;
            var length: usize = 0;
            var items = std.mem.splitScalar(u8, value_text, ',');
            while (items.next()) |item| {
                if (length + 4 > out.len) return Error.BadRecord;
                @memcpy(out[length..][0..4], &try parseIpv4(item));
                length += 4;
            }
            return length;
        },
        dns_rdata.SVCB_ECH_KEY => {
            const raw = stripSvcbQuotes(value_text) orelse return Error.BadRecord;
            if (raw.len == 0) return Error.BadRecord;
            const decoder = std.base64.standard.Decoder;
            const exact = decoder.calcSizeForSlice(raw) catch return Error.BadRecord;
            if (exact == 0 or exact > out.len) return Error.BadRecord;
            decoder.decode(out[0..exact], raw) catch return Error.BadRecord;
            return exact;
        },
        dns_rdata.SVCB_IPV6HINT_KEY => {
            if (value_text.len == 0) return Error.BadRecord;
            var length: usize = 0;
            var items = std.mem.splitScalar(u8, value_text, ',');
            while (items.next()) |item| {
                if (length + 16 > out.len) return Error.BadRecord;
                @memcpy(out[length..][0..16], &try parseIpv6(item));
                length += 16;
            }
            return length;
        },
        dns_rdata.SVCB_DOHPATH_KEY => {
            const decoded_len = try decodeSvcbString(value_text, out);
            if (decoded_len == 0) return Error.BadRecord;
            return decoded_len;
        },
        else => {
            if (value_text.len % 2 != 0) return Error.BadRecord;
            if (value_text.len / 2 > out.len) return Error.BadRecord;
            var index: usize = 0;
            while (index < value_text.len) : (index += 2) {
                const high = parseHexDigit(value_text[index]) orelse return Error.BadRecord;
                const low = parseHexDigit(value_text[index + 1]) orelse return Error.BadRecord;
                out[index / 2] = (high << 4) | low;
            }
            return value_text.len / 2;
        },
    }
}

/// Decode one SVCB presentation string: surrounding quotes are stripped and
/// `\DDD` decimal plus `\X` escapes resolved; unquoted values pass through
/// unless they contain a double quote.
fn decodeSvcbString(text: []const u8, out: []u8) Error!usize {
    if (text.len >= 2 and text[0] == '"') {
        if (text[text.len - 1] != '"') return Error.BadRecord;
        const inner = text[1 .. text.len - 1];
        var length: usize = 0;
        var index: usize = 0;
        while (index < inner.len) {
            if (length >= out.len) return Error.BadRecord;
            if (inner[index] != '\\') {
                out[length] = inner[index];
                length += 1;
                index += 1;
                continue;
            }
            index += 1;
            if (index >= inner.len) return Error.BadRecord;
            if (inner[index] >= '0' and inner[index] <= '9') {
                if (index + 3 > inner.len) return Error.BadRecord;
                const digits = inner[index .. index + 3];
                if (digits[1] < '0' or digits[1] > '9' or digits[2] < '0' or digits[2] > '9') return Error.BadRecord;
                out[length] = parseStrictDecimal(u8, digits) orelse return Error.BadRecord;
                length += 1;
                index += 3;
            } else {
                out[length] = inner[index];
                length += 1;
                index += 1;
            }
        }
        return length;
    }
    if (std.mem.indexOfScalar(u8, text, '"') != null) return Error.BadRecord;
    if (text.len > out.len) return Error.BadRecord;
    @memcpy(out[0..text.len], text);
    return text.len;
}

fn stripSvcbQuotes(text: []const u8) ?[]const u8 {
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') return text[1 .. text.len - 1];
    return text;
}

fn parseNaptr(text: []const u8) Error!dns_rdata.Naptr {
    const input = std.mem.trim(u8, text, " \t\r\n");
    var index: usize = 0;
    const order = try parseNaptrDecimal(input, &index);
    try parseNaptrWhitespace(input, &index);
    const preference = try parseNaptrDecimal(input, &index);
    try parseNaptrWhitespace(input, &index);

    var naptr = dns_rdata.Naptr{
        .order = order,
        .preference = preference,
        .replacement = dns_name.Name.root(),
    };
    const flags_len = try parseNaptrQuoted(input, &index, naptr.flags[0..]);
    try parseNaptrWhitespace(input, &index);
    const services_len = try parseNaptrQuoted(input, &index, naptr.services[0..]);
    try parseNaptrWhitespace(input, &index);
    const regexp_len = try parseNaptrQuoted(input, &index, naptr.regexp[0..]);
    try parseNaptrWhitespace(input, &index);
    const replacement_start = index;
    while (index < input.len and !std.ascii.isWhitespace(input[index])) index += 1;
    if (index == replacement_start) return Error.BadRecord;
    const replacement_text = input[replacement_start..index];
    if (!std.mem.endsWith(u8, replacement_text, ".")) return Error.BadRecord;
    if (std.mem.indexOfScalar(u8, replacement_text, '"') != null) return Error.BadRecord;
    naptr.replacement = dns_name.Name.fromText(replacement_text) catch return Error.BadRecord;
    while (index < input.len and std.ascii.isWhitespace(input[index])) index += 1;
    if (index != input.len) return Error.BadRecord;

    if (regexp_len != 0 and naptr.replacement.asWire().len != 1) return Error.BadRecord;
    const wire_len = 4 + (1 + flags_len) + (1 + services_len) + (1 + regexp_len) + naptr.replacement.asWire().len;
    if (wire_len > 512) return Error.BadRecord;
    naptr.flags_len = @intCast(flags_len);
    naptr.services_len = @intCast(services_len);
    naptr.regexp_len = @intCast(regexp_len);
    for (naptr.flagsText()) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return Error.BadRecord;
    }
    return naptr;
}

fn parseNaptrDecimal(text: []const u8, index: *usize) Error!u16 {
    const start = index.*;
    while (index.* < text.len and !std.ascii.isWhitespace(text[index.*])) index.* += 1;
    if (index.* == start) return Error.BadRecord;
    return parseStrictDecimal(u16, text[start..index.*]) orelse Error.BadRecord;
}

fn parseNaptrWhitespace(text: []const u8, index: *usize) Error!void {
    const start = index.*;
    while (index.* < text.len and std.ascii.isWhitespace(text[index.*])) index.* += 1;
    if (index.* == start) return Error.BadRecord;
}

fn parseNaptrQuoted(text: []const u8, index: *usize, output: []u8) Error!usize {
    if (index.* >= text.len or text[index.*] != '"') return Error.BadRecord;
    index.* += 1;
    var length: usize = 0;
    var closed = false;
    while (index.* < text.len) {
        const byte = text[index.*];
        index.* += 1;
        if (byte == '"') {
            closed = true;
            break;
        }
        if (length >= output.len) return Error.BadRecord;
        if (byte != '\\') {
            output[length] = byte;
            length += 1;
            continue;
        }
        if (index.* >= text.len) return Error.BadRecord;
        const escaped = text[index.*];
        if (escaped >= '0' and escaped <= '9') {
            if (index.* + 3 > text.len) return Error.BadRecord;
            const digits = text[index.* .. index.* + 3];
            if (digits[1] < '0' or digits[1] > '9' or digits[2] < '0' or digits[2] > '9') return Error.BadRecord;
            output[length] = parseStrictDecimal(u8, digits) orelse return Error.BadRecord;
            length += 1;
            index.* += 3;
        } else {
            output[length] = escaped;
            length += 1;
            index.* += 1;
        }
    }
    if (!closed or !std.unicode.utf8ValidateSlice(output[0..length])) return Error.BadRecord;
    return length;
}

fn parseSoa(text: []const u8) Error!dns_rdata.Soa {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const mname = tokens.next() orelse return Error.BadRecord;
    const rname = tokens.next() orelse return Error.BadRecord;
    const serial = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const refresh = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const retry = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const expire = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const minimum = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    if (minimum > max_ttl) return Error.BadTtl;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .mname = try parseRdataName(mname),
        .rname = try parseRdataName(rname),
        .serial = serial,
        .refresh = refresh,
        .retry = retry,
        .expire = expire,
        .minimum = minimum,
    };
}

fn normalizeRData(allocator: std.mem.Allocator, rrtype: RecordType, origin: []const u8, text: []const u8) ![]const u8 {
    if (rrtype.eql(.NAPTR)) return normalizeNaptrRData(allocator, origin, text);
    const minimum_tokens: usize = if (rrtype.eql(.MX)) 2 else if (rrtype.eql(.RT)) 2 else if (rrtype.eql(.RP)) 2 else if (rrtype.eql(.AFSDB)) 2 else if (rrtype.eql(.SRV)) 4 else if (rrtype.eql(.SOA)) 2 else if (rrtype.eql(.SVCB) or rrtype.eql(.HTTPS)) 2 else if (rrtype.eql(.NS) or rrtype.eql(.CNAME) or rrtype.eql(.DNAME) or rrtype.eql(.PTR)) 1 else 0;
    if (minimum_tokens == 0) return ZoneFile.copyText(allocator, text);

    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n()");
    var index: usize = 0;
    var length: usize = 0;
    while (tokens.next()) |token| : (index += 1) {
        if (index != 0) length = std.math.add(usize, length, 1) catch return error.OutOfMemory;
        const token_length = if (isDomainField(rrtype, index)) try expandedNameLength(token, origin) else token.len;
        length = std.math.add(usize, length, token_length) catch return error.OutOfMemory;
    }
    if (index < minimum_tokens) return Error.BadRecord;

    const normalized = try allocator.alloc(u8, length);
    errdefer allocator.free(normalized);
    tokens = std.mem.tokenizeAny(u8, text, " \t\r\n()");
    index = 0;
    var offset: usize = 0;
    while (tokens.next()) |token| : (index += 1) {
        if (index != 0) {
            normalized[offset] = ' ';
            offset += 1;
        }
        if (isDomainField(rrtype, index)) {
            try writeExpandedName(normalized, &offset, token, origin);
        } else {
            @memcpy(normalized[offset .. offset + token.len], token);
            offset += token.len;
        }
    }
    return normalized;
}

fn isDomainField(rrtype: RecordType, index: usize) bool {
    if (rrtype.eql(.NS) or rrtype.eql(.CNAME) or rrtype.eql(.DNAME) or rrtype.eql(.PTR)) return index == 0;
    if (rrtype.eql(.MX)) return index == 1;
    if (rrtype.eql(.RT)) return index == 1;
    if (rrtype.eql(.AFSDB)) return index == 1;
    if (rrtype.eql(.RP)) return index == 0 or index == 1;
    if (rrtype.eql(.SVCB) or rrtype.eql(.HTTPS)) return index == 1;
    if (rrtype.eql(.SRV)) return index == 3;
    if (rrtype.eql(.SOA)) return index == 0 or index == 1;
    return false;
}

/// Expand only the NAPTR replacement name against the origin. The quoted
/// flags/services/regexp fields may contain whitespace or parentheses, so the
/// generic whitespace tokenizer cannot be used; the replacement is always the
/// final whitespace-delimited token.
fn normalizeNaptrRData(allocator: std.mem.Allocator, origin: []const u8, text: []const u8) ![]const u8 {
    var end = text.len;
    while (end > 0 and std.ascii.isWhitespace(text[end - 1])) end -= 1;
    var start = end;
    while (start > 0 and !std.ascii.isWhitespace(text[start - 1])) start -= 1;
    if (start == end) return Error.BadRecord;
    const replacement = text[start..end];
    if (std.mem.eql(u8, replacement, "@")) {
        const normalized = try allocator.alloc(u8, start + origin.len + (text.len - end));
        errdefer allocator.free(normalized);
        @memcpy(normalized[0..start], text[0..start]);
        @memcpy(normalized[start .. start + origin.len], origin);
        @memcpy(normalized[start + origin.len ..], text[end..]);
        try validateName(origin);
        return normalized;
    }
    if (std.mem.endsWith(u8, replacement, ".")) return ZoneFile.copyText(allocator, text);
    const expanded_len = std.math.add(usize, replacement.len, 1) catch return error.OutOfMemory;
    const total_len = std.math.add(usize, std.math.add(usize, start, expanded_len) catch return error.OutOfMemory, std.math.add(usize, origin.len, text.len - end) catch return error.OutOfMemory) catch return error.OutOfMemory;
    const normalized = try allocator.alloc(u8, total_len);
    errdefer allocator.free(normalized);
    @memcpy(normalized[0..start], text[0..start]);
    var offset = start;
    @memcpy(normalized[offset .. offset + replacement.len], replacement);
    offset += replacement.len;
    normalized[offset] = '.';
    offset += 1;
    @memcpy(normalized[offset .. offset + origin.len], origin);
    offset += origin.len;
    @memcpy(normalized[offset..], text[end..]);
    try validateName(normalized[offset - origin.len .. offset]);
    return normalized;
}

fn expandedNameLength(token: []const u8, origin: []const u8) !usize {
    if (std.mem.eql(u8, token, "@") or std.mem.endsWith(u8, token, ".")) return if (std.mem.eql(u8, token, "@")) origin.len else token.len;
    const with_dot = std.math.add(usize, token.len, 1) catch return error.OutOfMemory;
    return std.math.add(usize, with_dot, origin.len) catch return error.OutOfMemory;
}

fn writeExpandedName(output: []u8, offset: *usize, token: []const u8, origin: []const u8) !void {
    const start = offset.*;
    if (std.mem.eql(u8, token, "@")) {
        @memcpy(output[offset.* .. offset.* + origin.len], origin);
        offset.* += origin.len;
    } else if (std.mem.endsWith(u8, token, ".")) {
        @memcpy(output[offset.* .. offset.* + token.len], token);
        offset.* += token.len;
    } else {
        @memcpy(output[offset.* .. offset.* + token.len], token);
        offset.* += token.len;
        output[offset.*] = '.';
        offset.* += 1;
        @memcpy(output[offset.* .. offset.* + origin.len], origin);
        offset.* += origin.len;
    }
    validateName(output[start..offset.*]) catch return Error.BadName;
}

fn ensureTrailingDot(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (text.len == 0) return Error.BadDirective;
    if (std.mem.endsWith(u8, text, ".")) return text;
    const dotted = try allocator.alloc(u8, text.len + 1);
    @memcpy(dotted[0..text.len], text);
    dotted[text.len] = '.';
    return dotted;
}

test "zone parser loads opaque DNSSEC records in presentation and generic form" {
    const dnskey = try parseRData(.DNSKEY, "257 3 8 QUJDRA==");
    try std.testing.expectEqual(@as(u16, 8), dnskey.Unknown.len);
    try std.testing.expectEqual(@as(u16, 257), std.mem.readInt(u16, dnskey.Unknown.bytes()[0..2], .big));

    const ds = try parseRData(.DS, "1234 8 2 DEADBEEF");
    try std.testing.expectEqual(@as(u16, 8), ds.Unknown.len);

    const rrsig = try parseRData(.RRSIG, "A 8 2 3600 2000000000 1000000000 1234 example. QUJD");
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, rrsig.Unknown.bytes()[0..2], .big));

    const nsec = try parseRData(.NSEC, "next.example. A RRSIG NSEC");
    try std.testing.expect(nsec.Unknown.len > 14);

    const param = try parseRData(.NSEC3PARAM, "1 0 10 -");
    try std.testing.expectEqual(@as(u16, 5), param.Unknown.len);

    const generic = try parseRData(.DNSKEY, "\\# 00010003 08AABBCC");
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x00, 0x03, 0x08, 0xaa, 0xbb, 0xcc }, generic.Unknown.bytes());

    try std.testing.expectError(Error.BadRecord, parseRData(.DNSKEY, "257 3"));
    try std.testing.expectError(Error.BadRecord, parseRData(.NSEC, "next.example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.DS, "1 2 3 ODD"));
}

test "zone parser loads origin ttl and basic records" {
    const text =
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2026053001 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\ns1 IN A 192.168.1.1
        \\dns 300 IN TXT "hello dns"
        \\
    ;

    var zone = try ZoneFile.parse(text);
    defer zone.deinit();
    try std.testing.expectEqualStrings("home.arpa.", zone.originText());
    try std.testing.expectEqual(@as(u32, 3600), zone.default_ttl);
    try std.testing.expectEqual(@as(usize, 4), zone.records.len);
    try std.testing.expect(zone.records.items[0].rrtype.eql(.SOA));
    try std.testing.expectEqualStrings("dns.home.arpa.", zone.records.items[3].ownerText());
    try std.testing.expectEqual(@as(u32, 300), zone.records.items[3].ttl);
}

test "zone parser serves one RRSet at its lowest TTL (RFC 2181 section 5.2)" {
    // RFC 2181 section 5.2: the TTLs of all RRs in an RRSet must be the same,
    // and in no case may a server send an RRSet with TTLs not all equal. The
    // zone gives one A RRSet two TTLs, so the RRSet is served at the lowest of
    // them, the value a client is told to assume.
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\ns IN A 192.0.2.1
        \\www 300 IN A 192.0.2.2
        \\www 600 IN A 192.0.2.3
        \\www 900 IN AAAA 2001:db8::1
        \\
    );
    defer zone.deinit();

    var a_records: usize = 0;
    var aaaa_records: usize = 0;
    for (zone.records.items) |record| {
        if (!std.mem.eql(u8, record.ownerText(), "www.example.")) continue;
        if (record.rrtype.eql(.A)) {
            try std.testing.expectEqual(@as(u32, 300), record.ttl);
            a_records += 1;
        }
        if (record.rrtype.eql(.AAAA)) {
            try std.testing.expectEqual(@as(u32, 900), record.ttl);
            aaaa_records += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), a_records);
    try std.testing.expectEqual(@as(usize, 1), aaaa_records);
}

test "zone parser gives an RRSIG the TTL of the RRSet it covers (RFC 4034 section 2.3)" {
    // RFC 4034 section 2.3: the TTL value of an RRSIG RR must match the TTL
    // value of the RRSet it covers, and that exemption is what lets RRSIGs at
    // one owner carry different TTLs.
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\www 300 IN A 192.0.2.2
        \\www 600 IN A 192.0.2.3
        \\www 300 IN RRSIG A 8 2 300 2000000000 1000000000 1234 example. QUJD
        \\
    );
    defer zone.deinit();

    var rrsig_records: usize = 0;
    for (zone.records.items) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        try std.testing.expectEqual(@as(u32, 300), record.ttl);
        rrsig_records += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), rrsig_records);
}
test "zone parser refuses TTLs above 2^31-1, including SOA MINIMUM (RFC 2181 §8)" {
    // A per-record TTL with the sign bit set has no legal wire encoding.
    try std.testing.expectError(error.BadTtl, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\www 2147483648 IN A 192.0.2.2
        \\
    ));
    // The $TTL default is bounded the same way.
    try std.testing.expectError(error.BadTtl, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 2147483648
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\
    ));
    // SOA MINIMUM feeds signer TTLs for DNSKEY/DS/NSEC/RRSIGs, so an
    // out-of-range MINIMUM would put sign-bit TTLs on the wire.
    try std.testing.expectError(error.BadTtl, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 2147483648
        \\@ IN NS ns
        \\
    ));
    // The maximum stays legal: 2^31-1 parses.
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 2147483647
        \\@ IN NS ns
        \\www 2147483647 IN A 192.0.2.2
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(@as(u32, 2147483647), zone.records.items[2].ttl);
}

test "zone parser rejects missing SOA or missing apex NS" {
    try std.testing.expectError(error.MissingSoa, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN NS ns1.home.arpa.
        \\
    ));

    try std.testing.expectError(error.MissingApexNs, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\
    ));
}

test "zone parser rejects non-apex and duplicate apex SOA records" {
    try std.testing.expectError(error.SoaNotAtApex, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\somewhere IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    ));

    try std.testing.expectError(error.MultipleApexSoa, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\HOME.ARPA. IN SOA ns1.home.arpa. hostmaster.home.arpa. 2 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    ));
}

test "zone parser rejects CNAME co-ownership" {
    try std.testing.expectError(error.CnameConflict, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME target
        \\alias IN A 192.0.2.1
        \\
    ));
}

test "zone parser rejects changing origin after records begin" {
    try std.testing.expectError(Error.BadDirective, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\$ORIGIN other.example.
        \\www IN A 192.0.2.1
        \\
    ));
}

test "zone parser rejects trailing directive tokens" {
    try std.testing.expectError(Error.BadDirective, ZoneFile.parse(
        \\$ORIGIN home.arpa. unexpected
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    ));

    try std.testing.expectError(Error.BadDirective, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600 unexpected
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    ));
}

test "zone parser expands relative domain-bearing RDATA against origin" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN Example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\alias IN CNAME target
        \\delegated IN NS ns-child
        \\reverse IN PTR host
        \\mail IN MX 10 exchange
        \\service IN SRV 10 20 53 target
        \\suffix IN DNAME target
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("ns.Example. hostmaster.Example. 1 3600 900 1209600 3600", zone.records.items[0].rdataText());
    try std.testing.expectEqualStrings("ns.Example.", zone.records.items[1].rdataText());
    try std.testing.expectEqualStrings("target.Example.", zone.records.items[2].rdataText());
    try std.testing.expectEqualStrings("ns-child.Example.", zone.records.items[3].rdataText());
    try std.testing.expectEqualStrings("host.Example.", zone.records.items[4].rdataText());
    try std.testing.expectEqualStrings("10 exchange.Example.", zone.records.items[5].rdataText());
    try std.testing.expectEqualStrings("10 20 53 target.Example.", zone.records.items[6].rdataText());
    try std.testing.expectEqualStrings("target.Example.", zone.records.items[7].rdataText());
}

test "zone parser preserves SRV numeric fields and root target" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN Example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\service IN SRV 0 65535 65535 target
        \\root-service IN SRV 65535 0 0 .
        \\
    );
    defer zone.deinit();

    const srv = try parseRData(.SRV, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(u16, 0), srv.SRV.priority);
    try std.testing.expectEqual(@as(u16, 65535), srv.SRV.weight);
    try std.testing.expectEqual(@as(u16, 65535), srv.SRV.port);
    try std.testing.expectEqualSlices(u8, &.{
        0x06, 't',  'a', 'r', 'g', 'e', 't',
        0x07, 'e',  'x', 'a', 'm', 'p', 'l',
        'e',  0x00,
    }, srv.SRV.target.asWire());

    const root = try parseRData(.SRV, zone.records.items[3].rdataText());
    try std.testing.expectEqual(@as(u16, 65535), root.SRV.priority);
    try std.testing.expectEqualSlices(u8, &.{0}, root.SRV.target.asWire());
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "65536 0 1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "+1 0 1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "0 +1 1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "0 1 +1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "1_0 0 1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "0 1_0 1 target.Example."));
    try std.testing.expectError(Error.BadRecord, parseRData(.SRV, "0 1 1_0 target.Example."));
}

test "zone parser rejects incomplete SOA RDATA at load time" {
    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster
        \\@ IN NS ns
        \\
    ));
}

test "zone parser rejects invalid address RDATA at load time" {
    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\bad-v4 IN A 999.0.2.1
        \\
    ));

    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\bad-v6 IN AAAA 2001:db8::g
        \\
    ));
}

test "zone parser rejects malformed domain-bearing RDATA at load time" {
    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\delegation IN NS ns extra
        \\
    ));
}

test "zone RDATA parser rejects malformed text for every supported type" {
    const cases = [_]struct { rrtype: RecordType, text: []const u8 }{
        .{ .rrtype = .A, .text = "999.0.2.1" },
        .{ .rrtype = .AAAA, .text = "2001:db8::g" },
        .{ .rrtype = .NS, .text = "ns.example. extra" },
        .{ .rrtype = .SOA, .text = "ns.example. hostmaster.example. 1 2 3 4 5 extra" },
        .{ .rrtype = .CNAME, .text = "target.example. extra" },
        .{ .rrtype = .DNAME, .text = "target.example. extra" },
        .{ .rrtype = .PTR, .text = "target.example. extra" },
        .{ .rrtype = .MX, .text = "10 mail.example. extra" },
        .{ .rrtype = .SRV, .text = "1 2 3 target.example. extra" },
        .{ .rrtype = .CAA, .text = "256 issue value" },
    };
    for (cases) |case| try std.testing.expectError(Error.BadRecord, parseRData(case.rrtype, case.text));

    const overlong_txt = @as([256]u8, @splat(@as(u8, 'x')));
    try std.testing.expectError(Error.BadRecord, parseRData(.TXT, &overlong_txt));
}

test "CAA zone text parses canonical tags and raw quoted values" {
    const empty = try parseRData(.CAA, "0 issue \"\"");
    try std.testing.expectEqual(@as(u8, 0), empty.CAA.flags);
    try std.testing.expectEqualStrings("issue", empty.CAA.tagText());
    try std.testing.expectEqual(@as(usize, 0), empty.CAA.valueText().len);

    const quoted = try parseRData(.CAA, "128 issue \"a\\ b\\000\\128\\255\"");
    try std.testing.expectEqual(@as(u8, 128), quoted.CAA.flags);
    try std.testing.expectEqualSlices(u8, &.{ 'a', ' ', 'b', 0, 128, 255 }, quoted.CAA.valueText());

    const raw = try parseRData(.CAA, "0 iodef \"space \\\"quote\\\" \\\\slash\"");
    try std.testing.expectEqualSlices(u8, "space \"quote\" \\slash", raw.CAA.valueText());

    const unquoted = try parseRData(.CAA, "0 issue letsencrypt.org");
    try std.testing.expectEqualStrings("letsencrypt.org", unquoted.CAA.valueText());
}

test "CAA zone text accepts the 512-octet RDATA boundary" {
    var input: [4 + 509]u8 = undefined;
    @memcpy(input[0..4], "0 a ");
    @memset(input[4..], 'x');

    const caa = try parseRData(.CAA, &input);
    try std.testing.expectEqual(@as(usize, 509), caa.CAA.valueText().len);
}

test "CAA zone text loads through ZoneFile" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\@ IN CAA 0 issue "letsencrypt.org"
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.CAA, zone.records.items[2].rrtype);
    const caa = try parseRData(.CAA, zone.records.items[2].rdataText());
    try std.testing.expectEqualStrings("issue", caa.CAA.tagText());
    try std.testing.expectEqualStrings("letsencrypt.org", caa.CAA.valueText());
}

test "CAA zone text rejects noncanonical fields and malformed values" {
    const invalid = [_][]const u8{
        "1 issue value",
        "127 issue value",
        "129 issue value",
        "256 issue value",
        "00 issue value",
        "0128 issue value",
        "+0 issue value",
        "0 Issue value",
        "0 is-sue value",
        "0 \"\" value",
        "0 issue",
        "0issue value",
        "0 issuevalue",
        "0 issue value extra",
        "0 issue \"unterminated",
        "0 issue \"unterminated\\",
        "0 issue \"value\" extra",
        "0 issue \"bad\\12\"",
        "0 issue \"bad\\1x2\"",
        "0 issue \"bad\\256\"",
        "0 issue \"bad\\2a3\"",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.CAA, text));

    var overlong: [4 + 510]u8 = undefined;
    @memcpy(overlong[0..4], "0 a ");
    @memset(overlong[4..], 'x');
    try std.testing.expectError(Error.BadRecord, parseRData(.CAA, &overlong));
}

test "X25 zone text accepts one bare or quoted decimal address" {
    const bare = try parseRData(.X25, "1234");
    try std.testing.expectEqualStrings("1234", bare.X25.text());

    const quoted = try parseRData(.X25, "\"1234\"");
    try std.testing.expectEqualStrings("1234", quoted.X25.text());

    var maximum: [255]u8 = undefined;
    @memset(&maximum, '9');
    const maximum_value = try parseRData(.X25, &maximum);
    try std.testing.expectEqual(@as(usize, 255), maximum_value.X25.text().len);
}

test "X25 zone text rejects malformed quoting fields escapes and addresses" {
    const invalid = [_][]const u8{
        "",
        "123",
        "1234 5678",
        "1234\t5678",
        "\"1234",
        "1234\"",
        "\"1234\" extra",
        "extra \"1234\"",
        "\"12 34\"",
        "\"1234 5678\"",
        "\"1234\\\"",
        "\"12\\34\"",
        "\"\\049234\"",
        "12a4",
        "\"12a4\"",
        "+1234",
        "-1234",
        "1234.",
        "\"\"",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.X25, text));

    var overlong: [256]u8 = undefined;
    @memset(&overlong, '9');
    try std.testing.expectError(Error.BadRecord, parseRData(.X25, &overlong));
}

test "zone parser recognizes and validates X25 records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\bare IN X25 1234
        \\quoted IN X25 "5678"
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.X25, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("1234", zone.records.items[2].rdataText());
    const bare = try parseRData(.X25, zone.records.items[2].rdataText());
    try std.testing.expectEqualStrings("1234", bare.X25.text());

    try std.testing.expectEqual(RecordType.X25, zone.records.items[3].rrtype);
    try std.testing.expectEqualStrings("\"5678\"", zone.records.items[3].rdataText());
    const quoted = try parseRData(.X25, zone.records.items[3].rdataText());
    try std.testing.expectEqualStrings("5678", quoted.X25.text());
}

test "ISDN zone text parses bare and quoted address fields" {
    const bare_address = try parseRData(.ISDN, "1234");
    try std.testing.expectEqualStrings("1234", bare_address.ISDN.addressText());
    try std.testing.expect(!bare_address.ISDN.has_subaddress);

    const quoted_address = try parseRData(.ISDN, "\"5678\"");
    try std.testing.expectEqualStrings("5678", quoted_address.ISDN.addressText());
    try std.testing.expect(!quoted_address.ISDN.has_subaddress);

    const bare_address_quoted_subaddress = try parseRData(.ISDN, "1234 \"aBf\"");
    try std.testing.expectEqualStrings("1234", bare_address_quoted_subaddress.ISDN.addressText());
    try std.testing.expectEqualStrings("aBf", bare_address_quoted_subaddress.ISDN.subaddressText());

    const bare_address_bare_subaddress = try parseRData(.ISDN, "1234 09af");
    try std.testing.expectEqualStrings("1234", bare_address_bare_subaddress.ISDN.addressText());
    try std.testing.expectEqualStrings("09af", bare_address_bare_subaddress.ISDN.subaddressText());

    const quoted_address_bare_subaddress = try parseRData(.ISDN, "\"5678\" 09af");
    try std.testing.expectEqualStrings("5678", quoted_address_bare_subaddress.ISDN.addressText());
    try std.testing.expectEqualStrings("09af", quoted_address_bare_subaddress.ISDN.subaddressText());

    const quoted_address_quoted_subaddress = try parseRData(.ISDN, "\"5678\" \"aBf\"");
    try std.testing.expectEqualStrings("5678", quoted_address_quoted_subaddress.ISDN.addressText());
    try std.testing.expectEqualStrings("aBf", quoted_address_quoted_subaddress.ISDN.subaddressText());
}

test "ISDN zone text accepts minimum and maximum strings" {
    const minimum = try parseRData(.ISDN, "1 a");
    try std.testing.expectEqualStrings("1", minimum.ISDN.addressText());
    try std.testing.expectEqualStrings("a", minimum.ISDN.subaddressText());

    var address: [255]u8 = undefined;
    @memset(&address, '9');
    var subaddress: [255]u8 = undefined;
    @memset(&subaddress, 'f');
    var input: [255 + 1 + 255]u8 = undefined;
    @memcpy(input[0..address.len], &address);
    input[address.len] = ' ';
    @memcpy(input[address.len + 1 ..], &subaddress);

    const maximum = try parseRData(.ISDN, &input);
    try std.testing.expectEqualSlices(u8, &address, maximum.ISDN.addressText());
    try std.testing.expectEqualSlices(u8, &subaddress, maximum.ISDN.subaddressText());
}

test "ISDN zone text rejects malformed presentation" {
    const invalid = [_][]const u8{
        "",
        "1234 5678 extra",
        "\"1234",
        "1234\"",
        "\"1234\" extra",
        "\"12 34\"",
        "1234 \"ab cd\"",
        "\"12\\34\"",
        "123a",
        "1234 g",
        "1234 \"ag\"",
        "\"\"",
        "1234 \"\"",
        "1234 \\",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.ISDN, text));

    var overlong_address: [256]u8 = undefined;
    @memset(&overlong_address, '1');
    try std.testing.expectError(Error.BadRecord, parseRData(.ISDN, &overlong_address));

    var overlong_subaddress: [256]u8 = undefined;
    @memset(&overlong_subaddress, 'f');
    var overlong_input: [1 + 1 + 256]u8 = undefined;
    overlong_input[0] = '1';
    overlong_input[1] = ' ';
    @memcpy(overlong_input[2..], &overlong_subaddress);
    try std.testing.expectError(Error.BadRecord, parseRData(.ISDN, &overlong_input));
}

test "zone parser recognizes and validates ISDN records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\phone IN ISDN 1234 "aBf"
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.ISDN, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("1234 \"aBf\"", zone.records.items[2].rdataText());
    const isdn = try parseRData(.ISDN, zone.records.items[2].rdataText());
    try std.testing.expectEqualStrings("1234", isdn.ISDN.addressText());
    try std.testing.expectEqualStrings("aBf", isdn.ISDN.subaddressText());
}

test "HINFO zone text parses quoted unquoted and escaped character strings" {
    const quoted = try parseRData(.HINFO, "\"Intel\" \"Linux\"");
    try std.testing.expectEqualStrings("Intel", quoted.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", quoted.HINFO.osText());

    const unquoted = try parseRData(.HINFO, "Intel Linux");
    try std.testing.expectEqualStrings("Intel", unquoted.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", unquoted.HINFO.osText());

    const escaped = try parseRData(.HINFO, "\"Intel\\032x\" \"Li\\010ux\"");
    try std.testing.expectEqualStrings("Intel x", escaped.HINFO.cpuText());
    try std.testing.expectEqualStrings("Li\nux", escaped.HINFO.osText());

    const escaped_quote = try parseRData(.HINFO, "\"Intel\\\"x\" \"Linux\"");
    try std.testing.expectEqualStrings("Intel\"x", escaped_quote.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", escaped_quote.HINFO.osText());

    const empty_os = try parseRData(.HINFO, "\"RFC8482\" \"\"");
    try std.testing.expectEqualStrings("RFC8482", empty_os.HINFO.cpuText());
    try std.testing.expectEqualStrings("", empty_os.HINFO.osText());
}

test "HINFO zone text rejects malformed presentation" {
    const invalid = [_][]const u8{
        "",
        "Intel",
        "Intel Linux extra",
        "\"Intel",
        "Intel\" Linux",
        "Intel\\Linux \"Linux\"",
        "\"Intel\\256\" \"Linux\"",
        "\"Intel\"Linux",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.HINFO, text));

    var overlong_cpu: [256]u8 = undefined;
    @memset(&overlong_cpu, 'x');
    try std.testing.expectError(Error.BadRecord, parseRData(.HINFO, &overlong_cpu));

    var overlong_os: [256]u8 = undefined;
    @memset(&overlong_os, 'x');
    var overlong_input: [1 + 256 + 1]u8 = undefined;
    @memcpy(overlong_input[0..1], "x");
    overlong_input[1] = ' ';
    @memcpy(overlong_input[2..], &overlong_os);
    try std.testing.expectError(Error.BadRecord, parseRData(.HINFO, &overlong_input));
}

test "zone parser recognizes and validates HINFO records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\host IN HINFO "Intel" "Linux"
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.HINFO, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("\"Intel\" \"Linux\"", zone.records.items[2].rdataText());
    const hinfo = try parseRData(.HINFO, zone.records.items[2].rdataText());
    try std.testing.expectEqualStrings("Intel", hinfo.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", hinfo.HINFO.osText());
}

test "RP zone text parses two absolute names and either root field" {
    const named = try parseRData(.RP, "mbox.example. txt.example.");
    try std.testing.expectEqualSlices(u8, &.{ 4, 'm', 'b', 'o', 'x', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, named.RP.mbox.asWire());
    try std.testing.expectEqualSlices(u8, &.{ 3, 't', 'x', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, named.RP.txt.asWire());

    const root_mbox = try parseRData(.RP, ". txt.example.");
    try std.testing.expectEqualSlices(u8, &.{0}, root_mbox.RP.mbox.asWire());
    try std.testing.expectEqualSlices(u8, named.RP.txt.asWire(), root_mbox.RP.txt.asWire());

    const root_txt = try parseRData(.RP, "mbox.example. .");
    try std.testing.expectEqualSlices(u8, named.RP.mbox.asWire(), root_txt.RP.mbox.asWire());
    try std.testing.expectEqualSlices(u8, &.{0}, root_txt.RP.txt.asWire());
}

test "RP zone text rejects missing extra relative and malformed names" {
    const invalid = [_][]const u8{
        "",
        "mbox.example.",
        "mbox.example. txt.example. extra",
        "mbox txt.example.",
        "mbox.example. txt",
        "bad..example. txt.example.",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.RP, text));
}

test "zone parser recognizes and validates RP records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\contact IN RP mbox.example. txt.example.
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.RP, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("mbox.example. txt.example.", zone.records.items[2].rdataText());
    const rp = try parseRData(.RP, zone.records.items[2].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 4, 'm', 'b', 'o', 'x', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, rp.RP.mbox.asWire());
    try std.testing.expectEqualSlices(u8, &.{ 3, 't', 'x', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, rp.RP.txt.asWire());
}

test "AFSDB zone text accepts subtype boundaries and absolute hostname" {
    const minimum = try parseRData(.AFSDB, "0 db.example.");
    try std.testing.expectEqual(@as(u16, 0), minimum.AFSDB.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'd', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, minimum.AFSDB.exchange.asWire());

    const maximum = try parseRData(.AFSDB, "65535 DB.EXAMPLE.");
    try std.testing.expectEqual(@as(u16, 65535), maximum.AFSDB.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'd', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, maximum.AFSDB.exchange.asWire());
}

test "RT zone text accepts preference boundaries and absolute intermediate host" {
    const minimum = try parseRData(.RT, "0 rt.example.");
    try std.testing.expectEqual(@as(u16, 0), minimum.RT.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'r', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, minimum.RT.exchange.asWire());

    const maximum = try parseRData(.RT, "65535 RT.EXAMPLE.");
    try std.testing.expectEqual(@as(u16, 65535), maximum.RT.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'r', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, maximum.RT.exchange.asWire());
}

test "RT zone text rejects missing extra nondecimal range relative and malformed input" {
    const invalid = [_][]const u8{
        "",
        "0",
        "rt.example.",
        "0 rt.example. extra",
        "+1 rt.example.",
        "-1 rt.example.",
        "65536 rt.example.",
        "1x rt.example.",
        "1 rt.example",
        "1 bad..example.",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.RT, text));
}

test "zone parser recognizes and validates RT records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\route IN RT 65535 rt.example.
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.RT, zone.records.items[2].rrtype);
    const rt = try parseRData(.RT, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(u16, 65535), rt.RT.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'r', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, rt.RT.exchange.asWire());
}

test "AFSDB zone text rejects malformed presentation" {
    const invalid = [_][]const u8{
        "",
        "0",
        "db.example.",
        "0 db.example. extra",
        "+1 db.example.",
        "-1 db.example.",
        "65536 db.example.",
        "1x db.example.",
        "1 db.example",
        "1 bad..example.",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.AFSDB, text));
}

test "zone parser recognizes and validates AFSDB records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\database IN AFSDB 65535 db.example.
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.AFSDB, zone.records.items[2].rrtype);
    const afsdb = try parseRData(.AFSDB, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(u16, 65535), afsdb.AFSDB.preference);
    try std.testing.expectEqualSlices(u8, &.{ 2, 'd', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, afsdb.AFSDB.exchange.asWire());
}

test "SSHFP zone text accepts mixed-case hex and exact supported lengths" {
    const sha1 = try parseRData(.SSHFP, "1 1 00112233445566778899AaBbCcDdEeFf00112233");
    try std.testing.expectEqual(@as(u8, 1), sha1.SSHFP.algorithm);
    try std.testing.expectEqual(@as(u8, 1), sha1.SSHFP.fingerprint_type);
    try std.testing.expectEqual(@as(usize, 20), sha1.SSHFP.fingerprintBytes().len);
    try std.testing.expectEqual(@as(u8, 0xaa), sha1.SSHFP.fingerprintBytes()[10]);

    const sha256 = try parseRData(.SSHFP, "6 2 00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF");
    try std.testing.expectEqual(@as(u8, 6), sha256.SSHFP.algorithm);
    try std.testing.expectEqual(@as(u8, 2), sha256.SSHFP.fingerprint_type);
    try std.testing.expectEqual(@as(usize, 32), sha256.SSHFP.fingerprintBytes().len);
}

test "SSHFP zone text rejects unsupported selectors, malformed hex, and field count errors" {
    const invalid = [_][]const u8{
        "0 1 00112233445566778899aabbccddeeff00112233",
        "5 1 00112233445566778899aabbccddeeff00112233",
        "7 1 00112233445566778899aabbccddeeff00112233",
        "1 0 00112233445566778899aabbccddeeff00112233",
        "1 3 00112233445566778899aabbccddeeff00112233",
        "1 1 00112233445566778899aabbccddeeff0011223",
        "1 1 00112233445566778899aabbccddeeff0011223g",
        "1 1 +a112233445566778899aabbccddeeff00112233",
        "1 1 -0112233445566778899aabbccddeeff00112233",
        "1 2 00112233445566778899aabbccddeeff00112233",
        "1 1 00112233445566778899aabbccddeeff00112233 extra",
        "256 1 00112233445566778899aabbccddeeff00112233",
        "1 1",
        "1",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.SSHFP, text));
}

test "SSHFP zone text rejects non-decimal selector syntax" {
    const fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    try std.testing.expectError(Error.BadRecord, parseRData(.SSHFP, "+4 2 " ++ fingerprint));
    try std.testing.expectError(Error.BadRecord, parseRData(.SSHFP, "4 +2 " ++ fingerprint));
    try std.testing.expectError(Error.BadRecord, parseRData(.SSHFP, "4_0 2 " ++ fingerprint));
}

test "zone parser recognizes and validates SSHFP records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\host IN SSHFP 4 2 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(RecordType.SSHFP, zone.records.items[2].rrtype);
}

test "TLSA zone text accepts split hex associations and exact digest lengths" {
    const sha256 = try parseRData(.TLSA, "0 0 1 000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    try std.testing.expectEqual(@as(u8, 0), sha256.TLSA.usage);
    try std.testing.expectEqual(@as(u8, 0), sha256.TLSA.selector);
    try std.testing.expectEqual(@as(u8, 1), sha256.TLSA.matching_type);
    try std.testing.expectEqual(@as(usize, 32), @as(usize, sha256.TLSA.association_len));
    for (sha256.TLSA.association[0..sha256.TLSA.association_len], 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index)), byte);
    }

    const sha512 = try parseRData(.TLSA, "1 1 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    try std.testing.expectEqual(@as(usize, 64), @as(usize, sha512.TLSA.association_len));
    try std.testing.expectEqual(@as(u8, 0x3f), sha512.TLSA.association[63]);

    var one_char_chunks: [133]u8 = undefined;
    @memcpy(one_char_chunks[0..6], "0 0 1 ");
    const hex = "0123456789abcdef";
    for (0..64) |index| {
        one_char_chunks[6 + index * 2] = hex[index % hex.len];
        if (index != 63) one_char_chunks[7 + index * 2] = ' ';
    }
    const chunked = try parseRData(.TLSA, &one_char_chunks);
    try std.testing.expectEqual(@as(usize, 32), @as(usize, chunked.TLSA.association_len));
    try std.testing.expectEqual(@as(u8, 0x01), chunked.TLSA.association[0]);
    try std.testing.expectEqual(@as(u8, 0xef), chunked.TLSA.association[31]);
}

test "TLSA zone text accepts type zero data and normalizes service owner" {
    const certificate = try parseRData(.TLSA, "3 1 0 aAbBcC");
    try std.testing.expectEqual(@as(u8, 3), certificate.TLSA.usage);
    try std.testing.expectEqual(@as(u8, 1), certificate.TLSA.selector);
    try std.testing.expectEqual(@as(u8, 0), certificate.TLSA.matching_type);
    try std.testing.expectEqual(@as(usize, 3), @as(usize, certificate.TLSA.association_len));
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, certificate.TLSA.association[0..3]);

    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\_443._tcp IN TLSA 3 1 0 aabbcc
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(RecordType.TLSA, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("_443._tcp.example.", zone.records.items[2].ownerText());
}

test "TLSA zone text rejects malformed selectors, chunks, and lengths" {
    const invalid = [_][]const u8{
        "0 0 0",
        "0 0 0 0g",
        "0 0 0 abc",
        "0 0 0 00 1g",
        "0 0 0 00 extra",
        "+0 0 0 00",
        "-0 0 0 00",
        "0_0 0 0 00",
        "256 0 0 00",
        "0 256 0 00",
        "0 0 256 00",
        "4 0 0 00",
        "0 2 0 00",
        "0 0 3 00",
        "0",
        "0 0",
        "0 0 0 \x80",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, text));

    const short_sha256 = "0 0 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e";
    const long_sha256 = "0 0 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const short_sha512 = "0 0 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a";
    const long_sha512 = "0 0 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c";
    try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, short_sha256));
    try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, long_sha256));
    try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, short_sha512));
    try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, long_sha512));

    var too_long: [1026]u8 = undefined;
    @memcpy(too_long[0..6], "0 0 0 ");
    @memset(too_long[6..], '0');
    try std.testing.expectError(Error.BadRecord, parseRData(.TLSA, &too_long));
}

test "URI zone text parses strict numeric fields and escaped target bytes" {
    const basic = try parseRData(.URI, "10 20 \"https://example.test/path\"");
    try std.testing.expectEqual(@as(u16, 10), basic.URI.priority);
    try std.testing.expectEqual(@as(u16, 20), basic.URI.weight);
    try std.testing.expectEqualStrings("https://example.test/path", basic.URI.targetBytes());

    const spaced = try parseRData(.URI, " \t1 2 \"spaced\" \r\n");
    try std.testing.expectEqualStrings("spaced", spaced.URI.targetBytes());

    const raw_target = try parseRData(.URI, " \t1\t2 \t\"target with spaces\" \r\n");
    try std.testing.expectEqualStrings("target with spaces", raw_target.URI.targetBytes());

    const maximum_fields = try parseRData(.URI, "65535 65535 \"max\"");
    try std.testing.expectEqual(@as(u16, 65535), maximum_fields.URI.priority);
    try std.testing.expectEqual(@as(u16, 65535), maximum_fields.URI.weight);

    const escaped = try parseRData(.URI, "1 2 \"quote\\\"slash\\\\tail\"");
    try std.testing.expectEqualStrings("quote\"slash\\tail", escaped.URI.targetBytes());

    const decimal_bytes = try parseRData(.URI, "1 2 \"A\\000B\\065C\\255\"");
    try std.testing.expectEqualSlices(u8, &.{ 'A', 0, 'B', 'A', 'C', 255 }, decimal_bytes.URI.targetBytes());

    const prefix = "65535 65535 \"";
    var maximum_input: [prefix.len + 508 + 1]u8 = undefined;
    @memcpy(maximum_input[0..prefix.len], prefix);
    @memset(maximum_input[prefix.len .. prefix.len + 508], 'x');
    maximum_input[maximum_input.len - 1] = '"';
    const maximum_target = try parseRData(.URI, &maximum_input);
    try std.testing.expectEqual(@as(u16, 508), maximum_target.URI.target_len);
}

test "URI zone text rejects malformed fields and targets" {
    const invalid = [_][]const u8{
        "1 2 target",
        "1 2 \"\"",
        "1 2 \"unterminated",
        "1 2 \"unterminated\\",
        "1 2 \"short\\1\"",
        "1 2 \"short\\12\"",
        "1 2 \"short\\12x\"",
        "1 2 \"bad\\256\"",
        "1 2 \"target\" extra",
        "1 2 \"target\"\"second\"",
        "+1 2 \"target\"",
        "1 +2 \"target\"",
        "1_0 2 \"target\"",
        "1 2_0 \"target\"",
        "65536 2 \"target\"",
        "1 65536 \"target\"",
        "1 2\"target\"",
        "1 2",
        "1",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.URI, text));

    const prefix = "1 2 \"";
    var overlong_target: [prefix.len + 509 + 1]u8 = undefined;
    @memcpy(overlong_target[0..prefix.len], prefix);
    @memset(overlong_target[prefix.len .. prefix.len + 509], 'x');
    overlong_target[overlong_target.len - 1] = '"';
    try std.testing.expectError(Error.BadRecord, parseRData(.URI, &overlong_target));
}

test "zone parser decodes escaped URI target bytes after stripping comments" {
    var zone = try ZoneFile.parse(
        "$ORIGIN example.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns hostmaster 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns\n" ++
            "service IN URI 1 2 \"a\\\"b\\\\c\\000\\255\" ; comment\n",
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("1 2 \"a\\\"b\\\\c\\000\\255\"", zone.records.items[2].rdataText());
    const uri = try parseRData(.URI, zone.records.items[2].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 'a', '"', 'b', 0x5c, 'c', 0, 255 }, uri.URI.targetBytes());
}

test "zone parser ignores parentheses inside escaped URI targets" {
    var zone = try ZoneFile.parse(
        "$ORIGIN example.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns hostmaster 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns\n" ++
            "service IN URI 3 4 \"a\\\"(b\\\\c\" ; comment\n",
    );
    defer zone.deinit();

    const uri = try parseRData(.URI, zone.records.items[2].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 'a', '"', '(', 'b', 0x5c, 'c' }, uri.URI.targetBytes());
}

test "zone parser recognizes and validates URI records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\service IN URI 10 20 "https://example.test/path"
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(RecordType.URI, zone.records.items[2].rrtype);
    try std.testing.expectEqualStrings("service.example.", zone.records.items[2].ownerText());
    try std.testing.expectEqualStrings("10 20 \"https://example.test/path\"", zone.records.items[2].rdataText());
}

test "APL zone text parses empty ordered duplicate and negated items" {
    const empty = try parseRData(.APL, " \t\r\n");
    try std.testing.expectEqual(@as(usize, 0), empty.APL.bytes().len);

    const apl = try parseRData(.APL, "!1:192.0.2.7/24 2:2001:db8:1::/48 1:192.0.2.7/24");
    try std.testing.expectEqualSlices(u8, &.{
        0,    1, 24, 0x83, 192,  0,    2,
        0,    2, 48, 6,    0x20, 0x01, 0x0d,
        0xb8, 0, 1,  0,    1,    24,   3,
        192,  0, 2,
    }, apl.APL.bytes());
}

test "APL zone text masks host bits and strips trailing zero octets" {
    const apl = try parseRData(.APL, "1:192.0.2.7/16 2:2001:db8:1::1234/64 1:192.255.2.7/9");
    try std.testing.expectEqualSlices(u8, &.{
        0,    1,    16,   1, 192,
        0,    2,    64,   6, 0x20,
        0x01, 0x0d, 0xb8, 0, 1,
        0,    1,    9,    2, 0xc0,
        0x80,
    }, apl.APL.bytes());
}

test "zone parser recognizes bare APL records" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\empty IN APL
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(RecordType.APL, zone.records.items[2].rrtype);
    try std.testing.expectEqual(@as(usize, 0), zone.records.items[2].rdataText().len);
    const apl = try parseRData(.APL, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(usize, 0), apl.APL.bytes().len);
}

test "APL zone text rejects malformed fields addresses families prefixes and bounds" {
    const invalid = [_][]const u8{
        "!",
        "!!1:192.0.2.0/24",
        "1::192.0.2.0/24",
        "1:192.0.2.0",
        "1:192.0.2.0/",
        "1:192.0.2.0//24",
        "1:192.0.2.0/24/1",
        "1:192.0.2.0/24:extra",
        "3:192.0.2.0/24",
        "+1:192.0.2.0/24",
        "-1:192.0.2.0/24",
        "65536:192.0.2.0/24",
        "1:999.0.2.1/24",
        "2:2001:db8::g/32",
        "1:2001:db8::/32",
        "2:192.0.2.0/24",
        "1:192.0.2.0/+24",
        "1:192.0.2.0/-1",
        "1:192.0.2.0/33",
        "2:2001:db8::/129",
        "1:192.0.2.0/18446744073709551616",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.APL, text));

    // 513 zero-prefix IPv4 items encode 2052 wire bytes, over the 2048
    // bounded opaque-RDATA profile shared with src/dns/rdata.zig.
    var overlong: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer overlong.deinit();
    for (0..513) |_| try overlong.writer.writeAll("1:192.0.2.0/0 ");
    try std.testing.expectError(Error.BadRecord, parseRData(.APL, overlong.written()));
}

test "SVCB zone text parses service mode parameters in order" {
    const svcb = try parseRData(.SVCB, "1 foo.example. alpn=h2,h3 port=443 ipv4hint=192.0.2.1,198.51.100.1");
    try std.testing.expectEqual(@as(u16, 1), svcb.SVCB.priority);
    var target: [64]u8 = undefined;
    try std.testing.expectEqualStrings("foo.example.", try svcb.SVCB.target.toText(&target));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x00, 0x06, 0x02, 'h',  '2',  0x02, 'h',  '3',
        0x00, 0x03, 0x00, 0x02, 0x01, 0xbb, 0x00, 0x04, 0x00, 0x08,
        192,  0,    2,    1,    198,  51,   100,  1,
    }, svcb.SVCB.paramsBytes());

    const https = try parseRData(.HTTPS, "0 alias.example.");
    try std.testing.expectEqual(@as(u16, 0), https.HTTPS.priority);
    try std.testing.expectEqual(@as(usize, 0), https.HTTPS.paramsBytes().len);
}

test "SVCB zone text accepts sorted optional parameters with base64 ech" {
    const svcb = try parseRData(
        .SVCB,
        "1 svc.example. alpn=h2 no-default-alpn port=8443 ipv4hint=192.0.2.1 ech=aGk= ipv6hint=2001:db8::1 key10=00ff",
    );
    try std.testing.expectEqual(@as(u16, 1), svcb.SVCB.priority);
    var offset: usize = 0;
    var prev: u16 = 0;
    var first = true;
    var saw_ech = false;
    while (offset < svcb.SVCB.paramsBytes().len) {
        const params = svcb.SVCB.paramsBytes();
        const key = std.mem.readInt(u16, params[offset..][0..2], .big);
        const len = std.mem.readInt(u16, params[offset + 2 ..][0..2], .big);
        if (!first) try std.testing.expect(prev < key);
        first = false;
        prev = key;
        if (key == 5) {
            saw_ech = true;
            try std.testing.expectEqualSlices(u8, "hi", params[offset + 4 .. offset + 4 + len]);
        }
        if (key == 10) {
            try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xff }, params[offset + 4 .. offset + 4 + len]);
        }
        offset += 4 + len;
    }
    try std.testing.expect(saw_ech);
    try std.testing.expectEqual(@as(u16, 10), prev);
}

test "SVCB zone text rejects unsorted duplicate uncovered and alias parameters" {
    const invalid = [_][]const u8{
        "1 foo.example. port=443 alpn=h2",
        "1 foo.example. port=443 port=80",
        "1 foo.example. mandatory=alpn",
        "1 foo.example. mandatory=mandatory",
        "1 foo.example. mandatory=port alpn=h2",
        "0 alias.example. port=443",
        "1 foo.example. port=99999",
        "1 foo.example. no-default-alpn=1",
        "1 foo.example. alpn=",
        "1 foo.example. ech=!!!",
        "1 foo.example. key10=0",
        "1 foo.example. bogus=1",
        "1",
        "one foo.example.",
    };
    for (invalid) |text| {
        try std.testing.expectError(Error.BadRecord, parseRData(.SVCB, text));
        try std.testing.expectError(Error.BadRecord, parseRData(.HTTPS, text));
    }
}

test "zone parser expands relative SVCB targets against origin" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\svc IN SVCB 1 target alpn=h2
        \\alias IN HTTPS 0 target
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqualStrings("1 target.example. alpn=h2", zone.records.items[2].rdataText());
    const svcb = try parseRData(.SVCB, zone.records.items[2].rdataText());
    var target: [64]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.", try svcb.SVCB.target.toText(&target));
    const https = try parseRData(.HTTPS, zone.records.items[3].rdataText());
    try std.testing.expectEqual(@as(u16, 0), https.HTTPS.priority);
}

test "NAPTR zone text parses strict fields and absolute replacement" {
    const naptr = try parseRData(.NAPTR, "100 200 \"U\" \"SIP+D2U\" \"\" replacement.example.");
    try std.testing.expectEqual(@as(u16, 100), naptr.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 200), naptr.NAPTR.preference);
    try std.testing.expectEqualStrings("U", naptr.NAPTR.flagsText());
    try std.testing.expectEqualStrings("SIP+D2U", naptr.NAPTR.servicesText());
    try std.testing.expectEqualStrings("", naptr.NAPTR.regexpText());

    var replacement_text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("replacement.example.", try naptr.NAPTR.replacement.toText(&replacement_text));

    const root = try parseRData(.NAPTR, "65535 65535 \"\" \"\" \"\" .");
    try std.testing.expectEqual(@as(u16, 65535), root.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 65535), root.NAPTR.preference);
    try std.testing.expectEqual(@as(usize, 0), root.NAPTR.flagsText().len);
    try std.testing.expectEqual(@as(usize, 0), root.NAPTR.servicesText().len);
    try std.testing.expectEqual(@as(usize, 0), root.NAPTR.regexpText().len);
    try std.testing.expectEqualSlices(u8, &.{0}, root.NAPTR.replacement.asWire());
}

test "NAPTR zone text decodes quoted escapes and UTF-8" {
    const naptr = try parseRData(.NAPTR, "1 2 \"U\" \"a\\\"b\\\\c SIP\\195\\169\" \"\\195\\169\" .");
    try std.testing.expectEqualStrings("U", naptr.NAPTR.flagsText());
    try std.testing.expectEqualSlices(u8, &.{ 'a', '"', 'b', '\\', 'c', ' ', 'S', 'I', 'P', 0xc3, 0xa9 }, naptr.NAPTR.servicesText());
    try std.testing.expectEqualSlices(u8, &.{ 0xc3, 0xa9 }, naptr.NAPTR.regexpText());
}

test "NAPTR zone text rejects malformed presentation" {
    const invalid = [_][]const u8{
        "+1 2 \"U\" \"S\" \"\" .",
        "1 +2 \"U\" \"S\" \"\" .",
        "65536 2 \"U\" \"S\" \"\" .",
        "1 65536 \"U\" \"S\" \"\" .",
        "1 2 \"U\" \"S\" \"\"",
        "1 2 U \"S\" \"\" .",
        "1 2 \"U \"S\" \"\" .",
        "1 2 \"U\" \"S\" \"unterminated .",
        "1 2 \"U\" \"S\" \"short\\1\" .",
        "1 2 \"U\" \"S\" \"short\\12\" .",
        "1 2 \"U\" \"S\" \"bad\\256\" .",
        "1 2 \"U\" \"S\" \"bad\\12x\" .",
        "1 2 \"U!\" \"S\" \"\" .",
        "1 2 \"U\" \"S\" \"\" relative",
        "1 2 \"U\" \"S\" \"\" bad..example.",
        "1 2 \"U\" \"S\" \"regexp\" replacement.example.",
        "1 2 \"U\" \"S\" \"\" \"fourth\".",
        "1 2 \"U\" \"S\" \"\" replacement.example. trailing",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.NAPTR, text));

    var overlong: [255 + 1]u8 = undefined;
    @memset(&overlong, 'x');
    const prefix = "1 2 \"";
    const suffix = "\" \"S\" \"\" .";
    var input: [prefix.len + overlong.len + suffix.len]u8 = undefined;
    @memcpy(input[0..prefix.len], prefix);
    @memcpy(input[prefix.len .. prefix.len + overlong.len], &overlong);
    @memcpy(input[prefix.len + overlong.len ..], suffix);
    try std.testing.expectError(Error.BadRecord, parseRData(.NAPTR, &input));
}

test "NAPTR zone text rejects non-UTF8 and oversized wire data" {
    try std.testing.expectError(Error.BadRecord, parseRData(.NAPTR, "1 2 \"U\" \"bad\\255\" \"\" ."));

    var field: [255]u8 = undefined;
    @memset(&field, 'x');
    var text: [4 + (1 + 1) + (1 + field.len) + (1 + field.len) + (1 + field.len) + 256]u8 = undefined;
    var index: usize = 0;
    @memcpy(text[index .. index + 4], "1 2 ");
    index += 4;
    for (0..3) |field_index| {
        text[index] = '"';
        index += 1;
        const bytes = if (field_index == 0) "U" else &field;
        @memcpy(text[index .. index + bytes.len], bytes);
        index += bytes.len;
        text[index] = '"';
        index += 1;
        text[index] = ' ';
        index += 1;
    }
    @memset(text[index .. index + 256], 'a');
    index += 256;
    text[index] = '.';
    index += 1;
    try std.testing.expectError(Error.BadRecord, parseRData(.NAPTR, text[0..index]));
}

test "zone parser decodes escaped NAPTR text across parentheses and comments" {
    var zone = try ZoneFile.parse(
        "$ORIGIN example.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns hostmaster 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns\n" ++
            "service IN NAPTR (\n" ++
            " 100 10 \"U\" \"SIP\\\"(D2U\\\\x\" \"\" .\n" ++
            ") ; comment\n",
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.NAPTR, zone.records.items[2].rrtype);
    const naptr = try parseRData(.NAPTR, zone.records.items[2].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 'S', 'I', 'P', '"', '(', 'D', '2', 'U', '\\', 'x' }, naptr.NAPTR.servicesText());
    try std.testing.expectEqualSlices(u8, &.{0}, naptr.NAPTR.replacement.asWire());
}

test "zone parser loads bundled home.arpa example" {
    const text =
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. (
        \\    2026053001 ; serial
        \\    3600       ; refresh
        \\    900        ; retry
        \\    1209600    ; expire
        \\    3600       ; minimum
        \\)
        \\
        \\@   IN NS ns1.home.arpa.
        \\ns1 IN A  192.168.1.1
        \\dns IN A  192.168.1.1
        \\
    ;
    var zone = try ZoneFile.parse(text);
    defer zone.deinit();
    try std.testing.expectEqualStrings("home.arpa.", zone.originText());
    try std.testing.expect(zone.records.len >= 4);
}

test "parses a large zone without arbitrary limits" {
    var input: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer input.deinit();

    try input.writer.writeAll(
        "$ORIGIN home.arpa.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns1.home.arpa.\n",
    );
    try input.writer.writeAll("long IN TXT \"");
    const long_text = @as([255]u8, @splat(@as(u8, 'x')));
    try input.writer.writeAll(&long_text);
    try input.writer.writeAll("\"\n");
    var index: usize = 0;
    while (index < 1001) : (index += 1) {
        try input.writer.print("host{d} IN A 192.0.2.1\n", .{index});
    }

    var zone = try ZoneFile.parse(input.written());
    defer zone.deinit();
    try std.testing.expectEqual(@as(usize, 1004), zone.records.len);
    try std.testing.expectEqualStrings("home.arpa.", zone.originText());
    try std.testing.expectEqual(@as(usize, 255), zone.records.items[2].rdataText().len - 2);
    try std.testing.expectEqualStrings("192.0.2.1", zone.records.items[zone.records.len - 1].rdataText());
}

test "zone parser owns its exact retained backing" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.0.2.1
        \\
    );
    defer zone.deinit();
    try std.testing.expect(zone.backing.len < max_zone_allocation_bytes);
    try std.testing.expectEqual(zone.backing.len, zone.storage.end_index);
}

test "zone parser rejects malformed record parse" {
    try std.testing.expectError(Error.BadName, ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\invalid... IN A 192.0.2.1
        \\
    ));
}

test "zone parser charges retained arena reallocations against its allocation budget" {
    var input: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer input.deinit();
    try input.writer.writeAll(
        "$ORIGIN home.arpa.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns1.home.arpa.\n",
    );
    var index: usize = 0;
    while (index < 32) : (index += 1) {
        try input.writer.print("host{d} IN A 192.0.2.1\n", .{index});
    }

    try std.testing.expectError(Error.AllocationBudgetExceeded, ZoneFile.parseWithBudget(input.written(), 4096));
}

test "zone parser retains exact backing within its allocation budget" {
    const allocation_budget = 4096;
    var zone = try ZoneFile.parseWithBudget(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.0.2.1
        \\
    , allocation_budget);
    defer zone.deinit();

    try std.testing.expect(zone.storage.buffer.len < allocation_budget);
    try std.testing.expectEqual(zone.storage.buffer.len, zone.storage.end_index);
}

test "zone parser appends a missing trailing dot on $ORIGIN" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\www IN A 192.0.2.1
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("example.", zone.originText());
    try std.testing.expectEqualStrings("ns.example. hostmaster.example. 1 3600 900 1209600 3600", zone.records.items[0].rdataText());
    try std.testing.expectEqualStrings("www.example.", zone.records.items[2].ownerText());
}

test "zone parser expands relative RP mailbox and text names against origin" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\contact IN RP mbox txt
        \\rooted IN RP . .
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("mbox.example. txt.example.", zone.records.items[2].rdataText());
    const rp = try parseRData(.RP, zone.records.items[2].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 4, 'm', 'b', 'o', 'x', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, rp.RP.mbox.asWire());
    try std.testing.expectEqualStrings(". .", zone.records.items[3].rdataText());

    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\short IN RP onlyone
        \\
    ));
}

test "zone parser expands relative AFSDB and RT exchange names against origin" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\database IN AFSDB 1 db
        \\route IN RT 1 gateway
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("1 db.example.", zone.records.items[2].rdataText());
    const afsdb = try parseRData(.AFSDB, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(u16, 1), afsdb.AFSDB.preference);
    try std.testing.expectEqualStrings("1 gateway.example.", zone.records.items[3].rdataText());
    const rt = try parseRData(.RT, zone.records.items[3].rdataText());
    try std.testing.expectEqual(@as(u16, 1), rt.RT.preference);

    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\database IN AFSDB 1
        \\
    ));
    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\route IN RT 1
        \\
    ));
}

test "zone parser expands relative NAPTR replacement names against origin" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\service IN NAPTR 100 10 "u" "SIP+D2U" "" replacement
        \\rooted IN NAPTR 100 10 "u" "SIP+D2U" "" .
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqualStrings("100 10 \"u\" \"SIP+D2U\" \"\" replacement.example.", zone.records.items[2].rdataText());
    const naptr = try parseRData(.NAPTR, zone.records.items[2].rdataText());
    var replacement_text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("replacement.example.", try naptr.NAPTR.replacement.toText(&replacement_text));
    try std.testing.expectEqualStrings("100 10 \"u\" \"SIP+D2U\" \"\" .", zone.records.items[3].rdataText());

    try std.testing.expectError(Error.BadRecord, ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\empty IN NAPTR
        \\
    ));
}

test "NSEC3 zone text decodes base32hex next hashes per RFC 5155" {
    const lower = try parseRData(.NSEC3, "1 1 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG");
    const wire = lower.Unknown.bytes();
    try std.testing.expectEqual(@as(u8, 1), wire[0]);
    try std.testing.expectEqual(@as(u8, 1), wire[1]);
    try std.testing.expectEqual(@as(u16, 10), std.mem.readInt(u16, wire[2..4], .big));
    try std.testing.expectEqual(@as(u8, 4), wire[4]);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, wire[5..9]);
    try std.testing.expectEqual(@as(u8, 20), wire[9]);
    try std.testing.expectEqualSlices(u8, &.{
        0x17, 0x4e, 0xb2, 0x40, 0x9f, 0xe2, 0x8b, 0xcb, 0x48, 0x87,
        0xa1, 0x83, 0x6f, 0x95, 0x7f, 0x0a, 0x84, 0x25, 0xe2, 0x7b,
    }, wire[10..30]);
    try std.testing.expectEqual(@as(u16, 38), lower.Unknown.len);

    const upper = try parseRData(.NSEC3, "1 1 10 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG");
    try std.testing.expectEqualSlices(u8, lower.Unknown.bytes(), upper.Unknown.bytes());

    const invalid = [_][]const u8{
        "1 1 10 aabbccdd wooooooo A",
        "1 1 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bowz A",
        "1 1 10 aabbccdd QUJD+/== A",
        "1 1 10 aabbccdd ABC A",
        "1 1 10 aabbccdd \"\" A",
        "1 1 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr=",
    };
    for (invalid) |text| try std.testing.expectError(Error.BadRecord, parseRData(.NSEC3, text));
}

test "zone parser loads NSEC3 records with base32hex next hashes" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\2t7b4g4vsa5smi47k61mv5bv1a22bojr IN NSEC3 1 1 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG
        \\
    );
    defer zone.deinit();

    try std.testing.expectEqual(RecordType.NSEC3, zone.records.items[2].rrtype);
    const nsec3 = try parseRData(.NSEC3, zone.records.items[2].rdataText());
    try std.testing.expectEqual(@as(u8, 20), nsec3.Unknown.bytes()[9]);
}
