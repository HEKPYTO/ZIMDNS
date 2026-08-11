/// Contract: Parses authoritative zone text into validated zone records.
/// Ownership: ZoneFile owns its exact retained backing and records; call ZoneFile.deinit; input text is borrowed.
/// Errors: Zone syntax and allocation limits are typed parser errors; file I/O belongs to callers.
const std = @import("std");
const RecordType = @import("../dns/types.zig").RecordType;
const dns_name = @import("../dns/name.zig");
const dns_rdata = @import("../dns/rdata.zig");

/// Maximum temporary parser-owned backing used while loading one zone.
pub const max_zone_allocation_bytes: usize = 16 * 1024 * 1024;

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
            const origin_text = ensureTrailingDot(origin);
            try validateName(origin_text);
            if (self.records.len != 0 and !std.ascii.eqlIgnoreCase(self.originText(), origin_text)) return Error.BadDirective;
            const copied_origin = try copyText(allocator, origin_text);
            self.origin = copied_origin;
            return;
        }

        if (std.mem.eql(u8, first, "$TTL")) {
            const ttl_text = tokens.next() orelse return Error.BadDirective;
            if (tokens.next() != null) return Error.BadDirective;
            self.default_ttl = std.fmt.parseInt(u32, ttl_text, 10) catch return Error.BadTtl;
            return;
        }

        if (self.origin.len == 0) return Error.MissingOrigin;
        if (self.default_ttl == 0) return Error.MissingTtl;

        var ttl = self.default_ttl;
        var rrtype: ?RecordType = null;
        const owner_token = first;

        var token = tokens.next() orelse return Error.BadRecord;
        if (parseOptionalTtl(token)) |parsed_ttl| {
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
    for (line, 0..) |byte, index| {
        if (byte == '"') in_quote = !in_quote;
        if (byte == ';' and !in_quote) return line[0..index];
    }
    return line;
}

fn updateParenDepth(start_depth: usize, line: []const u8) usize {
    var depth = start_depth;
    var in_quote = false;
    for (line) |byte| {
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
    if (std.mem.eql(u8, text, "TXT")) return .TXT;
    if (std.mem.eql(u8, text, "SRV")) return .SRV;
    if (std.mem.eql(u8, text, "CAA")) return .CAA;
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
    if (rrtype.eql(.TXT)) return .{ .TXT = try parseTxt(text) };
    if (rrtype.eql(.SRV)) return .{ .SRV = try parseSrv(text) };
    if (rrtype.eql(.CAA)) return .{ .CAA = try parseCaa(text) };
    return Error.BadRecord;
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

fn parseRdataName(text: []const u8) Error!dns_name.Name {
    return dns_name.Name.fromText(text) catch Error.BadRecord;
}

fn parseMx(text: []const u8) Error!dns_rdata.Mx {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const preference = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const exchange = tokens.next() orelse return Error.BadRecord;
    if (tokens.next() != null) return Error.BadRecord;
    return .{
        .preference = preference,
        .exchange = try parseRdataName(exchange),
    };
}

fn parseTxt(text: []const u8) Error!dns_rdata.Txt {
    const value = if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') text[1 .. text.len - 1] else text;
    if (value.len > 255) return Error.BadRecord;
    var txt = dns_rdata.Txt{ .len = @intCast(value.len) };
    @memcpy(txt.data[0..value.len], value);
    return txt;
}

fn parseSrv(text: []const u8) Error!dns_rdata.Srv {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const priority = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const weight = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const port = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
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
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const flags = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadRecord, 10) catch return Error.BadRecord;
    const tag = tokens.next() orelse return Error.BadRecord;
    const value = tokens.rest();
    if (tag.len > 32 or value.len > 255) return Error.BadRecord;
    var caa = dns_rdata.Caa{
        .flags = flags,
        .tag_len = @intCast(tag.len),
        .value_len = @intCast(value.len),
    };
    @memcpy(caa.tag[0..tag.len], tag);
    @memcpy(caa.value[0..value.len], value);
    return caa;
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
    const minimum_tokens: usize = if (rrtype.eql(.MX)) 2 else if (rrtype.eql(.SRV)) 4 else if (rrtype.eql(.SOA)) 2 else if (rrtype.eql(.NS) or rrtype.eql(.CNAME) or rrtype.eql(.DNAME) or rrtype.eql(.PTR)) 1 else 0;
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
    if (rrtype.eql(.SRV)) return index == 3;
    if (rrtype.eql(.SOA)) return index == 0 or index == 1;
    return false;
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

fn ensureTrailingDot(text: []const u8) []const u8 {
    return text;
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

    const overlong_txt = [_]u8{'x'} ** 256;
    try std.testing.expectError(Error.BadRecord, parseRData(.TXT, &overlong_txt));
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
    const long_text = [_]u8{'x'} ** 255;
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
