/// Contract: Parses authoritative zone text into validated zone records.
/// Ownership: ZoneFile owns its fixed backing reservation and records; call ZoneFile.deinit; input text is borrowed.
/// Errors: Zone syntax and allocation limits are typed parser errors; file I/O belongs to callers.
const std = @import("std");
const RecordType = @import("../dns/types.zig").RecordType;
const dns_name = @import("../dns/name.zig");

/// Maximum parser-owned backing payload retained by one loaded zone.
///
/// Every loaded zone owns a backing slice with this exact capacity for its lifetime.
/// This does not bound input storage, allocator metadata or page rounding, or
/// physical process RSS.
pub const max_zone_allocation_bytes: usize = 16 * 1024 * 1024;

pub const Error = error{
    MissingOrigin,
    MissingTtl,
    MissingSoa,
    MissingApexNs,
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
    /// its page-allocator backing reservation. Call deinit when it is no longer used.
    pub fn parse(text: []const u8) !ZoneFile {
        return parseWithBudget(text, max_zone_allocation_bytes);
    }

    fn parseWithBudget(text: []const u8, allocation_budget: usize) !ZoneFile {
        if (text.len > allocation_budget) return Error.AllocationBudgetExceeded;
        const backing = try std.heap.page_allocator.alloc(u8, allocation_budget);
        var zone = ZoneFile{
            .backing = backing,
            .storage = std.heap.FixedBufferAllocator.init(backing),
        };
        errdefer zone.deinit();
        parseWithAllocator(&zone, zone.storage.allocator(), text, allocation_budget) catch |err| switch (err) {
            error.OutOfMemory => return Error.AllocationBudgetExceeded,
            else => return err,
        };
        return zone;
    }

    fn parseWithAllocator(zone: *ZoneFile, storage_allocator: std.mem.Allocator, text: []const u8, allocation_budget: usize) !void {
        var saw_soa = false;
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
            try zone.parseLogicalLine(storage_allocator, logical, &saw_soa, &saw_apex_ns);
            logical_buffer.clearRetainingCapacity();
        }

        if (logical_buffer.items.len != 0) return Error.BadRecord;
        if (zone.origin.len == 0) return Error.MissingOrigin;
        if (zone.default_ttl == 0) return Error.MissingTtl;
        if (!saw_soa) return Error.MissingSoa;
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

    fn parseLogicalLine(self: *ZoneFile, allocator: std.mem.Allocator, line: []const u8, saw_soa: *bool, saw_apex_ns: *bool) !void {
        var tokens = Tokenizer.init(line);
        const first = tokens.next() orelse return;

        if (std.mem.eql(u8, first, "$ORIGIN")) {
            const origin = tokens.next() orelse return Error.BadDirective;
            const origin_text = ensureTrailingDot(origin);
            try validateName(origin_text);
            const copied_origin = try copyText(allocator, origin_text);
            self.origin = copied_origin;
            return;
        }

        if (std.mem.eql(u8, first, "$TTL")) {
            const ttl_text = tokens.next() orelse return Error.BadDirective;
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
        record.rdata = try copyText(allocator, tokens.rest());
        errdefer allocator.free(record.rdata);
        try self.records.append(allocator, record);

        if (record.rrtype.eql(.SOA)) saw_soa.* = true;
        if (record.rrtype.eql(.NS) and std.mem.eql(u8, record.ownerText(), self.originText())) saw_apex_ns.* = true;
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
    const long_text = [_]u8{'x'} ** 300;
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
    try std.testing.expect(zone.records.items[2].rdataText().len > 256);
    try std.testing.expectEqualStrings("192.0.2.1", zone.records.items[zone.records.len - 1].rdataText());
}

test "zone parser owns its fixed backing reservation" {
    var zone = try ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.0.2.1
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqual(max_zone_allocation_bytes, zone.storage.buffer.len);
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

test "zone parser retains no more than its fixed allocation budget" {
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

    try std.testing.expectEqual(allocation_budget, zone.storage.buffer.len);
    try std.testing.expect(zone.storage.end_index <= zone.storage.buffer.len);
}
