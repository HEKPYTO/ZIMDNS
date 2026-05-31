const std = @import("std");
const RecordType = @import("../dns/types.zig").RecordType;

const max_records = 256;
const max_text = 256;

pub const Error = error{
    MissingOrigin,
    MissingTtl,
    MissingSoa,
    MissingApexNs,
    TooManyRecords,
    BadDirective,
    BadRecord,
    BadTtl,
    TextTooLong,
};

pub const ZoneRecord = struct {
    owner: [max_text]u8 = undefined,
    owner_len: usize = 0,
    ttl: u32,
    rrtype: RecordType,
    rdata: [max_text]u8 = undefined,
    rdata_len: usize = 0,

    pub fn ownerText(self: *const ZoneRecord) []const u8 {
        return self.owner[0..self.owner_len];
    }

    pub fn rdataText(self: *const ZoneRecord) []const u8 {
        return self.rdata[0..self.rdata_len];
    }
};

pub const RecordList = struct {
    items: [max_records]ZoneRecord = undefined,
    len: usize = 0,

    pub fn append(self: *RecordList, record: ZoneRecord) Error!void {
        if (self.len >= max_records) return Error.TooManyRecords;
        self.items[self.len] = record;
        self.len += 1;
    }
};

pub const ZoneFile = struct {
    origin: [max_text]u8 = undefined,
    origin_len: usize = 0,
    default_ttl: u32 = 0,
    records: RecordList = .{},

    pub fn parse(text: []const u8) !ZoneFile {
        var zone = ZoneFile{};
        var saw_soa = false;
        var saw_apex_ns = false;

        var logical_buffer: [1024]u8 = undefined;
        var logical_len: usize = 0;
        var paren_depth: usize = 0;

        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const stripped = stripComment(raw_line);
            const trimmed = std.mem.trim(u8, stripped, " \t\r");
            if (trimmed.len == 0) continue;

            if (logical_len != 0) {
                if (logical_len >= logical_buffer.len) return Error.BadRecord;
                logical_buffer[logical_len] = ' ';
                logical_len += 1;
            }
            if (logical_len + trimmed.len > logical_buffer.len) return Error.BadRecord;
            @memcpy(logical_buffer[logical_len .. logical_len + trimmed.len], trimmed);
            logical_len += trimmed.len;
            paren_depth = updateParenDepth(paren_depth, trimmed);
            if (paren_depth != 0) continue;

            const logical = logical_buffer[0..logical_len];
            try zone.parseLogicalLine(logical, &saw_soa, &saw_apex_ns);
            logical_len = 0;
        }

        if (zone.origin_len == 0) return Error.MissingOrigin;
        if (zone.default_ttl == 0) return Error.MissingTtl;
        if (!saw_soa) return Error.MissingSoa;
        if (!saw_apex_ns) return Error.MissingApexNs;
        return zone;
    }

    pub fn originText(self: *const ZoneFile) []const u8 {
        return self.origin[0..self.origin_len];
    }

    fn parseLogicalLine(self: *ZoneFile, line: []const u8, saw_soa: *bool, saw_apex_ns: *bool) !void {
        var tokens = Tokenizer.init(line);
        const first = tokens.next() orelse return;

        if (std.mem.eql(u8, first, "$ORIGIN")) {
            const origin = tokens.next() orelse return Error.BadDirective;
            try copyText(&self.origin, &self.origin_len, ensureTrailingDot(origin));
            return;
        }

        if (std.mem.eql(u8, first, "$TTL")) {
            const ttl_text = tokens.next() orelse return Error.BadDirective;
            self.default_ttl = std.fmt.parseInt(u32, ttl_text, 10) catch return Error.BadTtl;
            return;
        }

        if (self.origin_len == 0) return Error.MissingOrigin;
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
        try self.expandOwner(owner_token, &record);
        try copyText(&record.rdata, &record.rdata_len, tokens.rest());
        try self.records.append(record);

        if (record.rrtype.eql(.SOA)) saw_soa.* = true;
        if (record.rrtype.eql(.NS) and std.mem.eql(u8, record.ownerText(), self.originText())) saw_apex_ns.* = true;
    }

    fn expandOwner(self: *const ZoneFile, owner: []const u8, record: *ZoneRecord) !void {
        if (std.mem.eql(u8, owner, "@")) {
            try copyText(&record.owner, &record.owner_len, self.originText());
        } else if (std.mem.endsWith(u8, owner, ".")) {
            try copyText(&record.owner, &record.owner_len, owner);
        } else {
            var buffer: [max_text]u8 = undefined;
            if (owner.len + 1 + self.origin_len > buffer.len) return Error.TextTooLong;
            @memcpy(buffer[0..owner.len], owner);
            buffer[owner.len] = '.';
            @memcpy(buffer[owner.len + 1 .. owner.len + 1 + self.origin_len], self.originText());
            try copyText(&record.owner, &record.owner_len, buffer[0 .. owner.len + 1 + self.origin_len]);
        }
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

fn copyText(dest: *[max_text]u8, len: *usize, text: []const u8) Error!void {
    if (text.len > dest.len) return Error.TextTooLong;
    @memcpy(dest[0..text.len], text);
    len.* = text.len;
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

    const zone = try ZoneFile.parse(text);
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
    const zone = try ZoneFile.parse(text);
    try std.testing.expectEqualStrings("home.arpa.", zone.originText());
    try std.testing.expect(zone.records.len >= 4);
}
