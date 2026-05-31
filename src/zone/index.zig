const std = @import("std");
const RecordType = @import("../dns/types.zig").RecordType;
const parser = @import("parser.zig");

pub const LookupKind = enum {
    answer,
    cname,
    nodata,
    nxdomain,
    not_authoritative,
};

pub const LookupResult = struct {
    kind: LookupKind,
    records: parser.RecordList = .{},
    soa: ?parser.ZoneRecord = null,
};

pub const Zone = struct {
    origin: [256]u8 = undefined,
    origin_len: usize = 0,
    records: parser.RecordList = .{},
    soa: ?parser.ZoneRecord = null,

    pub fn fromZoneFile(zone_file: parser.ZoneFile) !Zone {
        var zone = Zone{};
        try copyText(&zone.origin, &zone.origin_len, zone_file.originText());
        var index: usize = 0;
        while (index < zone_file.records.len) : (index += 1) {
            const record = zone_file.records.items[index];
            try zone.records.append(record);
            if (record.rrtype.eql(.SOA)) zone.soa = record;
        }
        return zone;
    }

    pub fn lookup(self: *const Zone, qname: []const u8, qtype: RecordType) LookupResult {
        if (!std.mem.endsWith(u8, qname, self.originText())) {
            return .{ .kind = .not_authoritative };
        }

        var result = LookupResult{ .kind = .nxdomain, .soa = self.soa };
        var owner_exists = false;
        var cname_result = LookupResult{ .kind = .cname, .soa = self.soa };

        var index: usize = 0;
        while (index < self.records.len) : (index += 1) {
            const record = self.records.items[index];
            if (!std.ascii.eqlIgnoreCase(record.ownerText(), qname)) continue;
            owner_exists = true;
            if (record.rrtype.eql(qtype)) {
                result.kind = .answer;
                result.soa = null;
                result.records.append(record) catch return .{ .kind = .nodata, .soa = self.soa };
            } else if (record.rrtype.eql(.CNAME) and !qtype.eql(.CNAME)) {
                cname_result.records.append(record) catch return .{ .kind = .nodata, .soa = self.soa };
            }
        }

        if (result.kind == .answer) return result;
        if (cname_result.records.len > 0) return cname_result;
        if (owner_exists) return .{ .kind = .nodata, .soa = self.soa };
        return result;
    }

    pub fn originText(self: *const Zone) []const u8 {
        return self.origin[0..self.origin_len];
    }
};

fn copyText(dest: *[256]u8, len: *usize, text: []const u8) !void {
    if (text.len > dest.len) return error.TextTooLong;
    @memcpy(dest[0..text.len], text);
    len.* = text.len;
}

test "zone index answers exact A lookup" {
    const zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    const zone = try Zone.fromZoneFile(zone_file);
    const result = zone.lookup("dns.home.arpa.", .A);
    try std.testing.expectEqual(LookupKind.answer, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualStrings("192.168.1.1", result.records.items[0].rdataText());
}

test "zone index returns CNAME, NODATA, and NXDOMAIN results" {
    const zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    const zone = try Zone.fromZoneFile(zone_file);

    const cname = zone.lookup("alias.home.arpa.", .A);
    try std.testing.expectEqual(LookupKind.cname, cname.kind);
    try std.testing.expectEqual(@as(usize, 1), cname.records.len);

    const nodata = zone.lookup("dns.home.arpa.", .AAAA);
    try std.testing.expectEqual(LookupKind.nodata, nodata.kind);
    try std.testing.expect(nodata.soa != null);

    const nxdomain = zone.lookup("missing.home.arpa.", .A);
    try std.testing.expectEqual(LookupKind.nxdomain, nxdomain.kind);
    try std.testing.expect(nxdomain.soa != null);
}
