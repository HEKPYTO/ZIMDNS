/// Contract: Builds authoritative lookup indexes from parsed zones.
/// Ownership: Zone owns moved ZoneFile backing and records; call Zone.deinit; lookup results own allocator storage and need deinit.
/// Errors: In-memory lookup has typed results; loading and file I/O are outside this module.
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

    pub fn deinit(self: *LookupResult, allocator: std.mem.Allocator) void {
        allocator.free(self.records.items);
        self.records = .{};
    }
};

pub const Zone = struct {
    backing: []u8,
    origin: []const u8 = &.{},
    records: parser.RecordList = .{},
    soa: ?parser.ZoneRecord = null,

    /// Moves parsed-zone ownership into an index. The moved-from ZoneFile is safe
    /// to deinit and no longer owns backing storage or records.
    pub fn fromZoneFile(zone_file: *parser.ZoneFile) !Zone {
        var zone = Zone{
            .backing = zone_file.backing,
            .origin = zone_file.origin,
            .records = zone_file.records,
        };
        zone_file.backing = &.{};
        zone_file.storage = std.heap.FixedBufferAllocator.init(zone_file.backing);
        zone_file.origin = &.{};
        zone_file.default_ttl = 0;
        zone_file.records = .{};
        for (zone.records.items[0..zone.records.len]) |record| {
            if (record.rrtype.eql(.SOA)) zone.soa = record;
        }
        return zone;
    }

    pub fn deinit(self: *Zone) void {
        std.heap.page_allocator.free(self.backing);
        self.backing = &.{};
        self.records = .{};
        self.origin = &.{};
        self.soa = null;
    }

    pub fn lookup(self: *const Zone, allocator: std.mem.Allocator, qname: []const u8, qtype: RecordType) LookupResult {
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
                result.records.append(allocator, record) catch {
                    result.deinit(allocator);
                    cname_result.deinit(allocator);
                    return .{ .kind = .nodata, .soa = self.soa };
                };
            } else if (record.rrtype.eql(.CNAME) and !qtype.eql(.CNAME)) {
                cname_result.records.append(allocator, record) catch {
                    result.deinit(allocator);
                    cname_result.deinit(allocator);
                    return .{ .kind = .nodata, .soa = self.soa };
                };
            }
        }

        if (result.kind == .answer) {
            cname_result.deinit(allocator);
            return result;
        }
        if (cname_result.records.len > 0) {
            result.deinit(allocator);
            return cname_result;
        }
        result.deinit(allocator);
        cname_result.deinit(allocator);
        if (owner_exists) return .{ .kind = .nodata, .soa = self.soa };
        return result;
    }

    pub fn originText(self: *const Zone) []const u8 {
        return self.origin;
    }
};

test "zone index answers exact A lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var result = zone.lookup(arena.allocator(), "dns.home.arpa.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualStrings("192.168.1.1", result.records.items[0].rdataText());
}

test "zone index returns CNAME, NODATA, and NXDOMAIN results" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var cname = zone.lookup(arena.allocator(), "alias.home.arpa.", .A);
    defer cname.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.cname, cname.kind);
    try std.testing.expectEqual(@as(usize, 1), cname.records.len);

    var nodata = zone.lookup(arena.allocator(), "dns.home.arpa.", .AAAA);
    defer nodata.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nodata, nodata.kind);
    try std.testing.expect(nodata.soa != null);

    var nxdomain = zone.lookup(arena.allocator(), "missing.home.arpa.", .A);
    defer nxdomain.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nxdomain, nxdomain.kind);
    try std.testing.expect(nxdomain.soa != null);
}

test "zone index moves zone file ownership before either value deinitializes" {
    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    zone_file.deinit();
    try std.testing.expectEqual(@as(usize, 0), zone_file.backing.len);
    try std.testing.expectEqual(@as(usize, 3), zone.records.len);
}
