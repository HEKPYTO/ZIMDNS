/// Contract: the RFC 9432 catalog zone's fixed shape — the schema-2 `version`
/// property and the member list under `zones` — read from zone text.
/// Ownership: `members` returns an allocation the caller frees (each label,
/// each name, and the slice itself).
/// Errors: a missing or unknown version, a version RRset that is not exactly
/// one record, a member node whose PTR RRset is not exactly one record, and
/// two member nodes naming the same zone are `BadCatalog` (RFC 9432 sections
/// 4.1, 4.2.1, and 5.1).
const std = @import("std");
const parser = @import("parser.zig");
const zone_index = @import("index.zig");
const RecordType = @import("../dns/types.zig").RecordType;

pub const Error = error{ BadCatalog, OutOfMemory };

/// One member node: the `<unique>` label and the zone it names.
pub const Member = struct {
    label: []const u8,
    name: []const u8,
};

/// The member zones `catalog_text` publishes for `apex`, in the order the
/// catalog lists them.
pub fn members(allocator: std.mem.Allocator, catalog_text: []const u8, apex: []const u8) Error![]const Member {
    var zone_file = parser.ZoneFile.parse(catalog_text) catch return Error.BadCatalog;
    defer zone_file.deinit();
    var zone = zone_index.Zone.fromZoneFile(&zone_file) catch return Error.BadCatalog;
    defer zone.deinit();

    var version_owner_buffer: [512]u8 = undefined;
    const version_owner = std.fmt.bufPrint(&version_owner_buffer, "version.{s}", .{apex}) catch return Error.BadCatalog;
    var version_records: usize = 0;
    var version_is_two = false;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.TXT)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), version_owner)) continue;
        version_records += 1;
        const parsed = parser.parseRData(.TXT, record.rdataText()) catch return Error.BadCatalog;
        const value = switch (parsed) {
            .TXT => |txt| txt.text(),
            else => return Error.BadCatalog,
        };
        if (std.mem.eql(u8, value, "2")) version_is_two = true;
    }
    if (version_records != 1 or !version_is_two) return Error.BadCatalog;

    var list: std.ArrayList(Member) = .empty;
    errdefer {
        for (list.items) |member| {
            allocator.free(member.label);
            allocator.free(member.name);
        }
        list.deinit(allocator);
    }
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.PTR)) continue;
        const label = memberLabel(record.ownerText(), apex) orelse continue;
        // RFC 9432 section 4.1: the PTR record MUST be the only record in
        // the PTR RRset with the member node's name.
        for (list.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.label, label)) return Error.BadCatalog;
        }
        const parsed = parser.parseRData(.PTR, record.rdataText()) catch return Error.BadCatalog;
        const target = switch (parsed) {
            .PTR => |name| name,
            else => return Error.BadCatalog,
        };
        var target_buffer: [512]u8 = undefined;
        const target_text = target.toText(&target_buffer) catch return Error.BadCatalog;
        // A catalog that lists itself is broken (RFC 9432 section 5.1's
        // shapes), and a consumer cannot provision its own catalog as a
        // member.
        if (std.ascii.eqlIgnoreCase(target_text, apex)) return Error.BadCatalog;
        for (list.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, target_text)) return Error.BadCatalog;
        }
        const owned_label = try allocator.dupe(u8, label);
        errdefer allocator.free(owned_label);
        const owned_name = try allocator.dupe(u8, target_text);
        try list.append(allocator, .{ .label = owned_label, .name = owned_name });
    }
    return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
}

fn memberLabel(owner: []const u8, apex: []const u8) ?[]const u8 {
    const tail = ".zones.";
    if (owner.len <= apex.len + tail.len) return null;
    const tail_offset = owner.len - (apex.len + tail.len);
    if (!std.ascii.eqlIgnoreCase(owner[tail_offset..][0..tail.len], tail)) return null;
    if (!std.ascii.eqlIgnoreCase(owner[tail_offset + tail.len ..], apex)) return null;
    const label = owner[0..tail_offset];
    if (label.len == 0 or std.mem.indexOfScalar(u8, label, '.') != null) return null;
    return label;
}

test "a catalog's members are read and a broken one is refused" {
    const good =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m2.zones IN PTR two.example.
        \\
    ;
    const parsed = try members(std.testing.allocator, good, "catalog.example.");
    defer {
        for (parsed) |member| {
            std.testing.allocator.free(member.label);
            std.testing.allocator.free(member.name);
        }
        std.testing.allocator.free(parsed);
    }
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqualStrings("m1", parsed[0].label);
    try std.testing.expectEqualStrings("one.example.", parsed[0].name);
    try std.testing.expectEqualStrings("m2", parsed[1].label);
    try std.testing.expectEqualStrings("two.example.", parsed[1].name);

    const broken_version =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "1"
        \\
    ;
    try std.testing.expectError(Error.BadCatalog, members(std.testing.allocator, broken_version, "catalog.example."));

    const duplicate_target =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m2.zones IN PTR one.example.
        \\
    ;
    try std.testing.expectError(Error.BadCatalog, members(std.testing.allocator, duplicate_target, "catalog.example."));

    // One member node with two PTR records breaks the RRset rule.
    const two_ptrs_one_node =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m1.zones IN PTR three.example.
        \\
    ;
    try std.testing.expectError(Error.BadCatalog, members(std.testing.allocator, two_ptrs_one_node, "catalog.example."));
}
