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

/// One RFC 9432 property attached to a member node: a `key=value` text.
pub const Property = struct {
    key: []const u8,
    value: []const u8,
};

/// One member node: the `<unique>` label and the zone it names, plus the
/// properties the catalog carries for it.
pub const Member = struct {
    label: []const u8,
    name: []const u8,
    properties: []const Property = &.{},
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
            for (member.properties) |property| {
                allocator.free(property.key);
                allocator.free(property.value);
            }
            allocator.free(member.properties);
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
        // RFC 9432 section 4.3/4.4: properties are carried as TXT records on
        // the same member node whose RDATA is a `key=value` pair. Every key
        // must be non-empty and appear at most once per node.
        var properties: std.ArrayList(Property) = .empty;
        errdefer {
            for (properties.items) |property| {
                allocator.free(property.key);
                allocator.free(property.value);
            }
            properties.deinit(allocator);
        }
        for (zone.records.items[0..zone.records.len]) |property_record| {
            if (!property_record.rrtype.eql(.TXT)) continue;
            if (!std.ascii.eqlIgnoreCase(property_record.ownerText(), record.ownerText())) continue;
            const parsed_property = parser.parseRData(.TXT, property_record.rdataText()) catch return Error.BadCatalog;
            const property_text = switch (parsed_property) {
                .TXT => |txt| txt.text(),
                else => return Error.BadCatalog,
            };
            const equals = std.mem.indexOfScalar(u8, property_text, '=') orelse continue;
            // A bare value without a key is not a property and is ignored.
            if (equals == 0) return Error.BadCatalog;
            const key = property_text[0..equals];
            const value = property_text[equals + 1 ..];
            for (properties.items) |existing| {
                if (std.ascii.eqlIgnoreCase(existing.key, key)) return Error.BadCatalog;
            }
            const owned_key = try allocator.dupe(u8, key);
            errdefer allocator.free(owned_key);
            const owned_value = try allocator.dupe(u8, value);
            try properties.append(allocator, .{ .key = owned_key, .value = owned_value });
        }
        const owned_label = try allocator.dupe(u8, label);
        errdefer allocator.free(owned_label);
        const owned_name = try allocator.dupe(u8, target_text);
        errdefer allocator.free(owned_name);
        const owned_properties = try properties.toOwnedSlice(allocator);
        errdefer {
            for (owned_properties) |property| {
                allocator.free(property.key);
                allocator.free(property.value);
            }
            allocator.free(owned_properties);
        }
        try list.append(allocator, .{ .label = owned_label, .name = owned_name, .properties = owned_properties });
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

/// RFC 9432 producer helper: render property TXT lines for one member node.
/// Conservative reading: properties ride on the member node's own owner
/// (the same name that carries its PTR) as `key=value` TXT records, one
/// record per property. Returns an owned, newline-terminated slice.
pub fn synthesizePropertyLines(allocator: std.mem.Allocator, label: []const u8, apex: []const u8, properties: []const Property) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var line: [1024]u8 = undefined;
    for (properties) |property| {
        try out.appendSlice(allocator, try std.fmt.bufPrint(&line, "{s}.zones.{s} IN TXT \"{s}={s}\"\n", .{ label, apex, property.key, property.value }));
    }
    return out.toOwnedSlice(allocator);
}

test "catalog member properties are parsed and validated" {
    const good =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m1.zones IN TXT "group=alpha"
        \\m1.zones IN TXT "coo=other.catalog."
        \\m1.zones IN TXT "custom=x"
        \\
    ;
    const parsed = try members(std.testing.allocator, good, "catalog.example.");
    defer {
        for (parsed) |member| {
            std.testing.allocator.free(member.label);
            std.testing.allocator.free(member.name);
            for (member.properties) |property| {
                std.testing.allocator.free(property.key);
                std.testing.allocator.free(property.value);
            }
            std.testing.allocator.free(member.properties);
        }
        std.testing.allocator.free(parsed);
    }
    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    try std.testing.expectEqual(@as(usize, 3), parsed[0].properties.len);

    const duplicate =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m1.zones IN TXT "group=a"
        \\m1.zones IN TXT "group=b"
        \\
    ;
    try std.testing.expectError(Error.BadCatalog, members(std.testing.allocator, duplicate, "catalog.example."));

    const empty_key =
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 7 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\m1.zones IN TXT "=value"
        \\
    ;
    try std.testing.expectError(Error.BadCatalog, members(std.testing.allocator, empty_key, "catalog.example."));
}

test "catalog property lines are synthesized" {
    const properties = [_]Property{ .{ .key = "coo", .value = "other.catalog." }, .{ .key = "group", .value = "alpha" } };
    const text = try synthesizePropertyLines(std.testing.allocator, "m1", "catalog.example.", &properties);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "m1.zones.catalog.example. IN TXT \"coo=other.catalog.\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "m1.zones.catalog.example. IN TXT \"group=alpha\"") != null);
}
