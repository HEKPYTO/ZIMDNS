const std = @import("std");
const zimdns = @import("zimdns");

// RFC 1123 section 2.1: "the restriction on the first character is relaxed to
// allow either a letter or a digit.  Host software MUST support this more
// liberal syntax." and "Host software MUST handle host names of up to 63
// characters and SHOULD handle host names of up to 255 characters."

/// A query for example.com A, the source of the A record type value.
const a_query = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
    0,    0x00, 0x01, 0x00, 0x01,
};

/// A zone holding one A record under `owner`.
fn zoneWithOwner(buffer: []u8, owner: []const u8) ![]const u8 {
    const head_len = (try std.fmt.bufPrint(
        buffer[0..],
        "$ORIGIN example.\n$TTL 3600\n@ IN SOA ns hostmaster 1 3600 900 1209600 300\n@ IN NS ns\n",
        .{},
    )).len;
    const total_len = head_len + (try std.fmt.bufPrint(buffer[head_len..], "{s} IN A 192.0.2.1\n", .{owner})).len;
    return buffer[0..total_len];
}

test "RFC 1123 2.1: the query command's name argument accepts a leading digit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const qtype = (try zimdns.dns_message.Message.parseQuery(arena.allocator(), &a_query)).question.?.qtype;
    var buffer: [512]u8 = undefined;
    const packet = try zimdns.cli_query.buildQueryPacket(&buffer, 0x1234, "4example.com.", qtype, false);

    const parsed = try zimdns.dns_message.Message.parseQuery(arena.allocator(), packet);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("4example.com.", try parsed.question.?.name.toText(&text));
}

test "RFC 1123 2.1: the query command's name argument refuses an over-long label and name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const qtype = (try zimdns.dns_message.Message.parseQuery(arena.allocator(), &a_query)).question.?.qtype;
    var buffer: [512]u8 = undefined;

    // A 64-octet label is one octet over the bound.
    var label: [70]u8 = undefined;
    @memset(label[0..64], 'a');
    label[64] = '.';
    try std.testing.expectError(zimdns.cli_query.Error.BadName, zimdns.cli_query.buildQueryPacket(&buffer, 0x1234, label[0..65], qtype, false));

    // 63+63+63+62 octet labels reach 256 wire octets, one over the name bound.
    var name: [256]u8 = undefined;
    @memset(name[0..63], 'a');
    @memset(name[64..127], 'a');
    @memset(name[128..191], 'a');
    @memset(name[192..254], 'a');
    name[63] = '.';
    name[127] = '.';
    name[191] = '.';
    name[254] = '.';
    try std.testing.expectError(zimdns.cli_query.Error.BadName, zimdns.cli_query.buildQueryPacket(&buffer, 0x1234, name[0..255], qtype, false));
}

test "RFC 1123 2.1: a zone-file owner label accepts a leading digit" {
    var zone = try zimdns.zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\4www IN A 192.0.2.1
        \\
    );
    defer zone.deinit();
    try std.testing.expectEqualStrings("4www.example.", zone.records.items[2].ownerText());
}

test "RFC 1123 2.1: a zone-file owner label reaches the 255-octet name bound" {
    // 63+63+63+61 octet labels are 254 wire octets plus the root octet.
    var owner: [256]u8 = undefined;
    @memset(owner[0..63], 'a');
    @memset(owner[64..127], 'a');
    @memset(owner[128..191], 'a');
    @memset(owner[192..253], 'a');
    owner[63] = '.';
    owner[127] = '.';
    owner[191] = '.';
    owner[253] = '.';

    var buffer: [1024]u8 = undefined;
    var zone = try zimdns.zone_parser.ZoneFile.parse(try zoneWithOwner(&buffer, owner[0..254]));
    defer zone.deinit();
    try std.testing.expectEqualStrings(owner[0..254], zone.records.items[2].ownerText());
}

test "RFC 1123 2.1: a zone-file owner label refuses an over-long label and name" {
    var buffer: [1024]u8 = undefined;

    // A 64-octet label is one octet over the bound.
    var label: [70]u8 = undefined;
    @memset(label[0..64], 'a');
    label[64] = '.';
    try std.testing.expectError(zimdns.zone_parser.Error.BadName, zimdns.zone_parser.ZoneFile.parse(try zoneWithOwner(&buffer, label[0..65])));

    // One more character in the last label crosses the 255-octet name bound.
    var name: [256]u8 = undefined;
    @memset(name[0..63], 'a');
    @memset(name[64..127], 'a');
    @memset(name[128..191], 'a');
    @memset(name[192..254], 'a');
    name[63] = '.';
    name[127] = '.';
    name[191] = '.';
    name[254] = '.';
    try std.testing.expectError(zimdns.zone_parser.Error.BadName, zimdns.zone_parser.ZoneFile.parse(try zoneWithOwner(&buffer, name[0..255])));
}
