/// Contract: the TLSA record this server accepts is the RFC 6698 section 2.1
/// record: three registry numbers and the association data. The CLI shows the
/// RFC 7218 acronyms in place of the numbers, and those acronyms are display
/// only, never zone text.
/// Ownership: every buffer and zone file a test owns is released before it
/// returns.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const dns_message = zimdns.dns_message;
const dns_record = zimdns.dns_record;
const dns_writer = zimdns.dns_writer;
const zone_parser = zimdns.zone_parser;

/// The wire form of host.home.arpa., the owner of every record below.
const owner_wire = [_]u8{ 4, 'h', 'o', 's', 't', 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 };

/// The 64 octets a SHA-512 matching type (2) requires, and the hexadecimal
/// text the CLI prints for them.
const sha512_association = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

const sha512_association_text = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// The association data of the records whose matching type is 0 (full).
const short_association = [_]u8{ 0xaa, 0xbb };

/// One TLSA record on the wire: a root owner, type 52, class IN, and the
/// usage, selector, matching type, and association data of RFC 6698
/// section 2.1.
fn tlsaRecord(buffer: []u8, usage: u8, selector: u8, matching_type: u8, association: []const u8) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU8(0);
    try writer.writeU16(52);
    try writer.writeU16(1);
    try writer.writeU32(3600);
    try writer.writeU16(@intCast(3 + association.len));
    try writer.writeU8(usage);
    try writer.writeU8(selector);
    try writer.writeU8(matching_type);
    try writer.writeBytes(association);
    return writer.written();
}

/// A DNS response carrying one TLSA answer, for the CLI renderer.
fn tlsaResponse(buffer: []u8, usage: u8, selector: u8, matching_type: u8, association: []const u8) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU16(0x1234);
    try writer.writeU16(0x8180);
    try writer.writeU16(0);
    try writer.writeU16(1);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try writer.writeBytes(&owner_wire);
    try writer.writeU16(52);
    try writer.writeU16(1);
    try writer.writeU32(3600);
    try writer.writeU16(@intCast(3 + association.len));
    try writer.writeU8(usage);
    try writer.writeU8(selector);
    try writer.writeU8(matching_type);
    try writer.writeBytes(association);
    return writer.written();
}

test "the CLI renders the RFC 7218 acronyms of the registry values the profile accepts" {
    const cases = [_]struct { usage: u8, selector: u8, matching_type: u8, text: []const u8 }{
        .{ .usage = 0, .selector = 0, .matching_type = 0, .text = "host.home.arpa. 3600 IN TLSA PKIX-TA Cert Full aabb\n" },
        .{ .usage = 1, .selector = 0, .matching_type = 0, .text = "host.home.arpa. 3600 IN TLSA PKIX-EE Cert Full aabb\n" },
        .{ .usage = 2, .selector = 1, .matching_type = 0, .text = "host.home.arpa. 3600 IN TLSA DANE-TA SPKI Full aabb\n" },
        .{ .usage = 3, .selector = 1, .matching_type = 2, .text = "host.home.arpa. 3600 IN TLSA DANE-EE SPKI SHA2-512 " ++ sha512_association_text ++ "\n" },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buffer: [128]u8 = undefined;
    for (cases) |case| {
        const association: []const u8 = if (case.matching_type == 2) &sha512_association else &short_association;
        const bytes = try tlsaResponse(&buffer, case.usage, case.selector, case.matching_type, association);
        const message = try dns_message.Message.parse(arena.allocator(), bytes);
        var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        try cli_query.writeResponse(message, &output.writer);
        try std.testing.expectEqualStrings(case.text, output.written());
    }
}

test "the RFC 7218 acronyms are display-only and are not accepted back as zone text" {
    try std.testing.expectError(zone_parser.Error.BadRecord, zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\_443._tcp IN TLSA PKIX-TA Cert SHA2-256 aabbcc
        \\
    ));
}

test "a TLSA record in another class is refused by the zone loader" {
    try std.testing.expectError(zone_parser.Error.BadRecord, zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\_443._tcp CH TLSA 3 1 0 aabbcc
        \\
    ));
}

test "the private-use TLSA code points are refused before the renderer sees them" {
    // RFC 7218 sections 2.1-2.3 reserve 255 for private use, so the
    // acronyms PrivCert, PrivSel, and PrivMatch never reach the CLI.
    var buffer: [128]u8 = undefined;
    const refused = [_]struct { usage: u8, selector: u8, matching_type: u8 }{
        .{ .usage = 255, .selector = 0, .matching_type = 0 },
        .{ .usage = 0, .selector = 255, .matching_type = 0 },
        .{ .usage = 0, .selector = 0, .matching_type = 255 },
    };
    for (refused) |case| {
        const bytes = try tlsaRecord(&buffer, case.usage, case.selector, case.matching_type, &.{0xaa});
        try std.testing.expectError(dns_record.Error.BadRData, dns_record.ResourceRecord.parse(bytes, 0));
    }

    try std.testing.expectError(zone_parser.Error.BadRecord, zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\_443._tcp IN TLSA 255 0 0 aabb
        \\
    ));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const bytes = try tlsaResponse(&buffer, 0, 0, 0, &.{0xaa});
    var message = try dns_message.Message.parse(arena.allocator(), bytes);
    message.answers.items[0].rdata = .{ .TLSA = .{ .usage = 255, .selector = 0, .matching_type = 0, .association_len = 0 } };

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(cli_query.Error.BadResponse, cli_query.writeResponse(message, &output.writer));
}
