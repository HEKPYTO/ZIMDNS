const std = @import("std");
const zimdns = @import("zimdns");

// RFC 2181 section 5.1: "A query for a specific (or non-specific) label,
// class, and type, will always return all records in the associated RRSet -
// whether that be one or more RRs."
// RFC 2181 section 5.2: "the TTLs of all RRs in an RRSet must be the same"
// and "In no case may a server send an RRSet with TTLs not all equal."
// RFC 2181 section 6.1: "A server for a zone should not return authoritative
// answers for queries related to names in another zone, which includes the
// NS, and perhaps A, records at a zone cut, unless it also happens to be a
// server for the other zone."
// RFC 2181 section 10.1: "An alias name (label of a CNAME record) may, if
// DNSSEC is in use, have SIG, NXT, and KEY RRs, but may have no other data."

test "RFC 2181 6.1: a name no loaded zone is authoritative for is REFUSED" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  4,    'e',  'l',  's',  'e',  3,    'c',  'o',
        'm',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.rcode == .refused);
    try std.testing.expect(!parsed.header.authoritative);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
}

test "RFC 2181 5.1 and 5.2: an RRSet is answered whole at the lowest TTL" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The zone gives one A RRSet two TTLs, so the served RRSet must carry one
    // TTL, the lowest of the two, and must carry every RR of the set.
    var zone_file = try zimdns.zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\www 300 IN A 192.0.2.2
        \\www 600 IN A 192.0.2.3
        \\
    );
    var zone = try zimdns.zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request = try zimdns.dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    var response = try zimdns.auth_response.buildResponse(request, &zone);
    defer response.deinit();

    try std.testing.expectEqual(@as(usize, 2), response.answers.len);
    try std.testing.expectEqual(@as(u32, 300), response.answers.items[0].ttl);
    try std.testing.expectEqual(@as(u32, 300), response.answers.items[1].ttl);
}

test "RFC 2181 10.1: a CNAME sharing an owner with other data is refused" {
    // The alias carries an A record first, so the CNAME is the record that
    // must be refused.
    try std.testing.expectError(zimdns.zone_parser.Error.CnameConflict, zimdns.zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 300
        \\@ IN NS ns
        \\alias IN A 192.0.2.1
        \\alias IN CNAME target
        \\
    ));
}
