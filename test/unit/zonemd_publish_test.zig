/// Contract: the RFC 8976 publisher and the verifier agree on a zone digest:
/// the record the publisher prints is the record the verifier accepts, and a
/// zone it cannot digest is refused instead of published.
/// Ownership: every zone, buffer and string a test owns is released before it
/// returns.
/// Errors: a refusal is asserted by its typed error and by the absence of a
/// digest on the writer.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_zonemd = zimdns.cli_zonemd;
const zone_index = zimdns.zone_index;
const zone_parser = zimdns.zone_parser;
const zone_zonemd = zimdns.zone_zonemd;

/// The RFC 8976 Appendix A.1 zone without its ZONEMD record. The digest the
/// RFC publishes for that zone is the digest of exactly this zone.
const rfc_a1_zone =
    \\$ORIGIN example.
    \\$TTL 86400
    \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
    \\@ IN NS ns1
    \\@ IN NS ns2
    \\ns1 3600 IN A 203.0.113.63
    \\ns2 3600 IN AAAA 2001:db8::63
    \\
;

/// The SIMPLE/SHA384 digest RFC 8976 Appendix A.1 publishes for the zone
/// above.
const rfc_a1_digest = "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9" ++
    "a9713b3c9ae5cc27777f98b8e730044c";

/// The placeholder record RFC 8976 section 3.1 puts at the apex before the
/// digest is calculated: the current SOA serial, the chosen scheme and hash,
/// and a digest that does not matter yet.
const placeholder_record = "@ IN ZONEMD 2018031900 1 1 " ++
    "000000000000000000000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000\n";

fn loadZone(text: []const u8) !zone_index.Zone {
    var zone_file = try zone_parser.ZoneFile.parse(text);
    defer zone_file.deinit();
    return zone_index.Zone.fromZoneFile(&zone_file);
}

test "the published record is the record the verifier accepts" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try cli_zonemd.publish(rfc_a1_zone, 1, 1, std.testing.allocator, &output.writer);

    // The record is zone text the operator can paste into the zone: the apex
    // owner, the TTL the RFC recommends for a ZONEMD record (the SOA's own
    // TTL), the zone's SOA serial, the scheme and hash codes, and the digest.
    const record = std.mem.trim(u8, output.written(), "\n");
    try std.testing.expectEqualStrings("example. 86400 IN ZONEMD 2018031900 1 1 " ++ rfc_a1_digest, record);

    // The zone carrying the published record verifies.
    const published_zone = try std.testing.allocator.alloc(u8, rfc_a1_zone.len + record.len + 1);
    defer std.testing.allocator.free(published_zone);
    @memcpy(published_zone[0..rfc_a1_zone.len], rfc_a1_zone);
    @memcpy(published_zone[rfc_a1_zone.len..][0..record.len], record);
    published_zone[published_zone.len - 1] = '\n';

    var zone = try loadZone(published_zone);
    defer zone.deinit();
    var report: [zone_zonemd.report_max_len]u8 = undefined;
    const message = try zone_zonemd.verify(&zone, std.testing.allocator, &report);
    try std.testing.expect(std.mem.startsWith(u8, message, "zone example.: ZONEMD verified (SIMPLE SHA384"));
}

test "the placeholder apex ZONEMD record stays outside the digest" {
    // RFC 8976 section 3.3.1.1: the placeholder apex ZONEMD RRset is not
    // part of the digest, so a zone that still carries the placeholder the
    // publisher is about to replace yields the same digest.
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try cli_zonemd.publish(rfc_a1_zone, 1, 1, std.testing.allocator, &output.writer);

    var with_placeholder: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer with_placeholder.deinit();
    try cli_zonemd.publish(rfc_a1_zone ++ placeholder_record, 1, 1, std.testing.allocator, &with_placeholder.writer);

    try std.testing.expectEqualStrings(output.written(), with_placeholder.written());
}

test "a new SOA serial is a new zone version with a new digest" {
    // RFC 8976 section 3.3.1.1 includes every record of the zone, the SOA
    // among them, and section 3.1 binds the record to the zone's current SOA
    // serial. A zone whose serial moved is a different zone version: the
    // digest moves with it, and the published record carries the new serial.
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try cli_zonemd.publish(rfc_a1_zone, 1, 1, std.testing.allocator, &output.writer);

    const bumped =
        \\$ORIGIN example.
        \\$TTL 86400
        \\@ IN SOA ns1 admin 2018031901 1800 900 604800 86400
        \\@ IN NS ns1
        \\@ IN NS ns2
        \\ns1 3600 IN A 203.0.113.63
        \\ns2 3600 IN AAAA 2001:db8::63
        \\
    ;
    var bumped_output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer bumped_output.deinit();
    try cli_zonemd.publish(bumped, 1, 1, std.testing.allocator, &bumped_output.writer);

    try std.testing.expect(!std.mem.eql(u8, output.written(), bumped_output.written()));
    try std.testing.expect(std.mem.indexOf(u8, bumped_output.written(), "ZONEMD 2018031901 1 1 ") != null);
}

test "a private-use scheme or hash algorithm is refused" {
    // RFC 8976 sections 5.2 and 5.3 reserve 240-254 for Private Use. No
    // digest can be computed for them, so the publisher refuses instead of
    // publishing a record it did not compute.
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(
        cli_zonemd.Error.UnsupportedScheme,
        cli_zonemd.publish(rfc_a1_zone, 241, 1, std.testing.allocator, &output.writer),
    );
    try std.testing.expectError(
        cli_zonemd.Error.UnsupportedHash,
        cli_zonemd.publish(rfc_a1_zone, 1, 240, std.testing.allocator, &output.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "ZONEMD") == null);
}

test "a zone the publisher cannot digest is refused" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    // A zone whose RDATA does not parse.
    try std.testing.expectError(
        cli_zonemd.Error.MalformedZone,
        cli_zonemd.publish(
            \\$ORIGIN example.
            \\$TTL 3600
            \\@ IN NS ns1.example.
            \\@ IN A not-an-address
            \\
        ,
            1,
            1,
            std.testing.allocator,
            &output.writer,
        ),
    );

    // A zone with no SOA record has no serial to bind the digest to.
    try std.testing.expectError(
        cli_zonemd.Error.NoSoa,
        cli_zonemd.publish(
            \\$ORIGIN example.
            \\$TTL 3600
            \\@ IN NS ns1.example.
            \\
        ,
            1,
            1,
            std.testing.allocator,
            &output.writer,
        ),
    );

    // No digest was printed for either refusal.
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "ZONEMD") == null);
}
