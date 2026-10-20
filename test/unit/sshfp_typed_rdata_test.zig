/// Contract: the SSHFP record this server accepts is the one RFC 4255
/// section 3.2 presents: a decimal algorithm, a decimal fingerprint type, and
/// a hexadecimal fingerprint, on the wire and in zone text.
/// Ownership: every buffer and zone file a test owns is released before it
/// returns.
const std = @import("std");
const zimdns = @import("zimdns");

const dns_record = zimdns.dns_record;
const dns_writer = zimdns.dns_writer;
const zone_parser = zimdns.zone_parser;

/// The algorithm code points this profile accepts: RSA (1) and DSS (2) from
/// RFC 4255 section 3.1.1, ECDSA (3) from RFC 6594 section 3.2.1, Ed25519 (4)
/// from RFC 7479 section 4, and Ed448 (6) from RFC 8709 section 8.
const accepted_algorithms = [_]u8{ 1, 2, 3, 4, 6 };

/// A SHA-1 fingerprint, the 20 octets fingerprint type 1 requires.
const sha1_fingerprint = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
};

/// The SHA-256 fingerprint of RFC 7479 section 2, the 32 octets fingerprint
/// type 2 requires.
const sha256_fingerprint = [_]u8{
    0xa8, 0x7f, 0x1b, 0x68, 0x7a, 0xc0, 0xe5, 0x7d, 0x2a, 0x08,
    0x1a, 0x2f, 0x28, 0x26, 0x72, 0x33, 0x4d, 0x90, 0xed, 0x31,
    0x6d, 0x2b, 0x81, 0x8c, 0xa9, 0x58, 0x0e, 0xa3, 0x84, 0xd9,
    0x24, 0x01,
};

/// The same fingerprint as the hexadecimal text RFC 4255 section 3.2 shows.
const sha256_fingerprint_text = "a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401";

/// One SSHFP record on the wire: a root owner, type 44, class IN, and the
/// algorithm, fingerprint type, and fingerprint of RFC 4255 section 3.1.
fn sshfpRecord(buffer: []u8, algorithm: u8, fingerprint_type: u8, fingerprint: []const u8) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU8(0);
    try writer.writeU16(44);
    try writer.writeU16(1);
    try writer.writeU32(3600);
    try writer.writeU16(@intCast(2 + fingerprint.len));
    try writer.writeU8(algorithm);
    try writer.writeU8(fingerprint_type);
    try writer.writeBytes(fingerprint);
    return writer.written();
}

test "SSHFP wire accepts every algorithm code point the profile supports" {
    var buffer: [64]u8 = undefined;
    for (accepted_algorithms) |algorithm| {
        const bytes = try sshfpRecord(&buffer, algorithm, 2, &sha256_fingerprint);
        const parsed = try dns_record.ResourceRecord.parse(bytes, 0);
        const record = parsed.record;
        try std.testing.expect(record.rrtype.eql(.SSHFP));
        try std.testing.expectEqual(algorithm, record.rdata.SSHFP.algorithm);
        try std.testing.expectEqual(@as(u8, 2), record.rdata.SSHFP.fingerprint_type);
        try std.testing.expectEqualSlices(u8, &sha256_fingerprint, record.rdata.SSHFP.fingerprintBytes());

        var encoded: [64]u8 = undefined;
        var writer = dns_writer.Writer.init(&encoded);
        try record.encode(&writer);
        try std.testing.expectEqualSlices(u8, bytes, writer.written());

        const sha1_bytes = try sshfpRecord(&buffer, algorithm, 1, &sha1_fingerprint);
        const sha1_record = (try dns_record.ResourceRecord.parse(sha1_bytes, 0)).record;
        try std.testing.expectEqual(algorithm, sha1_record.rdata.SSHFP.algorithm);
        try std.testing.expectEqual(@as(u8, 1), sha1_record.rdata.SSHFP.fingerprint_type);
        try std.testing.expectEqualSlices(u8, &sha1_fingerprint, sha1_record.rdata.SSHFP.fingerprintBytes());
    }
}

test "SSHFP zone text accepts the same algorithm code points" {
    var buffer: [64]u8 = undefined;
    const type_bytes = try sshfpRecord(&buffer, 4, 2, &sha256_fingerprint);
    const sshfp_type = (try dns_record.ResourceRecord.parse(type_bytes, 0)).record.rrtype;

    for (accepted_algorithms) |algorithm| {
        var text_buffer: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&text_buffer, "{d} 2 {s}", .{ algorithm, sha256_fingerprint_text });
        const rdata = try zone_parser.parseRData(sshfp_type, text);
        try std.testing.expectEqual(algorithm, rdata.SSHFP.algorithm);
        try std.testing.expectEqual(@as(u8, 2), rdata.SSHFP.fingerprint_type);
        try std.testing.expectEqualSlices(u8, &sha256_fingerprint, rdata.SSHFP.fingerprintBytes());

        var zone_buffer: [256]u8 = undefined;
        const zone_text = try std.fmt.bufPrint(
            &zone_buffer,
            "$ORIGIN example.\n$TTL 3600\n@ IN SOA ns hostmaster 1 3600 900 1209600 3600\n@ IN NS ns\nhost IN SSHFP {d} 2 {s}\n",
            .{ algorithm, sha256_fingerprint_text },
        );
        var zone = try zone_parser.ZoneFile.parse(zone_text);
        defer zone.deinit();
        try std.testing.expect(zone.records.items[2].rrtype.eql(.SSHFP));
    }
}

test "an SSHFP record in another class is refused by the zone loader" {
    try std.testing.expectError(zone_parser.Error.BadRecord, zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns hostmaster 1 3600 900 1209600 3600
        \\@ IN NS ns
        \\host CH SSHFP 4 2 a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401
        \\
    ));
}
