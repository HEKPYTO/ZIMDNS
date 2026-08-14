const std = @import("std");
const zimdns = @import("zimdns");
const Fixture = zimdns.golden_fixture.Fixture;

test "simple A query golden fixture" {
    const text = @embedFile("simple-a-query.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();
}

test "EDNS response golden fixture" {
    const text = @embedFile("edns-response.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();
}

test "SSHFP response fixture asserts exact authoritative wire and RDATA" {
    const fixture = try Fixture.parse(@embedFile("sshfp-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(answer.rrtype.eql(.SSHFP));
    try std.testing.expectEqual(@as(u8, 4), answer.rdata.SSHFP.algorithm);
    try std.testing.expectEqual(@as(u8, 2), answer.rdata.SSHFP.fingerprint_type);
    try std.testing.expectEqualSlices(u8, &sshfp_fingerprint, answer.rdata.SSHFP.fingerprintBytes());
}

test "TLSA response fixture asserts exact authoritative wire and RDATA" {
    const fixture = try Fixture.parse(@embedFile("tlsa-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(answer.rrtype.eql(.TLSA));
    try std.testing.expectEqual(@as(u8, 0), answer.rdata.TLSA.usage);
    try std.testing.expectEqual(@as(u8, 0), answer.rdata.TLSA.selector);
    try std.testing.expectEqual(@as(u8, 1), answer.rdata.TLSA.matching_type);
    try std.testing.expectEqualSlices(u8, &tlsa_association, answer.rdata.TLSA.association[0..answer.rdata.TLSA.association_len]);
}

test "URI response fixture asserts exact authoritative wire and RDATA" {
    const fixture = try Fixture.parse(@embedFile("uri-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(answer.rrtype.eql(.URI));
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.URI.priority);
    try std.testing.expectEqual(@as(u16, 20), answer.rdata.URI.weight);
    try std.testing.expectEqualStrings("https://example.test/path", answer.rdata.URI.targetBytes());
}

test "NAPTR response fixture asserts exact uncompressed replacement wire and RDATA" {
    const fixture = try Fixture.parse(@embedFile("naptr-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(answer.rrtype.eql(.NAPTR));
    try std.testing.expectEqual(@as(u16, 100), answer.rdata.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.NAPTR.preference);
    try std.testing.expectEqualSlices(u8, "U", answer.rdata.NAPTR.flagsText());
    try std.testing.expectEqualSlices(u8, "E2U+sip", answer.rdata.NAPTR.servicesText());
    try std.testing.expectEqualSlices(u8, "", answer.rdata.NAPTR.regexpText());
    var replacement: [256]u8 = undefined;
    try std.testing.expectEqualStrings("replacement.example.", try answer.rdata.NAPTR.replacement.toText(&replacement));
}

test "APL response fixture asserts exact ordered wire and RDATA" {
    const fixture = try Fixture.parse(@embedFile("apl-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(apl_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(answer.rrtype.eql(.APL));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x18, 0x83, 0xc0, 0x00, 0x02,
        0x00, 0x02, 0x30, 0x06, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x00, 0x01, 0x18, 0x03,
        0xc0, 0x00, 0x02,
    }, answer.rdata.APL.bytes());
}

test "AFSDB response fixture asserts exact authoritative wire and RDATA without additionals" {
    const fixture = try Fixture.parse(@embedFile("afsdb-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(afsdb_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    const answer = parsed.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.AFSDB));
    try std.testing.expectEqual(@as(u16, 42), answer.rdata.AFSDB.preference);
    var hostname: [256]u8 = undefined;
    try std.testing.expectEqualStrings("server.home.arpa.", try answer.rdata.AFSDB.exchange.toText(&hostname));
}

test "CAA response fixture asserts exact authoritative wire and raw RDATA" {
    const fixture = try Fixture.parse(@embedFile("caa-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(caa_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    const answer = parsed.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.CAA));
    try std.testing.expectEqual(@as(u8, 128), answer.rdata.CAA.flags);
    try std.testing.expectEqualStrings("issue", answer.rdata.CAA.tagText());
    try std.testing.expectEqualSlices(u8, &.{ 'a', 0, 128, 255 }, answer.rdata.CAA.valueText());
}

test "EDNS response fixture asserts exact encoded OPT response" {
    const fixture = try Fixture.parse(@embedFile("edns-response.gdns-fixture"));
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1232), parsed.edns.?.udp_payload_size);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.extended_rcode);
    try std.testing.expect(std.mem.indexOf(u8, actual, &.{ 0xc0, 0x0c }) != null);
}

test "authoritative semantics fixture asserts exact encoded wildcard response" {
    const fixture = try Fixture.parse(@embedFile("authoritative-semantics.gdns-fixture"));
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(authoritative_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(parsed.answers.items[0].rrtype.eql(.A));
    var owner: [256]u8 = undefined;
    try std.testing.expectEqualStrings("other.example.", try parsed.answers.items[0].owner.toText(&owner));
}

test "EDNS unknown option response is exact and empty" {
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x80, 0x00, 0x00, 0x07, 0xea, 0x60, 0x00, 0x03, 0x01, 0x02,
        0x03,
    };
    const expected = [_]u8{
        0x12, 0x37, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x00,
        0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    };

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(&query, &output);
    try std.testing.expectEqualSlices(u8, &expected, actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const opt = parsed.additionals.items[0].rdata.OPT;
    try std.testing.expectEqual(@as(usize, 0), opt.bytes().len);
}

test "EDNS BADVERS response is exact" {
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    const expected = [_]u8{
        0x12, 0x35, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(&query, &output);
    try std.testing.expectEqualSlices(u8, &expected, actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u8, 1), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
}

test "EDNS truncation response is exact" {
    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.writeAll(
        "$ORIGIN home.arpa.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns1.home.arpa.\n",
    );
    var index: usize = 0;
    while (index < 40) : (index += 1) {
        try zone_text.writer.print("many IN A 192.0.2.{d}\n", .{index + 1});
    }
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(zone_text.written());
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x36, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        4,    'm',  'a',  'n',  'y',  4,    'h',  'o',  'm',  'e',  4,    'a',
        'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x02,
        0x58, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    };
    const expected = [_]u8{
        0x12, 0x36, 0x87, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        4,    'm',  'a',  'n',  'y',  4,    'h',  'o',  'm',  'e',  4,    'a',
        'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x02,
        0x58, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    };

    var encoded: [2048]u8 = undefined;
    const full_response = try runtime.answer(&query, &encoded);
    var output: [1232]u8 = undefined;
    const actual = try zimdns.auth_response.truncateClassicUdpResponse(full_response, &output);
    try std.testing.expectEqualSlices(u8, &expected, actual);
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\host IN SSHFP 4 2 a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401
    \\_443._tcp IN TLSA 0 0 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    \\_https._tcp IN URI 10 20 "https://example.test/path"
    \\naptr IN NAPTR 100 10 "U" "E2U+sip" "" replacement.example.
    \\
;

const sshfp_fingerprint = [_]u8{
    0xa8, 0x7f, 0x1b, 0x68, 0x7a, 0xc0, 0xe5, 0x7d,
    0x2a, 0x08, 0x1a, 0x2f, 0x28, 0x26, 0x72, 0x33,
    0x4d, 0x90, 0xed, 0x31, 0x6d, 0x2b, 0x81, 0x8c,
    0xa9, 0x58, 0x0e, 0xa3, 0x84, 0xd9, 0x24, 0x01,
};

const tlsa_association = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

const authoritative_fixture_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\ns IN A 192.0.2.1
    \\*.example. IN A 192.0.2.3
    \\
;

const apl_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\apl IN APL !1:192.0.2.7/24 2:2001:db8:1::/48 1:192.0.2.7/24
    \\
;

const afsdb_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\afsdb IN AFSDB 42 server.home.arpa.
    \\server IN A 192.0.2.53
    \\
;

const caa_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\caa IN CAA 128 issue "a\000\128\255"
    \\
;
