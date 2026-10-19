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

test "TSIG response golden fixture is byte-exact" {
    const fixture = try Fixture.parse(@embedFile("tsig-response.gdns-fixture"));
    try fixture.run();

    var keyring = try zimdns.auth_keyring.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try zimdns.auth_runtime.Runtime.fromZoneTextWithKeyring(
        tsig_fixture_zone,
        &keyring,
    );
    defer runtime.deinit();
    runtime.setTsigNow(1_700_000_000);

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);
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

test "RP response fixture asserts exact authoritative wire and no synthesized TXT additional" {
    const fixture = try Fixture.parse(@embedFile("rp-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(rp_fixture_zone);
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
    try std.testing.expect(answer.rrtype.eql(.RP));
    var mbox: [256]u8 = undefined;
    var txt: [256]u8 = undefined;
    try std.testing.expectEqualStrings("mbox.home.arpa.", try answer.rdata.RP.mbox.toText(&mbox));
    try std.testing.expectEqualStrings("txt-dname.home.arpa.", try answer.rdata.RP.txt.toText(&txt));
}

test "X25 response fixture asserts exact authoritative wire and RDATA without additionals" {
    const fixture = try Fixture.parse(@embedFile("x25-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(x25_fixture_zone);
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
    try std.testing.expect(answer.rrtype.eql(.X25));
    try std.testing.expectEqualStrings("1234", answer.rdata.X25.text());
}

test "ISDN response fixture asserts exact authoritative wire and both fields without additionals" {
    const fixture = try Fixture.parse(@embedFile("isdn-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(isdn_fixture_zone);
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
    try std.testing.expect(answer.rrtype.eql(.ISDN));
    try std.testing.expectEqualStrings("1234", answer.rdata.ISDN.addressText());
    try std.testing.expect(answer.rdata.ISDN.has_subaddress);
    try std.testing.expectEqualStrings("aBf", answer.rdata.ISDN.subaddressText());
}

test "RT response fixture asserts exact authoritative wire and no synthesized additionals" {
    const fixture = try Fixture.parse(@embedFile("rt-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(rt_fixture_zone);
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
    try std.testing.expect(answer.rrtype.eql(.RT));
    try std.testing.expectEqual(@as(u16, 100), answer.rdata.RT.preference);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.RT.exchange.toText(&target));
}

test "SRV response fixture asserts exact uncompressed target wire and no additionals" {
    const fixture = try Fixture.parse(@embedFile("srv-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(srv_fixture_zone);
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
    try std.testing.expect(answer.rrtype.eql(.SRV));
    try std.testing.expectEqual(@as(u16, 10), answer.rdata.SRV.priority);
    try std.testing.expectEqual(@as(u16, 20), answer.rdata.SRV.weight);
    try std.testing.expectEqual(@as(u16, 8443), answer.rdata.SRV.port);
    try std.testing.expectEqualSlices(u8, &.{
        0x06, 't', 'a', 'r',  'g', 'e',  't',
        0x04, 'h', 'o', 'm',  'e', 0x04, 'a',
        'r',  'p', 'a', 0x00,
    }, answer.rdata.SRV.target.asWire());
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

test "RFC 7830 Padding request has an exact bare-OPT authoritative response" {
    const fixture = try Fixture.parse(@embedFile("edns-padding-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.OPT.bytes().len);
}

test "RFC 7871 ECS /0 request has an exact bare-OPT authoritative response" {
    const fixture = try Fixture.parse(@embedFile("edns-ecs-zero-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.OPT.bytes().len);
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

test "DNSSEC response fixture asserts exact DO-bit wire with covering RRSIG" {
    const fixture = try Fixture.parse(@embedFile("dnssec-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(dnssec_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    try std.testing.expectEqual(@as(u16, 2), parsed.header.answer_count);
    try std.testing.expect(parsed.answers.items[0].rrtype.eql(.A));
    try std.testing.expect(parsed.answers.items[1].rrtype.eql(.RRSIG));
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expect(!parsed.header.authenticated_data);
    const covers = try zimdns.dns_dnssec.rrsigCovers(parsed.answers.items[1].rdata.Unknown.bytes());
    try std.testing.expectEqual(@as(u16, 1), covers);
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

const dnssec_fixture_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\www IN A 192.0.2.1
    \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\
;

const tsig_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
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

const x25_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\x25 IN X25 1234
    \\
;

const isdn_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\isdn IN ISDN 1234 "aBf"
    \\
;

const rt_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\rt IN RT 100 target.home.arpa.
    \\target IN A 192.0.2.21
    \\target IN X25 1234
    \\target IN ISDN 1234 "aBf"
    \\
;

const srv_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\srv IN SRV 10 20 8443 target.home.arpa.
    \\target IN A 192.0.2.21
    \\target IN AAAA 2001:db8::21
    \\
;

const rp_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\rp IN RP mbox.home.arpa. txt-dname.home.arpa.
    \\txt-dname IN TXT "target text"
    \\
;

test "DNAME query golden fixture" {
    const text = @embedFile("dname-response.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(dname_fixture_zone);
    defer runtime.deinit();
    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[1];
    try std.testing.expect(answer.rrtype.eql(.CNAME));
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.target.example.", try answer.rdata.CNAME.toText(&target));
}

const dname_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\legacy IN DNAME target.example.
    \\target IN A 192.0.2.21
    \\
;

test "SVCB query golden fixture" {
    const text = @embedFile("svcb-response.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(svcb_fixture_zone);
    defer runtime.deinit();
    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.SVCB));
    try std.testing.expectEqual(@as(u16, 1), answer.rdata.SVCB.priority);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.SVCB.target.toText(&target));
}

const svcb_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\svc IN SVCB 1 target.home.arpa. alpn=h2 port=443
    \\target IN A 192.0.2.21
    \\
;
test "HTTPS query golden fixture" {
    const text = @embedFile("https-response.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(https_fixture_zone);
    defer runtime.deinit();
    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.HTTPS));
    try std.testing.expectEqual(@as(u16, 0), answer.rdata.HTTPS.priority);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.home.arpa.", try answer.rdata.HTTPS.target.toText(&target));
    try std.testing.expectEqual(@as(u16, 0), answer.rdata.HTTPS.params_len);
}

const https_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\alias IN HTTPS 0 target
    \\target IN A 192.0.2.21
    \\
;

test "AAAA query golden fixture" {
    const text = @embedFile("aaaa-response.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(aaaa_fixture_zone);
    defer runtime.deinit();
    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21 }, &answer.rdata.AAAA);
}

const aaaa_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\target IN AAAA 2001:db8::21
    \\
;
