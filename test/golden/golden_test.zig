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
    \\
;
