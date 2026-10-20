const std = @import("std");
const zimdns = @import("zimdns");
const Fixture = zimdns.golden_fixture.Fixture;

test "HINFO response fixture asserts exact authoritative wire and both fields without additionals" {
    const fixture = try Fixture.parse(@embedFile("hinfo-response.gdns-fixture"));
    try fixture.run();

    var runtime = try zimdns.auth_runtime.Runtime.fromZoneText(hinfo_fixture_zone);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const actual = try runtime.answer(fixture.inputBytes(), &output);
    try std.testing.expectEqualSlices(u8, fixture.responseBytes(), actual);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try zimdns.dns_message.Message.parse(arena.allocator(), actual);
    const answer = parsed.answers.items[0];
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expect(answer.rrtype.eql(.HINFO));
    try std.testing.expectEqualStrings("Intel", answer.rdata.HINFO.cpuText());
    try std.testing.expectEqualStrings("Linux", answer.rdata.HINFO.osText());
}

const hinfo_fixture_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 300
    \\@ IN NS ns.home.arpa.
    \\hinfo IN HINFO "Intel" "Linux"
    \\
;
