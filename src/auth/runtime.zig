const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_writer = @import("../dns/writer.zig");
const response = @import("response.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");

pub const Error = error{
    BadQuery,
    EncodeFailed,
};

pub const Runtime = struct {
    zone: zone_index.Zone,

    pub fn fromZoneText(text: []const u8) !Runtime {
        const zone_file = try zone_parser.ZoneFile.parse(text);
        return .{ .zone = try zone_index.Zone.fromZoneFile(zone_file) };
    }

    pub fn answer(self: *const Runtime, query_bytes: []const u8, output: []u8) ![]const u8 {
        const query = dns_message.Message.parseQuery(query_bytes) catch return Error.BadQuery;
        const message = try response.buildResponse(query, &self.zone);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return writer.written();
    }
};

test "authoritative runtime answers raw query bytes" {
    const runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &parsed.answers.items[0].rdata.A);
}
