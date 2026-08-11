/// Contract: Answers DNS queries against one authoritative zone and blocklist.
/// Ownership: Runtime owns its Zone and inline Blocklist; call Runtime.deinit; query and output buffers are borrowed.
/// Errors: Query and response failures are typed; transport I/O is handled by platform listeners.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_writer = @import("../dns/writer.zig");
const response = @import("response.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");
const metrics = @import("../metrics.zig");
const blocklist_mod = @import("../blocklist.zig");

pub const Error = error{
    BadQuery,
    EncodeFailed,
};

pub const Runtime = struct {
    zone: zone_index.Zone,
    blocklist: blocklist_mod.Blocklist = .{},

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneText(text: []const u8) !Runtime {
        var zone_file = try zone_parser.ZoneFile.parse(text);
        errdefer zone_file.deinit();
        return .{ .zone = try zone_index.Zone.fromZoneFile(&zone_file) };
    }

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneTextWithBlocklist(text: []const u8, blocklist: blocklist_mod.Blocklist) !Runtime {
        var zone_file = try zone_parser.ZoneFile.parse(text);
        errdefer zone_file.deinit();
        return .{
            .zone = try zone_index.Zone.fromZoneFile(&zone_file),
            .blocklist = blocklist,
        };
    }

    pub fn deinit(self: *Runtime) void {
        self.zone.deinit();
    }

    pub fn answer(self: *const Runtime, query_bytes: []const u8, output: []u8) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        const query = dns_message.Message.parseQuery(arena.allocator(), query_bytes) catch return Error.BadQuery;
        const message = try self.buildMessage(query);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return writer.written();
    }

    pub fn answerWithMetrics(self: *const Runtime, query_bytes: []const u8, output: []u8, counters: *metrics.Counters) ![]const u8 {
        counters.queries_total += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        const query = dns_message.Message.parseQuery(arena.allocator(), query_bytes) catch {
            counters.bad_queries_total += 1;
            return Error.BadQuery;
        };
        const message = try self.buildMessage(query);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch {
            counters.encode_failures_total += 1;
            return Error.EncodeFailed;
        };
        counters.responses_total += 1;
        return writer.written();
    }

    fn buildMessage(self: *const Runtime, query: dns_message.Message) !dns_message.Message {
        const q = query.question orelse return response.Error.MissingQuestion;
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return response.Error.BadQName;
        if (self.blocklist.blocks(qname_text)) {
            return .{
                .header = .{
                    .id = query.header.id,
                    .qr = true,
                    .recursion_desired = query.header.recursion_desired,
                    .recursion_available = false,
                    .rcode = .refused,
                    .question_count = 1,
                },
                .question = q,
            };
        }
        return response.buildResponse(query, &self.zone);
    }
};

test "authoritative runtime answers raw query bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
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
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &parsed.answers.items[0].rdata.A);
}

test "authoritative runtime records metrics for successful and bad queries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var counters = @import("../metrics.zig").Counters{};
    var output: [512]u8 = undefined;
    _ = try runtime.answerWithMetrics(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &counters);
    try std.testing.expectError(Error.BadQuery, runtime.answerWithMetrics(&.{ 0x12, 0x34 }, &output, &counters));

    try std.testing.expectEqual(@as(u64, 2), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 1), counters.bad_queries_total);
    try std.testing.expectEqual(@as(u64, 0), counters.encode_failures_total);
}

test "authoritative runtime refuses exact blocklisted names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const blocklist = try @import("../blocklist.zig").Blocklist.parse("ads.home.arpa.\n");
    var runtime = try Runtime.fromZoneTextWithBlocklist(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\ads IN A 192.168.1.99
        \\
    , blocklist);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
}
