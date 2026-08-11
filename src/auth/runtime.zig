/// Contract: Answers authoritative zones first and optionally forwards authorized UDP queries.
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
const resolver_mod = @import("../resolver.zig");

pub const Error = error{
    BadQuery,
    EncodeFailed,
};

pub const Runtime = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},
    resolver: ?resolver_mod.Resolver = null,

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneText(text: []const u8) !Runtime {
        var runtime = Runtime{};
        errdefer runtime.deinit();
        try runtime.appendZoneText(text);
        return runtime;
    }

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneTextWithBlocklist(text: []const u8, blocklist: blocklist_mod.Blocklist) !Runtime {
        var runtime = try fromZoneText(text);
        runtime.blocklist = blocklist;
        return runtime;
    }

    /// The returned runtime owns every zone value moved from `zones`.
    pub fn fromZones(allocator: std.mem.Allocator, zones: *std.ArrayList(zone_index.Zone), blocklist: blocklist_mod.Blocklist) Runtime {
        const runtime = Runtime{ .allocator = allocator, .zones = zones.*, .blocklist = blocklist };
        zones.* = .empty;
        return runtime;
    }

    pub fn fromZonesWithPolicy(allocator: std.mem.Allocator, zones: *std.ArrayList(zone_index.Zone), blocklist: blocklist_mod.Blocklist, io: std.Io, policy: resolver_mod.Policy) !Runtime {
        var runtime = fromZones(allocator, zones, blocklist);
        errdefer runtime.deinit();
        runtime.resolver = try resolver_mod.Resolver.init(allocator, io, policy);
        return runtime;
    }

    /// The returned runtime owns all parsed zone backing storage.
    pub fn fromZoneTexts(texts: []const []const u8) !Runtime {
        var runtime = Runtime{};
        errdefer runtime.deinit();
        for (texts) |text| try runtime.appendZoneText(text);
        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        if (self.resolver) |*resolver| resolver.deinit();
        self.resolver = null;
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.blocklist = .{};
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

    pub fn answerFrom(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), query_bytes) catch return Error.BadQuery;
        const q = query.question orelse return Error.BadQuery;
        if (query.header.opcode != .query) {
            return self.encodeMessage(try response.buildNotImplementedResponse(query), output);
        }
        if (query.edns) |edns| if (edns.version != dns_message.EDNS_VERSION) {
            return self.encodeMessage(try response.buildBadVersionResponse(query, q), output);
        };
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQuery;

        if (self.selectZone(qname_text) != null) {
            if (self.resolver) |*resolver| {
                const server_cookie = resolver.validateCookie(query, client) catch |err| switch (err) {
                    resolver_mod.Error.BadCookie => return self.encodeMessage(try resolver.badCookieResponse(query, client), output),
                    else => return err,
                };
                var message = try self.buildMessage(query);
                errdefer message.deinit();
                if (server_cookie) |cookie| try resolver_mod.appendCookie(&message, cookie);
                return self.encodeMessage(message, output);
            }
            return self.encodeMessage(try self.buildMessage(query), output);
        }
        if (self.blocklist.blocks(qname_text)) return self.encodeMessage(try response.buildRefusedResponse(query), output);
        if (!q.qclass.eql(@import("../dns/types.zig").Class.IN) or !query.header.recursion_desired) {
            return self.encodeMessage(try response.buildRefusedResponse(query), output);
        }
        if (self.resolver) |*resolver| {
            if (!resolver.policy.allows(client)) return self.encodeMessage(try response.buildRefusedResponse(query), output);
            return resolver.answer(query_bytes, query, client, output) catch |err| switch (err) {
                resolver_mod.Error.UpstreamFailure,
                resolver_mod.Error.BadUpstreamResponse,
                => self.encodeMessage(try resolver_mod.buildNetworkErrorResponse(query), output),
                resolver_mod.Error.NoForwarder => self.encodeMessage(try response.buildRefusedResponse(query), output),
                resolver_mod.Error.ResponseTooLarge => return Error.EncodeFailed,
                else => return err,
            };
        }
        return self.encodeMessage(try response.buildRefusedResponse(query), output);
    }

    pub fn answerFromWithMetrics(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress, counters: *metrics.Counters) ![]const u8 {
        counters.queries_total += 1;
        const result = self.answerFrom(query_bytes, output, client) catch |err| {
            if (err == Error.BadQuery) counters.bad_queries_total += 1;
            if (err == Error.EncodeFailed) counters.encode_failures_total += 1;
            return err;
        };
        counters.responses_total += 1;
        return result;
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

    fn encodeMessage(self: *const Runtime, response_message: dns_message.Message, output: []u8) ![]const u8 {
        _ = self;
        var message = response_message;
        defer message.deinit();
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return writer.written();
    }

    fn buildMessage(self: *const Runtime, query: dns_message.Message) !dns_message.Message {
        const q = query.question orelse return response.Error.MissingQuestion;
        if (query.header.opcode != .query) return response.buildNotImplementedResponse(query);
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return response.Error.BadQName;
        if (self.blocklist.blocks(qname_text)) return response.buildRefusedResponse(query);
        const selected = self.selectZone(qname_text) orelse return response.buildRefusedResponse(query);
        return response.buildResponse(query, selected);
    }

    fn appendZoneText(self: *Runtime, text: []const u8) !void {
        var zone_file = try zone_parser.ZoneFile.parse(text);
        errdefer zone_file.deinit();
        var zone = try zone_index.Zone.fromZoneFile(&zone_file);
        errdefer zone.deinit();
        try self.zones.append(self.allocator, zone);
    }

    fn selectZone(self: *const Runtime, qname: []const u8) ?*const zone_index.Zone {
        var selected: ?*const zone_index.Zone = null;
        for (self.zones.items) |*zone| {
            if (!zone.contains(qname)) continue;
            if (selected == null or zone.originText().len > selected.?.originText().len) selected = zone;
        }
        return selected;
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

test "authoritative runtime returns NOTIMP for non-IN queries outside a zone" {
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
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  4,    't',  'e',  's',
        't',  0,    0x00, 0x01, 0x00, 0x03,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.notimp, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 3), parsed.question.?.qclass.code());
}

test "authoritative runtime drops response packets instead of answering them" {
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
    try std.testing.expectError(Error.BadQuery, runtime.answerFrom(&.{
        0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &try std.Io.net.IpAddress.parse("127.0.0.1", 53000)));
}

test "authoritative runtime answers unassigned opcodes with local NOTIMP" {
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
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x19, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &try std.Io.net.IpAddress.parse("127.0.0.1", 53001));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.opcode), .unassigned_3), parsed.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notimp), parsed.header.rcode);
}

test "authoritative runtime applies configured Cookie validation" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer zone_file.deinit();
    const zone = try zone_index.Zone.fromZoneFile(&zone_file);
    var zones = std.ArrayList(zone_index.Zone).empty;
    try zones.append(std.testing.allocator, zone);
    const cookie_policy = resolver_mod.CookiePolicy.init("current-secret", null);
    var runtime = try Runtime.fromZonesWithPolicy(
        std.testing.allocator,
        &zones,
        .{},
        io,
        .{ .cookies = cookie_policy },
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53002);
    const invalid_cookie_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0,    0,    0,    0x00, 0x00, 0x0d, 0,    0x0a, 0,    9,    1,    2,
        3,    4,    5,    6,    7,    8,    9,
    };
    const response_bytes = try runtime.answerFrom(&invalid_cookie_query, &output, &client);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .badcookie), parsed.header.rcode);
    try std.testing.expectEqual(@as(u8, 1), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(usize, 24), findCookieOption(parsed).?.len);

    const client_cookie = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var server_cookie: [24]u8 = undefined;
    cookie_policy.makeServerCookie(&client, &client_cookie, &server_cookie);
    var valid_cookie_query: [70]u8 = undefined;
    @memcpy(valid_cookie_query[0..46], invalid_cookie_query[0..46]);
    std.mem.writeInt(u16, valid_cookie_query[40..42], 28, .big);
    std.mem.writeInt(u16, valid_cookie_query[44..46], 24, .big);
    @memcpy(valid_cookie_query[46..], &server_cookie);
    const valid_response_bytes = try runtime.answerFrom(&valid_cookie_query, &output, &client);
    const valid_response = try dns_message.Message.parse(arena.allocator(), valid_response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(valid_response.header.rcode), .no_error), valid_response.header.rcode);
    try std.testing.expectEqualSlices(u8, &server_cookie, findCookieOption(valid_response).?);
}

fn findCookieOption(message: dns_message.Message) ?[]const u8 {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const bytes = record.rdata.OPT.bytes();
        if (bytes.len < 4) continue;
        if (std.mem.readInt(u16, bytes[0..2], .big) != resolver_mod.COOKIE_OPTION_CODE) continue;
        const length = std.mem.readInt(u16, bytes[2..4], .big);
        if (length > bytes.len - 4) return null;
        return bytes[4 .. 4 + length];
    }
    return null;
}

test "authoritative runtime dispatches to the longest matching zone" {
    var runtime = try Runtime.fromZoneTexts(&.{
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
        ,
        \\$ORIGIN sub.example.
        \\$TTL 3600
        \\@ IN SOA ns.sub.example. hostmaster.sub.example. 1 3600 900 1209600 300
        \\@ IN NS ns.sub.example.
        \\www IN A 192.0.2.2
        \\
        ,
    });
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  3,    's',  'u',  'b',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &parsed.answers.items[0].rdata.A);
}

test "authoritative runtime selects longest mixed-case ancestor origin" {
    var runtime = try Runtime.fromZoneTexts(&.{
        \\$ORIGIN Example.
        \\$TTL 3600
        \\@ IN SOA ns.Example. hostmaster.Example. 1 3600 900 1209600 300
        \\@ IN NS ns.Example.
        \\www IN A 192.0.2.1
        \\
        ,
        \\$ORIGIN Sub.Example.
        \\$TTL 3600
        \\@ IN SOA ns.Sub.Example. hostmaster.Sub.Example. 1 3600 900 1209600 300
        \\@ IN NS ns.Sub.Example.
        \\www IN A 192.0.2.2
        \\
        ,
    });
    defer runtime.deinit();

    const selected = runtime.selectZone("WWW.SUB.EXAMPLE.") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("Sub.Example.", selected.originText());
    try std.testing.expect(runtime.selectZone("www.notexample.") == null);
}
