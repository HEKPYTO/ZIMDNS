const std = @import("std");
const dns_message = @import("../dns/message.zig");
const header = @import("../dns/header.zig");
const question = @import("../dns/question.zig");
const dns_name = @import("../dns/name.zig");
const dns_record = @import("../dns/record.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_types = @import("../dns/types.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");

pub const Error = error{
    MissingQuestion,
    BadQName,
    BadZoneRecord,
    BadAddress,
    TooManyRecords,
};

pub fn buildResponse(request: dns_message.Message, zone: *const zone_index.Zone) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    var qname_text_buffer: [256]u8 = undefined;
    const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQName;
    const lookup = zone.lookup(qname_text, q.qtype);

    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .authoritative = lookup.kind != .not_authoritative,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .rcode = switch (lookup.kind) {
                .nxdomain => .nxdomain,
                .not_authoritative => .refused,
                else => .no_error,
            },
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
    };
    errdefer response.deinit();

    switch (lookup.kind) {
        .answer, .cname => {
            var index: usize = 0;
            while (index < lookup.records.len) : (index += 1) {
                try response.answers.append(try toResourceRecord(lookup.records.items[index]));
            }
        },
        .nodata, .nxdomain => {
            if (lookup.soa) |soa| try response.authorities.append(try toResourceRecord(soa));
        },
        .not_authoritative => {},
    }

    try setHeaderCounts(&response);
    return response;
}

fn setHeaderCounts(response: *dns_message.Message) Error!void {
    const max_count = @as(usize, std.math.maxInt(u16));
    if (response.answers.len > max_count or response.authorities.len > max_count or response.additionals.len > max_count) {
        return Error.TooManyRecords;
    }
    response.header.answer_count = @intCast(response.answers.len);
    response.header.authority_count = @intCast(response.authorities.len);
    response.header.additional_count = @intCast(response.additionals.len);
}

fn toResourceRecord(record: zone_parser.ZoneRecord) !dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(record.ownerText()) catch return Error.BadZoneRecord,
        .rrtype = record.rrtype,
        .class = dns_types.Class.IN,
        .ttl = record.ttl,
        .rdata = try parseZoneRData(record),
    };
}

fn parseZoneRData(record: zone_parser.ZoneRecord) !dns_rdata.RData {
    if (record.rrtype.eql(.A)) {
        return .{ .A = try parseIpv4(record.rdataText()) };
    }
    if (record.rrtype.eql(.AAAA)) {
        return .{ .AAAA = try parseIpv6(record.rdataText()) };
    }
    if (record.rrtype.eql(.NS)) {
        return .{ .NS = dns_name.Name.fromText(record.rdataText()) catch return Error.BadZoneRecord };
    }
    if (record.rrtype.eql(.CNAME)) {
        return .{ .CNAME = dns_name.Name.fromText(record.rdataText()) catch return Error.BadZoneRecord };
    }
    if (record.rrtype.eql(.SOA)) {
        return .{ .SOA = try parseSoa(record.rdataText()) };
    }
    if (record.rrtype.eql(.MX)) {
        return .{ .MX = try parseMx(record.rdataText()) };
    }
    if (record.rrtype.eql(.TXT)) {
        return .{ .TXT = try parseTxt(record.rdataText()) };
    }
    if (record.rrtype.eql(.SRV)) {
        return .{ .SRV = try parseSrv(record.rdataText()) };
    }
    if (record.rrtype.eql(.CAA)) {
        return .{ .CAA = try parseCaa(record.rdataText()) };
    }
    return Error.BadZoneRecord;
}

fn parseIpv4(text: []const u8) ![4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var out: [4]u8 = undefined;
    var index: usize = 0;
    while (parts.next()) |part| {
        if (index >= 4) return Error.BadAddress;
        out[index] = std.fmt.parseInt(u8, part, 10) catch return Error.BadAddress;
        index += 1;
    }
    if (index != 4) return Error.BadAddress;
    return out;
}

fn parseIpv6(text: []const u8) ![16]u8 {
    const addr = std.Io.net.Ip6Address.parse(text, 0) catch return Error.BadAddress;
    return addr.bytes;
}

fn parseMx(text: []const u8) !dns_rdata.Mx {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const preference = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const exchange = tokens.next() orelse return Error.BadZoneRecord;
    return .{
        .preference = preference,
        .exchange = dns_name.Name.fromText(exchange) catch return Error.BadZoneRecord,
    };
}

fn parseTxt(text: []const u8) !dns_rdata.Txt {
    const value = if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') text[1 .. text.len - 1] else text;
    if (value.len > 255) return Error.BadZoneRecord;
    var txt = dns_rdata.Txt{ .len = @intCast(value.len) };
    @memcpy(txt.data[0..value.len], value);
    return txt;
}

fn parseSrv(text: []const u8) !dns_rdata.Srv {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const priority = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const weight = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const port = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const target = tokens.next() orelse return Error.BadZoneRecord;
    return .{
        .priority = priority,
        .weight = weight,
        .port = port,
        .target = dns_name.Name.fromText(target) catch return Error.BadZoneRecord,
    };
}

fn parseCaa(text: []const u8) !dns_rdata.Caa {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const flags = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const tag = tokens.next() orelse return Error.BadZoneRecord;
    const value = tokens.rest();
    if (tag.len > 32 or value.len > 255) return Error.BadZoneRecord;
    var caa = dns_rdata.Caa{
        .flags = flags,
        .tag_len = @intCast(tag.len),
        .value_len = @intCast(value.len),
    };
    @memcpy(caa.tag[0..tag.len], tag);
    @memcpy(caa.value[0..value.len], value);
    return caa;
}

fn parseSoa(text: []const u8) !dns_rdata.Soa {
    var tokens = std.mem.tokenizeAny(u8, text, " \t\r\n");
    const mname = tokens.next() orelse return Error.BadZoneRecord;
    const rname = tokens.next() orelse return Error.BadZoneRecord;
    const serial = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const refresh = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const retry = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const expire = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    const minimum = std.fmt.parseInt(u32, tokens.next() orelse return Error.BadZoneRecord, 10) catch return Error.BadZoneRecord;
    return .{
        .mname = dns_name.Name.fromText(mname) catch return Error.BadZoneRecord,
        .rname = dns_name.Name.fromText(rname) catch return Error.BadZoneRecord,
        .serial = serial,
        .refresh = refresh,
        .retry = retry,
        .expire = expire,
        .minimum = minimum,
    };
}

test "authoritative response builder answers exact A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    const zone = try zone_index.Zone.fromZoneFile(zone_file);

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.header.qr);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &response.answers.items[0].rdata.A);

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(@as(u16, 0x1234), round_trip.header.id);
    try std.testing.expectEqual(@as(u16, 1), round_trip.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &round_trip.answers.items[0].rdata.A);
}

test "authoritative response builder returns CNAME and SOA-backed negatives" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    const zone = try zone_index.Zone.fromZoneFile(zone_file);

    const cname_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        5,    'a',  'l',  'i',  'a',  's',  4,    'h',  'o',  'm',  'e',  4,
        'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const cname_response = try buildResponse(cname_request, &zone);
    try std.testing.expectEqual(@as(u16, 1), cname_response.header.answer_count);
    try std.testing.expect(cname_response.answers.items[0].rrtype.eql(.CNAME));

    const missing_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x36, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'm',  'i',  's',  's',  'i',  'n',  'g',  4,    'h',  'o',  'm',
        'e',  4,    'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const missing_response = try buildResponse(missing_request, &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, missing_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), missing_response.header.authority_count);
}

test "authoritative response builder converts phase-one zone record types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.test.
        \\$TTL 3600
        \\@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 900 1209600 3600
        \\@ IN NS ns1.example.test.
        \\www IN AAAA 2001:db8::1
        \\mail IN MX 10 mail.example.test.
        \\txt IN TXT "hello world"
        \\sip IN SRV 10 20 8443 sip.example.test.
        \\@ IN CAA 0 issue letsencrypt.org
        \\
    );
    const zone = try zone_index.Zone.fromZoneFile(zone_file);

    const txt_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    't',  'x',  't',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        4,    't',  'e',  's',  't',  0,    0x00, 0x10, 0x00, 0x01,
    });
    const txt_response = try buildResponse(txt_request, &zone);
    try std.testing.expectEqualStrings("hello world", txt_response.answers.items[0].rdata.TXT.text());

    const aaaa_record = try toResourceRecord(zone.records.items[2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &aaaa_record.rdata.AAAA);
    const mx_record = try toResourceRecord(zone.records.items[3]);
    try std.testing.expectEqual(@as(u16, 10), mx_record.rdata.MX.preference);
    const srv_record = try toResourceRecord(zone.records.items[5]);
    try std.testing.expectEqual(@as(u16, 8443), srv_record.rdata.SRV.port);
    const caa_record = try toResourceRecord(zone.records.items[6]);
    try std.testing.expectEqualStrings("issue", caa_record.rdata.CAA.tagText());
}

test "rejects response section counts beyond the DNS wire limit" {
    var response = dns_message.Message{ .header = .{ .id = 0x1234 } };
    response.answers.len = @as(usize, std.math.maxInt(u16)) + 1;

    try std.testing.expectError(Error.TooManyRecords, setHeaderCounts(&response));
}
