/// Contract: Builds authoritative DNS responses from parsed requests and one zone.
/// Ownership: Inputs and zone are borrowed; returned Message owns allocator-backed sections and requires deinit.
/// Errors: Response and wire failures are typed; network and file I/O are outside this module.
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

pub const CLASSIC_UDP_MESSAGE_SIZE: usize = 512;
pub const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

pub const Error = error{
    MissingQuestion,
    BadQName,
    BadZoneRecord,
    TooManyRecords,
    BadResponse,
    ResponseTooLarge,
};

pub fn truncateClassicUdpResponse(response_bytes: []const u8, output: []u8) Error![]const u8 {
    const payload_limit = responsePayloadLimit(response_bytes);
    if (response_bytes.len <= payload_limit) {
        if (response_bytes.len > output.len) return Error.ResponseTooLarge;
        @memcpy(output[0..response_bytes.len], response_bytes);
        return output[0..response_bytes.len];
    }
    if (response_bytes.len < 12 or output.len < 12) return Error.BadResponse;

    var reader = @import("../dns/reader.zig").Reader.init(response_bytes);
    const parsed_header = header.Header.parse(&reader) catch return Error.BadResponse;
    if (parsed_header.question_count > 1) return Error.BadResponse;

    var question_end: usize = 12;
    if (parsed_header.question_count == 1) {
        const parsed_question = question.Question.parse(response_bytes, question_end) catch return Error.BadResponse;
        question_end = parsed_question.next_offset;
    }
    if (question_end > output.len) return Error.ResponseTooLarge;

    @memcpy(output[0..question_end], response_bytes[0..question_end]);
    var flags = std.mem.readInt(u16, output[2..4], .big);
    flags |= 0x0200;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    if (findEdnsOpt(response_bytes)) |opt| {
        std.mem.writeInt(u16, output[10..12], 1, .big);
        opt.encode(&writer) catch return Error.ResponseTooLarge;
    } else {
        std.mem.writeInt(u16, output[10..12], 0, .big);
    }
    return writer.written();
}

/// Truncate a signed response while retaining its final TSIG RR.
/// The caller must recompute the response MAC after this wire-level rewrite.
pub fn truncateSignedClassicUdpResponse(response_bytes: []const u8, output: []u8) Error![]const u8 {
    const payload_limit = responsePayloadLimit(response_bytes);
    if (response_bytes.len <= payload_limit) {
        if (response_bytes.len > output.len) return Error.ResponseTooLarge;
        @memcpy(output[0..response_bytes.len], response_bytes);
        return output[0..response_bytes.len];
    }
    if (response_bytes.len < 12 or output.len < 12) return Error.BadResponse;

    const final = (@import("../dns/tsig.zig").parseFinalAdditional(response_bytes) catch return Error.BadResponse) orelse return Error.BadResponse;
    var reader = @import("../dns/reader.zig").Reader.init(response_bytes);
    const parsed_header = header.Header.parse(&reader) catch return Error.BadResponse;
    if (parsed_header.question_count > 1) return Error.BadResponse;

    var question_end: usize = 12;
    if (parsed_header.question_count == 1) {
        const parsed_question = question.Question.parse(response_bytes, question_end) catch return Error.BadResponse;
        question_end = parsed_question.next_offset;
    }
    if (question_end > output.len) return Error.ResponseTooLarge;

    @memcpy(output[0..question_end], response_bytes[0..question_end]);
    var flags = std.mem.readInt(u16, output[2..4], .big);
    flags = (flags | 0x0200) & 0xfff0;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);

    std.mem.writeInt(u16, output[10..12], 1, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    writer.writeBytes(response_bytes[final.record_start..final.record_end]) catch return Error.ResponseTooLarge;
    if (writer.len() > payload_limit) return Error.ResponseTooLarge;
    return writer.written();
}

fn responsePayloadLimit(response_bytes: []const u8) usize {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), response_bytes) catch return CLASSIC_UDP_MESSAGE_SIZE;
    if (parsed.edns) |edns| return @max(CLASSIC_UDP_MESSAGE_SIZE, @as(usize, edns.udp_payload_size));
    return CLASSIC_UDP_MESSAGE_SIZE;
}

fn findEdnsOpt(response_bytes: []const u8) ?dns_record.ResourceRecord {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), response_bytes) catch return null;
    for (parsed.additionals.slice()) |record| {
        if (record.rrtype.eql(.OPT)) return record;
    }
    return null;
}

pub fn buildResponse(request: dns_message.Message, zone: *const zone_index.Zone) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    if (request.header.opcode != .query) return buildNotImplementedResponse(request);
    if (!q.qclass.eql(dns_types.Class.IN)) return buildEmptyResponse(request, q, .notimp);
    if (request.edns) |edns| {
        if (edns.version != dns_message.EDNS_VERSION) {
            return buildBadVersionResponse(request, q);
        }
    }
    var qname_text_buffer: [256]u8 = undefined;
    const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQName;
    var lookup = zone.lookup(request.allocator, qname_text, q.qtype);
    defer lookup.deinit(request.allocator);

    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .authoritative = lookup.kind != .not_authoritative and lookup.kind != .referral and lookup.kind != .servfail,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .rcode = switch (lookup.kind) {
                .nxdomain => .nxdomain,
                .yxdomain => .yxdomain,
                .servfail => .servfail,
                .not_authoritative => .refused,
                else => .no_error,
            },
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (request.edns) |edns| .{
            .udp_payload_size = negotiateEdnsPayload(edns.udp_payload_size),
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer response.deinit();

    if (response.edns != null) try appendOpt(&response);

    switch (lookup.kind) {
        .answer, .cname, .dname, .yxdomain => {
            var index: usize = 0;
            while (index < lookup.records.len) : (index += 1) {
                try response.answers.append(try toResourceRecord(lookup.records.items[index], lookup.answer_owner));
            }
            if (lookup.synthesized_cname) |synthetic| {
                try response.answers.append(.{
                    .owner = synthetic.owner,
                    .rrtype = .CNAME,
                    .class = dns_types.Class.IN,
                    .ttl = synthetic.ttl,
                    .rdata = .{ .CNAME = synthetic.target },
                });
            }
        },
        .referral => {
            var index: usize = 0;
            while (index < lookup.authorities.len) : (index += 1) {
                try response.authorities.append(try toResourceRecord(lookup.authorities.items[index], null));
            }
            index = 0;
            while (index < lookup.additionals.len) : (index += 1) {
                try response.additionals.append(try toResourceRecord(lookup.additionals.items[index], null));
            }
        },
        .nodata, .nxdomain => {
            if (lookup.soa) |soa| try response.authorities.append(try toNegativeSoa(soa));
        },
        .servfail, .not_authoritative => {},
    }

    try setHeaderCounts(&response);
    return response;
}

pub fn buildRefusedResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    return buildEmptyResponse(request, q, if (q.qclass.eql(dns_types.Class.IN)) .refused else .notimp);
}

pub fn buildFormerrResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    var response = try buildEmptyResponse(request, q, .formerr);
    response.edns = null;
    response.additionals.len = 0;
    response.header.additional_count = 0;
    return response;
}

pub fn buildNotImplementedResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    return buildEmptyResponse(request, q, .notimp);
}

fn buildEmptyResponse(request: dns_message.Message, q: question.Question, rcode: header.Rcode) !dns_message.Message {
    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .opcode = request.header.opcode,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .rcode = rcode,
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (request.edns) |edns| .{
            .udp_payload_size = negotiateEdnsPayload(edns.udp_payload_size),
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer response.deinit();
    if (response.edns != null) try appendOpt(&response);
    try setHeaderCounts(&response);
    return response;
}

pub fn negotiateEdnsPayload(advertised: u16) u16 {
    if (advertised < dns_message.CLASSIC_UDP_PAYLOAD_SIZE) return dns_message.CLASSIC_UDP_PAYLOAD_SIZE;
    return @min(advertised, DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
}

pub fn buildBadVersionResponse(request: dns_message.Message, q: question.Question) !dns_message.Message {
    const request_edns = request.edns orelse return Error.BadResponse;
    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = .{
            .udp_payload_size = negotiateEdnsPayload(request_edns.udp_payload_size),
            .extended_rcode = 1,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = request_edns.dnssec_ok,
        },
    };
    errdefer response.deinit();
    try appendOpt(&response);
    try setHeaderCounts(&response);
    return response;
}

fn appendOpt(message: *dns_message.Message) !void {
    const edns = message.edns orelse return;
    try message.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(edns.udp_payload_size),
        .ttl = (@as(u32, edns.extended_rcode) << 24) |
            (@as(u32, edns.version) << 16) |
            (if (edns.dnssec_ok) @as(u32, 0x8000) else 0),
        .rdata = .{ .OPT = .{} },
    });
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

fn toResourceRecord(record: zone_parser.ZoneRecord, owner_override: ?[]const u8) !dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(owner_override orelse record.ownerText()) catch return Error.BadZoneRecord,
        .rrtype = record.rrtype,
        .class = dns_types.Class.IN,
        .ttl = record.ttl,
        .rdata = try parseZoneRData(record),
    };
}

fn toNegativeSoa(record: zone_parser.ZoneRecord) !dns_record.ResourceRecord {
    var rr = try toResourceRecord(record, null);
    if (rr.rdata == .SOA) rr.ttl = @min(rr.ttl, rr.rdata.SOA.minimum);
    return rr;
}

fn parseZoneRData(record: zone_parser.ZoneRecord) !dns_rdata.RData {
    return zone_parser.parseRData(record.rrtype, record.rdataText()) catch Error.BadZoneRecord;
}

test "authoritative response builder answers exact A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

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

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const cname_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        5,    'a',  'l',  'i',  'a',  's',  4,    'h',  'o',  'm',  'e',  4,
        'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const cname_response = try buildResponse(cname_request, &zone);
    try std.testing.expectEqual(@as(u16, 2), cname_response.header.answer_count);
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

test "non-IN queries return NOTIMP with the question and EDNS OPT preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "dns.home.arpa.", .A);
    request.question.?.qclass = dns_types.Class.fromCode(3);
    request.edns = .{
        .udp_payload_size = 1232,
        .extended_rcode = 0,
        .version = 0,
        .dnssec_ok = false,
    };
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expectEqual(header.Rcode.notimp, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
    try std.testing.expectEqual(@as(u16, 1), response.header.additional_count);
    try std.testing.expectEqual(dns_types.Class.fromCode(3), response.question.?.qclass);
    try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
}

test "authoritative response builder converts phase-one zone record types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
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
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const txt_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    't',  'x',  't',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        4,    't',  'e',  's',  't',  0,    0x00, 0x10, 0x00, 0x01,
    });
    const txt_response = try buildResponse(txt_request, &zone);
    try std.testing.expectEqualStrings("hello world", txt_response.answers.items[0].rdata.TXT.text());

    const aaaa_record = try toResourceRecord(zone.records.items[2], null);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &aaaa_record.rdata.AAAA);
    const mx_record = try toResourceRecord(zone.records.items[3], null);
    try std.testing.expectEqual(@as(u16, 10), mx_record.rdata.MX.preference);
    const srv_record = try toResourceRecord(zone.records.items[5], null);
    try std.testing.expectEqual(@as(u16, 8443), srv_record.rdata.SRV.port);
    const caa_record = try toResourceRecord(zone.records.items[6], null);
    try std.testing.expectEqualStrings("issue", caa_record.rdata.CAA.tagText());
}

test "authoritative response builder converts PTR zone records" {
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\reverse IN PTR target
        \\
    );
    defer zone_file.deinit();

    const ptr_record = try toResourceRecord(zone_file.records.items[2], null);
    try std.testing.expect(ptr_record.rrtype.eql(.PTR));
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.", try ptr_record.rdata.PTR.toText(&target));
}

test "rejects response section counts beyond the DNS wire limit" {
    var response = dns_message.Message{ .header = .{ .id = 0x1234 } };
    response.answers.len = @as(usize, std.math.maxInt(u16)) + 1;

    try std.testing.expectError(Error.TooManyRecords, setHeaderCounts(&response));
}

fn testQuery(allocator: std.mem.Allocator, name_text: []const u8, qtype: dns_types.RecordType) !dns_message.Message {
    return .{
        .allocator = allocator,
        .header = .{ .id = 0x1234 },
        .question = .{
            .name = try dns_name.Name.fromText(name_text),
            .qtype = qtype,
            .qclass = dns_types.Class.IN,
        },
    };
}

test "authoritative response rewrites wildcard owners and preserves negative SOA TTL" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\*.example. IN A 192.0.2.3
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const wildcard = try buildResponse(try testQuery(arena.allocator(), "other.example.", .A), &zone);
    try std.testing.expectEqual(@as(u16, 1), wildcard.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, &wildcard.answers.items[0].rdata.A);
    var wildcard_owner: [256]u8 = undefined;
    try std.testing.expectEqualStrings("other.example.", try wildcard.answers.items[0].owner.toText(&wildcard_owner));

    const nodata = try buildResponse(try testQuery(arena.allocator(), "www.example.", .AAAA), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, nodata.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), nodata.header.authority_count);
    try std.testing.expectEqual(@as(u32, 300), nodata.authorities.items[0].ttl);
}

test "authoritative response emits referral glue and uncompressed DNAME CNAME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.external.example.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.external.example. IN A 192.0.2.11
        \\legacy IN DNAME target.example.
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const referral = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    try std.testing.expect(!referral.header.authoritative);
    try std.testing.expectEqual(@as(u16, 2), referral.header.authority_count);
    try std.testing.expectEqual(@as(u16, 1), referral.header.additional_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, &referral.additionals.items[0].rdata.A);

    const dname = try buildResponse(try testQuery(arena.allocator(), "www.legacy.example.", .A), &zone);
    try std.testing.expectEqual(@as(u16, 2), dname.header.answer_count);
    try std.testing.expectEqual(dns_types.RecordType.DNAME, dname.answers.items[0].rrtype);
    try std.testing.expectEqual(dns_types.RecordType.CNAME, dname.answers.items[1].rrtype);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.target.example.", try dname.answers.items[1].rdata.CNAME.toText(&target));
}

test "unsupported EDNS version returns BADVERS" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.edns != null);
    try std.testing.expectEqual(@as(u8, 1), response.edns.?.extended_rcode);
    var output: [256]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&output);
    try response.encode(&writer);
    const parsed = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(@as(u8, 1), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
}

test "EDNS payload negotiation is bounded and preserves the classic floor" {
    try std.testing.expectEqual(@as(u16, 512), negotiateEdnsPayload(0));
    try std.testing.expectEqual(@as(u16, 512), negotiateEdnsPayload(300));
    try std.testing.expectEqual(@as(u16, 600), negotiateEdnsPayload(600));
    try std.testing.expectEqual(@as(u16, 1232), negotiateEdnsPayload(4096));
}

test "EDNS truncation uses negotiated payload and retains OPT" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x1234, .qr = true, .answer_count = 40 },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
        .edns = .{ .udp_payload_size = 600, .extended_rcode = 0, .version = 0, .dnssec_ok = false },
    };
    defer message.deinit();
    const owner = try dns_name.Name.fromText("many.example.");
    var index: usize = 0;
    while (index < 40) : (index += 1) {
        try message.answers.append(.{
            .owner = owner,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, @intCast(index + 1) } },
        });
    }
    try appendOpt(&message);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > 600);

    var output: [1232]u8 = undefined;
    const truncated = try truncateClassicUdpResponse(writer.written(), &output);
    try std.testing.expect(truncated.len <= 600);
    const parsed = try dns_message.Message.parse(arena.allocator(), truncated);
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), parsed.additionals.len);
    try std.testing.expectEqual(@as(u16, 600), parsed.edns.?.udp_payload_size);
}

test "authoritative response ignores unknown EDNS options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xea, 0x60, 0x00, 0x03, 0x01, 0x02,
        0x03,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.edns != null);
    try std.testing.expectEqual(@as(u16, 1232), response.edns.?.udp_payload_size);
    try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
    try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
}

test "authoritative response emits bare OPT for Padding and ECS /0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const padding_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0c, 0x00, 0x03, 0xaa, 0xbb,
        0xcc,
    };
    const ecs_zero_query = [_]u8{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01,
        0x00, 0x00,
    };

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    for ([_][]const u8{ &padding_query, &ecs_zero_query }) |wire| {
        const request = try dns_message.Message.parseQuery(arena.allocator(), wire);
        const response = try buildResponse(request, &zone);
        try std.testing.expect(response.edns != null);
        try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
        try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
    }
}
