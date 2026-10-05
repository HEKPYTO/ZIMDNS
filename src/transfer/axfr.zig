/// Contract: Builds RFC 5936 AXFR response sequences from an in-memory zone.
/// First message starts with the SOA, the last message ends with the SOA, and
/// every zone RR appears exactly once in between; each message stays within
/// the 64KiB TCP framing bound. IXFR queries fall back to a full transfer per
/// RFC 1995. Plain-DNS policy (refuse out-of-zone, refuse TSIG-chained
/// transfers) is encoded here as single error messages. ZIMDNS has no TLS
/// server, so there is no channel to label: xfr_tls.zig owns no bind entry
/// point and --serve-xfr refuses before opening a socket (transport/tls.zig).
/// Ownership: Returned messages own allocator-backed sections; the caller
/// deinits each message and frees the slice. Zone storage stays borrowed.
/// Errors: Non-transfer qtypes report NotTransferQuery so callers can run the
/// ordinary answer path; transfer shaping failures are typed.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_writer = @import("../dns/writer.zig");
const dns_types = @import("../dns/types.zig");
const response = @import("../auth/response.zig");
const zone_index = @import("../zone/index.zig");
const auth_runtime = @import("../auth/runtime.zig");
const dns_name = @import("../dns/name.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_record = @import("../dns/record.zig");
const dns_tsig = @import("../dns/tsig.zig");

pub const max_transfer_message_len: usize = 65535;
const trial_encode_threshold: usize = 60000;

pub const Error = error{
    NotTransferQuery,
    EncodeFailed,
};

fn isTransferType(qtype: dns_types.RecordType) bool {
    return qtype.eql(dns_types.RecordType.AXFR) or qtype.eql(dns_types.RecordType.IXFR);
}

fn selectZone(runtime: *const auth_runtime.Runtime, qname: []const u8) ?*const zone_index.Zone {
    var selected: ?*const zone_index.Zone = null;
    for (runtime.zones.items) |*zone| {
        if (!zone.contains(qname)) continue;
        if (selected == null or zone.originText().len > selected.?.originText().len) selected = zone;
    }
    return selected;
}

fn transferShell(allocator: std.mem.Allocator, query: dns_message.Message) !dns_message.Message {
    return .{
        .allocator = allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .authoritative = true,
            .recursion_desired = query.header.recursion_desired,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = query.question,
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
        .edns = null,
    };
}

fn syncCounts(message: *dns_message.Message) void {
    message.header.answer_count = @intCast(message.answers.len);
    message.header.authority_count = 0;
    message.header.additional_count = 0;
}

fn encodedLen(message: *const dns_message.Message, scratch: []u8) !usize {
    var writer = dns_writer.Writer.init(scratch);
    var mutable = message.*;
    mutable.encode(&writer) catch return Error.EncodeFailed;
    return writer.len();
}

/// Builds the full transfer sequence for AXFR/IXFR query bytes. Returns
/// NotTransferQuery for ordinary qtypes so the caller runs runtime.answer.
/// Out-of-zone queries yield one REFUSED message; TSIG-signed transfer queries
/// yield one REFUSED message because multi-message TSIG chaining is deferred.
pub fn buildTransferResponses(
    allocator: std.mem.Allocator,
    query_bytes: []const u8,
    runtime: *const auth_runtime.Runtime,
) ![]dns_message.Message {
    const final_record = dns_tsig.parseFinalAdditional(query_bytes) catch null;
    const signed = final_record != null;
    var query = if (final_record) |tsig_final|
        dns_message.Message.parseQueryWithoutTsig(allocator, query_bytes, tsig_final.record_start, tsig_final.record_end) catch return Error.NotTransferQuery
    else
        dns_message.Message.parseQuery(allocator, query_bytes) catch return Error.NotTransferQuery;
    errdefer query.deinit();

    const q = query.question orelse return Error.NotTransferQuery;
    if (!isTransferType(q.qtype)) return Error.NotTransferQuery;
    if (!q.qclass.eql(dns_types.Class.IN)) return Error.NotTransferQuery;

    var qname_buffer: [256]u8 = undefined;
    const qname = q.name.toText(&qname_buffer) catch return Error.NotTransferQuery;

    // TSIG-chained transfers are deferred: refuse instead of emitting an
    // unsigned sequence for a signed query (multi-message chaining lands
    // with the reviewed transfer-authentication work).
    if (signed) {
        defer query.deinit();
        const refused = try response.buildRefusedResponse(query);
        const out = try allocator.alloc(dns_message.Message, 1);
        out[0] = refused;
        return out;
    }

    const zone = selectZone(runtime, qname) orelse {
        defer query.deinit();
        const refused = try response.buildRefusedResponse(query);
        const out = try allocator.alloc(dns_message.Message, 1);
        out[0] = refused;
        return out;
    };
    const soa = zone.soa orelse {
        defer query.deinit();
        const refused = try response.buildRefusedResponse(query);
        const out = try allocator.alloc(dns_message.Message, 1);
        out[0] = refused;
        return out;
    };

    var messages = std.ArrayList(dns_message.Message).empty;
    errdefer {
        for (messages.items) |*message| message.deinit();
        messages.deinit(allocator);
    }
    // current is nullable so a message moved into messages is never freed twice.
    var current: ?dns_message.Message = try transferShell(allocator, query);
    errdefer if (current) |*message| message.deinit();
    const scratch = try allocator.alloc(u8, max_transfer_message_len);
    defer allocator.free(scratch);
    var estimate: usize = 0;

    // SOA first, then every non-SOA record in zone order, then SOA last.
    const soa_rr = try response.zoneRecordToResourceRecord(soa, null);
    try current.?.answers.append(soa_rr);
    estimate += 512;
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const record = zone.records.items[index];
        if (record.rrtype.eql(dns_types.RecordType.SOA)) continue;
        const rr = try response.zoneRecordToResourceRecord(record, null);
        try current.?.answers.append(rr);
        estimate += record.ownerText().len + 12 + 512;
        if (estimate >= trial_encode_threshold) {
            syncCounts(&current.?);
            if (try encodedLen(&current.?, scratch) > max_transfer_message_len) {
                // Move the overflowing RR to the next message.
                current.?.answers.len -= 1;
                syncCounts(&current.?);
                try messages.append(allocator, current.?);
                current = try transferShell(allocator, query);
                try current.?.answers.append(rr);
                estimate = record.ownerText().len + 12 + 512;
            } else {
                estimate = try encodedLen(&current.?, scratch);
            }
        }
    }
    try current.?.answers.append(soa_rr);
    syncCounts(&current.?);
    if (try encodedLen(&current.?, scratch) > max_transfer_message_len) {
        current.?.answers.len -= 1;
        syncCounts(&current.?);
        try messages.append(allocator, current.?);
        current = try transferShell(allocator, query);
        try current.?.answers.append(soa_rr);
        try current.?.answers.append(soa_rr);
        syncCounts(&current.?);
    }
    try messages.append(allocator, current.?);
    current = null;
    query.deinit();

    return messages.toOwnedSlice(allocator);
}

test "AXFR sequence starts and ends with SOA and covers every record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\www IN A 192.168.1.2
        \\
    );
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
        0xfc, 0x00, 0x01,
    };
    const messages = try buildTransferResponses(arena.allocator(), &query, &runtime);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    const answers = messages[0].answers.slice();
    try std.testing.expectEqual(@as(usize, 5), answers.len);
    try std.testing.expect(answers[0].rrtype.eql(dns_types.RecordType.SOA));
    try std.testing.expect(answers[answers.len - 1].rrtype.eql(dns_types.RecordType.SOA));
    var saw_ns = false;
    var saw_dns = false;
    var saw_www = false;
    for (answers) |answer| {
        if (answer.rrtype.eql(dns_types.RecordType.NS)) saw_ns = true;
        if (answer.rrtype.eql(dns_types.RecordType.A)) {
            if (std.mem.eql(u8, &answer.rdata.A, &.{ 192, 168, 1, 1 })) saw_dns = true;
            if (std.mem.eql(u8, &answer.rdata.A, &.{ 192, 168, 1, 2 })) saw_www = true;
        }
    }
    try std.testing.expect(saw_ns and saw_dns and saw_www);

    var scratch: [max_transfer_message_len]u8 = undefined;
    try std.testing.expect((try encodedLen(&messages[0], &scratch)) <= max_transfer_message_len);
}

test "IXFR falls back to a full transfer and ordinary qtypes decline" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    defer runtime.deinit();

    const ixfr_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
        0xfb, 0x00, 0x01,
    };
    const messages = try buildTransferResponses(arena.allocator(), &ixfr_query, &runtime);
    try std.testing.expect(messages.len >= 1);
    try std.testing.expect(messages[0].answers.slice()[0].rrtype.eql(dns_types.RecordType.SOA));

    const a_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
        0x01, 0x00, 0x01,
    };
    try std.testing.expectError(Error.NotTransferQuery, buildTransferResponses(arena.allocator(), &a_query, &runtime));
}

test "out-of-zone AXFR yields a single REFUSED message" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'n',  'e',  't',
        0,    0x00, 0xfc, 0x00, 0x01,
    };
    const messages = try buildTransferResponses(arena.allocator(), &query, &runtime);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, messages[0].header.rcode);
    try std.testing.expectEqual(@as(usize, 0), messages[0].answers.len);
}

test "TSIG-signed AXFR yields a single REFUSED message" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    defer runtime.deinit();

    // A final TSIG additional record makes the transfer query signed; only the
    // structure matters here, the refusal never reaches MAC verification.
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try writer.writeBytes(&.{ 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(0x00fc);
    try writer.writeU16(1);
    const algorithm = try dns_name.Name.fromText("hmac-sha256.");
    const owner = try dns_name.Name.fromText("key.");
    var zeros: [32]u8 = @splat(0);
    try (dns_record.ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = try dns_rdata.Tsig.init(algorithm, 0, 300, &zeros, 0x1234, 0, &.{}) },
    }).encode(&writer);

    const messages = try buildTransferResponses(arena.allocator(), writer.written(), &runtime);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, messages[0].header.rcode);
    try std.testing.expectEqual(@as(usize, 0), messages[0].answers.len);
}
