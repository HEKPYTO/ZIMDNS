/// Contract: Minimal RFC 5936 AXFR, RFC 1995 IXFR, and RFC 1996 NOTIFY serving
/// logic over the project's bounded TCP profile.
/// Ownership: Built messages own allocator-backed sections; call Message.deinit
/// on each. Input zones, queries, and key bytes are borrowed.
/// Errors: Non-authoritative zones, missing SOA data, oversized frames, and
/// over-long sequences are typed; transport I/O stays with platform listeners.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_writer = @import("../dns/writer.zig");
const dns_name = @import("../dns/name.zig");
const dns_types = @import("../dns/types.zig");
const dns_record = @import("../dns/record.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_tsig = @import("../dns/tsig.zig");
const header_mod = @import("../dns/header.zig");
const zone_parser = @import("parser.zig");
const zone_index = @import("index.zig");
const journal_mod = @import("journal.zig");

/// Reuses the platform TCP profile bounds without importing the listener:
/// one DNS message per length-prefixed frame, at most 65535 bytes each.
pub const tcp_max_frame_size: usize = 65535;
/// Reuses the TCP connection frame budget: one transfer query produces at most
/// this many response frames before the connection-level cap applies.
pub const max_messages_per_transfer: usize = 16;
/// Default answer-section chunking for transfer messages. Tests override this
/// to force multi-message sequences from small zones.
pub const default_records_per_message: usize = 64;
pub const tsig_fudge: u16 = 300;

pub const Error = error{
    MissingSoa,
    BadZoneRecord,
    NotAuthoritative,
    ResponseTooLarge,
    TooManyMessages,
    BadTransferQuery,
};

pub const TransferKind = enum {
    none,
    axfr,
    ixfr,
};

/// Classifies one question type for the IN class only. Transfers are never
/// served for other classes.
pub fn classify(qtype: dns_types.RecordType, qclass: dns_types.Class) TransferKind {
    if (!qclass.eql(dns_types.Class.IN)) return .none;
    if (qtype.eql(dns_types.RecordType.AXFR)) return .axfr;
    if (qtype.eql(dns_types.RecordType.IXFR)) return .ixfr;
    return .none;
}

/// Classifies an already-parsed request message. NOTIFY is reported through
/// isNotifyMessage instead; this covers opcode query transfers only.
pub fn classifyMessage(message: *const dns_message.Message) TransferKind {
    if (message.header.qr) return .none;
    if (message.header.opcode != .query) return .none;
    const question = message.question orelse return .none;
    return classify(question.qtype, question.qclass);
}

/// Reports whether a parsed message is an RFC 1996 NOTIFY query: opcode
/// notify with QR clear and exactly one question. The optional answer-section
/// SOA is accepted and ignored for the response decision.
pub fn isNotifyMessage(message: *const dns_message.Message) bool {
    if (message.header.qr) return false;
    if (message.header.opcode != .notify) return false;
    if (message.header.question_count != 1) return false;
    if (message.question == null) return false;
    return true;
}

/// Allocation-free peek at raw request bytes for the TCP dispatch path.
/// True only for QR-clear opcode-query messages with one question whose type
/// is AXFR or IXFR. NOTIFY and ordinary queries return false.
pub fn peekIsTransferRequest(bytes: []const u8) bool {
    if (bytes.len < 12) return false;
    if (bytes[2] & 0x80 != 0) return false;
    if ((bytes[2] >> 1) & 0x0f != 0) return false;
    if (std.mem.readInt(u16, bytes[4..6], .big) != 1) return false;
    var offset: usize = 12;
    while (true) {
        if (offset >= bytes.len) return false;
        const label_len = bytes[offset];
        if (label_len == 0) {
            offset += 1;
            break;
        }
        if (label_len & 0xc0 != 0) return false;
        if (label_len > 63) return false;
        offset += 1 + @as(usize, label_len);
    }
    if (bytes.len -| offset < 4) return false;
    const qtype = std.mem.readInt(u16, bytes[offset..][0..2], .big);
    return qtype == dns_types.RecordType.AXFR.code() or qtype == dns_types.RecordType.IXFR.code();
}

/// Removes the validated final TSIG record from raw request bytes so the
/// remaining message parses under transfer rules. Mirrors the header/ARCOUNT
/// handling of Message.parseQueryWithoutTsig without its section limits.
pub fn stripTsigRecord(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    record_start: usize,
    record_end: usize,
) error{ BadBounds, OutOfMemory }![]u8 {
    if (bytes.len < 12 or record_start < 12 or record_start > record_end or record_end > bytes.len or
        record_end - record_start > bytes.len - 12) return error.BadBounds;
    const additional_count = std.mem.readInt(u16, bytes[10..12], .big);
    if (additional_count == 0) return error.BadBounds;
    const stripped = try allocator.alloc(u8, bytes.len - (record_end - record_start));
    @memcpy(stripped[0..record_start], bytes[0..record_start]);
    std.mem.writeInt(u16, stripped[10..12], additional_count - 1, .big);
    @memcpy(stripped[record_start..], bytes[record_end..]);
    return stripped;
}

/// Validates a fully parsed transfer request after TSIG-stripped parsing.
/// Ordinary strict query parsing rejects IXFR authority SOAs and NOTIFY
/// answer SOAs, so transfer requests take this path instead.
pub fn validateTransferRequest(message: *const dns_message.Message) Error!TransferKind {
    if (message.header.qr) return Error.BadTransferQuery;
    if (message.header.opcode != .query) return Error.BadTransferQuery;
    const question = message.question orelse return Error.BadTransferQuery;
    const kind = classify(question.qtype, question.qclass);
    if (kind == .none) return Error.BadTransferQuery;
    if (message.header.answer_count != 0) return Error.BadTransferQuery;
    if (message.header.authority_count > 1) return Error.BadTransferQuery;
    if (message.header.additional_count > 1) return Error.BadTransferQuery;
    return kind;
}

pub const IxfrDecision = enum {
    /// Client serial equals the server serial: answer with one SOA record.
    up_to_date,
    /// A recorded delta chain connects the client serial to the current
    /// serial: answer with the incremental sequence.
    incremental,
    /// No usable delta: answer the IXFR with a full AXFR sequence.
    fallback_axfr,
};

/// Picks the RFC 1995 response shape for a server at `server_serial` asked
/// from `client_serial` (null when the query carries no authority SOA).
/// `deltas` is the zone's serial transition log; null means no delta history
/// is available and any older client falls back to AXFR.
pub fn decideIxfr(
    server_serial: u32,
    client_serial: ?u32,
    deltas: ?*const journal_mod.DeltaLog,
) IxfrDecision {
    const client = client_serial orelse return .fallback_axfr;
    switch (journal_mod.compareSerial(server_serial, client)) {
        .equal => return .up_to_date,
        .newer => {
            const log = deltas orelse return .fallback_axfr;
            return if (log.canServeIncremental(client, server_serial)) .incremental else .fallback_axfr;
        },
        .older, .undefined => return .fallback_axfr,
    }
}

/// Extracts the client's serial from an IXFR query's authority section: the
/// SOA record owned by the question name. Returns null when absent.
pub fn clientSerialFromMessage(message: *const dns_message.Message) ?u32 {
    const question = message.question orelse return null;
    var qname_text: [256]u8 = undefined;
    const qname = question.name.toText(&qname_text) catch return null;
    for (message.authorities.slice()) |record| {
        if (!record.rrtype.eql(dns_types.RecordType.SOA)) continue;
        var owner_text: [256]u8 = undefined;
        const owner = record.owner.toText(&owner_text) catch continue;
        if (!std.ascii.eqlIgnoreCase(owner, qname)) continue;
        if (record.rdata != .SOA) continue;
        return record.rdata.SOA.serial;
    }
    return null;
}

/// Orders zone records for an AXFR sequence per RFC 5936: the apex SOA first,
/// every other record in zone order, then the apex SOA last to close the
/// transfer. Returns an owned slice of borrowed records; the caller frees the
/// slice itself.
pub fn orderedAxfrRecords(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
) Error![]zone_parser.ZoneRecord {
    const apex_soa = zone.soa orelse return Error.MissingSoa;
    const total = zone.records.len + 1;
    var ordered = allocator.alloc(zone_parser.ZoneRecord, total) catch return Error.BadTransferQuery;
    errdefer allocator.free(ordered);
    ordered[0] = apex_soa;
    var index: usize = 0;
    var out: usize = 1;
    while (index < zone.records.len) : (index += 1) {
        const record = zone.records.items[index];
        if (record.rrtype.eql(dns_types.RecordType.SOA)) continue;
        ordered[out] = record;
        out += 1;
    }
    ordered[out] = apex_soa;
    return allocator.realloc(ordered, out + 1) catch return Error.BadTransferQuery;
}

fn toResourceRecord(record: zone_parser.ZoneRecord) Error!dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(record.ownerText()) catch return Error.BadZoneRecord,
        .rrtype = record.rrtype,
        .class = dns_types.Class.IN,
        .ttl = record.ttl,
        .rdata = zone_parser.parseRData(record.rrtype, record.rdataText()) catch return Error.BadZoneRecord,
    };
}

fn mirrorEdns(request: *const dns_message.Message) ?dns_message.EdnsState {
    const edns = request.edns orelse return null;
    return .{
        .udp_payload_size = @min(edns.udp_payload_size, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE),
        .extended_rcode = 0,
        .version = dns_message.EDNS_VERSION,
        .dnssec_ok = edns.dnssec_ok,
    };
}

fn appendOpt(message: *dns_message.Message) !void {
    const edns = message.edns orelse return;
    message.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(edns.udp_payload_size),
        .ttl = (@as(u32, edns.extended_rcode) << 24) |
            (@as(u32, edns.version) << 16) |
            (if (edns.dnssec_ok) @as(u32, 0x8000) else 0),
        .rdata = .{ .OPT = .{} },
    }) catch return Error.BadTransferQuery;
}

fn setHeaderCounts(message: *dns_message.Message) Error!void {
    const max_count = @as(usize, std.math.maxInt(u16));
    if (message.answers.len > max_count or message.authorities.len > max_count or
        message.additionals.len > max_count) return Error.BadTransferQuery;
    message.header.answer_count = @intCast(message.answers.len);
    message.header.authority_count = @intCast(message.authorities.len);
    message.header.additional_count = @intCast(message.additionals.len);
}

fn baseTransferMessage(
    allocator: std.mem.Allocator,
    request: *const dns_message.Message,
) Error!dns_message.Message {
    const question = request.question orelse return Error.BadTransferQuery;
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .opcode = request.header.opcode,
            .authoritative = true,
            .recursion_desired = request.header.recursion_desired,
            .checking_disabled = request.header.checking_disabled,
            .recursion_available = false,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = question,
        .answers = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .authorities = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .additionals = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .edns = mirrorEdns(request),
    };
    errdefer message.deinit();
    appendOpt(&message) catch return Error.BadTransferQuery;
    return message;
}

/// Builds the AXFR answer sequence for `zone` in chunks of at most
/// `records_per_message` answer records. Every message echoes the question so
/// each frame parses standalone; the first answer is the apex SOA and the
/// final answer of the last message is the same SOA. Caller owns the returned
/// messages and must deinit each.
pub fn buildAxfrMessages(
    allocator: std.mem.Allocator,
    request: *const dns_message.Message,
    zone: *const zone_index.Zone,
    records_per_message: usize,
) Error![]dns_message.Message {
    const per_message = @max(@as(usize, 1), records_per_message);
    const ordered = try orderedAxfrRecords(allocator, zone);
    defer allocator.free(ordered);
    const count = (ordered.len + per_message - 1) / per_message;
    if (count > max_messages_per_transfer) return Error.TooManyMessages;
    var messages = allocator.alloc(dns_message.Message, count) catch return Error.BadTransferQuery;
    // Only initialized slots own sections: later slots stay undefined until
    // their message is stored, so cleanup must not touch them.
    var initialized: usize = 0;
    errdefer {
        for (messages[0..initialized]) |*message| message.deinit();
        allocator.free(messages);
    }
    var index: usize = 0;
    while (index < count) : (index += 1) {
        var message = try baseTransferMessage(allocator, request);
        errdefer message.deinit();
        const start = index * per_message;
        const end = @min(start + per_message, ordered.len);
        for (ordered[start..end]) |record| {
            const converted = toResourceRecord(record) catch return Error.BadTransferQuery;
            message.answers.append(converted) catch return Error.BadTransferQuery;
        }
        try setHeaderCounts(&message);
        messages[index] = message;
        initialized = index + 1;
    }
    return messages;
}

/// Builds the single-message RFC 1995 up-to-date response: one answer holding
/// the current apex SOA.
pub fn buildIxfrUpToDateMessage(
    allocator: std.mem.Allocator,
    request: *const dns_message.Message,
    zone: *const zone_index.Zone,
) Error!dns_message.Message {
    const apex_soa = zone.soa orelse return Error.MissingSoa;
    var message = try baseTransferMessage(allocator, request);
    errdefer message.deinit();
    const converted = toResourceRecord(apex_soa) catch return Error.BadTransferQuery;
    message.answers.append(converted) catch return Error.BadTransferQuery;
    try setHeaderCounts(&message);
    return message;
}

/// Builds a coarse-grained RFC 1995 incremental sequence for a client at
/// `client_serial`: current SOA, the superseded SOA marking the start of the
/// deleted section, every current non-SOA record as the added section, then
/// the current SOA closing the sequence. Position conveys delete versus add
/// per RFC 1995 section 3; per-record deltas are not tracked by this profile.
pub fn buildIxfrIncrementalMessages(
    allocator: std.mem.Allocator,
    request: *const dns_message.Message,
    zone: *const zone_index.Zone,
    client_serial: u32,
) Error!dns_message.Message {
    const apex_soa = zone.soa orelse return Error.MissingSoa;
    var message = try baseTransferMessage(allocator, request);
    errdefer message.deinit();
    const current_soa = toResourceRecord(apex_soa) catch return Error.BadTransferQuery;
    message.answers.append(current_soa) catch return Error.BadTransferQuery;
    const current_rdata = zone_parser.parseRData(.SOA, apex_soa.rdataText()) catch return Error.BadZoneRecord;
    var old_soa_value = current_rdata.SOA;
    old_soa_value.serial = client_serial;
    message.answers.append(.{
        .owner = dns_name.Name.fromText(apex_soa.ownerText()) catch return Error.BadZoneRecord,
        .rrtype = .SOA,
        .class = dns_types.Class.IN,
        .ttl = apex_soa.ttl,
        .rdata = .{ .SOA = old_soa_value },
    }) catch return Error.BadTransferQuery;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(dns_types.RecordType.SOA)) continue;
        const converted = toResourceRecord(record) catch return Error.BadTransferQuery;
        message.answers.append(converted) catch return Error.BadTransferQuery;
    }
    const closing_soa = toResourceRecord(apex_soa) catch return Error.BadTransferQuery;
    message.answers.append(closing_soa) catch return Error.BadTransferQuery;
    try setHeaderCounts(&message);
    return message;
}

/// Builds the RFC 1996 NOTIFY response: QR set with the notify opcode, the
/// echoed question, and NOERROR. The optional query SOA needs no reply data.
pub fn buildNotifyResponse(
    allocator: std.mem.Allocator,
    request: *const dns_message.Message,
) Error!dns_message.Message {
    if (!isNotifyMessage(request)) return Error.BadTransferQuery;
    const question = request.question orelse return Error.BadTransferQuery;
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .opcode = .notify,
            .authoritative = true,
            .recursion_desired = request.header.recursion_desired,
            .checking_disabled = request.header.checking_disabled,
            .recursion_available = false,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = question,
        .answers = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .authorities = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .additionals = dns_message.RecordSection.init(allocator, 0) catch return Error.BadTransferQuery,
        .edns = mirrorEdns(request),
    };
    errdefer message.deinit();
    appendOpt(&message) catch return Error.BadTransferQuery;
    try setHeaderCounts(&message);
    return message;
}

/// Encodes transfer messages into one length-prefixed TCP blob: each message
/// gets its two-octet big-endian frame length. Enforces the bounded TCP
/// profile by rejecting oversized frames and over-long sequences.
pub fn encodeFramed(
    allocator: std.mem.Allocator,
    messages: []const dns_message.Message,
) Error![]u8 {
    if (messages.len == 0 or messages.len > max_messages_per_transfer) return Error.TooManyMessages;
    var blob: std.ArrayList(u8) = .empty;
    errdefer blob.deinit(allocator);
    var frame: [tcp_max_frame_size]u8 = undefined;
    for (messages) |message| {
        var writer = dns_writer.Writer.init(&frame);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        if (writer.len() == 0 or writer.len() > tcp_max_frame_size) return Error.ResponseTooLarge;
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(writer.len()), .big);
        blob.appendSlice(allocator, &prefix) catch return Error.BadTransferQuery;
        blob.appendSlice(allocator, writer.written()) catch return Error.BadTransferQuery;
    }
    return blob.toOwnedSlice(allocator) catch return Error.BadTransferQuery;
}

fn algorithmName(algorithm: dns_tsig.Algorithm) dns_name.Name {
    return dns_name.Name.fromText(switch (algorithm) {
        .hmac_sha1 => "hmac-sha1.",
        .hmac_sha224 => "hmac-sha224.",
        .hmac_sha256 => "hmac-sha256.",
        .hmac_sha384 => "hmac-sha384.",
        .hmac_sha512 => "hmac-sha512.",
    }) catch unreachable;
}

/// Appends a zeroed final TSIG record to a transfer message before encoding.
/// The caller encodes the message, signs it with signTransferMessage, and
/// patches the computed MAC into the encoded bytes.
pub fn appendTsigStub(
    message: *dns_message.Message,
    key_owner: dns_name.Name,
    algorithm: dns_tsig.Algorithm,
    query_id: u16,
    now: u64,
) Error!void {
    const digest_len: usize = dns_tsig.digestLength(algorithm);
    // The longest keyed hash output of the RFC 8945 section 6 HMAC-SHA set.
    var zero_mac: [64]u8 = @splat(0);
    const value = dns_rdata.Tsig.init(
        algorithmName(algorithm),
        now,
        tsig_fudge,
        zero_mac[0..digest_len],
        query_id,
        0,
        &.{},
    ) catch return Error.BadTransferQuery;
    message.additionals.append(.{
        .owner = key_owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }) catch return Error.BadTransferQuery;
    message.header.additional_count = @intCast(message.additionals.len);
}

/// Signs one encoded transfer message carrying its zeroed final TSIG record,
/// chaining the previous message MAC (or the request MAC for the first
/// message) through the project's chainedMac primitive. Returns the message
/// MAC for use as the next message's prior.
pub fn signTransferMessage(
    encoded: []u8,
    algorithm: dns_tsig.Algorithm,
    secret: []const u8,
    prior_mac: []const u8,
) dns_tsig.Error!dns_tsig.Mac {
    const final = (try dns_tsig.parseFinalAdditional(encoded)) orelse return dns_tsig.Error.Formerr;
    if (try dns_tsig.algorithmForName(&final.tsig.algorithm) != algorithm) {
        return dns_tsig.Error.UnsupportedAlgorithm;
    }
    const mac = try dns_tsig.signChainedFinal(encoded, final, secret, final.tsig, prior_mac);
    try dns_tsig.patchMac(encoded, final, mac.slice());
    return mac;
}

const transfer_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\mail IN MX 10 mail.example.
    \\
;

fn loadTransferTestZone() !zone_index.Zone {
    var zone_file = try zone_parser.ZoneFile.parse(transfer_test_zone);
    return zone_index.Zone.fromZoneFile(&zone_file);
}

const axfr_query_bytes = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0xfc, 0x00,
    0x01,
};

test "transfer classifies AXFR and IXFR questions for the IN class only" {
    try std.testing.expectEqual(TransferKind.axfr, classify(.AXFR, .IN));
    try std.testing.expectEqual(TransferKind.ixfr, classify(.IXFR, .IN));
    try std.testing.expectEqual(TransferKind.none, classify(.A, .IN));
    try std.testing.expectEqual(TransferKind.none, classify(.AXFR, .ANY));
    try std.testing.expectEqual(TransferKind.none, classify(.IXFR, dns_types.Class.fromCode(3)));
}

test "transfer peek dispatches raw AXFR and IXFR queries without allocation" {
    try std.testing.expect(peekIsTransferRequest(&axfr_query_bytes));
    var ixfr = axfr_query_bytes;
    ixfr[22] = 0xfb;
    try std.testing.expect(peekIsTransferRequest(&ixfr));
    var ordinary = axfr_query_bytes;
    ordinary[22] = 0x01;
    try std.testing.expect(!peekIsTransferRequest(&ordinary));
    var response = axfr_query_bytes;
    response[2] = 0x81;
    try std.testing.expect(!peekIsTransferRequest(&response));
    try std.testing.expect(!peekIsTransferRequest(axfr_query_bytes[0..5]));
}

test "transfer decides IXFR shapes from serial order and delta history" {
    var log = journal_mod.DeltaLog{};
    try log.record(9, 10);
    try std.testing.expectEqual(IxfrDecision.up_to_date, decideIxfr(10, 10, &log));
    try std.testing.expectEqual(IxfrDecision.incremental, decideIxfr(10, 9, &log));
    try std.testing.expectEqual(IxfrDecision.fallback_axfr, decideIxfr(10, 8, &log));
    try std.testing.expectEqual(IxfrDecision.fallback_axfr, decideIxfr(10, 9, null));
    try std.testing.expectEqual(IxfrDecision.fallback_axfr, decideIxfr(10, null, &log));
    try std.testing.expectEqual(IxfrDecision.fallback_axfr, decideIxfr(10, 11, &log));
    try std.testing.expectEqual(IxfrDecision.fallback_axfr, decideIxfr(10, 0x8000_0000, &log));
}

test "transfer orders AXFR records with the apex SOA first and last" {
    var zone = try loadTransferTestZone();
    defer zone.deinit();
    const allocator = std.testing.allocator;
    const ordered = try orderedAxfrRecords(allocator, &zone);
    defer allocator.free(ordered);
    try std.testing.expectEqual(zone.records.len + 1, ordered.len);
    try std.testing.expect(ordered[0].rrtype.eql(.SOA));
    try std.testing.expect(ordered[ordered.len - 1].rrtype.eql(.SOA));
    var soa_count: usize = 0;
    for (ordered) |record| {
        if (record.rrtype.eql(.SOA)) soa_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), soa_count);
}

test "transfer chunks AXFR answers into bounded standalone frames" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var zone = try loadTransferTestZone();
    defer zone.deinit();
    const request = try dns_message.Message.parseQuery(arena.allocator(), &axfr_query_bytes);
    try std.testing.expectEqual(TransferKind.axfr, classifyMessage(&request));

    const messages = try buildAxfrMessages(arena.allocator(), &request, &zone, 2);
    defer {
        for (messages) |*message| message.deinit();
        arena.allocator().free(messages);
    }
    try std.testing.expectEqual(@as(usize, 3), messages.len);
    for (messages) |message| {
        try std.testing.expect(message.header.qr);
        try std.testing.expect(message.header.authoritative);
        try std.testing.expect(message.answers.len <= 2);
    }
    try std.testing.expect(messages[0].answers.items[0].rrtype.eql(.SOA));
    const last = messages[messages.len - 1];
    try std.testing.expect(last.answers.items[last.answers.len - 1].rrtype.eql(.SOA));
    try std.testing.expectEqual(
        messages[0].answers.items[0].rdata.SOA.serial,
        last.answers.items[last.answers.len - 1].rdata.SOA.serial,
    );

    const blob = try encodeFramed(allocator, messages);
    defer allocator.free(blob);
    var offset: usize = 0;
    var frames: usize = 0;
    while (offset < blob.len) {
        const frame_len = std.mem.readInt(u16, blob[offset..][0..2], .big);
        try std.testing.expect(frame_len > 0);
        const parsed = try dns_message.Message.parse(arena.allocator(), blob[offset + 2 ..][0..frame_len]);
        try std.testing.expect(parsed.header.qr);
        try std.testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
        offset += 2 + frame_len;
        frames += 1;
    }
    try std.testing.expectEqual(messages.len, frames);
}
test "transfer AXFR answers echo the query CD bit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cd_query = axfr_query_bytes;
    cd_query[3] |= 0x10;
    const request = try dns_message.Message.parseQuery(arena.allocator(), &cd_query);
    try std.testing.expect(request.header.checking_disabled);
    var zone = try loadTransferTestZone();
    defer zone.deinit();
    const messages = try buildAxfrMessages(arena.allocator(), &request, &zone, 2);
    defer {
        for (messages) |*message| message.deinit();
        arena.allocator().free(messages);
    }
    try std.testing.expect(messages.len > 0);
    for (messages) |message| {
        try std.testing.expect(message.header.checking_disabled);
        try std.testing.expect(message.header.authoritative);
        try std.testing.expect(!message.header.recursion_available);
    }
}

test "transfer AXFR cleanup releases only initialized messages on a bad record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try dns_message.Message.parseQuery(arena.allocator(), &axfr_query_bytes);
    const soa = zone_parser.ZoneRecord{
        .owner = "example.",
        .ttl = 3600,
        .rrtype = .SOA,
        .rdata = "ns.example. hostmaster.example. 10 3600 900 1209600 3600",
    };
    var stored = [_]zone_parser.ZoneRecord{
        soa,
        .{ .owner = "www.example.", .ttl = 3600, .rrtype = .A, .rdata = "192.0.2.1" },
        .{ .owner = "bad-owner", .ttl = 3600, .rrtype = .A, .rdata = "192.0.2.2" },
    };
    const zone = zone_index.Zone{
        .backing = &.{},
        .origin = "example.",
        .records = .{ .items = &stored, .len = stored.len },
        .soa = soa,
    };
    // One record per message puts the failing record on message index 2, so
    // messages 0-1 own sections while slots 3+ stay undefined during cleanup.
    try std.testing.expectError(
        Error.BadTransferQuery,
        buildAxfrMessages(std.testing.allocator, &request, &zone, 1),
    );
}

test "transfer answers IXFR from the authority SOA serial" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var zone = try loadTransferTestZone();
    defer zone.deinit();

    const mname = try dns_name.Name.fromText("ns.example.");
    const rname = try dns_name.Name.fromText("hostmaster.example.");
    const owner = try dns_name.Name.fromText("example.");
    var query = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x2222, .question_count = 1, .authority_count = 1 },
        .question = .{ .name = owner, .qtype = .IXFR, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
    };
    try query.authorities.append(.{
        .owner = owner,
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = mname,
            .rname = rname,
            .serial = 9,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    });
    var wire: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&wire);
    try query.encode(&writer);
    const parsed = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(TransferKind.ixfr, validateTransferRequest(&parsed));
    try std.testing.expectEqual(@as(?u32, 9), clientSerialFromMessage(&parsed));

    var log = journal_mod.DeltaLog{};
    try log.record(9, 10);
    try std.testing.expectEqual(IxfrDecision.incremental, decideIxfr(10, clientSerialFromMessage(&parsed), &log));

    var up_to_date = try buildIxfrUpToDateMessage(arena.allocator(), &parsed, &zone);
    defer up_to_date.deinit();
    try std.testing.expectEqual(@as(usize, 1), up_to_date.answers.len);
    try std.testing.expectEqual(@as(u32, 10), up_to_date.answers.items[0].rdata.SOA.serial);

    var incremental = try buildIxfrIncrementalMessages(arena.allocator(), &parsed, &zone, 9);
    defer incremental.deinit();
    try std.testing.expect(incremental.answers.len >= 4);
    try std.testing.expectEqual(@as(u32, 10), incremental.answers.items[0].rdata.SOA.serial);
    try std.testing.expectEqual(@as(u32, 9), incremental.answers.items[1].rdata.SOA.serial);
    try std.testing.expectEqual(@as(u32, 10), incremental.answers.items[incremental.answers.len - 1].rdata.SOA.serial);
}

test "transfer builds NOTIFY responses that mirror the query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const notify_query = [_]u8{
        0x43, 0x21, 0x21, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0x06, 0x00,
        0x01,
    };
    const parsed = try dns_message.Message.parse(arena.allocator(), &notify_query);
    try std.testing.expect(isNotifyMessage(&parsed));
    try std.testing.expectEqual(TransferKind.none, classifyMessage(&parsed));
    var response = try buildNotifyResponse(arena.allocator(), &parsed);
    defer response.deinit();
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(header_mod.Opcode.notify, response.header.opcode);
    try std.testing.expectEqual(@as(u16, 0x4321), response.header.id);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expectEqual(@as(u16, 1), response.header.question_count);
    try std.testing.expect(response.header.checking_disabled);
}

test "transfer chains one TSIG per message through the chainedMac primitive" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const secret = "01234567890123456789012345678901";
    const key_owner = try dns_name.Name.fromText("key.");
    const request_mac = @as([32]u8, @splat(@as(u8, 0x5a)));
    const now = 1_700_000_000;

    var zone = try loadTransferTestZone();
    defer zone.deinit();
    const request = try dns_message.Message.parseQuery(arena.allocator(), &axfr_query_bytes);
    const messages = try buildAxfrMessages(arena.allocator(), &request, &zone, 2);
    defer {
        for (messages) |*message| message.deinit();
        arena.allocator().free(messages);
    }
    try std.testing.expect(messages.len > 1);
    try std.testing.expect(messages.len <= 3);

    var encoded: [3][tcp_max_frame_size]u8 = undefined;
    var lens: [3]usize = undefined;
    var prior: [32]u8 = request_mac;
    var index: usize = 0;
    while (index < messages.len) : (index += 1) {
        try appendTsigStub(&messages[index], key_owner, .hmac_sha256, 0x1234, now);
        var writer = dns_writer.Writer.init(&encoded[index]);
        try messages[index].encode(&writer);
        lens[index] = writer.len();
        const packet = encoded[index][0..lens[index]];
        const mac = try signTransferMessage(packet, .hmac_sha256, secret, prior[0..]);
        const verified = try dns_tsig.verifyChained(&.{packet}, secret, prior[0..], 32);
        try std.testing.expectEqualSlices(u8, mac.slice(), verified.slice());
        @memcpy(prior[0..mac.slice().len], mac.slice());
    }
    try std.testing.expectEqual(messages.len, index);

    const last = encoded[index - 1][0..lens[index - 1]];
    try std.testing.expectError(error.BadMac, dns_tsig.verifyChained(&.{last}, secret, request_mac[0..], 32));
}
