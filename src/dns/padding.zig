/// Contract: Adds the RFC 7830 "Padding" option to an encoded DNS response
/// when the query that produced it asked for one. The helper knows nothing
/// about transports, so only the encrypted ones call it: RFC 7830 section 6
/// says an implementation MUST NOT use the option when the DNS transport is
/// not encrypted.
/// Ownership: The padded response is allocated with the given allocator; the
/// query message and the response bytes are borrowed.
/// Errors: A response that is not a well-formed DNS message is reported as
/// MalformedResponse. A response that needs no padding yields null instead of
/// an error.
const std = @import("std");
const dns_header = @import("header.zig");
const dns_message = @import("message.zig");
const dns_name = @import("name.zig");
const dns_rdata = @import("rdata.zig");
const dns_reader = @import("reader.zig");
const dns_writer = @import("writer.zig");
const dns_types = @import("types.zig");

pub const Error = error{
    MalformedResponse,
};

/// The padded message is rounded up to a multiple of this many octets, so a
/// padded answer has a predictable size.
pub const PADDING_BLOCK: usize = 128;

/// The RFC 6891 section 6.1.2 framing of the Padding option: the two-octet
/// option code and the two-octet option length.
const option_header_len: usize = 4;

/// Where the OPT record of a response sits on the wire.
const OptLocation = struct {
    /// The RDLENGTH field of the record.
    rdlength_offset: usize,
    /// The first octet of the RDATA, the option framing.
    rdata_start: usize,
    /// The octet after the RDATA.
    rdata_end: usize,
};

/// The bounds of one resource record on the wire.
const RecordBounds = struct {
    rrtype: u16,
    rdlength_offset: usize,
    rdata_start: usize,
    rdata_end: usize,
};

/// The padded response, or null when the response needs no padding.
///
/// The padding is added when the query carried EDNS(0) and a Padding option:
/// RFC 7830 section 4 makes the padding mandatory then, and forbids it when
/// the query did not indicate EDNS(0) support. The octets are 0x00, the
/// OPTION-LENGTH carries their number, and the option occurs at most once per
/// OPT record, so a response that already carries one is left alone.
pub fn padResponse(
    allocator: std.mem.Allocator,
    query: *const dns_message.Message,
    response: []const u8,
) !?[]u8 {
    const edns = query.edns orelse return null;
    if (!hasPaddingOption(query)) return null;

    const opt = (try findResponseOpt(response)) orelse return null;
    const options = response[opt.rdata_start..opt.rdata_end];
    if (dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE) != null) return null;

    // RFC 7830 section 4: a padded message must not exceed the number of
    // octets the requestor advertised in the RR Class Field of its OPT
    // record. A response that already reaches that size is left alone.
    if (edns.udp_payload_size < response.len + option_header_len) return null;
    const room = edns.udp_payload_size - response.len - option_header_len;
    const length = @min(paddingLength(response.len + option_header_len), room);

    const padded = try allocator.alloc(u8, response.len + option_header_len + length);
    errdefer allocator.free(padded);
    @memcpy(padded[0..opt.rdata_end], response[0..opt.rdata_end]);
    @memcpy(padded[opt.rdata_end + option_header_len + length ..], response[opt.rdata_end..]);
    // The RDLENGTH of the OPT record covers the option framing and the
    // padding octets it adds.
    std.mem.writeInt(u16, padded[opt.rdlength_offset..][0..2], @intCast(options.len + option_header_len + length), .big);
    // RFC 7830 section 3: the option code is 12, the option length is the
    // number of padding octets, and the octets are 0x00.
    std.mem.writeInt(u16, padded[opt.rdata_end..][0..2], dns_rdata.EDNS_PADDING_OPTION_CODE, .big);
    std.mem.writeInt(u16, padded[opt.rdata_end + 2 ..][0..2], @intCast(length), .big);
    @memset(padded[opt.rdata_end + option_header_len ..][0..length], 0);
    return padded;
}

/// True when the query carried a Padding option in its OPT record.
fn hasPaddingOption(query: *const dns_message.Message) bool {
    const options = queryOptions(query) orelse return false;
    return dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE) != null;
}

/// The OPTION-DATA bytes of a message's OPT record, or null when it carries
/// no EDNS(0) at all.
fn queryOptions(query: *const dns_message.Message) ?[]const u8 {
    for (query.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return switch (record.rdata) {
            .OPT => |opt| opt.bytes(),
            else => unreachable,
        };
    }
    return null;
}

/// The number of padding octets that round the message up to a multiple of
/// PADDING_BLOCK.
fn paddingLength(total: usize) usize {
    const remainder = total % PADDING_BLOCK;
    return if (remainder == 0) 0 else PADDING_BLOCK - remainder;
}

/// The OPT record of a response, or null when the response carries none.
///
/// A response that ends in a TSIG record is left alone: the MAC of RFC 8945
/// section 4.2 covers the message octets, so padding added after the
/// signature would invalidate it.
fn findResponseOpt(response: []const u8) Error!?OptLocation {
    var reader = dns_reader.Reader.init(response);
    const header = dns_header.Header.parse(&reader) catch return Error.MalformedResponse;

    var offset: usize = 12;
    var index: usize = 0;
    while (index < header.question_count) : (index += 1) {
        const name = dns_name.Name.parse(response, offset) catch return Error.MalformedResponse;
        offset = name.next_offset + 4;
        if (offset > response.len) return Error.MalformedResponse;
    }
    index = 0;
    while (index < @as(usize, header.answer_count) + header.authority_count) : (index += 1) {
        const bounds = try readRecord(response, offset);
        offset = bounds.rdata_end;
    }

    var opt: ?OptLocation = null;
    index = 0;
    while (index < header.additional_count) : (index += 1) {
        const bounds = try readRecord(response, offset);
        if (bounds.rrtype == dns_types.RecordType.TSIG.code()) return null;
        if (bounds.rrtype == dns_types.RecordType.OPT.code()) {
            opt = .{
                .rdlength_offset = bounds.rdlength_offset,
                .rdata_start = bounds.rdata_start,
                .rdata_end = bounds.rdata_end,
            };
        }
        offset = bounds.rdata_end;
    }
    return opt;
}

/// The bounds of the resource record that starts at `offset`.
fn readRecord(response: []const u8, offset: usize) Error!RecordBounds {
    const owner = dns_name.Name.parse(response, offset) catch return Error.MalformedResponse;
    const fields = owner.next_offset;
    if (response.len -| fields < 10) return Error.MalformedResponse;
    const rrtype = std.mem.readInt(u16, response[fields..][0..2], .big);
    const rdlength = std.mem.readInt(u16, response[fields + 8 ..][0..2], .big);
    const rdata_start = fields + 10;
    if (rdlength > response.len -| rdata_start) return Error.MalformedResponse;
    return .{
        .rrtype = rrtype,
        .rdlength_offset = fields + 8,
        .rdata_start = rdata_start,
        .rdata_end = rdata_start + rdlength,
    };
}

/// A query for dns.home.arpa A whose OPT record advertises `payload_size`
/// and carries a Padding option of four octets: the RFC 7830 section 3
/// request that asks for a padded answer.
fn queryWithPadding(buffer: []u8, payload_size: u16) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU16(0x1234);
    try writer.writeU16(0x0100);
    try writer.writeU16(1);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try writer.writeU16(1);
    try writer.writeBytes(&.{ 0x03, 'd', 'n', 's', 0x04, 'h', 'o', 'm', 'e', 0x04, 'a', 'r', 'p', 'a', 0x00 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    // The OPT pseudo-record: the root owner, the type, the requestor's
    // payload size, a zero TTL, and the option framing of the option.
    try writer.writeU8(0);
    try writer.writeU16(dns_types.RecordType.OPT.code());
    try writer.writeU16(payload_size);
    try writer.writeU32(0);
    try writer.writeU16(option_header_len + 4);
    try writer.writeU16(dns_rdata.EDNS_PADDING_OPTION_CODE);
    try writer.writeU16(4);
    try writer.writeBytes(&.{ 0, 0, 0, 0 });
    return writer.written();
}

/// The same query with an EDNS(0) OPT record that carries no option.
fn queryWithEdns(buffer: []u8, payload_size: u16) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU16(0x1234);
    try writer.writeU16(0x0100);
    try writer.writeU16(1);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try writer.writeU16(1);
    try writer.writeBytes(&.{ 0x03, 'd', 'n', 's', 0x04, 'h', 'o', 'm', 'e', 0x04, 'a', 'r', 'p', 'a', 0x00 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    try writer.writeU8(0);
    try writer.writeU16(dns_types.RecordType.OPT.code());
    try writer.writeU16(payload_size);
    try writer.writeU32(0);
    try writer.writeU16(0);
    return writer.written();
}

/// The same query without an OPT record: it does not indicate EDNS(0)
/// support.
const plain_query = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 'd',  'n',  's',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',
    'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01,
};

/// The answer to that query: one A record and a bare OPT record.
const answer = [_]u8{
    0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x03, 'd',  'n',  's',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',
    'p',  'a',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x00,
    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/// The option framing of a response's OPT record.
fn responseOptions(response: []const u8) ![]const u8 {
    const opt = (try findResponseOpt(response)) orelse return error.MissingOpt;
    return response[opt.rdata_start..opt.rdata_end];
}

test "RFC 7830: a query that asked for padding gets a padded answer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_buffer: [64]u8 = undefined;
    const query = try dns_message.Message.parseQuery(arena.allocator(), try queryWithPadding(&query_buffer, 1232));
    const padded = (try padResponse(arena.allocator(), &query, &answer)).?;
    try std.testing.expect(padded.len > answer.len);
    // The answer is rounded up to the next multiple of the padding block.
    try std.testing.expectEqual(@as(usize, 0), padded.len % PADDING_BLOCK);

    const options = try responseOptions(padded);
    const padding = dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, padded.len - answer.len - option_header_len), padding.len);
    for (padding) |octet| try std.testing.expectEqual(@as(u8, 0), octet);

    // The answer the client reads is the same answer with one option more.
    const parsed = try dns_message.Message.parse(arena.allocator(), padded);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
}

test "RFC 7830: a query without the option, or without EDNS(0), gets no padding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_buffer: [64]u8 = undefined;
    const edns = try dns_message.Message.parseQuery(arena.allocator(), try queryWithEdns(&query_buffer, 1232));
    try std.testing.expectEqual(@as(?[]u8, null), try padResponse(arena.allocator(), &edns, &answer));

    const plain = try dns_message.Message.parseQuery(arena.allocator(), &plain_query);
    try std.testing.expectEqual(@as(?[]u8, null), try padResponse(arena.allocator(), &plain, &answer));
}

test "RFC 7830: a padded answer stays inside the requestor's payload size" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_buffer: [64]u8 = undefined;
    // The requestor advertised 96 octets, so the padding stops there instead
    // of reaching the next multiple of the padding block.
    const tight = try dns_message.Message.parseQuery(arena.allocator(), try queryWithPadding(&query_buffer, 96));
    const padded = (try padResponse(arena.allocator(), &tight, &answer)).?;
    try std.testing.expectEqual(@as(usize, 96), padded.len);

    // A requestor that advertised 64 octets gets an answer that stops there:
    // the padding fills the room the requestor left and no more.
    const exact = try dns_message.Message.parseQuery(arena.allocator(), try queryWithPadding(&query_buffer, 64));
    const exact_padded = (try padResponse(arena.allocator(), &exact, &answer)).?;
    try std.testing.expectEqual(@as(usize, 64), exact_padded.len);

    // A requestor that advertised less than the answer leaves no room for
    // the option framing, so the answer is not padded at all.
    const small = try dns_message.Message.parseQuery(arena.allocator(), try queryWithPadding(&query_buffer, 32));
    try std.testing.expectEqual(@as(?[]u8, null), try padResponse(arena.allocator(), &small, &answer));
}
