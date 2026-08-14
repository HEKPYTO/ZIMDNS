/// Contract: Parses and encodes complete DNS messages, including bounded EDNS sections.
/// Ownership: Message sections own allocator-backed arrays and require Message.deinit; inputs and Writer storage are borrowed.
/// Errors: Wire violations are typed parser/encoder errors; transport I/O is outside this module.
const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;
const CompressionTable = @import("writer.zig").CompressionTable;
const header_mod = @import("header.zig");
const question_mod = @import("question.zig");
const record_mod = @import("record.zig");
const rdata_mod = @import("rdata.zig");
const name_mod = @import("name.zig");

pub const Error = error{
    EndOfInput,
    ResponseNotQuery,
    UnsupportedQuestionCount,
    BadRecord,
    AllocationBudgetExceeded,
    TrailingData,
    MalformedEdnsOption,
    MalformedEcsOption,
    EdnsOptionsTooLong,
    MultipleOptRecords,
    InvalidOptOwner,
};

/// Maximum storage allocated for all resource-record sections in one message.
pub const max_message_allocation_bytes: usize = 1024 * 1024;
const min_record_wire_bytes: usize = 11;

pub const RecordSection = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    items: []record_mod.ResourceRecord = &.{},
    len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, count: usize) std.mem.Allocator.Error!RecordSection {
        return .{
            .allocator = allocator,
            .items = try allocator.alloc(record_mod.ResourceRecord, count),
        };
    }

    pub fn append(self: *RecordSection, record: record_mod.ResourceRecord) std.mem.Allocator.Error!void {
        if (self.len == self.items.len) {
            const new_capacity = if (self.items.len == 0) 1 else self.items.len * 2;
            self.items = if (self.items.len == 0)
                try self.allocator.alloc(record_mod.ResourceRecord, new_capacity)
            else
                try self.allocator.realloc(self.items, new_capacity);
        }
        self.items[self.len] = record;
        self.len += 1;
    }

    pub fn slice(self: *const RecordSection) []const record_mod.ResourceRecord {
        return self.items[0..self.len];
    }

    pub fn deinit(self: *RecordSection) void {
        if (self.items.len != 0) self.allocator.free(self.items);
        self.items = &.{};
        self.len = 0;
    }
};

pub const EdnsState = struct {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
};

pub const EDNS_VERSION: u8 = 0;
pub const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;
pub const CLASSIC_UDP_PAYLOAD_SIZE: u16 = 512;

pub const Message = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    header: header_mod.Header,
    question: ?question_mod.Question = null,
    answers: RecordSection = .{},
    authorities: RecordSection = .{},
    additionals: RecordSection = .{},
    edns: ?EdnsState = null,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Message {
        var reader = Reader.init(bytes);
        const header = header_mod.Header.parse(&reader) catch return Error.EndOfInput;
        if (header.question_count > 1) return Error.UnsupportedQuestionCount;

        var message = Message{ .allocator = allocator, .header = header };
        errdefer {
            message.answers.deinit();
            message.authorities.deinit();
            message.additionals.deinit();
        }
        if (header.question_count == 1) {
            const parsed_question = question_mod.Question.parse(bytes, reader.position()) catch return Error.EndOfInput;
            message.question = parsed_question.question;
            reader.offset = parsed_question.next_offset;
        }

        try validateSectionCounts(&reader, header);
        try parseSection(allocator, bytes, &reader, header.answer_count, &message.answers);
        try parseSection(allocator, bytes, &reader, header.authority_count, &message.authorities);
        try parseAdditionalSection(allocator, bytes, &reader, header.additional_count, &message);

        if (reader.position() != bytes.len) return Error.TrailingData;
        return message;
    }

    pub fn parseQuery(allocator: std.mem.Allocator, bytes: []const u8) !Message {
        var message = try Message.parse(allocator, bytes);
        if (message.header.qr) {
            message.deinit();
            return Error.ResponseNotQuery;
        }
        if (message.header.question_count != 1) {
            message.deinit();
            return Error.UnsupportedQuestionCount;
        }
        if (message.header.answer_count != 0 or message.header.authority_count != 0 or
            message.header.additional_count > 1 or
            (message.header.additional_count == 1 and message.edns == null))
        {
            message.deinit();
            return Error.UnsupportedQuestionCount;
        }
        for (message.additionals.slice()) |record| {
            if (!record.rrtype.eql(.OPT)) continue;
            const options = switch (record.rdata) {
                .OPT => |opt| opt.bytes(),
                else => unreachable,
            };
            rdata_mod.validateEdnsOptions(options, true) catch |err| {
                message.deinit();
                return switch (err) {
                    error.MalformedEcsOption => Error.MalformedEcsOption,
                    else => Error.MalformedEdnsOption,
                };
            };
        }
        return message;
    }

    /// Parse only the header and one question for a protocol error response.
    /// The remaining sections are intentionally ignored after the question.
    pub fn parseHeaderQuestion(allocator: std.mem.Allocator, bytes: []const u8) !Message {
        var reader = Reader.init(bytes);
        const header = try header_mod.Header.parse(&reader);
        if (header.qr) return Error.ResponseNotQuery;
        if (header.question_count != 1) return Error.UnsupportedQuestionCount;
        const parsed_question = try question_mod.Question.parse(bytes, reader.position());
        var message = Message{
            .allocator = allocator,
            .header = header,
            .question = parsed_question.question,
        };
        errdefer message.deinit();
        message.answers = try RecordSection.init(allocator, 0);
        message.authorities = try RecordSection.init(allocator, 0);
        message.additionals = try RecordSection.init(allocator, 0);
        return message;
    }

    pub fn deinit(self: *Message) void {
        self.answers.deinit();
        self.authorities.deinit();
        self.additionals.deinit();
    }

    pub fn encode(self: Message, writer: *Writer) !void {
        var compression = CompressionTable{};
        try self.header.encode(writer);
        if (self.question) |question| {
            try compression.writeName(writer, question.name.asWire());
            try writer.writeU16(question.qtype.code());
            try writer.writeU16(question.qclass.code());
        }
        for (self.answers.slice()) |record| try record.encodeCompressed(writer, &compression);
        for (self.authorities.slice()) |record| try record.encodeCompressed(writer, &compression);
        for (self.additionals.slice()) |record| try record.encodeCompressed(writer, &compression);
    }
};

fn validateSectionCounts(reader: *const Reader, header: header_mod.Header) Error!void {
    const record_count = @as(usize, header.answer_count) +
        @as(usize, header.authority_count) +
        @as(usize, header.additional_count);
    if (record_count > reader.remaining() / min_record_wire_bytes) return Error.BadRecord;
    if (record_count > max_message_allocation_bytes / @sizeOf(record_mod.ResourceRecord)) {
        return Error.AllocationBudgetExceeded;
    }
}

fn parseSection(allocator: std.mem.Allocator, bytes: []const u8, reader: *Reader, count: u16, section: *RecordSection) !void {
    section.* = try RecordSection.init(allocator, count);
    var index: u16 = 0;
    while (index < count) : (index += 1) {
        const parsed_record = record_mod.ResourceRecord.parse(bytes, reader.position()) catch return Error.BadRecord;
        section.items[index] = parsed_record.record;
        reader.offset = parsed_record.next_offset;
    }
    section.len = @intCast(count);
}

fn parseAdditionalSection(allocator: std.mem.Allocator, bytes: []const u8, reader: *Reader, count: u16, message: *Message) !void {
    message.additionals = try RecordSection.init(allocator, count);
    var index: u16 = 0;
    while (index < count) : (index += 1) {
        const record_offset = reader.position();
        const parsed_record = record_mod.ResourceRecord.parse(bytes, reader.position()) catch |err| switch (err) {
            record_mod.Error.MalformedOption => return Error.MalformedEdnsOption,
            record_mod.Error.MalformedEcsOption => return Error.MalformedEcsOption,
            record_mod.Error.OptionsTooLong => return Error.EdnsOptionsTooLong,
            else => return Error.BadRecord,
        };
        message.additionals.items[index] = parsed_record.record;
        if (parsed_record.record.rrtype.eql(.OPT)) {
            if (message.edns != null) return Error.MultipleOptRecords;
            var root = name_mod.Name.root();
            if (record_offset >= bytes.len or bytes[record_offset] != 0 or !parsed_record.record.owner.eql(&root)) {
                return Error.InvalidOptOwner;
            }
            message.edns = .{
                .udp_payload_size = parsed_record.record.class.code(),
                .extended_rcode = @intCast((parsed_record.record.ttl >> 24) & 0xff),
                .version = @intCast((parsed_record.record.ttl >> 16) & 0xff),
                .dnssec_ok = (parsed_record.record.ttl & 0x8000) != 0,
            };
        }
        reader.offset = parsed_record.next_offset;
    }
    message.additionals.len = @intCast(count);
}

test "message parses one-question A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    };
    const message = try Message.parseQuery(arena.allocator(), &bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), message.header.id);
    try std.testing.expect(message.question != null);

    var output: [64]u8 = undefined;
    var writer = Writer.init(&output);
    try message.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}

test "message accepts unassigned opcode and rejects unsupported question count" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const unassigned = try Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x78, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try std.testing.expectEqual(@as(@TypeOf(unassigned.header.opcode), .unassigned_15), unassigned.header.opcode);
    try std.testing.expectError(Error.UnsupportedQuestionCount, Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }));
}

test "message rejects response packets as queries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(Error.ResponseNotQuery, Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    }));
}

test "message parses response sections with compressed answer owner" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = [_]u8{
        0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x04, 192,  0,    2,    1,    0xc0, 0x0c, 0x00,
        0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x06, 3,    'n',  's',
        '1',  0xc0, 0x0c,
    };

    const parsed = try Message.parse(arena.allocator(), &bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(usize, 1), parsed.answers.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.authorities.len);
    try std.testing.expectEqual(@as(u32, 3600), parsed.answers.items[0].ttl);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &parsed.answers.items[0].rdata.A);
}

test "parses more than sixteen records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = try arena.allocator().alloc(u8, 301);
    @memset(bytes, 0);
    bytes[0] = 0x12;
    bytes[1] = 0x34;
    bytes[2] = 0x85;
    bytes[3] = 0x80;
    bytes[5] = 1;
    bytes[7] = 17;
    @memcpy(bytes[12..25], &[_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    bytes[26] = 1;
    bytes[28] = 1;

    const answer = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 192, 0, 2, 1 };
    var offset: usize = 29;
    while (offset < bytes.len) : (offset += answer.len) {
        @memcpy(bytes[offset .. offset + answer.len], &answer);
    }

    const parsed = try Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(usize, 17), parsed.answers.slice().len);
}

test "rejects impossible section count before allocating storage" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const bytes = [_]u8{
        0x12, 0x34, 0x85, 0x80, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    };

    try std.testing.expectError(Error.BadRecord, Message.parse(failing_allocator.allocator(), &bytes));
    try std.testing.expectEqual(@as(usize, 0), failing_allocator.allocations);
}

test "message extracts EDNS OPT state from additional section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
    };

    const parsed = try Message.parse(arena.allocator(), &bytes);
    try std.testing.expect(parsed.edns != null);
    try std.testing.expectEqual(@as(u16, 1232), parsed.edns.?.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(usize, 1), parsed.additionals.len);
}

test "message preserves EDNS extended RCODE, DO bit, and option bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00, 0x02, 0x00,
        0x80, 0x00, 0x00, 0x0b, 0xea, 0x60, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00,
        0x0f, 0x00, 0x00,
    };

    const parsed = try Message.parse(arena.allocator(), &bytes);
    try std.testing.expect(parsed.edns != null);
    try std.testing.expectEqual(@as(u16, 4096), parsed.edns.?.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 2), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqualSlices(u8, &.{ 0xea, 0x60, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x0f, 0x00, 0x00 }, parsed.additionals.items[0].rdata.OPT.bytes());
}

test "message rejects malformed OPT records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const multiple_opt = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0,    0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };
    try std.testing.expectError(Error.MultipleOptRecords, Message.parse(arena.allocator(), &multiple_opt));

    const invalid_owner = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0,    0x00, 0x01, 0x00, 0x01, 1,    'x',  0x00, 0x00, 0x29, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(Error.InvalidOptOwner, Message.parse(arena.allocator(), &invalid_owner));

    const malformed_option = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x03,
    };
    try std.testing.expectError(Error.MalformedEdnsOption, Message.parse(arena.allocator(), &malformed_option));
}

test "message rejects nonzero ECS scope in queries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x01,
        192,  0,    2,
    };

    const response_view = try Message.parse(arena.allocator(), &query);
    try std.testing.expect(response_view.edns != null);
    try std.testing.expectError(Error.MalformedEcsOption, Message.parseQuery(arena.allocator(), &query));
}

test "message response encoding uses backwards owner compression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const bytes = [_]u8{
        0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 3,    'w',  'w',  'w',  7,    'e',  'x',
        'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',  0,    0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192,  0,    2,    1,
        4,    'm',  'a',  'i',  'l',  7,    'e',  'x',  'a',  'm',  'p',  'l',
        'e',  3,    'c',  'o',  'm',  0,    0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x3c, 0x00, 0x04, 192,  0,    2,    2,
    };

    const parsed = try Message.parse(arena.allocator(), &bytes);
    var output: [256]u8 = undefined;
    var writer = Writer.init(&output);
    try parsed.encode(&writer);

    const encoded = writer.written();
    try std.testing.expect(std.mem.indexOf(u8, encoded, &.{ 3, 'w', 'w', 'w', 0xc0 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, &.{ 4, 'm', 'a', 'i', 'l', 0xc0 }) != null);
    var pointer_index: usize = 0;
    while (pointer_index + 1 < encoded.len) : (pointer_index += 1) {
        if ((encoded[pointer_index] & 0xc0) == 0xc0) {
            const pointer = std.mem.readInt(u16, encoded[pointer_index..][0..2], .big) & 0x3fff;
            try std.testing.expect(pointer < pointer_index);
        }
    }
}
