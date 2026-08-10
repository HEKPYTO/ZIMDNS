const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;
const header_mod = @import("header.zig");
const question_mod = @import("question.zig");
const record_mod = @import("record.zig");

pub const Error = error{
    EndOfInput,
    UnsupportedOpcode,
    UnsupportedQuestionCount,
    BadRecord,
    AllocationBudgetExceeded,
    TrailingData,
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
        const header = header_mod.Header.parse(&reader) catch |err| switch (err) {
            header_mod.Error.EndOfInput => return Error.EndOfInput,
            header_mod.Error.UnsupportedOpcode => return Error.UnsupportedOpcode,
        };
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
        if (message.header.question_count != 1) {
            message.deinit();
            return Error.UnsupportedQuestionCount;
        }
        if (message.header.answer_count != 0 or message.header.authority_count != 0 or message.header.additional_count != 0) {
            message.deinit();
            return Error.UnsupportedQuestionCount;
        }
        return message;
    }

    pub fn deinit(self: *Message) void {
        self.answers.deinit();
        self.authorities.deinit();
        self.additionals.deinit();
    }

    pub fn encode(self: Message, writer: *Writer) !void {
        try self.header.encode(writer);
        if (self.question) |question| {
            try question.encode(writer);
        }
        for (self.answers.slice()) |record| try record.encode(writer);
        for (self.authorities.slice()) |record| try record.encode(writer);
        for (self.additionals.slice()) |record| try record.encode(writer);
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
        const parsed_record = record_mod.ResourceRecord.parse(bytes, reader.position()) catch return Error.BadRecord;
        message.additionals.items[index] = parsed_record.record;
        if (parsed_record.record.rrtype.eql(.OPT)) {
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

test "message rejects unsupported opcode and unsupported question count" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(Error.UnsupportedOpcode, Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }));
    try std.testing.expectError(Error.UnsupportedQuestionCount, Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
