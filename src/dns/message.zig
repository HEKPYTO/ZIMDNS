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
    TooManyRecords,
    BadRecord,
    TrailingData,
};

pub const max_section_records = 16;

pub const RecordSection = struct {
    items: [max_section_records]record_mod.ResourceRecord = undefined,
    len: usize = 0,

    pub fn append(self: *RecordSection, record: record_mod.ResourceRecord) Error!void {
        if (self.len >= max_section_records) return Error.TooManyRecords;
        self.items[self.len] = record;
        self.len += 1;
    }

    pub fn slice(self: *const RecordSection) []const record_mod.ResourceRecord {
        return self.items[0..self.len];
    }
};

pub const EdnsState = struct {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
};

pub const Message = struct {
    header: header_mod.Header,
    question: ?question_mod.Question = null,
    answers: RecordSection = .{},
    authorities: RecordSection = .{},
    additionals: RecordSection = .{},
    edns: ?EdnsState = null,

    pub fn parse(bytes: []const u8) !Message {
        var reader = Reader.init(bytes);
        const header = header_mod.Header.parse(&reader) catch |err| switch (err) {
            header_mod.Error.EndOfInput => return Error.EndOfInput,
            header_mod.Error.UnsupportedOpcode => return Error.UnsupportedOpcode,
        };
        if (header.question_count > 1) return Error.UnsupportedQuestionCount;

        var message = Message{ .header = header };
        if (header.question_count == 1) {
            const parsed_question = question_mod.Question.parse(bytes, reader.position()) catch return Error.EndOfInput;
            message.question = parsed_question.question;
            reader.offset = parsed_question.next_offset;
        }

        try parseSection(bytes, &reader, header.answer_count, &message.answers);
        try parseSection(bytes, &reader, header.authority_count, &message.authorities);
        try parseAdditionalSection(bytes, &reader, header.additional_count, &message);

        if (reader.position() != bytes.len) return Error.TrailingData;
        return message;
    }

    pub fn parseQuery(bytes: []const u8) !Message {
        const message = try Message.parse(bytes);
        if (message.header.question_count != 1) return Error.UnsupportedQuestionCount;
        if (message.header.answer_count != 0 or message.header.authority_count != 0 or message.header.additional_count != 0) {
            return Error.UnsupportedQuestionCount;
        }
        return message;
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

fn parseSection(bytes: []const u8, reader: *Reader, count: u16, section: *RecordSection) Error!void {
    if (count > max_section_records) return Error.TooManyRecords;
    var index: u16 = 0;
    while (index < count) : (index += 1) {
        const parsed_record = record_mod.ResourceRecord.parse(bytes, reader.position()) catch return Error.BadRecord;
        try section.append(parsed_record.record);
        reader.offset = parsed_record.next_offset;
    }
}

fn parseAdditionalSection(bytes: []const u8, reader: *Reader, count: u16, message: *Message) Error!void {
    if (count > max_section_records) return Error.TooManyRecords;
    var index: u16 = 0;
    while (index < count) : (index += 1) {
        const parsed_record = record_mod.ResourceRecord.parse(bytes, reader.position()) catch return Error.BadRecord;
        try message.additionals.append(parsed_record.record);
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
}

test "message parses one-question A query" {
    const bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    };
    const message = try Message.parseQuery(&bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), message.header.id);
    try std.testing.expect(message.question != null);

    var output: [64]u8 = undefined;
    var writer = Writer.init(&output);
    try message.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}

test "message rejects unsupported opcode and unsupported question count" {
    try std.testing.expectError(Error.UnsupportedOpcode, Message.parseQuery(&.{
        0x12, 0x34, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }));
    try std.testing.expectError(Error.UnsupportedQuestionCount, Message.parseQuery(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }));
}

test "message parses response sections with compressed answer owner" {
    const bytes = [_]u8{
        0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x04, 192,  0,    2,    1,    0xc0, 0x0c, 0x00,
        0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x06, 3,    'n',  's',
        '1',  0xc0, 0x0c,
    };

    const parsed = try Message.parse(&bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(usize, 1), parsed.answers.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.authorities.len);
    try std.testing.expectEqual(@as(u32, 3600), parsed.answers.items[0].ttl);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &parsed.answers.items[0].rdata.A);
}

test "message extracts EDNS OPT state from additional section" {
    const bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
    };

    const parsed = try Message.parse(&bytes);
    try std.testing.expect(parsed.edns != null);
    try std.testing.expectEqual(@as(u16, 1232), parsed.edns.?.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(usize, 1), parsed.additionals.len);
}
