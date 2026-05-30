const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;
const Name = @import("name.zig").Name;
const types = @import("types.zig");

pub const Error = error{
    EndOfInput,
    BadName,
};

pub const Question = struct {
    name: Name,
    qtype: types.RecordType,
    qclass: types.Class,

    pub fn parse(message: []const u8, offset: usize) !struct { question: Question, next_offset: usize } {
        const name_result = Name.parse(message, offset) catch return Error.BadName;
        var reader = Reader.init(message[name_result.next_offset..]);
        const qtype_code = reader.readU16() catch return Error.EndOfInput;
        const qclass_code = reader.readU16() catch return Error.EndOfInput;
        return .{
            .question = .{
                .name = name_result.name,
                .qtype = types.RecordType.fromCode(qtype_code),
                .qclass = types.Class.fromCode(qclass_code),
            },
            .next_offset = name_result.next_offset + reader.position(),
        };
    }

    pub fn encode(self: Question, writer: *Writer) !void {
        try self.name.encode(writer);
        try writer.writeU16(self.qtype.code());
        try writer.writeU16(self.qclass.code());
    }
};

test "question parses and encodes example.com A IN" {
    const bytes = [_]u8{
        7,    'e',  'x',  'a',  'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0x00, 0x01, 0x00, 0x01,
    };
    const parsed = try Question.parse(&bytes, 0);
    try std.testing.expectEqual(types.RecordType.A, parsed.question.qtype);
    try std.testing.expectEqual(types.Class.IN, parsed.question.qclass);
    try std.testing.expectEqual(@as(usize, bytes.len), parsed.next_offset);

    var output: [32]u8 = undefined;
    var writer = Writer.init(&output);
    try parsed.question.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}
