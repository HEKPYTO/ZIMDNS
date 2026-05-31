const std = @import("std");
const Writer = @import("writer.zig").Writer;

const max_wire_len = 255;
const max_label_len = 63;
const max_jumps = 16;

pub const Error = error{
    EndOfInput,
    LabelTooLong,
    NameTooLong,
    ReservedLabelBits,
    PointerOutOfBounds,
    PointerLoop,
    NonTerminalPointer,
    OutputTooSmall,
};

pub const ParseResult = struct {
    name: Name,
    next_offset: usize,
};

pub const Name = struct {
    wire: [max_wire_len]u8 = undefined,
    wire_len: u8 = 1,

    pub fn root() Name {
        var name = Name{};
        name.wire[0] = 0;
        return name;
    }

    pub fn fromText(text: []const u8) Error!Name {
        if (std.mem.eql(u8, text, ".")) return Name.root();
        var name = Name{ .wire_len = 0 };
        var start: usize = 0;
        while (start < text.len) {
            const dot_index = std.mem.indexOfScalarPos(u8, text, start, '.') orelse return Error.EndOfInput;
            const label = text[start..dot_index];
            if (label.len == 0) {
                if (dot_index == text.len - 1) {
                    try name.pushByte(0);
                    return name;
                }
                return Error.EndOfInput;
            }
            if (label.len > max_label_len) return Error.LabelTooLong;
            try name.pushByte(@intCast(label.len));
            for (label) |byte| try name.pushByte(std.ascii.toLower(byte));
            start = dot_index + 1;
            if (start == text.len) {
                try name.pushByte(0);
                return name;
            }
        }
        return Error.EndOfInput;
    }

    pub fn asWire(self: *const Name) []const u8 {
        return self.wire[0..self.wire_len];
    }

    pub fn eql(a: *const Name, b: *const Name) bool {
        return std.ascii.eqlIgnoreCase(a.asWire(), b.asWire());
    }

    pub fn parse(message: []const u8, offset: usize) Error!ParseResult {
        if (offset >= message.len) return Error.EndOfInput;

        var out = Name{ .wire_len = 0 };
        var current = offset;
        var next_offset = offset;
        var jumped = false;
        var jumps: u8 = 0;
        var seen_offsets = [_]usize{0} ** max_jumps;

        while (true) {
            if (current >= message.len) return Error.EndOfInput;
            const len = message[current];

            if (len == 0) {
                try out.pushByte(0);
                if (!jumped) next_offset = current + 1;
                return .{ .name = out, .next_offset = next_offset };
            }

            const tag = len & 0xc0;
            if (tag == 0xc0) {
                if (current + 1 >= message.len) return Error.EndOfInput;
                const pointer = (@as(usize, len & 0x3f) << 8) | message[current + 1];
                if (pointer >= message.len) return Error.PointerOutOfBounds;
                if (jumps >= max_jumps) return Error.PointerLoop;
                for (seen_offsets[0..jumps]) |seen| {
                    if (seen == pointer) return Error.PointerLoop;
                }
                seen_offsets[jumps] = pointer;
                jumps += 1;
                if (!jumped) {
                    next_offset = current + 2;
                    jumped = true;
                }
                current = pointer;
                continue;
            }

            if (tag != 0) return Error.ReservedLabelBits;
            if (len > max_label_len) return Error.LabelTooLong;
            if (current + 1 + len > message.len) return Error.EndOfInput;

            try out.pushByte(len);
            const label = message[current + 1 .. current + 1 + len];
            for (label) |byte| {
                try out.pushByte(std.ascii.toLower(byte));
            }
            current += 1 + len;
            if (!jumped) next_offset = current;
        }
    }

    pub fn encode(self: *const Name, writer: *Writer) !void {
        try writer.writeBytes(self.asWire());
    }

    pub fn toText(self: *const Name, buffer: []u8) Error![]const u8 {
        if (self.wire_len == 1 and self.wire[0] == 0) {
            if (buffer.len < 1) return Error.OutputTooSmall;
            buffer[0] = '.';
            return buffer[0..1];
        }

        var input_index: usize = 0;
        var output_index: usize = 0;
        while (input_index < self.wire_len) {
            const len = self.wire[input_index];
            if (len == 0) {
                if (output_index >= buffer.len) return Error.OutputTooSmall;
                buffer[output_index] = '.';
                output_index += 1;
                return buffer[0..output_index];
            }
            input_index += 1;
            if (input_index + len > self.wire_len) return Error.EndOfInput;
            const separator_len: usize = if (output_index == 0) 0 else 1;
            if (output_index + separator_len + len + 1 > buffer.len) return Error.OutputTooSmall;
            if (separator_len == 1) {
                buffer[output_index] = '.';
                output_index += 1;
            }
            @memcpy(buffer[output_index .. output_index + len], self.wire[input_index .. input_index + len]);
            output_index += len;
            input_index += len;
        }

        return Error.EndOfInput;
    }

    fn pushByte(self: *Name, byte: u8) Error!void {
        if (self.wire_len >= max_wire_len) return Error.NameTooLong;
        self.wire[self.wire_len] = byte;
        self.wire_len += 1;
    }
};

test "name parses root and normal names" {
    const root = try Name.parse(&.{0}, 0);
    try std.testing.expectEqual(@as(usize, 1), root.next_offset);
    try std.testing.expectEqualSlices(u8, &.{0}, root.name.asWire());

    const bytes = [_]u8{ 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0 };
    const parsed = try Name.parse(&bytes, 0);
    try std.testing.expectEqual(@as(usize, bytes.len), parsed.next_offset);
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, parsed.name.asWire());

    var text: [32]u8 = undefined;
    try std.testing.expectEqualStrings("example.com.", try parsed.name.toText(&text));
}

test "name decodes compression pointer and nested pointer" {
    const bytes = [_]u8{
        3,    'c', 'o', 'm',  0,
        7,    'e', 'x', 'a',  'm',
        'p',  'l', 'e', 0xc0, 0x00,
        3,    'w', 'w', 'w',  0xc0,
        0x05,
    };

    const parsed = try Name.parse(&bytes, 15);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try parsed.name.toText(&text));
    try std.testing.expectEqual(@as(usize, 21), parsed.next_offset);
}

test "name rejects malformed compression and label encodings" {
    try std.testing.expectError(Error.PointerLoop, Name.parse(&.{ 0xc0, 0x00 }, 0));
    try std.testing.expectError(Error.PointerOutOfBounds, Name.parse(&.{ 0xc0, 0x10 }, 0));
    try std.testing.expectError(Error.ReservedLabelBits, Name.parse(&.{ 0x40, 0x00 }, 0));
    try std.testing.expectError(Error.EndOfInput, Name.parse(&.{ 3, 'w' }, 0));
}

test "name encodes without compression" {
    const bytes = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const parsed = try Name.parse(&bytes, 0);
    var output: [16]u8 = undefined;
    var writer = Writer.init(&output);
    try parsed.name.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}

test "name builds from presentation text" {
    const name = try Name.fromText("Example.COM.");
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("example.com.", try name.toText(&text));
}
