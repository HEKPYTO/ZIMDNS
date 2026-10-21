/// Contract: Parses DNS names and writes canonical wire names with pointer safety.
/// Ownership: Name values are inline and parse borrows message bytes; Writer storage is borrowed.
/// Errors: Name-format and capacity failures are typed; no file or socket I/O occurs.
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

    /// Parses presentation text into the canonical lowercase form every
    /// comparison and every signature uses.
    pub fn fromText(text: []const u8) Error!Name {
        return fromTextWithCase(text, true);
    }

    /// Parses presentation text and keeps every label byte as it was written.
    /// RFC 4343 section 4.1 does no case conversion on output, so a name the
    /// zone stored is served with the case the zone wrote.
    pub fn fromTextPreservingCase(text: []const u8) Error!Name {
        return fromTextWithCase(text, false);
    }

    fn fromTextWithCase(text: []const u8, fold_case: bool) Error!Name {
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
            for (label) |byte| try name.pushByte(if (fold_case) std.ascii.toLower(byte) else byte);
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

    /// The 0x20 mechanism: the case of the first letter of each label is
    /// drawn at random and the rest of the label keeps its case. The name
    /// still compares equal to the one it was built from, so the responder's
    /// case-insensitive comparison (RFC 1035 section 2.3.3) still matches it,
    /// while a forged answer has to carry the exact case to be accepted.
    pub fn withRandomizedLabelFirstCase(self: *const Name, random: std.Random) Name {
        var out = self.*;
        var index: usize = 0;
        while (index < out.wire_len) {
            const len: usize = out.wire[index];
            if (len == 0) break;
            const first = index + 1;
            if (first < out.wire_len) out.wire[first] = randomLetterCase(out.wire[first], random);
            index += 1 + len;
        }
        return out;
    }

    pub fn eql(a: *const Name, b: *const Name) bool {
        return std.ascii.eqlIgnoreCase(a.asWire(), b.asWire());
    }

    /// RFC 1123 section 2.1 keeps the RFC 952 host name syntax, so a label
    /// may neither begin nor end with a hyphen; the rest of the character set
    /// stays open because underscore labels are legal DNS names.
    pub fn hasHyphenEdgeLabel(self: *const Name) bool {
        var index: usize = 0;
        while (index < self.wire_len) {
            const len: usize = self.wire[index];
            if (len == 0) break;
            if (self.wire[index + 1] == '-' or self.wire[index + len] == '-') return true;
            index += 1 + len;
        }
        return false;
    }

    /// The canonical lowercase form of this name. RFC 4034 section 6.2 signs
    /// and RFC 5155 section 5 hashes a name in that form, so both paths fold
    /// the name they are given instead of assuming it arrived folded.
    pub fn folded(self: *const Name) Name {
        var out = self.*;
        for (out.wire[0..out.wire_len]) |*byte| byte.* = std.ascii.toLower(byte.*);
        return out;
    }

    /// Parses a name in the canonical lowercase form. Every label byte is
    /// folded, so the name compares equal to any other spelling of itself and
    /// re-encodes to the lowercase form RFC 4034 section 6.2 and RFC 5155
    /// section 5 require.
    pub fn parse(message: []const u8, offset: usize) Error!ParseResult {
        return parseWithCase(message, offset, true);
    }

    /// Parses a name and keeps every label byte exactly as it arrived.
    /// RFC 4343 section 4.1 requires the case of a name to be preserved on
    /// output, so the question's name keeps the case the client used; the
    /// canonical form above stays the default everywhere else.
    pub fn parsePreservingCase(message: []const u8, offset: usize) Error!ParseResult {
        return parseWithCase(message, offset, false);
    }

    fn parseWithCase(message: []const u8, offset: usize, fold_case: bool) Error!ParseResult {
        if (offset >= message.len) return Error.EndOfInput;

        var out = Name{ .wire_len = 0 };
        var current = offset;
        var next_offset = offset;
        var jumped = false;
        var jumps: u8 = 0;
        var seen_offsets = @as([max_jumps]usize, @splat(@as(usize, 0)));

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
                try out.pushByte(if (fold_case) std.ascii.toLower(byte) else byte);
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

    /// The case of one ASCII letter, drawn at random. A byte that is not a
    /// letter carries no 0x20 bit, so it keeps its value.
    fn randomLetterCase(byte: u8, random: std.Random) u8 {
        if (!std.ascii.isAlphabetic(byte)) return byte;
        return if (random.int(u1) == 1) std.ascii.toUpper(byte) else std.ascii.toLower(byte);
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

test "RFC 4343 4.1: the received case is kept, the canonical form folds it" {
    const bytes = [_]u8{ 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0 };

    const received = try Name.parsePreservingCase(&bytes, 0);
    try std.testing.expectEqualSlices(u8, &bytes, received.name.asWire());

    // The canonical parse is the lowercase form RFC 4034 section 6.2 signs
    // and RFC 5155 section 5 hashes.
    const canonical = try Name.parse(&bytes, 0);
    try std.testing.expectEqualSlices(u8, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, canonical.name.asWire());

    // RFC 1035 section 2.3.2: one name, two spellings.
    try std.testing.expect(received.name.eql(&canonical.name));
    const folded = received.name.folded();
    try std.testing.expectEqualSlices(u8, canonical.name.asWire(), folded.asWire());
}

test "0x20: the first letter of each label takes a random case, the rest keeps its case" {
    // A fixed seed keeps the drawn case reproducible; the CLI draws it from
    // the system CSPRNG.
    var prng = std.Random.Pcg.init(0x0020_2020);
    const random = prng.random();
    const name = try Name.fromText("www.example.com.");

    var upper: usize = 0;
    var lower: usize = 0;
    for (0..64) |_| {
        const randomized = name.withRandomizedLabelFirstCase(random);
        // RFC 1035 section 2.3.3: the name still compares equal.
        try std.testing.expect(randomized.eql(&name));

        var index: usize = 0;
        while (index < name.asWire().len) {
            const len: usize = name.asWire()[index];
            if (len == 0) break;
            const first = name.asWire()[index + 1];
            const drawn = randomized.asWire()[index + 1];
            // The first letter is the same letter in either case, and the
            // rest of the label is untouched.
            try std.testing.expectEqual(std.ascii.toLower(first), std.ascii.toLower(drawn));
            try std.testing.expectEqualSlices(
                u8,
                name.asWire()[index + 2 .. index + 1 + len],
                randomized.asWire()[index + 2 .. index + 1 + len],
            );
            if (std.ascii.isUpper(drawn)) upper += 1 else lower += 1;
            index += 1 + len;
        }
    }
    // The case is drawn, not fixed.
    try std.testing.expect(upper > 0);
    try std.testing.expect(lower > 0);
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

test "RFC 1123 2.1: host names accept a leading digit and the 63 and 255 octet bounds" {
    // "the restriction on the first character is relaxed to allow either a
    // letter or a digit. Host software MUST support this more liberal syntax."
    var text: [64]u8 = undefined;
    const digit_leading = try Name.fromText("4example.com.");
    try std.testing.expectEqualStrings("4example.com.", try digit_leading.toText(&text));

    // "Host software MUST handle host names of up to 63 characters and SHOULD
    // handle host names of up to 255 characters."
    var buffer: [300]u8 = undefined;
    @memset(buffer[0..63], 'a');
    buffer[63] = '.';
    try std.testing.expectEqual(@as(usize, 65), (try Name.fromText(buffer[0..64])).asWire().len);
    @memset(buffer[0..64], 'a');
    buffer[64] = '.';
    try std.testing.expectError(Error.LabelTooLong, Name.fromText(buffer[0..65]));

    // 63 + 63 + 63 + 61 octet labels reach the 255-octet name bound exactly;
    // one more character in the last label crosses it.
    @memset(buffer[0..63], 'a');
    @memset(buffer[64..127], 'a');
    @memset(buffer[128..191], 'a');
    @memset(buffer[192..253], 'a');
    buffer[63] = '.';
    buffer[127] = '.';
    buffer[191] = '.';
    buffer[253] = '.';
    try std.testing.expectEqual(@as(usize, 255), (try Name.fromText(buffer[0..254])).asWire().len);
    buffer[253] = 'a';
    buffer[254] = '.';
    try std.testing.expectError(Error.NameTooLong, Name.fromText(buffer[0..255]));
}

test "RFC 1123 2.1: a label may neither begin nor end with a hyphen" {
    try std.testing.expect((try Name.fromText("-bad.example.")).hasHyphenEdgeLabel());
    try std.testing.expect((try Name.fromText("bad-.example.")).hasHyphenEdgeLabel());
    try std.testing.expect(!(try Name.fromText("sri-nic.example.")).hasHyphenEdgeLabel());
    try std.testing.expect(!(try Name.fromText("_443._tcp.example.")).hasHyphenEdgeLabel());
}
