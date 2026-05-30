const std = @import("std");

pub const Error = error{
    EndOfInput,
};

pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: Reader) usize {
        return self.bytes.len - self.offset;
    }

    pub fn position(self: Reader) usize {
        return self.offset;
    }

    pub fn readU8(self: *Reader) Error!u8 {
        if (self.remaining() < 1) return Error.EndOfInput;
        const value = self.bytes[self.offset];
        self.offset += 1;
        return value;
    }

    pub fn readU16(self: *Reader) Error!u16 {
        const slice = try self.readBytes(2);
        return std.mem.readInt(u16, slice[0..2], .big);
    }

    pub fn readU32(self: *Reader) Error!u32 {
        const slice = try self.readBytes(4);
        return std.mem.readInt(u32, slice[0..4], .big);
    }

    pub fn readBytes(self: *Reader, len: usize) Error![]const u8 {
        if (self.remaining() < len) return Error.EndOfInput;
        const start = self.offset;
        self.offset += len;
        return self.bytes[start..self.offset];
    }
};

test "reader reads big-endian primitives and tracks remaining bytes" {
    var reader = Reader.init(&.{ 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef });
    try std.testing.expectEqual(@as(u16, 0x1234), try reader.readU16());
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), try reader.readU32());
    try std.testing.expectEqual(@as(usize, 0), reader.remaining());
}

test "reader rejects reads past end" {
    var reader = Reader.init(&.{0x12});
    try std.testing.expectError(Error.EndOfInput, reader.readU16());
    try std.testing.expectEqual(@as(usize, 0), reader.position());
}
