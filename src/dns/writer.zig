const std = @import("std");

pub const Error = error{
    OutOfSpace,
};

pub const Writer = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    pub fn len(self: Writer) usize {
        return self.offset;
    }

    pub fn written(self: Writer) []const u8 {
        return self.buffer[0..self.offset];
    }

    pub fn writeU8(self: *Writer, value: u8) Error!void {
        if (self.buffer.len - self.offset < 1) return Error.OutOfSpace;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    pub fn writeU16(self: *Writer, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try self.writeBytes(&bytes);
    }

    pub fn writeU32(self: *Writer, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try self.writeBytes(&bytes);
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) Error!void {
        if (self.buffer.len - self.offset < bytes.len) return Error.OutOfSpace;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }
};

test "writer writes big-endian primitives" {
    var buffer: [7]u8 = undefined;
    var writer = Writer.init(&buffer);
    try writer.writeU8(0xab);
    try writer.writeU16(0x1234);
    try writer.writeU32(0xdeadbeef);
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef }, writer.written());
}

test "writer rejects writes past capacity" {
    var buffer: [1]u8 = undefined;
    var writer = Writer.init(&buffer);
    try std.testing.expectError(Error.OutOfSpace, writer.writeU16(0x1234));
    try std.testing.expectEqual(@as(usize, 0), writer.len());
}
