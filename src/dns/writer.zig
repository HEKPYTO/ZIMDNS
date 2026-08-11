/// Contract: Writes bounded DNS wire primitives and names into caller storage.
/// Ownership: Writer borrows its output buffer and CompressionTable state remains caller-owned.
/// Errors: Capacity failures are typed OutOfSpace errors; no I/O occurs.
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

    pub fn rewind(self: *Writer, offset: usize) void {
        self.offset = offset;
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

    pub fn patchU16(self: *Writer, offset: usize, value: u16) Error!void {
        if (offset > self.buffer.len or self.buffer.len - offset < 2) return Error.OutOfSpace;
        std.mem.writeInt(u16, self.buffer[offset..][0..2], value, .big);
    }
};

const max_compression_entries = 64;

const CompressionEntry = struct {
    name: [255]u8 = undefined,
    len: u8 = 0,
    offset: u16 = 0,
};

pub const CompressionTable = struct {
    entries: [max_compression_entries]CompressionEntry = undefined,
    len: usize = 0,

    pub fn writeName(self: *CompressionTable, writer: *Writer, wire: []const u8) !void {
        const writer_start = writer.len();
        const entries_start = self.len;
        self.writeCompressed(writer, wire, writer_start) catch {
            writer.rewind(writer_start);
            self.len = entries_start;
            try writer.writeBytes(wire);
        };
    }

    fn writeCompressed(self: *CompressionTable, writer: *Writer, wire: []const u8, writer_start: usize) !void {
        var pointer_start: ?usize = null;
        var pointer_offset: u16 = 0;
        var label_start: usize = 0;
        while (label_start < wire.len and wire[label_start] != 0) {
            if (self.find(wire[label_start..])) |offset| {
                pointer_start = label_start;
                pointer_offset = offset;
                break;
            }
            label_start += 1 + wire[label_start];
        }

        const end = pointer_start orelse wire.len;
        var current: usize = 0;
        while (current < end) {
            const label_len = wire[current];
            if (label_len == 0) {
                try writer.writeU8(0);
                try self.remember(wire[current..], writer_start + current);
                current += 1;
                continue;
            }
            try self.remember(wire[current..], writer.len());
            try writer.writeBytes(wire[current .. current + 1 + label_len]);
            current += 1 + label_len;
        }

        if (pointer_start != null) {
            try writer.writeU16(0xc000 | pointer_offset);
        }
    }

    fn find(self: *const CompressionTable, wire: []const u8) ?u16 {
        for (self.entries[0..self.len]) |entry| {
            if (entry.len == wire.len and std.mem.eql(u8, entry.name[0..entry.len], wire)) {
                return entry.offset;
            }
        }
        return null;
    }

    fn remember(self: *CompressionTable, wire: []const u8, offset: usize) !void {
        if (wire.len == 0 or wire.len > 255 or offset > 0x3fff or self.len == self.entries.len) return;
        if (self.find(wire) != null) return;
        var entry = CompressionEntry{ .len = @intCast(wire.len), .offset = @intCast(offset) };
        @memcpy(entry.name[0..wire.len], wire);
        self.entries[self.len] = entry;
        self.len += 1;
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

test "compression table emits only backwards pointers" {
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    var table = CompressionTable{};
    try table.writeName(&writer, &.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    const first_end = writer.len();
    try table.writeName(&writer, &.{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    try std.testing.expectEqual(@as(u8, 0xc0), writer.written()[first_end + 4]);
    try std.testing.expect((std.mem.readInt(u16, writer.written()[first_end + 4 ..][0..2], .big) & 0x3fff) < first_end + 4);
}
