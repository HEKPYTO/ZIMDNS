const std = @import("std");

const max_entries = 256;
const max_text = 255;

pub const Error = error{
    TextTooLong,
    TooManyEntries,
};

const Entry = struct {
    bytes: [max_text]u8 = undefined,
    len: usize = 0,

    fn set(self: *Entry, value: []const u8) Error!void {
        if (value.len > self.bytes.len) return Error.TextTooLong;
        for (value, 0..) |byte, index| self.bytes[index] = std.ascii.toLower(byte);
        self.len = value.len;
    }

    fn text(self: *const Entry) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Blocklist = struct {
    entries: [max_entries]Entry = undefined,
    len: usize = 0,

    pub fn parse(text: []const u8) !Blocklist {
        var list = Blocklist{};
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, stripComment(raw_line), " \t\r");
            if (line.len == 0) continue;
            try list.add(line);
        }
        return list;
    }

    pub fn add(self: *Blocklist, name: []const u8) !void {
        if (self.len >= self.entries.len) return Error.TooManyEntries;
        var buffer: [max_text]u8 = undefined;
        const normalized = try normalizeName(name, &buffer);
        try self.entries[self.len].set(normalized);
        self.len += 1;
    }

    pub fn appendAll(self: *Blocklist, other: Blocklist) !void {
        var index: usize = 0;
        while (index < other.len) : (index += 1) {
            try self.add(other.entries[index].text());
        }
    }

    pub fn blocks(self: *const Blocklist, name: []const u8) bool {
        var buffer: [max_text]u8 = undefined;
        const normalized = normalizeName(name, &buffer) catch return false;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (std.ascii.eqlIgnoreCase(self.entries[index].text(), normalized)) return true;
        }
        return false;
    }
};

fn normalizeName(name: []const u8, buffer: []u8) Error![]const u8 {
    const needs_dot = !std.mem.endsWith(u8, name, ".");
    const normalized_len = name.len + @intFromBool(needs_dot);
    if (normalized_len > buffer.len) return Error.TextTooLong;
    for (name, 0..) |byte, index| buffer[index] = std.ascii.toLower(byte);
    if (needs_dot) buffer[name.len] = '.';
    return buffer[0..normalized_len];
}

fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |byte, index| {
        if (byte == '#') return line[0..index];
    }
    return line;
}

test "blocklist parses comments and matches exact names" {
    const list = try Blocklist.parse(
        \\# exact domains
        \\Ads.Example
        \\tracker.example.
        \\
    );

    try std.testing.expect(list.blocks("ads.example."));
    try std.testing.expect(list.blocks("tracker.example."));
    try std.testing.expect(!list.blocks("cdn.example."));
}

test "blocklist rejects too many and too long entries" {
    var long_name: [260]u8 = undefined;
    @memset(&long_name, 'a');
    try std.testing.expectError(error.TextTooLong, Blocklist.parse(&long_name));
}

test "blocklist appends entries from another list" {
    var list = try Blocklist.parse("ads.example.\n");
    const extra = try Blocklist.parse("tracker.example.\n");
    try list.appendAll(extra);

    try std.testing.expect(list.blocks("ads.example."));
    try std.testing.expect(list.blocks("tracker.example."));
}
