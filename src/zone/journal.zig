const std = @import("std");

pub const SerialOrder = enum {
    equal,
    older,
    newer,
    undefined,
};

pub fn compareSerial(left: u32, right: u32) SerialOrder {
    const distance = left -% right;
    if (distance == 0) return .equal;
    if (distance == 0x8000_0000) return .undefined;
    return if (distance < 0x8000_0000) .newer else .older;
}

pub const Error = error{
    InvalidRecord,
};

pub const Journal = struct {
    dir: std.Io.Dir,
    io: std.Io,
    path: []const u8,
    begin_hook: ?*const fn (Journal, []const u8, []const u8) anyerror!void = null,

    pub fn init(dir: std.Io.Dir, io: std.Io, path: []const u8) Journal {
        return .{ .dir = dir, .io = io, .path = path };
    }

    pub fn begin(self: Journal, temporary_path: []const u8, target_path: []const u8) !void {
        if (temporary_path.len == 0 or target_path.len == 0 or std.mem.eql(u8, temporary_path, target_path)) {
            return Error.InvalidRecord;
        }
        if (self.begin_hook) |hook| return hook(self, temporary_path, target_path);
        const record = try std.fmt.allocPrint(std.heap.page_allocator, "{s}\n{s}\n", .{ temporary_path, target_path });
        defer std.heap.page_allocator.free(record);
        try writeAndSync(self.dir, self.io, self.path, record);
        try syncDirectory(self.dir, self.io);
    }

    pub fn recover(self: Journal, expected_temporary_path: []const u8, expected_target_path: []const u8) !void {
        const record = self.dir.readFileAlloc(self.io, self.path, std.heap.page_allocator, .limited(4096)) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer std.heap.page_allocator.free(record);

        if (expected_temporary_path.len == 0 or expected_target_path.len == 0 or
            std.mem.eql(u8, expected_temporary_path, expected_target_path)) return Error.InvalidRecord;
        const expected_record = try std.fmt.allocPrint(std.heap.page_allocator, "{s}\n{s}\n", .{ expected_temporary_path, expected_target_path });
        defer std.heap.page_allocator.free(expected_record);
        if (!std.mem.eql(u8, record, expected_record)) return Error.InvalidRecord;

        self.dir.deleteFile(self.io, expected_temporary_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.clear();
    }

    pub fn clear(self: Journal) !void {
        self.dir.deleteFile(self.io, self.path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
};

pub fn syncDirectory(dir: std.Io.Dir, io: std.Io) !void {
    // Linux opens non-iterable directories with O_PATH, which cannot be fsynced.
    var sync_dir = try dir.openDir(io, ".", .{ .iterate = true });
    defer sync_dir.close(io);
    const file = std.Io.File{ .handle = sync_dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

fn writeAndSync(dir: std.Io.Dir, io: std.Io, path: []const u8, data: []const u8) !void {
    var file = try dir.createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.sync(io);
}

test "serial comparison treats equal values as equal" {
    try std.testing.expectEqual(SerialOrder.equal, compareSerial(42, 42));
}

test "serial comparison orders ordinary serials" {
    try std.testing.expectEqual(SerialOrder.older, compareSerial(1, 2));
    try std.testing.expectEqual(SerialOrder.newer, compareSerial(2, 1));
}

test "serial comparison treats zero after max as newer" {
    try std.testing.expectEqual(SerialOrder.newer, compareSerial(0, 0xffff_ffff));
}

test "serial comparison leaves the half-range undefined" {
    try std.testing.expectEqual(SerialOrder.undefined, compareSerial(0, 0x8000_0000));
    try std.testing.expectEqual(SerialOrder.undefined, compareSerial(0x8000_0000, 0));
}

test "journal recovery removes only the recorded temporary file" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.tmp", .data = "new" });

    var journal = Journal.init(tmp.dir, io, "zone.snapshot.journal");
    try journal.begin("zone.snapshot.tmp", "zone.snapshot");
    try journal.recover("zone.snapshot.tmp", "zone.snapshot");

    const retained = try tmp.dir.readFileAlloc(io, "zone.snapshot", std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(retained);
    try std.testing.expectEqualStrings("old", retained);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "zone.snapshot.tmp", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "zone.snapshot.journal", .{}));
}
