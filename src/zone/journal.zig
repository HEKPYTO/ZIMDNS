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

/// Bounded in-memory log of zone serial transitions backing RFC 1995 IXFR
/// delta decisions. It records which serials the current snapshot supersedes
/// so the server can tell a client asking from serial S whether an
/// incremental sequence to the current serial is still known. When the log no
/// longer connects S to the current serial, the server must fall back to a
/// full AXFR. Entries are evicted oldest-first; this is volatile transfer
/// state, not durable recovery data, so it is never written to disk.
pub const max_deltas: usize = 8;

pub const DeltaError = error{
    SerialEqual,
    SerialOlder,
    SerialUndefined,
};

pub const DeltaLog = struct {
    from_serials: [max_deltas]u32 = undefined,
    to_serials: [max_deltas]u32 = undefined,
    len: usize = 0,

    /// Records that the zone moved from `from_serial` to `to_serial`.
    /// Only RFC 1982 newer transitions are accepted.
    pub fn record(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
        switch (compareSerial(to_serial, from_serial)) {
            .newer => {},
            .equal => return DeltaError.SerialEqual,
            .older => return DeltaError.SerialOlder,
            .undefined => return DeltaError.SerialUndefined,
        }
        if (self.len == max_deltas) {
            std.mem.copyForwards(u32, self.from_serials[0 .. max_deltas - 1], self.from_serials[1..max_deltas]);
            std.mem.copyForwards(u32, self.to_serials[0 .. max_deltas - 1], self.to_serials[1..max_deltas]);
            self.len = max_deltas - 1;
        }
        self.from_serials[self.len] = from_serial;
        self.to_serials[self.len] = to_serial;
        self.len += 1;
    }

    /// Reports whether `serial` appears anywhere in the recorded chain,
    /// either as a superseded serial or as a reached serial.
    pub fn hasSerial(self: *const DeltaLog, serial: u32) bool {
        for (self.from_serials[0..self.len], self.to_serials[0..self.len]) |from, to| {
            if (from == serial or to == serial) return true;
        }
        return false;
    }

    /// Reports whether the log connects `client_serial` to `current_serial`
    /// through recorded transitions. A missing link means the delta is no
    /// longer known and the server must answer the IXFR with a full AXFR.
    pub fn canServeIncremental(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        if (client_serial == current_serial) return true;
        var next = client_serial;
        var hops: usize = 0;
        while (hops <= self.len) : (hops += 1) {
            var advanced = false;
            for (self.from_serials[0..self.len], self.to_serials[0..self.len]) |from, to| {
                if (from != next) continue;
                if (to == current_serial) return true;
                next = to;
                advanced = true;
                break;
            }
            if (!advanced) return false;
        }
        return false;
    }
};

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

test "delta log serves incremental answers only across recorded transitions" {
    var log = DeltaLog{};
    try log.record(10, 11);
    try log.record(11, 12);
    try std.testing.expect(log.hasSerial(10));
    try std.testing.expect(log.hasSerial(12));
    try std.testing.expect(!log.hasSerial(9));
    try std.testing.expect(log.canServeIncremental(12, 12));
    try std.testing.expect(log.canServeIncremental(10, 12));
    try std.testing.expect(log.canServeIncremental(11, 12));
    try std.testing.expect(!log.canServeIncremental(9, 12));
    try std.testing.expect(!log.canServeIncremental(10, 13));
}

test "delta log rejects transitions that are not RFC 1982 newer" {
    var log = DeltaLog{};
    try std.testing.expectError(DeltaError.SerialEqual, log.record(10, 10));
    try std.testing.expectError(DeltaError.SerialOlder, log.record(11, 10));
    try std.testing.expectError(DeltaError.SerialUndefined, log.record(0, 0x8000_0000));
    try std.testing.expectEqual(@as(usize, 0), log.len);
}

test "delta log evicts the oldest transition once bounded" {
    var log = DeltaLog{};
    var serial: u32 = 1;
    while (serial <= max_deltas + 1) : (serial += 1) {
        try log.record(serial, serial + 1);
    }
    try std.testing.expectEqual(max_deltas, log.len);
    try std.testing.expect(!log.hasSerial(1));
    try std.testing.expect(log.hasSerial(2));
    try std.testing.expect(!log.canServeIncremental(1, max_deltas + 2));
    try std.testing.expect(log.canServeIncremental(2, max_deltas + 2));
}
