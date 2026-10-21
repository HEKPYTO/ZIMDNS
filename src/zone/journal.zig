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

/// Bounded log of zone serial transitions backing RFC 1995 IXFR delta
/// decisions. It records which serials the current snapshot supersedes so
/// the server can tell a client asking from serial S whether an incremental
/// sequence to the current serial is still known. When the log no longer
/// connects S to the current serial, the server must fall back to a full
/// AXFR. Entries are evicted oldest-first. The log is volatile transfer
/// state, and it is written to disk only when the operator names a journal
/// file (see Journal).
pub const max_deltas: usize = 8;

/// The longest zone apex a journal record carries.
pub const max_origin_len = 256;

/// The longest journal path the server accepts.
pub const max_path_len = 256;

/// The journal file is read in one piece, and a bigger file is not read.
pub const max_journal_bytes = 1024 * 1024;

pub const DeltaError = error{
    SerialEqual,
    SerialOlder,
    SerialUndefined,
};

/// One transition read from the journal file.
pub const Transition = struct {
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    from_serial: u32 = 0,
    to_serial: u32 = 0,

    pub fn originText(self: *const Transition) []const u8 {
        return self.origin[0..self.origin_len];
    }
};

/// The durable RFC 1995 delta journal: the file that keeps a zone's serial
/// transitions across a restart, so an IXFR client at an old serial is still
/// answered incrementally after the server comes back. One transition per
/// line, holding the zone apex and the two serials. Nothing else is written
/// to the file: no zone data and no key material.
pub const Journal = struct {
    io: std.Io,
    file: ?std.Io.File = null,
    /// The offset the next transition is written at: the end of the file, so
    /// an existing journal keeps its records.
    offset: u64 = 0,

    /// Opens the journal for appending, creating the file when it is not
    /// there yet.
    pub fn open(io: std.Io, dir: std.Io.Dir, path: []const u8) !Journal {
        if (path.len == 0 or path.len > max_path_len) return error.BadPath;
        var journal = Journal{ .io = io };
        journal.file = try dir.createFile(io, path, .{ .read = true, .truncate = false });
        errdefer journal.file.?.close(io);
        const stat = try journal.file.?.stat(io);
        journal.offset = stat.size;
        return journal;
    }

    /// Closes the journal. Closing twice is harmless.
    pub fn close(self: *Journal) void {
        if (self.file) |file| {
            file.close(self.io);
            self.file = null;
        }
    }

    /// Appends one transition. The record is one line written at the end of
    /// the file, so a write that is cut short leaves a truncated tail the
    /// reader skips. A failed write leaves the journal as it was.
    pub fn append(self: *Journal, origin: []const u8, from_serial: u32, to_serial: u32) void {
        const file = self.file orelse return;
        if (origin.len == 0 or origin.len > max_origin_len) return;
        var line: [max_origin_len + 32]u8 = undefined;
        const text = std.fmt.bufPrint(&line, "{s} {d} {d}\n", .{ origin, from_serial, to_serial }) catch return;
        file.writePositionalAll(self.io, text, self.offset) catch return;
        self.offset += text.len;
    }

    /// Reads the transitions the journal holds. A line that does not parse is
    /// skipped, so a truncated or corrupt record costs the server that
    /// record and nothing else. A file that does not end in a newline was cut
    /// short, so its last line is a torn record and is not restored either.
    /// The caller owns the returned slice.
    pub fn read(self: *const Journal, allocator: std.mem.Allocator) ![]Transition {
        const file = self.file orelse return &.{};
        const stat = try file.stat(self.io);
        const size = stat.size;
        if (size == 0) return &.{};
        const want: usize = @intCast(@min(size, max_journal_bytes));
        const start = size - want;
        const buffer = try allocator.alloc(u8, want);
        defer allocator.free(buffer);
        const len = try file.readPositionalAll(self.io, buffer, start);
        var text = buffer[0..len];
        // A file bigger than the read bound starts in the middle of a
        // record, so the partial first line is dropped.
        if (start > 0) {
            const newline = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
            text = text[newline + 1 ..];
        }
        // A crash in the middle of an append leaves a record without its
        // closing newline; such a tail was never written whole, so it is not
        // restored even when it reads as a complete transition.
        if (text.len > 0 and text[text.len - 1] != '\n') {
            const newline = std.mem.lastIndexOfScalar(u8, text, '\n') orelse 0;
            text = text[0..newline];
        }
        var transitions: std.ArrayList(Transition) = .empty;
        errdefer transitions.deinit(allocator);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const transition = parseTransition(line) orelse continue;
            try transitions.append(allocator, transition);
        }
        return transitions.toOwnedSlice(allocator);
    }
};

/// Parses one journal line: the zone apex and the two serials of the
/// transition. A line that does not parse is not a transition.
fn parseTransition(line: []const u8) ?Transition {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    const origin = tokens.next() orelse return null;
    const from_text = tokens.next() orelse return null;
    const to_text = tokens.next() orelse return null;
    if (tokens.next() != null) return null;
    if (origin.len == 0 or origin.len > max_origin_len) return null;
    const from_serial = std.fmt.parseInt(u32, from_text, 10) catch return null;
    const to_serial = std.fmt.parseInt(u32, to_text, 10) catch return null;
    var transition = Transition{ .from_serial = from_serial, .to_serial = to_serial };
    @memcpy(transition.origin[0..origin.len], origin);
    transition.origin_len = origin.len;
    return transition;
}

/// The journal the running server appends to. One process serves one
/// configuration with one journal, so the file lives here instead of in
/// every per-zone log.
var active: ?*Journal = null;

/// Points the running server at its journal file.
pub fn activate(journal: *Journal) void {
    active = journal;
}

/// Stops appending to the journal. The file itself is closed by its owner.
pub fn deactivate(journal: *Journal) void {
    if (active) |current| {
        if (current == journal) active = null;
    }
}

pub const DeltaLog = struct {
    from_serials: [max_deltas]u32 = undefined,
    to_serials: [max_deltas]u32 = undefined,
    len: usize = 0,
    /// The apex this log belongs to. The journal file holds the transitions
    /// of every zone, and the apex says which zone a record belongs to.
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,

    /// Names the zone this log belongs to, so a transition can be written to
    /// the journal with the zone it belongs to.
    pub fn setOrigin(self: *DeltaLog, origin: []const u8) void {
        if (origin.len == 0 or origin.len > max_origin_len) return;
        @memcpy(self.origin[0..origin.len], origin);
        self.origin_len = origin.len;
    }

    pub fn originText(self: *const DeltaLog) []const u8 {
        return self.origin[0..self.origin_len];
    }

    /// Records that the zone moved from `from_serial` to `to_serial`.
    /// Only RFC 1982 newer transitions are accepted. The transition is
    /// appended to the journal when one is active, so the log survives a
    /// restart; a journal that cannot be written does not fail the record,
    /// because the in-memory log still carries the transition.
    pub fn record(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
        try self.push(from_serial, to_serial);
        if (active) |journal| journal.append(self.originText(), from_serial, to_serial);
    }

    /// Puts a transition read from the journal file into the log without
    /// writing it back: the file is the record, and the log is its replay.
    pub fn restore(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
        try self.push(from_serial, to_serial);
    }

    fn push(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
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

test "the journal file carries a transition across a restart" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    activate(&journal);
    defer deactivate(&journal);

    var log = DeltaLog{};
    log.setOrigin("one.example.");
    try log.record(10, 11);
    journal.close();

    // A server that comes back reads the file and finds the transition.
    var reopened = try Journal.open(io, tmp.dir, "journal.log");
    defer reopened.close();
    const transitions = try reopened.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("one.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);

    var restored = DeltaLog{};
    try restored.restore(transitions[0].from_serial, transitions[0].to_serial);
    try std.testing.expect(restored.canServeIncremental(10, 11));
    try std.testing.expect(!restored.canServeIncremental(9, 11));
}

test "the journal skips a corrupt or truncated record" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "journal.log",
        .data = "one.example. 10 11\ngarbage\ntwo.example. 12\n",
    });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The good record is kept, the truncated one and the garbage are not.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("one.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);
}

test "the journal skips a torn record that has no closing newline" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A crash in the middle of an append left the last record without its
    // newline, and it reads as a complete transition.
    try tmp.dir.writeFile(io, .{
        .sub_path = "journal.log",
        .data = "one.example. 10 11\ntwo.example. 20 21",
    });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The whole record is kept, the torn one is not.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("one.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);

    // The torn transition is not known, so a client at its serial is not
    // answered incrementally.
    var restored = DeltaLog{};
    try restored.restore(transitions[0].from_serial, transitions[0].to_serial);
    try std.testing.expect(!restored.canServeIncremental(20, 21));
}
