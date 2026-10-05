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
