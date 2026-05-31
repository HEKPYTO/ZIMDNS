const std = @import("std");

pub const Class = struct {
    value: u16,

    pub const IN = Class{ .value = 1 };

    pub fn fromCode(value: u16) Class {
        return .{ .value = value };
    }

    pub fn code(self: Class) u16 {
        return self.value;
    }

    pub fn eql(self: Class, other: Class) bool {
        return self.value == other.value;
    }
};

pub const RecordType = struct {
    value: u16,

    pub const A = RecordType{ .value = 1 };
    pub const NS = RecordType{ .value = 2 };
    pub const CNAME = RecordType{ .value = 5 };
    pub const SOA = RecordType{ .value = 6 };
    pub const PTR = RecordType{ .value = 12 };
    pub const MX = RecordType{ .value = 15 };
    pub const TXT = RecordType{ .value = 16 };
    pub const AAAA = RecordType{ .value = 28 };
    pub const SRV = RecordType{ .value = 33 };
    pub const OPT = RecordType{ .value = 41 };
    pub const CAA = RecordType{ .value = 257 };

    pub fn fromCode(value: u16) RecordType {
        return .{ .value = value };
    }

    pub fn code(self: RecordType) u16 {
        return self.value;
    }

    pub fn eql(self: RecordType, other: RecordType) bool {
        return self.value == other.value;
    }
};

test "record type and class codes round trip for phase-one values" {
    try std.testing.expectEqual(RecordType.A, RecordType.fromCode(1));
    try std.testing.expectEqual(@as(u16, 28), RecordType.AAAA.code());
    try std.testing.expectEqual(Class.IN, Class.fromCode(1));
    try std.testing.expectEqual(@as(u16, 1), Class.IN.code());
}

test "unknown record type and class preserve raw wire codes" {
    try std.testing.expectEqual(@as(u16, 65280), RecordType.fromCode(65280).code());
    try std.testing.expectEqual(@as(u16, 1232), Class.fromCode(1232).code());
}
