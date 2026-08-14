/// Contract: Defines DNS class and record-type value objects and mappings.
/// Ownership: Values are inline and hold no allocated or borrowed storage.
/// Errors: Unknown codes use typed mapping behavior; no I/O occurs.
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
    pub const DNAME = RecordType{ .value = 39 };
    pub const SOA = RecordType{ .value = 6 };
    pub const PTR = RecordType{ .value = 12 };
    pub const MX = RecordType{ .value = 15 };
    pub const AFSDB = RecordType{ .value = 18 };
    pub const TXT = RecordType{ .value = 16 };
    pub const AAAA = RecordType{ .value = 28 };
    pub const SRV = RecordType{ .value = 33 };
    pub const NAPTR = RecordType{ .value = 35 };
    pub const APL = RecordType{ .value = 42 };
    pub const SSHFP = RecordType{ .value = 44 };
    pub const TLSA = RecordType{ .value = 52 };
    pub const URI = RecordType{ .value = 256 };
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

test "SSHFP record type uses wire code 44" {
    try std.testing.expectEqual(@as(u16, 44), RecordType.SSHFP.code());
    try std.testing.expectEqual(RecordType.SSHFP, RecordType.fromCode(44));
}

test "TLSA record type uses wire code 52" {
    try std.testing.expectEqual(@as(u16, 52), RecordType.TLSA.code());
    try std.testing.expectEqual(RecordType.TLSA, RecordType.fromCode(52));
}

test "URI record type uses wire code 256" {
    try std.testing.expectEqual(@as(u16, 256), RecordType.URI.code());
    try std.testing.expectEqual(RecordType.URI, RecordType.fromCode(256));
}

test "NAPTR record type uses wire code 35" {
    try std.testing.expectEqual(@as(u16, 35), RecordType.NAPTR.code());
    try std.testing.expectEqual(RecordType.NAPTR, RecordType.fromCode(35));
}

test "APL record type uses wire code 42" {
    try std.testing.expectEqual(@as(u16, 42), RecordType.APL.code());
    try std.testing.expectEqual(RecordType.APL, RecordType.fromCode(42));
}

test "AFSDB record type uses wire code 18" {
    try std.testing.expectEqual(@as(u16, 18), RecordType.AFSDB.code());
    try std.testing.expectEqual(RecordType.AFSDB, RecordType.fromCode(18));
}
