pub const Class = enum(u16) {
    IN = 1,
    unknown = 0xffff,

    pub fn fromCode(value: u16) Class {
        return switch (value) {
            1 => .IN,
            else => .unknown,
        };
    }

    pub fn code(self: Class) u16 {
        return switch (self) {
            .IN => 1,
            .unknown => 0xffff,
        };
    }
};

pub const RecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    CAA = 257,
    unknown = 0xffff,

    pub fn fromCode(value: u16) RecordType {
        return switch (value) {
            1 => .A,
            2 => .NS,
            5 => .CNAME,
            6 => .SOA,
            12 => .PTR,
            15 => .MX,
            16 => .TXT,
            28 => .AAAA,
            33 => .SRV,
            41 => .OPT,
            257 => .CAA,
            else => .unknown,
        };
    }

    pub fn code(self: RecordType) u16 {
        return switch (self) {
            .A => 1,
            .NS => 2,
            .CNAME => 5,
            .SOA => 6,
            .PTR => 12,
            .MX => 15,
            .TXT => 16,
            .AAAA => 28,
            .SRV => 33,
            .OPT => 41,
            .CAA => 257,
            .unknown => 0xffff,
        };
    }
};

test "record type and class codes round trip for phase-one values" {
    const testing = @import("std").testing;
    try testing.expectEqual(RecordType.A, RecordType.fromCode(1));
    try testing.expectEqual(@as(u16, 28), RecordType.AAAA.code());
    try testing.expectEqual(Class.IN, Class.fromCode(1));
    try testing.expectEqual(@as(u16, 1), Class.IN.code());
}
