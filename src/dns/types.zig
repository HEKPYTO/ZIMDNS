/// Contract: Defines DNS class and record-type value objects and mappings.
/// Ownership: Values are inline and hold no allocated or borrowed storage.
/// Errors: Unknown codes use typed mapping behavior; no I/O occurs.
const std = @import("std");

pub const Class = struct {
    value: u16,

    pub const IN = Class{ .value = 1 };
    pub const ANY = Class{ .value = 255 };

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
    pub const RP = RecordType{ .value = 17 };
    pub const AFSDB = RecordType{ .value = 18 };
    pub const X25 = RecordType{ .value = 19 };
    pub const ISDN = RecordType{ .value = 20 };
    pub const RT = RecordType{ .value = 21 };
    pub const TXT = RecordType{ .value = 16 };
    pub const AAAA = RecordType{ .value = 28 };
    pub const SRV = RecordType{ .value = 33 };
    pub const NAPTR = RecordType{ .value = 35 };
    pub const APL = RecordType{ .value = 42 };
    pub const SSHFP = RecordType{ .value = 44 };
    pub const TLSA = RecordType{ .value = 52 };
    pub const URI = RecordType{ .value = 256 };
    pub const SVCB = RecordType{ .value = 64 };
    pub const HTTPS = RecordType{ .value = 65 };
    pub const OPT = RecordType{ .value = 41 };
    pub const CAA = RecordType{ .value = 257 };
    pub const TSIG = RecordType{ .value = 250 };
    pub const IXFR = RecordType{ .value = 251 };
    pub const AXFR = RecordType{ .value = 252 };
    pub const DS = RecordType{ .value = 43 };
    pub const RRSIG = RecordType{ .value = 46 };
    pub const NSEC = RecordType{ .value = 47 };
    pub const DNSKEY = RecordType{ .value = 48 };
    /// RFC 8482: meta-query for some or all records at the name.
    pub const ANY = RecordType{ .value = 255 };
    pub const NSEC3 = RecordType{ .value = 50 };
    pub const ZONEMD = RecordType{ .value = 63 };
    pub const NSEC3PARAM = RecordType{ .value = 51 };

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

test "TSIG record type and ANY class use their RFC wire codes" {
    try std.testing.expectEqual(@as(u16, 250), RecordType.TSIG.code());
    try std.testing.expectEqual(RecordType.TSIG, RecordType.fromCode(250));
    try std.testing.expectEqual(@as(u16, 255), Class.ANY.code());
    try std.testing.expectEqual(Class.ANY, Class.fromCode(255));
}

test "ISDN record type uses wire code 20" {
    try std.testing.expectEqual(@as(u16, 20), RecordType.ISDN.code());
    try std.testing.expectEqual(RecordType.ISDN, RecordType.fromCode(20));
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

test "RP record type uses wire code 17" {
    try std.testing.expectEqual(@as(u16, 17), RecordType.RP.code());
    try std.testing.expectEqual(RecordType.RP, RecordType.fromCode(17));
}

test "X25 record type uses wire code 19" {
    try std.testing.expectEqual(@as(u16, 19), RecordType.X25.code());
    try std.testing.expectEqual(RecordType.X25, RecordType.fromCode(19));
}

test "RT record type uses wire code 21" {
    try std.testing.expectEqual(@as(u16, 21), RecordType.RT.code());
    try std.testing.expectEqual(RecordType.RT, RecordType.fromCode(21));
}

test "AXFR and IXFR record types use RFC 5936 and RFC 1995 wire codes" {
    try std.testing.expectEqual(@as(u16, 252), RecordType.AXFR.code());
    try std.testing.expectEqual(RecordType.AXFR, RecordType.fromCode(252));
    try std.testing.expectEqual(@as(u16, 251), RecordType.IXFR.code());
    try std.testing.expectEqual(RecordType.IXFR, RecordType.fromCode(251));
}

test "DNSSEC record types use RFC 4034 and RFC 5155 wire codes" {
    try std.testing.expectEqual(@as(u16, 43), RecordType.DS.code());
    try std.testing.expectEqual(@as(u16, 46), RecordType.RRSIG.code());
    try std.testing.expectEqual(@as(u16, 47), RecordType.NSEC.code());
    try std.testing.expectEqual(@as(u16, 48), RecordType.DNSKEY.code());
    try std.testing.expectEqual(@as(u16, 50), RecordType.NSEC3.code());
    try std.testing.expectEqual(@as(u16, 51), RecordType.NSEC3PARAM.code());
    try std.testing.expectEqual(RecordType.DNSKEY, RecordType.fromCode(48));
}

test "SVCB and HTTPS record types use RFC 9460 wire codes" {
    try std.testing.expectEqual(@as(u16, 64), RecordType.SVCB.code());
    try std.testing.expectEqual(RecordType.SVCB, RecordType.fromCode(64));
    try std.testing.expectEqual(@as(u16, 65), RecordType.HTTPS.code());
    try std.testing.expectEqual(RecordType.HTTPS, RecordType.fromCode(65));
}

test "ZONEMD record type uses RFC 8976 wire code 63" {
    try std.testing.expectEqual(@as(u16, 63), RecordType.ZONEMD.code());
    try std.testing.expectEqual(RecordType.ZONEMD, RecordType.fromCode(63));
}
