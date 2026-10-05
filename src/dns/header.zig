/// Contract: Encodes and decodes DNS header flags, opcodes, and response codes.
/// Ownership: Header values are inline; parse borrows Reader bytes and encode borrows Writer storage.
/// Errors: Malformed wire data is reported as typed protocol errors; this module performs no I/O.
const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;

pub const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    unassigned_3 = 3,
    notify = 4,
    update = 5,
    unassigned_6 = 6,
    unassigned_7 = 7,
    unassigned_8 = 8,
    unassigned_9 = 9,
    unassigned_10 = 10,
    unassigned_11 = 11,
    unassigned_12 = 12,
    unassigned_13 = 13,
    unassigned_14 = 14,
    unassigned_15 = 15,
};

pub const Rcode = enum(u4) {
    no_error = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5,
    yxdomain = 6,
    /// Low 4 wire bits shared by RFC 7873 BADCOOKIE. A bare 7 without an
    /// accompanying OPT extended-rcode of 1 is reserved, not BADCOOKIE;
    /// use `isBadCookie`/`extendedCode` to split the two cases.
    badcookie = 7,
    nxrrset = 8,
    notauth = 9,
    notzone = 10,

    /// Full RFC 7873 extended code: OPT extended-rcode 1 + low bits 7.
    pub const BADCOOKIE_EXTENDED_CODE: u16 = 23;

    /// Combines the 4-bit header code with the OPT extended-rcode byte into
    /// the 12-bit extended RCODE. Without OPT the extended byte is zero.
    pub fn extendedCode(self: Rcode, extended_rcode: u8) u16 {
        return (@as(u16, extended_rcode) << 4) | @as(u16, @intFromEnum(self));
    }

    /// True only for extended RCODE 23: header low bits 7 plus OPT
    /// extended-rcode 1. A bare header 7 with no OPT is reserved.
    pub fn isBadCookie(self: Rcode, extended_rcode: u8) bool {
        return self == .badcookie and extended_rcode == 1;
    }
};

pub const Error = error{
    EndOfInput,
};

pub const Header = struct {
    id: u16,
    qr: bool = false,
    opcode: Opcode = .query,
    authoritative: bool = false,
    truncated: bool = false,
    recursion_desired: bool = false,
    recursion_available: bool = false,
    authenticated_data: bool = false,
    checking_disabled: bool = false,
    rcode: Rcode = .no_error,
    question_count: u16 = 0,
    answer_count: u16 = 0,
    authority_count: u16 = 0,
    additional_count: u16 = 0,

    pub fn parse(reader: *Reader) Error!Header {
        const id = reader.readU16() catch return Error.EndOfInput;
        const flags = reader.readU16() catch return Error.EndOfInput;
        const qd = reader.readU16() catch return Error.EndOfInput;
        const an = reader.readU16() catch return Error.EndOfInput;
        const ns = reader.readU16() catch return Error.EndOfInput;
        const ar = reader.readU16() catch return Error.EndOfInput;

        const opcode_code: u4 = @intCast((flags >> 11) & 0x0f);
        const opcode: Opcode = @enumFromInt(opcode_code);

        const rcode_code: u4 = @intCast(flags & 0x0f);
        const rcode = switch (rcode_code) {
            0 => Rcode.no_error,
            1 => Rcode.formerr,
            2 => Rcode.servfail,
            3 => Rcode.nxdomain,
            4 => Rcode.notimp,
            5 => Rcode.refused,
            6 => Rcode.yxdomain,
            7 => Rcode.badcookie,
            8 => Rcode.nxrrset,
            9 => Rcode.notauth,
            10 => Rcode.notzone,
            else => Rcode.servfail,
        };

        return .{
            .id = id,
            .qr = (flags & 0x8000) != 0,
            .opcode = opcode,
            .authoritative = (flags & 0x0400) != 0,
            .truncated = (flags & 0x0200) != 0,
            .recursion_desired = (flags & 0x0100) != 0,
            .recursion_available = (flags & 0x0080) != 0,
            .authenticated_data = (flags & 0x0020) != 0,
            .checking_disabled = (flags & 0x0010) != 0,
            .rcode = rcode,
            .question_count = qd,
            .answer_count = an,
            .authority_count = ns,
            .additional_count = ar,
        };
    }

    pub fn encode(self: Header, writer: *Writer) !void {
        var flags: u16 = 0;
        if (self.qr) flags |= 0x8000;
        flags |= (@as(u16, @intFromEnum(self.opcode)) & 0x0f) << 11;
        if (self.authoritative) flags |= 0x0400;
        if (self.truncated) flags |= 0x0200;
        if (self.recursion_desired) flags |= 0x0100;
        if (self.recursion_available) flags |= 0x0080;
        if (self.authenticated_data) flags |= 0x0020;
        if (self.checking_disabled) flags |= 0x0010;
        flags |= @as(u16, @intFromEnum(self.rcode)) & 0x0f;

        try writer.writeU16(self.id);
        try writer.writeU16(flags);
        try writer.writeU16(self.question_count);
        try writer.writeU16(self.answer_count);
        try writer.writeU16(self.authority_count);
        try writer.writeU16(self.additional_count);
    }
};

test "header parses standard recursive query header" {
    var reader = Reader.init(&.{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    const header = try Header.parse(&reader);
    try std.testing.expectEqual(@as(u16, 0x1234), header.id);
    try std.testing.expect(!header.qr);
    try std.testing.expectEqual(Opcode.query, header.opcode);
    try std.testing.expect(header.recursion_desired);
    try std.testing.expectEqual(@as(u16, 1), header.question_count);
}

test "header encodes response flags" {
    var buffer: [12]u8 = undefined;
    var writer = Writer.init(&buffer);
    try (Header{
        .id = 0x1234,
        .qr = true,
        .authoritative = true,
        .recursion_desired = true,
        .rcode = .nxdomain,
        .question_count = 1,
        .authority_count = 1,
    }).encode(&writer);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x85, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 }, writer.written());
}

test "header rejects short input and preserves unassigned opcode" {
    var short = Reader.init(&.{0x12});
    try std.testing.expectError(Error.EndOfInput, Header.parse(&short));

    var unsupported = Reader.init(&.{ 0x12, 0x34, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    const parsed = try Header.parse(&unsupported);
    try std.testing.expectEqual(Opcode.unassigned_15, parsed.opcode);
}

test "header round trips NXRRSET and NOTZONE" {
    var output: [12]u8 = undefined;
    var writer = Writer.init(&output);
    try (Header{ .id = 0x1234, .rcode = .nxrrset }).encode(&writer);
    try std.testing.expectEqual(@as(u8, 8), output[3] & 0x0f);
    var reader = Reader.init(&output);
    try std.testing.expectEqual(Rcode.nxrrset, (try Header.parse(&reader)).rcode);

    writer = Writer.init(&output);
    try (Header{ .id = 0x1234, .rcode = .notzone }).encode(&writer);
    try std.testing.expectEqual(@as(u8, 10), output[3] & 0x0f);
    reader = Reader.init(&output);
    try std.testing.expectEqual(Rcode.notzone, (try Header.parse(&reader)).rcode);
}

test "header splits bare RCODE 7 from extended BADCOOKIE 23" {
    try std.testing.expectEqual(@as(u16, 23), Rcode.BADCOOKIE_EXTENDED_CODE);
    // Bare header 7 with no OPT extended byte is reserved, not BADCOOKIE.
    try std.testing.expect(!(Rcode.badcookie.isBadCookie(0)));
    try std.testing.expectEqual(@as(u16, 7), Rcode.badcookie.extendedCode(0));
    // Header 7 plus OPT extended-rcode 1 is BADCOOKIE (23).
    try std.testing.expect(Rcode.badcookie.isBadCookie(1));
    try std.testing.expectEqual(@as(u16, 23), Rcode.badcookie.extendedCode(1));
    try std.testing.expect(!Rcode.servfail.isBadCookie(1));
}

test "header round trips NOTAUTH" {
    var output: [12]u8 = undefined;
    var writer = Writer.init(&output);
    try (Header{ .id = 0x1234, .rcode = .notauth }).encode(&writer);
    try std.testing.expectEqual(@as(u8, 9), output[3] & 0x0f);
    var reader = Reader.init(&output);
    try std.testing.expectEqual(Rcode.notauth, (try Header.parse(&reader)).rcode);
}
