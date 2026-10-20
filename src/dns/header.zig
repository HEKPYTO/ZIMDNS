/// Contract: Encodes and decodes DNS header flags, opcodes, and response codes.
/// Ownership: Header values are inline; parse borrows Reader bytes and encode borrows Writer storage.
/// Errors: Malformed wire data is reported as typed protocol errors; this module performs no I/O.
const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;

/// The flag bits of the header flags word, RFC 1035 section 4.1.1. AD and
/// CD are two of the three bits the Z field reserved; RFC 4035 section 3.1.6
/// and section 3.2.2 give their meaning, and the third Z bit stays reserved.
pub const Flags = struct {
    pub const qr: u16 = 0x8000;
    pub const aa: u16 = 0x0400;
    pub const tc: u16 = 0x0200;
    pub const rd: u16 = 0x0100;
    pub const ra: u16 = 0x0080;
    /// RFC 1035 section 4.1.1: the Z bit, reserved for future use.
    pub const reserved: u16 = 0x0040;
    /// RFC 4035 section 3.1.6: the AD bit.
    pub const ad: u16 = 0x0020;
    /// RFC 4035 section 3.2.2: the CD bit.
    pub const cd: u16 = 0x0010;
    /// The RCODE field, the low four bits of the flags word.
    pub const rcode: u16 = 0x000f;
};

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
        return (@as(u16, extended_rcode) << 4) | @as(u16, @backingInt(self));
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
    /// RFC 1035 section 4.1.1: the Z bit, reserved for future use. It must
    /// be zero in every query and every response, so a received value is
    /// recorded here and `encode` never writes it.
    reserved: bool = false,
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
        const opcode: Opcode = @fromBackingInt(@intCast(opcode_code));

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
            .qr = (flags & Flags.qr) != 0,
            .opcode = opcode,
            .authoritative = (flags & Flags.aa) != 0,
            .truncated = (flags & Flags.tc) != 0,
            .recursion_desired = (flags & Flags.rd) != 0,
            .recursion_available = (flags & Flags.ra) != 0,
            .authenticated_data = (flags & Flags.ad) != 0,
            .checking_disabled = (flags & Flags.cd) != 0,
            .reserved = (flags & Flags.reserved) != 0,
            .rcode = rcode,
            .question_count = qd,
            .answer_count = an,
            .authority_count = ns,
            .additional_count = ar,
        };
    }

    pub fn encode(self: Header, writer: *Writer) !void {
        var flags: u16 = 0;
        if (self.qr) flags |= Flags.qr;
        flags |= (@as(u16, @backingInt(self.opcode)) & 0x0f) << 11;
        if (self.authoritative) flags |= Flags.aa;
        if (self.truncated) flags |= Flags.tc;
        if (self.recursion_desired) flags |= Flags.rd;
        if (self.recursion_available) flags |= Flags.ra;
        if (self.authenticated_data) flags |= Flags.ad;
        if (self.checking_disabled) flags |= Flags.cd;
        // RFC 1035 section 4.1.1: the Z bit must be zero in all queries and
        // responses, so the reserved bit is never written.
        flags |= @as(u16, @backingInt(self.rcode)) & Flags.rcode;

        try writer.writeU16(self.id);
        try writer.writeU16(flags);
        try writer.writeU16(self.question_count);
        try writer.writeU16(self.answer_count);
        try writer.writeU16(self.authority_count);
        try writer.writeU16(self.additional_count);
    }
};

/// The flag bits of a response that the request does not supply. This is the
/// one place the response header flags are decided, so the AD, CD, and Z
/// rules are stated once.
pub const ResponseFlags = struct {
    /// AA, RFC 1035 section 4.1.1.
    authoritative: bool = false,
    /// TC, RFC 1035 section 4.1.1.
    truncated: bool = false,
    /// RA, RFC 1035 section 4.1.1.
    recursion_available: bool = false,
    /// AD, RFC 4035 section 3.1.6: set only when every RRset in the answer
    /// and authority sections is authentic, so a validated answer carries it
    /// and an authoritative one never does.
    authenticated_data: bool = false,
    /// RCODE, RFC 1035 section 4.1.1.
    rcode: Rcode = .no_error,

    /// The response header for `request`: QR set, OPCODE and RD copied from
    /// the request, CD copied from the request (RFC 4035 section 3.2.2), and
    /// the reserved Z bit never copied (RFC 1035 section 4.1.1). RFC 4035
    /// section 3.1.6 only recommends clearing CD in an authoritative
    /// response; the copy is kept because this server never validates.
    pub fn header(self: ResponseFlags, request: Header) Header {
        return .{
            .id = request.id,
            .qr = true,
            .opcode = request.opcode,
            .authoritative = self.authoritative,
            .truncated = self.truncated,
            .recursion_desired = request.recursion_desired,
            .recursion_available = self.recursion_available,
            .authenticated_data = self.authenticated_data,
            .checking_disabled = request.checking_disabled,
            .reserved = false,
            .rcode = self.rcode,
        };
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

test "the reserved Z bit is parsed but never encoded" {
    // RFC 1035 section 4.1.1: the Z bit must be zero in all queries and
    // responses, so a received value is recorded and never written back.
    var reader = Reader.init(&.{ 0x12, 0x34, 0x01, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    const parsed = try Header.parse(&reader);
    try std.testing.expect(parsed.reserved);

    var output: [12]u8 = undefined;
    var writer = Writer.init(&output);
    try (Header{ .id = 0x1234, .reserved = true }).encode(&writer);
    const flags = std.mem.readInt(u16, output[2..4], .big);
    try std.testing.expectEqual(@as(u16, 0), flags & Flags.reserved);
}

test "the response flag policy copies CD and clears the reserved bit" {
    const request = Header{
        .id = 0x1234,
        .opcode = .query,
        .recursion_desired = true,
        .authenticated_data = true,
        .checking_disabled = true,
        .reserved = true,
    };
    const response = (ResponseFlags{ .authoritative = true, .recursion_available = true }).header(request);
    try std.testing.expect(response.qr);
    try std.testing.expectEqual(Opcode.query, response.opcode);
    try std.testing.expect(response.recursion_desired);
    try std.testing.expect(response.authoritative);
    try std.testing.expect(response.recursion_available);
    // RFC 4035 section 3.1.6: AD is the responder's own claim that the
    // answer was authenticated, never a bit copied from the query.
    try std.testing.expect(!response.authenticated_data);
    // RFC 4035 section 3.2.2: the CD bit of the query is copied.
    try std.testing.expect(response.checking_disabled);
    // RFC 1035 section 4.1.1: the reserved Z bit is never copied.
    try std.testing.expect(!response.reserved);
}
