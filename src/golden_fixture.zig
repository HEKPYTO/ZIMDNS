const std = @import("std");
const Message = @import("dns/message.zig").Message;
const RecordType = @import("dns/types.zig").RecordType;
const Class = @import("dns/types.zig").Class;

const max_packet_len = 512;

pub const Error = error{
    MissingInput,
    MissingExpectation,
    BadHex,
    PacketTooLong,
    ParseFailed,
    ExpectedParseFailure,
    MismatchedId,
    MismatchedQName,
    MismatchedQType,
    MismatchedQClass,
    OutputTooSmall,
};

pub const Fixture = struct {
    input: [max_packet_len]u8 = undefined,
    input_len: usize = 0,
    response: [max_packet_len]u8 = undefined,
    response_len: usize = 0,
    expect_parse_ok: ?bool = null,
    expect_id: ?u16 = null,
    expect_qname: ?[]const u8 = null,
    expect_qtype: ?RecordType = null,
    expect_qclass: ?Class = null,

    pub fn parse(text: []const u8) !Fixture {
        var fixture = Fixture{};
        var in_hex = false;
        var in_response_hex = false;
        var in_expect = false;

        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            if (std.mem.eql(u8, line, "input_hex:")) {
                in_hex = true;
                in_response_hex = false;
                in_expect = false;
                continue;
            }
            if (std.mem.eql(u8, line, "response_hex:")) {
                in_hex = false;
                in_response_hex = true;
                in_expect = false;
                continue;
            }
            if (std.mem.eql(u8, line, "expect:")) {
                in_hex = false;
                in_response_hex = false;
                in_expect = true;
                continue;
            }

            if (in_hex) {
                try appendHexLine(&fixture.input, &fixture.input_len, line);
                continue;
            }

            if (in_response_hex) {
                try appendHexLine(&fixture.response, &fixture.response_len, line);
                continue;
            }

            if (in_expect) {
                try fixture.parseExpectation(line);
                continue;
            }
        }

        if (fixture.input_len == 0) return Error.MissingInput;
        if (fixture.expect_parse_ok == null) return Error.MissingExpectation;
        return fixture;
    }

    pub fn inputBytes(self: *const Fixture) []const u8 {
        return self.input[0..self.input_len];
    }

    pub fn responseBytes(self: *const Fixture) []const u8 {
        return self.response[0..self.response_len];
    }

    pub fn run(self: *const Fixture) !void {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        const parsed = Message.parse(arena.allocator(), self.input[0..self.input_len]) catch {
            if (self.expect_parse_ok == false) return;
            return Error.ParseFailed;
        };
        if (self.expect_parse_ok == false) return Error.ExpectedParseFailure;

        if (self.expect_id) |id| {
            if (parsed.header.id != id) return Error.MismatchedId;
        }
        if (self.expect_qname) |qname| {
            const question = parsed.question orelse return Error.MismatchedQName;
            var text_buffer: [256]u8 = undefined;
            const actual = question.name.toText(&text_buffer) catch return Error.OutputTooSmall;
            if (!std.mem.eql(u8, actual, qname)) return Error.MismatchedQName;
        }
        if (self.expect_qtype) |qtype| {
            const question = parsed.question orelse return Error.MismatchedQType;
            if (!question.qtype.eql(qtype)) return Error.MismatchedQType;
        }
        if (self.expect_qclass) |qclass| {
            const question = parsed.question orelse return Error.MismatchedQClass;
            if (!question.qclass.eql(qclass)) return Error.MismatchedQClass;
        }
    }

    fn appendHexLine(buffer: *[max_packet_len]u8, len: *usize, line: []const u8) !void {
        var parts = std.mem.tokenizeAny(u8, line, " \t");
        while (parts.next()) |part| {
            if (part.len != 2) return Error.BadHex;
            if (len.* >= max_packet_len) return Error.PacketTooLong;
            buffer[len.*] = try parseHexByte(part);
            len.* += 1;
        }
    }

    fn parseExpectation(self: *Fixture, line: []const u8) !void {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

        if (std.mem.eql(u8, key, "parse_ok")) {
            self.expect_parse_ok = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "id")) {
            self.expect_id = try parseU16(value);
        } else if (std.mem.eql(u8, key, "qname")) {
            self.expect_qname = value;
        } else if (std.mem.eql(u8, key, "qtype")) {
            self.expect_qtype = parseRecordType(value);
        } else if (std.mem.eql(u8, key, "qclass")) {
            self.expect_qclass = parseClass(value);
        }
    }
};

fn parseHexByte(text: []const u8) !u8 {
    const high = try parseHexNibble(text[0]);
    const low = try parseHexNibble(text[1]);
    return (high << 4) | low;
}

fn parseHexNibble(byte: u8) !u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => Error.BadHex,
    };
}

fn parseU16(text: []const u8) !u16 {
    if (std.mem.startsWith(u8, text, "0x")) {
        return std.fmt.parseInt(u16, text[2..], 16) catch Error.BadHex;
    }
    return std.fmt.parseInt(u16, text, 10) catch Error.BadHex;
}

fn parseRecordType(text: []const u8) RecordType {
    if (std.mem.eql(u8, text, "A")) return .A;
    if (std.mem.eql(u8, text, "AAAA")) return .AAAA;
    if (std.mem.eql(u8, text, "NS")) return .NS;
    if (std.mem.eql(u8, text, "CNAME")) return .CNAME;
    if (std.mem.eql(u8, text, "SOA")) return .SOA;
    if (std.mem.eql(u8, text, "MX")) return .MX;
    if (std.mem.eql(u8, text, "RT")) return .RT;
    if (std.mem.eql(u8, text, "SRV")) return .SRV;
    if (std.mem.eql(u8, text, "RP")) return .RP;
    if (std.mem.eql(u8, text, "AFSDB")) return .AFSDB;
    if (std.mem.eql(u8, text, "X25")) return .X25;
    if (std.mem.eql(u8, text, "ISDN")) return .ISDN;
    if (std.mem.eql(u8, text, "TXT")) return .TXT;
    if (std.mem.eql(u8, text, "SSHFP")) return .SSHFP;
    if (std.mem.eql(u8, text, "TLSA")) return .TLSA;
    if (std.mem.eql(u8, text, "NAPTR")) return .NAPTR;
    if (std.mem.eql(u8, text, "APL")) return .APL;
    if (std.mem.eql(u8, text, "URI")) return .URI;
    if (std.mem.eql(u8, text, "CAA")) return .CAA;
    return RecordType.fromCode(0xffff);
}

fn parseClass(text: []const u8) Class {
    if (std.mem.eql(u8, text, "IN")) return .IN;
    return Class.fromCode(0xffff);
}

test "golden fixture parser loads simple A query fixture" {
    const fixture_text =
        \\name: simple-a-query
        \\input_hex:
        \\  12 34 01 00 00 01 00 00 00 00 00 00
        \\  07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
        \\  00 01 00 01
        \\expect:
        \\  parse_ok: true
        \\  id: 0x1234
        \\  qname: example.com.
        \\  qtype: A
        \\  qclass: IN
        \\
    ;

    var fixture = try Fixture.parse(fixture_text);
    try fixture.run();
}
