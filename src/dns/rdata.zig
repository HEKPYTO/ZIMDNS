/// Contract: Parses and encodes supported DNS RDATA and EDNS option payloads.
/// Ownership: RDATA values own inline bounded bytes; input message and Writer storage are borrowed.
/// Errors: RDATA and option violations are typed; transport/file I/O is not handled here.
const std = @import("std");
const Writer = @import("writer.zig").Writer;
const CompressionTable = @import("writer.zig").CompressionTable;
const Name = @import("name.zig").Name;
const RecordType = @import("types.zig").RecordType;

const max_txt_len = 255;
const max_unknown_len = 512;
const max_opt_data_len = 512;
const max_caa_tag_len = 32;
const max_caa_value_len = 255;

pub const Error = error{
    EndOfInput,
    InvalidLength,
    TrailingData,
    TextTooLong,
    UnknownTooLong,
    CaaTagTooLong,
    CaaValueTooLong,
    BadName,
    MalformedOption,
    OptionsTooLong,
};

pub const Soa = struct {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const Mx = struct {
    preference: u16,
    exchange: Name,
};

pub const Srv = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
};

pub const Caa = struct {
    flags: u8,
    tag: [max_caa_tag_len]u8 = undefined,
    tag_len: u8 = 0,
    value: [max_caa_value_len]u8 = undefined,
    value_len: u8 = 0,

    pub fn tagText(self: *const Caa) []const u8 {
        return self.tag[0..self.tag_len];
    }

    pub fn valueText(self: *const Caa) []const u8 {
        return self.value[0..self.value_len];
    }
};

pub const Txt = struct {
    data: [max_txt_len]u8 = undefined,
    len: u8 = 0,

    pub fn text(self: *const Txt) []const u8 {
        return self.data[0..self.len];
    }
};

pub const Unknown = struct {
    data: [max_unknown_len]u8 = undefined,
    len: u16 = 0,

    pub fn bytes(self: *const Unknown) []const u8 {
        return self.data[0..self.len];
    }
};

pub const Opt = struct {
    data: [max_opt_data_len]u8 = undefined,
    len: u16 = 0,

    pub fn bytes(self: *const Opt) []const u8 {
        return self.data[0..self.len];
    }
};

pub const RData = union(enum) {
    A: [4]u8,
    AAAA: [16]u8,
    NS: Name,
    SOA: Soa,
    CNAME: Name,
    PTR: Name,
    MX: Mx,
    TXT: Txt,
    SRV: Srv,
    CAA: Caa,
    OPT: Opt,
    Unknown: Unknown,

    pub fn parse(rrtype: RecordType, message: []const u8, offset: usize, len: usize) Error!RData {
        if (offset > message.len or message.len - offset < len) return Error.EndOfInput;
        const end = offset + len;
        return switch (rrtype.code()) {
            RecordType.A.value => blk: {
                if (len != 4) return Error.InvalidLength;
                var bytes: [4]u8 = undefined;
                @memcpy(&bytes, message[offset..end]);
                break :blk .{ .A = bytes };
            },
            RecordType.AAAA.value => blk: {
                if (len != 16) return Error.InvalidLength;
                var bytes: [16]u8 = undefined;
                @memcpy(&bytes, message[offset..end]);
                break :blk .{ .AAAA = bytes };
            },
            RecordType.NS.value => .{ .NS = try parseNameOnly(message, offset, end) },
            RecordType.CNAME.value => .{ .CNAME = try parseNameOnly(message, offset, end) },
            RecordType.PTR.value => .{ .PTR = try parseNameOnly(message, offset, end) },
            RecordType.SOA.value => blk: {
                const mname_result = Name.parse(message, offset) catch return Error.BadName;
                const rname_result = Name.parse(message, mname_result.next_offset) catch return Error.BadName;
                if (end - rname_result.next_offset != 20) return Error.InvalidLength;
                var reader = @import("reader.zig").Reader.init(message[rname_result.next_offset..end]);
                break :blk .{ .SOA = .{
                    .mname = mname_result.name,
                    .rname = rname_result.name,
                    .serial = reader.readU32() catch return Error.EndOfInput,
                    .refresh = reader.readU32() catch return Error.EndOfInput,
                    .retry = reader.readU32() catch return Error.EndOfInput,
                    .expire = reader.readU32() catch return Error.EndOfInput,
                    .minimum = reader.readU32() catch return Error.EndOfInput,
                } };
            },
            RecordType.MX.value => blk: {
                if (len < 3) return Error.InvalidLength;
                const preference = std.mem.readInt(u16, message[offset..][0..2], .big);
                const exchange_result = Name.parse(message, offset + 2) catch return Error.BadName;
                if (exchange_result.next_offset != end) return Error.TrailingData;
                break :blk .{ .MX = .{ .preference = preference, .exchange = exchange_result.name } };
            },
            RecordType.SRV.value => blk: {
                if (len < 7) return Error.InvalidLength;
                const priority = std.mem.readInt(u16, message[offset..][0..2], .big);
                const weight = std.mem.readInt(u16, message[offset + 2 ..][0..2], .big);
                const port = std.mem.readInt(u16, message[offset + 4 ..][0..2], .big);
                const target_result = Name.parse(message, offset + 6) catch return Error.BadName;
                if (target_result.next_offset != end) return Error.TrailingData;
                break :blk .{ .SRV = .{
                    .priority = priority,
                    .weight = weight,
                    .port = port,
                    .target = target_result.name,
                } };
            },
            RecordType.TXT.value => blk: {
                if (len == 0) return Error.InvalidLength;
                const text_len = message[offset];
                if (text_len > max_txt_len) return Error.TextTooLong;
                if (@as(usize, text_len) + 1 != len) return Error.InvalidLength;
                var txt = Txt{ .len = text_len };
                @memcpy(txt.data[0..text_len], message[offset + 1 .. end]);
                break :blk .{ .TXT = txt };
            },
            RecordType.CAA.value => blk: {
                if (len < 2) return Error.InvalidLength;
                const flags = message[offset];
                const tag_len = message[offset + 1];
                if (tag_len > max_caa_tag_len) return Error.CaaTagTooLong;
                if (2 + @as(usize, tag_len) > len) return Error.InvalidLength;
                const value_len = len - 2 - tag_len;
                if (value_len > max_caa_value_len) return Error.CaaValueTooLong;
                var caa = Caa{
                    .flags = flags,
                    .tag_len = tag_len,
                    .value_len = @intCast(value_len),
                };
                @memcpy(caa.tag[0..tag_len], message[offset + 2 .. offset + 2 + tag_len]);
                @memcpy(caa.value[0..value_len], message[offset + 2 + tag_len .. end]);
                break :blk .{ .CAA = caa };
            },
            RecordType.OPT.value => blk: {
                if (len > max_opt_data_len) return Error.OptionsTooLong;
                var opt = Opt{ .len = @intCast(len) };
                @memcpy(opt.data[0..len], message[offset..end]);
                var option_offset: usize = 0;
                while (option_offset < len) {
                    if (len - option_offset < 4) return Error.MalformedOption;
                    const option_len = std.mem.readInt(u16, opt.data[option_offset + 2 ..][0..2], .big);
                    option_offset += 4;
                    if (option_len > len - option_offset) return Error.MalformedOption;
                    option_offset += option_len;
                }
                break :blk .{ .OPT = opt };
            },
            else => blk: {
                if (len > max_unknown_len) return Error.UnknownTooLong;
                var unknown = Unknown{ .len = @intCast(len) };
                @memcpy(unknown.data[0..len], message[offset..end]);
                break :blk .{ .Unknown = unknown };
            },
        };
    }

    pub fn encode(self: RData, writer: *Writer) !void {
        switch (self) {
            .A => |bytes| try writer.writeBytes(&bytes),
            .AAAA => |bytes| try writer.writeBytes(&bytes),
            .NS, .CNAME, .PTR => |name| try name.encode(writer),
            .SOA => |soa| {
                try soa.mname.encode(writer);
                try soa.rname.encode(writer);
                try writer.writeU32(soa.serial);
                try writer.writeU32(soa.refresh);
                try writer.writeU32(soa.retry);
                try writer.writeU32(soa.expire);
                try writer.writeU32(soa.minimum);
            },
            .MX => |mx| {
                try writer.writeU16(mx.preference);
                try mx.exchange.encode(writer);
            },
            .SRV => |srv| {
                try writer.writeU16(srv.priority);
                try writer.writeU16(srv.weight);
                try writer.writeU16(srv.port);
                try srv.target.encode(writer);
            },
            .TXT => |txt| {
                try writer.writeU8(txt.len);
                try writer.writeBytes(txt.text());
            },
            .CAA => |caa| {
                try writer.writeU8(caa.flags);
                try writer.writeU8(caa.tag_len);
                try writer.writeBytes(caa.tagText());
                try writer.writeBytes(caa.valueText());
            },
            .OPT => |opt| try writer.writeBytes(opt.bytes()),
            .Unknown => |unknown| try writer.writeBytes(unknown.bytes()),
        }
    }

    pub fn encodeCompressed(self: RData, writer: *Writer, table: *CompressionTable) !void {
        switch (self) {
            .A => |bytes| try writer.writeBytes(&bytes),
            .AAAA => |bytes| try writer.writeBytes(&bytes),
            .NS, .CNAME, .PTR => |name| try table.writeName(writer, name.asWire()),
            .SOA => |soa| {
                try table.writeName(writer, soa.mname.asWire());
                try table.writeName(writer, soa.rname.asWire());
                try writer.writeU32(soa.serial);
                try writer.writeU32(soa.refresh);
                try writer.writeU32(soa.retry);
                try writer.writeU32(soa.expire);
                try writer.writeU32(soa.minimum);
            },
            .MX => |mx| {
                try writer.writeU16(mx.preference);
                try table.writeName(writer, mx.exchange.asWire());
            },
            .SRV => |srv| {
                try writer.writeU16(srv.priority);
                try writer.writeU16(srv.weight);
                try writer.writeU16(srv.port);
                try table.writeName(writer, srv.target.asWire());
            },
            .TXT => |txt| {
                try writer.writeU8(txt.len);
                try writer.writeBytes(txt.text());
            },
            .CAA => |caa| {
                try writer.writeU8(caa.flags);
                try writer.writeU8(caa.tag_len);
                try writer.writeBytes(caa.tagText());
                try writer.writeBytes(caa.valueText());
            },
            .OPT => |opt| try writer.writeBytes(opt.bytes()),
            .Unknown => |unknown| try writer.writeBytes(unknown.bytes()),
        }
    }
};

fn parseNameOnly(message: []const u8, offset: usize, end: usize) Error!Name {
    const result = Name.parse(message, offset) catch return Error.BadName;
    if (result.next_offset != end) return Error.TrailingData;
    return result.name;
}

test "rdata parses and encodes A and AAAA records" {
    const a = try RData.parse(.A, &.{ 192, 0, 2, 1 }, 0, 4);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &a.A);

    var a_out: [4]u8 = undefined;
    var a_writer = Writer.init(&a_out);
    try a.encode(&a_writer);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, a_writer.written());

    const aaaa_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const aaaa = try RData.parse(.AAAA, &aaaa_bytes, 0, aaaa_bytes.len);
    try std.testing.expectEqualSlices(u8, &aaaa_bytes, &aaaa.AAAA);
}

test "rdata parses compressed domain-name records" {
    const message = [_]u8{
        7, 'e', 'x', 'a',  'm',  'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        2, 'n', 's', 0xc0, 0x00,
    };
    const ns = try RData.parse(.NS, &message, 13, 5);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("ns.example.com.", try ns.NS.toText(&text));
}

test "rdata parses and encodes MX and TXT records" {
    const mx_message = [_]u8{
        0x00, 0x0a,
        4,    'm',
        'a',  'i',
        'l',  7,
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  0,
    };
    const mx = try RData.parse(.MX, &mx_message, 0, mx_message.len);
    try std.testing.expectEqual(@as(u16, 10), mx.MX.preference);

    const txt = try RData.parse(.TXT, &.{ 5, 'h', 'e', 'l', 'l', 'o' }, 0, 6);
    try std.testing.expectEqualStrings("hello", txt.TXT.text());

    var txt_out: [8]u8 = undefined;
    var txt_writer = Writer.init(&txt_out);
    try txt.encode(&txt_writer);
    try std.testing.expectEqualSlices(u8, &.{ 5, 'h', 'e', 'l', 'l', 'o' }, txt_writer.written());
}

test "rdata parses SOA, SRV, and CAA records" {
    const soa_message = [_]u8{
        3,    'n',  's',  '1',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  0,
        10,   'h',  'o',  's',  't',  'm',  'a',  's',  't',  'e',  'r',  0xc0, 0x04,
        0x78, 0xb2, 0xd0, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x03, 0x84, 0x00,
        0x12, 0x75, 0x00, 0x00, 0x00, 0x0e, 0x10,
    };
    const soa = try RData.parse(.SOA, &soa_message, 0, soa_message.len);
    try std.testing.expectEqual(@as(u32, 2024984577), soa.SOA.serial);

    const srv_message = [_]u8{
        0x00, 0x0a,
        0x00, 0x14,
        0x20, 0xfb,
        3,    's',
        'i',  'p',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        0,
    };
    const srv = try RData.parse(.SRV, &srv_message, 0, srv_message.len);
    try std.testing.expectEqual(@as(u16, 10), srv.SRV.priority);
    try std.testing.expectEqual(@as(u16, 8443), srv.SRV.port);

    const caa_message = [_]u8{ 0, 5, 'i', 's', 's', 'u', 'e', 'l', 'e', 't', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't' };
    const caa = try RData.parse(.CAA, &caa_message, 0, caa_message.len);
    try std.testing.expectEqual(@as(u8, 0), caa.CAA.flags);
    try std.testing.expectEqualStrings("issue", caa.CAA.tagText());
    try std.testing.expectEqualStrings("letsencrypt", caa.CAA.valueText());
}

test "rdata preserves unknown record bytes" {
    const unknown = try RData.parse(RecordType.fromCode(65280), &.{ 1, 2, 3, 4 }, 0, 4);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, unknown.Unknown.bytes());
}

test "rdata validates and round trips bounded EDNS options" {
    const bytes = [_]u8{ 0xea, 0x60, 0x00, 0x03, 0x01, 0x02, 0x03 };
    const opt = try RData.parse(.OPT, &bytes, 0, bytes.len);
    var output: [16]u8 = undefined;
    var writer = Writer.init(&output);
    try opt.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
    try std.testing.expectError(Error.MalformedOption, RData.parse(.OPT, &.{ 0xea, 0x60, 0x00, 0x04, 0x01, 0x02, 0x03 }, 0, 7));
}
