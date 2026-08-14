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
const max_caa_payload_len = max_unknown_len - 2;
const max_sshfp_fingerprint_len = 32;
const max_tlsa_association_len = 509;
const max_uri_target_len = 508;

pub fn validSshfp(algorithm: u8, fingerprint_type: u8, fingerprint_len: usize) bool {
    const valid_algorithm = switch (algorithm) {
        1, 2, 3, 4, 6 => true,
        else => false,
    };
    const expected_len: usize = switch (fingerprint_type) {
        1 => 20,
        2 => 32,
        else => return false,
    };
    return valid_algorithm and fingerprint_len == expected_len;
}

pub fn validTlsa(usage: u8, selector: u8, matching_type: u8, association_len: usize) bool {
    if (usage > 3 or selector > 1) return false;
    return switch (matching_type) {
        0 => association_len > 0 and association_len <= max_tlsa_association_len,
        1 => association_len == 32,
        2 => association_len == 64,
        else => false,
    };
}

pub const Error = error{
    EndOfInput,
    InvalidLength,
    TrailingData,
    TextTooLong,
    UnknownTooLong,
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
    payload: [max_caa_payload_len]u8 = undefined,
    tag_len: u8 = 0,
    payload_len: u16 = 0,

    pub fn init(flags: u8, tag: []const u8, value: []const u8) Error!Caa {
        if ((flags != 0 and flags != 128) or tag.len == 0 or tag.len > std.math.maxInt(u8)) {
            return Error.InvalidLength;
        }
        if (value.len > max_caa_payload_len - tag.len) return Error.InvalidLength;
        for (tag) |byte| {
            if (!std.ascii.isAlphanumeric(byte)) return Error.InvalidLength;
        }

        var caa = Caa{
            .flags = flags,
            .tag_len = @intCast(tag.len),
            .payload_len = @intCast(tag.len + value.len),
        };
        @memcpy(caa.payload[0..tag.len], tag);
        @memcpy(caa.payload[tag.len .. tag.len + value.len], value);
        return caa;
    }

    pub fn tagText(self: *const Caa) []const u8 {
        return self.payload[0..self.tag_len];
    }

    pub fn valueText(self: *const Caa) []const u8 {
        return self.payload[self.tag_len..self.payload_len];
    }
};

pub const Sshfp = struct {
    algorithm: u8,
    fingerprint_type: u8,
    fingerprint: [max_sshfp_fingerprint_len]u8 = undefined,
    fingerprint_len: u8 = 0,

    pub fn fingerprintBytes(self: *const Sshfp) []const u8 {
        return self.fingerprint[0..self.fingerprint_len];
    }
};

pub const Tlsa = struct {
    usage: u8,
    selector: u8,
    matching_type: u8,
    association: [max_tlsa_association_len]u8 = undefined,
    association_len: u16 = 0,
};

pub const Uri = struct {
    priority: u16,
    weight: u16,
    target: [max_uri_target_len]u8 = undefined,
    target_len: u16 = 0,

    pub fn targetBytes(self: *const Uri) []const u8 {
        return self.target[0..self.target_len];
    }
};

pub const Naptr = struct {
    order: u16,
    preference: u16,
    flags: [max_txt_len]u8 = undefined,
    flags_len: u8 = 0,
    services: [max_txt_len]u8 = undefined,
    services_len: u8 = 0,
    regexp: [max_txt_len]u8 = undefined,
    regexp_len: u8 = 0,
    replacement: Name,

    pub fn flagsText(self: *const Naptr) []const u8 {
        return self.flags[0..self.flags_len];
    }

    pub fn servicesText(self: *const Naptr) []const u8 {
        return self.services[0..self.services_len];
    }

    pub fn regexpText(self: *const Naptr) []const u8 {
        return self.regexp[0..self.regexp_len];
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
    DNAME: Name,
    PTR: Name,
    MX: Mx,
    AFSDB: Mx,
    TXT: Txt,
    SRV: Srv,
    NAPTR: Naptr,
    APL: Unknown,
    CAA: Caa,
    SSHFP: Sshfp,
    TLSA: Tlsa,
    URI: Uri,
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
            RecordType.DNAME.value => .{ .DNAME = try parseUncompressedNameOnly(message, offset, end) },
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
            RecordType.AFSDB.value => blk: {
                if (len < 3) return Error.InvalidLength;
                const subtype = std.mem.readInt(u16, message[offset..][0..2], .big);
                const hostname_result = Name.parse(message, offset + 2) catch return Error.BadName;
                if (hostname_result.next_offset != end) return Error.TrailingData;
                break :blk .{ .AFSDB = .{ .preference = subtype, .exchange = hostname_result.name } };
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
            RecordType.NAPTR.value => .{ .NAPTR = try parseNaptr(message, offset, end) },
            RecordType.APL.value => blk: {
                if (len > max_unknown_len) return Error.UnknownTooLong;
                try parseApl(message, offset, end);
                var apl = Unknown{ .len = @intCast(len) };
                @memcpy(apl.data[0..len], message[offset..end]);
                break :blk .{ .APL = apl };
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
                if (len < 3 or len > max_unknown_len) return Error.InvalidLength;
                const tag_len = message[offset + 1];
                if (tag_len == 0 or @as(usize, tag_len) > len - 2) return Error.InvalidLength;
                const tag_end = offset + 2 + tag_len;
                break :blk .{ .CAA = Caa.init(
                    message[offset],
                    message[offset + 2 .. tag_end],
                    message[tag_end..end],
                ) catch return Error.InvalidLength };
            },
            RecordType.SSHFP.value => blk: {
                if (len < 2) return Error.InvalidLength;
                const algorithm = message[offset];
                const fingerprint_type = message[offset + 1];
                const fingerprint_len = len - 2;
                if (!validSshfp(algorithm, fingerprint_type, fingerprint_len)) return Error.InvalidLength;
                var sshfp = Sshfp{
                    .algorithm = algorithm,
                    .fingerprint_type = fingerprint_type,
                    .fingerprint_len = @intCast(fingerprint_len),
                };
                @memcpy(sshfp.fingerprint[0..fingerprint_len], message[offset + 2 .. end]);
                break :blk .{ .SSHFP = sshfp };
            },
            RecordType.TLSA.value => blk: {
                if (len < 3) return Error.InvalidLength;
                const usage = message[offset];
                const selector = message[offset + 1];
                const matching_type = message[offset + 2];
                const association_len = len - 3;
                if (!validTlsa(usage, selector, matching_type, association_len)) return Error.InvalidLength;
                var tlsa = Tlsa{
                    .usage = usage,
                    .selector = selector,
                    .matching_type = matching_type,
                    .association_len = @intCast(association_len),
                };
                @memcpy(tlsa.association[0..association_len], message[offset + 3 .. end]);
                break :blk .{ .TLSA = tlsa };
            },
            RecordType.URI.value => blk: {
                if (len < 5 or len > 4 + max_uri_target_len) return Error.InvalidLength;
                const priority = std.mem.readInt(u16, message[offset..][0..2], .big);
                const weight = std.mem.readInt(u16, message[offset + 2 ..][0..2], .big);
                const target_len = len - 4;
                var uri = Uri{
                    .priority = priority,
                    .weight = weight,
                    .target_len = @intCast(target_len),
                };
                @memcpy(uri.target[0..target_len], message[offset + 4 .. end]);
                break :blk .{ .URI = uri };
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
            .NS, .CNAME, .DNAME, .PTR => |name| try name.encode(writer),
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
            .AFSDB => |afsdb| {
                try writer.writeU16(afsdb.preference);
                try afsdb.exchange.encode(writer);
            },
            .SRV => |srv| {
                try writer.writeU16(srv.priority);
                try writer.writeU16(srv.weight);
                try writer.writeU16(srv.port);
                try srv.target.encode(writer);
            },
            .NAPTR => |naptr| {
                try writer.writeU16(naptr.order);
                try writer.writeU16(naptr.preference);
                try writer.writeU8(naptr.flags_len);
                try writer.writeBytes(naptr.flagsText());
                try writer.writeU8(naptr.services_len);
                try writer.writeBytes(naptr.servicesText());
                try writer.writeU8(naptr.regexp_len);
                try writer.writeBytes(naptr.regexpText());
                try naptr.replacement.encode(writer);
            },
            .APL => |apl| try writer.writeBytes(apl.bytes()),
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
            .SSHFP => |sshfp| {
                try writer.writeU8(sshfp.algorithm);
                try writer.writeU8(sshfp.fingerprint_type);
                try writer.writeBytes(sshfp.fingerprintBytes());
            },
            .TLSA => |tlsa| {
                try writer.writeU8(tlsa.usage);
                try writer.writeU8(tlsa.selector);
                try writer.writeU8(tlsa.matching_type);
                try writer.writeBytes(tlsa.association[0..tlsa.association_len]);
            },
            .URI => |uri| {
                try writer.writeU16(uri.priority);
                try writer.writeU16(uri.weight);
                try writer.writeBytes(uri.targetBytes());
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
            .DNAME => |name| try name.encode(writer),
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
            .AFSDB => |afsdb| {
                try writer.writeU16(afsdb.preference);
                try table.writeName(writer, afsdb.exchange.asWire());
            },
            .SRV => |srv| {
                try writer.writeU16(srv.priority);
                try writer.writeU16(srv.weight);
                try writer.writeU16(srv.port);
                try table.writeName(writer, srv.target.asWire());
            },
            .NAPTR => |naptr| {
                try writer.writeU16(naptr.order);
                try writer.writeU16(naptr.preference);
                try writer.writeU8(naptr.flags_len);
                try writer.writeBytes(naptr.flagsText());
                try writer.writeU8(naptr.services_len);
                try writer.writeBytes(naptr.servicesText());
                try writer.writeU8(naptr.regexp_len);
                try writer.writeBytes(naptr.regexpText());
                try naptr.replacement.encode(writer);
            },
            .APL => |apl| try writer.writeBytes(apl.bytes()),
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
            .SSHFP => |sshfp| {
                try writer.writeU8(sshfp.algorithm);
                try writer.writeU8(sshfp.fingerprint_type);
                try writer.writeBytes(sshfp.fingerprintBytes());
            },
            .TLSA => |tlsa| {
                try writer.writeU8(tlsa.usage);
                try writer.writeU8(tlsa.selector);
                try writer.writeU8(tlsa.matching_type);
                try writer.writeBytes(tlsa.association[0..tlsa.association_len]);
            },
            .URI => |uri| {
                try writer.writeU16(uri.priority);
                try writer.writeU16(uri.weight);
                try writer.writeBytes(uri.targetBytes());
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

fn parseApl(message: []const u8, offset: usize, end: usize) Error!void {
    var cursor = offset;
    while (cursor < end) {
        if (end - cursor < 4) return Error.EndOfInput;

        const afi = std.mem.readInt(u16, message[cursor..][0..2], .big);
        const prefix = message[cursor + 2];
        const afdlen = message[cursor + 3] & 0x7f;
        const max_prefix: u8 = switch (afi) {
            1 => 32,
            2 => 128,
            else => return Error.InvalidLength,
        };
        const max_afdlen: u8 = if (afi == 1) 4 else 16;
        if (prefix > max_prefix or afdlen > max_afdlen) return Error.InvalidLength;

        const required_len = (@as(usize, prefix) + 7) / 8;
        if (@as(usize, afdlen) > required_len) return Error.InvalidLength;

        cursor += 4;
        if (@as(usize, afdlen) > end - cursor) return Error.EndOfInput;
        if (afdlen != 0) {
            const last = message[cursor + afdlen - 1];
            if (last == 0) return Error.InvalidLength;
            if (@as(usize, afdlen) * 8 >= prefix and prefix % 8 != 0) {
                const padding_bits: u3 = @intCast(8 - prefix % 8);
                const padding_mask: u8 = (@as(u8, 1) << padding_bits) - 1;
                if (last & padding_mask != 0) return Error.InvalidLength;
            }
        }
        cursor += afdlen;
    }
}

fn parseNaptr(message: []const u8, offset: usize, end: usize) Error!Naptr {
    if (end - offset > max_unknown_len) return Error.InvalidLength;
    if (end - offset < 4) return Error.InvalidLength;
    var reader = @import("reader.zig").Reader.init(message[offset..end]);
    const order = reader.readU16() catch return Error.EndOfInput;
    const preference = reader.readU16() catch return Error.EndOfInput;
    var naptr = Naptr{
        .order = order,
        .preference = preference,
        .replacement = Name.root(),
    };
    naptr.flags_len = try parseNaptrString(&reader, &naptr.flags);
    naptr.services_len = try parseNaptrString(&reader, &naptr.services);
    naptr.regexp_len = try parseNaptrString(&reader, &naptr.regexp);
    for (naptr.flagsText()) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return Error.InvalidLength;
    }
    const replacement_offset = offset + reader.position();
    naptr.replacement = try parseUncompressedNameOnly(message, replacement_offset, end);
    if (naptr.regexp_len != 0 and naptr.replacement.asWire().len != 1) return Error.InvalidLength;
    return naptr;
}

fn parseNaptrString(reader: *@import("reader.zig").Reader, data: *[max_txt_len]u8) Error!u8 {
    const len = reader.readU8() catch return Error.EndOfInput;
    const bytes = reader.readBytes(len) catch return Error.EndOfInput;
    if (!std.unicode.utf8ValidateSlice(bytes)) return Error.InvalidLength;
    @memcpy(data[0..len], bytes);
    return len;
}

fn parseUncompressedNameOnly(message: []const u8, offset: usize, end: usize) Error!Name {
    if (offset >= message.len or end > message.len or offset > end) return Error.EndOfInput;
    var cursor = offset;
    while (cursor < end) {
        const len = message[cursor];
        if ((len & 0xc0) == 0xc0) return Error.BadName;
        if (len == 0) break;
        if ((len & 0xc0) != 0 or len > 63 or cursor + 1 + len > end) return Error.BadName;
        cursor += 1 + len;
    }
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

test "AFSDB wire round trips subtype boundaries with ordinary and compressed names" {
    const hostname = [_]u8{ 3, 'a', 'f', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };

    inline for ([_]u16{ 0, 0xffff }) |subtype| {
        var input: [2 + hostname.len]u8 = undefined;
        std.mem.writeInt(u16, input[0..2], subtype, .big);
        @memcpy(input[2..], &hostname);

        const parsed = try RData.parse(.AFSDB, &input, 0, input.len);
        try std.testing.expectEqual(subtype, parsed.AFSDB.preference);
        try std.testing.expectEqualSlices(u8, &hostname, parsed.AFSDB.exchange.asWire());

        var ordinary: [input.len]u8 = undefined;
        var ordinary_writer = Writer.init(&ordinary);
        try parsed.encode(&ordinary_writer);
        try std.testing.expectEqualSlices(u8, &input, ordinary_writer.written());

        var compressed: [hostname.len + 4]u8 = undefined;
        var compressed_writer = Writer.init(&compressed);
        var table = CompressionTable{};
        try table.writeName(&compressed_writer, &hostname);
        const rdata_offset = compressed_writer.len();
        try parsed.encodeCompressed(&compressed_writer, &table);
        try std.testing.expectEqualSlices(u8, &hostname, compressed[0..rdata_offset]);
        try std.testing.expectEqual(subtype, std.mem.readInt(u16, compressed[rdata_offset..][0..2], .big));
        try std.testing.expectEqual(@as(u16, 0xc000), std.mem.readInt(u16, compressed[rdata_offset + 2 ..][0..2], .big));

        const reparsed = try RData.parse(.AFSDB, compressed[0..compressed_writer.len()], rdata_offset, compressed_writer.len() - rdata_offset);
        try std.testing.expectEqual(subtype, reparsed.AFSDB.preference);
        try std.testing.expectEqualSlices(u8, &hostname, reparsed.AFSDB.exchange.asWire());
    }
}

test "AFSDB wire rejects truncated subtype, missing or malformed names, and trailing data" {
    try std.testing.expectError(Error.InvalidLength, RData.parse(.AFSDB, &.{0}, 0, 1));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.AFSDB, &.{ 0, 1 }, 0, 2));
    try std.testing.expectError(Error.BadName, RData.parse(.AFSDB, &.{ 0, 1, 3, 'x' }, 0, 4));
    try std.testing.expectError(Error.BadName, RData.parse(.AFSDB, &.{ 0, 1, 0x40, 0 }, 0, 4));
    try std.testing.expectError(Error.TrailingData, RData.parse(.AFSDB, &.{ 0, 1, 0, 0, 0xaa }, 0, 5));
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

test "CAA init validates and copies raw fields" {
    const caa = try Caa.init(128, "issue", &.{});
    try std.testing.expectEqual(@as(u8, 128), caa.flags);
    try std.testing.expectEqualStrings("issue", caa.tagText());
    try std.testing.expectEqual(@as(usize, 0), caa.valueText().len);

    try std.testing.expectError(Error.InvalidLength, Caa.init(1, "issue", &.{}));
    try std.testing.expectError(Error.InvalidLength, Caa.init(0, &.{}, &.{}));
}

test "CAA preserves mixed-case tags and raw values in both encoders" {
    const bytes = [_]u8{ 128, 4, 'I', 's', 'S', 'u', 0xff, 0, 0xc3 };
    const caa = try RData.parse(.CAA, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(u8, 128), caa.CAA.flags);
    try std.testing.expectEqualStrings("IsSu", caa.CAA.tagText());
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 0, 0xc3 }, caa.CAA.valueText());

    var ordinary_bytes: [bytes.len]u8 = undefined;
    var ordinary = Writer.init(&ordinary_bytes);
    try caa.encode(&ordinary);
    try std.testing.expectEqualSlices(u8, &bytes, ordinary.written());

    var compressed_bytes: [bytes.len]u8 = undefined;
    var compressed = Writer.init(&compressed_bytes);
    var table = CompressionTable{};
    try caa.encodeCompressed(&compressed, &table);
    try std.testing.expectEqualSlices(u8, &bytes, compressed.written());
}

test "CAA accepts empty and bounded raw values" {
    const value_lengths = [_]usize{ 0, 128, 255 };
    for (value_lengths) |value_len| {
        var bytes: [258]u8 = undefined;
        bytes[0] = 0;
        bytes[1] = 1;
        bytes[2] = 'a';
        @memset(bytes[3..], 0xff);

        const caa = try RData.parse(.CAA, &bytes, 0, 3 + value_len);
        try std.testing.expectEqual(@as(usize, value_len), caa.CAA.valueText().len);
        try std.testing.expectEqualSlices(u8, bytes[3 .. 3 + value_len], caa.CAA.valueText());
    }
}

test "CAA accepts the full RDATA bound with maximum tag and value" {
    var bytes: [max_unknown_len]u8 = undefined;
    bytes[0] = 0;
    bytes[1] = 255;
    for (bytes[2..257], 0..) |*byte, index| {
        byte.* = if (index % 2 == 0) 'A' else '7';
    }
    @memset(bytes[257..], 0xff);

    const caa = try RData.parse(.CAA, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(usize, 255), caa.CAA.tagText().len);
    try std.testing.expectEqual(@as(usize, 255), caa.CAA.valueText().len);
    try std.testing.expectEqualSlices(u8, bytes[2..257], caa.CAA.tagText());
    try std.testing.expectEqualSlices(u8, bytes[257..], caa.CAA.valueText());

    var output_bytes: [max_unknown_len]u8 = undefined;
    var writer = Writer.init(&output_bytes);
    try caa.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}

test "CAA accepts a one-byte tag with a 509-byte value" {
    var bytes: [max_unknown_len]u8 = undefined;
    bytes[0] = 128;
    bytes[1] = 1;
    bytes[2] = 'z';
    @memset(bytes[3..], 0x80);

    const caa = try RData.parse(.CAA, &bytes, 0, bytes.len);
    try std.testing.expectEqualStrings("z", caa.CAA.tagText());
    try std.testing.expectEqual(@as(usize, 509), caa.CAA.valueText().len);
    try std.testing.expectEqualSlices(u8, bytes[3..], caa.CAA.valueText());
}

test "CAA rejects invalid flags, tags, truncation, and overbound data" {
    for ([_]u8{ 1, 127, 129, 255 }) |flags| {
        try std.testing.expectError(Error.InvalidLength, RData.parse(.CAA, &.{ flags, 1, 'a' }, 0, 3));
    }
    try std.testing.expectError(Error.InvalidLength, RData.parse(.CAA, &.{ 0, 0 }, 0, 2));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.CAA, &.{ 0, 3, 'a', '-' }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.CAA, &.{ 0, 3, 'a', 'b' }, 0, 4));

    var overbound: [max_unknown_len + 1]u8 = undefined;
    overbound[0] = 0;
    overbound[1] = 1;
    overbound[2] = 'a';
    @memset(overbound[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.CAA, &overbound, 0, overbound.len));
}

test "rdata preserves unknown record bytes" {
    const unknown = try RData.parse(RecordType.fromCode(65280), &.{ 1, 2, 3, 4 }, 0, 4);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, unknown.Unknown.bytes());
}

test "rdata keeps unknown wire data within the declared bounded profile" {
    var max: [max_unknown_len]u8 = undefined;
    @memset(&max, 0xa5);
    const unknown = try RData.parse(RecordType.fromCode(65280), &max, 0, max.len);
    try std.testing.expectEqual(@as(usize, max_unknown_len), unknown.Unknown.bytes().len);

    var overlong: [max_unknown_len + 1]u8 = undefined;
    try std.testing.expectError(Error.UnknownTooLong, RData.parse(RecordType.fromCode(65280), &overlong, 0, overlong.len));
}

test "rdata parses and encodes DNAME targets without compression" {
    const bytes = [_]u8{ 3, 'n', 'e', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    const dname = try RData.parse(.DNAME, &bytes, 0, bytes.len);
    var output: [32]u8 = undefined;
    var writer = Writer.init(&output);
    try dname.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
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

test "SSHFP wire parses and encodes exact selector and fingerprint bytes" {
    var bytes: [34]u8 = undefined;
    bytes[0] = 4;
    bytes[1] = 2;
    for (bytes[2..], 0..) |*byte, index| byte.* = @intCast(index);

    const sshfp = try RData.parse(.SSHFP, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(u8, 4), sshfp.SSHFP.algorithm);
    try std.testing.expectEqual(@as(u8, 2), sshfp.SSHFP.fingerprint_type);
    try std.testing.expectEqualSlices(u8, bytes[2..], sshfp.SSHFP.fingerprintBytes());

    var encoded: [34]u8 = undefined;
    var writer = Writer.init(&encoded);
    try sshfp.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());

    var compressed: [34]u8 = undefined;
    var compressed_writer = Writer.init(&compressed);
    var table = CompressionTable{};
    try sshfp.encodeCompressed(&compressed_writer, &table);
    try std.testing.expectEqualSlices(u8, &bytes, compressed_writer.written());
}

test "SSHFP wire rejects truncation, unsupported selectors, and wrong lengths" {
    const short_sha1 = [_]u8{ 4, 2 } ++ [_]u8{0} ** 19;
    const wrong_type_sha1 = [_]u8{ 4, 1 } ++ [_]u8{0} ** 19;
    const short_sha256 = [_]u8{ 4, 2 } ++ [_]u8{0} ** 31;
    const unsupported_algorithm_zero = [_]u8{ 0, 2 } ++ [_]u8{0} ** 32;
    const unsupported_algorithm_five = [_]u8{ 5, 2 } ++ [_]u8{0} ** 32;
    const unsupported_algorithm_seven = [_]u8{ 7, 2 } ++ [_]u8{0} ** 32;
    const unsupported_type_zero = [_]u8{ 4, 0 } ++ [_]u8{0} ** 32;
    const unsupported_type_three = [_]u8{ 4, 3 } ++ [_]u8{0} ** 32;
    try std.testing.expectError(Error.EndOfInput, RData.parse(.SSHFP, &.{4}, 0, 2));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &short_sha1, 0, 21));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &wrong_type_sha1, 0, 21));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &short_sha256, 0, 33));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &unsupported_algorithm_zero, 0, 34));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &unsupported_algorithm_five, 0, 34));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &unsupported_algorithm_seven, 0, 34));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &unsupported_type_zero, 0, 34));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.SSHFP, &unsupported_type_three, 0, 34));
}

test "TLSA wire parses and encodes exact selector and association bytes" {
    var sha256: [35]u8 = undefined;
    sha256[0] = 0;
    sha256[1] = 0;
    sha256[2] = 1;
    for (sha256[3..], 0..) |*byte, index| byte.* = @intCast(index);

    var sha512: [67]u8 = undefined;
    sha512[0] = 1;
    sha512[1] = 1;
    sha512[2] = 2;
    for (sha512[3..], 0..) |*byte, index| byte.* = @intCast(index + 1);

    const certificate = [_]u8{ 3, 0, 0, 0xaa, 0xbb, 0xcc };
    const cases = .{
        .{ &sha256, @as(usize, 32) },
        .{ &sha512, @as(usize, 64) },
        .{ &certificate, @as(usize, 3) },
    };

    inline for (cases) |case| {
        const input = case[0];
        const association_len = case[1];
        const tlsa = try RData.parse(.TLSA, input, 0, input.len);
        try std.testing.expectEqual(input[0], tlsa.TLSA.usage);
        try std.testing.expectEqual(input[1], tlsa.TLSA.selector);
        try std.testing.expectEqual(input[2], tlsa.TLSA.matching_type);
        try std.testing.expectEqual(association_len, @as(usize, tlsa.TLSA.association_len));
        try std.testing.expectEqualSlices(u8, input[3..], tlsa.TLSA.association[0..tlsa.TLSA.association_len]);

        var encoded: [67]u8 = undefined;
        var writer = Writer.init(&encoded);
        try tlsa.encode(&writer);
        try std.testing.expectEqualSlices(u8, input, writer.written());

        var compressed: [67]u8 = undefined;
        var compressed_writer = Writer.init(&compressed);
        var table = CompressionTable{};
        try tlsa.encodeCompressed(&compressed_writer, &table);
        try std.testing.expectEqualSlices(u8, input, compressed_writer.written());
    }

    var max_type_zero: [512]u8 = undefined;
    max_type_zero[0..3].* = .{ 3, 0, 0 };
    @memset(max_type_zero[3..], 0xa5);
    const max_tlsa = try RData.parse(.TLSA, &max_type_zero, 0, max_type_zero.len);

    var max_encoded: [512]u8 = undefined;
    var max_writer = Writer.init(&max_encoded);
    try max_tlsa.encode(&max_writer);
    try std.testing.expectEqualSlices(u8, &max_type_zero, max_writer.written());

    var max_compressed: [512]u8 = undefined;
    var max_compressed_writer = Writer.init(&max_compressed);
    var max_table = CompressionTable{};
    try max_tlsa.encodeCompressed(&max_compressed_writer, &max_table);
    try std.testing.expectEqualSlices(u8, &max_type_zero, max_compressed_writer.written());
}

test "TLSA wire rejects unsupported selectors and association lengths" {
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{}, 0, 0));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{0}, 0, 1));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 0, 0 }, 0, 2));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 0, 0, 0 }, 0, 3));

    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 4, 0, 0, 0xaa }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 0, 2, 0, 0xaa }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 0, 0, 3, 0xaa }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &.{ 0, 0, 0 }, 0, 3));

    var short_sha256: [34]u8 = undefined;
    short_sha256[0..3].* = .{ 0, 0, 1 };
    @memset(short_sha256[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &short_sha256, 0, short_sha256.len));

    var long_sha256: [36]u8 = undefined;
    long_sha256[0..3].* = .{ 0, 0, 1 };
    @memset(long_sha256[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &long_sha256, 0, long_sha256.len));

    var short_sha512: [66]u8 = undefined;
    short_sha512[0..3].* = .{ 0, 0, 2 };
    @memset(short_sha512[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &short_sha512, 0, short_sha512.len));

    var long_sha512: [68]u8 = undefined;
    long_sha512[0..3].* = .{ 0, 0, 2 };
    @memset(long_sha512[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &long_sha512, 0, long_sha512.len));

    var too_long_type_zero: [513]u8 = undefined;
    too_long_type_zero[0..3].* = .{ 0, 0, 0 };
    @memset(too_long_type_zero[3..], 0);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.TLSA, &too_long_type_zero, 0, too_long_type_zero.len));
}

test "URI wire parses and encodes exact target bytes" {
    const ascii = [_]u8{
        0x00, 0x0a, 0x00, 0x01,
        'h',  't',  't',  'p',
        ':',  '/',  '/',  'e',
        'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',
        'o',  'm',  '/',  's',
        'e',  'r',  'v',  'i',
        'c',  'e',
    };
    const uri = try RData.parse(.URI, &ascii, 0, ascii.len);
    try std.testing.expectEqual(@as(u16, 10), uri.URI.priority);
    try std.testing.expectEqual(@as(u16, 1), uri.URI.weight);
    try std.testing.expectEqualSlices(u8, ascii[4..], uri.URI.target[0..uri.URI.target_len]);

    var encoded: [ascii.len]u8 = undefined;
    var writer = Writer.init(&encoded);
    try uri.encode(&writer);
    try std.testing.expectEqualSlices(u8, &ascii, writer.written());

    var compressed: [ascii.len]u8 = undefined;
    var compressed_writer = Writer.init(&compressed);
    var table = CompressionTable{};
    try uri.encodeCompressed(&compressed_writer, &table);
    try std.testing.expectEqualSlices(u8, &ascii, compressed_writer.written());

    const arbitrary = [_]u8{ 0x12, 0x34, 0xab, 0xcd, 0x00, '"', '\\', 0xff };
    const arbitrary_uri = try RData.parse(.URI, &arbitrary, 0, arbitrary.len);
    try std.testing.expectEqual(@as(u16, 0x1234), arbitrary_uri.URI.priority);
    try std.testing.expectEqual(@as(u16, 0xabcd), arbitrary_uri.URI.weight);
    try std.testing.expectEqualSlices(u8, arbitrary[4..], arbitrary_uri.URI.target[0..arbitrary_uri.URI.target_len]);

    var arbitrary_encoded: [arbitrary.len]u8 = undefined;
    var arbitrary_writer = Writer.init(&arbitrary_encoded);
    try arbitrary_uri.encode(&arbitrary_writer);
    try std.testing.expectEqualSlices(u8, &arbitrary, arbitrary_writer.written());

    var arbitrary_compressed: [arbitrary.len]u8 = undefined;
    var arbitrary_compressed_writer = Writer.init(&arbitrary_compressed);
    var arbitrary_table = CompressionTable{};
    try arbitrary_uri.encodeCompressed(&arbitrary_compressed_writer, &arbitrary_table);
    try std.testing.expectEqualSlices(u8, &arbitrary, arbitrary_compressed_writer.written());
}

test "URI wire accepts the bounded maximum target" {
    var bytes: [512]u8 = undefined;
    bytes[0..4].* = .{ 0x12, 0x34, 0xab, 0xcd };
    @memset(bytes[4..], 0xa5);

    const uri = try RData.parse(.URI, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(u16, 0x1234), uri.URI.priority);
    try std.testing.expectEqual(@as(u16, 0xabcd), uri.URI.weight);
    try std.testing.expectEqual(@as(usize, 508), uri.URI.target_len);
    try std.testing.expectEqualSlices(u8, bytes[4..], uri.URI.target[0..uri.URI.target_len]);
}

test "URI wire rejects missing and overlong targets" {
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &.{}, 0, 0));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &.{0}, 0, 1));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &.{ 0, 1 }, 0, 2));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &.{ 0, 1, 0 }, 0, 3));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &.{ 0, 10, 0, 1 }, 0, 4));

    var overlong: [513]u8 = undefined;
    overlong[0..4].* = .{ 0, 10, 0, 1 };
    @memset(overlong[4..], 0xa5);
    try std.testing.expectError(Error.InvalidLength, RData.parse(.URI, &overlong, 0, overlong.len));
}

test "NAPTR wire parses and encodes exact fields without replacement compression" {
    const bytes = [_]u8{
        0x00, 0x64, 0x00, 0x0a,
        0x01, 'U',  0x07, 'E',
        '2',  'U',  '+',  's',
        'i',  'p',  0x00, 0x0b,
        'r',  'e',  'p',  'l',
        'a',  'c',  'e',  'm',
        'e',  'n',  't',  0x07,
        'e',  'x',  'a',  'm',
        'p',  'l',  'e',  0x00,
    };
    const naptr = try RData.parse(.NAPTR, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(u16, 100), naptr.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 10), naptr.NAPTR.preference);
    try std.testing.expectEqualSlices(u8, "U", naptr.NAPTR.flagsText());
    try std.testing.expectEqualSlices(u8, "E2U+sip", naptr.NAPTR.servicesText());
    try std.testing.expectEqualSlices(u8, "", naptr.NAPTR.regexpText());
    var replacement_text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("replacement.example.", try naptr.NAPTR.replacement.toText(&replacement_text));

    var ordinary: [bytes.len]u8 = undefined;
    var ordinary_writer = Writer.init(&ordinary);
    try naptr.encode(&ordinary_writer);
    try std.testing.expectEqualSlices(u8, &bytes, ordinary_writer.written());

    var compressed: [bytes.len * 2]u8 = undefined;
    var compressed_writer = Writer.init(&compressed);
    var table = CompressionTable{};
    try table.writeName(&compressed_writer, naptr.NAPTR.replacement.asWire());
    const replacement_start = compressed_writer.len();
    try naptr.encodeCompressed(&compressed_writer, &table);
    try std.testing.expectEqual(@as(u8, 0x0b), compressed_writer.written()[replacement_start + 4 + 2 + 8 + 1]);
    try std.testing.expectEqualSlices(u8, &bytes, compressed_writer.written()[replacement_start..]);
}

test "NAPTR wire accepts UTF-8 fields and root replacement" {
    const bytes = [_]u8{
        0x12, 0x34, 0xab, 0xcd,
        0x03, 'a',  'Z',  '9',
        0x06, 0xe6, 0x9c, 0x8d,
        0xe5, 0x8a, 0xa1, 0x02,
        0xc3, 0xa9, 0x00,
    };
    const naptr = try RData.parse(.NAPTR, &bytes, 0, bytes.len);
    try std.testing.expectEqualSlices(u8, "aZ9", naptr.NAPTR.flagsText());
    try std.testing.expectEqualSlices(u8, "服务", naptr.NAPTR.servicesText());
    try std.testing.expectEqualSlices(u8, "é", naptr.NAPTR.regexpText());
    try std.testing.expectEqualSlices(u8, &.{0}, naptr.NAPTR.replacement.asWire());
}

test "NAPTR wire accepts empty strings with root replacement" {
    const bytes = [_]u8{ 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const naptr = try RData.parse(.NAPTR, &bytes, 0, bytes.len);
    try std.testing.expectEqual(@as(u16, 0xffff), naptr.NAPTR.order);
    try std.testing.expectEqual(@as(u16, 0), naptr.NAPTR.preference);
    try std.testing.expectEqual(@as(usize, 0), naptr.NAPTR.flagsText().len);
    try std.testing.expectEqual(@as(usize, 0), naptr.NAPTR.servicesText().len);
    try std.testing.expectEqual(@as(usize, 0), naptr.NAPTR.regexpText().len);
    try std.testing.expectEqualSlices(u8, &.{0}, naptr.NAPTR.replacement.asWire());
}

test "NAPTR wire rejects malformed fields and oversized RDATA" {
    try std.testing.expectError(Error.InvalidLength, RData.parse(.NAPTR, &.{ 0, 1, 0 }, 0, 3));
    try std.testing.expectError(Error.EndOfInput, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 1 }, 0, 5));
    try std.testing.expectError(Error.BadName, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 0, 0, 0, 0xc0, 0 }, 0, 9));
    try std.testing.expectError(Error.BadName, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 0, 0, 0, 3, 'x' }, 0, 9));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 2, 'U', '_', 0, 0 }, 0, 9));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 0, 2, 0xff, 0xff, 0, 0 }, 0, 10));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 0, 0, 1, '!', 1, 'x', 0 }, 0, 11));
    try std.testing.expectError(Error.TrailingData, RData.parse(.NAPTR, &.{ 0, 1, 0, 2, 0, 0, 0, 0, 0xaa }, 0, 9));

    var oversized: [513]u8 = undefined;
    oversized[0..4].* = .{ 0, 1, 0, 2 };
    oversized[4] = 250;
    @memset(oversized[5..255], 'A');
    oversized[255] = 255;
    @memset(oversized[256..511], 'x');
    oversized[511] = 0;
    oversized[512] = 0;
    try std.testing.expectError(Error.InvalidLength, RData.parse(.NAPTR, &oversized, 0, oversized.len));
}

test "APL wire accepts empty, ordered, negated, and duplicate items" {
    const empty = try RData.parse(.APL, &.{}, 0, 0);
    try std.testing.expectEqual(@as(usize, 0), empty.APL.bytes().len);

    var empty_encoded: [0]u8 = .{};
    var empty_writer = Writer.init(&empty_encoded);
    try empty.encode(&empty_writer);
    try std.testing.expectEqual(@as(usize, 0), empty_writer.len());

    var empty_compressed: [0]u8 = .{};
    var empty_compressed_writer = Writer.init(&empty_compressed);
    var empty_table = CompressionTable{};
    try empty.encodeCompressed(&empty_compressed_writer, &empty_table);
    try std.testing.expectEqual(@as(usize, 0), empty_compressed_writer.len());

    const bytes = [_]u8{
        0x00, 0x01, 0x18, 0x03, 0xc0, 0x00, 0x02,
        0x00, 0x02, 0x20, 0x84, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x01, 0x18, 0x83, 0xc0, 0x00,
        0x02,
    };
    const apl = try RData.parse(.APL, &bytes, 0, bytes.len);
    try std.testing.expectEqualSlices(u8, &bytes, apl.APL.bytes());

    var encoded: [bytes.len]u8 = undefined;
    var writer = Writer.init(&encoded);
    try apl.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());

    var compressed: [bytes.len]u8 = undefined;
    var compressed_writer = Writer.init(&compressed);
    var table = CompressionTable{};
    try apl.encodeCompressed(&compressed_writer, &table);
    try std.testing.expectEqualSlices(u8, &bytes, compressed_writer.written());
}

test "APL wire accepts shorter AFDPART than the prefix requires" {
    const bytes = [_]u8{ 0x00, 0x01, 0x18, 0x02, 0xc0, 0x01 };
    const apl = try RData.parse(.APL, &bytes, 0, bytes.len);
    try std.testing.expectEqualSlices(u8, &bytes, apl.APL.bytes());
}

test "APL wire rejects malformed items and noncanonical bytes" {
    try std.testing.expectError(Error.EndOfInput, RData.parse(.APL, &.{0}, 0, 1));
    try std.testing.expectError(Error.EndOfInput, RData.parse(.APL, &.{ 0, 1, 24, 3, 192, 0 }, 0, 6));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 33, 0 }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 2, 129, 0 }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 3, 0, 0 }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 24, 0x88 }, 0, 4));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 17, 4, 0x80, 0, 0, 1 }, 0, 8));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 17, 3, 0x80, 0, 1 }, 0, 7));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 9, 2, 0x80, 0x01 }, 0, 6));
    try std.testing.expectError(Error.InvalidLength, RData.parse(.APL, &.{ 0, 1, 24, 1, 0 }, 0, 5));

    const boundary = [_]u8{ 0, 1, 9, 2, 0x80, 0x80 };
    const valid = try RData.parse(.APL, &boundary, 0, boundary.len);
    try std.testing.expectEqualSlices(u8, &boundary, valid.APL.bytes());
}

test "APL wire rejects RDATA over the bounded payload" {
    var oversized: [max_unknown_len + 1]u8 = undefined;
    @memset(&oversized, 0);
    try std.testing.expectError(Error.UnknownTooLong, RData.parse(.APL, &oversized, 0, oversized.len));
}
