/// Contract: Inspects raw DNS messages for one final TSIG additional record.
/// Ownership: Parsed TSIG data is inline; the input packet remains borrowed.
/// Errors: Malformed framing and TSIG placement are reported without I/O.
const std = @import("std");
const Header = @import("header.zig").Header;
const Name = @import("name.zig").Name;
const rdata = @import("rdata.zig");
const RData = rdata.RData;
const Tsig = rdata.Tsig;
const ResourceRecord = @import("record.zig").ResourceRecord;
const RecordType = @import("types.zig").RecordType;
const Class = @import("types.zig").Class;
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;

pub const Error = error{
    EndOfInput,
    InvalidClass,
    InvalidTtl,
    TsigNotFinal,
    MalformedTsig,
    Formerr,
    UnsupportedAlgorithm,
    BadMac,
    BadTrunc,
    InvalidPriorMac,
    InvalidOriginalId,
};

pub const Algorithm = enum {
    hmac_sha1,
    hmac_sha256,
};

pub const Mac = struct {
    bytes: [32]u8 = undefined,
    len: u8 = 0,

    pub fn slice(self: *const Mac) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const FinalAdditional = struct {
    owner: Name,
    record_start: usize,
    rdata_start: usize,
    rdata_end: usize,
    record_end: usize,
    tsig: Tsig,
};

pub fn parseFinalAdditional(packet: []const u8) Error!?FinalAdditional {
    var reader = Reader.init(packet);
    const header = Header.parse(&reader) catch return Error.EndOfInput;
    var offset = reader.position();

    offset = skipQuestions(packet, offset, header.question_count) catch return Error.EndOfInput;
    offset = skipRecords(packet, offset, header.answer_count) catch |err| switch (err) {
        Error.TsigNotFinal => return Error.TsigNotFinal,
        else => return Error.EndOfInput,
    };
    offset = skipRecords(packet, offset, header.authority_count) catch |err| switch (err) {
        Error.TsigNotFinal => return Error.TsigNotFinal,
        else => return Error.EndOfInput,
    };

    var found: ?FinalAdditional = null;
    for (0..@as(usize, header.additional_count)) |index| {
        const record_start = offset;
        const owner = Name.parse(packet, offset) catch return Error.EndOfInput;
        offset = owner.next_offset;
        if (packet.len -| offset < 10) return Error.EndOfInput;

        const rrtype = std.mem.readInt(u16, packet[offset..][0..2], .big);
        const class = std.mem.readInt(u16, packet[offset + 2 ..][0..2], .big);
        const ttl = std.mem.readInt(u32, packet[offset + 4 ..][0..4], .big);
        const rdlength = std.mem.readInt(u16, packet[offset + 8 ..][0..2], .big);
        const rdata_start = offset + 10;
        if (@as(usize, rdlength) > packet.len -| rdata_start) {
            if (rrtype == RecordType.TSIG.code()) return Error.MalformedTsig;
            return Error.EndOfInput;
        }
        const rdata_end = rdata_start + rdlength;
        offset = rdata_end;

        if (rrtype != RecordType.TSIG.code()) continue;
        if (index + 1 != @as(usize, header.additional_count)) return Error.TsigNotFinal;
        if (class != Class.ANY.code()) return Error.InvalidClass;
        if (ttl != 0) return Error.InvalidTtl;
        if (found != null) return Error.TsigNotFinal;

        const parsed = RData.parse(RecordType.TSIG, packet, rdata_start, rdlength) catch return Error.MalformedTsig;
        found = .{
            .owner = owner.name,
            .record_start = record_start,
            .rdata_start = rdata_start,
            .rdata_end = rdata_end,
            .record_end = rdata_end,
            .tsig = parsed.TSIG,
        };
    }

    if (offset != packet.len) return Error.EndOfInput;
    return found;
}

fn skipQuestions(packet: []const u8, start: usize, count: u16) Error!usize {
    var offset = start;
    for (0..@as(usize, count)) |_| {
        const name = Name.parse(packet, offset) catch return Error.EndOfInput;
        offset = name.next_offset;
        if (packet.len -| offset < 4) return Error.EndOfInput;
        offset += 4;
    }
    return offset;
}

fn skipRecords(packet: []const u8, start: usize, count: u16) Error!usize {
    var offset = start;
    for (0..@as(usize, count)) |_| {
        const owner = Name.parse(packet, offset) catch return Error.EndOfInput;
        offset = owner.next_offset;
        if (packet.len -| offset < 10) return Error.EndOfInput;
        const rrtype = std.mem.readInt(u16, packet[offset..][0..2], .big);
        if (rrtype == RecordType.TSIG.code()) return Error.TsigNotFinal;
        const rdlength = std.mem.readInt(u16, packet[offset + 8 ..][0..2], .big);
        offset += 10;
        if (@as(usize, rdlength) > packet.len -| offset) return Error.EndOfInput;
        offset += rdlength;
    }
    return offset;
}

const hmac_sha1_wire = [_]u8{ 9, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '1', 0 };
const hmac_sha256_wire = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0 };

pub fn algorithmForName(name: *const Name) Error!Algorithm {
    if (std.mem.eql(u8, name.asWire(), &hmac_sha1_wire)) return .hmac_sha1;
    if (std.mem.eql(u8, name.asWire(), &hmac_sha256_wire)) return .hmac_sha256;
    return Error.UnsupportedAlgorithm;
}

pub fn sign(
    packet: []const u8,
    key: []const u8,
    owner: Name,
    tsig: Tsig,
    prior_mac: ?[]const u8,
) Error!Mac {
    const found = parseFinalAdditional(packet) catch return Error.Formerr;
    if (found == null and std.mem.readInt(u16, packet[0..2], .big) != tsig.original_id) {
        return Error.InvalidOriginalId;
    }
    return standardMac(packet, found, key, owner, tsig, prior_mac, true);
}

pub fn verify(
    packet: []const u8,
    key: []const u8,
    prior_mac: ?[]const u8,
    minimum_mac_len: usize,
) Error!Mac {
    const found = parseFinalAdditional(packet) catch return Error.Formerr;
    const final = found orelse return Error.Formerr;
    const expected = try standardMac(packet, final, key, final.owner, final.tsig, prior_mac, true);
    const received = final.tsig.macBytes();
    if (received.len > expected.slice().len) return Error.Formerr;
    const protocol_minimum = @max(@as(usize, 10), expected.slice().len / 2);
    if (received.len == 0 or received.len < protocol_minimum) return Error.Formerr;
    if (std.crypto.timing_safe.compare(u8, received, expected.slice()[0..received.len], .big) != .eq) {
        return Error.BadMac;
    }
    if (received.len < minimum_mac_len) return Error.BadTrunc;
    return expected;
}

pub fn signChained(
    packets: []const []const u8,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    return chainedMac(packets, null, key, tsig, prior_mac);
}

pub fn verifyChained(
    packets: []const []const u8,
    key: []const u8,
    prior_mac: []const u8,
    minimum_mac_len: usize,
) Error!Mac {
    if (packets.len == 0) return Error.Formerr;
    const packet = packets[packets.len - 1];
    const found = parseFinalAdditional(packet) catch return Error.Formerr;
    const final = found orelse return Error.Formerr;
    const expected = try chainedMac(packets, final, key, final.tsig, prior_mac);
    const received = final.tsig.macBytes();
    if (received.len > expected.slice().len) return Error.Formerr;
    const protocol_minimum = @max(@as(usize, 10), expected.slice().len / 2);
    if (received.len == 0 or received.len < protocol_minimum) return Error.Formerr;
    if (std.crypto.timing_safe.compare(u8, received, expected.slice()[0..received.len], .big) != .eq) {
        return Error.BadMac;
    }
    if (received.len < minimum_mac_len) return Error.BadTrunc;
    return expected;
}

/// Signs one already-encoded transfer message that carries its own zeroed
/// final TSIG record. The digest covers the previous chain MAC plus the
/// unsigned message form, matching what verifyChained recomputes for a
/// single-packet chain. Use the returned MAC as the prior for the next
/// message in the sequence.
pub fn signChainedFinal(
    packet: []const u8,
    final: FinalAdditional,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    return chainedMac(&.{packet}, final, key, tsig, prior_mac);
}

pub fn digestLength(algorithm: Algorithm) usize {
    return switch (algorithm) {
        .hmac_sha1 => 20,
        .hmac_sha256 => 32,
    };
}

pub fn patchMac(packet: []u8, final: FinalAdditional, mac: []const u8) Error!void {
    if (mac.len != final.tsig.macBytes().len) return Error.Formerr;
    const mac_start = final.rdata_start + final.tsig.algorithm.asWire().len + 10;
    if (mac_start > packet.len or mac.len > packet.len - mac_start) return Error.Formerr;
    @memcpy(packet[mac_start .. mac_start + mac.len], mac);
}

fn standardMac(
    packet: []const u8,
    final: ?FinalAdditional,
    key: []const u8,
    owner: Name,
    tsig: Tsig,
    prior_mac: ?[]const u8,
    replace_id: bool,
) Error!Mac {
    return switch (try algorithmForName(&tsig.algorithm)) {
        .hmac_sha1 => standardMacWith(std.crypto.auth.hmac.HmacSha1, packet, final, key, owner, tsig, prior_mac, replace_id),
        .hmac_sha256 => standardMacWith(std.crypto.auth.hmac.sha2.HmacSha256, packet, final, key, owner, tsig, prior_mac, replace_id),
    };
}

fn standardMacWith(
    comptime Hmac: type,
    packet: []const u8,
    final: ?FinalAdditional,
    key: []const u8,
    owner: Name,
    tsig: Tsig,
    prior_mac: ?[]const u8,
    replace_id: bool,
) Error!Mac {
    var hmac = Hmac.init(key);
    try updatePrior(&hmac, prior_mac);
    try updateUnsigned(&hmac, packet, final, tsig.original_id, replace_id);
    updateVariables(&hmac, owner, tsig);

    var digest: [Hmac.mac_length]u8 = undefined;
    hmac.final(&digest);
    var result = Mac{ .len = @intCast(digest.len) };
    @memcpy(result.bytes[0..digest.len], &digest);
    return result;
}

fn chainedMac(
    packets: []const []const u8,
    final: ?FinalAdditional,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    return switch (try algorithmForName(&tsig.algorithm)) {
        .hmac_sha1 => chainedMacWith(std.crypto.auth.hmac.HmacSha1, packets, final, key, tsig, prior_mac),
        .hmac_sha256 => chainedMacWith(std.crypto.auth.hmac.sha2.HmacSha256, packets, final, key, tsig, prior_mac),
    };
}

fn chainedMacWith(
    comptime Hmac: type,
    packets: []const []const u8,
    final: ?FinalAdditional,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    var hmac = Hmac.init(key);
    try updatePrior(&hmac, prior_mac);
    for (packets, 0..) |packet, index| {
        if (index == packets.len - 1 and final != null) {
            try updateUnsigned(&hmac, packet, final, tsig.original_id, true);
        } else {
            hmac.update(packet);
        }
    }
    updateTimers(&hmac, tsig);

    var digest: [Hmac.mac_length]u8 = undefined;
    hmac.final(&digest);
    var result = Mac{ .len = @intCast(digest.len) };
    @memcpy(result.bytes[0..digest.len], &digest);
    return result;
}

fn updatePrior(hmac: anytype, prior_mac: ?[]const u8) Error!void {
    const bytes = prior_mac orelse return;
    if (bytes.len > std.math.maxInt(u16)) return Error.InvalidPriorMac;
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(bytes.len), .big);
    hmac.update(&length);
    hmac.update(bytes);
}

fn updateUnsigned(
    hmac: anytype,
    packet: []const u8,
    final: ?FinalAdditional,
    original_id: u16,
    replace_id: bool,
) Error!void {
    if (packet.len < 12) return Error.Formerr;

    if (final) |record| {
        if (record.record_start < 12 or record.record_end > packet.len or record.record_start > record.record_end) {
            return Error.Formerr;
        }
        var header: [12]u8 = undefined;
        @memcpy(&header, packet[0..12]);
        const additional_count = std.mem.readInt(u16, header[10..12], .big);
        if (additional_count == 0) return Error.Formerr;
        std.mem.writeInt(u16, header[10..12], additional_count - 1, .big);
        if (replace_id) std.mem.writeInt(u16, header[0..2], original_id, .big);
        hmac.update(&header);
        hmac.update(packet[12..record.record_start]);
        hmac.update(packet[record.record_end..]);
    } else if (!replace_id or std.mem.readInt(u16, packet[0..2], .big) == original_id) {
        hmac.update(packet);
    } else {
        var header: [12]u8 = undefined;
        @memcpy(&header, packet[0..12]);
        std.mem.writeInt(u16, header[0..2], original_id, .big);
        hmac.update(&header);
        hmac.update(packet[12..]);
    }
}

fn updateVariables(hmac: anytype, owner: Name, tsig: Tsig) void {
    hmac.update(owner.asWire());
    var class_and_ttl: [6]u8 = undefined;
    std.mem.writeInt(u16, class_and_ttl[0..2], Class.ANY.code(), .big);
    std.mem.writeInt(u32, class_and_ttl[2..6], 0, .big);
    hmac.update(&class_and_ttl);
    hmac.update(tsig.algorithm.asWire());
    updateTimers(hmac, tsig);
    var error_and_other_len: [4]u8 = undefined;
    std.mem.writeInt(u16, error_and_other_len[0..2], tsig.error_code, .big);
    std.mem.writeInt(u16, error_and_other_len[2..4], tsig.other_len, .big);
    hmac.update(&error_and_other_len);
    hmac.update(tsig.otherData());
}

fn updateTimers(hmac: anytype, tsig: Tsig) void {
    var timers: [8]u8 = undefined;
    timers[0] = @intCast((tsig.time_signed >> 40) & 0xff);
    timers[1] = @intCast((tsig.time_signed >> 32) & 0xff);
    timers[2] = @intCast((tsig.time_signed >> 24) & 0xff);
    timers[3] = @intCast((tsig.time_signed >> 16) & 0xff);
    timers[4] = @intCast((tsig.time_signed >> 8) & 0xff);
    timers[5] = @intCast(tsig.time_signed & 0xff);
    std.mem.writeInt(u16, timers[6..8], tsig.fudge, .big);
    hmac.update(&timers);
}

test "tsig raw parser exposes the final additional record range" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x22, 0x0b, 'h',  'm',  'a',  'c',  '-',  's',  'h',
        'a',  '2',  '5',  '6',  0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00,
        0x3c, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x12, 0x34, 0x00, 0x00, 0x00, 0x02,
        0xde, 0xad,
    };

    const found = (try parseFinalAdditional(&packet)) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 17), found.record_start);
    try std.testing.expectEqual(@as(usize, 28), found.rdata_start);
    try std.testing.expectEqual(@as(usize, 62), found.rdata_end);
    try std.testing.expectEqual(found.rdata_end, found.record_end);
    try std.testing.expectEqual(@as(u64, 0x000102030405), found.tsig.time_signed);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, found.tsig.macBytes());
}

test "tsig raw parser rejects invalid class and ttl" {
    var invalid_class = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfa, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x22, 0x0b, 'h',  'm',  'a',  'c',  '-',  's',  'h',
        'a',  '2',  '5',  '6',  0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00,
        0x3c, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x12, 0x34, 0x00, 0x00, 0x00, 0x02,
        0xde, 0xad,
    };
    try std.testing.expectError(Error.InvalidClass, parseFinalAdditional(&invalid_class));

    invalid_class[21] = 0xff;
    invalid_class[25] = 0x01;
    try std.testing.expectError(Error.InvalidTtl, parseFinalAdditional(&invalid_class));
}

test "tsig raw parser requires one final additional record" {
    var packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x22, 0x0b, 'h',  'm',  'a',  'c',  '-',  's',  'h',
        'a',  '2',  '5',  '6',  0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00,
        0x3c, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x12, 0x34, 0x00, 0x00, 0x00, 0x02,
        0xde, 0xad,
    };
    packet[11] = 2;
    try std.testing.expectError(Error.TsigNotFinal, parseFinalAdditional(&packet));
}

test "tsig raw parser returns null for unsigned messages" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01,
    };
    try std.testing.expect((try parseFinalAdditional(&packet)) == null);
}

test "tsig rejects type 250 outside the additional section" {
    const answer = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const authority = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    try std.testing.expectError(Error.TsigNotFinal, parseFinalAdditional(&answer));
    try std.testing.expectError(Error.TsigNotFinal, parseFinalAdditional(&authority));
}

test "tsig rdata can encode a bounded 48-bit time and fields" {
    const algorithm = try Name.fromText("hmac-sha256.");
    const value = try Tsig.init(
        algorithm,
        0x0000ffffffffffff,
        300,
        &.{ 0xaa, 0xbb },
        0x1234,
        0,
        &.{ 0xde, 0xad },
    );
    var bytes: [512]u8 = undefined;
    var writer = Writer.init(&bytes);
    try (RData{ .TSIG = value }).encode(&writer);
    const parsed = try RData.parse(.TSIG, writer.written(), 0, writer.len());
    try std.testing.expectEqual(value.time_signed, parsed.TSIG.time_signed);
    try std.testing.expectEqualSlices(u8, value.macBytes(), parsed.TSIG.macBytes());
    try std.testing.expectEqualSlices(u8, value.otherData(), parsed.TSIG.otherData());
}

test "tsig rdata rejects compressed algorithm names and malformed lengths" {
    try std.testing.expectError(rdata.Error.BadName, RData.parse(.TSIG, &.{ 0xc0, 0x00 }, 0, 2));
    try std.testing.expectError(rdata.Error.InvalidLength, RData.parse(.TSIG, &.{}, 0, 0));

    const algorithm = try Name.fromText("hmac-sha256.");
    const too_large = Tsig{
        .algorithm = algorithm,
        .time_signed = 0x0001000000000000,
        .fudge = 0,
        .original_id = 0,
        .error_code = 0,
    };
    var output: [512]u8 = undefined;
    var writer = Writer.init(&output);
    try std.testing.expectError(rdata.Error.InvalidLength, (RData{ .TSIG = too_large }).encode(&writer));
}

test "tsig raw parser rejects a MAC larger than HMAC-SHA256" {
    const algorithm = try Name.fromText("hmac-sha256.");
    var raw: [62]u8 = undefined;
    var writer = Writer.init(&raw);
    var time_signed = [_]u8{0} ** 6;
    var mac = [_]u8{0} ** 33;
    try algorithm.encode(&writer);
    try writer.writeBytes(&time_signed);
    try writer.writeU16(0);
    try writer.writeU16(@intCast(mac.len));
    try writer.writeBytes(&mac);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try std.testing.expectEqual(raw.len, writer.len());

    try std.testing.expectError(rdata.Error.InvalidLength, RData.parse(.TSIG, &raw, 0, raw.len));
}

test "tsig RDATA stays within the common record encoder boundary" {
    const algorithm = try Name.fromText("hmac-sha256.");
    var mac = [_]u8{0} ** 32;
    var max_other = [_]u8{0} ** 451;
    const maximum = try Tsig.init(algorithm, 0, 0, &mac, 0, 0, &max_other);

    var output: [1024]u8 = undefined;
    var writer = Writer.init(&output);
    try (ResourceRecord{
        .owner = Name.root(),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = maximum },
    }).encode(&writer);

    var one_over = [_]u8{0} ** 452;
    try std.testing.expectError(
        rdata.Error.InvalidLength,
        Tsig.init(algorithm, 0, 0, &mac, 0, 0, &one_over),
    );
}

// Fixed SHA-256, chained, and altered-intermediary-ID values are reproduced independently in
// docs/decisions/tsig-vectors.md.
test "tsig SHA-256 known-answer vector verifies the received raw wire message" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6b, 0x65,
        0x79, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0b, 0x68, 0x6d, 0x61,
        0x63, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x2c, 0x00, 0x20, 0x2b, 0xcb, 0xce, 0x33, 0x18, 0xfb, 0x82, 0x4c, 0x9e, 0x99, 0x95, 0x2a, 0x71,
        0x02, 0x45, 0x24, 0x0e, 0x8e, 0x49, 0xfb, 0x98, 0x17, 0x8e, 0xc6, 0x32, 0xd2, 0x05, 0x9f, 0xd7,
        0xab, 0xac, 0x45, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
    };
    const mac = try verify(&packet, "topsecret", null, 16);
    try std.testing.expectEqual(@as(usize, 32), mac.slice().len);
    try std.testing.expectEqualSlices(u8, &.{
        0x2b, 0xcb, 0xce, 0x33, 0x18, 0xfb, 0x82, 0x4c,
        0x9e, 0x99, 0x95, 0x2a, 0x71, 0x02, 0x45, 0x24,
        0x0e, 0x8e, 0x49, 0xfb, 0x98, 0x17, 0x8e, 0xc6,
        0x32, 0xd2, 0x05, 0x9f, 0xd7, 0xab, 0xac, 0x45,
    }, mac.slice());

    var altered_id = packet;
    altered_id[0] ^= 0xff;
    const id_mac = try verify(&altered_id, "topsecret", null, 16);
    try std.testing.expectEqualSlices(u8, mac.slice(), id_mac.slice());

    var altered_byte = packet;
    altered_byte[14] = 'f';
    try std.testing.expectError(Error.BadMac, verify(&altered_byte, "topsecret", null, 16));

    var truncated: [89]u8 = undefined;
    @memcpy(truncated[0..67], packet[0..67]);
    std.mem.writeInt(u16, truncated[42..44], 45, .big);
    std.mem.writeInt(u16, truncated[65..67], 16, .big);
    @memcpy(truncated[67..83], packet[67..83]);
    @memcpy(truncated[83..], packet[99..]);
    const truncated_mac = try verify(&truncated, "topsecret", null, 16);
    try std.testing.expectEqualSlices(u8, mac.slice(), truncated_mac.slice());
    try std.testing.expectError(Error.BadTrunc, verify(&truncated, "topsecret", null, 32));

    var forged_truncated = truncated;
    forged_truncated[67] ^= 0xff;
    try std.testing.expectError(Error.BadMac, verify(&forged_truncated, "topsecret", null, 32));

    var too_short: [88]u8 = undefined;
    @memcpy(too_short[0..67], packet[0..67]);
    std.mem.writeInt(u16, too_short[42..44], 44, .big);
    std.mem.writeInt(u16, too_short[65..67], 15, .big);
    @memcpy(too_short[67..82], packet[67..82]);
    @memcpy(too_short[82..], packet[99..]);
    try std.testing.expectError(Error.Formerr, verify(&too_short, "topsecret", null, 16));

    var too_long: [106]u8 = undefined;
    @memcpy(too_long[0..67], packet[0..67]);
    std.mem.writeInt(u16, too_long[42..44], 62, .big);
    std.mem.writeInt(u16, too_long[65..67], 33, .big);
    @memcpy(too_long[67..99], packet[67..99]);
    too_long[99] = 0;
    @memcpy(too_long[100..], packet[99..]);
    try std.testing.expectError(Error.Formerr, verify(&too_long, "topsecret", null, 16));

    var response = packet;
    response[2] = 0x81;
    response[3] = 0x80;
    @memset(response[67..99], 0);
    const response_final = (try parseFinalAdditional(&response)).?;
    const response_mac = try sign(
        &response,
        "topsecret",
        response_final.owner,
        response_final.tsig,
        mac.slice(),
    );
    @memcpy(response[67..99], response_mac.slice());
    try std.testing.expectEqualSlices(
        u8,
        response_mac.slice(),
        (try verify(&response, "topsecret", mac.slice(), 16)).slice(),
    );

    var forwarded_response = response;
    std.mem.writeInt(u16, forwarded_response[0..2], 0x5678, .big);
    @memset(forwarded_response[67..99], 0);
    const forwarded_final = (try parseFinalAdditional(&forwarded_response)).?;
    const forwarded_mac = try sign(
        &forwarded_response,
        "topsecret",
        forwarded_final.owner,
        forwarded_final.tsig,
        mac.slice(),
    );
    try std.testing.expectEqualSlices(u8, &.{
        0x9b, 0xdf, 0x94, 0x4e, 0x57, 0x7f, 0xd7, 0xf9,
        0x17, 0xe7, 0x2b, 0x49, 0x97, 0x76, 0x63, 0x8c,
        0xfb, 0x5b, 0xad, 0xf0, 0x3a, 0xa3, 0x94, 0xf3,
        0x38, 0x90, 0x77, 0xba, 0x83, 0x69, 0xc3, 0x84,
    }, forwarded_mac.slice());

    var unsigned_request: [29]u8 = undefined;
    @memcpy(&unsigned_request, packet[0..29]);
    std.mem.writeInt(u16, unsigned_request[10..12], 0, .big);
    var mismatched_request_tsig = response_final.tsig;
    mismatched_request_tsig.original_id = 0x5678;
    try std.testing.expectError(Error.InvalidOriginalId, sign(
        unsigned_request[0..],
        "topsecret",
        response_final.owner,
        mismatched_request_tsig,
        null,
    ));

    var intermediary: [29]u8 = undefined;
    @memcpy(&intermediary, packet[0..29]);
    std.mem.writeInt(u16, intermediary[10..12], 0, .big);

    var final_unsigned: [29]u8 = undefined;
    @memcpy(&final_unsigned, response[0..29]);
    std.mem.writeInt(u16, final_unsigned[10..12], 0, .big);

    const chained_mac = try signChained(
        &.{ intermediary[0..], final_unsigned[0..] },
        "topsecret",
        response_final.tsig,
        mac.slice(),
    );
    try std.testing.expectEqualSlices(u8, &.{
        0x23, 0x2f, 0x37, 0x48, 0x06, 0xfd, 0x46, 0x04,
        0x26, 0x88, 0xdf, 0xfc, 0xe4, 0x18, 0x91, 0xd1,
        0x4b, 0x25, 0xf2, 0x02, 0xe1, 0x59, 0x77, 0x5a,
        0x24, 0xb5, 0xdb, 0x22, 0x96, 0x65, 0x1e, 0x84,
    }, chained_mac.slice());

    var differently_id_intermediary = intermediary;
    std.mem.writeInt(u16, differently_id_intermediary[0..2], 0xabcd, .big);
    const differently_id_mac = try signChained(
        &.{ differently_id_intermediary[0..], final_unsigned[0..] },
        "topsecret",
        response_final.tsig,
        mac.slice(),
    );
    try std.testing.expectEqualSlices(u8, &.{
        0xd8, 0xaa, 0xdd, 0x7f, 0xdb, 0x1d, 0x40, 0x53,
        0xed, 0x11, 0x2c, 0x58, 0x5d, 0x49, 0x5e, 0x01,
        0xff, 0x75, 0x68, 0xe8, 0xda, 0x2a, 0x97, 0xb6,
        0x4f, 0xcd, 0xe5, 0xec, 0x4c, 0x13, 0xc1, 0xbc,
    }, differently_id_mac.slice());

    var chained_response = response;
    @memcpy(chained_response[67..99], chained_mac.slice());
    try std.testing.expectEqualSlices(u8, chained_mac.slice(), (try verifyChained(
        &.{ intermediary[0..], chained_response[0..] },
        "topsecret",
        mac.slice(),
        16,
    )).slice());

    var differently_id_response = response;
    @memcpy(differently_id_response[67..99], differently_id_mac.slice());
    try std.testing.expectEqualSlices(u8, differently_id_mac.slice(), (try verifyChained(
        &.{ differently_id_intermediary[0..], differently_id_response[0..] },
        "topsecret",
        mac.slice(),
        16,
    )).slice());

    var chained_truncated: [89]u8 = undefined;
    @memcpy(chained_truncated[0..67], chained_response[0..67]);
    std.mem.writeInt(u16, chained_truncated[42..44], 45, .big);
    std.mem.writeInt(u16, chained_truncated[65..67], 16, .big);
    @memcpy(chained_truncated[67..83], chained_response[67..83]);
    @memcpy(chained_truncated[83..], chained_response[99..]);
    try std.testing.expectError(Error.BadTrunc, verifyChained(
        &.{ intermediary[0..], chained_truncated[0..] },
        "topsecret",
        mac.slice(),
        32,
    ));

    var forged_chained_truncated = chained_truncated;
    forged_chained_truncated[67] ^= 0xff;
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ intermediary[0..], forged_chained_truncated[0..] },
        "topsecret",
        mac.slice(),
        32,
    ));

    var altered_chained = chained_response;
    altered_chained[14] = 'f';
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ intermediary[0..], altered_chained[0..] },
        "topsecret",
        mac.slice(),
        16,
    ));

    var altered_intermediary = intermediary;
    altered_intermediary[14] = 'f';
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ altered_intermediary[0..], chained_response[0..] },
        "topsecret",
        mac.slice(),
        16,
    ));
}

// Fixed SHA-1 value is reproduced independently in docs/decisions/tsig-vectors.md.
test "tsig SHA-1 known-answer vector verifies the received raw wire message" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6b, 0x65,
        0x79, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x09, 0x68, 0x6d, 0x61,
        0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2c, 0x00,
        0x14, 0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79, 0xb6, 0xca, 0xb9, 0xf4, 0x1f,
        0xce, 0xc1, 0x06, 0xa8, 0x19, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
    };
    const mac = try verify(&packet, "topsecret", null, 10);
    try std.testing.expectEqual(@as(usize, 20), mac.slice().len);
    try std.testing.expectEqualSlices(u8, &.{
        0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79,
        0xb6, 0xca, 0xb9, 0xf4, 0x1f, 0xce, 0xc1, 0x06, 0xa8, 0x19,
    }, mac.slice());
}
