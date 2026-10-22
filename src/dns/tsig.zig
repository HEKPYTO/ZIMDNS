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
    InvalidPriorMac,
    InvalidOriginalId,
};

/// The HMAC-SHA family of RFC 8945 section 6, with the three truncated
/// names of the same table. HMAC-MD5.SIG-ALG.REG.INT is listed there with a
/// MUST NOT use, and gss-tsig delegates the cryptography to GSS, so neither
/// is a DNS TSIG algorithm this server implements.
pub const Algorithm = enum {
    hmac_sha1,
    hmac_sha224,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,
    hmac_sha256_128,
    hmac_sha384_192,
    hmac_sha512_256,
};

pub const Mac = struct {
    /// The longest keyed hash output in the set: SHA-512 (RFC 8945 section 6).
    bytes: [64]u8 = undefined,
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
        // The algorithm name keeps the spelling the peer used, so the reply
        // carries it back unchanged; the MAC input folds it (section 4.3.3).
        const algorithm = Name.parsePreservingCase(packet, rdata_start) catch return Error.MalformedTsig;
        var value = parsed.TSIG;
        value.algorithm = algorithm.name;
        found = .{
            .owner = owner.name,
            .record_start = record_start,
            .rdata_start = rdata_start,
            .rdata_end = rdata_end,
            .record_end = rdata_end,
            .tsig = value,
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
const hmac_sha224_wire = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '2', '4', 0 };
const hmac_sha256_wire = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0 };
const hmac_sha384_wire = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '3', '8', '4', 0 };
const hmac_sha512_wire = [_]u8{ 11, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '5', '1', '2', 0 };
const hmac_sha256_128_wire = [_]u8{ 15, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', '-', '1', '2', '8', 0 };
const hmac_sha384_192_wire = [_]u8{ 15, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '3', '8', '4', '-', '1', '9', '2', 0 };
const hmac_sha512_256_wire = [_]u8{ 15, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '5', '1', '2', '-', '2', '5', '6', 0 };

/// The algorithm name is a domain name and is compared case-insensitively
/// (RFC 8945 section 9), so a registry name matches in any case.
pub fn algorithmForName(name: *const Name) Error!Algorithm {
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha1_wire)) return .hmac_sha1;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha224_wire)) return .hmac_sha224;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha256_wire)) return .hmac_sha256;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha384_wire)) return .hmac_sha384;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha512_wire)) return .hmac_sha512;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha256_128_wire)) return .hmac_sha256_128;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha384_192_wire)) return .hmac_sha384_192;
    if (std.ascii.eqlIgnoreCase(name.asWire(), &hmac_sha512_256_wire)) return .hmac_sha512_256;
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
    const full = try standardMac(packet, found, key, owner, tsig, prior_mac, true);
    // RFC 8945 section 4.2: the MAC field holds the keyed hash truncated to
    // the MAC Size of the record.
    return truncate(full, @min(@as(usize, tsig.mac_len), full.slice().len));
}

/// Verifies the final TSIG record of a request. The MAC is compared against
/// the truncated prefix of the computed keyed hash in constant time. The local
/// truncation policy floor is not applied here: RFC 8945 section 5.2 orders
/// the truncation policy check after the time check, so the caller applies
/// the floor once the time check has had its say (section 5.2.4).
///
/// The returned MAC is the one that appears in the message: RFC 8945 section
/// 4.3.1 digests the MAC exactly as it is transmitted, so a caller that
/// chains on it must use the transmitted value and not the whole keyed hash.
pub fn verify(
    packet: []const u8,
    key: []const u8,
    prior_mac: ?[]const u8,
) Error!Mac {
    const found = parseFinalAdditional(packet) catch return Error.Formerr;
    const final = found orelse return Error.Formerr;
    const algorithm = try algorithmForName(&final.tsig.algorithm);
    const full = try standardMac(packet, final, key, final.owner, final.tsig, prior_mac, true);
    const received = final.tsig.macBytes();
    // RFC 8945 section 5.2.2.1 case 1: a MAC longer than the keyed hash
    // output is a format error. The bound is the output of the hash function
    // in use, which the truncated names of RFC 4868 section 2.6 keep.
    if (received.len > full.slice().len) return Error.Formerr;
    // Case 3: a MAC shorter than the larger of 10 octets and half the hash
    // length is a format error.
    const protocol_minimum = @max(@as(usize, 10), hashLength(algorithm) / 2);
    if (received.len == 0 or received.len < protocol_minimum) return Error.Formerr;
    // Case 4: the computed MAC is truncated to the size the peer sent and
    // only the truncated values are compared.
    if (std.crypto.timing_safe.compare(u8, received, full.slice()[0..received.len], .big) != .eq) {
        return Error.BadMac;
    }
    // The MAC that appears in the message is the value the next message of a
    // chain carries as its prior MAC (RFC 8945 sections 4.3.1 and 5.3.1).
    return truncate(full, received.len);
}

pub fn signChained(
    packets: []const []const u8,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    const full = try chainedMac(packets, null, key, tsig, prior_mac);
    return truncate(full, @min(@as(usize, tsig.mac_len), full.slice().len));
}

pub fn verifyChained(
    packets: []const []const u8,
    key: []const u8,
    prior_mac: []const u8,
) Error!Mac {
    if (packets.len == 0) return Error.Formerr;
    const packet = packets[packets.len - 1];
    const found = parseFinalAdditional(packet) catch return Error.Formerr;
    const final = found orelse return Error.Formerr;
    const algorithm = try algorithmForName(&final.tsig.algorithm);
    const full = try chainedMac(packets, final, key, final.tsig, prior_mac);
    const received = final.tsig.macBytes();
    // RFC 8945 section 5.2.2.1 case 1: a MAC longer than the keyed hash
    // output is a format error.
    if (received.len > full.slice().len) return Error.Formerr;
    const protocol_minimum = @max(@as(usize, 10), hashLength(algorithm) / 2);
    if (received.len == 0 or received.len < protocol_minimum) return Error.Formerr;
    if (std.crypto.timing_safe.compare(u8, received, full.slice()[0..received.len], .big) != .eq) {
        return Error.BadMac;
    }
    // The MAC that appears in the message is the value the next message of a
    // chain carries as its prior MAC (RFC 8945 sections 4.3.1 and 5.3.1).
    return truncate(full, received.len);
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
    const full = try chainedMac(&.{packet}, final, key, tsig, prior_mac);
    return truncate(full, @min(@as(usize, tsig.mac_len), full.slice().len));
}

/// The first `len` octets of a keyed hash.
fn truncate(mac: Mac, len: usize) Mac {
    return .{ .bytes = mac.bytes, .len = @intCast(len) };
}

/// The MAC length of each algorithm: the keyed hash output of the full
/// HMAC-SHA family, and the RFC 4868 truncation of the truncated names.
pub fn digestLength(algorithm: Algorithm) usize {
    return switch (algorithm) {
        .hmac_sha1 => 20,
        .hmac_sha224 => 28,
        .hmac_sha256 => 32,
        .hmac_sha384 => 48,
        .hmac_sha512 => 64,
        .hmac_sha256_128 => 16,
        .hmac_sha384_192 => 24,
        .hmac_sha512_256 => 32,
    };
}

/// The keyed hash output length of the hash function behind each algorithm:
/// the secret floor of RFC 8945 section 8, the RFC 4868 section 2.6 key
/// length, which the truncated names keep, and the bound of the MAC size
/// (RFC 8945 section 5.2.2.1 case 1).
pub fn hashLength(algorithm: Algorithm) usize {
    return switch (algorithm) {
        .hmac_sha1 => 20,
        .hmac_sha224 => 28,
        .hmac_sha256, .hmac_sha256_128 => 32,
        .hmac_sha384, .hmac_sha384_192 => 48,
        .hmac_sha512, .hmac_sha512_256 => 64,
    };
}

/// Local truncation policy: the shortest MAC the server accepts per algorithm,
/// and every longer MAC up to the full keyed hash output is accepted too
/// (RFC 8945 section 7). The server applies the floor after the time check
/// (section 5.2) and answers a shorter MAC with BADTRUNC (section 5.2.4).
/// SHA-1 takes 12 octets (section 6 SHOULD implement SHA-1
/// truncated to 96 bits) and SHA-256 takes 16 (the section 5.2.2.1 case 3
/// floor, SHA-256-128). The other HMAC-SHA algorithms take the section
/// 5.2.2.1 case 3 floor of half the keyed hash output, which is also the
/// SHA-384-192 and SHA-512-256 truncation of RFC 4868. A truncated name takes
/// the floor of the algorithm it truncates, which is the length of its own
/// MAC.
pub fn minimumMacLength(algorithm: Algorithm) usize {
    return switch (algorithm) {
        .hmac_sha1 => 12,
        .hmac_sha224 => 14,
        .hmac_sha256, .hmac_sha256_128 => 16,
        .hmac_sha384, .hmac_sha384_192 => 24,
        .hmac_sha512, .hmac_sha512_256 => 32,
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
    const algorithm = try algorithmForName(&tsig.algorithm);
    return switch (algorithm) {
        .hmac_sha1 => standardMacWith(std.crypto.auth.hmac.HmacSha1, packet, final, key, owner, tsig, prior_mac, replace_id),
        .hmac_sha224 => standardMacWith(std.crypto.auth.hmac.sha2.HmacSha224, packet, final, key, owner, tsig, prior_mac, replace_id),
        .hmac_sha256, .hmac_sha256_128 => standardMacWith(std.crypto.auth.hmac.sha2.HmacSha256, packet, final, key, owner, tsig, prior_mac, replace_id),
        .hmac_sha384, .hmac_sha384_192 => standardMacWith(std.crypto.auth.hmac.sha2.HmacSha384, packet, final, key, owner, tsig, prior_mac, replace_id),
        .hmac_sha512, .hmac_sha512_256 => standardMacWith(std.crypto.auth.hmac.sha2.HmacSha512, packet, final, key, owner, tsig, prior_mac, replace_id),
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
    var result = Mac{ .len = @intCast(Hmac.mac_length) };
    @memcpy(result.bytes[0..Hmac.mac_length], &digest);
    return result;
}

fn chainedMac(
    packets: []const []const u8,
    final: ?FinalAdditional,
    key: []const u8,
    tsig: Tsig,
    prior_mac: []const u8,
) Error!Mac {
    const algorithm = try algorithmForName(&tsig.algorithm);
    return switch (algorithm) {
        .hmac_sha1 => chainedMacWith(std.crypto.auth.hmac.HmacSha1, packets, final, key, tsig, prior_mac),
        .hmac_sha224 => chainedMacWith(std.crypto.auth.hmac.sha2.HmacSha224, packets, final, key, tsig, prior_mac),
        .hmac_sha256, .hmac_sha256_128 => chainedMacWith(std.crypto.auth.hmac.sha2.HmacSha256, packets, final, key, tsig, prior_mac),
        .hmac_sha384, .hmac_sha384_192 => chainedMacWith(std.crypto.auth.hmac.sha2.HmacSha384, packets, final, key, tsig, prior_mac),
        .hmac_sha512, .hmac_sha512_256 => chainedMacWith(std.crypto.auth.hmac.sha2.HmacSha512, packets, final, key, tsig, prior_mac),
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
    var result = Mac{ .len = @intCast(Hmac.mac_length) };
    @memcpy(result.bytes[0..Hmac.mac_length], &digest);
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
    // RFC 8945 section 4.3.3: the algorithm name enters the digest in
    // canonical wire format, whatever case the peer sent it in.
    const algorithm = tsig.algorithm.folded();
    hmac.update(algorithm.asWire());
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

test "tsig raw parser rejects a MAC larger than the record bound" {
    const algorithm = try Name.fromText("hmac-sha256.");
    var raw: [94]u8 = undefined;
    var writer = Writer.init(&raw);
    var time_signed = @as([6]u8, @splat(@as(u8, 0)));
    var mac = @as([65]u8, @splat(@as(u8, 0)));
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
    var mac = @as([32]u8, @splat(@as(u8, 0)));
    var max_other = @as([451]u8, @splat(@as(u8, 0)));
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

    var one_over = @as([452]u8, @splat(@as(u8, 0)));
    try std.testing.expectError(
        rdata.Error.InvalidLength,
        Tsig.init(algorithm, 0, 0, &mac, 0, 0, &one_over),
    );
}

// Fixed SHA-256, chained, and altered-intermediary-ID values are reproduced independently in
// src/dns/README.md and the tests below.
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
    const mac = try verify(&packet, "topsecret", null);
    try std.testing.expectEqual(@as(usize, 32), mac.slice().len);
    try std.testing.expectEqualSlices(u8, &.{
        0x2b, 0xcb, 0xce, 0x33, 0x18, 0xfb, 0x82, 0x4c,
        0x9e, 0x99, 0x95, 0x2a, 0x71, 0x02, 0x45, 0x24,
        0x0e, 0x8e, 0x49, 0xfb, 0x98, 0x17, 0x8e, 0xc6,
        0x32, 0xd2, 0x05, 0x9f, 0xd7, 0xab, 0xac, 0x45,
    }, mac.slice());

    var altered_id = packet;
    altered_id[0] ^= 0xff;
    const id_mac = try verify(&altered_id, "topsecret", null);
    try std.testing.expectEqualSlices(u8, mac.slice(), id_mac.slice());

    var altered_byte = packet;
    altered_byte[14] = 'f';
    try std.testing.expectError(Error.BadMac, verify(&altered_byte, "topsecret", null));

    var truncated: [89]u8 = undefined;
    @memcpy(truncated[0..67], packet[0..67]);
    std.mem.writeInt(u16, truncated[42..44], 45, .big);
    std.mem.writeInt(u16, truncated[65..67], 16, .big);
    @memcpy(truncated[67..83], packet[67..83]);
    @memcpy(truncated[83..], packet[99..]);
    const truncated_mac = try verify(&truncated, "topsecret", null);
    // The MAC that appears in the message is the value the next message of a
    // chain carries as its prior MAC (RFC 8945 sections 4.3.1 and 5.3.1).
    try std.testing.expectEqual(@as(usize, 16), truncated_mac.slice().len);
    try std.testing.expectEqualSlices(u8, mac.slice()[0..16], truncated_mac.slice());

    var forged_truncated = truncated;
    forged_truncated[67] ^= 0xff;
    try std.testing.expectError(Error.BadMac, verify(&forged_truncated, "topsecret", null));

    var too_short: [88]u8 = undefined;
    @memcpy(too_short[0..67], packet[0..67]);
    std.mem.writeInt(u16, too_short[42..44], 44, .big);
    std.mem.writeInt(u16, too_short[65..67], 15, .big);
    @memcpy(too_short[67..82], packet[67..82]);
    @memcpy(too_short[82..], packet[99..]);
    try std.testing.expectError(Error.Formerr, verify(&too_short, "topsecret", null));

    var too_long: [106]u8 = undefined;
    @memcpy(too_long[0..67], packet[0..67]);
    std.mem.writeInt(u16, too_long[42..44], 62, .big);
    std.mem.writeInt(u16, too_long[65..67], 33, .big);
    @memcpy(too_long[67..99], packet[67..99]);
    too_long[99] = 0;
    @memcpy(too_long[100..], packet[99..]);
    try std.testing.expectError(Error.Formerr, verify(&too_long, "topsecret", null));

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
        (try verify(&response, "topsecret", mac.slice())).slice(),
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
    )).slice());

    var differently_id_response = response;
    @memcpy(differently_id_response[67..99], differently_id_mac.slice());
    try std.testing.expectEqualSlices(u8, differently_id_mac.slice(), (try verifyChained(
        &.{ differently_id_intermediary[0..], differently_id_response[0..] },
        "topsecret",
        mac.slice(),
    )).slice());

    var chained_truncated: [89]u8 = undefined;
    @memcpy(chained_truncated[0..67], chained_response[0..67]);
    std.mem.writeInt(u16, chained_truncated[42..44], 45, .big);
    std.mem.writeInt(u16, chained_truncated[65..67], 16, .big);
    @memcpy(chained_truncated[67..83], chained_response[67..83]);
    @memcpy(chained_truncated[83..], chained_response[99..]);
    // RFC 8945 section 5.2.2.1 case 4: the chained MAC is truncated to the
    // size the peer sent and only the truncated values are compared. The MAC
    // that appears in the message is the value the next message of the chain
    // carries as its prior MAC (RFC 8945 sections 4.3.1 and 5.3.1).
    const chained_truncated_mac = try verifyChained(
        &.{ intermediary[0..], chained_truncated[0..] },
        "topsecret",
        mac.slice(),
    );
    try std.testing.expectEqual(@as(usize, 16), chained_truncated_mac.slice().len);
    try std.testing.expectEqualSlices(u8, chained_mac.slice()[0..16], chained_truncated_mac.slice());

    var forged_chained_truncated = chained_truncated;
    forged_chained_truncated[67] ^= 0xff;
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ intermediary[0..], forged_chained_truncated[0..] },
        "topsecret",
        mac.slice(),
    ));

    var altered_chained = chained_response;
    altered_chained[14] = 'f';
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ intermediary[0..], altered_chained[0..] },
        "topsecret",
        mac.slice(),
    ));

    var altered_intermediary = intermediary;
    altered_intermediary[14] = 'f';
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{ altered_intermediary[0..], chained_response[0..] },
        "topsecret",
        mac.slice(),
    ));
}

// Fixed SHA-1 value is reproduced independently in the test below.
test "tsig SHA-1 known-answer vector verifies the received raw wire message" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6b, 0x65,
        0x79, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x09, 0x68, 0x6d, 0x61,
        0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2c, 0x00,
        0x14, 0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79, 0xb6, 0xca, 0xb9, 0xf4, 0x1f,
        0xce, 0xc1, 0x06, 0xa8, 0x19, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
    };
    const mac = try verify(&packet, "topsecret", null);
    try std.testing.expectEqual(@as(usize, 20), mac.slice().len);
    try std.testing.expectEqualSlices(u8, &.{
        0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79,
        0xb6, 0xca, 0xb9, 0xf4, 0x1f, 0xce, 0xc1, 0x06, 0xa8, 0x19,
    }, mac.slice());
}

/// Rebuilds the SHA-1 known-answer request with a MAC field of `mac_len`
/// octets holding the known digest prefix. The digest never covers the MAC
/// field, so the expected MAC stays the known answer.
fn sha1RequestWithMac(packet: []const u8, out: []u8, mac_len: usize) void {
    const rdlength_at = 42;
    const mac_size_at = 63;
    const mac_start = 65;
    const known_mac_len = 20;
    const known_rdlength = 47;
    @memcpy(out[0..mac_start], packet[0..mac_start]);
    std.mem.writeInt(u16, out[rdlength_at..][0..2], @intCast(known_rdlength - known_mac_len + mac_len), .big);
    std.mem.writeInt(u16, out[mac_size_at..][0..2], @intCast(mac_len), .big);
    @memset(out[mac_start .. mac_start + mac_len], 0);
    const copied = @min(mac_len, known_mac_len);
    @memcpy(out[mac_start..][0..copied], packet[mac_start..][0..copied]);
    @memcpy(out[mac_start + mac_len ..], packet[mac_start + known_mac_len ..]);
}

test "tsig SHA-1 truncation follows the protocol floor" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6b, 0x65,
        0x79, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x09, 0x68, 0x6d, 0x61,
        0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x2c, 0x00,
        0x14, 0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79, 0xb6, 0xca, 0xb9, 0xf4, 0x1f,
        0xce, 0xc1, 0x06, 0xa8, 0x19, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
    };

    // RFC 8945 section 4.2: the MAC Size gives the length of the MAC field, so
    // the twelve-octet truncation of the known digest authenticates.
    var truncated: [83]u8 = undefined;
    sha1RequestWithMac(&packet, &truncated, 12);
    const mac = try verify(&truncated, "topsecret", null);
    try std.testing.expectEqualSlices(u8, &.{
        0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79, 0xb6, 0xca,
    }, mac.slice());

    // RFC 8945 section 5.2.2.1 case 3: the protocol floor is the larger of ten
    // octets and half the hash length, so ten octets is the shortest MAC this
    // module accepts. The local policy floor is the caller's, and section 5.2
    // orders that check after the time check.
    var at_floor: [81]u8 = undefined;
    sha1RequestWithMac(&packet, &at_floor, 10);
    const floor_mac = try verify(&at_floor, "topsecret", null);
    try std.testing.expectEqualSlices(u8, &.{
        0xa6, 0xbf, 0x26, 0xfc, 0xb2, 0x0e, 0x83, 0x61, 0x62, 0x79,
    }, floor_mac.slice());

    // One octet below the protocol floor is a format error.
    var too_short: [80]u8 = undefined;
    sha1RequestWithMac(&packet, &too_short, 9);
    try std.testing.expectError(Error.Formerr, verify(&too_short, "topsecret", null));

    // RFC 8945 section 5.2.2.1 case 1: a MAC longer than the keyed hash
    // output is a format error.
    var too_long: [92]u8 = undefined;
    sha1RequestWithMac(&packet, &too_long, 21);
    try std.testing.expectError(Error.Formerr, verify(&too_long, "topsecret", null));

    // A MAC of zero octets is the unsigned case and never authenticates.
    var unsigned: [71]u8 = undefined;
    sha1RequestWithMac(&packet, &unsigned, 0);
    try std.testing.expectError(Error.Formerr, verify(&unsigned, "topsecret", null));
}

/// Writes the known-answer request used by the SHA-1 and SHA-256 vectors
/// with another algorithm name and MAC field length. The digest never covers
/// the MAC field, so the expected MAC only depends on the algorithm name.
fn writeRequest(writer: *Writer, algorithm: []const u8, mac_len: usize) !void {
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try writer.writeBytes(&.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    var mac = @as([64]u8, @splat(@as(u8, 0)));
    const value = try Tsig.init(try Name.fromText(algorithm), 1, 300, mac[0..mac_len], 0x1234, 0, &.{});
    try (ResourceRecord{
        .owner = try Name.fromText("key."),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(writer);
}

test "tsig algorithm names cover the RFC 8945 section 6 HMAC-SHA family" {
    const cases = [_]struct { name: []const u8, algorithm: Algorithm }{
        .{ .name = "hmac-sha1.", .algorithm = .hmac_sha1 },
        .{ .name = "hmac-sha224.", .algorithm = .hmac_sha224 },
        .{ .name = "hmac-sha256.", .algorithm = .hmac_sha256 },
        .{ .name = "hmac-sha384.", .algorithm = .hmac_sha384 },
        .{ .name = "hmac-sha512.", .algorithm = .hmac_sha512 },
        .{ .name = "hmac-sha256-128.", .algorithm = .hmac_sha256_128 },
        .{ .name = "hmac-sha384-192.", .algorithm = .hmac_sha384_192 },
        .{ .name = "hmac-sha512-256.", .algorithm = .hmac_sha512_256 },
    };
    for (cases) |case| {
        const name = try Name.fromText(case.name);
        try std.testing.expectEqual(case.algorithm, try algorithmForName(&name));
    }
    // HMAC-MD5.SIG-ALG.REG.INT is a MUST NOT use in section 6, and gss-tsig
    // delegates the cryptography to GSS.
    for ([_][]const u8{
        "hmac-md5.sig-alg.reg.int.",
        "gss-tsig.",
    }) |refused| {
        const name = try Name.fromText(refused);
        try std.testing.expectError(Error.UnsupportedAlgorithm, algorithmForName(&name));
    }
}

test "tsig verifies a request signed with a truncated algorithm name" {
    const cases = [_]struct { name: []const u8, algorithm: Algorithm, mac_len: usize }{
        .{ .name = "hmac-sha256-128.", .algorithm = .hmac_sha256_128, .mac_len = 16 },
        .{ .name = "hmac-sha384-192.", .algorithm = .hmac_sha384_192, .mac_len = 24 },
        .{ .name = "hmac-sha512-256.", .algorithm = .hmac_sha512_256, .mac_len = 32 },
    };
    for (cases) |case| {
        var packet: [512]u8 = undefined;
        var writer = Writer.init(&packet);
        try writeRequest(&writer, case.name, case.mac_len);
        const final = (try parseFinalAdditional(writer.written())).?;
        const mac = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);
        try std.testing.expectEqual(case.mac_len, mac.slice().len);
        try std.testing.expectEqual(case.mac_len, digestLength(case.algorithm));

        var signed: [512]u8 = undefined;
        requestWithMacPrefix(writer.written(), final, mac.slice(), case.mac_len, &signed);
        const verified = try verify(signed[0..writer.len()], "topsecret", null);
        try std.testing.expectEqualSlices(u8, mac.slice(), verified.slice());

        // RFC 8945 section 5.2.2.1 case 3: a MAC shorter than half the hash
        // length is a format error.
        var shorter: [512]u8 = undefined;
        var shorter_writer = Writer.init(&shorter);
        try writeRequest(&shorter_writer, case.name, case.mac_len - 1);
        try std.testing.expectError(Error.Formerr, verify(shorter_writer.written(), "topsecret", null));
    }
}

test "tsig verifies a truncated name whose MAC is longer than the algorithm's own length" {
    const cases = [_]struct { name: []const u8, algorithm: Algorithm, mac_len: usize }{
        .{ .name = "hmac-sha256-128.", .algorithm = .hmac_sha256_128, .mac_len = 20 },
        .{ .name = "hmac-sha384-192.", .algorithm = .hmac_sha384_192, .mac_len = 28 },
        .{ .name = "hmac-sha512-256.", .algorithm = .hmac_sha512_256, .mac_len = 36 },
    };
    for (cases) |case| {
        var packet: [512]u8 = undefined;
        var writer = Writer.init(&packet);
        try writeRequest(&writer, case.name, case.mac_len);
        const final = (try parseFinalAdditional(writer.written())).?;
        const mac = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);
        try std.testing.expectEqual(case.mac_len, mac.slice().len);
        try patchMac(packet[0..writer.len()], final, mac.slice());
        // RFC 8945 section 5.2.2.1 case 4: the computed MAC is truncated to
        // the size the peer sent and only the truncated values are compared.
        // The truncated name names the hash function and its truncation, so
        // the bound is the keyed hash output and not the truncation.
        const verified = try verify(writer.written(), "topsecret", null);
        try std.testing.expectEqualSlices(u8, mac.slice(), verified.slice());
    }
}

test "the verified MAC is the MAC that appears in the message" {
    var packet: [512]u8 = undefined;
    var writer = Writer.init(&packet);
    try writeRequest(&writer, "hmac-sha256.", 32);
    const final = (try parseFinalAdditional(writer.written())).?;
    const signed = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);
    try patchMac(packet[0..writer.len()], final, signed.slice());
    // The MAC that goes on the wire and the MAC the verification returns are
    // the same value (RFC 8945 section 4.2).
    const verified = try verify(packet[0..writer.len()], "topsecret", null);
    try std.testing.expectEqualSlices(u8, signed.slice(), verified.slice());
}

test "a truncated MAC chains the next message of the chain" {
    var packet: [512]u8 = undefined;
    var writer = Writer.init(&packet);
    try writeRequest(&writer, "hmac-sha256.", 32);
    const final = (try parseFinalAdditional(writer.written())).?;
    const mac = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);
    try std.testing.expectEqual(@as(usize, 32), mac.slice().len);

    // The peer sends a MAC of sixteen octets. The verification returns the
    // MAC as it appears in the message, which is the value the next message
    // of the chain carries as its prior MAC (RFC 8945 sections 4.3.1
    // and 5.3.1).
    var truncated: [512]u8 = undefined;
    requestWithMacPrefix(writer.written(), final, mac.slice(), 16, &truncated);
    const truncated_len = writer.len() - (mac.slice().len - 16);
    const verified = try verify(truncated[0..truncated_len], "topsecret", null);
    try std.testing.expectEqual(@as(usize, 16), verified.slice().len);
    try std.testing.expectEqualSlices(u8, mac.slice()[0..16], verified.slice());

    // The next message of the chain carries the verified MAC as its prior
    // MAC, and the peer agrees with the chained MAC.
    var next: [512]u8 = undefined;
    var next_writer = Writer.init(&next);
    try writeRequest(&next_writer, "hmac-sha256.", 32);
    const next_final = (try parseFinalAdditional(next_writer.written())).?;
    const chained = try signChainedFinal(
        next_writer.written(),
        next_final,
        "topsecret",
        next_final.tsig,
        verified.slice(),
    );
    try patchMac(next[0..next_writer.len()], next_final, chained.slice());
    const chained_verified = try verifyChained(
        &.{next[0..next_writer.len()]},
        "topsecret",
        verified.slice(),
    );
    try std.testing.expectEqualSlices(u8, chained.slice(), chained_verified.slice());

    // The untruncated digest is a different prior MAC: it chains to a
    // different MAC and refuses the message the peer signed.
    const untruncated = try signChainedFinal(
        next_writer.written(),
        next_final,
        "topsecret",
        next_final.tsig,
        mac.slice(),
    );
    try std.testing.expect(!std.mem.eql(u8, chained.slice(), untruncated.slice()));
    try std.testing.expectError(Error.BadMac, verifyChained(
        &.{next[0..next_writer.len()]},
        "topsecret",
        mac.slice(),
    ));
}

test "tsig refuses a MAC longer than the keyed hash output of a truncated name" {
    const cases = [_]struct { name: []const u8, algorithm: Algorithm, mac_len: usize }{
        .{ .name = "hmac-sha256-128.", .algorithm = .hmac_sha256_128, .mac_len = 33 },
        .{ .name = "hmac-sha384-192.", .algorithm = .hmac_sha384_192, .mac_len = 49 },
    };
    for (cases) |case| {
        var packet: [512]u8 = undefined;
        var writer = Writer.init(&packet);
        try writeRequest(&writer, case.name, case.mac_len);
        // RFC 8945 section 5.2.2.1 case 1: a MAC longer than the keyed hash
        // output is a format error.
        try std.testing.expectError(Error.Formerr, verify(writer.written(), "topsecret", null));
    }
}

test "tsig keeps the truncated algorithm names apart from the full family" {
    const cases = [_]struct { truncated: []const u8, full: []const u8 }{
        .{ .truncated = "hmac-sha256-128.", .full = "hmac-sha256." },
        .{ .truncated = "hmac-sha384-192.", .full = "hmac-sha384." },
        .{ .truncated = "hmac-sha512-256.", .full = "hmac-sha512." },
    };
    for (cases) |case| {
        const truncated_name = try Name.fromText(case.truncated);
        const full_name = try Name.fromText(case.full);
        const truncated = try algorithmForName(&truncated_name);
        const full = try algorithmForName(&full_name);
        // A key of the full algorithm never authenticates a request that
        // names the truncated one, and the other way round.
        try std.testing.expect(truncated != full);
        // RFC 4868 section 2.6: the truncated name keeps the key length of
        // the algorithm it truncates and halves the output.
        try std.testing.expectEqual(hashLength(full), hashLength(truncated));
        try std.testing.expectEqual(digestLength(full) / 2, digestLength(truncated));
    }
}

test "tsig matches the algorithm name case-insensitively and answers with the peer's spelling" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6b, 0x65,
        0x79, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0b, 0x68, 0x6d, 0x61,
        0x63, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x2c, 0x00, 0x20, 0x2b, 0xcb, 0xce, 0x33, 0x18, 0xfb, 0x82, 0x4c, 0x9e, 0x99, 0x95, 0x2a, 0x71,
        0x02, 0x45, 0x24, 0x0e, 0x8e, 0x49, 0xfb, 0x98, 0x17, 0x8e, 0xc6, 0x32, 0xd2, 0x05, 0x9f, 0xd7,
        0xab, 0xac, 0x45, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
    };
    const final = (try parseFinalAdditional(&packet)).?;
    // The peer spelled the algorithm name in another case. The MAC still
    // covers the canonical form (RFC 8945 section 4.3.3), so the request
    // authenticates, and the reply carries the spelling back.
    var upper = packet;
    @memcpy(upper[final.rdata_start + 1 ..][0..11], "HMAC-SHA256");

    const mac = try verify(&upper, "topsecret", null);
    try std.testing.expectEqualSlices(u8, &.{
        0x2b, 0xcb, 0xce, 0x33, 0x18, 0xfb, 0x82, 0x4c,
        0x9e, 0x99, 0x95, 0x2a, 0x71, 0x02, 0x45, 0x24,
        0x0e, 0x8e, 0x49, 0xfb, 0x98, 0x17, 0x8e, 0xc6,
        0x32, 0xd2, 0x05, 0x9f, 0xd7, 0xab, 0xac, 0x45,
    }, mac.slice());

    const upper_final = (try parseFinalAdditional(&upper)).?;
    try std.testing.expectEqualSlices(u8, "HMAC-SHA256", upper_final.tsig.algorithm.asWire()[1..12]);
    try std.testing.expectEqual(Algorithm.hmac_sha256, try algorithmForName(&upper_final.tsig.algorithm));

    var response = upper;
    response[2] = 0x81;
    response[3] = 0x80;
    @memset(response[67..99], 0);
    const response_final = (try parseFinalAdditional(&response)).?;
    const response_mac = try sign(&response, "topsecret", response_final.owner, response_final.tsig, mac.slice());
    @memcpy(response[67..99], response_mac.slice());
    try std.testing.expectEqualSlices(
        u8,
        response_mac.slice(),
        (try verify(&response, "topsecret", mac.slice())).slice(),
    );
    const reply_final = (try parseFinalAdditional(&response)).?;
    try std.testing.expectEqualSlices(u8, "HMAC-SHA256", reply_final.tsig.algorithm.asWire()[1..12]);
}

test "tsig digest length is the keyed hash output of each algorithm" {
    try std.testing.expectEqual(@as(usize, 20), digestLength(.hmac_sha1));
    try std.testing.expectEqual(@as(usize, 28), digestLength(.hmac_sha224));
    try std.testing.expectEqual(@as(usize, 32), digestLength(.hmac_sha256));
    try std.testing.expectEqual(@as(usize, 48), digestLength(.hmac_sha384));
    try std.testing.expectEqual(@as(usize, 64), digestLength(.hmac_sha512));
}

test "tsig signs with the keyed hash of each supported algorithm" {
    // The SHA-224, SHA-384, and SHA-512 answers come from an independent
    // HMAC over the section 4.3 digest input; the SHA-1 and SHA-256 answers
    // are the known-answer vectors above.
    const cases = [_]struct { name: []const u8, algorithm: Algorithm, expected: []const u8 }{
        .{ .name = "hmac-sha224.", .algorithm = .hmac_sha224, .expected = &.{
            0x94, 0x18, 0x68, 0x94, 0x4d, 0xea, 0xd1, 0xa3, 0xe4, 0xa2, 0x16, 0xbb, 0x6f, 0x10,
            0x64, 0x07, 0x39, 0xa5, 0x0b, 0xdd, 0x8f, 0x1a, 0x1e, 0x9e, 0xbc, 0x8e, 0xdd, 0x4e,
        } },
        .{ .name = "hmac-sha384.", .algorithm = .hmac_sha384, .expected = &.{
            0x83, 0x64, 0x89, 0x92, 0xee, 0xf7, 0x06, 0xdb, 0x45, 0x2f, 0x2e, 0xb5, 0x81, 0x99,
            0x39, 0x93, 0xb6, 0xbe, 0x96, 0x82, 0xe1, 0x51, 0xda, 0xbc, 0x41, 0xcb, 0xd6, 0x65,
            0x73, 0xc4, 0xdd, 0x6e, 0xfe, 0x10, 0x18, 0x6a, 0x57, 0xec, 0x5b, 0x9c, 0x8c, 0x2e,
            0x2c, 0x2a, 0xa1, 0x9b, 0x24, 0x5f,
        } },
        .{ .name = "hmac-sha512.", .algorithm = .hmac_sha512, .expected = &.{
            0xf9, 0x35, 0xca, 0x6f, 0x7d, 0x61, 0xe0, 0xcb, 0x88, 0xf4, 0x42, 0x54, 0x30, 0xb1,
            0x13, 0xff, 0x5b, 0x1c, 0x9a, 0x69, 0x9e, 0x12, 0x82, 0x5b, 0x16, 0x26, 0xf7, 0x44,
            0x93, 0x9f, 0x5e, 0xfd, 0x5e, 0x54, 0xee, 0xf9, 0x6b, 0x28, 0xad, 0x78, 0x75, 0xf9,
            0xf1, 0xa2, 0xdf, 0xd4, 0x51, 0x9d, 0xa7, 0xee, 0x9f, 0xe3, 0x16, 0xcc, 0x3a, 0xb4,
            0x4b, 0xd3, 0x8d, 0x0a, 0x8c, 0xc2, 0xb7, 0x1e,
        } },
    };
    for (cases) |case| {
        var packet: [512]u8 = undefined;
        var writer = Writer.init(&packet);
        try writeRequest(&writer, case.name, digestLength(case.algorithm));
        const final = (try parseFinalAdditional(writer.written())).?;
        const mac = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);
        try std.testing.expectEqual(digestLength(case.algorithm), mac.slice().len);
        try std.testing.expectEqualSlices(u8, case.expected, mac.slice());
    }
}

test "tsig rejects a MAC longer than the keyed hash output" {
    var packet: [512]u8 = undefined;
    var writer = Writer.init(&packet);
    try writeRequest(&writer, "hmac-sha384.", 49);
    // RFC 8945 section 5.2.2.1 case 1: a MAC longer than the keyed hash
    // output is a format error.
    try std.testing.expectError(Error.Formerr, verify(writer.written(), "topsecret", null));
}

/// Rebuilds a signed request with a MAC field of `mac_len` octets holding the
/// prefix of the computed MAC. The digest never covers the MAC field, so the
/// expected MAC stays the same.
fn requestWithMacPrefix(request: []const u8, final: FinalAdditional, mac: []const u8, mac_len: usize, out: []u8) void {
    const mac_size_at = final.rdata_start + final.tsig.algorithm.asWire().len + 8;
    const mac_start = mac_size_at + 2;
    @memcpy(out[0..mac_start], request[0..mac_start]);
    std.mem.writeInt(u16, out[final.rdata_start - 2 ..][0..2], @intCast(final.rdata_end - final.rdata_start - (mac.len - mac_len)), .big);
    std.mem.writeInt(u16, out[mac_size_at..][0..2], @intCast(mac_len), .big);
    @memcpy(out[mac_start..][0..mac_len], mac[0..mac_len]);
    const tail = request[mac_start + mac.len ..];
    @memcpy(out[mac_start + mac_len ..][0..tail.len], tail);
}

test "tsig truncation follows the protocol floor of each HMAC-SHA algorithm" {
    const cases = [_]struct { name: []const u8, algorithm: Algorithm }{
        .{ .name = "hmac-sha224.", .algorithm = .hmac_sha224 },
        .{ .name = "hmac-sha384.", .algorithm = .hmac_sha384 },
        .{ .name = "hmac-sha512.", .algorithm = .hmac_sha512 },
    };
    for (cases) |case| {
        var packet: [512]u8 = undefined;
        var writer = Writer.init(&packet);
        try writeRequest(&writer, case.name, digestLength(case.algorithm));
        const final = (try parseFinalAdditional(writer.written())).?;
        const mac = try sign(writer.written(), "topsecret", final.owner, final.tsig, null);

        // RFC 8945 section 5.2.2.1 case 3: the protocol floor is the larger
        // of ten octets and half the keyed hash output.
        const floor = @max(@as(usize, 10), hashLength(case.algorithm) / 2);
        var truncated: [512]u8 = undefined;
        requestWithMacPrefix(writer.written(), final, mac.slice(), floor, &truncated);
        _ = try verify(truncated[0 .. writer.len() - (mac.slice().len - floor)], "topsecret", null);

        // One octet below the floor is below the section 5.2.2.1 case 3
        // minimum of half the keyed hash output, so it is a format error.
        var too_short: [512]u8 = undefined;
        requestWithMacPrefix(writer.written(), final, mac.slice(), floor - 1, &too_short);
        try std.testing.expectError(Error.Formerr, verify(
            too_short[0 .. writer.len() - (mac.slice().len - floor + 1)],
            "topsecret",
            null,
        ));
    }
}
