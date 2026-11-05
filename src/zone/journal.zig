const std = @import("std");
const builtin = @import("builtin");
const dns_name = @import("../dns/name.zig");
const dns_record = @import("../dns/record.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const zone_parser = @import("parser.zig");

pub const SerialOrder = enum {
    equal,
    older,
    newer,
    undefined,
};

pub fn compareSerial(left: u32, right: u32) SerialOrder {
    const distance = left -% right;
    if (distance == 0) return .equal;
    if (distance == 0x8000_0000) return .undefined;
    return if (distance < 0x8000_0000) .newer else .older;
}

test "serial comparison treats equal values as equal" {
    try std.testing.expectEqual(SerialOrder.equal, compareSerial(42, 42));
}

test "serial comparison orders ordinary serials" {
    try std.testing.expectEqual(SerialOrder.older, compareSerial(1, 2));
    try std.testing.expectEqual(SerialOrder.newer, compareSerial(2, 1));
}

test "serial comparison treats zero after max as newer" {
    try std.testing.expectEqual(SerialOrder.newer, compareSerial(0, 0xffff_ffff));
}

test "serial comparison leaves the half-range undefined" {
    try std.testing.expectEqual(SerialOrder.undefined, compareSerial(0, 0x8000_0000));
    try std.testing.expectEqual(SerialOrder.undefined, compareSerial(0x8000_0000, 0));
}

/// Bounded log of zone serial transitions backing RFC 1995 IXFR delta
/// decisions. It records which serials the current snapshot supersedes so
/// the server can tell a client asking from serial S whether an incremental
/// sequence to the current serial is still known. When the log no longer
/// connects S to the current serial, the server must fall back to a full
/// AXFR. Entries are evicted oldest-first. The log is volatile transfer
/// state, and it is written to disk only when the operator names a journal
/// file (see Journal).
pub const max_deltas: usize = 8;

/// The longest zone apex a journal record carries.
pub const max_origin_len = 256;

/// The longest journal path the server accepts.
pub const max_path_len = 256;

/// The journal file is read in one piece, and it is not written past this
/// size: a bigger file is not read, and the file cannot grow without bound.
pub const max_journal_bytes = 1024 * 1024;

/// The largest difference one transition carries, in bytes of encoded text.
/// A change bigger than this is not recorded as a difference, so the client
/// at the old serial gets the full transfer instead of a wrong difference.
pub const max_delta_bytes = 1024;

/// The differences the running server keeps. The delta log holds eight
/// transitions, so the store holds more than a log can reach.
pub const max_stored_deltas = 32;

pub const DeltaError = error{
    SerialEqual,
    SerialOlder,
    SerialUndefined,
    /// The transition carries no difference, so the client at its serial is
    /// answered with the full transfer.
    NoDifference,
};

/// One transition read from the journal file.
pub const Transition = struct {
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    from_serial: u32 = 0,
    to_serial: u32 = 0,

    pub fn originText(self: *const Transition) []const u8 {
        return self.origin[0..self.origin_len];
    }
};

/// One stored difference: the records one transition removed and added.
const StoredDelta = struct {
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    from_serial: u32 = 0,
    to_serial: u32 = 0,
    text: [max_delta_bytes]u8 = undefined,
    text_len: usize = 0,
    /// The wire size of the records the difference carries besides its own
    /// SOA records.
    wire_bytes: usize = 0,
};

/// A non-shorter incremental chain the shared-lock read path decided to
/// answer with AXFR, drained under the exclusive lock after release.
pub const PendingEvict = struct {
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    client_serial: u32 = 0,
    server_serial: u32 = 0,

    pub fn originText(self: *const PendingEvict) []const u8 {
        return self.origin[0..self.origin_len];
    }
};

/// The differences the running server keeps. The oldest difference goes
/// when a new one arrives, and the transition it belonged to falls back to
/// the full transfer.
var stored: [max_stored_deltas]StoredDelta = undefined;
var stored_len: usize = 0;

/// The zones the server serves, by apex. The zone index registers a zone
/// here when it loads the zone, so the RFC 1995 section 5 comparison has the
/// full transfer of the zone to measure the incremental answer against.
const max_zones = 64;

const ZoneSize = struct {
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    /// The wire size of the records a full transfer of the zone carries.
    bytes: usize = 0,
};

var zone_sizes: [max_zones]ZoneSize = undefined;
var zone_sizes_len: usize = 0;

/// Records the wire size of the full transfer of the zone with the given
/// apex. A zone the table does not hold is not recorded: the server then
/// knows no full transfer, and the incremental answer is the one it serves.
pub fn registerZoneSize(origin: []const u8, bytes: usize) void {
    if (origin.len == 0 or origin.len > max_origin_len) return;
    for (zone_sizes[0..zone_sizes_len]) |*entry| {
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        entry.bytes = bytes;
        return;
    }
    if (zone_sizes_len == max_zones) return;
    const entry = &zone_sizes[zone_sizes_len];
    @memcpy(entry.origin[0..origin.len], origin);
    entry.origin_len = origin.len;
    entry.bytes = bytes;
    zone_sizes_len += 1;
}

/// The wire size of the full transfer of the zone with the given apex, or
/// zero when the server does not know it.
pub fn zoneSize(origin: []const u8) usize {
    for (zone_sizes[0..zone_sizes_len]) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        return entry.bytes;
    }
    return 0;
}

/// One difference on the way from a client's serial to the current one.
pub const Delta = struct {
    from_serial: u32,
    to_serial: u32,
    /// The records the transition removed and added, in the journal's
    /// encoding.
    text: []const u8,
    /// The wire size of the records the difference carries besides its own
    /// SOA records.
    wire_bytes: usize,
};

/// Keeps the difference of one transition. A difference that does not fit the
/// bound, a difference that cannot be turned into records, or a transition
/// that is not RFC 1982 newer, is not kept: the client at its serial then
/// gets the full transfer.
fn storeDelta(origin: []const u8, from_serial: u32, to_serial: u32, text: []const u8) void {
    if (origin.len == 0 or origin.len > max_origin_len) return;
    if (text.len == 0 or text.len > max_delta_bytes) return;
    if (compareSerial(to_serial, from_serial) != .newer) return;
    // A difference that cannot be turned into records is dropped: the
    // client at that serial gets the full transfer, never an incremental
    // answer built from records that are not records.
    if (!differenceIsUsable(text)) return;
    // A difference that does not open with the two SOA records of its
    // transition is not the transition it claims to be, so it is dropped
    // the same way.
    if (!differenceMatchesTransition(text, from_serial, to_serial)) return;
    const wire_bytes = differenceBytes(text);
    // A transition the store already holds keeps its place: the difference
    // that comes later is the one the answer is built from.
    for (stored[0..stored_len]) |*entry| {
        if (entry.from_serial != from_serial or entry.to_serial != to_serial) continue;
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        @memcpy(entry.text[0..text.len], text);
        entry.text_len = text.len;
        entry.wire_bytes = wire_bytes;
        return;
    }
    if (stored_len == max_stored_deltas) {
        std.mem.copyForwards(StoredDelta, stored[0 .. max_stored_deltas - 1], stored[1..]);
        stored_len = max_stored_deltas - 1;
    }
    const entry = &stored[stored_len];
    @memcpy(entry.origin[0..origin.len], origin);
    entry.origin_len = origin.len;
    entry.from_serial = from_serial;
    entry.to_serial = to_serial;
    @memcpy(entry.text[0..text.len], text);
    entry.text_len = text.len;
    entry.wire_bytes = wire_bytes;
    stored_len += 1;
}

/// The wire size of one record: the bytes the record takes in a DNS
/// message, the same count the answer carries.
pub fn recordBytes(record: dns_record.ResourceRecord) usize {
    var buffer: [max_record_bytes]u8 = undefined;
    var writer = dns_writer.Writer.init(&buffer);
    // A record that does not fit the wire is malformed, and the buffer is
    // the largest a record can be.
    record.encode(&writer) catch return buffer.len;
    return writer.len();
}

/// The longest a record can be on the wire.
const max_record_bytes = 65535;

/// The wire size of the records a difference carries besides its own two SOA
/// records: the bytes the incremental answer adds to the two current SOA
/// records it shares with the full transfer. Both answers carry those two
/// records, so only the other records are compared (RFC 1995 section 5).
/// The full transfer drops its own SOA for the same reason.
fn differenceBytes(text: []const u8) usize {
    var total: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const record = parseDeltaRecord(line) orelse continue;
        // The difference carries the older SOA and the newer SOA; the answer
        // carries the current SOA twice, so the difference's own SOA records
        // are not part of the comparison.
        if (record.rrtype_code == dns_types.RecordType.SOA.code()) continue;
        const converted = toResourceRecord(record) catch continue;
        total += recordBytes(converted);
    }
    return total;
}

/// The difference one transition carries, or null when the store does not
/// hold it.
pub fn differenceFor(origin: []const u8, from_serial: u32, to_serial: u32) ?[]const u8 {
    for (stored[0..stored_len]) |*entry| {
        if (entry.from_serial != from_serial or entry.to_serial != to_serial) continue;
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        return entry.text[0..entry.text_len];
    }
    return null;
}

/// The next difference on the way out of `from_serial`, or null when the
/// store does not hold one.
pub fn nextDelta(origin: []const u8, from_serial: u32) ?Delta {
    for (stored[0..stored_len]) |*entry| {
        if (entry.from_serial != from_serial) continue;
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        return .{
            .from_serial = entry.from_serial,
            .to_serial = entry.to_serial,
            .text = entry.text[0..entry.text_len],
            .wire_bytes = entry.wire_bytes,
        };
    }
    return null;
}

/// The wire size of the differences on the way from `from_serial` to
/// `to_serial`: the bytes the incremental answer carries besides its two
/// current SOA records.
pub fn differenceChainBytes(origin: []const u8, from_serial: u32, to_serial: u32) usize {
    var total: usize = 0;
    var next = from_serial;
    var hops: usize = 0;
    while (next != to_serial) : (hops += 1) {
        if (hops > max_stored_deltas) return total;
        const delta = nextDelta(origin, next) orelse return total;
        total += delta.wire_bytes;
        next = delta.to_serial;
    }
    return total;
}

/// Drops the difference of the oldest version on the way out of
/// `from_serial`: the information about that version does not stay in the
/// store, so the storage stays bounded the way RFC 1995 section 5
/// describes. Reachable only from the runtime exclusive lock; never from a
/// shared-lock read path.
pub fn evictOldestDifference(origin: []const u8, from_serial: u32) void {
    for (stored[0..stored_len], 0..) |entry, index| {
        if (entry.from_serial != from_serial) continue;
        if (!std.ascii.eqlIgnoreCase(entry.origin[0..entry.origin_len], origin)) continue;
        dropStored(index);
        return;
    }
}

/// Removes one difference from the store.
fn dropStored(index: usize) void {
    std.mem.copyForwards(StoredDelta, stored[index .. stored_len - 1], stored[index + 1 .. stored_len]);
    stored_len -= 1;
}

/// Reports whether the store holds every difference on the way from
/// `client_serial` to `current_serial`.
pub fn differenceChainHolds(origin: []const u8, client_serial: u32, current_serial: u32) bool {
    var next = client_serial;
    var hops: usize = 0;
    while (next != current_serial) : (hops += 1) {
        if (hops > max_stored_deltas) return false;
        const delta = nextDelta(origin, next) orelse return false;
        next = delta.to_serial;
    }
    return true;
}

/// One record of a difference, as the journal's encoding carries it.
pub const DeltaRecord = struct {
    /// True for a record the transition removed, false for one it added.
    deleted: bool,
    owner: []const u8,
    ttl: u32,
    /// The class the record carries, so the difference keeps it.
    class_code: u16,
    rrtype_code: u16,
    rdata: []const u8,
};

/// Appends one record to a difference, in the journal's encoding: the flag
/// ('D' for a deleted record, 'A' for an added one), the owner, the TTL, the
/// type code, and the rdata, which is the rest of the line. A record of a
/// class other than the default IN class carries the class with it, as a
/// "C<class>" marker in the class place of a zone file line.
pub fn encodeRecord(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    deleted: bool,
    owner: []const u8,
    ttl: u32,
    rrtype_code: u16,
    rdata: []const u8,
) !void {
    var head: [max_origin_len + 64]u8 = undefined;
    const text = std.fmt.bufPrint(
        &head,
        "{c} {s} {d} {d} ",
        .{ @as(u8, if (deleted) 'D' else 'A'), owner, ttl, rrtype_code },
    ) catch return error.OutOfMemory;
    try out.appendSlice(allocator, text);
    try out.appendSlice(allocator, rdata);
    try out.append(allocator, '\n');
}

/// The records a difference carries, in the order the difference lists them:
/// the deleted records first, then the added ones. The slices point into
/// `text`, which the caller owns.
pub fn decodeRecords(allocator: std.mem.Allocator, text: []const u8) ![]DeltaRecord {
    var records: std.ArrayList(DeltaRecord) = .empty;
    errdefer records.deinit(allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const record = parseDeltaRecord(line) orelse continue;
        try records.append(allocator, record);
    }
    return records.toOwnedSlice(allocator);
}

fn parseDeltaRecord(line: []const u8) ?DeltaRecord {
    if (line.len < 2) return null;
    const flag = line[0];
    if (flag != 'D' and flag != 'A') return null;
    var tokens = std.mem.tokenizeAny(u8, line[1..], " ");
    const owner = tokens.next() orelse return null;
    const ttl_text = tokens.next() orelse return null;
    const ttl = std.fmt.parseInt(u32, ttl_text, 10) catch return null;
    // The class travels with the record: it is written as a "C<class>"
    // marker, and a record without one is of the default IN class.
    var class_code: u16 = dns_types.Class.IN.code();
    var type_text = tokens.next() orelse return null;
    if (type_text.len > 1 and type_text[0] == 'C') {
        class_code = std.fmt.parseInt(u16, type_text[1..], 10) catch return null;
        type_text = tokens.next() orelse return null;
    }
    const rrtype_code = std.fmt.parseInt(u16, type_text, 10) catch return null;
    return .{
        .deleted = flag == 'D',
        .owner = owner,
        .ttl = ttl,
        .class_code = class_code,
        .rrtype_code = rrtype_code,
        .rdata = tokens.rest(),
    };
}

/// A record of a difference that cannot be turned into a DNS record.
pub const RecordError = error{BadRecord};

/// Turns one record of a difference into a DNS record. The record's owner
/// and rdata are the zone's own text, so the record is refused when either
/// of them does not parse.
pub fn toResourceRecord(record: DeltaRecord) RecordError!dns_record.ResourceRecord {
    const rrtype = dns_types.RecordType.fromCode(record.rrtype_code);
    return .{
        .owner = dns_name.Name.fromText(record.owner) catch return error.BadRecord,
        .rrtype = rrtype,
        .class = dns_types.Class.fromCode(record.class_code),
        .ttl = record.ttl,
        .rdata = zone_parser.parseRData(rrtype, record.rdata) catch return error.BadRecord,
    };
}

/// True when every record of the difference can be turned into a DNS
/// record. A difference that cannot is not kept: the client at that serial
/// gets the full transfer (RFC 1995 section 4) instead of an incremental
/// answer built from records that are not records.
fn differenceIsUsable(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const record = parseDeltaRecord(line) orelse return false;
        _ = toResourceRecord(record) catch return false;
    }
    return true;
}

/// True when the difference is the transition it claims to be: RFC 1995
/// section 4 puts the older SOA first among the deleted records and the
/// newer SOA first among the added ones. A difference whose records all
/// parse but do not open that way is not the transition, so it is dropped
/// and the client at that serial gets the full transfer.
fn differenceMatchesTransition(text: []const u8, from_serial: u32, to_serial: u32) bool {
    var deleted_seen = false;
    var added_seen = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const record = parseDeltaRecord(line) orelse return false;
        if (record.deleted) {
            if (deleted_seen) continue;
            deleted_seen = true;
            if (!soaHasSerial(record, from_serial)) return false;
            continue;
        }
        if (added_seen) continue;
        added_seen = true;
        if (!soaHasSerial(record, to_serial)) return false;
    }
    return deleted_seen and added_seen;
}

/// True when the record is an SOA whose serial is `serial`.
fn soaHasSerial(record: DeltaRecord, serial: u32) bool {
    if (record.rrtype_code != dns_types.RecordType.SOA.code()) return false;
    const parsed = zone_parser.parseRData(.SOA, record.rdata) catch return false;
    if (parsed != .SOA) return false;
    return parsed.SOA.serial == serial;
}

/// The durable RFC 1995 delta journal: the file that keeps a zone's serial
/// transitions across a restart, so an IXFR client at an old serial is still
/// answered incrementally after the server comes back. One transition per
/// line, holding the zone apex, the two serials, and the difference the
/// transition carries. Nothing else is written to the file: no zone data and
/// no key material.
pub const Journal = struct {
    io: std.Io,
    file: ?std.Io.File = null,
    /// The offset the next transition is written at: the end of the file, so
    /// an existing journal keeps its records.
    offset: u64 = 0,
    /// The transitions the journal could not record because the file was at
    /// its bound. A dropped transition is counted, so it never looks like a
    /// recorded one.
    dropped: u64 = 0,

    /// Opens the journal for appending, creating the file when it is not
    /// there yet.
    pub fn open(io: std.Io, dir: std.Io.Dir, path: []const u8) !Journal {
        if (path.len == 0 or path.len > max_path_len) return error.BadPath;
        var journal = Journal{ .io = io };
        journal.file = try dir.createFile(io, path, .{ .read = true, .truncate = false });
        errdefer journal.file.?.close(io);
        const stat = try journal.file.?.stat(io);
        journal.offset = stat.size;
        return journal;
    }

    /// Closes the journal. Closing twice is harmless.
    pub fn close(self: *Journal) void {
        if (self.file) |file| {
            file.close(self.io);
            self.file = null;
        }
    }

    /// Appends one transition and the difference it carries. The record is
    /// one line written at the end of the file, so a write that is cut short
    /// leaves a truncated tail the reader skips. A failed write leaves the
    /// journal as it was. A file at its bound takes no more transitions: the
    /// transition is dropped and counted, and the server keeps working
    /// without it. A difference too big for the bound is left out of the
    /// line: the transition keeps its serials, and the client at the old
    /// serial gets the full transfer.
    pub fn append(self: *Journal, origin: []const u8, from_serial: u32, to_serial: u32, difference: []const u8) void {
        const file = self.file orelse return;
        if (origin.len == 0 or origin.len > max_origin_len) return;
        const payload = if (difference.len <= max_delta_bytes) difference else "";
        var line: [max_origin_len + 64 + 2 * max_delta_bytes]u8 = undefined;
        const head = std.fmt.bufPrint(&line, "{s} {d} {d}", .{ origin, from_serial, to_serial }) catch return;
        var length = head.len;
        if (payload.len != 0) {
            line[length] = ' ';
            length += 1;
            for (payload) |byte| {
                line[length] = hexDigits[byte >> 4];
                line[length + 1] = hexDigits[byte & 0x0f];
                length += 2;
            }
        }
        line[length] = '\n';
        length += 1;
        const text = line[0..length];
        // The file stops growing at its bound, so a long-lived server cannot
        // fill the disk. The transition is lost, and the zone falls back to
        // the full transfer once the in-memory log no longer holds it.
        if (self.offset + @as(u64, text.len) > max_journal_bytes) {
            self.dropped += 1;
            reportDropped(self.io, origin, from_serial, to_serial);
            return;
        }
        file.writePositionalAll(self.io, text, self.offset) catch return;
        self.offset += text.len;
    }

    /// Reads the transitions the journal holds. A line that does not parse is
    /// skipped, so a truncated or corrupt record costs the server that
    /// record and nothing else. A file that does not end in a newline was cut
    /// short, so its last line is a torn record and is not restored either.
    /// The caller owns the returned slice.
    pub fn read(self: *const Journal, allocator: std.mem.Allocator) ![]Transition {
        const file = self.file orelse return &.{};
        const stat = try file.stat(self.io);
        const size = stat.size;
        if (size == 0) return &.{};
        const want: usize = @intCast(@min(size, max_journal_bytes));
        const start = size - want;
        const buffer = try allocator.alloc(u8, want);
        defer allocator.free(buffer);
        const len = try file.readPositionalAll(self.io, buffer, start);
        var text = buffer[0..len];
        // A file bigger than the read bound starts in the middle of a
        // record, so the partial first line is dropped.
        if (start > 0) {
            const newline = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
            text = text[newline + 1 ..];
        }
        // A crash in the middle of an append leaves a record without its
        // closing newline; such a tail was never written whole, so it is not
        // restored even when it reads as a complete transition.
        if (text.len > 0 and text[text.len - 1] != '\n') {
            const newline = std.mem.lastIndexOfScalar(u8, text, '\n') orelse 0;
            text = text[0..newline];
        }
        var transitions: std.ArrayList(Transition) = .empty;
        errdefer transitions.deinit(allocator);
        var payload_buffer: [max_delta_bytes]u8 = undefined;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const parsed = parseLine(line, &payload_buffer) orelse continue;
            // The difference the line carries goes to the store, so a
            // transition restored from the file can be answered
            // incrementally.
            storeDelta(
                parsed.transition.originText(),
                parsed.transition.from_serial,
                parsed.transition.to_serial,
                parsed.difference,
            );
            try transitions.append(allocator, parsed.transition);
        }
        return transitions.toOwnedSlice(allocator);
    }
};

/// One operator-facing line about a transition the journal could not
/// record. A test build has no operator and the test runner fails on any
/// stderr write, so the line is printed by the server build only.
fn reportDropped(io: std.Io, origin: []const u8, from_serial: u32, to_serial: u32) void {
    if (builtin.is_test) return;
    var line_buffer: [512]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "error: the IXFR journal file is at its {d}-byte bound; the transition for {s} from serial {d} to {d} was not recorded",
        .{ max_journal_bytes, origin, from_serial, to_serial },
    ) catch return;
    var stderr_buffer: [256]u8 = undefined;
    // The streaming writer appends at the shared file position; the
    // positional one would rewrite every line from the start of the file.
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);
    stderr_writer.interface.print("{s}\n", .{line}) catch {};
    stderr_writer.interface.flush() catch {};
}

/// One journal line: the transition it holds and the difference it carries.
const ParsedLine = struct {
    transition: Transition,
    /// The difference, decoded into the caller's buffer. Empty when the line
    /// carries none, as a line written before the journal carried
    /// differences does.
    difference: []const u8,
};

/// Parses one journal line: the zone apex, the two serials of the
/// transition, and the difference it carries. A line that does not parse is
/// not a transition.
fn parseLine(line: []const u8, buffer: []u8) ?ParsedLine {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    const origin = tokens.next() orelse return null;
    const from_text = tokens.next() orelse return null;
    const to_text = tokens.next() orelse return null;
    const payload = tokens.next();
    if (tokens.next() != null) return null;
    if (origin.len == 0 or origin.len > max_origin_len) return null;
    const from_serial = std.fmt.parseInt(u32, from_text, 10) catch return null;
    const to_serial = std.fmt.parseInt(u32, to_text, 10) catch return null;
    var transition = Transition{ .from_serial = from_serial, .to_serial = to_serial };
    @memcpy(transition.origin[0..origin.len], origin);
    transition.origin_len = origin.len;
    var difference: []const u8 = &.{};
    if (payload) |hex| {
        difference = decodeHex(hex, buffer) orelse return null;
    }
    return .{ .transition = transition, .difference = difference };
}

const hexDigits = "0123456789abcdef";

fn hexValue(digit: u8) ?u8 {
    return switch (digit) {
        '0'...'9' => digit - '0',
        'a'...'f' => digit - 'a' + 10,
        'A'...'F' => digit - 'A' + 10,
        else => null,
    };
}

/// Decodes the hex payload of a journal line into `buffer`. Null when the
/// payload is not hex or does not fit.
fn decodeHex(hex: []const u8, buffer: []u8) ?[]const u8 {
    if (hex.len % 2 != 0) return null;
    if (hex.len / 2 > buffer.len) return null;
    var index: usize = 0;
    while (index < hex.len) : (index += 2) {
        const high = hexValue(hex[index]) orelse return null;
        const low = hexValue(hex[index + 1]) orelse return null;
        buffer[index / 2] = (high << 4) | low;
    }
    return buffer[0 .. hex.len / 2];
}

/// The journal the running server appends to. One process serves one
/// configuration with one journal, so the file lives here instead of in
/// every per-zone log.
var active: ?*Journal = null;

/// Points the running server at its journal file.
pub fn activate(journal: *Journal) void {
    active = journal;
}

/// Stops appending to the journal. The file itself is closed by its owner.
pub fn deactivate(journal: *Journal) void {
    if (active) |current| {
        if (current == journal) active = null;
    }
}

pub const DeltaLog = struct {
    from_serials: [max_deltas]u32 = undefined,
    to_serials: [max_deltas]u32 = undefined,
    len: usize = 0,
    /// The apex this log belongs to. The journal file holds the transitions
    /// of every zone, and the apex says which zone a record belongs to.
    origin: [max_origin_len]u8 = undefined,
    origin_len: usize = 0,
    /// The wire size of the records a full transfer of the zone carries, or
    /// zero when the server does not know it yet. A zero takes the size the
    /// zone index registered when it loaded the zone.
    full_transfer_bytes: usize = 0,

    /// Names the zone this log belongs to, so a transition can be written to
    /// the journal with the zone it belongs to.
    pub fn setOrigin(self: *DeltaLog, origin: []const u8) void {
        if (origin.len == 0 or origin.len > max_origin_len) return;
        @memcpy(self.origin[0..origin.len], origin);
        self.origin_len = origin.len;
    }

    pub fn originText(self: *const DeltaLog) []const u8 {
        return self.origin[0..self.origin_len];
    }

    /// Records the wire size of the records a full transfer of the zone
    /// carries, so the incremental answer is measured against the full
    /// transfer it replaces (RFC 1995 section 5).
    pub fn setFullTransferBytes(self: *DeltaLog, bytes: usize) void {
        self.full_transfer_bytes = bytes;
    }

    /// Records that the zone moved from `from_serial` to `to_serial`, with
    /// the difference the two zones make. Only RFC 1982 newer transitions
    /// are accepted. The transition is appended to the journal when one is
    /// active, so the log survives a restart; a journal that cannot be
    /// written does not fail the record, because the in-memory log still
    /// carries the transition. A journal at its bound drops the
    /// transition: the server keeps running, the drop is reported, and the
    /// transition is gone after a restart, so the zone falls back to the
    /// full transfer.
    pub fn record(self: *DeltaLog, from_serial: u32, to_serial: u32, difference: []const u8) DeltaError!void {
        try self.push(from_serial, to_serial);
        storeDelta(self.originText(), from_serial, to_serial, difference);
        if (active) |journal| journal.append(self.originText(), from_serial, to_serial, difference);
    }

    /// Puts a transition read from the journal file into the log without
    /// writing it back: the file is the record, and the log is its replay.
    /// A transition the file holds no difference for is not restored: the
    /// client at its serial gets the full transfer.
    pub fn restore(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
        if (differenceFor(self.originText(), from_serial, to_serial) == null) return DeltaError.NoDifference;
        try self.push(from_serial, to_serial);
    }

    fn push(self: *DeltaLog, from_serial: u32, to_serial: u32) DeltaError!void {
        switch (compareSerial(to_serial, from_serial)) {
            .newer => {},
            .equal => return DeltaError.SerialEqual,
            .older => return DeltaError.SerialOlder,
            .undefined => return DeltaError.SerialUndefined,
        }
        if (self.len == max_deltas) {
            std.mem.copyForwards(u32, self.from_serials[0 .. max_deltas - 1], self.from_serials[1..max_deltas]);
            std.mem.copyForwards(u32, self.to_serials[0 .. max_deltas - 1], self.to_serials[1..max_deltas]);
            self.len = max_deltas - 1;
        }
        self.from_serials[self.len] = from_serial;
        self.to_serials[self.len] = to_serial;
        self.len += 1;
    }

    /// Reports whether `serial` appears anywhere in the recorded chain,
    /// either as a superseded serial or as a reached serial.
    pub fn hasSerial(self: *const DeltaLog, serial: u32) bool {
        for (self.from_serials[0..self.len], self.to_serials[0..self.len]) |from, to| {
            if (from == serial or to == serial) return true;
        }
        return false;
    }

    /// Reports whether the log connects `client_serial` to `current_serial`
    /// through recorded transitions, and whether every transition on the way
    /// carries the difference the incremental answer needs. A missing link
    /// means the delta is no longer known and the server must answer the
    /// IXFR with a full AXFR.
    pub fn canServeIncremental(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        if (client_serial == current_serial) return true;
        if (!self.chainKnown(client_serial, current_serial)) return false;
        // RFC 1995 section 5: the incremental answer must not be longer
        // than the full transfer it replaces.
        return self.incrementalIsShorter(client_serial, current_serial);
    }

    /// Reports whether the recorded transitions connect `client_serial` to
    /// `current_serial` and every transition on the way still carries its
    /// difference.
    pub fn chainKnown(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        if (client_serial == current_serial) return true;
        if (!self.chainConnects(client_serial, current_serial)) return false;
        // Every transition on the way carries the difference the incremental
        // answer is built from.
        return differenceChainHolds(self.originText(), client_serial, current_serial);
    }

    /// Reports whether the held incremental chain for `client_serial` is
    /// shorter than the full transfer of the zone.
    pub fn servesIncremental(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        return self.chainKnown(client_serial, current_serial) and self.incrementalIsShorter(client_serial, current_serial);
    }

    /// Reports whether the held incremental chain for `client_serial` is
    /// at least as long as the full transfer, so serving AXFR lets the
    /// server drop the oldest difference (RFC 1995 section 5).
    pub fn chainLongerThanFull(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        if (!self.chainKnown(client_serial, current_serial)) return false;
        return !self.incrementalIsShorter(client_serial, current_serial);
    }

    /// Reports whether the incremental answer for `client_serial` is
    /// shorter than the full transfer of the zone. Both answers carry the
    /// two current SOA records, so only the other records are compared.
    /// Read-only: when the answer would not be shorter the caller serves
    /// the full transfer and drains the oldest difference under the
    /// runtime exclusive lock (see `evictOldestDifference`).
    fn incrementalIsShorter(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        const full = if (self.full_transfer_bytes != 0)
            self.full_transfer_bytes
        else
            zoneSize(self.originText());
        if (full == 0) return true;
        const chain = differenceChainBytes(self.originText(), client_serial, current_serial);
        return chain < full;
    }

    /// Reports whether the recorded transitions connect `client_serial` to
    /// `current_serial`.
    fn chainConnects(self: *const DeltaLog, client_serial: u32, current_serial: u32) bool {
        var next = client_serial;
        var hops: usize = 0;
        while (hops <= self.len) : (hops += 1) {
            var advanced = false;
            for (self.from_serials[0..self.len], self.to_serials[0..self.len]) |from, to| {
                if (from != next) continue;
                if (to == current_serial) return true;
                next = to;
                advanced = true;
                break;
            }
            if (!advanced) return false;
        }
        return false;
    }
};

/// The difference one transition carries: the journal only keeps the text, the
/// transfer reads it. The difference of the transition from `from_serial` to
/// `to_serial` opens with the older SOA and the added records open with the
/// newer one (RFC 1995 section 4).
fn testDifference(allocator: std.mem.Allocator, from_serial: u32, to_serial: u32) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buffer: [128]u8 = undefined;
    const older = try std.fmt.bufPrint(&buffer, "ns.chain.example. hostmaster.chain.example. {d} 3600 900 1209600 3600", .{from_serial});
    try encodeRecord(&out, allocator, true, "chain.example.", 3600, dns_types.RecordType.SOA.code(), older);
    try encodeRecord(&out, allocator, true, "a.chain.example.", 3600, dns_types.RecordType.A.code(), "192.0.2.1");
    const newer = try std.fmt.bufPrint(&buffer, "ns.chain.example. hostmaster.chain.example. {d} 3600 900 1209600 3600", .{to_serial});
    try encodeRecord(&out, allocator, false, "chain.example.", 3600, dns_types.RecordType.SOA.code(), newer);
    try encodeRecord(&out, allocator, false, "a.chain.example.", 3600, dns_types.RecordType.A.code(), "192.0.2.2");
    return out.toOwnedSlice(allocator);
}

test "delta log serves incremental answers only across recorded transitions" {
    var log = DeltaLog{};
    log.setOrigin("chain.example.");
    const first = try testDifference(std.testing.allocator, 10, 11);
    defer std.testing.allocator.free(first);
    const second = try testDifference(std.testing.allocator, 11, 12);
    defer std.testing.allocator.free(second);
    try log.record(10, 11, first);
    try log.record(11, 12, second);
    try std.testing.expect(log.hasSerial(10));
    try std.testing.expect(log.hasSerial(12));
    try std.testing.expect(!log.hasSerial(9));
    try std.testing.expect(log.canServeIncremental(12, 12));
    try std.testing.expect(log.canServeIncremental(10, 12));
    try std.testing.expect(log.canServeIncremental(11, 12));
    try std.testing.expect(!log.canServeIncremental(9, 12));
    try std.testing.expect(!log.canServeIncremental(10, 13));
}

test "a difference that is not shorter than the full transfer is kept on read" {
    var log = DeltaLog{};
    log.setOrigin("purge.example.");
    const difference = try testDifference(std.testing.allocator, 10, 11);
    defer std.testing.allocator.free(difference);
    try log.record(10, 11, difference);
    try std.testing.expect(differenceFor("purge.example.", 10, 11) != null);

    // The server knows the size of the full transfer of the zone, and the
    // difference is longer: the client at the old serial gets the full
    // transfer, but the read-only decision keeps the difference in place.
    // The exclusive drain drops it later.
    log.setFullTransferBytes(16);
    try std.testing.expect(!log.canServeIncremental(10, 11));
    try std.testing.expect(differenceFor("purge.example.", 10, 11) != null);
    try std.testing.expect(!log.canServeIncremental(10, 11));
    try std.testing.expect(differenceFor("purge.example.", 10, 11) != null);
    try std.testing.expect(log.len <= max_deltas);
    try std.testing.expect(stored_len <= max_stored_deltas);
}

test "the exclusive drain drops only the oldest difference of one origin" {
    var log = DeltaLog{};
    log.setOrigin("evict.example.");
    const difference = try testDifference(std.testing.allocator, 10, 11);
    defer std.testing.allocator.free(difference);
    try log.record(10, 11, difference);
    var other = DeltaLog{};
    other.setOrigin("other.example.");
    const other_difference = try testDifference(std.testing.allocator, 20, 21);
    defer std.testing.allocator.free(other_difference);
    try other.record(20, 21, other_difference);
    log.setFullTransferBytes(16);

    try std.testing.expect(!log.canServeIncremental(10, 11));
    evictOldestDifference("evict.example.", 10);
    try std.testing.expect(differenceFor("evict.example.", 10, 11) == null);
    try std.testing.expect(!log.canServeIncremental(10, 11));
    try std.testing.expect(differenceFor("other.example.", 20, 21) != null);
    try std.testing.expect(log.len <= max_deltas);
    try std.testing.expect(stored_len <= max_stored_deltas);
}

test "delta log rejects transitions that are not RFC 1982 newer" {
    var log = DeltaLog{};
    const difference = try testDifference(std.testing.allocator, 10, 11);
    defer std.testing.allocator.free(difference);
    try std.testing.expectError(DeltaError.SerialEqual, log.record(10, 10, difference));
    try std.testing.expectError(DeltaError.SerialOlder, log.record(11, 10, difference));
    try std.testing.expectError(DeltaError.SerialUndefined, log.record(0, 0x8000_0000, difference));
    try std.testing.expectEqual(@as(usize, 0), log.len);
}

test "delta log evicts the oldest transition once bounded" {
    var log = DeltaLog{};
    log.setOrigin("bounded.example.");
    var serial: u32 = 1;
    while (serial <= max_deltas + 1) : (serial += 1) {
        const difference = try testDifference(std.testing.allocator, serial, serial + 1);
        defer std.testing.allocator.free(difference);
        try log.record(serial, serial + 1, difference);
    }
    try std.testing.expectEqual(max_deltas, log.len);
    try std.testing.expect(!log.hasSerial(1));
    try std.testing.expect(log.hasSerial(2));
    try std.testing.expect(!log.canServeIncremental(1, max_deltas + 2));
    try std.testing.expect(log.canServeIncremental(2, max_deltas + 2));
}

test "the journal file carries a transition across a restart" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    activate(&journal);
    defer deactivate(&journal);

    var log = DeltaLog{};
    log.setOrigin("restart-journal.example.");
    const difference = try testDifference(std.testing.allocator, 10, 11);
    defer std.testing.allocator.free(difference);
    try log.record(10, 11, difference);
    journal.close();

    // A server that comes back reads the file and finds the transition.
    var reopened = try Journal.open(io, tmp.dir, "journal.log");
    defer reopened.close();
    const transitions = try reopened.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("restart-journal.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);

    var restored = DeltaLog{};
    restored.setOrigin("restart-journal.example.");
    try restored.restore(transitions[0].from_serial, transitions[0].to_serial);
    try std.testing.expect(restored.canServeIncremental(10, 11));
    try std.testing.expect(!restored.canServeIncremental(9, 11));
    // The difference the file carried is what the answer is built from.
    try std.testing.expect(differenceFor("restart-journal.example.", 10, 11) != null);
    // The client at the old serial is answered incrementally again.
    const transfer = @import("transfer.zig");
    try std.testing.expectEqual(transfer.IxfrDecision.incremental, transfer.decideIxfr(11, 10, &restored));
}

test "a journal file in the old format falls back to the full transfer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A file written before the journal carried differences: the serials of
    // the transition are there, the difference is not.
    try tmp.dir.writeFile(io, .{
        .sub_path = "journal.log",
        .data = "old.example. 10 11\n",
    });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The file is read, so the server starts.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);

    // The transition cannot be turned into a difference, so it is not
    // restored and the client at its serial gets the full transfer.
    var restored = DeltaLog{};
    restored.setOrigin("old.example.");
    try std.testing.expectError(DeltaError.NoDifference, restored.restore(transitions[0].from_serial, transitions[0].to_serial));
    const transfer = @import("transfer.zig");
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(11, 10, &restored));
}

test "the journal skips a corrupt or truncated record" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "journal.log",
        .data = "one.example. 10 11\ngarbage\ntwo.example. 12\n",
    });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The good record is kept, the truncated one and the garbage are not.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("one.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);
}

test "the journal skips a torn record that has no closing newline" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A crash in the middle of an append left the last record without its
    // newline, and it reads as a complete transition.
    try tmp.dir.writeFile(io, .{
        .sub_path = "journal.log",
        .data = "torn.example. 10 11\ntwo.example. 20 21",
    });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The whole record is kept, the torn one is not.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqualStrings("torn.example.", transitions[0].originText());
    try std.testing.expectEqual(@as(u32, 10), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 11), transitions[0].to_serial);

    // The record carries no difference, so it cannot be turned into one:
    // the transition is not restored, and a client at its serial is answered
    // with the full transfer.
    var restored = DeltaLog{};
    restored.setOrigin("torn.example.");
    try std.testing.expectError(DeltaError.NoDifference, restored.restore(transitions[0].from_serial, transitions[0].to_serial));
    try std.testing.expect(!restored.canServeIncremental(20, 21));
}

test "a journal difference that cannot be turned into records is dropped" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // The difference holds a record whose rdata is not an address, so it
    // cannot be turned into records.
    const corrupt = "D a.chain.example. 3600 1 999.999.999.999\n";
    var hex: [2 * max_delta_bytes]u8 = undefined;
    for (corrupt, 0..) |byte, index| {
        hex[index * 2] = hexDigits[byte >> 4];
        hex[index * 2 + 1] = hexDigits[byte & 0x0f];
    }
    var line_buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "corrupt.example. 20 21 {s}\n", .{hex[0 .. corrupt.len * 2]});
    try tmp.dir.writeFile(io, .{ .sub_path = "journal.log", .data = line });

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);

    // The line is read, so the transition is there, but its difference is
    // dropped: the client at that serial gets the full transfer.
    try std.testing.expectEqual(@as(usize, 1), transitions.len);
    try std.testing.expectEqual(@as(u32, 20), transitions[0].from_serial);
    try std.testing.expectEqual(@as(u32, 21), transitions[0].to_serial);
    try std.testing.expect(differenceFor("corrupt.example.", 20, 21) == null);

    var restored = DeltaLog{};
    restored.setOrigin("corrupt.example.");
    try std.testing.expectError(DeltaError.NoDifference, restored.restore(transitions[0].from_serial, transitions[0].to_serial));
    const transfer = @import("transfer.zig");
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(21, 20, &restored));

    // The same difference recorded in memory is dropped the same way.
    var log = DeltaLog{};
    log.setOrigin("corrupt-memory.example.");
    try log.record(20, 21, corrupt);
    try std.testing.expect(!log.canServeIncremental(20, 21));
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(21, 20, &log));
}

test "a difference that does not open with the two SOA records is dropped" {
    // RFC 1995 section 4: the first deleted record is the older SOA and the
    // first added record the newer one. A difference whose records all parse
    // but do not open that way is not the transition it claims to be.
    var log = DeltaLog{};
    log.setOrigin("mismatch.example.");
    const damaged = "D a.chain.example. 3600 1 192.0.2.1\nA a.chain.example. 3600 1 192.0.2.2\n";
    try log.record(10, 11, damaged);
    // The transition is recorded, but its difference is not: the client at
    // that serial gets the full transfer.
    try std.testing.expect(log.hasSerial(10));
    try std.testing.expect(differenceFor("mismatch.example.", 10, 11) == null);
    try std.testing.expect(!log.canServeIncremental(10, 11));
    const transfer = @import("transfer.zig");
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(11, 10, &log));

    // The SOA records of the difference must carry the serials of the
    // transition: a difference of another transition is dropped the same way.
    var other = DeltaLog{};
    other.setOrigin("wrong-serial.example.");
    const wrong = try testDifference(std.testing.allocator, 9, 10);
    defer std.testing.allocator.free(wrong);
    try other.record(10, 11, wrong);
    try std.testing.expect(differenceFor("wrong-serial.example.", 10, 11) == null);
    try std.testing.expect(!other.canServeIncremental(10, 11));
}

test "the difference carries the class of the record" {
    // A record of a class other than the default IN class carries the class
    // with it, and the record keeps that class when it is turned back into
    // a DNS record.
    const records = try decodeRecords(std.testing.allocator, "A a.chain.example. 3600 C3 1 192.0.2.1\n");
    defer std.testing.allocator.free(records);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual(@as(u16, 3), records[0].class_code);
    const record = try toResourceRecord(records[0]);
    try std.testing.expectEqual(@as(u16, 3), record.class.code());

    // A record of the default class keeps the short form and the class.
    const plain = try decodeRecords(std.testing.allocator, "A a.chain.example. 3600 1 192.0.2.1\n");
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqual(dns_types.Class.IN.code(), plain[0].class_code);
    const plain_record = try toResourceRecord(plain[0]);
    try std.testing.expect(plain_record.class.eql(dns_types.Class.IN));
}

test "the journal stops growing at its bound and drops the transitions past it" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    defer journal.close();

    // A long apex makes the records big, so the file reaches its bound in
    // a few thousand transitions.
    var origin_buffer: [max_origin_len]u8 = undefined;
    @memset(&origin_buffer, 'a');
    const origin = origin_buffer[0..];
    var serial: u32 = 1;
    var dropped: u32 = 0;
    while (journal.dropped == 0 and serial < 100_000) : (serial += 1) {
        const difference = try testDifference(std.testing.allocator, serial, serial + 1);
        defer std.testing.allocator.free(difference);
        journal.append(origin, serial, serial + 1, difference);
        if (journal.dropped > 0) dropped = serial;
    }

    // The file stopped at its bound, and the drop was counted, not silent.
    try std.testing.expect(dropped > 0);
    try std.testing.expectEqual(@as(u64, 1), journal.dropped);
    const stat = try tmp.dir.statFile(io, "journal.log", .{});
    try std.testing.expect(stat.size <= max_journal_bytes);

    // The transition that did not fit is not in the file.
    const transitions = try journal.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);
    try std.testing.expect(transitions.len > 0);
    try std.testing.expectEqual(dropped, transitions[transitions.len - 1].to_serial);
}

test "a journal at its bound leaves the dropped transition to the full transfer fallback" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.open(io, tmp.dir, "journal.log");
    var origin_buffer: [max_origin_len]u8 = undefined;
    @memset(&origin_buffer, 'a');
    const origin = origin_buffer[0..];
    var serial: u32 = 1;
    var dropped: u32 = 0;
    while (journal.dropped == 0 and serial < 100_000) : (serial += 1) {
        const difference = try testDifference(std.testing.allocator, serial, serial + 1);
        defer std.testing.allocator.free(difference);
        journal.append(origin, serial, serial + 1, difference);
        if (journal.dropped > 0) dropped = serial;
    }
    journal.close();

    // A server that comes back reads the file and finds every transition
    // but the dropped one.
    var reopened = try Journal.open(io, tmp.dir, "journal.log");
    defer reopened.close();
    const transitions = try reopened.read(std.testing.allocator);
    defer std.testing.allocator.free(transitions);
    var restored = DeltaLog{};
    for (transitions) |transition| restored.restore(transition.from_serial, transition.to_serial) catch continue;

    // The client at the dropped transition's serial is answered with the
    // full transfer, exactly as a client at a serial the journal never held
    // is.
    const transfer = @import("transfer.zig");
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(dropped + 1, dropped, &restored));
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(dropped + 1, 0, &restored));
}
