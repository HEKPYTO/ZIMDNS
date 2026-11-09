/// Contract: fetches one zone over DNS/TCP, by AXFR (RFC 5936) or by an
/// incremental IXFR delta (RFC 1995) applied to the served copy.
/// Ownership: the caller owns the returned text and frees it with `allocator`.
/// Errors: a connection, framing, or transfer-shape failure is typed; the
/// transfer is bounded in frames, in total bytes (64 MiB), by `timeout` as
/// one absolute wall-clock budget for the whole exchange, and by a 10 s
/// per-frame idle deadline so a stalled primary fails fast.
/// A transfer whose first record is not the zone's SOA is refused rather
/// than guessed at. With `tsig`, the request is TSIG-signed and every
/// response frame's chained TSIG is verified before its records are used.
const std = @import("std");
const limits = @import("../dns/limits.zig");
const dns_message = @import("../dns/message.zig");
const dns_name = @import("../dns/name.zig");
const dns_record = @import("../dns/record.zig");
const dns_tsig = @import("../dns/tsig.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const zone_mod = @import("index.zig");
const zone_update = @import("update.zig");

/// RFC 5936 section 4.2: a transfer is a sequence of messages, each framed by
/// the two-octet length of the Do53/TCP framing. The cap keeps a hostile
/// primary from holding the startup open forever.
pub const max_frames = 4096;
/// The Do53/TCP frame limit is the 16-bit length prefix.
const max_frame_bytes = limits.max_message_bytes;
/// RFC 5936 lets one transfer run to `max_frames` full frames; the total cap
/// keeps a compliant-but-huge primary from exhausting allocator memory.
pub const max_total_bytes: usize = 64 * 1024 * 1024;

pub const Error = error{
    ConnectFailed,
    IoFailed,
    BadTransfer,
    TooManyFrames,
    TooLarge,
    BadMac,
    BadKey,
    OutOfMemory,
};

/// TSIG material for a signed secondary fetch: the key name the request is
/// signed with, its algorithm, the secret bytes, and the fudge/origin time.
pub const TsigKey = struct {
    owner: dns_name.Name,
    algorithm: dns_tsig.Algorithm,
    secret: []const u8,
    now: u64,
};

/// One AXFR over DNS/TCP: connect, ask for `zone`, read frames until the
/// closing SOA, and return the records as zone text the zone parser accepts.
/// Every record is written in the RFC 3597 generic form, so a type this build
/// does not render loses nothing.
pub fn fetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    timeout: std.Io.Timeout,
) Error![]u8 {
    return fetchSigned(allocator, io, primary, zone, timeout, null);
}

/// Signed AXFR: `tsig` signs the request (RFC 8945 section 4) and every
/// response frame's chained TSIG (section 5.3.1) is verified before its
/// records are used. An unsigned or badly MACed frame fails the transfer.
pub fn fetchSigned(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    timeout: std.Io.Timeout,
    tsig: ?TsigKey,
) Error![]u8 {
    return fetchSignedBudget(allocator, io, primary, zone, timeout, tsig, max_total_bytes);
}

/// AXFR core with an injectable total-byte budget; production passes
/// `max_total_bytes`. Tests pass a small budget to prove the TooLarge path
/// without moving 64 MiB over loopback.
pub fn fetchSignedBudget(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    timeout: std.Io.Timeout,
    tsig: ?TsigKey,
    budget_bytes: usize,
) Error![]u8 {
    const name = @import("../dns/name.zig").Name.fromText(zone) catch return Error.BadTransfer;
    // One total wall-clock budget for the whole exchange plus a 10 s
    // per-frame idle deadline: a blackholed primary fails at the budget, a
    // primary that stalls mid-transfer at the idle deadline.
    const total_deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
    var stream = connectBounded(io, primary, total_deadline) catch return Error.ConnectFailed;
    defer stream.close(io);

    var query_buffer: [512]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    io.random(&id_bytes);
    var query = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = std.mem.readInt(u16, &id_bytes, .big),
            .opcode = .query,
            .question_count = 1,
        },
        .question = .{ .name = name, .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
    };
    if (tsig) |key| signQuery(&query, key) catch return Error.BadTransfer;
    var writer = dns_writer.Writer.init(&query_buffer);
    query.encode(&writer) catch return Error.BadTransfer;
    var request_mac: ?dns_tsig.Mac = null;
    if (tsig) |key| request_mac = patchQueryMac(query_buffer[0..writer.len()], key) catch return Error.BadTransfer;
    const request = writer.written();

    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(request.len), .big);
    tcp_deadline.writeExact(stream.socket.handle, io, &prefix, total_deadline) catch return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, request, total_deadline) catch return Error.IoFailed;

    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    output.writer.print("$ORIGIN {s}\n$TTL 1\n", .{zone}) catch return Error.OutOfMemory;

    var soa_count: usize = 0;
    var total_bytes: usize = 0;
    var first_serial: ?u32 = null;
    var seen_record = false;
    var frame_index: usize = 0;
    var frame_buffer: [max_frame_bytes]u8 = undefined;
    while (frame_index < max_frames) : (frame_index += 1) {
        // The idle deadline bounds one frame; the total deadline bounds the
        // exchange. Whichever fires first ends the read.
        const frame_deadline = idleDeadline(io, total_deadline);
        var length_bytes: [2]u8 = undefined;
        tcp_deadline.readExact(stream.socket.handle, io, &length_bytes, frame_deadline) catch return Error.IoFailed;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length == 0) return Error.BadTransfer;
        total_bytes += length;
        if (total_bytes > budget_bytes) return Error.TooLarge;
        tcp_deadline.readExact(stream.socket.handle, io, frame_buffer[0..length], frame_deadline) catch return Error.IoFailed;

        if (tsig) |key| {
            const first_frame = frame_index == 0;
            request_mac = verifyFrame(frame_buffer[0..length], key, request_mac, first_frame) catch return Error.BadMac;
        }
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const message = dns_message.Message.parse(arena_state.allocator(), frame_buffer[0..length]) catch return Error.BadTransfer;
        if (message.header.id != query.header.id) return Error.BadTransfer;
        if (message.header.truncated) return Error.BadTransfer;
        if (message.header.rcode != .no_error) return Error.BadTransfer;
        for (message.answers.slice()) |record| {
            // RFC 5936 section 2.2: the first record of the transfer is the
            // zone's SOA; a primary that prepends anything else is refused.
            if (!seen_record) {
                if (!record.rrtype.eql(.SOA)) return Error.BadTransfer;
                seen_record = true;
            }
            if (record.rrtype.eql(.SOA)) {
                soa_count += 1;
                if (soa_count > 2) return Error.BadTransfer;
                const serial = switch (record.rdata) {
                    .SOA => |soa| soa.serial,
                    else => return Error.BadTransfer,
                };
                if (soa_count == 1) {
                    var owner_buffer: [256]u8 = undefined;
                    const owner = record.owner.toText(&owner_buffer) catch return Error.BadTransfer;
                    if (!std.ascii.eqlIgnoreCase(owner, zone)) return Error.BadTransfer;
                    first_serial = serial;
                }
                if (soa_count == 2) {
                    var owner_buffer: [256]u8 = undefined;
                    const owner = record.owner.toText(&owner_buffer) catch return Error.BadTransfer;
                    if (!std.ascii.eqlIgnoreCase(owner, zone)) return Error.BadTransfer;
                    if (serial != first_serial.?) return Error.BadTransfer;
                    // The closing SOA frames the transfer on the wire
                    // (RFC 5936 section 2.2); the zone text carries the one
                    // apex SOA the first record brought.
                    var list = output.toArrayList();
                    return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
                }
            }
            try writeRecord(&output.writer, record);
        }
    }
    return Error.TooManyFrames;
}

/// One record in the RFC 3597 generic form: the owner and TTL as received,
/// the type code, and the RDATA octets in hex. The zone parser reads this
/// form for every type, so the transferred zone is served with the same
/// typed RDATA the primary sent.
/// One IXFR over DNS/TCP (RFC 1995 section 3): ask with the served copy's
/// serial, then either keep the copy, fall back to a full AXFR when the
/// primary answers with the full zone, or apply the incremental delta to the
/// records the copy already holds and return the rebuilt zone text.
pub fn fetchIxfr(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    current: *const zone_mod.Zone,
    timeout: std.Io.Timeout,
) Error![]u8 {
    return fetchIxfrSigned(allocator, io, primary, zone, current, timeout, null);
}

/// Signed IXFR: like `fetchSigned` but the query carries the served copy's
/// serial in the authority section (RFC 1995 section 3).
pub fn fetchIxfrSigned(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    current: *const zone_mod.Zone,
    timeout: std.Io.Timeout,
    tsig: ?TsigKey,
) Error![]u8 {
    return fetchIxfrSignedBudget(allocator, io, primary, zone, current, timeout, tsig, max_total_bytes);
}

/// IXFR core with an injectable total-byte budget; mirrors fetchSignedBudget.
pub fn fetchIxfrSignedBudget(
    allocator: std.mem.Allocator,
    io: std.Io,
    primary: *const std.Io.net.IpAddress,
    zone: []const u8,
    current: *const zone_mod.Zone,
    timeout: std.Io.Timeout,
    tsig: ?TsigKey,
    budget_bytes: usize,
) Error![]u8 {
    const name = @import("../dns/name.zig").Name.fromText(zone) catch return Error.BadTransfer;
    const current_serial = current.soaSerial() orelse return fetchSigned(allocator, io, primary, zone, timeout, tsig);
    const total_deadline = tcp_deadline.deadlineFromTimeout(io, timeout) orelse return Error.IoFailed;
    var stream = connectBounded(io, primary, total_deadline) catch return Error.ConnectFailed;
    defer stream.close(io);

    var query_buffer: [512]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    io.random(&id_bytes);
    var query = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = std.mem.readInt(u16, &id_bytes, .big),
            .opcode = .query,
            .question_count = 1,
            .authority_count = 1,
        },
        .question = .{ .name = name, .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .authorities = dns_message.RecordSection.init(allocator, 1) catch return Error.OutOfMemory,
    };
    defer query.deinit();
    query.authorities.append(.{
        .owner = name,
        .rrtype = dns_types.RecordType.SOA,
        .class = dns_types.Class.IN,
        .ttl = 0,
        .rdata = .{ .SOA = .{
            .mname = name,
            .rname = name,
            .serial = current_serial,
            .refresh = 0,
            .retry = 0,
            .expire = 0,
            .minimum = 0,
        } },
    }) catch return Error.OutOfMemory;
    if (tsig) |key| signQuery(&query, key) catch return Error.BadTransfer;
    var writer = dns_writer.Writer.init(&query_buffer);
    query.encode(&writer) catch return Error.BadTransfer;
    var request_mac: ?dns_tsig.Mac = null;
    if (tsig) |key| request_mac = patchQueryMac(query_buffer[0..writer.len()], key) catch return Error.BadTransfer;
    const request = writer.written();

    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(request.len), .big);
    tcp_deadline.writeExact(stream.socket.handle, io, &prefix, total_deadline) catch return Error.IoFailed;
    tcp_deadline.writeExact(stream.socket.handle, io, request, total_deadline) catch return Error.IoFailed;

    // The parsed answer records point into these bytes; the arena outlives
    // every frame so the delta can be applied after the last frame arrives.
    var response_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer response_arena_state.deinit();
    const response_arena = response_arena_state.allocator();

    const Phase = enum { first, second, deletions, additions, done, full, full_done };
    var phase: Phase = .first;
    var soa_seen: usize = 0;
    var total_answers: usize = 0;
    var new_serial: u32 = 0;
    var deletions: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer deletions.deinit(response_arena);
    var additions: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer additions.deinit(response_arena);
    var serial_added = false;
    var first_soa_record: ?dns_record.ResourceRecord = null;
    var full_records: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer full_records.deinit(response_arena);
    var full_soa_seen: usize = 0;
    var closing_soa: ?dns_record.ResourceRecord = null;

    var frame_index: usize = 0;
    var frame_buffer: [max_frame_bytes]u8 = undefined;
    var total_bytes: usize = 0;
    while (frame_index < max_frames) : (frame_index += 1) {
        const frame_deadline = idleDeadline(io, total_deadline);
        var length_bytes: [2]u8 = undefined;
        tcp_deadline.readExact(stream.socket.handle, io, &length_bytes, frame_deadline) catch return Error.IoFailed;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length == 0) return Error.BadTransfer;
        total_bytes += length;
        if (total_bytes > budget_bytes) return Error.TooLarge;
        tcp_deadline.readExact(stream.socket.handle, io, frame_buffer[0..length], frame_deadline) catch return Error.IoFailed;
        if (tsig) |key| {
            const first_frame = frame_index == 0;
            request_mac = verifyFrame(frame_buffer[0..length], key, request_mac, first_frame) catch return Error.BadMac;
        }
        const message = dns_message.Message.parse(response_arena, frame_buffer[0..length]) catch return Error.BadTransfer;
        if (message.header.id != query.header.id) return Error.BadTransfer;
        if (message.header.truncated) return Error.BadTransfer;
        if (message.header.rcode != .no_error) return Error.BadTransfer;
        for (message.answers.slice()) |record_value| {
            // An opaque RDATA over 2048 bytes is borrowed from the shared
            // frame buffer; the delta is applied after later frames reuse it,
            // so own a copy in the arena before the record outlives this frame.
            var record = record_value;
            try ownBorrowedRdata(response_arena, &record);
            total_answers += 1;
            if (record.rrtype.eql(.SOA)) {
                soa_seen += 1;
                const serial = switch (record.rdata) {
                    .SOA => |soa| soa.serial,
                    else => return Error.BadTransfer,
                };
                switch (phase) {
                    .first => {
                        var owner_buffer: [256]u8 = undefined;
                        const owner = record.owner.toText(&owner_buffer) catch return Error.BadTransfer;
                        if (!std.ascii.eqlIgnoreCase(owner, zone)) return Error.BadTransfer;
                        // RFC 1982: the first SOA must be newer than the served
                        // copy, unless it equals it (the up-to-date answer is
                        // a single SOA, checked below). Anything else is a
                        // stale or wrapped answer the refresh must not apply.
                        if (serial != current_serial and !zone_update.serialGreaterThan(serial, current_serial)) return Error.BadTransfer;
                        new_serial = serial;
                        first_soa_record = record;
                        phase = .second;
                    },
                    .second => {
                        // RFC 1995 section 3: the second record of a
                        // differential is the served copy's SOA. Anything
                        // else is not the delta from the served serial and
                        // is refused before anything is applied.
                        if (serial != current_serial) return Error.BadTransfer;
                        phase = .deletions;
                    },
                    .deletions => {
                        // The old SOA frames the deletions; the next new SOA
                        // opens the additions and carries the new serial. A
                        // different serial here opens a further delta: fall
                        // back to a full AXFR on a fresh connection rather
                        // than misapplying half a chain (the deferred close
                        // ends the delta connection).
                        if (serial != new_serial) return fetchSignedBudget(allocator, io, primary, zone, remainingTimeout(io, total_deadline), tsig, budget_bytes -| total_bytes);
                        additions.append(response_arena, record) catch return Error.OutOfMemory;
                        serial_added = true;
                        phase = .additions;
                    },
                    .additions => {
                        if (serial == new_serial) {
                            phase = .done;
                            break;
                        }
                        // A legal multi-delta sequence (RFC 1995 section 3)
                        // carries more than one delta: this client applies at
                        // most one, so it falls back to a full AXFR on a
                        // fresh connection rather than misapplying half a
                        // chain. The remaining total budget covers the retry.
                        return fetchSignedBudget(allocator, io, primary, zone, remainingTimeout(io, total_deadline), tsig, budget_bytes -| total_bytes);
                    },
                    .done, .full_done => return Error.BadTransfer,
                    .full => {
                        full_soa_seen += 1;
                        if (full_soa_seen == 2) {
                            // The closing SOA is not written to the zone text
                            // (same shape as `fetch`), but it is kept for the
                            // owner/serial equality check below.
                            closing_soa = record;
                            phase = .full_done;
                            break;
                        }
                        full_records.append(response_arena, record) catch return Error.OutOfMemory;
                    },
                }
                continue;
            }
            switch (phase) {
                .deletions => {
                    var deleted = record;
                    // RFC 2136 section 2.4: a delete-one RR carries the
                    // record to match, with class NONE and TTL zero.
                    deleted.class = dns_types.Class.fromCode(254);
                    deleted.ttl = 0;
                    deletions.append(response_arena, deleted) catch return Error.OutOfMemory;
                },
                .additions => {
                    if (!record.class.eql(dns_types.Class.IN)) return Error.BadTransfer;
                    additions.append(response_arena, record) catch return Error.OutOfMemory;
                    if (record.rrtype.eql(.SOA)) serial_added = true;
                },
                .second => {
                    // A non-SOA second record shows the full zone: fall back
                    // to the AXFR-shaped answer on this same connection.
                    full_records.append(response_arena, first_soa_record.?) catch return Error.OutOfMemory;
                    full_records.append(response_arena, record) catch return Error.OutOfMemory;
                    full_soa_seen = 1;
                    phase = .full;
                },
                .first => return Error.BadTransfer,
                .full => {
                    full_records.append(response_arena, record) catch return Error.OutOfMemory;
                },
                .done, .full_done => {},
            }
        }
        if (phase == .done or phase == .full_done) break;
        // RFC 1995 section 2: the up-to-date answer is a single SOA carrying
        // the served serial. Anything else alone is not up-to-date.
        if (total_answers == 1 and soa_seen == 1 and phase == .second) {
            if (new_serial != current_serial) return Error.BadTransfer;
            return zone_update.renderZoneText(allocator, zone, current.records.items[0..current.records.len]);
        }
    }
    if (phase == .full_done) {
        // RFC 1995 section 4: the primary answered with the whole zone. The
        // closing SOA must match the opening one exactly (owner and serial),
        // the same rule `fetch` enforces; otherwise refuse the transfer.
        const last_full = closing_soa orelse return Error.BadTransfer;
        if (full_records.items.len == 0) return Error.BadTransfer;
        const first_full = full_records.items[0];
        var first_owner: [256]u8 = undefined;
        var last_owner: [256]u8 = undefined;
        const first_text = first_full.owner.toText(&first_owner) catch return Error.BadTransfer;
        const last_text = last_full.owner.toText(&last_owner) catch return Error.BadTransfer;
        if (!std.ascii.eqlIgnoreCase(first_text, last_text)) return Error.BadTransfer;
        if (!std.ascii.eqlIgnoreCase(first_text, zone)) return Error.BadTransfer;
        const first_serial = switch (first_full.rdata) {
            .SOA => |soa| soa.serial,
            else => return Error.BadTransfer,
        };
        const last_serial = switch (last_full.rdata) {
            .SOA => |soa| soa.serial,
            else => return Error.BadTransfer,
        };
        if (first_serial != last_serial) return Error.BadTransfer;
        var output = std.Io.Writer.Allocating.init(allocator);
        output.writer.print("$ORIGIN {s}\n$TTL 1\n", .{zone}) catch return Error.OutOfMemory;
        for (full_records.items) |record| try writeRecord(&output.writer, record);
        var list = output.toArrayList();
        return list.toOwnedSlice(allocator) catch return Error.OutOfMemory;
    }
    if (phase != .done) return Error.BadTransfer;
    if (!serial_added) return Error.BadTransfer;
    // One RFC 2136 transaction carries the delta in RFC 1995 order: the
    // delete-one records first, then the added records (the new SOA included,
    // so the primary's serial is applied exactly rather than raised by one).
    var updates: std.ArrayList(dns_record.ResourceRecord) = .empty;
    defer updates.deinit(allocator);
    updates.appendSlice(allocator, deletions.items) catch return Error.OutOfMemory;
    updates.appendSlice(allocator, additions.items) catch return Error.OutOfMemory;
    const outcome = zone_update.apply(allocator, current, zone, &.{}, updates.items) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
    };
    return switch (outcome) {
        .zone_text => |text| text,
        .rcode => Error.BadTransfer,
    };
}
/// One total wall-clock budget plus one per-frame idle deadline (10 s):
/// `total_deadline` is the absolute budget; `idleDeadline` caps one frame
/// read. A stalled primary fails at the idle deadline, a slow-but-moving
/// one at the budget.
/// Copies an opaque RDATA borrowed from the frame buffer into `arena`, so a
/// record kept across frames never points at bytes a later read overwrites.
fn ownBorrowedRdata(arena: std.mem.Allocator, record: *dns_record.ResourceRecord) Error!void {
    switch (record.rdata) {
        .Unknown => |*unknown| if (unknown.borrowed) |borrowed| {
            const copy = arena.dupe(u8, borrowed) catch return Error.OutOfMemory;
            unknown.len = @intCast(copy.len);
            unknown.borrowed = copy;
        },
        else => {},
    }
}

/// The remaining wall-clock budget as a relative timeout, so an IXFR->AXFR
/// fallback cannot start a fresh full budget on the same refresh.
fn remainingTimeout(io: std.Io, total_deadline: std.Io.Clock.Timestamp) std.Io.Timeout {
    const remaining_ns = total_deadline.durationFromNow(io).raw.nanoseconds;
    const clamped: i96 = if (remaining_ns > 0) remaining_ns else 0;
    return .{ .duration = .{ .raw = .fromNanoseconds(clamped), .clock = .awake } };
}

pub const idle_timeout_ns: i64 = 10 * std.time.ns_per_s;

fn idleDeadline(io: std.Io, total_deadline: std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
    const idle = std.Io.Clock.Duration{ .raw = .fromNanoseconds(idle_timeout_ns), .clock = .awake };
    const idle_deadline = std.Io.Clock.Timestamp.fromNow(io, idle);
    // Earlier deadline = shorter remaining duration from now.
    const idle_remaining = idle_deadline.durationFromNow(io).raw.nanoseconds;
    const total_remaining = total_deadline.durationFromNow(io).raw.nanoseconds;
    return if (idle_remaining < total_remaining) idle_deadline else total_deadline;
}

/// TSIG-signs `query` in place: appends a zeroed final TSIG record keyed by
/// `key` (RFC 8945 section 4.2) before encoding. The MAC is patched after
/// encoding by `patchQueryMac`, which signs the encoded bytes directly.
fn signQuery(query: *dns_message.Message, key: TsigKey) !void {
    const digest_len = dns_tsig.digestLength(key.algorithm);
    var zero_mac: [64]u8 = @splat(0);
    // Tests pin `now` so the suite never depends on wall time; production
    // leaves it zero and the wall clock is used.
    const now_s: u64 = if (key.now != 0) key.now else @intCast(@divTrunc(std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds, std.time.ns_per_s));
    const algorithm_name = switch (key.algorithm) {
        .hmac_sha1 => "hmac-sha1.",
        .hmac_sha224 => "hmac-sha224.",
        .hmac_sha256 => "hmac-sha256.",
        .hmac_sha384 => "hmac-sha384.",
        .hmac_sha512 => "hmac-sha512.",
        .hmac_sha256_128 => "hmac-sha256-128.",
        .hmac_sha384_192 => "hmac-sha384-192.",
        .hmac_sha512_256 => "hmac-sha512-256.",
    };
    const algorithm = @import("../dns/name.zig").Name.fromText(algorithm_name) catch return error.Formerr;
    const value = @import("../dns/rdata.zig").Tsig.init(algorithm, now_s, 300, zero_mac[0..digest_len], query.header.id, 0, &.{}) catch return error.Formerr;
    query.additionals.append(.{
        .owner = key.owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }) catch return error.OutOfMemory;
    query.header.additional_count += 1;
}

/// Signs already-encoded `request` bytes (no prior MAC, RFC 8945 section 4),
/// patches the MAC in place, and returns it as the first response's prior.
fn patchQueryMac(request: []u8, key: TsigKey) !dns_tsig.Mac {
    const final = (dns_tsig.parseFinalAdditional(request) catch return error.Formerr) orelse return error.Formerr;
    const mac = dns_tsig.sign(request, key.secret, final.owner, final.tsig, null) catch return error.Formerr;
    dns_tsig.patchMac(request, final, mac.slice()) catch return error.Formerr;
    return mac;
}

/// Verifies one response frame's chained TSIG against `key` and the prior
/// MAC, returning the frame's MAC as the next prior (RFC 8945 5.3.1). The
/// first message of a multi-message answer carries the standard answer MAC
/// (request MAC in the digest); later messages chain on the previous MAC.
fn verifyFrame(frame: []u8, key: TsigKey, prior: ?dns_tsig.Mac, first: bool) !dns_tsig.Mac {
    const prior_mac = prior orelse return error.BadMac;
    if (first) {
        return dns_tsig.verify(frame, key.secret, prior_mac.slice()) catch error.BadMac;
    }
    return dns_tsig.verifyChained(&.{frame}, key.secret, prior_mac.slice()) catch error.BadMac;
}

/// One TCP connect bounded by `deadline`: a nonblocking connect plus a poll,
/// so a blackholed primary fails at the budget instead of the OS SYN timeout.
/// Mirrors the resolver's forwarding connect without importing the resolver.
fn connectBounded(io: std.Io, primary: *const std.Io.net.IpAddress, deadline: std.Io.Clock.Timestamp) !std.Io.net.Stream {
    const duration = deadline.durationFromNow(io);
    const timeout_ms = duration.raw.toMilliseconds();
    if (timeout_ms <= 0) return error.Timeout;
    const poll_timeout: i32 = @intCast(@min(timeout_ms, std.math.maxInt(i32)));
    var local = switch (primary.*) {
        .ip4 => std.Io.net.IpAddress{ .ip4 = .unspecified(0) },
        .ip6 => std.Io.net.IpAddress{ .ip6 = .unspecified(0) },
    };
    var socket = std.Io.net.IpAddress.bind(&local, io, .{ .mode = .stream, .protocol = .tcp }) catch return error.Unexpected;
    errdefer socket.close(io);
    const get = std.posix.system.fcntl(socket.handle, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(get) != .SUCCESS) return error.Unexpected;
    const set = std.posix.system.fcntl(socket.handle, std.posix.F.SETFL, @as(usize, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }))));
    if (std.posix.errno(set) != .SUCCESS) return error.Unexpected;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const address_len = std.Io.Threaded.addressToPosix(primary, &storage);
    switch (std.posix.errno(std.posix.system.connect(socket.handle, &storage.any, address_len))) {
        .SUCCESS => {},
        .INPROGRESS, .AGAIN => {
            var poll_fds = [_]std.posix.pollfd{.{ .fd = socket.handle, .events = std.posix.POLL.OUT, .revents = 0 }};
            const ready = std.posix.poll(&poll_fds, poll_timeout) catch return error.Unexpected;
            if (ready == 0) return error.Timeout;
            if ((poll_fds[0].revents & (std.posix.POLL.OUT | std.posix.POLL.ERR | std.posix.POLL.HUP)) == 0) return error.Timeout;
            var socket_error: i32 = 0;
            var option_length: std.posix.socklen_t = @sizeOf(@TypeOf(socket_error));
            const option_result = std.posix.system.getsockopt(socket.handle, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&socket_error), &option_length);
            if (std.posix.errno(option_result) != .SUCCESS or socket_error != 0) return error.ConnectionRefused;
        },
        else => return error.Unexpected,
    }
    const restore = std.posix.system.fcntl(socket.handle, std.posix.F.SETFL, @as(usize, @intCast(get)));
    if (std.posix.errno(restore) != .SUCCESS) return error.Unexpected;
    return .{ .socket = socket };
}

fn writeRecord(writer: *std.Io.Writer, record: dns_record.ResourceRecord) Error!void {
    if (record.class.value != dns_types.Class.IN.value) return Error.BadTransfer;
    var name_buffer: [256]u8 = undefined;
    const owner = record.owner.toText(&name_buffer) catch return Error.BadTransfer;
    var wire: [max_frame_bytes]u8 = undefined;
    var wire_writer = dns_writer.Writer.init(&wire);
    record.rdata.encode(&wire_writer) catch return Error.BadTransfer;
    writer.print("{s} {d} IN TYPE{d} \\# {d} ", .{ owner, record.ttl, record.rrtype.code(), wire_writer.len() }) catch return Error.OutOfMemory;
    for (wire_writer.written()) |byte| writer.print("{x:0>2}", .{byte}) catch return Error.OutOfMemory;
    writer.writeByte('\n') catch return Error.OutOfMemory;
}

test "an AXFR over DNS/TCP returns the transferred zone as text" {
    // The fixture runs a real loopback server on its own thread. The two
    // sides get separate threaded Io backends: sharing one backend across a
    // blocked accept and a blocked client poll can starve the poll and turn
    // the transfer into a timeout under a loaded test gate.
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const transfer = @import("transfer.zig");
    const zone_index = @import("index.zig");
    const zone_parser = @import("parser.zig");

    const zone_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\www IN A 192.0.2.80
        \\
    ;
    var zone_file = try zone_parser.ZoneFile.parse(zone_text);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };

    const ServerArgs = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        zone: *const zone_index.Zone,
        ready: *std.atomic.Value(bool),
    };
    const Server = struct {
        fn run(args: ServerArgs) void {
            args.ready.store(true, .release);
            var connection = args.listener.accept(args.io) catch return;
            defer connection.close(args.io);
            var read_buffer: [4096]u8 = undefined;
            var reader = connection.reader(args.io, &read_buffer);
            var length_bytes: [2]u8 = undefined;
            readExact(&reader, &length_bytes) catch return;
            const length = std.mem.readInt(u16, &length_bytes, .big);
            var query_buffer: [limits.max_message_bytes]u8 = undefined;
            readExact(&reader, query_buffer[0..length]) catch return;
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const request = dns_message.Message.parseQuery(arena.allocator(), query_buffer[0..length]) catch return;
            const messages = transfer.buildAxfrMessages(std.heap.page_allocator, &request, args.zone, 2) catch return;
            defer {
                for (messages) |*message| message.deinit();
                std.heap.page_allocator.free(messages);
            }
            for (messages) |*message| {
                var frame: [limits.max_message_bytes]u8 = undefined;
                var writer = dns_writer.Writer.init(&frame);
                message.encode(&writer) catch return;
                var prefix: [2]u8 = undefined;
                std.mem.writeInt(u16, &prefix, @intCast(writer.len()), .big);
                writeAll(connection, args.io, &prefix) catch return;
                writeAll(connection, args.io, writer.written()) catch return;
            }
        }
        fn readExact(reader: *std.Io.net.Stream.Reader, buffer: []u8) !void {
            try reader.interface.readSliceAll(buffer);
        }
        fn writeAll(stream: std.Io.net.Stream, args_io: std.Io, bytes: []const u8) !void {
            var write_buffer: [4096]u8 = undefined;
            var writer = stream.writer(args_io, &write_buffer);
            try writer.interface.writeAll(bytes);
            try writer.interface.flush();
        }
    };

    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, Server.run, .{ServerArgs{ .io = server_io, .listener = &listener, .zone = &zone, .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    // Fifteen seconds leaves room for a loaded parallel test runner to
    // schedule the loopback primary; the AXFR assertions below are about
    // the transfer, not about a tight timeout.
    const fetched = try fetch(std.testing.allocator, io, &primary, "transferred.example.", .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try zone_parser.ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try zone_index.Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 42), fetched_zone.soaSerial().?);
    var lookup = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(zone_index.LookupKind.answer, lookup.kind);
    const answer = try @import("parser.zig").parseRData(.A, lookup.records.items[0].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 80 }, &answer.A);
}

const FrameServerArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    bytes: []u8,
    ready: *std.atomic.Value(bool),
};
const FrameServer = struct {
    fn run(args: FrameServerArgs) void {
        args.ready.store(true, .release);
        var connection = args.listener.accept(args.io) catch return;
        defer connection.close(args.io);
        var read_buffer: [4096]u8 = undefined;
        var reader = connection.reader(args.io, &read_buffer);
        var length_bytes: [2]u8 = undefined;
        readExact(&reader, &length_bytes) catch return;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        var query_buffer: [limits.max_message_bytes]u8 = undefined;
        readExact(&reader, query_buffer[0..length]) catch return;
        // Echo the query's ID into the canned answer: the fetch refuses any
        // response whose ID differs from the randomized query ID, so a
        // fixed fixture ID would be rejected for the wrong reason.
        if (length >= 2 and args.bytes.len >= 2) {
            args.bytes[0] = query_buffer[0];
            args.bytes[1] = query_buffer[1];
        }
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(args.bytes.len), .big);
        writeAll(connection, args.io, &prefix) catch return;
        writeAll(connection, args.io, args.bytes) catch return;
    }
    fn readExact(reader: *std.Io.net.Stream.Reader, buffer: []u8) !void {
        try reader.interface.readSliceAll(buffer);
    }
    fn writeAll(stream: std.Io.net.Stream, stream_io: std.Io, bytes: []const u8) !void {
        var write_buffer: [4096]u8 = undefined;
        var writer = stream.writer(stream_io, &write_buffer);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }
};

fn testSoa(owner: []const u8, serial: u32) !dns_record.ResourceRecord {
    const name = try @import("../dns/name.zig").Name.fromText(owner);
    return .{
        .owner = name,
        .rrtype = dns_types.RecordType.SOA,
        .class = dns_types.Class.IN,
        .ttl = 0,
        .rdata = .{ .SOA = .{
            .mname = name,
            .rname = name,
            .serial = serial,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
}

fn testA(owner: []const u8, address: [4]u8) !dns_record.ResourceRecord {
    return .{
        .owner = try @import("../dns/name.zig").Name.fromText(owner),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .A = address },
    };
}

test "an incremental IXFR applies the delta to the served copy" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\dns IN A 192.0.2.54
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4242,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 6,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("dns.transferred.example.", .{ 192, 0, 2, 54 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 43), fetched_zone.soaSerial().?);
    var added = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer added.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, added.kind);
    const added_rdata = try @import("parser.zig").parseRData(.A, added.records.items[0].rdataText());
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 99 }, &added_rdata.A);
    var deleted = fetched_zone.lookup(std.testing.allocator, "dns.transferred.example.", .A);
    defer deleted.deinit(std.testing.allocator);
    try std.testing.expect(deleted.kind != @import("index.zig").LookupKind.answer);
}

test "an IXFR answered with the full zone is applied without a second connection" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4244,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 5,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 5),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(.{
        .owner = try @import("../dns/name.zig").Name.fromText(zone_name),
        .rrtype = dns_types.RecordType.NS,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .NS = try @import("../dns/name.zig").Name.fromText("ns.transferred.example.") },
    });
    try response.answers.append(try testA("dns.transferred.example.", .{ 192, 0, 2, 54 }));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 43), fetched_zone.soaSerial().?);
    var added = fetched_zone.lookup(std.testing.allocator, "www.transferred.example.", .A);
    defer added.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, added.kind);
}

test "an up-to-date IXFR keeps the served copy" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();

    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\dns IN A 192.0.2.54
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{
            .id = 0x4243,
            .qr = true,
            .opcode = .query,
            .question_count = 1,
            .answer_count = 1,
        },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);

    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 42), fetched_zone.soaSerial().?);
    var kept = fetched_zone.lookup(std.testing.allocator, "dns.transferred.example.", .A);
    defer kept.deinit(std.testing.allocator);
    try std.testing.expectEqual(@import("index.zig").LookupKind.answer, kept.kind);
}

test "an IXFR with an older first SOA is rejected and the served copy is untouched" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 43 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4250, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 6 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("evil.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 43), current.soaSerial().?);
}

test "a single-SOA IXFR with a different serial is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4251, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 1 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}

test "a two-delta IXFR falls back to AXFR rather than half-applying" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var delta = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4252, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 9 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 9),
    };
    try delta.answers.append(try testSoa(zone_name, 44));
    try delta.answers.append(try testSoa(zone_name, 42));
    try delta.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try delta.answers.append(try testSoa(zone_name, 43));
    try delta.answers.append(try testA("a.transferred.example.", .{ 192, 0, 2, 1 }));
    try delta.answers.append(try testSoa(zone_name, 43));
    try delta.answers.append(try testA("b.transferred.example.", .{ 192, 0, 2, 2 }));
    try delta.answers.append(try testSoa(zone_name, 44));
    try delta.answers.append(try testSoa(zone_name, 44));
    var delta_buffer: [limits.max_message_bytes]u8 = undefined;
    var delta_writer = dns_writer.Writer.init(&delta_buffer);
    try delta.encode(&delta_writer);
    // The fallback AXFR the client requests on a fresh connection: the
    // full zone at serial 44.
    var full = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4253, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 6 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try full.answers.append(try testSoa(zone_name, 44));
    try full.answers.append(.{
        .owner = try @import("../dns/name.zig").Name.fromText(zone_name),
        .rrtype = dns_types.RecordType.NS,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .NS = try @import("../dns/name.zig").Name.fromText("ns.transferred.example.") },
    });
    try full.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try full.answers.append(try testA("a.transferred.example.", .{ 192, 0, 2, 1 }));
    try full.answers.append(try testA("b.transferred.example.", .{ 192, 0, 2, 2 }));
    try full.answers.append(try testSoa(zone_name, 44));
    var full_buffer: [limits.max_message_bytes]u8 = undefined;
    var full_writer = dns_writer.Writer.init(&full_buffer);
    try full.encode(&full_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    const FallbackServer = struct {
        fn run(args: TwoFrameServerArgs) void {
            args.ready.store(true, .release);
            // First connection: the multi-delta IXFR answer.
            var first = args.listener.accept(args.io) catch return;
            defer first.close(args.io);
            serveOne(first, args.io, args.first) catch return;
            // Second connection: the fallback AXFR answer.
            var second = args.listener.accept(args.io) catch return;
            defer second.close(args.io);
            serveOne(second, args.io, args.second) catch return;
        }
        fn serveOne(connection: std.Io.net.Stream, stream_io: std.Io, bytes: []u8) !void {
            var read_buffer: [4096]u8 = undefined;
            var reader = connection.reader(stream_io, &read_buffer);
            var length_bytes: [2]u8 = undefined;
            try FrameServer.readExact(&reader, &length_bytes);
            const length = std.mem.readInt(u16, &length_bytes, .big);
            var query_buffer: [limits.max_message_bytes]u8 = undefined;
            try FrameServer.readExact(&reader, query_buffer[0..length]);
            if (length >= 2 and bytes.len >= 2) {
                bytes[0] = query_buffer[0];
                bytes[1] = query_buffer[1];
            }
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(bytes.len), .big);
            try FrameServer.writeAll(connection, stream_io, &prefix);
            try FrameServer.writeAll(connection, stream_io, bytes);
        }
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FallbackServer.run, .{TwoFrameServerArgs{ .io = server_io, .listener = &listener, .first = @constCast(delta_writer.written()), .second = @constCast(full_writer.written()), .ready = &ready }});
    // The listener is closed before the join (defer order): a missing
    // second connection then fails the server's accept instead of hanging
    // the join forever.
    defer thread.join();
    defer listener.deinit(server_io);
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const fetched = try fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } });
    defer std.testing.allocator.free(fetched);
    var fetched_file = try @import("parser.zig").ZoneFile.parse(fetched);
    defer fetched_file.deinit();
    var fetched_zone = try @import("index.zig").Zone.fromZoneFile(&fetched_file);
    defer fetched_zone.deinit();
    try std.testing.expectEqual(@as(u32, 44), fetched_zone.soaSerial().?);
}
const TwoFrameServerArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    first: []u8,
    second: []u8,
    ready: *std.atomic.Value(bool),
};
const TwoFrameServer = struct {
    fn run(args: TwoFrameServerArgs) void {
        args.ready.store(true, .release);
        var connection = args.listener.accept(args.io) catch return;
        defer connection.close(args.io);
        var read_buffer: [4096]u8 = undefined;
        var reader = connection.reader(args.io, &read_buffer);
        var length_bytes: [2]u8 = undefined;
        FrameServer.readExact(&reader, &length_bytes) catch return;
        const length = std.mem.readInt(u16, &length_bytes, .big);
        var query_buffer: [limits.max_message_bytes]u8 = undefined;
        FrameServer.readExact(&reader, query_buffer[0..length]) catch return;
        if (length >= 2) {
            if (args.first.len >= 2) {
                args.first[0] = query_buffer[0];
                args.first[1] = query_buffer[1];
            }
            if (args.second.len >= 2) {
                args.second[0] = query_buffer[0];
                args.second[1] = query_buffer[1];
            }
        }
        for ([_][]u8{ args.first, args.second }) |bytes| {
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(bytes.len), .big);
            FrameServer.writeAll(connection, args.io, &prefix) catch return;
            FrameServer.writeAll(connection, args.io, bytes) catch return;
        }
    }
};

test "an AXFR frame with TC set is rejected as a failed transfer" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4260, .qr = true, .truncated = true, .opcode = .query, .question_count = 1, .answer_count = 2 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 2),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetch(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
}

test "an IXFR first frame with TC set is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4261, .qr = true, .truncated = true, .opcode = .query, .question_count = 1, .answer_count = 6 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 6),
    };
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("ns.transferred.example.", .{ 192, 0, 2, 53 }));
    try response.answers.append(try testSoa(zone_name, 43));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    try response.answers.append(try testSoa(zone_name, 43));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}

test "an IXFR with TC set on a later frame is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const current_text =
        \\$ORIGIN transferred.example.
        \\$TTL 3600
        \\@ IN SOA ns.transferred.example. hostmaster.transferred.example. 42 3600 900 1209600 3600
        \\@ IN NS ns.transferred.example.
        \\ns IN A 192.0.2.53
        \\
    ;
    var current_file = try @import("parser.zig").ZoneFile.parse(current_text);
    defer current_file.deinit();
    var current = try @import("index.zig").Zone.fromZoneFile(&current_file);
    defer current.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var first = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4262, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 2 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.IXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 2),
    };
    try first.answers.append(try testSoa(zone_name, 43));
    try first.answers.append(try testSoa(zone_name, 42));
    var second = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4262, .qr = true, .truncated = true, .opcode = .query, .answer_count = 1 },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try second.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 99 }));
    var first_buffer: [limits.max_message_bytes]u8 = undefined;
    var first_writer = dns_writer.Writer.init(&first_buffer);
    try first.encode(&first_writer);
    const first_bytes = first_writer.written();
    var second_buffer: [limits.max_message_bytes]u8 = undefined;
    var second_writer = dns_writer.Writer.init(&second_buffer);
    try second.encode(&second_writer);
    const second_bytes = second_writer.written();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, TwoFrameServer.run, .{TwoFrameServerArgs{ .io = server_io, .listener = &listener, .first = @constCast(first_bytes), .second = @constCast(second_bytes), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetchIxfr(std.testing.allocator, io, &primary, zone_name, &current, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
    try std.testing.expectEqual(@as(u32, 42), current.soaSerial().?);
}
test "an AXFR with a wrong message ID is rejected" {
    // A fixed fixture ID never matches the randomized query ID, which is
    // exactly the spoof the check refuses: the canned answer is patched
    // with a wrong ID on purpose, so the fetch must reject it. The server
    // copies the frame untouched instead of echoing the query ID.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x1234, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 2 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 2),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    const FixedServer = struct {
        fn run(args: FrameServerArgs) void {
            args.ready.store(true, .release);
            var connection = args.listener.accept(args.io) catch return;
            defer connection.close(args.io);
            var read_buffer: [4096]u8 = undefined;
            var reader = connection.reader(args.io, &read_buffer);
            var length_bytes: [2]u8 = undefined;
            FrameServer.readExact(&reader, &length_bytes) catch return;
            const length = std.mem.readInt(u16, &length_bytes, .big);
            var query_buffer: [limits.max_message_bytes]u8 = undefined;
            FrameServer.readExact(&reader, query_buffer[0..length]) catch return;
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(args.bytes.len), .big);
            FrameServer.writeAll(connection, args.io, &prefix) catch return;
            FrameServer.writeAll(connection, args.io, args.bytes) catch return;
        }
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FixedServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetch(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
}

test "an AXFR whose closing SOA differs is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4242, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 3 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 3),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    // A closing SOA with a different owner and serial is a different zone
    // version smuggled into the transfer: refuse it.
    try response.answers.append(try testSoa("other.example.", 43));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetch(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
}

test "an AXFR past the total byte cap is rejected" {
    // The production cap is exactly 64 MiB; moving that over loopback per
    // test would be slow, so the budget core is exercised with a tiny
    // budget against the normal multi-record AXFR fixture: the first frame
    // already exceeds it, proving the accumulator fires.
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), max_total_bytes);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4242, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 3 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 3),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    // One byte of budget: the first frame exceeds it.
    try std.testing.expectError(Error.TooLarge, fetchSignedBudget(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }, null, 1));
}

test "a signed AXFR against an unsigned server fails closed" {
    // Verification is enforced: a server that answers without TSIG cannot
    // feed a signed fetch. The unsigned frame fails verification, so the
    // transfer fails rather than serving unsigned data as signed.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    const key_owner = try @import("../dns/name.zig").Name.fromText("key.");
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4242, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 3 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 3),
    };
    try response.answers.append(try testSoa(zone_name, 42));
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    try response.answers.append(try testSoa(zone_name, 42));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const key = TsigKey{ .owner = key_owner, .algorithm = .hmac_sha256, .secret = "01234567890123456789012345678901", .now = 0 };
    try std.testing.expectError(Error.BadMac, fetchSigned(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }, key));
}

pub const RefreshAction = enum {
    idle,
    refresh_due,
    retry_due,
    expired,
};

pub const RefreshInput = struct {
    now_ns: i64,
    last_success_ns: ?i64,
    refresh_sec: u32,
    retry_sec: u32,
    expire_sec: u32,
    last_attempt_failed: bool = false,
    last_attempt_ns: ?i64 = null,
};

fn secondsToNs(seconds: u32) i64 {
    if (seconds == 0) return 0;
    // Conservative: cap at i64 max to avoid overflow; zero timers mean
    // "never due by this clock" rather than wrap-around.
    const product = @as(i128, seconds) * @as(i128, std.time.ns_per_s);
    if (product > std.math.maxInt(i64)) return std.math.maxInt(i64);
    return @intCast(product);
}

/// Pure RFC 1034/1035 SOA refresh schedule for one secondary zone. Pure
/// function with no I/O; the runtime drives it on each serve loop tick.
pub fn refreshDecision(input: RefreshInput) RefreshAction {
    // A failed attempt gates every retry behind the retry interval (60 s
    // when `retry_sec` is unset), even when the zone never loaded or is
    // past expire: the gate only delays the next fetch, the stale `expired`
    // flag on the secondary keeps answers SERVFAIL/REFUSED meanwhile.
    const retry_sec = if (input.retry_sec == 0) 60 else input.retry_sec;
    const retry_ns = secondsToNs(retry_sec);
    if (input.last_attempt_failed) {
        if (input.last_attempt_ns) |attempt| {
            if (input.now_ns < attempt) return .idle; // clock moved backwards
            if (input.now_ns - attempt < retry_ns) return .idle;
        }
        // Retry window elapsed (or no attempt recorded): due, keeping the
        // expired state observable so the zone stays SERVFAIL/REFUSED.
        if (input.last_success_ns) |last_success| {
            if (input.now_ns < last_success) return .idle; // clock moved backwards
            const expire_ns = secondsToNs(input.expire_sec);
            if (expire_ns != 0 and input.now_ns - last_success >= expire_ns) return .expired;
            return .retry_due;
        }
        return .retry_due;
    }
    const last_success = input.last_success_ns orelse return .refresh_due;
    if (input.now_ns < last_success) return .idle; // clock moved backwards
    const elapsed = input.now_ns - last_success;

    const refresh_ns = secondsToNs(input.refresh_sec);
    const expire_ns = secondsToNs(input.expire_sec);

    // Conservative: an unset (zero) expire means never expire.
    if (expire_ns != 0 and elapsed >= expire_ns) return .expired;

    if (refresh_ns != 0 and elapsed >= refresh_ns) return .refresh_due;
    return .idle;
}

test "an AXFR whose first record is not the zone SOA is rejected" {
    const io_impl = @import("std").Io.Threaded;
    var server_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = io_impl.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zone_name = "transferred.example.";
    var response = dns_message.Message{
        .allocator = arena,
        .header = .{ .id = 0x4261, .qr = true, .opcode = .query, .question_count = 1, .answer_count = 1 },
        .question = .{ .name = try @import("../dns/name.zig").Name.fromText(zone_name), .qtype = dns_types.RecordType.AXFR, .qclass = dns_types.Class.IN },
        .answers = try dns_message.RecordSection.init(arena, 1),
    };
    try response.answers.append(try testA("www.transferred.example.", .{ 192, 0, 2, 80 }));
    var frame_buffer: [limits.max_message_bytes]u8 = undefined;
    var frame_writer = dns_writer.Writer.init(&frame_buffer);
    try response.encode(&frame_writer);
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, FrameServer.run, .{FrameServerArgs{ .io = server_io, .listener = &listener, .bytes = @constCast(frame_writer.written()), .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    const primary = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(Error.BadTransfer, fetch(std.testing.allocator, io, &primary, zone_name, .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } }));
}

test "a borrowed opaque RDATA survives frame buffer reuse" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var source: [4096]u8 = undefined;
    @memset(&source, 0xAB);
    var record = dns_record.ResourceRecord{
        .owner = try @import("../dns/name.zig").Name.fromText("example."),
        .rrtype = dns_types.RecordType.TXT,
        .class = dns_types.Class.IN,
        .ttl = 0,
        .rdata = .{ .Unknown = .{ .len = 3000, .borrowed = source[0..3000] } },
    };
    try ownBorrowedRdata(arena_state.allocator(), &record);
    @memset(source[0..3000], 0);
    const owned = record.rdata.Unknown.bytes();
    try std.testing.expectEqual(@as(usize, 3000), owned.len);
    try std.testing.expectEqual(@as(u8, 0xAB), owned[0]);
    try std.testing.expectEqual(@as(u8, 0xAB), owned[2999]);
}

test "refresh decision: never fetched means refresh due" {
    try std.testing.expectEqual(RefreshAction.refresh_due, refreshDecision(.{ .now_ns = 100, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: refresh interval" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 10, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
    try std.testing.expectEqual(RefreshAction.refresh_due, refreshDecision(.{ .now_ns = 60000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: retry after failure" {
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 0, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = null }));
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 10, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 30000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
}

test "refresh decision: expired" {
    try std.testing.expectEqual(RefreshAction.expired, refreshDecision(.{ .now_ns = 3600000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: clock backwards is idle" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = -5, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600 }));
}

test "refresh decision: zero timers conservative" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 100, .last_success_ns = 0, .refresh_sec = 0, .retry_sec = 30, .expire_sec = 0 }));
}

test "refresh decision: never-loaded failure is gated by retry" {
    // Attempt within the retry window: no fetch.
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 10, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    // Retry window elapsed: due again.
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 30000000000, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
}

test "refresh decision: expired failure is gated by retry but stays expired" {
    // Attempt within the retry window: gated, even when past expire.
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 3600000000010, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 3600000000000 }));
    // Retry window elapsed: observable expiry, so the serve path keeps
    // answering SERVFAIL while the refresh is retried.
    try std.testing.expectEqual(RefreshAction.expired, refreshDecision(.{ .now_ns = 3600030000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 30, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
}

test "refresh decision: zero retry means 60 s" {
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 59000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 0, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 60000000000, .last_success_ns = 0, .refresh_sec = 60, .retry_sec = 0, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    try std.testing.expectEqual(RefreshAction.idle, refreshDecision(.{ .now_ns = 59000000000, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 0, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
    try std.testing.expectEqual(RefreshAction.retry_due, refreshDecision(.{ .now_ns = 60000000000, .last_success_ns = null, .refresh_sec = 60, .retry_sec = 0, .expire_sec = 3600, .last_attempt_failed = true, .last_attempt_ns = 0 }));
}
