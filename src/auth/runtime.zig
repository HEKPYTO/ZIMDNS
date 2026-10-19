/// Contract: Answers authoritative zones first and optionally forwards authorized UDP queries.
/// Ownership: Runtime owns its Zone and inline Blocklist; call Runtime.deinit; query and output buffers are borrowed.
/// Errors: Query and response failures are typed; transport I/O is handled by platform listeners.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const dns_writer = @import("../dns/writer.zig");
const response = @import("response.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");
const metrics = @import("../metrics.zig");
const blocklist_mod = @import("../blocklist.zig");
const resolver_mod = @import("../resolver.zig");
const local_zone = @import("../local_zone.zig");
const keyring_mod = @import("keyring.zig");
const tsig = @import("../dns/tsig.zig");
const transfer = @import("../zone/transfer.zig");
const journal_mod = @import("../zone/journal.zig");

pub const Error = error{
    BadQuery,
    EncodeFailed,
};

const TsigAuth = struct {
    final: tsig.FinalAdditional,
    key: *const keyring_mod.Key,
    request_mac: tsig.Mac,
};

const FailureCode = enum {
    bad_query,
    formerr,
    badkey,
    badsig,
    badtime,
    badtrunc,
};

const Failure = struct {
    code: FailureCode,
    final: ?tsig.FinalAdditional = null,
    key: ?*const keyring_mod.Key = null,
    request_mac: ?tsig.Mac = null,
};

const Incoming = struct {
    query: dns_message.Message,
    auth: ?TsigAuth = null,
};

const IncomingResult = union(enum) {
    incoming: Incoming,
    failure: Failure,
};

pub const Runtime = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},
    resolver: ?resolver_mod.Resolver = null,
    /// RFC 6303/6761/7793/8375 locally served zones, on by default so a
    /// configured forwarder can never leak one of these names upstream
    /// (RFC 7793 section 2, RFC 6598 section 3). `local-zones off` is the
    /// RFC 6303 section 3 mechanism to disable it.
    local_zones: bool = true,
    /// Per-zone override apexes (`local-zones except`), lowercase with
    /// trailing dot, heap-owned. Empty unless configured.
    local_zones_except: []const []const u8 = &.{},
    /// What an authoritative answer may carry back in its OPT record, from the
    /// `nsid` and `zoneversion` directives. `nsid` is heap-owned so it outlives
    /// the config text it was decoded from.
    edns: response.EdnsPolicy = .{},
    keyring: keyring_mod.Keyring = .{},
    tsig_now: ?u64 = null,
    /// Volatile per-zone RFC 1995 serial transitions feeding IXFR delta
    /// decisions. Entry i parallels `zones.items[i]`; appended best-effort so
    /// bulk-loaded runtimes need no fallible log setup. A length mismatch
    /// means no usable history and decideIxfr falls back to AXFR.
    transfer_delta_logs: std.ArrayList(journal_mod.DeltaLog) = .empty,
    // ceiling: global runtime lock serializes all zone reads; use per-zone or read/write locks if contention matters.
    mutex: std.Io.Mutex = .init,

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneText(text: []const u8) !Runtime {
        var runtime = Runtime{};
        errdefer runtime.deinit();
        try runtime.appendZoneText(text);
        return runtime;
    }

    pub fn fromZoneTextWithKeyring(text: []const u8, keyring: *keyring_mod.Keyring) !Runtime {
        var runtime = try fromZoneText(text);
        runtime.keyring = keyring.*;
        keyring.deinit();
        return runtime;
    }

    /// The returned runtime owns its authoritative zone; call deinit when done.
    pub fn fromZoneTextWithBlocklist(text: []const u8, blocklist: blocklist_mod.Blocklist) !Runtime {
        var runtime = try fromZoneText(text);
        runtime.blocklist = blocklist;
        return runtime;
    }

    pub fn fromZoneTextWithBlocklistAndKeyring(
        text: []const u8,
        blocklist: blocklist_mod.Blocklist,
        keyring: *keyring_mod.Keyring,
    ) !Runtime {
        var runtime = try fromZoneTextWithBlocklist(text, blocklist);
        runtime.keyring = keyring.*;
        keyring.deinit();
        return runtime;
    }

    /// The returned runtime owns every zone value moved from `zones`.
    pub fn fromZones(allocator: std.mem.Allocator, zones: *std.ArrayList(zone_index.Zone), blocklist: blocklist_mod.Blocklist) Runtime {
        const runtime = Runtime{ .allocator = allocator, .zones = zones.*, .blocklist = blocklist };
        zones.* = .empty;
        return runtime;
    }

    pub fn fromZonesWithKeyring(
        allocator: std.mem.Allocator,
        zones: *std.ArrayList(zone_index.Zone),
        blocklist: blocklist_mod.Blocklist,
        keyring: *keyring_mod.Keyring,
    ) Runtime {
        var runtime = fromZones(allocator, zones, blocklist);
        runtime.keyring = keyring.*;
        keyring.deinit();
        return runtime;
    }

    pub fn fromZonesWithPolicy(allocator: std.mem.Allocator, zones: *std.ArrayList(zone_index.Zone), blocklist: blocklist_mod.Blocklist, io: std.Io, policy: resolver_mod.Policy) !Runtime {
        var runtime = fromZones(allocator, zones, blocklist);
        errdefer runtime.deinit();
        runtime.resolver = try resolver_mod.Resolver.init(allocator, io, policy);
        return runtime;
    }

    pub fn fromZonesWithPolicyAndKeyring(
        allocator: std.mem.Allocator,
        zones: *std.ArrayList(zone_index.Zone),
        blocklist: blocklist_mod.Blocklist,
        io: std.Io,
        policy: resolver_mod.Policy,
        keyring: *keyring_mod.Keyring,
    ) !Runtime {
        var runtime = try fromZonesWithPolicy(allocator, zones, blocklist, io, policy);
        runtime.keyring = keyring.*;
        keyring.deinit();
        return runtime;
    }

    /// The returned runtime owns all parsed zone backing storage.
    pub fn fromZoneTexts(texts: []const []const u8) !Runtime {
        var runtime = Runtime{};
        errdefer runtime.deinit();
        for (texts) |text| try runtime.appendZoneText(text);
        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        self.lock();
        defer self.unlock();
        if (self.resolver) |*resolver| resolver.deinit();
        self.resolver = null;
        self.keyring.deinit();
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.transfer_delta_logs.deinit(self.allocator);
        self.transfer_delta_logs = .empty;
        self.blocklist = .{};
        if (self.edns.nsid) |nsid| self.allocator.free(nsid);
        self.edns = .{};
        for (self.local_zones_except) |apex| self.allocator.free(apex);
        if (self.local_zones_except.len != 0) self.allocator.free(self.local_zones_except);
        self.local_zones_except = &.{};
    }

    pub fn setTsigNow(self: *Runtime, now: u64) void {
        self.tsig_now = now;
    }

    /// Read-only per-zone log for const contexts holding the runtime lock.
    /// Never grows: a length mismatch means no usable history, so decideIxfr
    /// falls back to AXFR for that decision.
    fn deltaLogForOriginConst(self: *const Runtime, origin: []const u8) ?*const journal_mod.DeltaLog {
        if (self.transfer_delta_logs.items.len != self.zones.items.len) return null;
        for (self.zones.items, 0..) |*zone, index| {
            if (!std.ascii.eqlIgnoreCase(zone.originText(), origin)) continue;
            return &self.transfer_delta_logs.items[index];
        }
        return null;
    }

    fn lock(self: *const Runtime) void {
        std.Io.Threaded.mutexLockUncancelable(@constCast(&self.mutex));
    }

    fn unlock(self: *const Runtime) void {
        std.Io.Threaded.mutexUnlock(@constCast(&self.mutex));
    }

    fn currentTsigTime(self: *const Runtime) u64 {
        if (self.tsig_now) |now| return now;
        const timestamp = std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).nanoseconds;
        return @intCast(@divTrunc(timestamp, std.time.ns_per_s));
    }

    fn copyMac(bytes: []const u8) ?tsig.Mac {
        var mac = tsig.Mac{};
        if (bytes.len > mac.bytes.len) return null;
        mac.len = @intCast(bytes.len);
        @memcpy(mac.bytes[0..bytes.len], bytes);
        return mac;
    }

    fn parseIncoming(self: *const Runtime, allocator: std.mem.Allocator, packet: []const u8) !IncomingResult {
        const final = tsig.parseFinalAdditional(packet) catch |err| switch (err) {
            error.TsigNotFinal,
            error.InvalidClass,
            error.InvalidTtl,
            error.MalformedTsig,
            => return .{ .failure = .{ .code = .formerr } },
            else => {
                const query = dns_message.Message.parseQuery(allocator, packet) catch |parse_err| switch (parse_err) {
                    error.MalformedEcsOption => return .{ .failure = .{ .code = .formerr } },
                    // RFC 9619 section 4: QDCOUNT > 1 is FORMERR for any
                    // OPCODE (Message.parse returns TooManyQuestions).
                    error.TooManyQuestions => return .{ .failure = .{ .code = .formerr } },
                    // RFC 6891 section 6.1.1: a query carrying more than one
                    // OPT RR is answered FORMERR. Section 6.1.2 requires the
                    // OPT owner to be the root and its option framing to be
                    // well formed, so a malformed OPT record is a format
                    // error (RFC 1035 section 4.1.1) answered FORMERR
                    // instead of being dropped without an answer.
                    error.MultipleOptRecords,
                    error.InvalidOptOwner,
                    error.MalformedEdnsOption,
                    => return .{ .failure = .{ .code = .formerr } },
                    error.OutOfMemory => return parse_err,
                    else => {
                        if (parseTransferFallback(allocator, packet)) |fallback| {
                            return .{ .incoming = .{ .query = fallback } };
                        }
                        return .{ .failure = .{ .code = .bad_query } };
                    },
                };
                return .{ .incoming = .{ .query = query } };
            },
        };
        const final_record = final orelse {
            const query = dns_message.Message.parseQuery(allocator, packet) catch |err| switch (err) {
                error.MalformedEcsOption => return .{ .failure = .{ .code = .formerr } },
                // RFC 9619 section 4: QDCOUNT > 1 is FORMERR for any OPCODE
                // (Message.parse returns TooManyQuestions uniformly).
                error.TooManyQuestions => return .{ .failure = .{ .code = .formerr } },
                // RFC 6891 section 6.1.1/6.1.2: a malformed OPT record is a
                // format error answered FORMERR rather than dropped.
                error.MultipleOptRecords,
                error.InvalidOptOwner,
                error.MalformedEdnsOption,
                => return .{ .failure = .{ .code = .formerr } },
                error.OutOfMemory => return err,
                else => {
                    if (parseTransferFallback(allocator, packet)) |fallback| {
                        return .{ .incoming = .{ .query = fallback } };
                    }
                    return .{ .failure = .{ .code = .bad_query } };
                },
            };
            return .{ .incoming = .{ .query = query } };
        };

        const key = self.keyring.find(final_record.owner) orelse {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        };
        const algorithm = tsig.algorithmForName(&final_record.tsig.algorithm) catch {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        };
        if (algorithm != key.algorithm) {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        }
        if (final_record.tsig.error_code != 0) {
            return .{ .failure = .{ .code = .formerr, .final = final_record } };
        }
        const request_mac = copyMac(final_record.tsig.macBytes()) orelse {
            return .{ .failure = .{ .code = .badsig, .final = final_record, .key = key } };
        };
        _ = tsig.verify(packet, key.secretBytes(), null, tsig.digestLength(algorithm)) catch |err| switch (err) {
            error.BadTrunc => return .{ .failure = .{
                .code = .badtrunc,
                .final = final_record,
                .key = key,
                .request_mac = request_mac,
            } },
            error.BadMac => return .{ .failure = .{ .code = .badsig, .final = final_record, .key = key } },
            error.UnsupportedAlgorithm => return .{ .failure = .{ .code = .badkey, .final = final_record } },
            error.Formerr => return .{ .failure = .{ .code = .formerr, .final = final_record } },
            else => return .{ .failure = .{ .code = .formerr, .final = final_record } },
        };

        const now = self.currentTsigTime();
        const signed_time = final_record.tsig.time_signed;
        const delta = if (now >= signed_time) now - signed_time else signed_time - now;
        if (delta > final_record.tsig.fudge) {
            return .{ .failure = .{
                .code = .badtime,
                .final = final_record,
                .key = key,
                .request_mac = request_mac,
            } };
        }

        const auth = TsigAuth{ .final = final_record, .key = key, .request_mac = request_mac };
        const query = dns_message.Message.parseQueryWithoutTsig(
            allocator,
            packet,
            final_record.record_start,
            final_record.record_end,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                if (parseSignedTransferFallback(allocator, packet, final_record)) |fallback| {
                    return .{ .incoming = .{ .query = fallback, .auth = auth } };
                }
                return .{ .failure = .{ .code = .formerr, .final = final_record } };
            },
        };
        return .{ .incoming = .{ .query = query, .auth = auth } };
    }

    /// Parses an unsigned request that strict query parsing rejects but the
    /// transfer profile accepts: IXFR authority SOAs and NOTIFY answer SOAs.
    /// Returns null when the bytes are not a valid transfer request.
    fn parseTransferFallback(allocator: std.mem.Allocator, packet: []const u8) ?dns_message.Message {
        var message = dns_message.Message.parse(allocator, packet) catch return null;
        if (transfer.isNotifyMessage(&message)) return message;
        if (transfer.validateTransferRequest(&message)) |_| return message else |_| {}
        message.deinit();
        return null;
    }

    /// Parses a TSIG-verified request that strict query parsing rejects but
    /// the transfer profile accepts. Authentication already succeeded; only
    /// the section layout differs.
    fn parseSignedTransferFallback(
        allocator: std.mem.Allocator,
        packet: []const u8,
        final_record: tsig.FinalAdditional,
    ) ?dns_message.Message {
        const stripped = transfer.stripTsigRecord(
            allocator,
            packet,
            final_record.record_start,
            final_record.record_end,
        ) catch return null;
        defer allocator.free(stripped);
        var message = dns_message.Message.parse(allocator, stripped) catch return null;
        if (transfer.isNotifyMessage(&message)) return message;
        if (transfer.validateTransferRequest(&message)) |_| return message else |_| {}
        message.deinit();
        return null;
    }

    fn writeTsigTime(now: u64, output: *[6]u8) void {
        output[0] = @intCast((now >> 40) & 0xff);
        output[1] = @intCast((now >> 32) & 0xff);
        output[2] = @intCast((now >> 24) & 0xff);
        output[3] = @intCast((now >> 16) & 0xff);
        output[4] = @intCast((now >> 8) & 0xff);
        output[5] = @intCast(now & 0xff);
    }

    fn encodeFailure(
        self: *const Runtime,
        allocator: std.mem.Allocator,
        packet: []const u8,
        output: []u8,
        failure: Failure,
    ) ![]const u8 {
        if (failure.code == .bad_query) return Error.BadQuery;
        var partial = dns_message.Message.parseHeaderQuestion(allocator, packet) catch return Error.BadQuery;
        defer partial.deinit();

        switch (failure.code) {
            .formerr => return self.encodeMessage(try response.buildFormerrResponse(partial), output),
            .badkey, .badsig => {
                var message = try response.buildRefusedResponse(partial);
                message.header.rcode = .notauth;
                const final = failure.final orelse return self.encodeMessage(message, output);
                return self.encodeUnsignedTsigErrorMessage(message, output, final, if (failure.code == .badkey) 17 else 16);
            },
            .badtime, .badtrunc => {
                const final = failure.final orelse return Error.BadQuery;
                const key = failure.key orelse return Error.BadQuery;
                const request_mac = failure.request_mac orelse return Error.BadQuery;
                var message = try response.buildRefusedResponse(partial);
                message.header.rcode = .notauth;
                var other: [6]u8 = undefined;
                const error_code: u16 = if (failure.code == .badtime) 18 else 22;
                if (failure.code == .badtime) {
                    writeTsigTime(self.currentTsigTime(), &other);
                    return self.encodeSignedMessage(
                        message,
                        output,
                        .{ .final = final, .key = key, .request_mac = request_mac },
                        error_code,
                        &other,
                        final.tsig.time_signed,
                    );
                }
                return self.encodeSignedMessage(
                    message,
                    output,
                    .{ .final = final, .key = key, .request_mac = request_mac },
                    error_code,
                    &.{},
                    null,
                );
            },
            .bad_query => unreachable,
        }
    }

    fn encodeSignedMessage(
        self: *const Runtime,
        response_message: dns_message.Message,
        output: []u8,
        auth: TsigAuth,
        error_code: u16,
        other_data: []const u8,
        time_signed: ?u64,
    ) ![]const u8 {
        var message = response_message;
        defer message.deinit();

        const algorithm = tsig.algorithmForName(&auth.final.tsig.algorithm) catch return Error.EncodeFailed;
        const digest_len = tsig.digestLength(algorithm);
        var value = auth.final.tsig;
        value.time_signed = time_signed orelse self.currentTsigTime();
        value.original_id = auth.final.tsig.original_id;
        value.mac_len = @intCast(digest_len);
        @memset(value.mac[0..digest_len], 0);
        value.error_code = error_code;
        value.other_len = @intCast(other_data.len);
        @memcpy(value.other_data[0..other_data.len], other_data);
        try message.additionals.append(.{
            .owner = auth.final.owner,
            .rrtype = .TSIG,
            .class = .ANY,
            .ttl = 0,
            .rdata = .{ .TSIG = value },
        });
        message.header.additional_count = @intCast(message.additionals.len);

        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        const encoded = output[0..writer.len()];
        const final = (tsig.parseFinalAdditional(encoded) catch return Error.EncodeFailed) orelse return Error.EncodeFailed;
        const signed = tsig.sign(
            encoded,
            auth.key.secretBytes(),
            final.owner,
            final.tsig,
            if (auth.request_mac.len == 0) null else auth.request_mac.slice(),
        ) catch return Error.EncodeFailed;
        tsig.patchMac(@constCast(encoded), final, signed.slice()) catch return Error.EncodeFailed;
        return encoded;
    }

    fn encodeUnsignedTsigErrorMessage(
        self: *const Runtime,
        response_message: dns_message.Message,
        output: []u8,
        request: tsig.FinalAdditional,
        error_code: u16,
    ) ![]const u8 {
        var message = response_message;
        defer message.deinit();

        var value = request.tsig;
        value.time_signed = self.currentTsigTime();
        value.original_id = request.tsig.original_id;
        value.mac_len = 0;
        value.error_code = error_code;
        value.other_len = 0;
        try message.additionals.append(.{
            .owner = request.owner,
            .rrtype = .TSIG,
            .class = .ANY,
            .ttl = 0,
            .rdata = .{ .TSIG = value },
        });
        message.header.additional_count = @intCast(message.additionals.len);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return output[0..writer.len()];
    }

    fn answerIncoming(
        self: *Runtime,
        allocator: std.mem.Allocator,
        query_bytes: []const u8,
        output: []u8,
        client: ?*const std.Io.net.IpAddress,
    ) ![]const u8 {
        const parsed = try self.parseIncoming(allocator, query_bytes);
        switch (parsed) {
            .failure => |failure| return self.encodeFailure(allocator, query_bytes, output, failure),
            .incoming => |incoming| {
                if (incoming.auth) |auth| {
                    return self.encodeSignedMessage(try self.buildMessage(incoming.query), output, auth, 0, &.{}, null);
                }
                if (client) |address| return self.answerFromUnlocked(query_bytes, output, address, incoming.query);
                return self.encodeMessage(try self.buildMessage(incoming.query), output);
            },
        }
    }

    pub fn answer(self: *const Runtime, query_bytes: []const u8, output: []u8) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        self.lock();
        defer self.unlock();
        const parsed = try self.parseIncoming(arena.allocator(), query_bytes);
        switch (parsed) {
            .failure => |failure| return self.encodeFailure(arena.allocator(), query_bytes, output, failure),
            .incoming => |incoming| {
                if (incoming.auth) |auth| {
                    return self.encodeSignedMessage(try self.buildMessage(incoming.query), output, auth, 0, &.{}, null);
                }
                if (try self.localZoneAnswer(incoming.query)) |local| return self.encodeMessage(local, output);
                return self.encodeMessage(try self.buildMessage(incoming.query), output);
            },
        }
    }

    pub fn answerFrom(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        self.lock();
        defer self.unlock();
        return self.answerIncoming(arena.allocator(), query_bytes, output, client);
    }

    pub fn truncateUdpResponse(self: *Runtime, query_bytes: []const u8, response_bytes: []const u8, output: []u8) ![]const u8 {
        const response_final = (tsig.parseFinalAdditional(response_bytes) catch null) orelse {
            return response.truncateClassicUdpResponse(response_bytes, output) catch return Error.EncodeFailed;
        };
        if (response_final.tsig.macBytes().len == 0) {
            return response.truncateSignedClassicUdpResponse(response_bytes, output) catch return Error.EncodeFailed;
        }

        self.lock();
        defer self.unlock();
        const request_final = (tsig.parseFinalAdditional(query_bytes) catch return Error.EncodeFailed) orelse return Error.EncodeFailed;
        const key = self.keyring.find(request_final.owner) orelse return Error.EncodeFailed;
        const truncated = response.truncateSignedClassicUdpResponse(response_bytes, output) catch return Error.EncodeFailed;
        const final = (tsig.parseFinalAdditional(truncated) catch return Error.EncodeFailed) orelse return Error.EncodeFailed;
        const signed = tsig.sign(
            truncated,
            key.secretBytes(),
            final.owner,
            final.tsig,
            if (request_final.tsig.macBytes().len == 0) null else request_final.tsig.macBytes(),
        ) catch return Error.EncodeFailed;
        tsig.patchMac(@constCast(truncated), final, signed.slice()) catch return Error.EncodeFailed;
        return truncated;
    }

    /// Serves one AXFR/IXFR query as an owned length-prefixed TCP blob, one
    /// two-octet frame per message. Unsigned and TSIG-signed requests share
    /// this path; signed sequences chain one TSIG per message through the
    /// chainedMac primitive starting from the request MAC. Non-transfer
    /// queries and failures yield a single frame so the client always gets an
    /// answer. The caller owns the returned blob.
    pub fn encodeTransferFrames(
        self: *const Runtime,
        allocator: std.mem.Allocator,
        request_bytes: []const u8,
    ) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        self.lock();
        defer self.unlock();
        const parsed = try self.parseIncoming(arena.allocator(), request_bytes);
        switch (parsed) {
            .failure => |failure| {
                var output: [transfer.tcp_max_frame_size]u8 = undefined;
                const single = try self.encodeFailure(arena.allocator(), request_bytes, &output, failure);
                return frameSingle(allocator, single);
            },
            .incoming => |incoming| {
                const q = incoming.query.question orelse return Error.BadQuery;
                if (transfer.classify(q.qtype, q.qclass) == .none) {
                    var output: [transfer.tcp_max_frame_size]u8 = undefined;
                    const single = if (incoming.auth) |auth|
                        try self.encodeSignedMessage(
                            try self.buildMessage(incoming.query),
                            &output,
                            auth,
                            0,
                            &.{},
                            null,
                        )
                    else
                        try self.encodeMessage(try self.buildMessage(incoming.query), &output);
                    return frameSingle(allocator, single);
                }
                var qname_text_buffer: [256]u8 = undefined;
                const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQuery;
                const zone = self.selectZone(qname_text) orelse {
                    var output: [transfer.tcp_max_frame_size]u8 = undefined;
                    const single = try self.encodeMessage(
                        try response.buildRefusedResponse(incoming.query),
                        &output,
                    );
                    return frameSingle(allocator, single);
                };
                return self.encodeZoneTransfer(allocator, arena.allocator(), &incoming, zone);
            },
        }
    }

    fn frameSingle(allocator: std.mem.Allocator, single: []const u8) ![]u8 {
        if (single.len == 0 or single.len > transfer.tcp_max_frame_size) return Error.EncodeFailed;
        var blob: std.ArrayList(u8) = .empty;
        errdefer blob.deinit(allocator);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(single.len), .big);
        blob.appendSlice(allocator, &prefix) catch return Error.EncodeFailed;
        blob.appendSlice(allocator, single) catch return Error.EncodeFailed;
        return blob.toOwnedSlice(allocator) catch return Error.EncodeFailed;
    }

    fn encodeZoneTransfer(
        self: *const Runtime,
        allocator: std.mem.Allocator,
        scratch: std.mem.Allocator,
        incoming: *const Incoming,
        zone: *const zone_index.Zone,
    ) ![]u8 {
        const query = incoming.query;
        const q = query.question orelse return Error.BadQuery;
        const kind = transfer.classify(q.qtype, q.qclass);
        const serial = zone.soaSerial() orelse return Error.EncodeFailed;

        var single_slot: ?dns_message.Message = null;
        defer if (single_slot) |*message| message.deinit();
        var one: [1]dns_message.Message = undefined;
        var messages: []dns_message.Message = &.{};
        var sequence: []dns_message.Message = &.{};
        defer if (sequence.len != 0) scratch.free(sequence);
        switch (kind) {
            .axfr => {
                sequence = transfer.buildAxfrMessages(
                    scratch,
                    &query,
                    zone,
                    transfer.default_records_per_message,
                ) catch return Error.EncodeFailed;
                messages = sequence;
            },
            .ixfr => {
                const client = transfer.clientSerialFromMessage(&query);
                switch (transfer.decideIxfr(serial, client, self.deltaLogForOriginConst(zone.originText()))) {
                    .up_to_date => {
                        single_slot = transfer.buildIxfrUpToDateMessage(scratch, &query, zone) catch
                            return Error.EncodeFailed;
                        one[0] = single_slot.?;
                        messages = one[0..];
                    },
                    .incremental => {
                        const client_serial = client orelse return Error.EncodeFailed;
                        single_slot = transfer.buildIxfrIncrementalMessages(
                            scratch,
                            &query,
                            zone,
                            client_serial,
                        ) catch return Error.EncodeFailed;
                        one[0] = single_slot.?;
                        messages = one[0..];
                    },
                    .fallback_axfr => {
                        sequence = transfer.buildAxfrMessages(
                            scratch,
                            &query,
                            zone,
                            transfer.default_records_per_message,
                        ) catch return Error.EncodeFailed;
                        messages = sequence;
                    },
                }
            },
            .none => return Error.BadQuery,
        }
        defer for (sequence) |*message| message.deinit();

        var prior_mac: ?tsig.Mac = if (incoming.auth) |auth| auth.request_mac else null;
        const now = self.currentTsigTime();
        var blob: std.ArrayList(u8) = .empty;
        errdefer blob.deinit(allocator);
        var frame: [transfer.tcp_max_frame_size]u8 = undefined;
        for (messages) |*message| {
            if (incoming.auth) |auth| {
                transfer.appendTsigStub(
                    message,
                    auth.final.owner,
                    auth.key.algorithm,
                    query.header.id,
                    now,
                ) catch return Error.EncodeFailed;
            }
            var writer = dns_writer.Writer.init(&frame);
            message.encode(&writer) catch return Error.EncodeFailed;
            if (writer.len() == 0 or writer.len() > transfer.tcp_max_frame_size) return Error.EncodeFailed;
            if (prior_mac != null) {
                const auth = incoming.auth.?;
                const signed = transfer.signTransferMessage(
                    frame[0..writer.len()],
                    auth.key.algorithm,
                    auth.key.secretBytes(),
                    prior_mac.?.slice(),
                ) catch return Error.EncodeFailed;
                var next = tsig.Mac{ .len = @intCast(signed.slice().len) };
                @memcpy(next.bytes[0..signed.slice().len], signed.slice());
                prior_mac = next;
            }
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(writer.len()), .big);
            blob.appendSlice(allocator, &prefix) catch return Error.EncodeFailed;
            blob.appendSlice(allocator, frame[0..writer.len()]) catch return Error.EncodeFailed;
        }
        return blob.toOwnedSlice(allocator) catch return Error.EncodeFailed;
    }

    fn answerFromUnlocked(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress, query: dns_message.Message) ![]const u8 {
        const q = query.question orelse return Error.BadQuery;
        if (query.header.opcode != .query) {
            return self.encodeMessage(try response.buildNotImplementedResponse(query), output);
        }
        if (query.edns) |edns| if (edns.version != dns_message.EDNS_VERSION) {
            return self.encodeMessage(try response.buildBadVersionResponse(query, q), output);
        };
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQuery;

        if (self.selectZone(qname_text) != null) {
            if (self.resolver) |*resolver| {
                const server_cookie = resolver.validateCookie(query, client) catch |err| switch (err) {
                    resolver_mod.Error.BadCookie => return self.encodeMessage(try resolver.badCookieResponse(query, client), output),
                    else => return err,
                };
                var message = try self.buildMessage(query);
                errdefer message.deinit();
                if (server_cookie) |cookie| try resolver_mod.appendCookie(&message, cookie);
                return self.encodeMessage(message, output);
            }
            return self.encodeMessage(try self.buildMessage(query), output);
        }
        if (try self.localZoneAnswer(query)) |local| return self.encodeMessage(local, output);
        if (self.blocklist.blocks(qname_text)) return self.encodeMessage(try response.buildRefusedResponse(query), output);
        if (!q.qclass.eql(@import("../dns/types.zig").Class.IN) or !query.header.recursion_desired) {
            return self.encodeMessage(try response.buildRefusedResponse(query), output);
        }
        if (self.resolver) |*resolver| {
            if (!resolver.policy.allows(client)) return self.encodeMessage(try response.buildRefusedResponse(query), output);
            return resolver.answer(query_bytes, query, client, output) catch |err| switch (err) {
                resolver_mod.Error.UpstreamFailure,
                resolver_mod.Error.BadUpstreamResponse,
                => self.encodeMessage(try resolver_mod.buildNetworkErrorResponse(query), output),
                resolver_mod.Error.NoForwarder => self.encodeMessage(try response.buildRefusedResponse(query), output),
                resolver_mod.Error.EcsRefused => self.encodeMessage(try response.buildRefusedResponse(query), output),
                resolver_mod.Error.ResponseTooLarge => return Error.EncodeFailed,
                else => return err,
            };
        }
        return self.encodeMessage(try response.buildRefusedResponse(query), output);
    }

    /// Answers the locally served zones of RFC 6303, RFC 7793, RFC 6761, and
    /// RFC 8375 from one static table. Consulted before the blocklist, the
    /// cache, and the forwarding policy, so these names never reach an
    /// upstream. An operator's own primary zone wins, which is the RFC 6303
    /// section 2 "configured otherwise" case. Returns null when the question
    /// is outside every locally served zone.
    fn localZoneAnswer(self: *const Runtime, query: dns_message.Message) !?dns_message.Message {
        if (!self.local_zones) return null;
        const q = query.question orelse return null;
        // AXFR/IXFR has no zone file to transfer from a synthesized zone and is
        // refused exactly as the authoritative path refuses a transfer.
        if (transfer.classify(q.qtype, q.qclass) != .none) return null;
        var qname_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_buffer) catch return null;
        // This profile answers class IN only; every other class keeps the
        // existing out-of-zone behaviour, which is NOTIMP for TCP ingress.
        if (!q.qclass.eql(@import("../dns/types.zig").Class.IN)) return null;
        if (self.selectZone(qname_text) != null) return null;
        const zone = local_zone.match(qname_text) orelse return null;
        // Per-zone override: an excluded apex falls through to the cache,
        // forwarder, or REFUSED exactly as a non-local name would.
        for (self.local_zones_except) |apex| {
            if (std.ascii.eqlIgnoreCase(zone.apex, apex)) return null;
        }
        const dnssec_ok = if (query.edns) |edns| edns.dnssec_ok else false;
        if (local_zone.forwardsUpstream(zone, q.qtype, dnssec_ok)) return null;
        return try local_zone.build(query, zone);
    }

    pub fn answerFromWithMetrics(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress, counters: *metrics.Counters) ![]const u8 {
        counters.queries_total += 1;
        self.lock();
        defer self.unlock();
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const result = self.answerIncoming(arena.allocator(), query_bytes, output, client) catch |err| {
            if (err == Error.BadQuery) counters.bad_queries_total += 1;
            if (err == Error.EncodeFailed) counters.encode_failures_total += 1;
            return err;
        };
        counters.responses_total += 1;
        return result;
    }

    pub fn answerWithMetrics(self: *const Runtime, query_bytes: []const u8, output: []u8, counters: *metrics.Counters) ![]const u8 {
        counters.queries_total += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        self.lock();
        defer self.unlock();
        const parsed = self.parseIncoming(arena.allocator(), query_bytes) catch |err| {
            counters.bad_queries_total += 1;
            return err;
        };
        const result = switch (parsed) {
            .failure => |failure| self.encodeFailure(arena.allocator(), query_bytes, output, failure),
            .incoming => |incoming| if (incoming.auth) |auth|
                self.encodeSignedMessage(try self.buildMessage(incoming.query), output, auth, 0, &.{}, null)
            else
                self.encodeMessage(try self.buildMessage(incoming.query), output),
        } catch |err| {
            if (err == Error.BadQuery) counters.bad_queries_total += 1;
            if (err == Error.EncodeFailed) counters.encode_failures_total += 1;
            return err;
        };
        counters.responses_total += 1;
        return result;
    }

    fn encodeMessage(self: *const Runtime, response_message: dns_message.Message, output: []u8) ![]const u8 {
        _ = self;
        var message = response_message;
        defer message.deinit();
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return writer.written();
    }

    fn buildMessage(self: *const Runtime, query: dns_message.Message) !dns_message.Message {
        // RFC 2136 section 3 answers an unimplemented UPDATE with NOTIMP,
        // and section 3.4.1.3 lets it carry no zone section, so the
        // refusal is built before a question is required.
        if (query.header.opcode != .query and query.header.opcode != .notify) {
            return response.buildNotImplementedResponse(query);
        }
        const q = query.question orelse return response.Error.MissingQuestion;
        if (query.header.opcode == .notify) {
            if (!transfer.isNotifyMessage(&query)) return response.buildFormerrResponse(query);
            var notify_name_buffer: [256]u8 = undefined;
            const notify_name = q.name.toText(&notify_name_buffer) catch return response.Error.BadQName;
            if (self.blocklist.blocks(notify_name)) return response.buildRefusedResponse(query);
            const zone = self.selectZone(notify_name) orelse return response.buildRefusedResponse(query);
            _ = zone;
            return transfer.buildNotifyResponse(query.allocator, &query) catch return Error.EncodeFailed;
        }
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return response.Error.BadQName;
        if (self.blocklist.blocks(qname_text)) return response.buildRefusedResponse(query);
        // Zone transfers are served only as multi-frame TCP sequences through
        // encodeTransferFrames. The single-message path refuses them so a
        // partial zone can never leak through one datagram or frame.
        if (transfer.classify(q.qtype, q.qclass) != .none) return response.buildRefusedResponse(query);
        const selected = self.selectZone(qname_text) orelse return response.buildRefusedResponse(query);
        return response.buildResponseWithEdns(query, selected, self.edns);
    }

    fn appendZoneText(self: *Runtime, text: []const u8) !void {
        var zone_file = try zone_parser.ZoneFile.parse(text);
        errdefer zone_file.deinit();
        var zone = try zone_index.Zone.fromZoneFile(&zone_file);
        errdefer zone.deinit();
        try self.zones.append(self.allocator, zone);
        // Best-effort: a length mismatch means no usable history, which
        // decideIxfr already treats as "fall back to AXFR".
        self.transfer_delta_logs.append(self.allocator, .{}) catch {};
    }

    fn selectZone(self: *const Runtime, qname: []const u8) ?*const zone_index.Zone {
        var selected: ?*const zone_index.Zone = null;
        for (self.zones.items) |*zone| {
            if (!zone.contains(qname)) continue;
            if (selected == null or zone.originText().len > selected.?.originText().len) selected = zone;
        }
        return selected;
    }
};

test "authoritative runtime answers raw query bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &parsed.answers.items[0].rdata.A);
}

test "authoritative runtime preserves bad-query errors for truncated unsigned sections" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const truncated = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    };
    try std.testing.expectError(Error.BadQuery, runtime.answer(&truncated, &output));
}

test "runtime authenticates a signed query and signs the authoritative response" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var query = try makeSignedQueryWithEdns(now, 32);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(parsed.edns != null);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 32), response_final.tsig.macBytes().len);
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes(), 32);
}

test "runtime accepts a signed query whose Original ID differs from the packet ID" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var query = try makeSignedQuery(now, 32);
    std.mem.writeInt(u16, query.packet[0..2], 0x5678, .big);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 0x5678), parsed.header.id);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 0x1234), response_final.tsig.original_id);
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes(), 32);
}

test "runtime maps TSIG key and MAC failures before query dispatch" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var unknown = try makeSignedQuery(now, 32);
    std.mem.writeInt(u16, unknown.packet[0..2], 0x5678, .big);
    unknown.packet[unknown.owner_start + 1] = 'b';
    unknown.packet[unknown.owner_start + 2] = 'a';
    unknown.packet[unknown.owner_start + 3] = 'd';
    var output: [1024]u8 = undefined;
    var response_bytes = try runtime.answer(unknown.packet[0..unknown.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(u16, 17), parsed.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.additionals.items[0].rdata.TSIG.original_id);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.TSIG.macBytes().len);

    var bad_mac = try makeSignedQuery(now, 32);
    std.mem.writeInt(u16, bad_mac.packet[0..2], 0x5678, .big);
    bad_mac.packet[bad_mac.question_start + 1] ^= 1;
    response_bytes = try runtime.answer(bad_mac.packet[0..bad_mac.len], &output);
    parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(u16, 16), parsed.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.additionals.items[0].rdata.TSIG.original_id);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.TSIG.macBytes().len);
}

test "runtime signs BADTIME and BADTRUNC responses" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();

    var query = try makeSignedQuery(request_time, 32);
    runtime.setTsigNow(request_time + 1000);
    var output: [1024]u8 = undefined;
    var response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 18), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 6), response_final.tsig.otherData().len);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    try std.testing.expectEqual(request_final.tsig.time_signed, response_final.tsig.time_signed);
    try std.testing.expectEqual(request_final.tsig.fudge, response_final.tsig.fudge);
    var expected_server_time: [6]u8 = undefined;
    expected_server_time[0] = @intCast(((request_time + 1000) >> 40) & 0xff);
    expected_server_time[1] = @intCast(((request_time + 1000) >> 32) & 0xff);
    expected_server_time[2] = @intCast(((request_time + 1000) >> 24) & 0xff);
    expected_server_time[3] = @intCast(((request_time + 1000) >> 16) & 0xff);
    expected_server_time[4] = @intCast(((request_time + 1000) >> 8) & 0xff);
    expected_server_time[5] = @intCast((request_time + 1000) & 0xff);
    try std.testing.expectEqualSlices(u8, &expected_server_time, response_final.tsig.otherData());
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes(), 32);

    query = try makeSignedQuery(request_time, 16);
    runtime.setTsigNow(request_time);
    response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 22), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 32), response_final.tsig.macBytes().len);
    const badtrunc_request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", badtrunc_request_final.tsig.macBytes(), 32);
}

test "runtime rejects oversize MAC without overflowing copyMac" {
    var oversize = @as([33]u8, @splat(@as(u8, 0xab)));
    try std.testing.expect(Runtime.copyMac(&oversize) == null);

    var exact = @as([32]u8, @splat(@as(u8, 0xcd)));
    const mac = Runtime.copyMac(&exact).?;
    try std.testing.expectEqual(@as(u8, 32), mac.len);
    try std.testing.expectEqualSlices(u8, &exact, mac.slice());
}

test "runtime returns FORMERR for non-final TSIG placement" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var query = try makeSignedQuery(now, 32);
    std.mem.writeInt(u16, query.packet[10..12], 2, .big);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
}

const SignedQuery = struct {
    packet: [512]u8,
    len: usize,
    question_start: usize,
    owner_start: usize,
};

fn makeSignedQuery(time_signed: u64, mac_len: usize) !SignedQuery {
    return makeSignedQueryWithEdnsOption(time_signed, mac_len, false);
}

fn makeSignedQueryWithEdns(time_signed: u64, mac_len: usize) !SignedQuery {
    return makeSignedQueryWithEdnsOption(time_signed, mac_len, true);
}

fn makeSignedQueryWithEdnsOption(time_signed: u64, mac_len: usize, include_edns: bool) !SignedQuery {
    const algorithm = try @import("../dns/name.zig").Name.fromText("hmac-sha256.");
    const owner = try @import("../dns/name.zig").Name.fromText("key.");
    const root = @import("../dns/name.zig").Name.root();
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    const additional_count: u16 = if (include_edns) 2 else 1;
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    });
    try writer.writeU16(additional_count);
    const question_start = writer.len();
    try writer.writeBytes(&.{ 3, 'd', 'n', 's', 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    if (include_edns) {
        try (@import("../dns/record.zig").ResourceRecord{
            .owner = root,
            .rrtype = .OPT,
            .class = @import("../dns/types.zig").Class.fromCode(1232),
            .ttl = 0,
            .rdata = .{ .OPT = .{} },
        }).encode(&writer);
    }
    const owner_start = writer.len();
    var zeros: [32]u8 = @splat(0);
    const value = try @import("../dns/rdata.zig").Tsig.init(algorithm, time_signed, 300, zeros[0..mac_len], 0x1234, 0, &.{});
    try (@import("../dns/record.zig").ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const signed = try tsig.sign(writer.written(), "01234567890123456789012345678901", final.owner, final.tsig, null);
    try tsig.patchMac(packet[0..writer.len()], final, signed.slice()[0..mac_len]);
    return .{ .packet = packet, .len = writer.len(), .question_start = question_start, .owner_start = owner_start };
}

test "runtime returns bare FORMERR for malformed ECS with a valid question" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    const malformed_ecs_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x01,
        192,  0,    2,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53003);
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&malformed_ecs_query, &output, &client);

    var arena_ecs = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_ecs.deinit();
    const parsed_ecs = try dns_message.Message.parse(arena_ecs.allocator(), response_bytes);
    try std.testing.expect(parsed_ecs.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed_ecs.header.rcode), .formerr), parsed_ecs.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed_ecs.header.question_count);
    try std.testing.expectEqual(@as(u16, 0), parsed_ecs.header.additional_count);
    try std.testing.expect(parsed_ecs.edns == null);
}


test "RFC 6891: a query carrying two OPT records is answered FORMERR" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    defer runtime.deinit();

    const multiple_opts_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53113);
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&multiple_opts_query, &output, &client);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.question_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expect(parsed.edns == null);
}

test "RFC 9619: an OPCODE 0 query with QDCOUNT 2 is answered FORMERR" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    // Section 4: "A DNS message with OPCODE = 0 and QDCOUNT > 1 MUST be
    // treated as an incorrectly formatted message. The value of the RCODE
    // parameter in the response message MUST be set to 1 (FORMERR)."
    const two_question_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 5,    'a',  'l',  'i',  'a',
        's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,
        0x00, 0x01, 0x00, 0x01,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53004);
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&two_question_query, &output, &client);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.question_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("dns.home.arpa.", try parsed.question.?.name.toText(&text));
}
test "RFC 9619: a non-query OPCODE with QDCOUNT 2 is answered FORMERR" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    // OPCODE 15 (unassigned) with QDCOUNT 2: Message.parse reports
    // TooManyQuestions for any OPCODE, so the answer is FORMERR rather
    // than a silent drop.
    const two_question_query = [_]u8{
        0x12, 0x34, 0x79, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 5,    'a',  'l',  'i',  'a',
        's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,
        0x00, 0x01, 0x00, 0x01,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53005);
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&two_question_query, &output, &client);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
}

test "RFC 9619: an OPCODE 0 query with QDCOUNT 0 is never answered FORMERR" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    // Section 4: "Such firewalls MUST NOT treat messages with OPCODE = 0 and
    // QDCOUNT = 0 as malformed." The profile serves no RFC 7873 cookie
    // request, so it declines the query without an RCODE rather than
    // answering FORMERR.
    const zero_question_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53005);
    var output: [512]u8 = undefined;
    try std.testing.expectError(Error.BadQuery, runtime.answerFrom(&zero_question_query, &output, &client));
}

test "authoritative runtime records metrics for successful and bad queries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var counters = @import("../metrics.zig").Counters{};
    var output: [512]u8 = undefined;
    _ = try runtime.answerWithMetrics(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &counters);
    try std.testing.expectError(Error.BadQuery, runtime.answerWithMetrics(&.{ 0x12, 0x34 }, &output, &counters));

    try std.testing.expectEqual(@as(u64, 2), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 1), counters.bad_queries_total);
    try std.testing.expectEqual(@as(u64, 0), counters.encode_failures_total);
}

test "authoritative runtime refuses exact blocklisted names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const blocklist = try @import("../blocklist.zig").Blocklist.parse("ads.home.arpa.\n");
    var runtime = try Runtime.fromZoneTextWithBlocklist(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\ads IN A 192.168.1.99
        \\
    , blocklist);
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
}

test "authoritative runtime returns NOTIMP for non-IN queries outside a zone" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  4,    't',  'e',  's',
        't',  0,    0x00, 0x01, 0x00, 0x03,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.notimp, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 3), parsed.question.?.qclass.code());
}

test "authoritative runtime drops response packets instead of answering them" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    try std.testing.expectError(Error.BadQuery, runtime.answerFrom(&.{
        0x12, 0x34, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &try std.Io.net.IpAddress.parse("127.0.0.1", 53000)));
}

test "authoritative runtime answers unassigned opcodes with local NOTIMP" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x19, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &try std.Io.net.IpAddress.parse("127.0.0.1", 53001));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.opcode), .unassigned_3), parsed.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notimp), parsed.header.rcode);
}

test "authoritative runtime answers RFC 2136 UPDATE with NOTIMP" {
    const dns_name = @import("../dns/name.zig");
    const dns_record = @import("../dns/record.zig");
    const dns_types = @import("../dns/types.zig");

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    const soa_record: dns_record.ResourceRecord = .{
        .owner = try dns_name.Name.fromText("home.arpa."),
        .rrtype = dns_types.RecordType.SOA,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns1.home.arpa."),
            .rname = try dns_name.Name.fromText("hostmaster.home.arpa."),
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
    var request_bytes: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // nsupdate shape: ZOCOUNT 1 carrying the zone SOA, UPCOUNT 1 carrying
    // the record being added, and no additional section.
    var update = dns_message.Message{
        .header = .{
            .id = 0x1234,
            .opcode = .update,
            .question_count = 1,
            .answer_count = 1,
            .authority_count = 1,
        },
        .question = .{
            .name = try dns_name.Name.fromText("home.arpa."),
            .qtype = dns_types.RecordType.SOA,
            .qclass = dns_types.Class.IN,
        },
    };
    defer update.deinit();
    try update.answers.append(soa_record);
    try update.authorities.append(.{
        .owner = try dns_name.Name.fromText("dns.home.arpa."),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 3600,
        .rdata = .{ .A = .{ 192, 168, 1, 99 } },
    });
    var update_writer = dns_writer.Writer.init(&request_bytes);
    try update.encode(&update_writer);

    const wire = try dns_message.Message.parse(arena.allocator(), update_writer.written());
    try std.testing.expectEqual(@as(@TypeOf(wire.header.opcode), .update), wire.header.opcode);
    try std.testing.expectEqual(@as(u16, 1), wire.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), wire.header.authority_count);

    const response_bytes = try runtime.answer(update_writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.opcode), .update), parsed.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notimp), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.question_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);

    // RFC 2136 section 3.4.1.3: the zone section may be empty when the zone
    // comes from a prerequisite SOA, leaving QDCOUNT 0 and no question.
    var zoneless = dns_message.Message{
        .header = .{ .id = 0x4321, .opcode = .update, .authority_count = 1 },
    };
    defer zoneless.deinit();
    try zoneless.authorities.append(soa_record);
    var zoneless_writer = dns_writer.Writer.init(&request_bytes);
    try zoneless.encode(&zoneless_writer);

    const zoneless_response = try runtime.answer(zoneless_writer.written(), &output);
    const zoneless_parsed = try dns_message.Message.parse(arena.allocator(), zoneless_response);
    try std.testing.expect(zoneless_parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(zoneless_parsed.header.opcode), .update), zoneless_parsed.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(zoneless_parsed.header.rcode), .notimp), zoneless_parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), zoneless_parsed.header.question_count);
}

test "authoritative runtime applies configured Cookie validation" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer zone_file.deinit();
    const zone = try zone_index.Zone.fromZoneFile(&zone_file);
    var zones = std.ArrayList(zone_index.Zone).empty;
    try zones.append(std.testing.allocator, zone);
    const cookie_policy = resolver_mod.CookiePolicy.init("current-secret", null);
    var runtime = try Runtime.fromZonesWithPolicy(
        std.testing.allocator,
        &zones,
        .{},
        io,
        .{ .cookies = cookie_policy },
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53002);
    const invalid_cookie_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0,    0,    0,    0x00, 0x00, 0x0d, 0,    0x0a, 0,    9,    1,    2,
        3,    4,    5,    6,    7,    8,    9,
    };
    const response_bytes = try runtime.answerFrom(&invalid_cookie_query, &output, &client);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .badcookie), parsed.header.rcode);
    try std.testing.expectEqual(@as(u8, 1), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(usize, 24), findCookieOption(parsed).?.len);

    const client_cookie = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var server_cookie: [24]u8 = undefined;
    cookie_policy.makeServerCookie(&client, &client_cookie, &server_cookie);
    var valid_cookie_query: [70]u8 = undefined;
    @memcpy(valid_cookie_query[0..46], invalid_cookie_query[0..46]);
    std.mem.writeInt(u16, valid_cookie_query[40..42], 28, .big);
    std.mem.writeInt(u16, valid_cookie_query[44..46], 24, .big);
    @memcpy(valid_cookie_query[46..], &server_cookie);
    const valid_response_bytes = try runtime.answerFrom(&valid_cookie_query, &output, &client);
    const valid_response = try dns_message.Message.parse(arena.allocator(), valid_response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(valid_response.header.rcode), .no_error), valid_response.header.rcode);
    try std.testing.expectEqualSlices(u8, &server_cookie, findCookieOption(valid_response).?);
}

fn findCookieOption(message: dns_message.Message) ?[]const u8 {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        const bytes = record.rdata.OPT.bytes();
        if (bytes.len < 4) continue;
        if (std.mem.readInt(u16, bytes[0..2], .big) != resolver_mod.COOKIE_OPTION_CODE) continue;
        const length = std.mem.readInt(u16, bytes[2..4], .big);
        if (length > bytes.len - 4) return null;
        return bytes[4 .. 4 + length];
    }
    return null;
}

test "authoritative runtime dispatches to the longest matching zone" {
    var runtime = try Runtime.fromZoneTexts(&.{
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
        ,
        \\$ORIGIN sub.example.
        \\$TTL 3600
        \\@ IN SOA ns.sub.example. hostmaster.sub.example. 1 3600 900 1209600 300
        \\@ IN NS ns.sub.example.
        \\www IN A 192.0.2.2
        \\
        ,
    });
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  3,    's',  'u',  'b',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &parsed.answers.items[0].rdata.A);
}

test "authoritative runtime selects longest mixed-case ancestor origin" {
    var runtime = try Runtime.fromZoneTexts(&.{
        \\$ORIGIN Example.
        \\$TTL 3600
        \\@ IN SOA ns.Example. hostmaster.Example. 1 3600 900 1209600 300
        \\@ IN NS ns.Example.
        \\www IN A 192.0.2.1
        \\
        ,
        \\$ORIGIN Sub.Example.
        \\$TTL 3600
        \\@ IN SOA ns.Sub.Example. hostmaster.Sub.Example. 1 3600 900 1209600 300
        \\@ IN NS ns.Sub.Example.
        \\www IN A 192.0.2.2
        \\
        ,
    });
    defer runtime.deinit();

    const selected = runtime.selectZone("WWW.SUB.EXAMPLE.") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("Sub.Example.", selected.originText());
    try std.testing.expect(runtime.selectZone("www.notexample.") == null);
}

const transfer_test_axfr_query = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0xfc, 0x00,
    0x01,
};

test "runtime answers NOTIFY with a mirrored response and refuses transfers singly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
    );
    defer runtime.deinit();

    var output: [512]u8 = undefined;
    const notify_query = [_]u8{
        0x43, 0x21, 0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0x06, 0x00,
        0x01,
    };
    const notify_bytes = try runtime.answer(&notify_query, &output);
    const notify_response = try dns_message.Message.parse(arena.allocator(), notify_bytes);
    try std.testing.expect(notify_response.header.qr);
    try std.testing.expect(notify_response.header.opcode == .notify);
    try std.testing.expectEqual(@as(u16, 0x4321), notify_response.header.id);

    const axfr_bytes = try runtime.answer(&transfer_test_axfr_query, &output);
    const axfr_response = try dns_message.Message.parse(arena.allocator(), axfr_bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), axfr_response.header.id);
    try std.testing.expectEqual(@as(@TypeOf(axfr_response.header.rcode), .refused), axfr_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), axfr_response.header.answer_count);
}

test "runtime serves AXFR as one bounded TCP blob opening and closing with SOA" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
    );
    defer runtime.deinit();

    const blob = try runtime.encodeTransferFrames(std.testing.allocator, &transfer_test_axfr_query);
    defer std.testing.allocator.free(blob);
    try std.testing.expect(blob.len > 2);

    var offset: usize = 0;
    var frames: usize = 0;
    while (offset < blob.len) {
        const frame_len = std.mem.readInt(u16, blob[offset..][0..2], .big);
        try std.testing.expect(frame_len > 0);
        const parsed = try dns_message.Message.parse(arena.allocator(), blob[offset + 2 ..][0..frame_len]);
        try std.testing.expect(parsed.header.qr);
        try std.testing.expect(parsed.header.authoritative);
        try std.testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
        try std.testing.expect(parsed.answers.len > 0);
        offset += 2 + frame_len;
        frames += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), frames);

    const only_len = std.mem.readInt(u16, blob[0..2], .big);
    const only = try dns_message.Message.parse(arena.allocator(), blob[2..][0..only_len]);
    try std.testing.expect(only.answers.items[0].rrtype.eql(.SOA));
    try std.testing.expect(only.answers.items[only.answers.len - 1].rrtype.eql(.SOA));
    try std.testing.expectEqual(@as(u32, 10), only.answers.items[0].rdata.SOA.serial);
    try std.testing.expectEqual(@as(u32, 10), only.answers.items[only.answers.len - 1].rdata.SOA.serial);
}
