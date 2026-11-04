/// Contract: Answers authoritative zones first and optionally forwards authorized queries.
/// The forwarding dispatch takes the client address, so one query is answered the same
/// way over UDP and over TCP.
/// Ownership: Runtime owns its Zone and inline Blocklist; call Runtime.deinit; query and output buffers are borrowed.
/// Errors: Query and response failures are typed; transport I/O is handled by platform listeners.
const std = @import("std");
const builtin = @import("builtin");
const dns_dnssec = @import("../dns/dnssec.zig");
const dns_header = @import("../dns/header.zig");
const dns_message = @import("../dns/message.zig");
const dns_name_mod = @import("../dns/name.zig");
const dns_record_mod = @import("../dns/record.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_types = @import("../dns/types.zig");
const dns_validate = @import("../dns/validate.zig");
const dns_writer = @import("../dns/writer.zig");
const response = @import("response.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_signer = @import("../zone/signer.zig");
const metrics = @import("../metrics.zig");
const blocklist_mod = @import("../blocklist.zig");
const resolver_mod = @import("../resolver.zig");
const local_zone = @import("../local_zone.zig");
const keyring_mod = @import("keyring.zig");
const tsig = @import("../dns/tsig.zig");
const transfer = @import("../zone/transfer.zig");
const journal_mod = @import("../zone/journal.zig");
const zone_update = @import("../zone/update.zig");
const catalog_mod = @import("../zone/catalog.zig");
const zonemd = @import("../zone/zonemd.zig");
const xfr_client = @import("../zone/xfr_client.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");

/// Scratch memory for one answer. Nothing parsed or built for a response
/// outlives the encoded bytes, so one arena per thread is reset and reused
/// instead of mapping and unmapping pages per query. The answer entry points
/// are not reentrant: none of them calls another.
threadlocal var answer_scratch_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

fn answerScratch() std.mem.Allocator {
    _ = answer_scratch_arena.reset(.retain_capacity);
    return answer_scratch_arena.allocator();
}

/// Frees the calling thread's retained scratch buffers. A thread that answers
/// one frame and exits has no reuse to gain from them, and thread-local
/// storage has no destructor, so that thread would leak them; every such
/// thread calls this before it exits. A long-lived thread never calls it.
pub fn releaseAnswerScratch() void {
    answer_scratch_arena.deinit();
    answer_scratch_arena = .init(std.heap.page_allocator);
}

/// RFC 9462 section 5: the known name is exactly `_dns.<target>`, and case
/// folding is the only difference RFC 1035 section 2.3.3 allows. Comparing the
/// whole wire name keeps the match at label boundaries, so `_dns.xfoo.example.`
/// is not the known name of `foo.example.`.
fn isKnownResolverName(name: *const dns_name_mod.Name, target: *const dns_name_mod.Name) bool {
    const wire = name.asWire();
    const target_wire = target.asWire();
    if (wire.len != target_wire.len + 5) return false;
    if (wire[0] != 4) return false;
    if (!std.ascii.eqlIgnoreCase(wire[1..5], "_dns")) return false;
    return std.ascii.eqlIgnoreCase(wire[5..], target_wire);
}

test "releaseAnswerScratch frees the retained buffers" {
    const scratch = answerScratch();
    _ = try scratch.alloc(u8, 4096);
    try std.testing.expect(answer_scratch_arena.queryCapacity() >= 4096);
    releaseAnswerScratch();
    try std.testing.expectEqual(@as(usize, 0), answer_scratch_arena.queryCapacity());
}

pub const Error = error{
    BadQuery,
    EncodeFailed,
};

/// The zone file an operator can replace, and the apex that file must
/// provide. The directory and the path are borrowed; the runtime copies the
/// path and the apex.
pub const ReloadSource = struct {
    dir: std.Io.Dir,
    path: []const u8,
    origin: []const u8,
};

/// RFC 9432 section 5 consumer state: the catalog apex, the primary it is
/// fetched from, and the members most recently provisioned.
pub const CatalogConsumer = struct {
    apex: []const u8,
    primary: std.Io.net.IpAddress,
    members: std.ArrayList(CatalogMember) = .empty,
    group_selector: ?[]const u8 = null,
};

/// One provisioned member: the `<unique>` label of the catalog node and the
/// zone it names. A changed label is a removal and a fresh add (RFC 9432
/// section 5.4), so both travel together.
pub const CatalogMember = struct {
    label: []const u8,
    name: []const u8,
    properties: []const catalog_mod.Property = &.{},
};

/// What one catalog refresh did.
pub const CatalogRefreshOutcome = enum { unchanged, updated, failed };

/// The smallest interval between two catalog refresh attempts.
pub const catalog_refresh_window_ns: i64 = 1 * std.time.ns_per_s;

/// One RFC 1996 NOTIFY destination: the zone apex whose change is announced
/// and the address the announcement goes to.
pub const NotifyTarget = struct {
    apex: []const u8,
    address: std.Io.net.IpAddress,
};

/// One RFC 2136 update policy: the zone apex an operator allowed updates for,
/// the one TSIG key allowed to write it, and the zone file the accepted change
/// is persisted to before the response.
pub const UpdatePolicy = struct {
    origin: []const u8,
    key_name: []const u8,
    dir: std.Io.Dir,
    path: []const u8,
};

/// What one zone replacement did. The served zone changes only when the
/// outcome is `replaced`; every other outcome keeps the old zone serving.
pub const ReloadOutcome = enum {
    /// The zone was replaced and the serial transition was recorded.
    replaced,
    /// No zone file is configured, so there is nothing to reload.
    no_source,
    /// The zone file could not be read or the zone text could not be parsed.
    load_failed,
    /// The server does not serve a zone with that apex.
    no_zone,
    /// The new zone provides another apex than the zone it replaces.
    wrong_zone,
    /// The new zone's SOA serial is not RFC 1982 newer than the served one.
    serial_not_newer,
    /// The served zone is signed and the new one could not be signed, so the
    /// served zone stays.
    sign_failed,
};

/// What one TSIG key file replacement did. The served keys change only when
/// the outcome is `replaced`; every other outcome keeps the keys the server
/// already has.
pub const KeyReloadOutcome = enum {
    /// The keyring was replaced by the one the key file provides.
    replaced,
    /// No key file is configured, so there is nothing to reload.
    no_source,
    /// The key file could not be read or the key text could not be parsed.
    load_failed,
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

pub const SecondaryState = struct {
    apex: []const u8,
    primary: std.Io.net.IpAddress,
    last_success_ns: ?i64 = null,
    last_attempt_ns: ?i64 = null,
    last_attempt_failed: bool = false,
    refresh_sec: u32 = 0,
    retry_sec: u32 = 0,
    expire_sec: u32 = 0,
    expired: bool = false,
};

pub const SecondaryFetch = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, zone_name: []const u8) anyerror!?[]const u8;

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
    /// What an authoritative answer may carry back in its OPT record, and
    /// which agent domain the server monitors, from the `nsid`, `zoneversion`,
    /// `error-report-agent`, and `error-report-monitor` directives. `nsid` is
    /// heap-owned so it outlives the config text it was decoded from; the
    /// agent domains are names, so they are inline and own nothing.
    answer_policy: response.AnswerPolicy = .{},
    /// The signing material of a signed zone, kept so the answer path can sign
    /// an RRset that is not in the zone file (RFC 8482 section 4.2). Null
    /// when no zone is signed.
    dnssec_session: ?zone_signer.Session = null,
    keyring: keyring_mod.Keyring = .{},
    tsig_now: ?u64 = null,
    /// Volatile per-zone RFC 1995 serial transitions feeding IXFR delta
    /// decisions. Entry i parallels `zones.items[i]`; appended best-effort so
    /// bulk-loaded runtimes need no fallible log setup. A length mismatch
    /// means no usable history and decideIxfr falls back to AXFR.
    transfer_delta_logs: std.ArrayList(journal_mod.DeltaLog) = .empty,
    /// The zone file an operator can replace, and the apex it must provide.
    /// Null when no zone file is reloadable.
    /// Every configured zone file a SIGHUP re-reads, in configuration order.
    reload_sources: std.ArrayList(ReloadSource) = .empty,
    /// RFC 2136 update policies, one per zone the operator allowed updates
    /// for. Empty unless `allow-update` is configured.
    update_policies: std.ArrayList(UpdatePolicy) = .empty,
    /// RFC 1996 secondaries to notify when one of the listed zones changes.
    /// Empty unless `notify` is configured. The apex string is heap-owned.
    notify_targets: std.ArrayList(NotifyTarget) = .empty,
    /// Secondary-zone refresh state (last success/failure/expired). Empty unless configured.
    secondary_zones: std.ArrayList(SecondaryState) = .empty,
    /// The TTL of the service-binding records. RFC 9461 sets none; an hour is
    /// the answer's own lifetime, not the zone's.
    ddr_ttl: u32 = 3600,
    /// RFC 9432 section 5: the catalog this server was provisioned from, and
    /// the members it currently serves. Null unless `catalog-consumer` is
    /// configured; every name is owned.
    catalog_consumer: ?CatalogConsumer = null,
    /// Set by a NOTIFY for the catalog apex and cleared by the refresh that
    /// answers it; the serving loop performs the network fetch.
    catalog_refresh_requested: std.atomic.Value(bool) = .init(false),
    /// The last refresh attempt, so a NOTIFY storm cannot drive one transfer
    /// per packet through the serving thread.
    catalog_refresh_attempted_ns: ?i64 = null,
    /// RFC 9461 service-binding RDATA (wire form) the resolver publishes at
    /// `_dns.resolver.arpa.` for RFC 9462 discovery. Empty unless `ddr` is
    /// configured; every slice is owned.
    ddr_rdatas: std.ArrayList([]const u8) = .empty,
    /// The TargetName of each `ddr_rdatas` entry, in the same order: RFC 9462
    /// section 5 also publishes the binding at the known name `_dns.<target>`.
    ddr_targets: std.ArrayList(dns_name_mod.Name) = .empty,
    /// Set by the SIGHUP handler and cleared by the reload that answers it.
    /// The handler only stores the flag; the file is read outside it.
    reload_requested: std.atomic.Value(bool) = .init(false),
    // ceiling: global runtime lock serializes all zone reads; use per-zone or read/write locks if contention matters.
    mutex: std.Io.RwLock = .init,
    /// The io the read-write lock waits on. A runtime built without one falls
    /// back to the single-threaded instance, whose futex wait is a no-op, so
    /// only uncontended paths may run there: tests answer with readers only,
    /// and the server passes the io it serves on through `fromZonesWithPolicy`.
    io: std.Io = std.Io.Threaded.global_single_threaded.io(),

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
        runtime.io = io;
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

    pub fn maybeRefreshSecondaries(self: *Runtime, now_ns: u64, fetch: SecondaryFetch, fetch_ctx: *anyopaque) !void {
        for (self.secondary_zones.items) |*secondary| {
            if (secondary.expired) continue;
            const action = xfr_client.refreshDecision(.{
                .now_ns = @intCast(now_ns),
                .last_success_ns = secondary.last_success_ns,
                .refresh_sec = secondary.refresh_sec,
                .retry_sec = secondary.retry_sec,
                .expire_sec = secondary.expire_sec,
                .last_attempt_failed = secondary.last_attempt_failed,
                .last_attempt_ns = secondary.last_attempt_ns,
            });
            switch (action) {
                .idle => {},
                .expired => {
                    secondary.expired = true;
                },
                .refresh_due, .retry_due => {
                    secondary.last_attempt_ns = @intCast(now_ns);
                    const text = fetch(fetch_ctx, self.allocator, secondary.apex) catch {
                        secondary.last_attempt_failed = true;
                        continue;
                    };
                    if (text) |zone_text| {
                        defer self.allocator.free(zone_text);
                        var zone_file = zone_parser.ZoneFile.parse(zone_text) catch {
                            secondary.last_attempt_failed = true;
                            continue;
                        };
                        defer zone_file.deinit();
                        var new_zone = zone_index.Zone.fromZoneFile(&zone_file) catch {
                            secondary.last_attempt_failed = true;
                            continue;
                        };
                        var installed = false;
                        defer if (!installed) new_zone.deinit();
                        // swap zone in zones
                        for (self.zones.items) |*zone| {
                            if (std.ascii.eqlIgnoreCase(zone.originText(), secondary.apex)) {
                                zone.deinit();
                                zone.* = new_zone;
                                installed = true;
                                break;
                            }
                        }
                        secondary.last_success_ns = @intCast(now_ns);
                        secondary.last_attempt_failed = false;
                    } else {
                        secondary.last_attempt_failed = true;
                    }
                },
            }
        }
    }

    pub fn fetchSecondaryViaXfr(ctx: *anyopaque, allocator: std.mem.Allocator, zone_name: []const u8) anyerror!?[]const u8 {
        const self: *Runtime = @ptrCast(@alignCast(ctx));
        for (self.secondary_zones.items) |secondary| {
            if (std.ascii.eqlIgnoreCase(secondary.apex, zone_name)) {
                const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } };
                // A served copy asks for only the difference the primary still
                // holds; without one, or when the primary answers with the
                // full zone, fall back to AXFR.
                for (self.zones.items) |*zone| {
                    if (std.ascii.eqlIgnoreCase(zone.originText(), zone_name)) {
                        return xfr_client.fetchIxfr(allocator, self.io, &secondary.primary, zone_name, zone, timeout) catch return null;
                    }
                }
                const text = xfr_client.fetch(allocator, self.io, &secondary.primary, zone_name, timeout) catch return null;
                return text;
            }
        }
        return null;
    }

    pub fn deinit(self: *Runtime) void {
        self.lockExclusive();
        defer self.unlockExclusive();
        if (self.resolver) |*resolver| resolver.deinit();
        self.resolver = null;
        self.keyring.deinit();
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.transfer_delta_logs.deinit(self.allocator);
        self.transfer_delta_logs = .empty;
        for (self.reload_sources.items) |source| {
            self.allocator.free(source.path);
            self.allocator.free(source.origin);
        }
        self.reload_sources.deinit(self.allocator);
        self.reload_sources = .empty;
        for (self.update_policies.items) |policy| {
            self.allocator.free(policy.origin);
            self.allocator.free(policy.key_name);
            self.allocator.free(policy.path);
        }
        self.update_policies.deinit(self.allocator);
        self.update_policies = .empty;
        for (self.notify_targets.items) |target| self.allocator.free(target.apex);
        self.notify_targets.deinit(self.allocator);
        self.notify_targets = .empty;
        for (self.secondary_zones.items) |*secondary| self.allocator.free(secondary.apex);
        self.secondary_zones.deinit(self.allocator);
        self.secondary_zones = .empty;
        for (self.ddr_rdatas.items) |rdata| self.allocator.free(rdata);
        self.ddr_rdatas.deinit(self.allocator);
        self.ddr_rdatas = .empty;
        self.ddr_targets.deinit(self.allocator);
        self.ddr_targets = .empty;
        if (self.catalog_consumer) |*consumer| {
            self.allocator.free(consumer.apex);
            if (consumer.group_selector) |value| self.allocator.free(value);
            for (consumer.members.items) |member| {
                self.allocator.free(member.label);
                self.allocator.free(member.name);
                for (member.properties) |property| {
                    self.allocator.free(property.key);
                    self.allocator.free(property.value);
                }
                self.allocator.free(member.properties);
            }
            consumer.members.deinit(self.allocator);
            self.catalog_consumer = null;
        }
        self.blocklist = .{};
        if (self.answer_policy.nsid) |nsid| self.allocator.free(nsid);
        self.answer_policy = .{};
        if (self.dnssec_session) |*session| session.deinit();
        self.dnssec_session = null;
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

    /// Names the zone file an operator can replace, and the apex that file
    /// must provide. The runtime copies the path and the apex, so the caller
    /// keeps ownership of its own text; the directory is borrowed.
    pub fn setReloadSource(self: *Runtime, dir: std.Io.Dir, path: []const u8, origin: []const u8) !void {
        self.clearReloadSources();
        try self.addReloadSource(dir, path, origin);
    }

    /// Adds one configured zone file a SIGHUP re-reads. A multi-zone
    /// configuration calls this once per zone file.
    pub fn addReloadSource(self: *Runtime, dir: std.Io.Dir, path: []const u8, origin: []const u8) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const owned_origin = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned_origin);
        try self.reload_sources.append(self.allocator, .{ .dir = dir, .path = owned_path, .origin = owned_origin });
    }

    fn clearReloadSources(self: *Runtime) void {
        for (self.reload_sources.items) |source| {
            self.allocator.free(source.path);
            self.allocator.free(source.origin);
        }
        self.reload_sources.clearRetainingCapacity();
    }

    /// Records an RFC 2136 update policy: the apex, the TSIG key name that may
    /// write it, and the zone file the change is persisted to.
    pub fn setUpdatePolicy(self: *Runtime, dir: std.Io.Dir, origin: []const u8, key_name: []const u8, path: []const u8) !void {
        const owned_origin = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned_origin);
        const owned_key = try self.allocator.dupe(u8, key_name);
        errdefer self.allocator.free(owned_key);
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        try self.update_policies.append(self.allocator, .{
            .origin = owned_origin,
            .key_name = owned_key,
            .dir = dir,
            .path = owned_path,
        });
    }

    /// Registers one RFC 9461 SVCB record for `_dns.resolver.arpa.` and its
    /// RFC 9462 section 5 known name `_dns.<target>`. The presentation form is
    /// parsed and its wire RDATA kept, so a query costs no re-parse; the target
    /// is kept inline so a known-name query needs no allocator.
    pub fn addDdrRecord(self: *Runtime, target: []const u8, alpn: []const u8, port: u16, dohpath: ?[]const u8) !void {
        const target_name = dns_name_mod.Name.fromText(target) catch return error.BadConfiguration;
        var text_buffer: [512]u8 = undefined;
        const text = if (dohpath) |path|
            try std.fmt.bufPrint(&text_buffer, "1 {s} alpn={s} port={d} dohpath={s}", .{ target, alpn, port, path })
        else
            try std.fmt.bufPrint(&text_buffer, "1 {s} alpn={s} port={d}", .{ target, alpn, port });
        const parsed = zone_parser.parseRData(dns_types.RecordType.SVCB, text) catch return error.BadConfiguration;
        var wire: [512]u8 = undefined;
        var writer = dns_writer.Writer.init(&wire);
        parsed.encode(&writer) catch return error.BadConfiguration;
        const owned = try self.allocator.dupe(u8, writer.written());
        errdefer self.allocator.free(owned);
        try self.ddr_rdatas.append(self.allocator, owned);
        // The two lists are one record; a failed second append must not leave
        // them different lengths.
        errdefer _ = self.ddr_rdatas.pop();
        try self.ddr_targets.append(self.allocator, target_name);
    }

    /// Records the RFC 9432 catalog this server is provisioned from. The
    /// apex is copied.
    pub fn setCatalogConsumer(self: *Runtime, apex: []const u8, primary: std.Io.net.IpAddress, group_selector: ?[]const u8) !void {
        const owned = try self.allocator.dupe(u8, apex);
        errdefer self.allocator.free(owned);
        if (self.catalog_consumer) |*consumer| {
            // A consumer pointed at a different primary keeps the members it
            // serves; the next refresh reconciles them against the catalog.
            self.allocator.free(consumer.apex);
            consumer.apex = owned;
            consumer.primary = primary;
            if (consumer.group_selector) |value| self.allocator.free(value);
            consumer.group_selector = if (group_selector) |value| try self.allocator.dupe(u8, value) else null;
            return;
        }
        const owned_group = if (group_selector) |value| try self.allocator.dupe(u8, value) else null;
        errdefer if (owned_group) |value| self.allocator.free(value);
        self.catalog_consumer = .{ .apex = owned, .primary = primary, .group_selector = owned_group };
    }

    /// Records the members the catalog currently names.
    pub fn setCatalogMembers(self: *Runtime, members: []const catalog_mod.Member) !void {
        var list: std.ArrayList(CatalogMember) = .empty;
        errdefer {
            for (list.items) |member| {
                self.allocator.free(member.label);
                self.allocator.free(member.name);
            }
            list.deinit(self.allocator);
        }
        for (members) |member| {
            const label = try self.allocator.dupe(u8, member.label);
            errdefer self.allocator.free(label);
            const name = try self.allocator.dupe(u8, member.name);
            errdefer self.allocator.free(name);
            var property_list: std.ArrayList(catalog_mod.Property) = .empty;
            errdefer {
                for (property_list.items) |property| {
                    self.allocator.free(property.key);
                    self.allocator.free(property.value);
                }
                property_list.deinit(self.allocator);
            }
            for (member.properties) |property| {
                const key = try self.allocator.dupe(u8, property.key);
                errdefer self.allocator.free(key);
                const value = try self.allocator.dupe(u8, property.value);
                try property_list.append(self.allocator, .{ .key = key, .value = value });
            }
            const properties = try property_list.toOwnedSlice(self.allocator);
            try list.append(self.allocator, .{ .label = label, .name = name, .properties = properties });
        }
        const consumer = if (self.catalog_consumer) |*value| value else {
            for (list.items) |member| {
                self.allocator.free(member.label);
                self.allocator.free(member.name);
            }
            list.deinit(self.allocator);
            return;
        };
        for (consumer.members.items) |member| {
            self.allocator.free(member.label);
            self.allocator.free(member.name);
        }
        consumer.members.deinit(self.allocator);
        consumer.members = list;
    }

    /// RFC 9432 section 5.4: a NOTIFY for the catalog asks the consumer to
    /// read it again. The handler only sets the flag; the serve path fetches.
    pub fn requestCatalogRefresh(self: *Runtime) void {
        self.catalog_refresh_requested.store(true, .release);
    }

    /// Answers a pending catalog NOTIFY: re-fetch the catalog and apply its
    /// members. The fetch runs before the exclusive lock is taken, so other
    /// answers are not blocked by the lock; the fetch itself runs on the
    /// serving thread, so an answer that arrives during it waits for the
    /// transfer (a bounded ceiling, not a background job). At most one
    /// attempt starts per `catalog_refresh_window_ns`, and a failed attempt
    /// re-arms the request, so a transient failure retries after the window
    /// instead of never.
    pub fn refreshCatalogIfRequested(self: *Runtime, io: std.Io) ?CatalogRefreshOutcome {
        if (!self.catalog_refresh_requested.swap(false, .acq_rel)) return null;
        const now: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
        if (self.catalog_refresh_attempted_ns) |last| {
            if (now - last < catalog_refresh_window_ns) {
                self.catalog_refresh_requested.store(true, .release);
                return null;
            }
        }
        self.catalog_refresh_attempted_ns = now;
        const outcome = self.refreshCatalog(io);
        if (outcome == .failed) self.catalog_refresh_requested.store(true, .release);
        return outcome;
    }

    fn refreshCatalog(self: *Runtime, io: std.Io) CatalogRefreshOutcome {
        const consumer = if (self.catalog_consumer) |*value| value else return .failed;
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(5000), .clock = .awake } };
        const catalog_text = xfr_client.fetch(self.allocator, io, &consumer.primary, consumer.apex, timeout) catch {
            reportReload(io, "error: cannot fetch the catalog {s}", .{consumer.apex});
            return .failed;
        };
        defer self.allocator.free(catalog_text);
        const new_members = catalog_mod.members(self.allocator, catalog_text, consumer.apex) catch {
            reportReload(io, "error: the catalog {s} is malformed", .{consumer.apex});
            return .failed;
        };
        defer {
            for (new_members) |member| {
                self.allocator.free(member.label);
                self.allocator.free(member.name);
            }
            self.allocator.free(new_members);
        }

        var catalog_file = zone_parser.ZoneFile.parse(catalog_text) catch return .failed;
        defer catalog_file.deinit();
        var catalog_zone = zone_index.Zone.fromZoneFile(&catalog_file) catch return .failed;
        if (!std.ascii.eqlIgnoreCase(catalog_zone.originText(), consumer.apex)) {
            catalog_zone.deinit();
            return .failed;
        }
        const new_serial = catalog_zone.soaSerial() orelse {
            catalog_zone.deinit();
            return .failed;
        };
        if (!self.refreshedZoneDigestOk(io, &catalog_zone)) {
            catalog_zone.deinit();
            return .failed;
        }

        // An unchanged serial means an unchanged membership: the members are
        // not fetched at all.
        self.lockShared();
        const old_serial: ?u32 = if (self.zoneIndexForOrigin(consumer.apex)) |index| self.zones.items[index].soaSerial() else null;
        self.unlockShared();
        if (old_serial) |value| {
            if (journal_mod.compareSerial(new_serial, value) != .newer) {
                catalog_zone.deinit();
                return .unchanged;
            }
        }

        // Every member is fetched and parsed before the lock is taken, so a
        // failed transfer or a broken zone leaves the served set whole.
        var member_zones: std.ArrayList(zone_index.Zone) = .empty;
        for (new_members) |member| {
            var is_coo = false;
            for (member.properties) |property| if (std.ascii.eqlIgnoreCase(property.key, "coo")) {
                is_coo = true;
            };
            if (is_coo) continue;
            const text = xfr_client.fetch(self.allocator, io, &consumer.primary, member.name, timeout) catch {
                reportReload(io, "error: cannot fetch the catalog member {s}", .{member.name});
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            };
            defer self.allocator.free(text);
            var member_file = zone_parser.ZoneFile.parse(text) catch {
                reportReload(io, "error: the catalog member {s} is malformed", .{member.name});
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            };
            defer member_file.deinit();
            var member_zone = zone_index.Zone.fromZoneFile(&member_file) catch {
                reportReload(io, "error: the catalog member {s} is malformed", .{member.name});
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            };
            if (!std.ascii.eqlIgnoreCase(member_zone.originText(), member.name)) {
                member_zone.deinit();
                reportReload(io, "error: the catalog member {s} arrived as another zone", .{member.name});
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            }
            if (!self.refreshedZoneDigestOk(io, &member_zone)) {
                member_zone.deinit();
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            }
            member_zones.append(self.allocator, member_zone) catch {
                member_zone.deinit();
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                catalog_zone.deinit();
                return .failed;
            };
        }

        self.lockExclusive();
        defer self.unlockExclusive();
        if (self.zoneIndexForOrigin(consumer.apex)) |_| {
            const catalog_outcome = self.installZoneLocked(io, consumer.apex, &catalog_zone);
            if (catalog_outcome != .replaced) {
                catalog_zone.deinit();
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                // Another refresh installed the same serial first.
                return if (catalog_outcome == .serial_not_newer) .unchanged else .failed;
            }
        } else {
            self.zones.append(self.allocator, catalog_zone) catch {
                catalog_zone.deinit();
                for (member_zones.items) |*zone| zone.deinit();
                member_zones.deinit(self.allocator);
                return .failed;
            };
            self.transfer_delta_logs.append(self.allocator, .{}) catch {};
        }

        // A member whose label changed is removed and added again with fresh
        // state (RFC 9432 section 5.4); a member the catalog stops naming is
        // removed. The catalog zone itself stays.
        var index: usize = 0;
        while (index < consumer.members.items.len) {
            const old = consumer.members.items[index];
            var keep = false;
            for (new_members) |member| {
                if (!std.ascii.eqlIgnoreCase(member.name, old.name)) continue;
                if (!std.ascii.eqlIgnoreCase(member.label, old.label)) continue;
                keep = true;
            }
            if (keep) {
                index += 1;
                continue;
            }
            self.removeZoneLocked(old.name);
            self.allocator.free(old.label);
            self.allocator.free(old.name);
            for (old.properties) |property| {
                self.allocator.free(property.key);
                self.allocator.free(property.value);
            }
            self.allocator.free(old.properties);
            _ = consumer.members.orderedRemove(index);
        }
        var member_zone_index: usize = 0;
        for (new_members) |member| {
            // coo members are not provisioned here.
            var coo_member = false;
            for (member.properties) |property| if (std.ascii.eqlIgnoreCase(property.key, "coo")) {
                coo_member = true;
            };
            if (coo_member) continue;
            var member_zone = member_zones.items[member_zone_index];
            member_zone_index += 1;
            if (self.zoneIndexForOrigin(member.name) != null) {
                const installed = self.installZoneLocked(io, member.name, &member_zone);
                if (installed != .replaced) member_zone.deinit();
            } else {
                self.zones.append(self.allocator, member_zone) catch {
                    member_zone.deinit();
                    continue;
                };
                self.transfer_delta_logs.append(self.allocator, .{}) catch {};
            }
            // RFC 9432 section 4.3: a member whose `coo` property points at
            // another catalog belongs to that catalog, not this one; this
            // consumer skips provisioning it.
            var is_coo = false;
            for (member.properties) |property| {
                if (std.ascii.eqlIgnoreCase(property.key, "coo")) is_coo = true;
            }
            if (is_coo) continue;
            const label = self.allocator.dupe(u8, member.label) catch continue;
            const name = self.allocator.dupe(u8, member.name) catch {
                self.allocator.free(label);
                continue;
            };
            var property_list: std.ArrayList(catalog_mod.Property) = .empty;
            for (member.properties) |property| {
                const key = self.allocator.dupe(u8, property.key) catch {
                    self.allocator.free(label);
                    self.allocator.free(name);
                    for (property_list.items) |owned_property| {
                        self.allocator.free(owned_property.key);
                        self.allocator.free(owned_property.value);
                    }
                    property_list.deinit(self.allocator);
                    continue;
                };
                const value = self.allocator.dupe(u8, property.value) catch {
                    self.allocator.free(key);
                    self.allocator.free(label);
                    self.allocator.free(name);
                    for (property_list.items) |owned_property| {
                        self.allocator.free(owned_property.key);
                        self.allocator.free(owned_property.value);
                    }
                    property_list.deinit(self.allocator);
                    continue;
                };
                property_list.append(self.allocator, .{ .key = key, .value = value }) catch {};
            }
            const properties = property_list.toOwnedSlice(self.allocator) catch &.{};
            consumer.members.append(self.allocator, .{ .label = label, .name = name, .properties = properties }) catch {
                self.allocator.free(label);
                self.allocator.free(name);
                for (properties) |property| {
                    self.allocator.free(property.key);
                    self.allocator.free(property.value);
                }
                self.allocator.free(properties);
            };
        }
        member_zones.deinit(self.allocator);
        // Track each provisioned member as a secondary for periodic refresh.
        // Standalone secondaries (not catalog members) survive a catalog refresh.
        var saved_secondary_zones = self.secondary_zones;
        self.secondary_zones = .empty;
        for (consumer.members.items) |member| {
            var preserved: ?i64 = null;
            for (saved_secondary_zones.items) |old| {
                if (std.ascii.eqlIgnoreCase(old.apex, member.name)) {
                    preserved = old.last_success_ns;
                    break;
                }
            }
            var refresh_sec: u32 = 3600;
            var retry_sec: u32 = 900;
            var expire_sec: u32 = 1209600;
            if (self.zoneIndexForOrigin(member.name)) |zone_index_value| {
                const soa_rec = self.zones.items[zone_index_value].soa;
                if (soa_rec) |rec| {
                    if (zone_parser.parseRData(.SOA, rec.rdataText())) |soa_rdata| {
                        if (soa_rdata == .SOA) {
                            refresh_sec = soa_rdata.SOA.refresh;
                            retry_sec = soa_rdata.SOA.retry;
                            expire_sec = soa_rdata.SOA.expire;
                        }
                    } else |_| {}
                }
            }
            self.secondary_zones.append(self.allocator, .{
                .apex = self.allocator.dupe(u8, member.name) catch return .failed,
                .primary = consumer.primary,
                .last_success_ns = if (preserved) |value| value else @as(i64, @intCast(std.Io.Clock.awake.now(io).nanoseconds)),
                .refresh_sec = refresh_sec,
                .retry_sec = retry_sec,
                .expire_sec = expire_sec,
            }) catch return .failed;
        }
        for (saved_secondary_zones.items) |old| {
            var is_member = false;
            for (consumer.members.items) |member| {
                if (std.ascii.eqlIgnoreCase(old.apex, member.name)) {
                    is_member = true;
                    break;
                }
            }
            if (is_member) {
                self.allocator.free(old.apex);
            } else {
                self.secondary_zones.append(self.allocator, old) catch self.allocator.free(old.apex);
            }
        }
        saved_secondary_zones.deinit(self.allocator);
        reportReload(io, "reloaded the catalog {s}: {d} member(s)", .{ consumer.apex, consumer.members.items.len });
        return .updated;
    }

    /// RFC 8976 section 4: a zone whose apex ZONEMD does not match its data
    /// is refused, the same check the startup loader makes. The
    /// anchor-based authenticity steps stay a startup check: the runtime
    /// holds no trust anchors.
    fn refreshedZoneDigestOk(self: *Runtime, io: std.Io, zone: *const zone_index.Zone) bool {
        var report: [zonemd.report_max_len]u8 = undefined;
        _ = zonemd.verify(zone, self.allocator, &report) catch {
            const written = std.mem.indexOfScalar(u8, &report, 0) orelse report.len;
            reportReload(io, "{s}", .{report[0..written]});
            return false;
        };
        return true;
    }

    /// Removes one zone from the served set. The caller holds the exclusive
    /// lock.
    fn removeZoneLocked(self: *Runtime, origin: []const u8) void {
        const index = self.zoneIndexForOrigin(origin) orelse return;
        self.zones.items[index].deinit();
        _ = self.zones.orderedRemove(index);
        if (index < self.transfer_delta_logs.items.len) _ = self.transfer_delta_logs.orderedRemove(index);
    }

    /// Registers one RFC 1996 NOTIFY destination. The apex is copied, so the
    /// configuration text can be released.
    pub fn addNotifyTarget(self: *Runtime, apex: []const u8, address: std.Io.net.IpAddress) !void {
        const owned = try self.allocator.dupe(u8, apex);
        errdefer self.allocator.free(owned);
        try self.notify_targets.append(self.allocator, .{ .apex = owned, .address = address });
    }

    /// RFC 1996 section 3.8: a master sends a NOTIFY to its secondaries when a
    /// zone changes. One datagram per configured target, sent from the answer
    /// path after the change is committed; a lost datagram falls back to the
    /// secondary's refresh timer, and no retry loop runs here.
    fn notifySecondaries(self: *Runtime, origin: []const u8, zone: *const zone_index.Zone) void {
        const soa = zone.soa orelse return;
        for (self.notify_targets.items) |target| {
            if (!std.ascii.eqlIgnoreCase(target.apex, origin)) continue;
            self.sendNotify(target.address, origin, soa) catch {};
        }
    }

    fn sendNotify(self: *Runtime, address: std.Io.net.IpAddress, origin: []const u8, soa: zone_parser.ZoneRecord) !void {
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const allocator = scratch.allocator();
        var id_bytes: [2]u8 = undefined;
        self.io.random(&id_bytes);
        const name = dns_name_mod.Name.fromText(origin) catch return error.BadZoneRecord;
        const soa_rr = try response.zoneRecordToResourceRecord(soa, null);
        var message = dns_message.Message{
            .allocator = allocator,
            .header = .{
                .id = std.mem.readInt(u16, &id_bytes, .big),
                .opcode = .notify,
                .authoritative = true,
                .question_count = 1,
                .answer_count = 1,
            },
            .question = .{ .name = name, .qtype = dns_types.RecordType.SOA, .qclass = dns_types.Class.IN },
            .answers = try dns_message.RecordSection.init(allocator, 1),
        };
        try message.answers.append(soa_rr);
        var buffer: [1024]u8 = undefined;
        var writer = dns_writer.Writer.init(&buffer);
        try message.encode(&writer);
        var local = switch (address) {
            .ip4 => std.Io.net.IpAddress{ .ip4 = .unspecified(0) },
            .ip6 => std.Io.net.IpAddress{ .ip6 = .unspecified(0) },
        };
        var socket = try std.Io.net.IpAddress.bind(&local, self.io, .{ .mode = .dgram, .protocol = .udp });
        defer socket.close(self.io);
        try socket.send(self.io, &address, writer.written());
    }

    fn updatePolicyFor(self: *const Runtime, origin: []const u8) ?*const UpdatePolicy {
        for (self.update_policies.items) |*policy| {
            if (sameDnsName(policy.origin, origin)) return policy;
        }
        return null;
    }
    fn secondaryFor(self: *const Runtime, origin: []const u8) ?*const SecondaryState {
        for (self.secondary_zones.items) |*secondary| {
            if (sameDnsName(secondary.apex, origin)) return secondary;
        }
        return null;
    }

    fn sameDnsName(left: []const u8, right: []const u8) bool {
        const a = std.mem.trimEnd(u8, left, ".");
        const b = std.mem.trimEnd(u8, right, ".");
        return std.ascii.eqlIgnoreCase(a, b);
    }

    /// Asks for the configured zone to be re-read. The signal handler calls
    /// this and nothing else: the file is read and the zone is swapped
    /// outside the handler.
    pub fn requestZoneReload(self: *Runtime) void {
        self.reload_requested.store(true, .release);
    }

    /// Replaces the configured zone and the TSIG keys when a reload was
    /// requested. Returns the zone outcome, or null when no reload was
    /// pending.
    pub fn reloadZoneIfRequested(self: *Runtime, io: std.Io) ?ReloadOutcome {
        if (!self.reload_requested.swap(false, .acq_rel)) return null;
        // A key file that cannot be read leaves the served keys in place,
        // so the zone is still replaced.
        _ = self.reloadKeyring(io);
        return self.reloadZone(io);
    }

    /// Re-reads the TSIG key file and replaces the keyring it provides.
    /// The file is read and parsed completely before the served keyring
    /// changes, so a missing, unreadable, or malformed file leaves the keys
    /// the server already has in place.
    pub fn reloadKeyring(self: *Runtime, io: std.Io) KeyReloadOutcome {
        const source = self.keyring.source orelse return .no_source;
        const text = source.dir.readFileAlloc(io, source.path(), self.allocator, .limited(1024 * 1024)) catch |err| {
            reportReload(io, "error: cannot read the TSIG key file {s}: {t}", .{ source.path(), err });
            return .load_failed;
        };
        defer {
            // The key text holds the secrets in their file form.
            std.crypto.secureZero(u8, text);
            self.allocator.free(text);
        }
        var ring = keyring_mod.Keyring.parse(text) catch |err| {
            reportReload(io, "error: cannot parse the TSIG key file {s}: {t}", .{ source.path(), err });
            return .load_failed;
        };
        self.lockExclusive();
        defer self.unlockExclusive();
        // The swap happens under the lock, so a request is verified against
        // the old keyring or the new one, never a half-built one.
        self.keyring.replace(&ring);
        // The runtime holds the only remaining copy of the new secrets.
        ring.deinit();
        reportReload(io, "reloaded the TSIG key file {s}: {d} key(s)", .{ source.path(), self.keyring.len });
        return .replaced;
    }

    /// Re-reads the configured zone file and replaces the zone it provides.
    /// The file is read, parsed, and built completely before the served zone
    /// changes, so a broken file leaves the old zone serving.
    pub fn reloadZone(self: *Runtime, io: std.Io) ReloadOutcome {
        if (self.reload_sources.items.len == 0) {
            reportReload(io, "error: no zone file is configured to reload", .{});
            return .no_source;
        }
        // Every configured zone is re-read; one broken file leaves that zone
        // serving its old data and the others reload.
        var outcome: ReloadOutcome = .replaced;
        for (self.reload_sources.items) |source| {
            const text = source.dir.readFileAlloc(io, source.path, self.allocator, .limited(1024 * 1024)) catch |err| {
                reportReload(io, "error: cannot read the zone file {s}: {t}", .{ source.path, err });
                outcome = .load_failed;
                continue;
            };
            defer self.allocator.free(text);
            const replaced = self.replaceZoneText(io, source.origin, text);
            if (replaced != .replaced and outcome == .replaced) outcome = replaced;
        }
        return outcome;
    }

    /// Replaces the zone with apex `origin` by the zone built from `text`.
    /// The new zone is parsed and built completely before the served zone
    /// changes, so a text that does not parse, names another apex, or
    /// carries no RFC 1982 newer serial leaves the old zone serving. A zone
    /// that was signed is signed again with the key the server holds, so the
    /// served chain covers the new content; a zone that cannot be signed
    /// leaves the old zone serving too. The serial transition is recorded,
    /// so an IXFR client at the old serial gets the incremental answer
    /// instead of a full AXFR.
    pub fn replaceZoneText(self: *Runtime, io: std.Io, origin: []const u8, text: []const u8) ReloadOutcome {
        var zone_file = zone_parser.ZoneFile.parse(text) catch |err| {
            reportReload(io, "error: cannot parse the zone file for {s}: {t}", .{ origin, err });
            return .load_failed;
        };
        var zone = zone_index.Zone.fromZoneFile(&zone_file) catch |err| {
            zone_file.deinit();
            reportReload(io, "error: cannot build the zone for {s}: {t}", .{ origin, err });
            return .load_failed;
        };
        if (!std.ascii.eqlIgnoreCase(zone.originText(), origin)) {
            zone.deinit();
            reportReload(io, "error: the zone file for {s} provides {s}", .{ origin, zone.originText() });
            return .wrong_zone;
        }
        // The new zone is built before the lock is taken, so a reload does
        // not hold up the answers it does not change.
        self.lockExclusive();
        defer self.unlockExclusive();
        const outcome = self.installZoneLocked(io, origin, &zone);
        if (outcome != .replaced) zone.deinit();
        return outcome;
    }

    /// Installs a zone the caller built, under the exclusive lock: the serial
    /// transition is compared, a signed zone is signed again, the delta is
    /// journaled, and only then is the served zone swapped. The caller keeps
    /// ownership of `zone` unless the outcome is `.replaced`.
    fn installZoneLocked(self: *Runtime, io: std.Io, origin: []const u8, zone: *zone_index.Zone) ReloadOutcome {
        const target = self.zoneIndexForOrigin(origin) orelse {
            reportReload(io, "error: the server does not serve a zone for {s}", .{origin});
            return .no_zone;
        };
        const new_serial = zone.soaSerial() orelse {
            reportReload(io, "error: the zone file for {s} has no SOA serial", .{origin});
            return .load_failed;
        };
        const old_serial = self.zones.items[target].soaSerial() orelse {
            reportReload(io, "error: the served zone for {s} has no SOA serial", .{origin});
            return .load_failed;
        };
        switch (journal_mod.compareSerial(new_serial, old_serial)) {
            .newer => {},
            .equal => {
                reportReload(io, "error: the zone file for {s} carries serial {d}, the serial already served", .{ origin, new_serial });
                return .serial_not_newer;
            },
            .older => {
                reportReload(io, "error: the zone file for {s} carries serial {d}, older than the served serial {d}", .{ origin, new_serial, old_serial });
                return .serial_not_newer;
            },
            .undefined => {
                reportReload(io, "error: the zone file for {s} carries serial {d}, not comparable with the served serial {d}", .{ origin, new_serial, old_serial });
                return .serial_not_newer;
            },
        }
        // A zone that was signed is signed again here, with the key the server
        // holds, so the served chain covers the new content. A zone that was
        // not signed is not signed by a reload.
        if (self.zones.items[target].generated.len != 0) {
            if (self.dnssec_session) |*session| {
                // A reload signs the zone with a window that starts now, so a
                // zone that has been running for weeks is signed with the
                // validity period it has left (RFC 4034 section 3.1.5). The
                // key does not move, so a validator that holds the old DS
                // still validates the reloaded zone.
                const now_seconds: u32 = @intCast(@divTrunc(
                    std.Io.Clock.real.now(io).nanoseconds,
                    std.time.ns_per_s,
                ));
                const window = session.options.fromNow(now_seconds);
                zone_signer.resignZone(self.allocator, zone, &session.key, window, &self.zones.items[target]) catch |err| {
                    reportReload(io, "error: cannot sign the reloaded zone for {s}: {t}", .{ origin, err });
                    return .sign_failed;
                };
                // The session signs the RFC 8482 minimal answer too, so its
                // window moves with the zone's.
                session.options = window;
            } else {
                reportReload(io, "error: the zone for {s} is signed and the server holds no signing key", .{origin});
                return .sign_failed;
            }
        }
        // The delta log is parallel to the zone list, and a runtime built
        // from a zone list starts without one.
        while (self.transfer_delta_logs.items.len < self.zones.items.len) {
            self.transfer_delta_logs.append(self.allocator, .{}) catch {
                reportReload(io, "error: cannot record the serial transition for {s}", .{origin});
                return .load_failed;
            };
        }
        // The difference between the two zones is computed here, where both
        // snapshots exist, so the incremental answer carries the records
        // that changed.
        const difference = zone_index.difference(self.allocator, &self.zones.items[target], zone) catch |err| {
            reportReload(io, "error: cannot compute the difference of the zone for {s}: {t}", .{ origin, err });
            return .load_failed;
        };
        defer self.allocator.free(difference);
        self.transfer_delta_logs.items[target].setOrigin(zone.originText());
        self.transfer_delta_logs.items[target].record(old_serial, new_serial, difference) catch |err| {
            reportReload(io, "error: cannot record the serial transition for {s}: {t}", .{ origin, err });
            return .serial_not_newer;
        };
        // Swap only after the new zone is built and the transition recorded.
        self.zones.items[target].deinit();
        self.zones.items[target] = zone.*;
        reportReload(io, "reloaded the zone for {s}: serial {d} -> {d}", .{ origin, old_serial, new_serial });
        // RFC 1996 section 3.8: a master notifies its secondaries when a zone
        // changes, and both the RFC 2136 path and a reload land here.
        self.notifySecondaries(origin, &self.zones.items[target]);
        return .replaced;
    }

    fn zoneIndexForOrigin(self: *const Runtime, origin: []const u8) ?usize {
        for (self.zones.items, 0..) |zone, index| {
            if (!std.ascii.eqlIgnoreCase(zone.originText(), origin)) continue;
            return index;
        }
        return null;
    }

    fn lockShared(self: *const Runtime) void {
        @constCast(&self.mutex).lockSharedUncancelable(self.io);
    }

    fn unlockShared(self: *const Runtime) void {
        @constCast(&self.mutex).unlockShared(self.io);
    }

    fn lockExclusive(self: *const Runtime) void {
        @constCast(&self.mutex).lockUncancelable(self.io);
    }

    fn unlockExclusive(self: *const Runtime) void {
        @constCast(&self.mutex).unlock(self.io);
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
                    error.EdnsOptionsTooLong,
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
                error.EdnsOptionsTooLong,
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

        const now = self.currentTsigTime();
        const algorithm = tsig.algorithmForName(&final_record.tsig.algorithm) catch {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        };
        // RFC 8945 sections 4.2 and 5.2.1: the key name may carry several
        // algorithms, so every key holding the name is a candidate and the
        // algorithm the request names selects the one that authenticates it.
        const key = self.keyring.findAlgorithm(final_record.owner, algorithm) orelse {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        };
        // An operator-configured expiry makes the key unusable, and RFC 8945
        // section 5.2.1 answers an unusable key as an unknown one: NOTAUTH
        // with BADKEY and no MAC (section 5.3.2).
        if (!key.activeAt(now)) {
            return .{ .failure = .{ .code = .badkey, .final = final_record } };
        }
        if (final_record.tsig.error_code != 0) {
            return .{ .failure = .{ .code = .formerr, .final = final_record } };
        }
        const request_mac = copyMac(final_record.tsig.macBytes()) orelse {
            return .{ .failure = .{ .code = .badsig, .final = final_record, .key = key } };
        };
        _ = tsig.verify(packet, key.secretBytes(), null) catch |err| switch (err) {
            error.BadMac => return .{ .failure = .{ .code = .badsig, .final = final_record, .key = key } },
            error.UnsupportedAlgorithm => return .{ .failure = .{ .code = .badkey, .final = final_record } },
            error.Formerr => return .{ .failure = .{ .code = .formerr, .final = final_record } },
            else => return .{ .failure = .{ .code = .formerr, .final = final_record } },
        };

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

        // RFC 8945 section 5.2: the truncation policy check comes after the
        // time check. Section 5.2.4: a MAC too short for the local policy is
        // answered with BADTRUNC.
        if (@as(usize, request_mac.len) < tsig.minimumMacLength(algorithm)) {
            return .{ .failure = .{
                .code = .badtrunc,
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

        // The reply is signed with the same key and algorithm that
        // authenticated the request (RFC 8945 section 5.3).
        const digest_len = tsig.digestLength(auth.key.algorithm);
        // RFC 8945 section 7: a reply carries a MAC at least as long as the request's.
        const reply_mac_len = @max(digest_len, @as(usize, auth.request_mac.len));
        var value = auth.final.tsig;
        value.time_signed = time_signed orelse self.currentTsigTime();
        value.original_id = auth.final.tsig.original_id;
        value.mac_len = @intCast(reply_mac_len);
        @memset(value.mac[0..reply_mac_len], 0);
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

    /// Answers one request and counts it, so every transport that reports
    /// metrics counts the same way.
    /// One answer for either transport. Parsing happens before the runtime
    /// lock is taken: an RFC 2136 UPDATE takes the exclusive lock itself (it
    /// rewrites the zone), and every other opcode takes it shared.
    fn dispatchAnswer(
        self: *Runtime,
        allocator: std.mem.Allocator,
        query_bytes: []const u8,
        output: []u8,
        client: ?*const std.Io.net.IpAddress,
        counters: ?*metrics.Counters,
        over_tcp: bool,
    ) ![]const u8 {
        if (counters) |value| metrics.bump(&value.queries_total);
        const parsed = self.parseIncoming(allocator, query_bytes) catch |err| {
            countAnswerError(counters, err);
            return err;
        };
        if (parsed == .incoming and parsed.incoming.query.header.opcode == .update) {
            return self.answerUpdate(allocator, output, parsed.incoming, query_bytes) catch |err| {
                countAnswerError(counters, err);
                return err;
            };
        }
        self.lockShared();
        defer self.unlockShared();
        const result = self.answerParsed(allocator, query_bytes, output, client, counters, over_tcp, parsed) catch |err| {
            countAnswerError(counters, err);
            return err;
        };
        if (counters) |value| metrics.bump(&value.responses_total);
        return result;
    }

    fn countAnswerError(counters: ?*metrics.Counters, err: anyerror) void {
        const value = counters orelse return;
        if (err == Error.BadQuery) metrics.bump(&value.bad_queries_total);
        if (err == Error.EncodeFailed) metrics.bump(&value.encode_failures_total);
    }

    fn answerParsed(
        self: *Runtime,
        allocator: std.mem.Allocator,
        query_bytes: []const u8,
        output: []u8,
        client: ?*const std.Io.net.IpAddress,
        counters: ?*metrics.Counters,
        over_tcp: bool,
        parsed: IncomingResult,
    ) ![]const u8 {
        switch (parsed) {
            .failure => |failure| return self.encodeFailure(allocator, query_bytes, output, failure),
            .incoming => |incoming| {
                if (counters) |value| countInboundBits(value, incoming.query);
                if (incoming.auth) |auth| {
                    return self.encodeSignedMessage(try self.buildMessage(incoming.query, over_tcp, client), output, auth, 0, &.{}, null);
                }
                if (client) |address| return self.answerFromUnlocked(query_bytes, output, address, incoming.query, over_tcp);
                if (try self.localZoneAnswer(incoming.query)) |local| return self.encodeMessage(local, output);
                return self.encodeMessage(try self.buildMessage(incoming.query, over_tcp, client), output);
            },
        }
    }

    /// RFC 2136 section 3: one update transaction. The zone section is checked
    /// first, then the operator's policy and the request's TSIG, then the
    /// prerequisite and update sections are applied, the new zone text is
    /// persisted to the zone file, and only then does the served zone swap.
    /// A zone with no local policy that this server serves as a secondary is
    /// forwarded to its primary instead (RFC 2136 section 3.1.1): the primary
    /// owns the write, so nothing is applied here and no serial moves.
    fn answerUpdate(
        self: *Runtime,
        allocator: std.mem.Allocator,
        output: []u8,
        incoming: Incoming,
        query_bytes: []const u8,
    ) ![]const u8 {
        const query = incoming.query;
        // Nothing is enabled: the opcode is not implemented by policy, and the
        // message body is not inspected.
        if (self.update_policies.items.len == 0 and self.secondary_zones.items.len == 0) return self.encodeUpdateReply(query, incoming.auth, .notimp, output);
        const q = query.question orelse return self.encodeUpdateReply(query, incoming.auth, .formerr, output);
        if (!q.qtype.eql(.SOA) or !q.qclass.eql(dns_types.Class.IN)) {
            return self.encodeUpdateReply(query, incoming.auth, .formerr, output);
        }
        var apex_buffer: [512]u8 = undefined;
        const apex = q.name.toText(&apex_buffer) catch return self.encodeUpdateReply(query, incoming.auth, .formerr, output);
        if (self.updatePolicyFor(apex) == null) {
            if (self.secondaryFor(apex)) |secondary| {
                const primary = secondary.primary;
                return self.forwardUpdateToPrimary(&primary, query_bytes, incoming, output);
            }
            return self.encodeUpdateReply(query, incoming.auth, .notimp, output);
        }
        const policy = self.updatePolicyFor(apex).?;
        const auth = incoming.auth orelse return self.encodeUpdateReply(query, incoming.auth, .refused, output);
        var key_buffer: [512]u8 = undefined;
        const key_name = auth.key.name.toText(&key_buffer) catch return self.encodeUpdateReply(query, incoming.auth, .refused, output);
        if (!std.ascii.eqlIgnoreCase(key_name, policy.key_name)) {
            return self.encodeUpdateReply(query, incoming.auth, .refused, output);
        }
        if (self.zoneIndexForOrigin(apex) == null) {
            return self.encodeUpdateReply(query, incoming.auth, .notauth, output);
        }

        // The lock is exclusive from the first read of the zone to the swap:
        // one update at a time, and no answer sees a half-applied change.
        self.lockExclusive();
        defer self.unlockExclusive();
        const target = self.zoneIndexForOrigin(apex) orelse return self.encodeUpdateReply(query, incoming.auth, .notauth, output);
        const outcome = zone_update.apply(
            allocator,
            &self.zones.items[target],
            apex,
            query.answers.items[0..query.answers.len],
            query.authorities.items[0..query.authorities.len],
        ) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        const text = switch (outcome) {
            .rcode => |rcode| return self.encodeUpdateReply(query, incoming.auth, rcode, output),
            .zone_text => |text| text,
        };
        defer allocator.free(text);
        self.persistZoneText(self.io, policy, text) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);

        var zone_file = zone_parser.ZoneFile.parse(text) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        var zone = zone_index.Zone.fromZoneFile(&zone_file) catch {
            zone_file.deinit();
            return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        };
        const installed = self.installZoneLocked(self.io, apex, &zone);
        if (installed != .replaced) zone.deinit();
        return switch (installed) {
            .replaced => self.encodeUpdateReply(query, incoming.auth, .no_error, output),
            else => self.encodeUpdateReply(query, incoming.auth, .servfail, output),
        };
    }
    /// RFC 2136 section 3.1.1: the original UPDATE wire message is sent to
    /// the zone's primary over DNS/TCP in one two-octet frame, and the
    /// primary's response frame is relayed to the client unchanged. Any
    /// transport failure is SERVFAIL; relaying a partial or oversized frame
    /// would corrupt the response, so it is never truncated.
    fn forwardUpdateToPrimary(
        self: *Runtime,
        primary: *const std.Io.net.IpAddress,
        query_bytes: []const u8,
        incoming: Incoming,
        output: []u8,
    ) ![]const u8 {
        const query = incoming.query;
        if (query_bytes.len == 0 or query_bytes.len > 65535) return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } };
        var stream = std.Io.net.IpAddress.connect(primary, self.io, .{ .mode = .stream, .protocol = .tcp }) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        defer stream.close(self.io);
        const deadline = tcp_deadline.deadlineFromTimeout(self.io, timeout) orelse return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(query_bytes.len), .big);
        tcp_deadline.writeExact(stream.socket.handle, self.io, &prefix, deadline) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        tcp_deadline.writeExact(stream.socket.handle, self.io, query_bytes, deadline) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        var length_bytes: [2]u8 = undefined;
        tcp_deadline.readExact(stream.socket.handle, self.io, &length_bytes, deadline) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        const length = std.mem.readInt(u16, &length_bytes, .big);
        if (length == 0 or @as(usize, length) > output.len) return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        tcp_deadline.readExact(stream.socket.handle, self.io, output[0..length], deadline) catch return self.encodeUpdateReply(query, incoming.auth, .servfail, output);
        return output[0..length];
    }

    /// RFC 2136 section 3.5: the change is committed before the response. The
    /// zone file is rewritten through a temporary file in the same directory
    /// and renamed, so a crash leaves either the old file or the new one.
    fn persistZoneText(self: *const Runtime, io: std.Io, policy: *const UpdatePolicy, text: []const u8) !void {
        _ = self;
        var temp_buffer: [512]u8 = undefined;
        const temp_path = std.fmt.bufPrint(&temp_buffer, "{s}.update.tmp", .{policy.path}) catch return error.PathTooLong;
        // The temporary file is flushed to nonvolatile storage before the
        // rename, so the committed name never refers to a page that only
        // exists in the page cache (RFC 2136 section 3.5).
        const file = try policy.dir.createFile(io, temp_path, .{ .truncate = true });
        defer file.close(io);
        try file.writeStreamingAll(io, text);
        try file.sync(io);
        try policy.dir.rename(temp_path, policy.dir, policy.path, io);
    }

    /// RFC 2136 section 3.8: the response echoes the zone section and carries
    /// the rcode; a signed request gets a signed response.
    fn encodeUpdateReply(
        self: *const Runtime,
        query: dns_message.Message,
        auth: ?TsigAuth,
        rcode: dns_header.Rcode,
        output: []u8,
    ) ![]const u8 {
        var message = (if (rcode == .notimp)
            response.buildNotSupportedResponse(query)
        else
            response.buildNotImplementedResponse(query)) catch return Error.EncodeFailed;
        message.header.rcode = rcode;
        if (auth) |value| return self.encodeSignedMessage(message, output, value, 0, &.{}, null);
        return self.encodeMessage(message, output);
    }

    pub fn answer(self: *const Runtime, query_bytes: []const u8, output: []u8) ![]const u8 {
        return @constCast(self).dispatchAnswer(answerScratch(), query_bytes, output, null, null, true);
    }

    pub fn answerFrom(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress) ![]const u8 {
        return self.dispatchAnswer(answerScratch(), query_bytes, output, client, null, false);
    }

    /// Answers a request that arrived on a TCP session. RFC 7828 section 3.3.2
    /// lets the server answer the edns-tcp-keepalive option on a TCP session
    /// only, so the transport of the request is part of the answer.
    pub fn answerFromTcp(
        self: *Runtime,
        query_bytes: []const u8,
        output: []u8,
        client: *const std.Io.net.IpAddress,
        counters: ?*metrics.Counters,
    ) ![]const u8 {
        return self.dispatchAnswer(answerScratch(), query_bytes, output, client, counters, true);
    }

    pub fn truncateUdpResponse(self: *Runtime, query_bytes: []const u8, response_bytes: []const u8, output: []u8) ![]const u8 {
        const response_final = (tsig.parseFinalAdditional(response_bytes) catch null) orelse {
            return response.truncateClassicUdpResponse(response_bytes, output) catch return Error.EncodeFailed;
        };
        if (response_final.tsig.macBytes().len == 0) {
            return response.truncateSignedClassicUdpResponse(response_bytes, output) catch return Error.EncodeFailed;
        }

        self.lockShared();
        defer self.unlockShared();
        const request_final = (tsig.parseFinalAdditional(query_bytes) catch return Error.EncodeFailed) orelse return Error.EncodeFailed;
        const algorithm = tsig.algorithmForName(&request_final.tsig.algorithm) catch return Error.EncodeFailed;
        const key = self.keyring.findAlgorithm(request_final.owner, algorithm) orelse return Error.EncodeFailed;
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
    /// this path; a signed sequence carries one TSIG per message, the first
    /// message signed as a standard answer and every later one chained on the
    /// MAC of the message before it (RFC 8945 section 5.3.1). Non-transfer
    /// queries and failures yield a single frame so the client always gets an
    /// answer. The caller owns the returned blob.
    pub fn encodeTransferFrames(
        self: *const Runtime,
        allocator: std.mem.Allocator,
        request_bytes: []const u8,
    ) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        self.lockShared();
        defer self.unlockShared();
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
                            try self.buildMessage(incoming.query, false, null),
                            &output,
                            auth,
                            0,
                            &.{},
                            null,
                        )
                    else
                        try self.encodeMessage(try self.buildMessage(incoming.query, false, null), &output);
                    return frameSingle(allocator, single);
                }
                var qname_text_buffer: [256]u8 = undefined;
                const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQuery;
                const zone = self.selectZone(qname_text) orelse {
                    var output: [transfer.tcp_max_frame_size]u8 = undefined;
                    // RFC 8945 section 5.3: the answer to a signed request is
                    // signed, so the refusal of an out-of-zone transfer is too.
                    const single = if (incoming.auth) |auth|
                        try self.encodeSignedMessage(
                            try response.buildRefusedResponse(incoming.query),
                            &output,
                            auth,
                            0,
                            &.{},
                            null,
                        )
                    else
                        try self.encodeMessage(try response.buildRefusedResponse(incoming.query), &output);
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
        var first_frame = true;
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
            if (incoming.auth) |auth| {
                // RFC 8945 section 5.3.1: the first message of a multi-message
                // response is a standard answer, so its MAC covers the request
                // MAC and the whole TSIG record, and only the later messages
                // chain on the MAC of the message before them.
                const signed = if (first_frame)
                    try self.signFirstTransferFrame(frame[0..writer.len()], auth)
                else
                    try transfer.signTransferMessage(
                        frame[0..writer.len()],
                        auth.key.algorithm,
                        auth.key.secretBytes(),
                        prior_mac.?.slice(),
                    );
                var next = tsig.Mac{ .len = @intCast(signed.slice().len) };
                @memcpy(next.bytes[0..signed.slice().len], signed.slice());
                prior_mac = next;
                first_frame = false;
            }
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(writer.len()), .big);
            blob.appendSlice(allocator, &prefix) catch return Error.EncodeFailed;
            blob.appendSlice(allocator, frame[0..writer.len()]) catch return Error.EncodeFailed;
        }
        return blob.toOwnedSlice(allocator) catch return Error.EncodeFailed;
    }

    /// Signs the first frame of a signed transfer sequence with the standard
    /// answer MAC of RFC 8945 section 5.3: the request MAC and the whole TSIG
    /// record are in the digest, which is what a client verifies the first
    /// message of a multi-message response with.
    fn signFirstTransferFrame(self: *const Runtime, frame: []u8, auth: TsigAuth) !tsig.Mac {
        _ = self;
        const final = (tsig.parseFinalAdditional(frame) catch return Error.EncodeFailed) orelse return Error.EncodeFailed;
        const signed = tsig.sign(
            frame,
            auth.key.secretBytes(),
            final.owner,
            final.tsig,
            auth.request_mac.slice(),
        ) catch return Error.EncodeFailed;
        tsig.patchMac(frame, final, signed.slice()) catch return Error.EncodeFailed;
        return signed;
    }

    fn answerFromUnlocked(
        self: *Runtime,
        query_bytes: []const u8,
        output: []u8,
        client: *const std.Io.net.IpAddress,
        query: dns_message.Message,
        over_tcp: bool,
    ) ![]const u8 {
        const q = query.question orelse return Error.BadQuery;
        // RFC 1996 section 3.8: a NOTIFY is answered over the transport it
        // arrived on, so it takes the same path as a query. Every other
        // opcode this server does not implement is NOTIMP (RFC 2136
        // section 3 handles UPDATE before this point).
        if (query.header.opcode == .notify) {
            return self.encodeMessage(try self.buildMessage(query, over_tcp, client), output);
        }
        if (query.header.opcode != .query) {
            return self.encodeMessage(try response.buildNotSupportedResponse(query), output);
        }
        if (query.edns) |edns| if (edns.version != dns_message.EDNS_VERSION) {
            return self.encodeMessage(try response.buildBadVersionResponse(query, q), output);
        };
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQuery;

        // RFC 9462 sections 4 and 5: `_dns.resolver.arpa.` and each known name
        // `_dns.<target>` are special-use names this resolver publishes for
        // itself, so they are answered before any zone the name falls in. A
        // QTYPE the published name does not carry is NODATA rather than a
        // forward, and a known name this server was not configured for falls
        // through without being claimed. Only class IN asks for these records.
        if (q.qclass.eql(dns_types.Class.IN) and self.ddr_rdatas.items.len != 0 and std.ascii.eqlIgnoreCase(qname_text, "_dns.resolver.arpa.")) {
            const answers: []const []const u8 = if (q.qtype.eql(.SVCB) or q.qtype.eql(.ANY)) self.ddr_rdatas.items else &.{};
            return self.encodeMessage(try response.buildDdrResponse(query, "_dns.resolver.arpa.", answers, self.ddr_ttl), output);
        }
        if (q.qclass.eql(dns_types.Class.IN)) {
            for (self.ddr_targets.items) |target| {
                if (!isKnownResolverName(&q.name, &target)) continue;
                var answers: std.ArrayList([]const u8) = .empty;
                defer answers.deinit(query.allocator);
                if (q.qtype.eql(.SVCB) or q.qtype.eql(.ANY)) {
                    for (self.ddr_targets.items, self.ddr_rdatas.items) |candidate, rdata| {
                        if (candidate.eql(&target)) try answers.append(query.allocator, rdata);
                    }
                }
                return self.encodeMessage(try response.buildDdrResponse(query, qname_text, answers.items, self.ddr_ttl), output);
            }
        }

        if (self.selectZone(qname_text) != null) {
            if (self.resolver) |*resolver| {
                const server_cookie = resolver.validateCookie(query, client) catch |err| switch (err) {
                    resolver_mod.Error.BadCookie => return self.encodeMessage(try resolver.badCookieResponse(query, client), output),
                    else => return err,
                };
                var message = try self.buildMessage(query, over_tcp, client);
                errdefer message.deinit();
                if (server_cookie) |cookie| try resolver_mod.appendCookie(&message, cookie);
                return self.encodeMessage(message, output);
            }
            return self.encodeMessage(try self.buildMessage(query, over_tcp, client), output);
        }
        if (try self.localZoneAnswer(query)) |local| return self.encodeMessage(local, output);
        if (self.blocklist.blocks(qname_text)) return self.encodeMessage(try response.buildBlockedResponse(query), output);
        if (!q.qclass.eql(@import("../dns/types.zig").Class.IN)) {
            return self.encodeMessage(try response.buildRefusedResponse(query), output);
        }
        // RFC 8914 section 4.21: a REFUSED answer to a query with the RD bit
        // clear says the server is not authoritative for the name.
        if (!query.header.recursion_desired) {
            return self.encodeMessage(try response.buildNotAuthoritativeResponse(query), output);
        }
        if (self.resolver) |*resolver| {
            if (!resolver.policy.allows(client)) return self.encodeMessage(try response.buildProhibitedResponse(query), output);
            return resolver.answer(query_bytes, query, client, output) catch |err| switch (err) {
                resolver_mod.Error.UpstreamFailure,
                resolver_mod.Error.BadUpstreamResponse,
                => self.encodeMessage(try resolver_mod.buildNetworkErrorResponse(query), output),
                resolver_mod.Error.NoForwarder => self.encodeMessage(try response.buildNotAuthoritativeResponse(query), output),
                resolver_mod.Error.EcsRefused => self.encodeMessage(try response.buildRefusedResponse(query), output),
                resolver_mod.Error.ResponseTooLarge => return Error.EncodeFailed,
                else => return err,
            };
        }
        // RFC 8914 section 4.21: the server holds no zone for the name and is
        // not configured to recurse for it.
        return self.encodeMessage(try response.buildNotAuthoritativeResponse(query), output);
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

    /// Counts the query header bits the RFCs require to be zero: the reserved
    /// Z bit (RFC 1035 section 4.1.1) and the AD bit of a query (RFC 4035
    /// section 3: a name server must ignore the setting of the AD bit in
    /// queries).
    fn countInboundBits(counters: *metrics.Counters, query: dns_message.Message) void {
        if (query.header.reserved) metrics.bump(&counters.reserved_bit_queries_total);
        if (query.header.authenticated_data) metrics.bump(&counters.ad_bit_queries_total);
    }

    pub fn answerFromWithMetrics(self: *Runtime, query_bytes: []const u8, output: []u8, client: *const std.Io.net.IpAddress, counters: *metrics.Counters) ![]const u8 {
        return self.dispatchAnswer(answerScratch(), query_bytes, output, client, counters, false);
    }

    pub fn answerWithMetrics(self: *const Runtime, query_bytes: []const u8, output: []u8, counters: *metrics.Counters) ![]const u8 {
        return @constCast(self).dispatchAnswer(answerScratch(), query_bytes, output, null, counters, true);
    }

    fn encodeMessage(self: *const Runtime, response_message: dns_message.Message, output: []u8) ![]const u8 {
        _ = self;
        var message = response_message;
        defer message.deinit();
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.EncodeFailed;
        return writer.written();
    }

    /// True when two addresses name the same host. RFC 1996 lets a master
    /// notify from any source port, so the port is not compared.
    fn sameIp(a: *const std.Io.net.IpAddress, b: *const std.Io.net.IpAddress) bool {
        return switch (a.*) {
            .ip4 => |ip| switch (b.*) {
                .ip4 => |other| std.mem.eql(u8, &ip.bytes, &other.bytes),
                .ip6 => false,
            },
            .ip6 => |ip| switch (b.*) {
                .ip4 => false,
                .ip6 => |other| std.mem.eql(u8, &ip.bytes, &other.bytes),
            },
        };
    }

    fn buildMessage(
        self: *const Runtime,
        query: dns_message.Message,
        over_tcp: bool,
        notify_source: ?*const std.Io.net.IpAddress,
    ) !dns_message.Message {
        // RFC 2136 section 3 answers an unimplemented UPDATE with NOTIMP,
        // and section 3.4.1.3 lets it carry no zone section, so the
        // refusal is built before a question is required.
        if (query.header.opcode != .query and query.header.opcode != .notify) {
            return response.buildNotSupportedResponse(query);
        }
        const q = query.question orelse return response.Error.MissingQuestion;
        if (query.header.opcode == .notify) {
            if (!transfer.isNotifyMessage(&query)) return response.buildFormerrResponse(query);
            // RFC 1996 section 3.7: the question of a NOTIFY is the zone's
            // SOA, so a question for anything else is malformed.
            if (!q.qtype.eql(dns_types.RecordType.SOA)) return response.buildFormerrResponse(query);
            // RFC 1996 section 3.7: the master hints at its new SOA in the
            // answer section, and that serial is what the zone's own is
            // compared against. A NOTIFY with an empty answer section carries
            // no hint, which is legal: the slave then asks its masters for
            // the new data.
            const notify_serial = transfer.notifySerialFromMessage(&query);
            var notify_name_buffer: [256]u8 = undefined;
            const notify_name = q.name.toText(&notify_name_buffer) catch return response.Error.BadQName;
            if (self.blocklist.blocks(notify_name)) return response.buildBlockedResponse(query);
            const zone = self.selectZone(notify_name) orelse return response.buildRefusedResponse(query);
            // RFC 9432 section 5.4: a NOTIFY for the catalog means the
            // consumer should read it again. RFC 1996 section 3.10: a NOTIFY
            // from a host that is not the zone's master is ignored, so only
            // the configured primary can start the fetch.
            if (self.catalog_consumer) |*consumer| {
                if (std.ascii.eqlIgnoreCase(consumer.apex, notify_name)) {
                    const from_master = if (notify_source) |source| sameIp(source, &consumer.primary) else false;
                    if (from_master) @constCast(self).requestCatalogRefresh();
                }
            }
            // RFC 1996 section 3.10: a NOTIFY for a served secondary asks
            // it to check its master now rather than at the next SOA
            // refresh. A null `last_success_ns` is the `refreshDecision`
            // input that is always due, so the next tick fetches instead
            // of idling or expiring; clearing `expired` keeps that tick
            // from being skipped.
            for (@constCast(self).secondary_zones.items) |*secondary| {
                if (std.ascii.eqlIgnoreCase(secondary.apex, notify_name)) {
                    secondary.last_success_ns = null;
                    secondary.expired = false;
                }
            }
            return transfer.buildNotifyResponse(query.allocator, &query, zone, notify_serial) catch return Error.EncodeFailed;
        }
        var qname_text_buffer: [256]u8 = undefined;
        const qname_text = q.name.toText(&qname_text_buffer) catch return response.Error.BadQName;
        if (self.blocklist.blocks(qname_text)) return response.buildBlockedResponse(query);
        // Zone transfers are served only as multi-frame TCP sequences through
        // encodeTransferFrames. The single-message path refuses them so a
        // partial zone can never leak through one datagram or frame.
        if (transfer.classify(q.qtype, q.qclass) != .none) return response.buildRefusedResponse(query);
        // RFC 8914 section 4.21: the server holds no zone for the name and is
        // not configured to recurse for it.
        const selected = self.selectZone(qname_text) orelse return response.buildNotAuthoritativeResponse(query);
        return response.buildResponseWithPolicy(query, selected, self.answer_policy, self.signingSession(), over_tcp);
    }

    /// The signing material of a signed zone, when there is one.
    fn signingSession(self: *const Runtime) ?*const zone_signer.Session {
        if (self.dnssec_session) |*session| return session;
        return null;
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

/// One operator-facing line about a zone replacement. A test build has no
/// operator and the test runner fails on any stderr write.
fn reportReload(io: std.Io, comptime format: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    var line_buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buffer, format, args) catch return;
    var stderr_buffer: [256]u8 = undefined;
    // The streaming writer appends at the shared file position; the
    // positional one would rewrite every line from the start of the file.
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);
    stderr_writer.interface.print("{s}\n", .{line}) catch {};
    stderr_writer.interface.flush() catch {};
}

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

test "two threads answering one authoritative query return the same bytes" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    const query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    };

    var expected: [512]u8 = undefined;
    const expected_bytes = try runtime.answer(&query, &expected);

    const Runner = struct {
        runtime: *Runtime,
        query: []const u8,
        expected: []const u8,
        failures: *std.atomic.Value(usize),

        fn run(self: @This()) void {
            var output: [512]u8 = undefined;
            var iteration: usize = 0;
            while (iteration < 100) : (iteration += 1) {
                const bytes = self.runtime.answer(self.query, &output) catch {
                    _ = self.failures.fetchAdd(1, .monotonic);
                    return;
                };
                if (!std.mem.eql(u8, bytes, self.expected)) _ = self.failures.fetchAdd(1, .monotonic);
            }
        }
    };

    var failures = std.atomic.Value(usize).init(0);
    var threads: [2]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Runner.run, .{Runner{
            .runtime = &runtime,
            .query = &query,
            .expected = expected_bytes,
            .failures = &failures,
        }});
    }
    for (threads) |thread| thread.join();

    try std.testing.expectEqual(@as(usize, 0), failures.load(.monotonic));
}

test "the runtime holds no signing key once it is deinitialized" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var key = try zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    runtime.dnssec_session = zone_signer.Session.start(&key, .{ .inception = 1_000_000_000, .expiration = 2_000_000_000 });
    try std.testing.expect(runtime.dnssec_session != null);

    // The private key is wiped with the session, so the runtime holds no
    // signing material once it is deinitialized.
    runtime.deinit();
    try std.testing.expect(runtime.dnssec_session == null);
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
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes());
}

test "runtime authenticates a key name bundled with several algorithms" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
            "key \"key.\" { algorithm hmac-sha512; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==\"; };",
    );
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

    var query = try makeSignedQueryWithKey(now, 64, sha512_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    // The reply carries the algorithm the request named and is signed with
    // the key that authenticated it, not with the first key of the name.
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha512, try tsig.algorithmForName(&response_final.tsig.algorithm));
    try std.testing.expectEqual(@as(usize, 64), response_final.tsig.macBytes().len);
    _ = try tsig.verify(response_bytes, sha512_test_key.secret, request_final.tsig.macBytes());
    try std.testing.expectError(error.BadMac, tsig.verify(response_bytes, sha256_test_key.secret, request_final.tsig.macBytes()));
}

test "runtime refuses a request whose algorithm no key of the name carries" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
            "key \"key.\" { algorithm hmac-sha512; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==\"; };",
    );
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

    var query = try makeSignedQueryWithKey(now, 20, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(u16, 17), parsed.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.TSIG.macBytes().len);
}

const reload_zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

test "a reload re-reads every configured zone file" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const first_text =
        \\$ORIGIN a.example.
        \\$TTL 3600
        \\@ IN SOA ns.a.example. hostmaster.a.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.a.example.
        \\www IN A 192.0.2.1
        \\
    ;
    const second_text =
        \\$ORIGIN b.example.
        \\$TTL 3600
        \\@ IN SOA ns.b.example. hostmaster.b.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.b.example.
        \\www IN A 192.0.2.2
        \\
    ;
    try dir.dir.writeFile(io, .{ .sub_path = "a.zone", .data = first_text });
    try dir.dir.writeFile(io, .{ .sub_path = "b.zone", .data = second_text });
    var runtime = try Runtime.fromZoneTexts(&.{ first_text, second_text });
    defer runtime.deinit();
    try runtime.setReloadSource(dir.dir, "a.zone", "a.example.");
    try runtime.addReloadSource(dir.dir, "b.zone", "b.example.");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try dir.dir.writeFile(io, .{ .sub_path = "a.zone", .data = try std.mem.replaceOwned(u8, arena.allocator(), first_text, "a.example. 1 3600", "a.example. 2 3600") });
    try dir.dir.writeFile(io, .{ .sub_path = "b.zone", .data = try std.mem.replaceOwned(u8, arena.allocator(), second_text, "b.example. 1 3600", "b.example. 2 3600") });
    runtime.requestZoneReload();
    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.reloadZoneIfRequested(io).?);
    try std.testing.expectEqual(@as(?u32, 2), runtime.zones.items[runtime.zoneIndexForOrigin("a.example.").?].soaSerial());
    try std.testing.expectEqual(@as(?u32, 2), runtime.zones.items[runtime.zoneIndexForOrigin("b.example.").?].soaSerial());

    // One broken file leaves that zone serving its old data and the other
    // zones reload.
    try dir.dir.writeFile(io, .{ .sub_path = "a.zone", .data = try std.mem.replaceOwned(u8, arena.allocator(), first_text, "a.example. 1 3600", "a.example. 3 3600") });
    try dir.dir.writeFile(io, .{ .sub_path = "b.zone", .data = "not a zone file\n" });
    runtime.requestZoneReload();
    try std.testing.expectEqual(ReloadOutcome.load_failed, runtime.reloadZoneIfRequested(io).?);
    try std.testing.expectEqual(@as(?u32, 3), runtime.zones.items[runtime.zoneIndexForOrigin("a.example.").?].soaSerial());
    try std.testing.expectEqual(@as(?u32, 2), runtime.zones.items[runtime.zoneIndexForOrigin("b.example.").?].soaSerial());
}

test "a reload adds the TSIG key the new key file names" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const now = 1_700_000_000;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{
        .sub_path = "tsig.keys",
        .data = "key \"new.\" { algorithm hmac-sha256; secret \"YWFhYWJiYmJjY2NjZGRkZGVlZWVmZmZmZ2dnZ2hoaGg=\"; };\n",
    });

    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };",
    );
    try keyring.setSource(dir.dir, "tsig.keys");
    var runtime = try Runtime.fromZoneTextWithKeyring(reload_zone_text, &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    const added = TestKey{ .algorithm = "hmac-sha256.", .secret = "aaaabbbbccccddddeeeeffffgggghhhh", .name = "new." };
    const query = try makeSignedQueryWithKey(now, 32, added);
    var output: [1024]u8 = undefined;

    // The key file is not read yet, so the key is unknown.
    var response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 17), parsed.additionals.items[0].rdata.TSIG.error_code);

    // A SIGHUP re-reads the key file as well as the zone. No zone file is
    // configured here, so the zone reload has nothing to do; the key file
    // is read all the same.
    runtime.requestZoneReload();
    try std.testing.expectEqual(ReloadOutcome.no_source, runtime.reloadZoneIfRequested(io).?);

    response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    _ = try tsig.verify(response_bytes, added.secret, request_final.tsig.macBytes());
}

test "a reload drops the TSIG key the new key file no longer names" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const now = 1_700_000_000;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{
        .sub_path = "tsig.keys",
        .data = "key \"other.\" { algorithm hmac-sha256; secret \"YWFhYWJiYmJjY2NjZGRkZGVlZWVmZmZmZ2dnZ2hoaGg=\"; };\n",
    });

    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };",
    );
    try keyring.setSource(dir.dir, "tsig.keys");
    var runtime = try Runtime.fromZoneTextWithKeyring(reload_zone_text, &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    const query = try makeSignedQuery(now, 32);
    var output: [1024]u8 = undefined;
    var response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);

    try std.testing.expectEqual(KeyReloadOutcome.replaced, runtime.reloadKeyring(io));

    response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 17), parsed.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.TSIG.macBytes().len);
}

test "a reload with a malformed key file keeps the served keys" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const now = 1_700_000_000;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "tsig.keys", .data = "this is not a key file\n" });

    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };",
    );
    try keyring.setSource(dir.dir, "tsig.keys");
    var runtime = try Runtime.fromZoneTextWithKeyring(reload_zone_text, &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    try std.testing.expectEqual(KeyReloadOutcome.load_failed, runtime.reloadKeyring(io));

    // The server keeps answering with the keys it already has.
    const query = try makeSignedQuery(now, 32);
    var output: [1024]u8 = undefined;
    var response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);

    // A key file that is gone is the same failure, and the same answer.
    try dir.dir.deleteFile(io, "tsig.keys");
    try std.testing.expectEqual(KeyReloadOutcome.load_failed, runtime.reloadKeyring(io));
    response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
}

test "a reload wipes the secrets of the keyring it replaces" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{
        .sub_path = "tsig.keys",
        .data = "key \"other.\" { algorithm hmac-sha256; secret \"YWFhYWJiYmJjY2NjZGRkZGVlZWVmZmZmZ2dnZ2hoaGg=\"; };\n",
    });

    var keyring = try keyring_mod.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
            "key \"second.\" { algorithm hmac-sha256; secret \"MTExMTIyMjIzMzMzNDQ0NDU1NTU2NjY2Nzc3Nzg4ODg=\"; };",
    );
    try keyring.setSource(dir.dir, "tsig.keys");
    var runtime = try Runtime.fromZoneTextWithKeyring(reload_zone_text, &keyring);
    defer runtime.deinit();

    try std.testing.expectEqual(KeyReloadOutcome.replaced, runtime.reloadKeyring(io));

    // The slot the replaced keyring used holds no secret any more.
    try std.testing.expectEqual(@as(usize, 1), runtime.keyring.len);
    for (runtime.keyring.keys[1].secret) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expectEqual(@as(u8, 0), runtime.keyring.keys[1].secret_len);
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
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes());
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

test "runtime answers an expired TSIG key with unsigned BADKEY" {
    const valid_now = 1_700_000_000;
    const expired_now = 1_893_456_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; expires 20300101000000; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();

    runtime.setTsigNow(valid_now);
    const before = try makeSignedQuery(valid_now, 32);
    var output: [1024]u8 = undefined;
    var response_bytes = try runtime.answer(before.packet[0..before.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);

    // The request's time_signed is the same expired instant, so only the
    // key's expiry, not the time window, is under test.
    runtime.setTsigNow(expired_now);
    const after = try makeSignedQuery(expired_now, 32);
    response_bytes = try runtime.answer(after.packet[0..after.len], &output);
    parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expectEqual(@as(u16, 17), parsed.additionals.items[0].rdata.TSIG.error_code);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.additionals.items[0].rdata.TSIG.original_id);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.items[0].rdata.TSIG.macBytes().len);
}

test "runtime signs BADTIME responses" {
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

    const query = try makeSignedQuery(request_time, 32);
    runtime.setTsigNow(request_time + 1000);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
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
    _ = try tsig.verify(response_bytes, "01234567890123456789012345678901", request_final.tsig.macBytes());
}

test "runtime answers a MAC below the policy floor with a signed BADTRUNC" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(request_time);

    // RFC 8945 section 5.2.4: a MAC that is too short for the local policy is
    // answered with a signed BADTRUNC. Eleven octets clear the section
    // 5.2.2.1 case 3 floor of ten but not the twelve-octet SHA-1 policy floor.
    const query = try makeSignedQueryWithKey(request_time, 11, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 22), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 20), response_final.tsig.macBytes().len);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    _ = try tsig.verify(response_bytes, sha1_test_key.secret, request_final.tsig.macBytes());
}

test "RFC 8945 section 5.2: a request that is out of time and short of the local MAC floor is answered BADTIME, not BADTRUNC" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(request_time + 1000);

    // RFC 8945 section 5.2: the checks run in the order key, MAC, time
    // values, truncation policy. The request is out of the fudge window and
    // its eleven-octet MAC is below the twelve-octet SHA-1 policy floor, so
    // the time check answers BADTIME before the truncation policy is applied.
    const query = try makeSignedQueryWithKey(request_time, 11, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 18), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 6), response_final.tsig.otherData().len);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    _ = try tsig.verify(response_bytes, sha1_test_key.secret, request_final.tsig.macBytes());
}

test "runtime accepts a truncated MAC and answers with a MAC at least as long" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(request_time);

    // RFC 8945 section 4.2: the MAC Size gives the length of the MAC field, so
    // a twelve-octet truncation of the SHA-1 MAC authenticates the request.
    const query = try makeSignedQueryWithKey(request_time, 12, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])).?;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(usize, 12), request_final.tsig.macBytes().len);
    // RFC 8945 section 7: the reply MAC is at least as long as the request's.
    try std.testing.expect(response_final.tsig.macBytes().len >= request_final.tsig.macBytes().len);
    try std.testing.expectEqual(@as(usize, 20), response_final.tsig.macBytes().len);
    _ = try tsig.verify(response_bytes, sha1_test_key.secret, request_final.tsig.macBytes());
}

test "runtime rejects a MAC longer than the keyed hash output" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(request_time);

    // RFC 8945 section 5.2.2.1 case 1: a MAC Size above the keyed hash
    // output length is a format error.
    const query = try makeSignedQueryWithKey(request_time, 21, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
}

test "runtime rejects a zero-length MAC" {
    const request_time = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(request_time);

    // RFC 8945 section 5.2.2.1 case 3: a MAC Size of zero is the unsigned
    // case and never authenticates a request.
    const query = try makeSignedQueryWithKey(request_time, 0, sha1_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
}

test "runtime rejects oversize MAC without overflowing copyMac" {
    var oversize = @as([65]u8, @splat(@as(u8, 0xab)));
    try std.testing.expect(Runtime.copyMac(&oversize) == null);

    var exact = @as([64]u8, @splat(@as(u8, 0xcd)));
    const mac = Runtime.copyMac(&exact).?;
    try std.testing.expectEqual(@as(u8, 64), mac.len);
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

/// The key material a test request is signed with, matched by the keyring the
/// runtime is built from.
const TestKey = struct {
    algorithm: []const u8,
    secret: []const u8,
    /// The TSIG key name the request names.
    name: []const u8 = "key.",
};

const sha256_test_key = TestKey{ .algorithm = "hmac-sha256.", .secret = "01234567890123456789012345678901" };
const sha1_test_key = TestKey{ .algorithm = "hmac-sha1.", .secret = "01234567890123456789" };
const sha512_test_key = TestKey{ .algorithm = "hmac-sha512.", .secret = "0123456789012345678901234567890123456789012345678901234567890123" };

fn makeSignedQuery(time_signed: u64, mac_len: usize) !SignedQuery {
    return makeSignedQueryWithEdnsOption(time_signed, mac_len, false);
}

fn makeSignedQueryWithEdns(time_signed: u64, mac_len: usize) !SignedQuery {
    return makeSignedQueryWithEdnsOption(time_signed, mac_len, true);
}

/// One question on the wire: dns.home.arpa. A IN.
const signed_question_wire = [_]u8{
    3,   'd', 'n', 's',  4,    'h',  'o',  'm', 'e', 4, 'a', 'r',
    'p', 'a', 0,   0x00, 0x01, 0x00, 0x01,
};

fn makeSignedQueryWithEdnsOption(time_signed: u64, mac_len: usize, include_edns: bool) !SignedQuery {
    return makeSignedQueryWithQuestions(time_signed, mac_len, include_edns, 1, &signed_question_wire, sha256_test_key);
}

fn makeSignedQueryWithKey(time_signed: u64, mac_len: usize, key: TestKey) !SignedQuery {
    return makeSignedQueryWithQuestions(time_signed, mac_len, false, 1, &signed_question_wire, key);
}

/// Builds a TSIG-signed query carrying `question_count` questions.
fn makeSignedQueryWithQuestions(
    time_signed: u64,
    mac_len: usize,
    include_edns: bool,
    question_count: u16,
    questions: []const u8,
    key: TestKey,
) !SignedQuery {
    const algorithm = try @import("../dns/name.zig").Name.fromText(key.algorithm);
    const owner = try @import("../dns/name.zig").Name.fromText(key.name);
    const root = @import("../dns/name.zig").Name.root();
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    const additional_count: u16 = if (include_edns) 2 else 1;
    try writer.writeBytes(&.{ 0x12, 0x34, 0x01, 0x00 });
    try writer.writeU16(question_count);
    try writer.writeBytes(&.{ 0x00, 0x00, 0x00, 0x00 });
    try writer.writeU16(additional_count);
    const question_start = writer.len();
    try writer.writeBytes(questions);
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
    var zeros: [64]u8 = @splat(0);
    const value = try @import("../dns/rdata.zig").Tsig.init(algorithm, time_signed, 300, zeros[0..mac_len], 0x1234, 0, &.{});
    try (@import("../dns/record.zig").ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const signed = try tsig.sign(writer.written(), key.secret, final.owner, final.tsig, null);
    // The digest never covers the MAC field, so a request can also carry a MAC
    // longer than the keyed hash output; the extra octets stay zero.
    var mac_bytes: [64]u8 = @splat(0);
    const copied = @min(mac_len, signed.slice().len);
    @memcpy(mac_bytes[0..copied], signed.slice()[0..copied]);
    try tsig.patchMac(packet[0..writer.len()], final, mac_bytes[0..mac_len]);
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
test "RFC 6891: an OPT whose option overruns RDLENGTH is answered FORMERR" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    defer runtime.deinit();

    // One OPT, ARCOUNT 1, RDLENGTH 4, but the option header claims 10 data
    // octets that are not there: EdnsOptionsTooLong, a format error.
    const overrun_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x0a,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53114);
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answerFrom(&overrun_query, &output, &client);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(parsed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .formerr), parsed.header.rcode);
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

test "RFC 9619: a TSIG-signed OPCODE 0 query with QDCOUNT 2 is answered FORMERR" {
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

    // The signed path strips the TSIG record and parses the rest, so the
    // QDCOUNT > 1 rejection has to hold there too, not only on the
    // unsigned path.
    const two_questions = [_]u8{
        3,    'd',  'n',  's',  4,    'h',  'o',  'm', 'e', 4,   'a', 'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 5,   'a', 'l', 'i', 'a',
        's',  4,    'h',  'o',  'm',  'e',  4,    'a', 'r', 'p', 'a', 0,
        0x00, 0x01, 0x00, 0x01,
    };
    const query = try makeSignedQueryWithQuestions(now, 32, false, 2, &two_questions, sha256_test_key);
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, query.packet[4..6], .big));
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.packet[0..query.len], &output);

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

test "authoritative runtime records metrics for successful, bad, and bit-flagged queries" {
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

    try std.testing.expectEqual(@as(u64, 2), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.bad_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.encode_failures_total.load(.monotonic));
    // A query that carries neither bit leaves the inbound-bit counters alone.
    try std.testing.expectEqual(@as(u64, 0), counters.reserved_bit_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.ad_bit_queries_total.load(.monotonic));

    // RFC 1035 section 4.1.1: the reserved Z bit must be zero in a query, so
    // a query that carries it is counted on the network answer path.
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53005);
    _ = try runtime.answerFromWithMetrics(&.{
        0x12, 0x34, 0x01, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &client, &counters);
    // RFC 4035 section 3: the AD bit of a query must be ignored, so a query
    // that carries it is counted on the stream answer path.
    _ = try runtime.answerWithMetrics(&.{
        0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &counters);

    try std.testing.expectEqual(@as(u64, 1), counters.reserved_bit_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.ad_bit_queries_total.load(.monotonic));

    var metrics_output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer metrics_output.deinit();
    try @import("../metrics.zig").formatPrometheus(counters, &metrics_output.writer);
    const text = metrics_output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_reserved_bit_queries_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_ad_bit_queries_total 1\n") != null);
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

test "a blocklisted name is answered REFUSED with the RFC 8914 Blocked EDE code" {
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

    // The query carries an OPT pseudo-RR and no DO bit: RFC 8914 section 2
    // allows the EDE option in any response to such a query.
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    // RFC 8914 section 4.16: INFO-CODE 15 is "Blocked", and the EXTRA-TEXT
    // says why: the operator's policy refused the name.
    const ede = @import("../dns/rdata.zig").findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0f }, ede.?[0..2]);
    try std.testing.expectEqualStrings("blocked by policy", ede.?[2..]);
}

test "a blocklisted name without EDNS is refused without an EDE option" {
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

    // RFC 8914 section 2 allows the EDE option only in a response to a query
    // that includes an OPT pseudo-RR, and this query carries none.
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expect(parsed.edns == null);
}

test "a query the server is not authoritative for is refused with the RFC 8914 Not Authoritative EDE code" {
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

    // The query carries an OPT pseudo-RR, so RFC 8914 section 2 allows the
    // EDE option in the answer.
    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29,
        0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, &output, &client);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    // RFC 8914 section 4.21: INFO-CODE 20 is "Not Authoritative", and the
    // EXTRA-TEXT says why: the server holds no zone for the name and is not
    // configured to recurse for it.
    const ede = dns_rdata.findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x14 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("not authoritative for this name", ede.?[2..]);
}

test "a query the server is not authoritative for without EDNS is refused without an EDE option" {
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

    // RFC 8914 section 2 allows the EDE option only in a response to a query
    // that includes an OPT pseudo-RR, and this query carries none.
    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &client);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expect(parsed.edns == null);
}

test "a query with the RD bit clear is refused with the RFC 8914 Not Authoritative EDE code" {
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

    // The RD bit is clear and the query carries an OPT pseudo-RR, so RFC 8914
    // section 4.21 asks for the Not Authoritative code in the refusal.
    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29,
        0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, &output, &client);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    const ede = dns_rdata.findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x14 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("not authoritative for this name", ede.?[2..]);
}

test "the Not Authoritative EDE option rides on a query that asked for the DO bit" {
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

    // The OPT record asks for the DO bit, and the EDE option rides on it: the
    // two are independent, and the refusal carries the code either way.
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29,
        0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    const ede = dns_rdata.findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x14 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("not authoritative for this name", ede.?[2..]);
}

test "a client outside the recursion ACL is refused with the RFC 8914 Prohibited EDE code" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The operator's recursion ACL serves one network; the client below is
    // outside it, so the refusal is the policy's and not the server's.
    var policy = resolver_mod.Policy{};
    policy.recursion_allow[0] = try @import("../config/parser.zig").Cidr.parse("192.0.2.0/24");
    policy.recursion_allow_len = 1;
    var zones = std.ArrayList(zone_index.Zone).empty;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    // The query carries an OPT pseudo-RR, so RFC 8914 section 2 allows the
    // EDE option in the answer.
    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29,
        0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, &output, &client);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    // RFC 8914 section 4.19: INFO-CODE 18 is "Prohibited", and the EXTRA-TEXT
    // says why: the operator's recursion policy refused the client.
    const ede = dns_rdata.findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x12 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("prohibited by policy", ede.?[2..]);
}

test "a client outside the recursion ACL without EDNS is refused without an EDE option" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var policy = resolver_mod.Policy{};
    policy.recursion_allow[0] = try @import("../config/parser.zig").Cidr.parse("192.0.2.0/24");
    policy.recursion_allow_len = 1;
    var zones = std.ArrayList(zone_index.Zone).empty;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    // RFC 8914 section 2 allows the EDE option only in a response to a query
    // that includes an OPT pseudo-RR, and this query carries none.
    var output: [512]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("198.51.100.7", 41002);
    const response_bytes = try runtime.answerFrom(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'o',  'u',  't',  's',  'i',  'd',  'e',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0,    0x00, 0x01, 0x00, 0x01,
    }, &output, &client);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expect(parsed.edns == null);
}

test "a refused transfer carries no EDE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    );
    defer runtime.deinit();

    // The transfer is refused by the single-message path, and that refusal
    // names no policy, so it carries no EDE option.
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0xfc, 0x00,
        0x01, 0,    0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, &output);

    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    try std.testing.expectEqual(@as(usize, 0), opt.rdata.OPT.bytes().len);
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

test "an unsupported opcode is NOTIMP with EDE 21 when the query had EDNS" {
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
        0x12, 0x34, 0x18, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
        0x06, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    }, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.notimp, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    // RFC 8914 section 4.22: INFO-CODE 21 is "Not Supported".
    const ede = @import("../dns/rdata.zig").findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x15 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("operation not supported", ede.?[2..]);
}

test "an unsupported opcode without EDNS is NOTIMP without an EDE option" {
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
        0x12, 0x35, 0x18, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
        0x06, 0x00, 0x01,
    }, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.notimp, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
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

/// A TSIG-signed RFC 2136 UPDATE: the zone section, one prerequisite set and
/// the update records, then the TSIG record the request is signed with.
fn encodeSignedUpdateRequest(
    allocator: std.mem.Allocator,
    buffer: []u8,
    zone: []const u8,
    prerequisites: []const dns_record_mod.ResourceRecord,
    updates: []const dns_record_mod.ResourceRecord,
    time_signed: u64,
    key: TestKey,
) ![]const u8 {
    const dns_name = @import("../dns/name.zig");
    var request = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = 0x7777,
            .opcode = .update,
            .question_count = 1,
            .answer_count = @intCast(prerequisites.len),
            .authority_count = @intCast(updates.len),
            .additional_count = 1,
        },
        .question = .{
            .name = try dns_name.Name.fromText(zone),
            .qtype = dns_types.RecordType.SOA,
            .qclass = dns_types.Class.IN,
        },
        .answers = try dns_message.RecordSection.init(allocator, prerequisites.len),
        .authorities = try dns_message.RecordSection.init(allocator, updates.len),
        .additionals = try dns_message.RecordSection.init(allocator, 1),
    };
    for (prerequisites) |record| try request.answers.append(record);
    for (updates) |record| try request.authorities.append(record);
    var zeros: [64]u8 = @splat(0);
    const value = try dns_rdata.Tsig.init(
        try dns_name.Name.fromText(key.algorithm),
        time_signed,
        300,
        zeros[0..32],
        0x7777,
        0,
        &.{},
    );
    try request.additionals.append(.{
        .owner = try dns_name.Name.fromText(key.name),
        .rrtype = dns_types.RecordType.TSIG,
        .class = dns_types.Class.ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    });
    var writer = dns_writer.Writer.init(buffer);
    try request.encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const signed = try tsig.sign(writer.written(), key.secret, final.owner, final.tsig, null);
    try tsig.patchMac(buffer[0..writer.len()], final, signed.slice());
    return writer.written();
}

/// Builds one OPCODE 0, RD-set query so a DDR test can name any target without
/// hand-writing its wire form.
fn encodeDdrQuery(allocator: std.mem.Allocator, buffer: []u8, name: []const u8, qtype: dns_types.RecordType) ![]const u8 {
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4444, .opcode = .query, .recursion_desired = true, .question_count = 1 },
        .question = .{
            .name = try dns_name_mod.Name.fromText(name),
            .qtype = qtype,
            .qclass = dns_types.Class.IN,
        },
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
    };
    defer message.deinit();
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

test "the resolver publishes RFC 9461 SVCB records at _dns.resolver.arpa" {
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN one.example.
        \\$TTL 3600
        \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.one.example.
        \\
    , &keyring);
    defer runtime.deinit();
    try runtime.addDdrRecord("dns.example.", "dot", 853, null);
    try runtime.addDdrRecord("dns.example.", "h2", 443, "/dns-query{?dns}");
    try std.testing.expectEqual(@as(usize, 2), runtime.ddr_rdatas.items.len);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const client = try std.Io.net.IpAddress.parse("192.0.2.1", 5555);

    // _dns.resolver.arpa. SVCB
    const svcb_query = [_]u8{
        0x44, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    '_',  'd',  'n',  's',  8,    'r',  'e',  's',  'o',  'l',  'v',
        'e',  'r',  4,    'a',  'r',  'p',  'a',  0,    0x00, 0x40, 0x00, 0x01,
    };
    var output: [1024]u8 = undefined;
    const svcb_response = try runtime.answerFrom(&svcb_query, &output, &client);
    const svcb = try dns_message.Message.parse(arena.allocator(), svcb_response);
    try std.testing.expectEqual(@as(u16, 2), svcb.header.answer_count);
    try std.testing.expectEqual(@as(@TypeOf(svcb.header.rcode), .no_error), svcb.header.rcode);
    try std.testing.expect(svcb.answers.items[0].rrtype.eql(.SVCB));
    const target_buffer = svcb.answers.items[0].rdata.SVCB.target.toText(&output) catch return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("dns.example.", target_buffer);
    try std.testing.expect(svcb.answers.items[0].rdata.SVCB.paramsBytes().len != 0);

    // The same name with a QTYPE it does not carry is NODATA, not a forward.
    const a_query = [_]u8{
        0x44, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4,    '_',  'd',  'n',  's',  8,    'r',  'e',  's',  'o',  'l',  'v',
        'e',  'r',  4,    'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    };
    const a_response = try runtime.answerFrom(&a_query, &output, &client);
    const a_answer = try dns_message.Message.parse(arena.allocator(), a_response);
    try std.testing.expectEqual(@as(@TypeOf(a_answer.header.rcode), .no_error), a_answer.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), a_answer.header.answer_count);
}

test "RFC 9462 section 5 known names answer with their own target's records" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN one.example.
        \\$TTL 3600
        \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.one.example.
        \\
    );
    defer runtime.deinit();
    try runtime.addDdrRecord("one.example.", "dot", 853, null);
    try runtime.addDdrRecord("two.example.", "h2", 443, "/two{?dns}");
    try runtime.addDdrRecord("one.example.", "h2", 443, "/one{?dns}");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const client = try std.Io.net.IpAddress.parse("192.0.2.1", 5555);
    var query_buffer: [512]u8 = undefined;
    var output: [1024]u8 = undefined;
    var text_buffer: [256]u8 = undefined;

    // `one.example.` is a served zone, so NOERROR with two answers proves the
    // known name is answered before the zone path sees `_dns.one.example.`.
    const one_name = try dns_name_mod.Name.fromText("_dns.one.example.");
    const one_query = try encodeDdrQuery(arena.allocator(), &query_buffer, "_dns.one.example.", .SVCB);
    const one = try dns_message.Message.parse(arena.allocator(), try runtime.answerFrom(one_query, &output, &client));
    try std.testing.expectEqual(@as(u16, 2), one.header.answer_count);
    for (one.answers.items) |record| {
        try std.testing.expect(record.rrtype.eql(.SVCB));
        try std.testing.expect(record.owner.eql(&one_name));
        const target = try record.rdata.SVCB.target.toText(&text_buffer);
        try std.testing.expectEqualStrings("one.example.", target);
    }

    // The other target answers at its own name, and the match folds case.
    const two_name = try dns_name_mod.Name.fromText("_dns.two.example.");
    const two_query = try encodeDdrQuery(arena.allocator(), &query_buffer, "_DNS.TWO.EXAMPLE.", .SVCB);
    const two = try dns_message.Message.parse(arena.allocator(), try runtime.answerFrom(two_query, &output, &client));
    try std.testing.expectEqual(@as(u16, 1), two.header.answer_count);
    try std.testing.expect(two.answers.items[0].owner.eql(&two_name));
    const two_target = try two.answers.items[0].rdata.SVCB.target.toText(&text_buffer);
    try std.testing.expectEqualStrings("two.example.", two_target);

    // A QTYPE the known name does not carry is NODATA, not a forward. The zone
    // would answer NXDOMAIN for the same query name, so NOERROR proves the DDR
    // path answered it.
    const a_query = try encodeDdrQuery(arena.allocator(), &query_buffer, "_dns.one.example.", .A);
    const a = try dns_message.Message.parse(arena.allocator(), try runtime.answerFrom(a_query, &output, &client));
    try std.testing.expectEqual(@as(@TypeOf(a.header.rcode), .no_error), a.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), a.header.answer_count);
}

test "RFC 9462 section 5 does not claim a known name this server was not configured for" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN one.example.
        \\$TTL 3600
        \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.one.example.
        \\
    );
    defer runtime.deinit();
    try runtime.addDdrRecord("one.example.", "dot", 853, null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const client = try std.Io.net.IpAddress.parse("192.0.2.1", 5555);
    var query_buffer: [512]u8 = undefined;
    var output: [1024]u8 = undefined;

    // No resolver is configured, so the fall-through answer is the server's
    // not-authoritative refusal, never a DDR NODATA.
    const query = try encodeDdrQuery(arena.allocator(), &query_buffer, "_dns.unknown.example.", .SVCB);
    const answer = try dns_message.Message.parse(arena.allocator(), try runtime.answerFrom(query, &output, &client));
    try std.testing.expectEqual(@as(@TypeOf(answer.header.rcode), .refused), answer.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), answer.header.answer_count);
    try std.testing.expect(!answer.header.authoritative);
}

test "a signed update sends an RFC 1996 NOTIFY to the configured secondary" {
    const io = std.Io.Threaded.global_single_threaded.io();
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

    // The secondary the master announces to: a loopback socket the test reads.
    var secondary_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var secondary = try std.Io.net.IpAddress.bind(&secondary_address, io, .{ .mode = .dgram, .protocol = .udp });
    defer secondary.close(io);
    const port = switch (secondary.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    try runtime.addNotifyTarget("home.arpa.", try std.Io.net.IpAddress.parse("127.0.0.1", port));
    // A target for another zone is never told about this one.
    try runtime.addNotifyTarget("other.arpa.", try std.Io.net.IpAddress.parse("127.0.0.1", port));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try runtime.setUpdatePolicy(tmp.dir, "home.arpa.", "key.", "zone.db");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [1024]u8 = undefined;
    var updates = [_]dns_record_mod.ResourceRecord{.{
        .owner = try dns_name_mod.Name.fromText("www.home.arpa."),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 168, 1, 9 } },
    }};
    const request = try encodeSignedUpdateRequest(arena.allocator(), &request_buffer, "home.arpa.", &.{}, &updates, now, .{
        .algorithm = "hmac-sha256.",
        .secret = "01234567890123456789012345678901",
    });
    var output: [1024]u8 = undefined;
    _ = try runtime.answer(request, &output);

    // RFC 1996 section 4.3: a NOTIFY with the question's SOA and the zone's
    // SOA, carrying the serial the update produced.
    var notify_buffer: [1024]u8 = undefined;
    const incoming = secondary.receiveTimeout(io, &notify_buffer, .{ .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake } }) catch return error.TestUnexpectedResult;
    const notify = try dns_message.Message.parse(arena.allocator(), incoming.data);
    try std.testing.expectEqual(@as(@TypeOf(notify.header.opcode), .notify), notify.header.opcode);
    try std.testing.expect(!notify.header.qr);
    try std.testing.expect(notify.header.authoritative);
    try std.testing.expectEqual(@as(u16, 1), notify.header.question_count);
    try std.testing.expectEqual(@as(u16, 1), notify.header.answer_count);
    try std.testing.expect(notify.question.?.name.eql(&try dns_name_mod.Name.fromText("home.arpa.")));
    try std.testing.expect(notify.answers.items[0].rrtype.eql(.SOA));
    const soa = notify.answers.items[0].rdata.SOA;
    try std.testing.expectEqual(@as(u32, 2), soa.serial);

    // Exactly one datagram: the other zone's target hears nothing.
    var extra: [1024]u8 = undefined;
    try std.testing.expectError(error.Timeout, secondary.receiveTimeout(io, &extra, .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } }));
}

test "runtime applies a signed RFC 2136 update and persists the zone" {
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

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try runtime.setUpdatePolicy(tmp.dir, "home.arpa.", "key.", "zone.db");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [1024]u8 = undefined;
    var updates = [_]dns_record_mod.ResourceRecord{.{
        .owner = try dns_name_mod.Name.fromText("www.home.arpa."),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 168, 1, 9 } },
    }};
    const request = try encodeSignedUpdateRequest(arena.allocator(), &request_buffer, "home.arpa.", &.{}, &updates, now, .{
        .algorithm = "hmac-sha256.",
        .secret = "01234567890123456789012345678901",
    });

    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(request, &output);
    const update_response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(update_response.header.rcode), .no_error), update_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), update_response.header.question_count);
    try std.testing.expect((try tsig.parseFinalAdditional(response_bytes)) != null);

    // The added record answers, and the serial moved.
    var query_buffer: [256]u8 = undefined;
    var query = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x2222, .opcode = .query, .recursion_desired = true, .question_count = 1 },
        .question = .{
            .name = try dns_name_mod.Name.fromText("www.home.arpa."),
            .qtype = dns_types.RecordType.A,
            .qclass = dns_types.Class.IN,
        },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
    };
    defer query.deinit();
    var query_writer = dns_writer.Writer.init(&query_buffer);
    try query.encode(&query_writer);
    const answer_bytes = try runtime.answer(query_writer.written(), &output);
    const answer = try dns_message.Message.parse(arena.allocator(), answer_bytes);
    try std.testing.expectEqual(@as(u16, 1), answer.header.answer_count);
    try std.testing.expectEqual(@as(u8, 192), answer.answers.items[0].rdata.A[0]);
    try std.testing.expectEqual(@as(u8, 9), answer.answers.items[0].rdata.A[3]);
    try std.testing.expectEqual(@as(u32, 2), runtime.zones.items[0].soaSerial().?);

    // RFC 2136 section 3.5: the change was written before the response.
    const persisted = try tmp.dir.readFileAlloc(runtime.io, "zone.db", std.testing.allocator, .limited(1 << 20));
    defer std.testing.allocator.free(persisted);
    try std.testing.expect(std.mem.indexOf(u8, persisted, "www.home.arpa.") != null);
}

test "runtime refuses an unsigned or wrongly keyed RFC 2136 update" {
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
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try runtime.setUpdatePolicy(tmp.dir, "home.arpa.", "key.", "zone.db");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var updates = [_]dns_record_mod.ResourceRecord{.{
        .owner = try dns_name_mod.Name.fromText("www.home.arpa."),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 168, 1, 9 } },
    }};
    var update_message = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x7778, .opcode = .update, .question_count = 1, .authority_count = 1 },
        .question = .{
            .name = try dns_name_mod.Name.fromText("home.arpa."),
            .qtype = dns_types.RecordType.SOA,
            .qclass = dns_types.Class.IN,
        },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 1),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
    };
    defer update_message.deinit();
    for (updates) |record| try update_message.authorities.append(record);
    var request_buffer: [1024]u8 = undefined;
    var writer = dns_writer.Writer.init(&request_buffer);
    try update_message.encode(&writer);
    var output: [1024]u8 = undefined;
    const unsigned = try runtime.answer(writer.written(), &output);
    const unsigned_response = try dns_message.Message.parse(arena.allocator(), unsigned);
    try std.testing.expectEqual(@as(@TypeOf(unsigned_response.header.rcode), .refused), unsigned_response.header.rcode);

    var wrong_key_buffer: [1024]u8 = undefined;
    const wrong_key_request = try encodeSignedUpdateRequest(arena.allocator(), &wrong_key_buffer, "home.arpa.", &.{}, &updates, now, .{
        .algorithm = "hmac-sha256.",
        .secret = "abcdefghijklmnopqrstuvwxyz012345",
        .name = "other.",
    });
    // The keyring does not hold "other.", so the request is refused before any
    // zone change.
    const wrong = try runtime.answer(wrong_key_request, &output);
    const wrong_response = try dns_message.Message.parse(arena.allocator(), wrong);
    try std.testing.expectEqual(@as(@TypeOf(wrong_response.header.rcode), .notauth), wrong_response.header.rcode);
}

test "authoritative runtime answers RFC 2136 UPDATE with NOTIMP" {
    const dns_name = @import("../dns/name.zig");
    const dns_record = @import("../dns/record.zig");

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
test "a secondary forwards a signed RFC 2136 update to its primary" {
    // The fixture runs a primary on its own thread. The two sides get
    // separate threaded Io backends so a blocked accept and a blocked client
    // poll cannot starve each other under a loaded test gate.
    var server_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer server_threaded.deinit();
    const server_io = server_threaded.io();
    var client_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer client_threaded.deinit();
    const io = client_threaded.io();
    const now = 1_700_000_000;
    const zone_text =
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    ;
    var primary_keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var primary = try Runtime.fromZoneTextWithKeyring(zone_text, &primary_keyring);
    defer primary.deinit();
    primary.io = server_io;
    primary.setTsigNow(now);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try primary.setUpdatePolicy(tmp.dir, "home.arpa.", "key.", "zone.db");
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, server_io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 4 });
    defer listener.deinit(server_io);
    const port = switch (listener.socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    var secondary_keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var secondary = try Runtime.fromZoneTextWithKeyring(zone_text, &secondary_keyring);
    defer secondary.deinit();
    secondary.io = io;
    secondary.setTsigNow(now);
    try secondary.secondary_zones.append(secondary.allocator, .{
        .apex = try secondary.allocator.dupe(u8, "home.arpa."),
        .primary = try std.Io.net.IpAddress.parse("127.0.0.1", port),
    });
    const ServerArgs = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        runtime: *Runtime,
        ready: *std.atomic.Value(bool),
    };
    const Server = struct {
        fn run(args: ServerArgs) void {
            args.ready.store(true, .release);
            var connection = args.listener.accept(args.io) catch return;
            defer connection.close(args.io);
            var length_bytes: [2]u8 = undefined;
            readExact(connection, args.io, &length_bytes) catch return;
            const length = std.mem.readInt(u16, &length_bytes, .big);
            var request_buffer: [65535]u8 = undefined;
            readExact(connection, args.io, request_buffer[0..length]) catch return;
            var response_buffer: [65535]u8 = undefined;
            const response_bytes = args.runtime.answerFromTcp(request_buffer[0..length], &response_buffer, &connection.socket.address, null) catch return;
            var prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
            writeAll(connection, args.io, &prefix) catch return;
            writeAll(connection, args.io, response_bytes) catch return;
        }
        fn readExact(stream: std.Io.net.Stream, stream_io: std.Io, buffer: []u8) !void {
            var read_buffer: [4096]u8 = undefined;
            var reader = stream.reader(stream_io, &read_buffer);
            try reader.interface.readSliceAll(buffer);
        }
        fn writeAll(stream: std.Io.net.Stream, stream_io: std.Io, bytes: []const u8) !void {
            var write_buffer: [4096]u8 = undefined;
            var writer = stream.writer(stream_io, &write_buffer);
            try writer.interface.writeAll(bytes);
            try writer.interface.flush();
        }
    };
    var ready = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, Server.run, .{ServerArgs{ .io = server_io, .listener = &listener, .runtime = &primary, .ready = &ready }});
    defer thread.join();
    while (!ready.load(.acquire)) std.Thread.yield() catch {};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [1024]u8 = undefined;
    var updates = [_]dns_record_mod.ResourceRecord{.{
        .owner = try dns_name_mod.Name.fromText("www.home.arpa."),
        .rrtype = dns_types.RecordType.A,
        .class = dns_types.Class.IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 168, 1, 9 } },
    }};
    const request = try encodeSignedUpdateRequest(arena.allocator(), &request_buffer, "home.arpa.", &.{}, &updates, now, .{
        .algorithm = "hmac-sha256.",
        .secret = "01234567890123456789012345678901",
    });
    var output: [1024]u8 = undefined;
    const response_bytes = try secondary.answer(request, &output);
    const forwarded = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(forwarded.header.rcode), .no_error), forwarded.header.rcode);
    try std.testing.expect((try tsig.parseFinalAdditional(response_bytes)) != null);
    // The primary owns the write: its serial moved and it serves the record.
    try std.testing.expectEqual(@as(u32, 2), primary.zones.items[0].soaSerial().?);
    var primary_lookup = primary.zones.items[0].lookup(std.testing.allocator, "www.home.arpa.", .A);
    defer primary_lookup.deinit(std.testing.allocator);
    try std.testing.expectEqual(zone_index.LookupKind.answer, primary_lookup.kind);
    // The secondary's served copy is unchanged until refresh.
    try std.testing.expectEqual(@as(u32, 1), secondary.zones.items[0].soaSerial().?);
    var secondary_lookup = secondary.zones.items[0].lookup(std.testing.allocator, "www.home.arpa.", .A);
    defer secondary_lookup.deinit(std.testing.allocator);
    try std.testing.expect(secondary_lookup.kind != zone_index.LookupKind.answer);
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

fn findKeepaliveOption(message: dns_message.Message) ?[]const u8 {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return dns_rdata.findOption(record.rdata.OPT.bytes(), dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE);
    }
    return null;
}

test "RFC 7828: a TCP query with the keepalive option is answered with it, the same query over UDP is not" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\www IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();

    // A query whose OPT record carries the empty edns-tcp-keepalive option of
    // RFC 7828 section 3.2.1.
    const keepalive_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'w',  'w',  'w',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53004);
    var output: [512]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Section 3.3.2: the answer carries the idle timeout the server applies,
    // counted in units of 100 milliseconds.
    const tcp_bytes = try runtime.answerFromTcp(&keepalive_query, &output, &client, null);
    const tcp_response = try dns_message.Message.parse(arena.allocator(), tcp_bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 50 }, findKeepaliveOption(tcp_response).?);

    // Section 3.3.1: the option in a UDP query is ignored.
    const udp_bytes = try runtime.answerFrom(&keepalive_query, &output, &client);
    const udp_response = try dns_message.Message.parse(arena.allocator(), udp_bytes);
    try std.testing.expect(findKeepaliveOption(udp_response) == null);
}

test "RFC 8482: the minimal ANY TTL follows the transport the query arrived over" {
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\www IN A 192.168.1.1
        \\
    );
    defer runtime.deinit();
    runtime.answer_policy.minimal_any_ttl = 300;
    runtime.answer_policy.minimal_any_ttl_tcp = 3600;

    // A QTYPE=ANY query for an owner the zone carries.
    const any_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0xff, 0x00, 0x01,
    };
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 53004);
    var output: [512]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The same query over UDP and over TCP carries the TTL of its transport.
    const udp_bytes = try runtime.answerFrom(&any_query, &output, &client);
    const udp_response = try dns_message.Message.parse(arena.allocator(), udp_bytes);
    try std.testing.expectEqual(@as(u32, 300), udp_response.answers.items[0].ttl);

    const tcp_bytes = try runtime.answerFromTcp(&any_query, &output, &client, null);
    const tcp_response = try dns_message.Message.parse(arena.allocator(), tcp_bytes);
    try std.testing.expectEqual(@as(u32, 3600), tcp_response.answers.items[0].ttl);
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

/// A NOTIFY request for `qname` whose answer section hints at an SOA with
/// the given serial, the shape a master sends (RFC 1996 section 4.5). A null
/// serial leaves the answer section empty.
fn encodeNotifyRequest(
    allocator: std.mem.Allocator,
    buffer: []u8,
    qname: []const u8,
    serial: ?u32,
    qtype: dns_types.RecordType,
) ![]const u8 {
    const dns_name = @import("../dns/name.zig");
    const owner = try dns_name.Name.fromText(qname);
    var request = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4321, .opcode = .notify, .question_count = 1 },
        .question = .{ .name = owner, .qtype = qtype, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
    };
    if (serial) |value| {
        request.header.answer_count = 1;
        try request.answers.append(.{
            .owner = owner,
            .rrtype = .SOA,
            .class = .IN,
            .ttl = 3600,
            .rdata = .{ .SOA = .{
                .mname = try dns_name.Name.fromText("ns.example."),
                .rname = try dns_name.Name.fromText("hostmaster.example."),
                .serial = value,
                .refresh = 3600,
                .retry = 900,
                .expire = 1209600,
                .minimum = 3600,
            } },
        });
    }
    var writer = dns_writer.Writer.init(buffer);
    try request.encode(&writer);
    return writer.written();
}

/// The NOTIFY of `encodeNotifyRequest` with a TSIG the request is signed
/// with, the shape a master that authenticates its NOTIFYs sends.
fn encodeSignedNotifyRequest(
    allocator: std.mem.Allocator,
    buffer: []u8,
    qname: []const u8,
    serial: u32,
    time_signed: u64,
    key: TestKey,
) ![]const u8 {
    const dns_name = @import("../dns/name.zig");
    const owner = try dns_name.Name.fromText(qname);
    var request = dns_message.Message{
        .allocator = allocator,
        .header = .{
            .id = 0x4321,
            .opcode = .notify,
            .question_count = 1,
            .answer_count = 1,
            .additional_count = 1,
        },
        .question = .{ .name = owner, .qtype = .SOA, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(allocator, 1),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 1),
    };
    try request.answers.append(.{
        .owner = owner,
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns.example."),
            .rname = try dns_name.Name.fromText("hostmaster.example."),
            .serial = serial,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    });
    var zeros: [64]u8 = @splat(0);
    const value = try @import("../dns/rdata.zig").Tsig.init(
        try dns_name.Name.fromText(key.algorithm),
        time_signed,
        300,
        zeros[0..32],
        0x4321,
        0,
        &.{},
    );
    try request.additionals.append(.{
        .owner = try dns_name.Name.fromText(key.name),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    });
    var writer = dns_writer.Writer.init(buffer);
    try request.encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const signed = try tsig.sign(writer.written(), key.secret, final.owner, final.tsig, null);
    try tsig.patchMac(buffer[0..writer.len()], final, signed.slice());
    return writer.written();
}

test "a catalog NOTIFY is honored only from the configured primary" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(
        \\$ORIGIN catalog.example.
        \\$TTL 3600
        \\@ IN SOA invalid. hostmaster.invalid. 2 3600 900 1209600 3600
        \\@ IN NS invalid.
        \\version IN TXT "2"
        \\m1.zones IN PTR one.example.
        \\
    );
    defer runtime.deinit();
    try runtime.setCatalogConsumer("catalog.example.", try std.Io.net.IpAddress.parse("192.0.2.1", 53), null);

    var output: [1024]u8 = undefined;
    var request_buffer: [512]u8 = undefined;
    const request = try encodeNotifyRequest(arena.allocator(), &request_buffer, "catalog.example.", 2, .SOA);

    // RFC 1996 section 3.10: a NOTIFY from a host that is not the zone's
    // master is ignored.
    var stranger = try std.Io.net.IpAddress.parse("127.0.0.1", 40000);
    _ = try runtime.answerFrom(request, &output, &stranger);
    try std.testing.expect(!runtime.catalog_refresh_requested.load(.acquire));

    // A NOTIFY from the master's address asks for a read; the source port
    // is not part of the identity.
    var master = try std.Io.net.IpAddress.parse("192.0.2.1", 40000);
    _ = try runtime.answerFrom(request, &output, &master);
    try std.testing.expect(runtime.catalog_refresh_requested.load(.acquire));
}

const SecondaryFetchStub = struct {
    calls: usize = 0,
    last_zone_name: ?[]const u8 = null,

    fn fetch(ctx: *anyopaque, allocator: std.mem.Allocator, zone_name: []const u8) anyerror!?[]const u8 {
        const stub: *SecondaryFetchStub = @ptrCast(@alignCast(ctx));
        stub.calls += 1;
        stub.last_zone_name = zone_name;
        const text = try allocator.dupe(u8,
            \\$ORIGIN example.
            \\$TTL 3600
            \\@ IN SOA ns.example. hostmaster.example. 11 3600 900 1209600 3600
            \\@ IN NS ns.example.
            \\www IN A 192.0.2.1
            \\
        );
        return text;
    }
};

test "a NOTIFY for a secondary marks it due for the next refresh tick" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneTexts(&.{
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
        ,
        \\$ORIGIN primary.example.
        \\$TTL 3600
        \\@ IN SOA ns.primary.example. hostmaster.primary.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.primary.example.
        \\
        ,
    });
    defer runtime.deinit();
    try runtime.secondary_zones.append(runtime.allocator, .{
        .apex = try runtime.allocator.dupe(u8, "example."),
        .primary = try std.Io.net.IpAddress.parse("192.0.2.1", 53),
        .last_success_ns = 5_000_000_000,
        .refresh_sec = 3600,
        .retry_sec = 900,
        .expire_sec = 1209600,
    });
    var stub: SecondaryFetchStub = .{};
    // One second after the last success the refresh interval has not
    // elapsed, so the tick is idle before any NOTIFY.
    try runtime.maybeRefreshSecondaries(6_000_000_000, SecondaryFetchStub.fetch, &stub);
    try std.testing.expectEqual(@as(usize, 0), stub.calls);

    var output: [1024]u8 = undefined;
    var request_buffer: [512]u8 = undefined;
    // A NOTIFY for a zone that is not a tracked secondary does not mark
    // the secondary due.
    const primary_request = try encodeNotifyRequest(arena.allocator(), &request_buffer, "primary.example.", 11, .SOA);
    _ = try runtime.answer(primary_request, &output);
    try runtime.maybeRefreshSecondaries(6_000_000_000, SecondaryFetchStub.fetch, &stub);
    try std.testing.expectEqual(@as(usize, 0), stub.calls);

    // A NOTIFY for the tracked secondary marks it due, so the next tick
    // fetches it even though the refresh interval has not elapsed.
    const secondary_request = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, .SOA);
    _ = try runtime.answer(secondary_request, &output);
    try runtime.maybeRefreshSecondaries(6_000_000_000, SecondaryFetchStub.fetch, &stub);
    try std.testing.expectEqual(@as(usize, 1), stub.calls);
    try std.testing.expectEqualStrings("example.", stub.last_zone_name.?);
    try std.testing.expectEqual(@as(?i64, 6_000_000_000), runtime.secondary_zones.items[0].last_success_ns);
}

test "runtime answers NOTIFY by comparing the serial and refuses transfers singly" {
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
    var request_buffer: [512]u8 = undefined;

    const newer = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, .SOA);
    const newer_bytes = try runtime.answer(newer, &output);
    const newer_response = try dns_message.Message.parse(arena.allocator(), newer_bytes);
    try std.testing.expect(newer_response.header.qr);
    try std.testing.expect(newer_response.header.opcode == .notify);
    try std.testing.expectEqual(@as(u16, 0x4321), newer_response.header.id);
    try std.testing.expectEqual(@as(@TypeOf(newer_response.header.rcode), .no_error), newer_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), newer_response.header.answer_count);
    try std.testing.expectEqual(@as(u32, 10), newer_response.answers.items[0].rdata.SOA.serial);

    const equal = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 10, .SOA);
    const equal_bytes = try runtime.answer(equal, &output);
    const equal_response = try dns_message.Message.parse(arena.allocator(), equal_bytes);
    try std.testing.expectEqual(@as(@TypeOf(equal_response.header.rcode), .notauth), equal_response.header.rcode);

    const older = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 9, .SOA);
    const older_bytes = try runtime.answer(older, &output);
    const older_response = try dns_message.Message.parse(arena.allocator(), older_bytes);
    try std.testing.expectEqual(@as(@TypeOf(older_response.header.rcode), .notauth), older_response.header.rcode);

    // RFC 1996 section 3.7: a NOTIFY with an empty answer section is legal
    // and carries no hint, so it is answered like any other accepted NOTIFY.
    const without_soa = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", null, .SOA);
    const without_soa_bytes = try runtime.answer(without_soa, &output);
    const without_soa_response = try dns_message.Message.parse(arena.allocator(), without_soa_bytes);
    try std.testing.expect(without_soa_response.header.qr);
    try std.testing.expect(without_soa_response.header.opcode == .notify);
    try std.testing.expectEqual(@as(@TypeOf(without_soa_response.header.rcode), .no_error), without_soa_response.header.rcode);

    // RFC 1996 section 3.7: the question of a NOTIFY is the zone's SOA, so a
    // question for anything else is malformed.
    const wrong_type = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, .A);
    const wrong_type_bytes = try runtime.answer(wrong_type, &output);
    const wrong_type_response = try dns_message.Message.parse(arena.allocator(), wrong_type_bytes);
    try std.testing.expectEqual(@as(@TypeOf(wrong_type_response.header.rcode), .formerr), wrong_type_response.header.rcode);

    const unserved = try encodeNotifyRequest(arena.allocator(), &request_buffer, "other.", 11, .SOA);
    const unserved_bytes = try runtime.answer(unserved, &output);
    const unserved_response = try dns_message.Message.parse(arena.allocator(), unserved_bytes);
    try std.testing.expectEqual(@as(@TypeOf(unserved_response.header.rcode), .refused), unserved_response.header.rcode);

    const axfr_bytes = try runtime.answer(&transfer_test_axfr_query, &output);
    const axfr_response = try dns_message.Message.parse(arena.allocator(), axfr_bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), axfr_response.header.id);
    try std.testing.expectEqual(@as(@TypeOf(axfr_response.header.rcode), .refused), axfr_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), axfr_response.header.answer_count);
}

test "runtime signs the answer to a signed NOTIFY" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [512]u8 = undefined;
    const request = try encodeSignedNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, now, sha256_test_key);
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(request, &output);

    // RFC 8945 section 5.3: the reply to a signed request is signed with the
    // same key and algorithm. The TSIG is the last record of the message,
    // which is what parseFinalAdditional accepts.
    const request_final = (try tsig.parseFinalAdditional(request)) orelse return error.TestExpectedEqual;
    const response_final = (try tsig.parseFinalAdditional(response_bytes)) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 32), response_final.tsig.macBytes().len);
    _ = try tsig.verify(response_bytes, sha256_test_key.secret, request_final.tsig.macBytes());

    // The signed answer keeps the shape of the unsigned one: the same RCODE,
    // the same echoed question, and the zone's own SOA in the answer section.
    const signed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expect(signed.header.qr);
    try std.testing.expectEqual(@as(@TypeOf(signed.header.opcode), .notify), signed.header.opcode);
    try std.testing.expectEqual(@as(@TypeOf(signed.header.rcode), .no_error), signed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), signed.header.question_count);
    try std.testing.expectEqual(@as(u16, 1), signed.header.answer_count);
    try std.testing.expectEqual(@as(u32, 10), signed.answers.items[0].rdata.SOA.serial);

    // The signed answer is the unsigned answer plus the TSIG record.
    var unsigned_request_buffer: [512]u8 = undefined;
    const unsigned_request = try encodeNotifyRequest(arena.allocator(), &unsigned_request_buffer, "example.", 11, .SOA);
    var unsigned_output: [1024]u8 = undefined;
    const unsigned_bytes = try runtime.answer(unsigned_request, &unsigned_output);
    try std.testing.expectEqual(unsigned_bytes.len + response_final.record_end - response_final.record_start, response_bytes.len);
    try std.testing.expectEqualSlices(u8, unsigned_bytes[0..10], response_bytes[0..10]);
    try std.testing.expectEqualSlices(u8, unsigned_bytes[12..], response_bytes[12..unsigned_bytes.len]);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, unsigned_bytes[10..12], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response_bytes[10..12], .big));

    // A signed NOTIFY whose serial is not newer is answered NOTAUTH, and
    // that answer is signed too.
    var stale_buffer: [512]u8 = undefined;
    const stale = try encodeSignedNotifyRequest(arena.allocator(), &stale_buffer, "example.", 10, now, sha256_test_key);
    var stale_output: [1024]u8 = undefined;
    const stale_bytes = try runtime.answer(stale, &stale_output);
    const stale_response = try dns_message.Message.parse(arena.allocator(), stale_bytes);
    try std.testing.expectEqual(@as(@TypeOf(stale_response.header.rcode), .notauth), stale_response.header.rcode);
    const stale_final = (try tsig.parseFinalAdditional(stale_bytes)) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 32), stale_final.tsig.macBytes().len);
    const stale_request_final = (try tsig.parseFinalAdditional(stale)) orelse return error.TestExpectedEqual;
    _ = try tsig.verify(stale_bytes, sha256_test_key.secret, stale_request_final.tsig.macBytes());
}

test "an unsigned NOTIFY is answered with no TSIG record" {
    const now = 1_700_000_000;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [512]u8 = undefined;
    const request = try encodeNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, .SOA);

    // A runtime with a key configured answers an unsigned NOTIFY with the
    // very same bytes as one without a key: no TSIG record is added.
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var keyed = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    , &keyring);
    defer keyed.deinit();
    keyed.setTsigNow(now);
    var plain = try Runtime.fromZoneText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    );
    defer plain.deinit();

    var keyed_output: [1024]u8 = undefined;
    var plain_output: [1024]u8 = undefined;
    const keyed_bytes = try keyed.answer(request, &keyed_output);
    const plain_bytes = try plain.answer(request, &plain_output);
    try std.testing.expectEqualSlices(u8, plain_bytes, keyed_bytes);
    try std.testing.expect((try tsig.parseFinalAdditional(keyed_bytes)) == null);
    const parsed = try dns_message.Message.parse(arena.allocator(), keyed_bytes);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .no_error), parsed.header.rcode);
}

test "a NOTIFY whose MAC does not verify is answered NOTAUTH with BADSIG" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var request_buffer: [512]u8 = undefined;
    const request = try encodeSignedNotifyRequest(arena.allocator(), &request_buffer, "example.", 11, now, sha256_test_key);
    var broken = request_buffer;
    // The request MAC starts after the algorithm name and the fixed fields of
    // the TSIG RDATA, so a flipped octet there breaks the MAC.
    const request_final = (try tsig.parseFinalAdditional(request)) orelse return error.TestExpectedEqual;
    const mac_start = request_final.rdata_start + request_final.tsig.algorithm.asWire().len + 10;
    broken[mac_start] ^= 0xff;

    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(broken[0..request.len], &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .notauth), parsed.header.rcode);
    // RFC 8945 section 5.2.2: the error response carries the BADSIG code and
    // is unsigned.
    const response_final = (try tsig.parseFinalAdditional(response_bytes)) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u16, 16), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 0), response_final.tsig.macBytes().len);
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

/// The question of `transfer_test_axfr_query` on its own, for a request the
/// test signs.
const axfr_question_wire = [_]u8{
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x00, 0xfc, 0x00, 0x01,
};

/// The AXFR question of a name this server does not serve.
const other_zone_question_wire = [_]u8{
    0x05, 'o', 't', 'h', 'e', 'r', 0x00, 0x00, 0xfc, 0x00, 0x01,
};

test "a signed AXFR is answered with signed frames a client can verify" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    // A zone with more records than one frame carries, so the answer is a
    // sequence of messages and the chain between them is exercised.
    var zone_text: std.ArrayList(u8) = .empty;
    defer zone_text.deinit(std.testing.allocator);
    try zone_text.appendSlice(std.testing.allocator,
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    );
    var index: usize = 0;
    while (index < 70) : (index += 1) {
        const line = try std.fmt.allocPrint(std.testing.allocator, "h{d} IN A 192.0.2.{d}\n", .{ index, index % 254 + 1 });
        defer std.testing.allocator.free(line);
        try zone_text.appendSlice(std.testing.allocator, line);
    }
    var runtime = try Runtime.fromZoneTextWithKeyring(zone_text.items, &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const query = try makeSignedQueryWithQuestions(now, 32, false, 1, &axfr_question_wire, sha256_test_key);
    const blob = try runtime.encodeTransferFrames(arena.allocator(), query.packet[0..query.len]);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])) orelse return error.TestExpectedEqual;

    var offset: usize = 0;
    var frames: usize = 0;
    var prior_bytes: [64]u8 = undefined;
    var prior_len: usize = 0;
    while (offset < blob.len) {
        const frame_len = std.mem.readInt(u16, blob[offset..][0..2], .big);
        const frame = blob[offset + 2 ..][0..frame_len];
        // Every frame of a signed sequence carries a TSIG record.
        const final = (try tsig.parseFinalAdditional(frame)) orelse return error.TestExpectedEqual;
        if (frames == 0) {
            // RFC 8945 section 5.3.1: the first message of a multi-message
            // response is a standard answer, so it verifies with the request
            // MAC and the whole TSIG record.
            _ = try tsig.verify(frame, sha256_test_key.secret, request_final.tsig.macBytes());
        } else {
            // A later message chains on the MAC of the message before it.
            _ = try tsig.verifyChained(&.{frame}, sha256_test_key.secret, prior_bytes[0..prior_len]);
        }
        prior_len = final.tsig.macBytes().len;
        @memcpy(prior_bytes[0..prior_len], final.tsig.macBytes());
        offset += 2 + frame_len;
        frames += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), frames);
}

test "a signed out-of-zone AXFR is refused with a signed frame" {
    const now = 1_700_000_000;
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    , &keyring);
    defer runtime.deinit();
    runtime.setTsigNow(now);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const query = try makeSignedQueryWithQuestions(now, 32, false, 1, &other_zone_question_wire, sha256_test_key);
    const blob = try runtime.encodeTransferFrames(arena.allocator(), query.packet[0..query.len]);
    const frame_len = std.mem.readInt(u16, blob[0..2], .big);
    const frame = blob[2..][0..frame_len];
    const parsed = try dns_message.Message.parse(arena.allocator(), frame);
    try std.testing.expectEqual(@as(@TypeOf(parsed.header.rcode), .refused), parsed.header.rcode);
    // The refusal of a signed request is signed too.
    const final = (try tsig.parseFinalAdditional(frame)) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 32), final.tsig.macBytes().len);
    const request_final = (try tsig.parseFinalAdditional(query.packet[0..query.len])) orelse return error.TestExpectedEqual;
    _ = try tsig.verify(frame, sha256_test_key.secret, request_final.tsig.macBytes());
}

const reload_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\
;

const reload_zone_next =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.2
    \\
;

const reload_zone_older =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 9 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.3
    \\
;

const reload_zone_other_apex =
    \\$ORIGIN other.example.
    \\$TTL 3600
    \\@ IN SOA ns.other.example. hostmaster.other.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.other.example.
    \\www IN A 192.0.2.4
    \\
;

const reload_a_query = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
    0,    0x00, 0x01, 0x00, 0x01,
};

fn expectReloadedAddress(runtime: *const Runtime, arena: std.mem.Allocator, expected: [4]u8) !void {
    var output: [512]u8 = undefined;
    const response_bytes = try runtime.answer(&reload_a_query, &output);
    const parsed = try dns_message.Message.parse(arena, response_bytes);
    try std.testing.expectEqual(@as(usize, 1), parsed.answers.len);
    try std.testing.expectEqualSlices(u8, &expected, &parsed.answers.items[0].rdata.A);
}

test "a replaced zone serves the new data and records the serial transition" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(reload_zone);
    defer runtime.deinit();

    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.replaceZoneText(io, "example.", reload_zone_next));
    try expectReloadedAddress(&runtime, arena.allocator(), .{ 192, 0, 2, 2 });

    // The recorded transition lets an IXFR client at the old serial get the
    // incremental answer, and a client at an unknown serial still gets the
    // full transfer.
    const log = runtime.deltaLogForOriginConst("example.").?;
    try std.testing.expect(log.hasSerial(10));
    try std.testing.expect(log.hasSerial(11));
    try std.testing.expectEqual(transfer.IxfrDecision.incremental, transfer.decideIxfr(11, 10, log));
    try std.testing.expectEqual(transfer.IxfrDecision.up_to_date, transfer.decideIxfr(11, 11, log));
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(11, 5, log));
}

test "a zone file that does not parse leaves the served zone in place" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(reload_zone);
    defer runtime.deinit();

    try std.testing.expectEqual(ReloadOutcome.load_failed, runtime.replaceZoneText(io, "example.", "not a zone file\n"));
    try expectReloadedAddress(&runtime, arena.allocator(), .{ 192, 0, 2, 1 });

    // No transition was recorded, so the served zone is still the only one.
    const log = runtime.deltaLogForOriginConst("example.").?;
    try std.testing.expect(!log.hasSerial(10));
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(10, 9, log));
}

test "a zone file without a newer serial leaves the served zone in place" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(reload_zone);
    defer runtime.deinit();

    try std.testing.expectEqual(ReloadOutcome.serial_not_newer, runtime.replaceZoneText(io, "example.", reload_zone_older));
    try expectReloadedAddress(&runtime, arena.allocator(), .{ 192, 0, 2, 1 });

    // The refused transition is not recorded, so an IXFR client at the
    // refused serial still gets the full transfer.
    const log = runtime.deltaLogForOriginConst("example.").?;
    try std.testing.expect(!log.hasSerial(9));
    try std.testing.expectEqual(transfer.IxfrDecision.fallback_axfr, transfer.decideIxfr(10, 9, log));
}

test "a zone file for another apex is refused" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(reload_zone);
    defer runtime.deinit();

    try std.testing.expectEqual(ReloadOutcome.wrong_zone, runtime.replaceZoneText(io, "example.", reload_zone_other_apex));
    try expectReloadedAddress(&runtime, arena.allocator(), .{ 192, 0, 2, 1 });
}

test "a signed zone the server holds no signing key for is not replaced" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var runtime = try Runtime.fromZoneText(reload_zone);
    defer runtime.deinit();

    // The startup signer installs the records it generates in the zone's
    // `generated` field. A zone that carries them is signed again on every
    // reload, and a server that holds no key cannot sign it, so the served
    // zone stays.
    var generated = [_]zone_parser.ZoneRecord{.{
        .owner = "example.",
        .ttl = 3600,
        .rrtype = .RRSIG,
        .rdata = "",
    }};
    runtime.zones.items[0].generated = generated[0..];

    try std.testing.expectEqual(ReloadOutcome.sign_failed, runtime.replaceZoneText(io, "example.", reload_zone_next));
    try expectReloadedAddress(&runtime, arena.allocator(), .{ 192, 0, 2, 1 });
}

/// The RFC 8080 section 6.1 Ed25519 key: the key the server signs a zone
/// with.
const dnssec_reload_key = "ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n";

/// The window every signature of these tests carries, so the validator
/// accepts them at a fixed time.
const dnssec_reload_window = zone_signer.Options{ .inception = 1_000_000_000, .expiration = 2_000_000_000 };

const dnssec_reload_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\
;

/// The same zone with a newer serial and another owner name, so the denial
/// records have to name the new content.
const dnssec_reload_zone_next =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\mail IN A 192.0.2.2
    \\
;

/// A second zone, so a reload of one zone leaves the other one alone.
const dnssec_reload_zone_other =
    \\$ORIGIN other.
    \\$TTL 3600
    \\@ IN SOA ns.other. hostmaster.other. 10 3600 900 1209600 3600
    \\@ IN NS ns.other.
    \\www IN A 192.0.2.3
    \\
;

/// The same second zone with a newer serial.
const dnssec_reload_zone_other_next =
    \\$ORIGIN other.
    \\$TTL 3600
    \\@ IN SOA ns.other. hostmaster.other. 11 3600 900 1209600 3600
    \\@ IN NS ns.other.
    \\mail IN A 192.0.2.4
    \\
;

/// A zone file that already carries DNSSEC records, which the signer refuses
/// rather than sign twice.
const dnssec_reload_zone_signed =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 12 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
    \\mail IN A 192.0.2.2
    \\
;

/// A DO-bit query for the apex SOA of the zone above.
const dnssec_reload_soa_query = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  0,    0x00, 0x06, 0x00,
    0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
};

/// The RDATA of the first record of `rrtype` at `owner`, copied out of the
/// zone so it outlives the parsed value.
fn zoneOpaque(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    rrtype: dns_types.RecordType,
    owner: []const u8,
) !?[]u8 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(rrtype)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner)) continue;
        const rdata = try zone_parser.parseRData(rrtype, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        return try allocator.dupe(u8, bytes);
    }
    return null;
}

/// The RRSIG at `owner` that covers `covered`, copied out of the zone.
fn zoneRrsig(
    allocator: std.mem.Allocator,
    zone: *const zone_index.Zone,
    owner: []const u8,
    covered: u16,
) !?[]u8 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner)) continue;
        const rdata = try zone_parser.parseRData(.RRSIG, record.rdataText());
        const bytes = switch (rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        if (bytes.len < 2 or std.mem.readInt(u16, bytes[0..2], .big) != covered) continue;
        return try allocator.dupe(u8, bytes);
    }
    return null;
}

/// The validity period an RRSIG carries: the inception and the expiration,
/// in seconds since the epoch (RFC 4034 section 3.1.5).
const SignatureWindow = struct {
    inception: u32,
    expiration: u32,
};

fn rrsigWindow(rrsig: []const u8) SignatureWindow {
    std.debug.assert(rrsig.len >= 16);
    return .{
        .inception = std.mem.readInt(u32, rrsig[12..16], .big),
        .expiration = std.mem.readInt(u32, rrsig[8..12], .big),
    };
}

/// The wall clock in seconds since the epoch, the unit a signature window is
/// counted in.
fn nowSeconds(io: std.Io) u32 {
    return @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}

fn zoneHas(zone: *const zone_index.Zone, rrtype: dns_types.RecordType, owner: []const u8) bool {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(rrtype)) continue;
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner)) continue;
        return true;
    }
    return false;
}

test "a signed zone that is reloaded is signed again with the same key" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = Runtime{ .allocator = std.testing.allocator };
    defer runtime.deinit();
    try runtime.appendZoneText(dnssec_reload_zone);

    var key = try zone_signer.parseKey(dnssec_reload_key);
    defer key.deinit();
    try zone_signer.signZone(runtime.allocator, &runtime.zones.items[0], &key, dnssec_reload_window);
    runtime.dnssec_session = zone_signer.Session.start(&key, dnssec_reload_window);

    // The chain the startup signing pass made: the signature over the old
    // SOA and the DNSKEY that names the key.
    const old_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    const old_dnskey = (try zoneOpaque(allocator, &runtime.zones.items[0], .DNSKEY, "example.")).?;
    const old_ds = (try zoneOpaque(allocator, &runtime.zones.items[0], .DS, "example.")).?;

    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.replaceZoneText(io, "example.", dnssec_reload_zone_next));

    // The served zone is the new content.
    try std.testing.expectEqual(@as(?u32, 11), runtime.zones.items[0].soaSerial());

    // RFC 4034 section 5.1.4: the DS holds a digest of the DNSKEY it names,
    // so the DNSKEY, its key tag, and the DS do not move with the zone.
    const new_dnskey = (try zoneOpaque(allocator, &runtime.zones.items[0], .DNSKEY, "example.")).?;
    try std.testing.expectEqualSlices(u8, old_dnskey, new_dnskey);
    const ds = (try zoneOpaque(allocator, &runtime.zones.items[0], .DS, "example.")).?;
    try std.testing.expectEqualSlices(u8, old_ds, ds);
    try std.testing.expectEqual(dns_dnssec.keyTag(new_dnskey), std.mem.readInt(u16, ds[0..2], .big));

    // The signature over the old SOA is gone: the new one covers the new
    // content, so it is a different signature.
    const new_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    try std.testing.expect(!std.mem.eql(u8, old_rrsig, new_rrsig));

    // The project's own validator accepts the new signature over the new
    // SOA, with the DNSKEY the zone publishes as the trust anchor. The
    // signature carries the window the reload started, so the validator is
    // given a time inside that window.
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{
        .owner = (try @import("../dns/name.zig").Name.fromText("example.")),
        .rrtype = .DNSKEY,
        .rdata = new_dnskey,
    };
    anchors.len = 1;
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(&dnssec_reload_soa_query, &output);
    const query = try dns_message.Message.parseQuery(allocator, &dnssec_reload_soa_query);
    const answer = try dns_message.Message.parse(allocator, response_bytes);
    const result = try dns_validate.validate(allocator, &anchors, query, answer, &.{}, rrsigWindow(new_rrsig).inception + 1);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);

    // The denial records are the new content's: the chain names the new owner
    // and no longer names the old one.
    try std.testing.expect(zoneHas(&runtime.zones.items[0], .NSEC, "mail.example."));
    try std.testing.expect(!zoneHas(&runtime.zones.items[0], .NSEC, "www.example."));
    const apex_nsec = (try zoneOpaque(allocator, &runtime.zones.items[0], .NSEC, "example.")).?;
    const next = (try @import("../dns/name.zig").Name.fromText("mail.example.")).asWire();
    try std.testing.expectEqualSlices(u8, next, apex_nsec[0..next.len]);

    // The denial records of the new content are signed, so the proof the
    // reloaded zone serves can be authenticated.
    try std.testing.expect((try zoneRrsig(allocator, &runtime.zones.items[0], "mail.example.", dns_types.RecordType.NSEC.code())) != null);
}

test "a reload signs the zone with a window that starts now" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = Runtime{ .allocator = std.testing.allocator };
    defer runtime.deinit();
    try runtime.appendZoneText(dnssec_reload_zone);

    var key = try zone_signer.parseKey(dnssec_reload_key);
    defer key.deinit();
    try zone_signer.signZone(runtime.allocator, &runtime.zones.items[0], &key, dnssec_reload_window);
    runtime.dnssec_session = zone_signer.Session.start(&key, dnssec_reload_window);

    const old_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    const old_window = rrsigWindow(old_rrsig);

    const before = nowSeconds(io);
    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.replaceZoneText(io, "example.", dnssec_reload_zone_next));
    const after = nowSeconds(io);

    const new_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    const new_window = rrsigWindow(new_rrsig);

    // The reloaded zone is signed with a window that starts at the reload, so
    // a zone that has been running for weeks is signed with the validity
    // period it has left (RFC 4034 section 3.1.5).
    try std.testing.expect(new_window.inception >= before);
    try std.testing.expect(new_window.inception <= after);
    try std.testing.expect(new_window.inception != old_window.inception);

    // The window is the one the server was configured with, counted from the
    // reload and not from the start of the server.
    try std.testing.expectEqual(
        old_window.expiration - old_window.inception,
        new_window.expiration - new_window.inception,
    );
}

test "a zone that is not reloaded keeps the window it was signed with" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = Runtime{ .allocator = std.testing.allocator };
    defer runtime.deinit();
    try runtime.appendZoneText(dnssec_reload_zone);
    try runtime.appendZoneText(dnssec_reload_zone_other);

    var key = try zone_signer.parseKey(dnssec_reload_key);
    defer key.deinit();
    try zone_signer.signZone(runtime.allocator, &runtime.zones.items[0], &key, dnssec_reload_window);
    runtime.dnssec_session = zone_signer.Session.start(&key, dnssec_reload_window);

    const old_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    const old_window = rrsigWindow(old_rrsig);

    // Another zone is reloaded; the signed one is not.
    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.replaceZoneText(io, "other.", dnssec_reload_zone_other_next));

    // The signed zone keeps the signatures it was signed with: only a reload
    // of that zone refreshes its window.
    const kept_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    try std.testing.expectEqualSlices(u8, old_rrsig, kept_rrsig);
    try std.testing.expectEqual(old_window.inception, rrsigWindow(kept_rrsig).inception);
    try std.testing.expectEqual(old_window.expiration, rrsigWindow(kept_rrsig).expiration);
}

test "a reload that fails leaves the served signed zone in place" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = Runtime{ .allocator = std.testing.allocator };
    defer runtime.deinit();
    try runtime.appendZoneText(dnssec_reload_zone);

    var key = try zone_signer.parseKey(dnssec_reload_key);
    defer key.deinit();
    try zone_signer.signZone(runtime.allocator, &runtime.zones.items[0], &key, dnssec_reload_window);
    runtime.dnssec_session = zone_signer.Session.start(&key, dnssec_reload_window);

    const old_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;

    try std.testing.expectEqual(ReloadOutcome.load_failed, runtime.replaceZoneText(io, "example.", "not a zone file\n"));

    // A zone file that already carries DNSSEC records cannot be signed, so
    // the reload is refused rather than half-signed.
    try std.testing.expectEqual(ReloadOutcome.sign_failed, runtime.replaceZoneText(io, "example.", dnssec_reload_zone_signed));

    // The served zone keeps the old serial, the old signature, and the old
    // denial records.
    try std.testing.expectEqual(@as(?u32, 10), runtime.zones.items[0].soaSerial());
    const kept_rrsig = (try zoneRrsig(allocator, &runtime.zones.items[0], "example.", dns_types.RecordType.SOA.code())).?;
    try std.testing.expectEqualSlices(u8, old_rrsig, kept_rrsig);
    try std.testing.expect(zoneHas(&runtime.zones.items[0], .NSEC, "www.example."));
    try std.testing.expect(!zoneHas(&runtime.zones.items[0], .NSEC, "mail.example."));
}

test "a zone that was not signed is not signed by a reload" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = Runtime{ .allocator = std.testing.allocator };
    defer runtime.deinit();
    try runtime.appendZoneText(reload_zone);

    var key = try zone_signer.parseKey(dnssec_reload_key);
    defer key.deinit();
    runtime.dnssec_session = zone_signer.Session.start(&key, dnssec_reload_window);

    try std.testing.expectEqual(ReloadOutcome.replaced, runtime.replaceZoneText(io, "example.", reload_zone_next));

    // The zone was not signed before the reload, so it is not signed after
    // it either.
    const zone = &runtime.zones.items[0];
    try std.testing.expect(!zoneHas(zone, .DNSKEY, "example."));
    try std.testing.expect(!zoneHas(zone, .DS, "example."));
    try std.testing.expect(!zoneHas(zone, .RRSIG, "example."));
    try std.testing.expect(!zoneHas(zone, .NSEC, "example."));
    try std.testing.expectEqual(@as(usize, 0), zone.generated.len);
}
