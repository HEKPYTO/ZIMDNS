/// Contract: Loads one parsed server configuration and its referenced assets, confined to `dir`.
/// Ownership: ServerContext owns its Config, ordered zones, blocklist, and optional TSIG keyring; call deinit.
/// Errors: Parser and referenced-file I/O errors stay typed; missing referenced assets map to MissingReferencedFile.
/// Paths: every loader path (config plus referenced zone/blocklist/TSIG files) must be relative,
/// NUL-free, and without `..` components; symlink-resolved canonical targets must stay beneath `dir`.
const std = @import("std");
const builtin = @import("builtin");
const auth_runtime = @import("../auth/runtime.zig");
const response_mod = @import("../auth/response.zig");
const dns_message = @import("../dns/message.zig");
const keyring_mod = @import("../auth/keyring.zig");
const blocklist_mod = @import("../blocklist.zig");
const parser = @import("parser.zig");
const listener = @import("../platform/listener.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");
const resolver_mod = @import("../resolver.zig");
const zonemd = @import("../zone/zonemd.zig");
const signer = @import("../zone/signer.zig");
const journal_mod = @import("../zone/journal.zig");

const validate_mod = @import("../dns/validate.zig");
const dns_name = @import("../dns/name.zig");
const RecordType = @import("../dns/types.zig").RecordType;
const tsig = @import("../dns/tsig.zig");
/// RFC 4034 section 3.1.5 signature window for a zone signed at startup. The
/// key file is re-read and every zone re-signed on each start, so the window
/// only has to outlast one uptime: an operator who serves longer without
/// restarting publishes expired signatures, which is said here plainly rather
/// than hidden behind a refresh timer this profile does not have.
const signature_validity_seconds: u32 = 30 * 24 * 60 * 60;

pub const Error = error{
    MissingReferencedFile,
    InvalidReferencedPath,
    NoPrimaryZone,
    BadConfiguration,
    ZoneNameMismatch,
    ZonemdMismatch,
    /// The apex ZONEMD record is signed, but not to a configured trust anchor.
    ZonemdSignatureInvalid,
    /// The zone publishes no ZONEMD record, and none of its own DNSSEC
    /// records proves that the RRset does not exist.
    ZonemdAbsenceUnproven,
    BadDnssecKey,
    BadTrustAnchorFile,
    /// The RFC 9432 catalog zone names a zone the server also serves, so the
    /// synthesized catalog and the configuration would contradict.
    BadCatalogZone,
};

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    config: parser.Config,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},
    keyring: keyring_mod.Keyring = .{},
    /// The zone signing key, kept so the serving path can sign an RRset that
    /// is not in the zone file (RFC 8482 section 4.2). Null when no
    /// `dnssec-key-file` is configured. The runtime that inherits it owns it
    /// and wipes it when it is deinited.
    dnssec_session: ?signer.Session = null,
    /// RFC 4035 section 5.2 trust anchors for the forwarding path. Empty when
    /// no `trust-anchor-file` is configured, which is what keeps the forwarder
    /// a non-validating one.
    anchors: validate_mod.Anchors = .{},
    /// The RFC 1995 delta journal the operator asked for. Null when the
    /// configuration names no journal file, and the delta log then lives in
    /// memory only.
    journal: ?journal_mod.Journal = null,

    pub fn load(dir: std.Io.Dir, io: std.Io, config_path: []const u8, allocator: std.mem.Allocator) !ServerContext {
        try ensureConfined(dir, io, config_path);
        const config_text = try dir.readFileAlloc(io, config_path, allocator, .limited(1024 * 1024));
        defer allocator.free(config_text);

        var context = ServerContext{
            .allocator = allocator,
            .config = try parser.Config.parse(config_text),
        };
        errdefer context.deinit();

        // RFC 9210 section 4.2: the connection limits the operator configured
        // are the ones the TCP listener enforces.
        listener.setTcpLimits(context.config.tcp_limits);

        // RFC 1995 section 3: the delta log can be kept in a file, so an
        // IXFR client at an old serial is still answered incrementally after
        // the server comes back.
        if (context.config.ixfrJournalFileText()) |path| {
            context.journal = try openJournal(dir, io, path);
        }

        if (context.config.tsigKeyFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            context.keyring = parseKeyTextAndClear(key_text) catch |err| return err;
            // The reload re-reads this file, so the keyring remembers the
            // file it was parsed from.
            context.keyring.setSource(dir, key_path) catch |err| return err;
        }

        // The key is read before any zone is loaded, so a bad key file fails
        // startup without leaving a half-signed zone behind. The private
        // scalar is wiped as soon as every zone has been signed, unless the
        // serving path needs it: an RRset that is not in the zone file can
        // only be signed while the key is held (RFC 8482 section 4.2).
        var dnssec_key: ?signer.Key = null;
        defer if (dnssec_key) |*key| key.deinit();
        if (context.config.dnssecKeyFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            dnssec_key = parseDnssecKeyTextAndClear(key_text) catch return Error.BadDnssecKey;
        }
        // RFC 6781 section 3.1: a zone that separates the roles publishes a
        // key-signing key the parent points its DS at. It signs the DNSKEY
        // RRset and nothing else, so the key the `dnssec-key-file` names
        // signs every other RRset.
        if (context.config.dnssecKskFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            var ksk = parseDnssecKeyTextAndClear(key_text) catch return Error.BadDnssecKey;
            defer ksk.deinit();
            if (dnssec_key) |*key| {
                key.ksk = .{ .material = ksk.material };
            } else {
                // A key-signing key without a zone-signing key signs nothing.
                return Error.BadDnssecKey;
            }
        }
        // RFC 6781 section 4.1.2: the Double-Signature scheme publishes a
        // second key-signing key that signs the DNSKEY RRset beside the
        // first, while the parent's DS still points at the first.
        if (context.config.dnssecNewKskFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            var ksk = parseDnssecKeyTextAndClear(key_text) catch return Error.BadDnssecKey;
            defer ksk.deinit();
            const zone_key = if (dnssec_key) |*key| key else {
                // A second key-signing key without a zone-signing key signs
                // nothing.
                return Error.BadDnssecKey;
            };
            const first_ksk = if (zone_key.ksk) |*first| first else {
                // The DS the zone publishes states one key, and the scheme
                // needs that key to name the second one beside.
                return Error.BadDnssecKey;
            };
            // The same key twice would put the same DNSKEY in the RRset
            // twice, and an RRset with a duplicate RR is not the RRset a
            // signature covers.
            if (signer.samePublicKey(ksk.material, first_ksk.material)) return Error.BadDnssecKey;
            if (signer.samePublicKey(ksk.material, zone_key.material)) return Error.BadDnssecKey;
            // RFC 6781 section 4.1.2.1: the key the operator marks `revoked` is
            // the one being removed, so it is published with the REVOKE bit
            // set and it still signs the DNSKEY RRset that carries it.
            zone_key.published_ksk = .{
                .material = ksk.material,
                .revoked = context.config.dnssecNewKskRevoked(),
            };
        }

        // Read before any zone is loaded, so a bad anchor file fails startup
        // rather than leaving a forwarder running with no trust domain.
        if (context.config.trustAnchorFileText()) |anchor_path| {
            const anchor_text = try readReferencedFile(dir, io, anchor_path, allocator);
            defer allocator.free(anchor_text);
            context.anchors = validate_mod.Anchors.parse(context.allocator, anchor_text) catch return Error.BadTrustAnchorFile;
        }
        const now_seconds: u32 = @intCast(@divTrunc(
            std.Io.Clock.real.now(io).nanoseconds,
            std.time.ns_per_s,
        ));

        // The chain the operator chose for the signed zones, or null when the
        // zone's own apex NSEC3PARAM decides, as it always did.
        const chain_policy: ?signer.ChainPolicy = if (context.config.chain) |*chain| switch (chain.chain) {
            .nsec => .{ .chain = .nsec },
            .nsec3 => .{ .chain = .nsec3, .iterations = chain.iterations, .salt = chain.saltBytes() },
        } else null;

        for (context.config.zones.items[0..context.config.zones.len]) |*configured| {
            const zone_text = try readReferencedFile(dir, io, configured.fileText(), allocator);
            defer allocator.free(zone_text);
            try loadZoneText(
                &context,
                allocator,
                io,
                zone_text,
                configured.nameText(),
                if (dnssec_key) |*key| key else null,
                now_seconds,
                chain_policy,
            );
        }

        // RFC 9432 section 4: a catalog zone is a normal zone. The producer
        // role publishes one for the zones this server serves, so the
        // membership list has one source and cannot drift from the zones the
        // configuration actually names.
        if (context.config.catalogZoneText()) |catalog_text| {
            const catalog_apex = try lowerDot(allocator, catalog_text);
            defer allocator.free(catalog_apex);
            for (context.config.zones.items[0..context.config.zones.len]) |*configured| {
                if (zoneNamesEqual(catalog_apex, configured.nameText())) return Error.BadCatalogZone;
            }
            const catalog_zone_text = try synthesizeCatalogZoneText(allocator, catalog_apex, context.config.zones.items[0..context.config.zones.len]);
            defer allocator.free(catalog_zone_text);
            try loadZoneText(
                &context,
                allocator,
                io,
                catalog_zone_text,
                catalog_apex,
                if (dnssec_key) |*key| key else null,
                now_seconds,
                chain_policy,
            );
        }

        // The key outlives the startup signing pass: the serving path signs
        // the RFC 8482 minimal answer, which is not part of the signed zone.
        if (dnssec_key) |*key| {
            context.dnssec_session = signer.Session.start(key, .{
                .inception = now_seconds,
                .expiration = now_seconds + signature_validity_seconds,
            });
            // The session holds its own copy, so the local one is wiped here.
            key.deinit();
            dnssec_key = null;
        }

        var blocklist_index: usize = 0;
        while (blocklist_index < context.config.blocklists.len) : (blocklist_index += 1) {
            const blocklist_path = context.config.blocklists.items[blocklist_index].pathText();
            const blocklist_text = try readReferencedFile(dir, io, blocklist_path, allocator);
            defer allocator.free(blocklist_text);
            const parsed_blocklist = try blocklist_mod.Blocklist.parse(blocklist_text);
            try context.blocklist.appendAll(parsed_blocklist);
        }

        return context;
    }

    pub fn takeRuntime(self: *ServerContext, io: std.Io) Error!auth_runtime.Runtime {
        if (self.zones.items.len == 0) return Error.NoPrimaryZone;
        // The NSID payload outlives the config text it was written in, so the
        // runtime owns the decoded octets. Decoded before anything moves out of
        // this context, so a failure here leaves the context whole.
        const nsid = if (self.config.nsidText()) |text|
            decodeNsid(self.allocator, text) catch return error.BadConfiguration
        else
            null;
        // RFC 9567 section 5: the agent domain is a domain name, and the
        // option carries it in wire form, so it is parsed into a name here.
        // A value that is not a domain name stops the server at startup
        // rather than advertising a channel nobody can report to.
        const report_agent = if (self.config.errorReportAgentText()) |text|
            agentDomainName(text) catch return error.BadConfiguration
        else
            null;
        // RFC 9567 section 6.3: the monitored agent domain is a domain name
        // too, and a value that is not one stops the server at startup rather
        // than monitoring a domain that cannot be named.
        const report_monitor = if (self.config.errorReportMonitorText()) |text|
            agentDomainName(text) catch return error.BadConfiguration
        else
            null;
        // Per-zone override apexes outlive the config text: lowercased with a
        // trailing dot, owned by the runtime. Decoded before the runtime
        // exists, so a failure here leaves the context whole.
        var except_owned = if (self.config.local_zones_except.len != 0) blk: {
            const list = self.allocator.alloc([]const u8, self.config.local_zones_except.len) catch return error.BadConfiguration;
            errdefer self.allocator.free(list);
            for (self.config.local_zones_except.items[0..self.config.local_zones_except.len], 0..) |slot, i| {
                list[i] = lowerDot(self.allocator, slot.text()) catch {
                    for (list[0..i]) |done| self.allocator.free(done);
                    return error.BadConfiguration;
                };
            }
            break :blk list;
        } else null;
        errdefer if (except_owned) |l| {
            for (l) |apex| self.allocator.free(apex);
            self.allocator.free(l);
        };
        var policy = resolver_mod.Policy.fromConfig(&self.config) catch return error.BadConfiguration;
        // The anchors move into the policy the resolver keeps, so exactly one
        // owner frees them and no reload path exists to double-free.
        policy.anchors = self.anchors;
        self.anchors = .{};
        // RFC 2136: an update is accepted only for a configured zone, with a
        // TSIG key the keyring holds, and is persisted to that zone's file.
        // The policy is validated before the runtime is built, so a bad line
        // costs nothing.
        for (self.config.allow_updates.items[0..self.config.allow_updates.len]) |entry| {
            const apex = entry.apexText();
            var served = false;
            for (self.config.zones.items[0..self.config.zones.len]) |zone| {
                if (std.ascii.eqlIgnoreCase(zone.nameText(), apex)) served = true;
            }
            if (!served) return error.BadConfiguration;
            if (!self.keyring.containsName(entry.keyText())) return error.BadConfiguration;
        }

        var runtime = if (self.config.forwarder != null or self.config.recursion_allow.len != 0 or self.config.cookies.enabled)
            try auth_runtime.Runtime.fromZonesWithPolicyAndKeyring(self.allocator, &self.zones, self.blocklist, io, policy, &self.keyring)
        else
            auth_runtime.Runtime.fromZonesWithKeyring(self.allocator, &self.zones, self.blocklist, &self.keyring);
        runtime.local_zones = self.config.local_zones;
        if (except_owned) |l| {
            runtime.local_zones_except = l;
            except_owned = null;
        }
        runtime.answer_policy.nsid = nsid;
        runtime.answer_policy.report_agent = report_agent;
        runtime.answer_policy.report_monitor = report_monitor;
        runtime.answer_policy.zoneversion = self.config.zoneversion;
        for (self.config.allow_updates.items[0..self.config.allow_updates.len]) |entry| {
            const apex = entry.apexText();
            var zone_path: []const u8 = &.{};
            for (self.config.zones.items[0..self.config.zones.len]) |zone| {
                if (std.ascii.eqlIgnoreCase(zone.nameText(), apex)) zone_path = zone.fileText();
            }
            runtime.setUpdatePolicy(std.Io.Dir.cwd(), apex, entry.keyText(), zone_path) catch {
                runtime.deinit();
                return error.BadConfiguration;
            };
        }
        if (self.config.minimal_any_ttl) |ttl| runtime.answer_policy.minimal_any_ttl = ttl;
        if (self.config.minimal_any_ttl_tcp) |ttl| runtime.answer_policy.minimal_any_ttl_tcp = ttl;
        // RFC 7828 section 3.3.2: the option carries the idle timeout the
        // connection holds, so it carries the timeout the operator set.
        if (self.config.tcp_limits.idle_timeout) |seconds| {
            runtime.answer_policy.tcp_keepalive_timeout = @intCast(seconds * response_mod.TCP_KEEPALIVE_UNITS_PER_SECOND);
        }
        // The signing key moves into the runtime, which owns it from here on
        // and wipes it when it is deinited.
        runtime.dnssec_session = self.dnssec_session;
        self.dnssec_session = null;
        // The delta log of every zone is restored from the journal file, and
        // the journal the running server appends to is the one the file is
        // open on.
        if (self.journal) |*journal| {
            restoreJournal(self.allocator, &runtime, journal) catch return Error.BadConfiguration;
            journal_mod.activate(journal);
        }
        self.blocklist = .{};
        self.config = .{};
        return runtime;
    }

    pub fn deinit(self: *ServerContext) void {
        if (self.journal) |*journal| {
            journal_mod.deactivate(journal);
            journal.close();
            self.journal = null;
        }
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.blocklist = .{};
        self.keyring.deinit();
        self.config = .{};
        if (self.dnssec_session) |*session| session.deinit();
        self.dnssec_session = null;
        // Anchors that never reached a policy (load failed, or the context was
        // dropped without takeRuntime) are still owned here.
        self.anchors.deinit(self.allocator);
        self.anchors = .{};
    }
};

/// Opens the RFC 1995 delta journal the configuration names. The file is
/// created when it is not there yet, and it sits directly in the
/// configuration directory: a symlink could carry the server's writes
/// outside it.
fn openJournal(dir: std.Io.Dir, io: std.Io, path: []const u8) !journal_mod.Journal {
    if (!isConfinedPath(path)) return Error.InvalidReferencedPath;
    if (std.mem.indexOfScalar(u8, path, '/') != null) return Error.InvalidReferencedPath;
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return journal_mod.Journal.open(io, dir, path),
        else => return err,
    };
    if (stat.kind != .file) return Error.InvalidReferencedPath;
    return journal_mod.Journal.open(io, dir, path);
}

/// Puts the transitions the journal file holds back into the runtime's
/// per-zone delta logs, so an IXFR client at an old serial is answered
/// incrementally after a restart.
fn restoreJournal(allocator: std.mem.Allocator, runtime: *auth_runtime.Runtime, journal: *const journal_mod.Journal) !void {
    // The delta log is parallel to the zone list: the runtime reads the log
    // of a zone by index, and a length mismatch means no history at all.
    while (runtime.transfer_delta_logs.items.len < runtime.zones.items.len) {
        runtime.transfer_delta_logs.append(runtime.allocator, .{}) catch return error.OutOfMemory;
    }
    for (runtime.zones.items, 0..) |*zone, index| {
        runtime.transfer_delta_logs.items[index].setOrigin(zone.originText());
    }
    const transitions = try journal.read(allocator);
    defer allocator.free(transitions);
    for (transitions) |transition| {
        for (runtime.zones.items, 0..) |*zone, index| {
            if (!std.ascii.eqlIgnoreCase(zone.originText(), transition.originText())) continue;
            // A transition that is not RFC 1982 newer is a corrupt record:
            // it is skipped, and the zone falls back to a full transfer.
            runtime.transfer_delta_logs.items[index].restore(transition.from_serial, transition.to_serial) catch continue;
        }
    }
}

/// One operator-facing startup failure line. A test build has no operator and
/// the test runner fails on any stderr write, so the line is printed by the
/// server build only.
fn printStartupError(io: std.Io, message: []const u8) void {
    if (builtin.is_test) return;
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    stderr_writer.interface.print("error: {s}\n", .{message}) catch {};
    stderr_writer.interface.flush() catch {};
}

fn readReferencedFile(dir: std.Io.Dir, io: std.Io, sub_path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    ensureConfined(dir, io, sub_path) catch |err| switch (err) {
        error.FileNotFound => return Error.MissingReferencedFile,
        else => return err,
    };
    return dir.readFileAlloc(io, sub_path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return Error.MissingReferencedFile,
        else => return err,
    };
}

/// RFC 5001 section 2.4 hex digits to the opaque OPTION-DATA octets the wire
/// carries. The config parser has already rejected an odd count or a non-hex
/// character, so every failure here is the same misconfiguration.
fn decodeNsid(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(bytes);
    _ = std.fmt.hexToBytes(bytes, text) catch return error.BadConfiguration;
    return bytes;
}
/// RFC 9567 section 5: the agent domain an operator configured, as the name
/// the Report-Channel option carries, and the domain the monitoring agent
/// monitors. A name written without its trailing dot is completed, and a
/// value that is not a domain name is refused, so a broken agent domain stops
/// the server instead of advertising a channel nobody can report to.
fn agentDomainName(text: []const u8) !dns_name.Name {
    if (text.len == 0) return error.BadConfiguration;
    var buffer: [256]u8 = undefined;
    const absolute = if (text[text.len - 1] == '.') text else blk: {
        if (text.len + 1 > buffer.len) return error.BadConfiguration;
        @memcpy(buffer[0..text.len], text);
        buffer[text.len] = '.';
        break :blk buffer[0 .. text.len + 1];
    };
    return dns_name.Name.fromText(absolute) catch error.BadConfiguration;
}

/// Loads one zone text into the server context: parse, name check, sign, and
/// the RFC 8976 ZONEMD checks. Shared by a configured zone file and the
/// RFC 9432 catalog zone synthesized from the configuration.
fn loadZoneText(
    context: *ServerContext,
    allocator: std.mem.Allocator,
    io: std.Io,
    zone_text: []const u8,
    expected_name: []const u8,
    dnssec_key: ?*signer.Key,
    now_seconds: u32,
    chain_policy: ?signer.ChainPolicy,
) !void {
    var zone_file = try zone_parser.ZoneFile.parse(zone_text);
    errdefer zone_file.deinit();
    if (!zoneNamesEqual(expected_name, zone_file.originText())) {
        return Error.ZoneNameMismatch;
    }
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    errdefer zone.deinit();
    // RFC 4035 section 2.3: signing adds DNSKEY, DS, RRSIG, and NSEC to
    // the loaded zone, so the signed RRsets are served from here on
    // without touching the zone file on disk.
    if (dnssec_key) |key| {
        signer.signZone(context.allocator, &zone, key, .{
            .inception = now_seconds,
            .expiration = now_seconds + signature_validity_seconds,
            .chain = chain_policy,
        }) catch |err| switch (err) {
            // The zone states the parameters of its own chain and the
            // configuration names other ones: the zone is refused
            // rather than served as two chains.
            error.BadChainParameters => {
                var report: [256]u8 = undefined;
                const message = std.fmt.bufPrint(&report, "zone {s}: the configuration names NSEC3 parameters the zone's apex NSEC3PARAM contradicts", .{zone.originText()}) catch "zone: the configuration names NSEC3 parameters the zone's apex NSEC3PARAM contradicts";
                printStartupError(io, message);
                return Error.BadDnssecKey;
            },
            else => return Error.BadDnssecKey,
        };
    }
    // RFC 8976 section 4 steps 1 to 3: a zone that carries an apex
    // ZONEMD record and is named by a configured trust anchor is
    // expected to be signed, and its SOA and ZONEMD RRsets must carry
    // valid signatures chaining up to that anchor. The chain is
    // checked before the digest, so a zone that is not authentic is
    // never accepted on the strength of its digest alone.
    if (zonemd.hasApexRecord(&zone)) {
        const chained = validate_mod.zoneSignedToAnchor(
            allocator,
            &context.anchors,
            &zone,
            &.{ RecordType.SOA.code(), RecordType.ZONEMD.code() },
            now_seconds,
        ) catch false;
        if (!chained) {
            var report: [256]u8 = undefined;
            const message = std.fmt.bufPrint(&report, "zone {s}: the SOA and ZONEMD RRsets do not carry valid signatures chaining to a configured trust anchor", .{zone.originText()}) catch "zone: the SOA and ZONEMD RRsets are not signed to a configured trust anchor";
            printStartupError(io, message);
            return Error.ZonemdSignatureInvalid;
        }
    } else {
        // RFC 8976 section 4 step 2: for a zone where signatures are
        // expected, the existence of the apex ZONEMD record must be
        // validated. A zone that publishes no ZONEMD is a different
        // answer from a zone whose ZONEMD does not match, and the zone
        // tells the two apart with its own denial records: the absence
        // is proven only when an NSEC or NSEC3 record of the zone
        // denies the RRset. An unproven absence leaves absent and
        // unknown indistinguishable, so the server refuses to start.
        const absence = validate_mod.zoneZonemdAbsence(
            allocator,
            &context.anchors,
            &zone,
            now_seconds,
        ) catch .unknown;
        if (absence == .unknown) {
            var report: [256]u8 = undefined;
            const message = std.fmt.bufPrint(&report, "zone {s}: no apex ZONEMD record, and no NSEC or NSEC3 record of the zone proves that it does not exist", .{zone.originText()}) catch "zone: the absence of the apex ZONEMD record is not proven";
            printStartupError(io, message);
            return Error.ZonemdAbsenceUnproven;
        }
    }
    // RFC 8976 section 4: refuse to serve a zone whose apex ZONEMD
    // record does not match the loaded data, so a corrupted or
    // tampered zone file fails closed at startup instead of answering
    // queries. The report names the zone and both digests.
    var zonemd_report: [zonemd.report_max_len]u8 = undefined;
    _ = zonemd.verify(&zone, allocator, &zonemd_report) catch {
        const written = std.mem.indexOfScalar(u8, &zonemd_report, 0) orelse zonemd_report.len;
        printStartupError(io, zonemd_report[0..written]);
        return Error.ZonemdMismatch;
    };
    try context.zones.append(allocator, zone);
}

/// The RFC 9432 section 4 catalog zone for the zones this server serves: the
/// schema-2 version property, one member node per configured zone, and the
/// SOA and NS that make the zone syntactically valid. Member labels are the
/// configuration order, so the synthesized zone is stable across restarts.
fn synthesizeCatalogZoneText(
    allocator: std.mem.Allocator,
    apex: []const u8,
    members: []const parser.Zone,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var line: [512]u8 = undefined;
    try out.appendSlice(allocator, try std.fmt.bufPrint(
        &line,
        "$ORIGIN {s}\n$TTL 3600\n@ IN SOA invalid. hostmaster.invalid. 1 3600 900 1209600 0\n@ IN NS invalid.\nversion IN TXT \"2\"\n",
        .{apex},
    ));
    for (members, 1..) |member, number| {
        const name = member.nameText();
        const dotted = name.len != 0 and name[name.len - 1] == '.';
        try out.appendSlice(allocator, try std.fmt.bufPrint(&line, "m{d}.zones IN PTR {s}{s}\n", .{
            number,
            name,
            if (dotted) "" else ".",
        }));
    }
    return out.toOwnedSlice(allocator);
}

/// Lowercase an override apex with its trailing dot, for comparison against
/// `local_zone.Zone.apex`. The parser stores raw text; the runtime compares
/// case-insensitively, but canonicalizing here keeps one comparison path.
fn lowerDot(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const dotted = text.len != 0 and text[text.len - 1] == '.';
    const out = try allocator.alloc(u8, text.len + @intFromBool(!dotted));
    errdefer allocator.free(out);
    for (text, 0..) |byte, i| out[i] = std.ascii.toLower(byte);
    if (!dotted) out[out.len - 1] = '.';
    return out;
}

fn ensureConfined(dir: std.Io.Dir, io: std.Io, sub_path: []const u8) !void {
    if (!isConfinedPath(sub_path)) return Error.InvalidReferencedPath;
    // The confinement base is resolved through "." rather than Dir.realPath.
    // Dir.realPath issues fcntl(handle, F_GETPATH) on the handle itself, and the
    // handle of Dir.cwd() is AT_FDCWD, which fcntl rejects with EBADF; every
    // caller that passes a cwd-relative Dir therefore failed to load at all.
    // realPathFile opens "." to obtain a real descriptor first, then reports the
    // same fully canonicalised base path that realPath reports for a real
    // descriptor, so the comparison below stays byte-for-byte as strict.
    var base_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const base_len = try dir.realPathFile(io, ".", &base_buffer);
    const base = base_buffer[0..base_len];
    var target_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const target_len = dir.realPathFile(io, sub_path, &target_buffer) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.SymLinkLoop => return Error.InvalidReferencedPath,
        else => return err,
    };
    if (!isWithinBase(base, target_buffer[0..target_len])) return Error.InvalidReferencedPath;
}

fn isConfinedPath(sub_path: []const u8) bool {
    if (sub_path.len == 0) return false;
    if (std.mem.indexOfScalar(u8, sub_path, 0) != null) return false;
    if (std.fs.path.isAbsolute(sub_path)) return false;
    var parts = std.mem.splitScalar(u8, sub_path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn isWithinBase(base: []const u8, target: []const u8) bool {
    if (base.len == 1 and base[0] == '/') return target.len > 0 and target[0] == '/';
    if (target.len <= base.len) return false;
    if (!std.mem.eql(u8, target[0..base.len], base)) return false;
    return target[base.len] == '/';
}

fn zoneNamesEqual(configured: []const u8, parsed: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(configured, parsed)) return true;
    if (std.mem.endsWith(u8, parsed, ".") and std.ascii.eqlIgnoreCase(configured, parsed[0 .. parsed.len - 1])) return true;
    if (std.mem.endsWith(u8, configured, ".") and std.ascii.eqlIgnoreCase(configured[0 .. configured.len - 1], parsed)) return true;
    return false;
}

fn parseKeyTextAndClear(key_text: []u8) keyring_mod.Error!keyring_mod.Keyring {
    defer std.crypto.secureZero(u8, key_text);
    return keyring_mod.Keyring.parse(key_text);
}

fn parseDnssecKeyTextAndClear(key_text: []u8) signer.Error!signer.Key {
    defer std.crypto.secureZero(u8, key_text);
    return signer.parseKey(key_text);
}

test "server context applies the configured TCP limits to the listener" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const previous_limits = listener.tcpLimits();
    defer listener.setTcpLimits(previous_limits);

    try dir.dir.writeFile(io, .{
        .sub_path = "limits.gdns",
        .data = "tcp-max-connections-per-source 25\ntcp-max-connection-duration 60\n",
    });
    var context = try ServerContext.load(dir.dir, io, "limits.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(u32, 25), listener.tcpLimits().max_connections_per_source.?);
    try std.testing.expectEqual(@as(u32, 60), listener.tcpLimits().max_connection_duration.?);

    // A configuration without the directives leaves the project's own policy
    // in force.
    try dir.dir.writeFile(io, .{ .sub_path = "plain.gdns", .data = "listen dns udp 127.0.0.1:1053\n" });
    var plain = try ServerContext.load(dir.dir, io, "plain.gdns", std.testing.allocator);
    defer plain.deinit();
    try std.testing.expect(listener.tcpLimits().max_connections_per_source == null);
    try std.testing.expect(listener.tcpLimits().max_connection_duration == null);
}

test "server context carries the TCP idle timeout to the listener and the answer policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const previous_limits = listener.tcpLimits();
    defer listener.setTcpLimits(previous_limits);

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\tcp-idle-timeout 30
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The listener waits the configured time for a frame on an idle
    // connection, and the keepalive option carries that same timeout.
    try std.testing.expectEqual(@as(u32, 30), listener.tcpLimits().idle_timeout.?);
    try std.testing.expectEqual(@as(u32, 30), listener.tcpIdleTimeout().seconds);
    try std.testing.expectEqual(@as(u16, 300), runtime.answer_policy.tcp_keepalive_timeout);

    // A configuration without the directive leaves the project's own five
    // seconds in force.
    try dir.dir.writeFile(io, .{ .sub_path = "plain.gdns", .data = "zone one.example primary one.zone\n" });
    var plain = try ServerContext.load(dir.dir, io, "plain.gdns", std.testing.allocator);
    defer plain.deinit();
    var plain_runtime = try plain.takeRuntime(io);
    defer plain_runtime.deinit();
    try std.testing.expect(listener.tcpLimits().idle_timeout == null);
    try std.testing.expectEqual(@as(u32, 5), listener.tcpIdleTimeout().seconds);
    try std.testing.expectEqual(@as(u16, 50), plain_runtime.answer_policy.tcp_keepalive_timeout);
}

test "server context publishes a catalog zone listing the served zones" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "two.zone", .data = "$ORIGIN two.example.\n$TTL 3600\n@ IN SOA ns.two.example. hostmaster.two.example. 1 3600 900 1209600 3600\n@ IN NS ns.two.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\zone two.example primary two.zone
        \\catalog-zone catalog.example.
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 3), context.zones.items.len);

    var catalog: ?*const zone_index.Zone = null;
    for (context.zones.items) |*zone| {
        if (std.ascii.eqlIgnoreCase(zone.originText(), "catalog.example.")) catalog = zone;
    }
    const z = catalog orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), countType(z.*, .TXT));
    try std.testing.expectEqual(@as(usize, 2), countType(z.*, .PTR));
    try std.testing.expectEqual(@as(usize, 1), countType(z.*, .SOA));
    try std.testing.expectEqual(@as(usize, 1), countType(z.*, .NS));

    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // version.catalog.example. TXT answers "2", and m1.zones.catalog.example.
    // PTR answers the first configured zone.
    const version_query = [_]u8{
        0x22, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'v',  'e',  'r',  's',  'i',  'o',  'n',  7,    'c',  'a',  't',
        'a',  'l',  'o',  'g',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x10, 0x00, 0x01,
    };
    var output: [512]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const version_response = try runtime.answer(&version_query, &output);
    const parsed_version = try dns_message.Message.parse(arena.allocator(), version_response);
    try std.testing.expectEqual(@as(u16, 1), parsed_version.header.answer_count);
    try std.testing.expect(parsed_version.answers.items[0].rrtype.eql(.TXT));

    const member_query = [_]u8{
        0x22, 0x23, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        2,    'm',  '1',  5,    'z',  'o',  'n',  'e',  's',  7,    'c',  'a',
        't',  'a',  'l',  'o',  'g',  7,    'e',  'x',  'a',  'm',  'p',  'l',
        'e',  0,    0x00, 0x0c, 0x00, 0x01,
    };
    const member_response = try runtime.answer(&member_query, &output);
    const parsed_member = try dns_message.Message.parse(arena.allocator(), member_response);
    try std.testing.expectEqual(@as(u16, 1), parsed_member.header.answer_count);
    try std.testing.expect(parsed_member.answers.items[0].rrtype.eql(.PTR));
}

// A configuration that names the catalog apex as one of its own zones cannot
// be published: the catalog would list itself.
test "server context refuses a catalog apex that names a served zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary one.zone\ncatalog-zone ONE.example\n" });

    try std.testing.expectError(Error.BadCatalogZone, ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator));
}

test "allow-update for a zone or key the server does not hold fails the load" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{
        .sub_path = "tsig.keys",
        .data = "key \"update-key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };\n",
    });
    try dir.dir.writeFile(io, .{
        .sub_path = "config.gdns",
        .data = "zone one.example primary one.zone\ntsig-key-file tsig.keys\nallow-update one.example update-key.\n",
    });
    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();
    try std.testing.expectEqual(@as(usize, 1), runtime.update_policies.items.len);
    try std.testing.expectEqualStrings("one.example", runtime.update_policies.items[0].origin);

    // A zone the server does not serve is a configuration error.
    try dir.dir.writeFile(io, .{
        .sub_path = "bad-zone.gdns",
        .data = "zone one.example primary one.zone\ntsig-key-file tsig.keys\nallow-update other.example. update-key.\n",
    });
    var bad_zone = try ServerContext.load(dir.dir, io, "bad-zone.gdns", std.testing.allocator);
    defer bad_zone.deinit();
    try std.testing.expectError(error.BadConfiguration, bad_zone.takeRuntime(io));

    // A key the keyring does not hold is a configuration error too.
    try dir.dir.writeFile(io, .{
        .sub_path = "bad-key.gdns",
        .data = "zone one.example primary one.zone\ntsig-key-file tsig.keys\nallow-update one.example missing-key.\n",
    });
    var bad_key = try ServerContext.load(dir.dir, io, "bad-key.gdns", std.testing.allocator);
    defer bad_key.deinit();
    try std.testing.expectError(error.BadConfiguration, bad_key.takeRuntime(io));
}

test "server context loads the configured TSIG key file during startup" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{
        .sub_path = "tsig.keys",
        .data = "key \"Example.COM.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };\n",
    });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "tsig-key-file tsig.keys\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    try std.testing.expectEqual(@as(usize, 1), context.keyring.len);
    const name = try @import("../dns/name.zig").Name.fromText("example.com.");
    try std.testing.expect(context.keyring.findAlgorithm(name, .hmac_sha256) != null);
}

test "server context rejects an unreadable TSIG key file" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "tsig-key-file missing.keys\n" });
    try std.testing.expectError(
        error.MissingReferencedFile,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context preserves non-missing TSIG key file I/O errors" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.createDir(io, "tsig.keys", .default_dir);
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "tsig-key-file tsig.keys\n" });

    try std.testing.expectError(
        error.IsDir,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context clears the temporary TSIG key text after parsing" {
    var key_text = "key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };".*;
    var ring = try parseKeyTextAndClear(&key_text);
    defer ring.deinit();

    for (key_text) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

/// The RFC 8080 section 6.1 Ed25519 example key. It is published in the RFC,
/// so nothing secret enters the repository, and the DNSKEY it derives is the
/// one the RFC's own DS digest pins.
const dnssec_test_key = "ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n";

/// The RFC 6605 section 6.1 ECDSA P-256 example key, published in the RFC. It
/// is the key-signing key of the zone that separates the roles.
const dnssec_test_ksk_key = "ecdsap256sha256 GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n";

/// The RFC 6605 section 6.2 ECDSA P-384 example key, published in the RFC. It
/// is the second key-signing key of a Double-Signature rollover.
const dnssec_test_new_ksk_key = "ecdsap384sha384 WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR\n";

const dnssec_test_zone =
    \\$ORIGIN signed.example.
    \\$TTL 3600
    \\@ IN SOA ns1.signed.example. hostmaster.signed.example. 2026100501 3600 900 1209600 3600
    \\@ IN NS ns1.signed.example.
    \\ns1 IN A 192.0.2.1
    \\www IN A 192.0.2.80
    \\* IN A 192.0.2.99
;

/// The same zone with the apex DNSKEY already present. A Zig multiline literal
/// drops its final newline, so the appended record starts with one.
const dnssec_test_already_signed_zone = dnssec_test_zone ++
    "\n@ IN DNSKEY \\# 36 0101030fccf9d9fd0c047bb4bc0b948fcf639f4b9451e34013936feb62713dc472048a3b\n";

fn countType(zone: zone_index.Zone, rrtype: @import("../dns/types.zig").RecordType) usize {
    var total: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(rrtype)) total += 1;
    }
    return total;
}

fn hasRrsigCovering(zone: zone_index.Zone, owner: []const u8, covered: u16) bool {
    return countRrsigCovering(zone, owner, covered) != 0;
}

/// How many signatures cover `covered` at `owner`. RFC 6781 section 4.1.2
/// gives the DNSKEY RRset one signature per key-signing key, so the count
/// tells the two apart.
fn countRrsigCovering(zone: zone_index.Zone, owner: []const u8, covered: u16) usize {
    var total: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(record.owner, owner)) continue;
        const rdata = zone_parser.parseRData(.RRSIG, record.rdataText()) catch return total;
        const bytes = switch (rdata) {
            .Unknown => |unknown| unknown.bytes(),
            else => return total,
        };
        if (bytes.len < 2) continue;
        if (std.mem.readInt(u16, bytes[0..2], .big) == covered) total += 1;
    }
    return total;
}

/// The DNSKEY RDATA the zone publishes, which a validator anchors on. The
/// record is served opaque, so the bytes are copied out of the parser's
/// value.
fn zoneDnskeyRdata(allocator: std.mem.Allocator, zone: zone_index.Zone) ![]const u8 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.DNSKEY)) continue;
        const rdata = try zone_parser.parseRData(.DNSKEY, record.rdataText());
        switch (rdata) {
            .Unknown => |unknown| return allocator.dupe(u8, unknown.bytes()),
            else => return error.TestUnexpectedResult,
        }
    }
    return error.TestUnexpectedResult;
}

test "a signed zone served by the runtime answers a DO=1 ANY query with a valid RRSIG" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // A QTYPE=ANY query for www.signed.example. with an EDNS(0) OPT record
    // that sets DO.
    const query_bytes = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'w',  'w',  'w',  6,    's',  'i',  'g',  'n',  'e',  'd',  7,
        'e',  'x',  'a',  'm',  'p',  'l',  'e',  0,    0x00, 0xff, 0x00, 0x01,
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    };
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(&query_bytes, &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    // RFC 8482 section 4.2: the synthesized HINFO and, because the zone is
    // signed and the query set DO=1, a valid RRSIG over it.
    try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.HINFO));
    try std.testing.expect(response.answers.items[1].rrtype.eql(.RRSIG));

    // The signature is checked by the project's own validator, against the
    // DNSKEY the zone publishes.
    const dnskey_rdata = try zoneDnskeyRdata(arena.allocator(), runtime.zones.items[0]);
    var anchors = validate_mod.Anchors{};
    anchors.items[0] = .{
        .owner = try @import("../dns/name.zig").Name.fromText("signed.example."),
        .rrtype = .DNSKEY,
        .rdata = dnskey_rdata,
    };
    anchors.len = 1;
    const query = try dns_message.Message.parseQuery(arena.allocator(), &query_bytes);
    const now_seconds: u32 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const result = try validate_mod.validate(arena.allocator(), &anchors, query, response, &.{}, now_seconds);
    try std.testing.expectEqual(validate_mod.Status.secure, result.status);

    // The private key never reaches the wire: neither the secret as it is
    // written in the key file nor the octets it decodes to.
    try std.testing.expect(std.mem.indexOf(u8, response_bytes, dnssec_test_key) == null);
    var secret: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&secret, "DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=");
    try std.testing.expect(std.mem.indexOf(u8, response_bytes, &secret) == null);
}

/// The key tag the zone's DS states, which is the key tag of the key the
/// parent points at.
fn dsKeyTag(zone: zone_index.Zone) !u16 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.DS)) continue;
        const rdata = try zone_parser.parseRData(.DS, record.rdataText());
        switch (rdata) {
            .Unknown => |unknown| return std.mem.readInt(u16, unknown.bytes()[0..2], .big),
            else => return error.TestUnexpectedResult,
        }
    }
    return error.TestUnexpectedResult;
}

/// The DNSKEY flags the zone publishes for the key of `algorithm`. RFC 5011
/// section 3 puts the REVOKE bit in the flags of the key being revoked.
fn dnskeyFlags(zone: zone_index.Zone, algorithm: u8) !u16 {
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.DNSKEY)) continue;
        const rdata = try zone_parser.parseRData(.DNSKEY, record.rdataText());
        switch (rdata) {
            .Unknown => |unknown| {
                const bytes = unknown.bytes();
                if (bytes[3] != algorithm) continue;
                return std.mem.readInt(u16, bytes[0..2], .big);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    return error.TestUnexpectedResult;
}

test "server context signs every zone named by the configured DNSSEC key file" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\n" });

    // std.testing.allocator fails this test if the generated DNSKEY, DS, RRSIG,
    // and NSEC records outlive the zone, which is the whole reason the zone
    // now carries the allocator that made them.
    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    const zone = context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 1), countType(zone, .DNSKEY));
    try std.testing.expectEqual(@as(usize, 1), countType(zone, .DS));
    // Apex, ns1, www, and the wildcard owner are authoritative, so each joins
    // the NSEC chain with one record.
    try std.testing.expectEqual(@as(usize, 4), countType(zone, .NSEC));
    // The apex has no A RRset, so it is signed for the types it does carry.
    try std.testing.expect(hasRrsigCovering(zone, "signed.example.", RecordType.SOA.code()));
    try std.testing.expect(hasRrsigCovering(zone, "signed.example.", RecordType.DNSKEY.code()));
    try std.testing.expect(hasRrsigCovering(zone, "www.signed.example.", RecordType.A.code()));
    // RFC 4034 section 3.1.3: the wildcard owner is signed with one label
    // fewer, because the signature covers the expanded names below it.
    try std.testing.expect(hasRrsigCovering(zone, "*.signed.example.", RecordType.A.code()));
}

test "server context signs a zone with a key-signing key beside the zone-signing key" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    // RFC 6781 section 3.1: the zone publishes both keys, and the one DS it
    // publishes states the key-signing key.
    const zone = context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 2), countType(zone, .DNSKEY));
    try std.testing.expectEqual(@as(usize, 1), countType(zone, .DS));
    try std.testing.expectEqual(@as(u16, 55648), try dsKeyTag(zone));
    // The DNSKEY RRset is signed by the key-signing key, and the rest of the
    // zone by the zone-signing key.
    try std.testing.expect(hasRrsigCovering(zone, "signed.example.", RecordType.DNSKEY.code()));
    try std.testing.expect(hasRrsigCovering(zone, "signed.example.", RecordType.SOA.code()));
}

test "a zone with a second key-signing key publishes both DNSKEYs at the apex" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_new_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file new-ksk.key\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    // RFC 6781 section 4.1.2: the zone publishes the zone-signing key and
    // both key-signing keys, and the one DS it publishes states the key the
    // parent's DS points at.
    const zone = context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 3), countType(zone, .DNSKEY));
    try std.testing.expectEqual(@as(usize, 1), countType(zone, .DS));
    try std.testing.expectEqual(@as(u16, 55648), try dsKeyTag(zone));
    // The DNSKEY RRset carries one signature per key-signing key.
    try std.testing.expectEqual(@as(usize, 2), countRrsigCovering(zone, "signed.example.", RecordType.DNSKEY.code()));
    try std.testing.expectEqual(@as(usize, 1), countRrsigCovering(zone, "signed.example.", RecordType.SOA.code()));
}

test "a revoked second key-signing key is published with the REVOKE bit" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_new_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file new-ksk.key revoked\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    // RFC 6781 section 4.1.2.1: the key being removed is published with the
    // REVOKE bit of RFC 5011 section 3 set, so its DNSKEY carries flags 385
    // and not the 257 of a key that is not revoked.
    const zone = context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 3), countType(zone, .DNSKEY));
    try std.testing.expectEqual(@as(u16, 385), try dnskeyFlags(zone, 14));
    try std.testing.expectEqual(@as(u16, 257), try dnskeyFlags(zone, 13));
    // The DS still states the key `dnssec-ksk-file` names, and the DNSKEY
    // RRset is still covered by one signature per key-signing key.
    try std.testing.expectEqual(@as(u16, 55648), try dsKeyTag(zone));
    try std.testing.expectEqual(@as(usize, 2), countRrsigCovering(zone, "signed.example.", RecordType.DNSKEY.code()));
}

test "server context refuses a second key-signing key marked with a word it does not know" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_new_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file new-ksk.key bogus\n" });

    // Only the word `revoked` marks the key, so the server refuses to start
    // rather than publish a key the operator did not ask to revoke.
    try std.testing.expectError(
        error.BadDirective,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses a second key-signing key without a zone-signing key" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_new_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file new-ksk.key\n" });

    // A second key-signing key without a zone-signing key has nothing to
    // sign and no DS to name, so the server refuses to start.
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses a second key-signing key without a key-signing key to name in the DS" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_new_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-new-ksk-file new-ksk.key\n" });

    // The DS the zone publishes states one key, and a second key-signing key
    // with no key-signing key to name in it has no place in the scheme.
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses a second key-signing key that is a key the zone already publishes" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });

    // The same key as the first key-signing key: the DNSKEY RRset would
    // hold the same record twice.
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_ksk_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file new-ksk.key\n" });
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );

    // The same key as the zone-signing key: the same DNSKEY twice.
    try dir.dir.writeFile(io, .{ .sub_path = "new-ksk.key", .data = dnssec_test_key });
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses a second key-signing key file that is missing or unusable" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "ksk.key", .data = dnssec_test_ksk_key });

    // A key file the configuration names but that does not exist is refused
    // like every other key file.
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file missing.key\n" });
    try std.testing.expectError(
        error.MissingReferencedFile,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );

    // A key file that does not parse is refused like every other key file.
    try dir.dir.writeFile(io, .{ .sub_path = "bad.key", .data = "ed25519 not-base64\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\ndnssec-new-ksk-file bad.key\n" });
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses a configuration whose key-signing key file does not exist" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-ksk-file missing.key\n" });

    // The key file the configuration names does not exist, so the server
    // refuses to start rather than sign with half the keys it was given.
    try std.testing.expectError(
        error.MissingReferencedFile,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context publishes the chain the configuration names" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    // A zone that states an apex NSEC3PARAM, and a configuration that asks
    // for the NSEC chain: the zone publishes the RFC 4034 chain.
    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone ++ "\n@ IN NSEC3PARAM 1 0 0 -\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-chain nsec\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    const zone = context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 4), countType(zone, .NSEC));
    try std.testing.expectEqual(@as(usize, 0), countType(zone, .NSEC3));

    // The NSEC3 chain the configuration names, in a zone that states no
    // NSEC3PARAM: the signer publishes the apex NSEC3PARAM that states the
    // chain's parameters.
    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-chain nsec3 0 -\n" });

    var nsec3_context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer nsec3_context.deinit();
    const nsec3_zone = nsec3_context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 0), countType(nsec3_zone, .NSEC));
    try std.testing.expectEqual(@as(usize, 4), countType(nsec3_zone, .NSEC3));
    try std.testing.expectEqual(@as(usize, 1), countType(nsec3_zone, .NSEC3PARAM));

    // The same chain in a zone that states the parameters itself: the zone
    // keeps its own apex NSEC3PARAM, and the chain is the one it describes.
    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone ++ "\n@ IN NSEC3PARAM 1 0 0 -\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-chain nsec3 0 -\n" });

    var stated_context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer stated_context.deinit();
    const stated_zone = stated_context.zones.items[0];
    try std.testing.expectEqual(@as(usize, 0), countType(stated_zone, .NSEC));
    try std.testing.expectEqual(@as(usize, 4), countType(stated_zone, .NSEC3));
    try std.testing.expectEqual(@as(usize, 1), countType(stated_zone, .NSEC3PARAM));
}

test "server context refuses a configuration whose NSEC3 parameters the zone contradicts" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone ++ "\n@ IN NSEC3PARAM 1 0 2 73616c74\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\ndnssec-chain nsec3 0 -\n" });

    // The zone states the parameters of its own chain and the configuration
    // names other ones, so the zone is refused rather than served as two
    // chains.
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context refuses an unusable DNSSEC key file and an already signed zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "bad.key", .data = "ed25519 not-base64\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file bad.key\n" });
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );

    // A zone file that already carries DNSSEC records is refused rather than
    // signed twice, so an operator cannot publish two sets of signatures.
    try dir.dir.writeFile(io, .{ .sub_path = "signed.example.zone", .data = dnssec_test_already_signed_zone });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone signed.example primary signed.example.zone\ndnssec-key-file zsk.key\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try std.testing.expectError(
        error.BadDnssecKey,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context rejects absolute referenced zone paths" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary /etc/passwd\n" });
    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context rejects parent-traversal referenced paths" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary ../escape.zone\n" });
    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );

    try dir.dir.writeFile(io, .{ .sub_path = "config2.gdns", .data = "blocklist file sub/../../escape.list\n" });
    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "config2.gdns", std.testing.allocator),
    );

    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "../escape.gdns", std.testing.allocator),
    );
}

test "server context rejects NUL in referenced paths" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary a\x00b.zone\n" });
    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context rejects symlink escape outside the base directory" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var outer = std.testing.tmpDir(.{});
    defer outer.cleanup();

    try outer.dir.writeFile(io, .{
        .sub_path = "outer.zone",
        .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n",
    });
    var outer_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const outer_len = try outer.dir.realPathFile(io, "outer.zone", &outer_buffer);
    const outer_absolute = outer_buffer[0..outer_len];

    try dir.dir.symLink(io, outer_absolute, "escape.zone", .{});
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary escape.zone\n" });
    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context canonicalizes redundant components inside the base directory" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.createDir(io, "sub", .default_dir);
    try dir.dir.writeFile(io, .{
        .sub_path = "sub/one.zone",
        .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n",
    });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary sub/./one.zone\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

/// RFC 8976 Appendix A.1 zone carrying the digest the RFC itself publishes.
const zonemd_verified_zone_text =
    \\$ORIGIN example.
    \\$TTL 86400
    \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
    \\@ IN NS ns1
    \\@ IN NS ns2
    \\@ IN ZONEMD 2018031900 1 1 (
    \\    c68090d90a7aed71
    \\    6bc459f9340e3d7c
    \\    1370d4d24b7e2fc3
    \\    a1ddc0b9a87153b9
    \\    a9713b3c9ae5cc27
    \\    777f98b8e730044c )
    \\ns1 3600 IN A 203.0.113.63
    \\ns2 3600 IN AAAA 2001:db8::63
    \\
;

/// The same zone without the ZONEMD record, so the absence of the RRset is
/// what RFC 8976 section 4 step 2 has to resolve.
const zonemd_absent_zone_text =
    \\$ORIGIN example.
    \\$TTL 86400
    \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
    \\@ IN NS ns1
    \\ns1 3600 IN A 203.0.113.63
    \\
;

/// The same zone with every digest digit changed to zero, so the zone loads
/// but no longer matches its ZONEMD record.
const zonemd_zone_text =
    \\$ORIGIN example.
    \\$TTL 86400
    \\@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
    \\@ IN NS ns1
    \\@ IN NS ns2
    \\@ IN ZONEMD 2018031900 1 1 (
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000
    \\    0000000000000000 )
    \\ns1 3600 IN A 203.0.113.63
    \\ns2 3600 IN AAAA 2001:db8::63
    \\
;

test "server context loads a zone whose ZONEMD digest matches" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zonemd_verified_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary one.zone\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

test "server context refuses to start on a ZONEMD digest mismatch" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zonemd_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary one.zone\n" });

    try std.testing.expectError(
        Error.ZonemdMismatch,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

/// The RFC 8080 section 6.1 Ed25519 DNSKEY: the trust anchor an operator
/// writes for the key this server signs a zone with.
const dnssec_test_anchor =
    \\example. DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=
;

/// The RFC 6605 section 6.1 P-256 DNSKEY: a trust anchor for a key the zone
/// is not signed with.
const dnssec_test_other_anchor =
    \\example. DNSKEY 257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==
;

test "server context accepts a signed zone whose apex ZONEMD chains to the trust anchor" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // RFC 8976 section 4: the zone carries an apex ZONEMD record, a trust
    // anchor names the zone, and the SOA and ZONEMD RRsets are signed to that
    // anchor, so the zone is accepted on the strength of both.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_verified_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = dnssec_test_anchor });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ndnssec-key-file zsk.key\ntrust-anchor-file anchors.txt\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

test "server context refuses to start when the apex ZONEMD does not chain to the trust anchor" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // The same zone and the same digest, but the anchor holds another key: the
    // signatures over the SOA and the ZONEMD cannot be made by it, so the zone
    // is not authentic and the server refuses to start.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_verified_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = dnssec_test_other_anchor });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ndnssec-key-file zsk.key\ntrust-anchor-file anchors.txt\n" });

    try std.testing.expectError(
        Error.ZonemdSignatureInvalid,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context checks the ZONEMD digest only when no trust anchor covers the zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // An anchor for another zone says nothing about this one, so the digest is
    // still checked as a checksum and the zone loads.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_verified_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = ". DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ndnssec-key-file zsk.key\ntrust-anchor-file anchors.txt\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

test "server context loads a signed zone that publishes no ZONEMD" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // RFC 8976 section 4 step 2: the zone publishes no ZONEMD record, and the
    // NSEC the signer writes at the apex denies the type, so the absence is
    // proven. That is an answer, not a failed verification, so the zone
    // loads.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_absent_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = dnssec_test_anchor });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ndnssec-key-file zsk.key\ntrust-anchor-file anchors.txt\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

test "server context refuses to start when the absence of the apex ZONEMD is not proven" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // The same zone, but signed by nobody: the anchor names the zone, so
    // RFC 8976 section 4 step 1 expects DNSSEC records, and with no NSEC or
    // NSEC3 record the absence of the ZONEMD cannot be told from the unknown,
    // so the server refuses to start.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_absent_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = dnssec_test_anchor });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ntrust-anchor-file anchors.txt\n" });

    try std.testing.expectError(
        Error.ZonemdAbsenceUnproven,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context still refuses a ZONEMD that does not match" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    // The zone publishes a ZONEMD record whose digest is wrong. The record is
    // signed to the anchor, so the chain holds and the digest decides, and a
    // zone that publishes a ZONEMD that does not match is a failed
    // verification rather than a zone that publishes none.
    try dir.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zonemd_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "zsk.key", .data = dnssec_test_key });
    try dir.dir.writeFile(io, .{ .sub_path = "anchors.txt", .data = dnssec_test_anchor });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone example. primary example.zone\ndnssec-key-file zsk.key\ntrust-anchor-file anchors.txt\n" });

    try std.testing.expectError(
        Error.ZonemdMismatch,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context carries the NAT64 prefix into the forwarding policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\forwarder 127.0.0.1:5353
        \\nat64-prefix 64:ff9b::/96
        \\nat64-prefix 2001:db8:100::/96 192.0.2.0/24
        \\dns64-exclude 2001:db8:1::/48
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The prefixes reach the resolver that answers the forwarding path.
    const policy = &runtime.resolver.?.policy;
    try std.testing.expectEqual(@as(usize, 2), policy.nat64_prefixes.len);
    try std.testing.expectEqual(@as(u8, 96), policy.nat64_prefixes.items[0].length);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x64, 0xff, 0x9b }, policy.nat64_prefixes.items[0].bytes[0..4]);
    try std.testing.expectEqual(@as(u8, 24), policy.nat64_prefixes.items[1].range.prefix);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 0 }, policy.nat64_prefixes.items[1].range.bytes[0..4]);
    // The excluded ranges reach the resolver too.
    try std.testing.expectEqual(@as(usize, 1), policy.dns64_excluded.len);
    try std.testing.expectEqual(@as(u8, 48), policy.dns64_excluded.items[0].prefix);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8 }, policy.dns64_excluded.items[0].bytes[0..4]);
}

test "server context carries the minimal ANY TTLs into the answer policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\minimal-any-ttl 300
        \\minimal-any-ttl-tcp 3600
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The TTLs reach the policy that builds the minimal ANY answer.
    try std.testing.expectEqual(@as(u32, 300), runtime.answer_policy.minimal_any_ttl);
    try std.testing.expectEqual(@as(u32, 3600), runtime.answer_policy.minimal_any_ttl_tcp.?);
}

test "server context carries the RFC 9520 failure cache time into the forwarding policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\forwarder 127.0.0.1:5353
        \\minimum-failure-cache-time 42
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The cache time reaches the resolver that holds the failure cache.
    try std.testing.expectEqual(@as(u32, 42), runtime.resolver.?.policy.failure_cache_seconds);
}

test "server context carries the denied source ports and the cacheable prefix into the forwarding policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\forwarder 127.0.0.1:5353
        \\forwarder-deny-port 53
        \\forwarder-deny-port 40000-40100
        \\client-subnet-max-prefix 24
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The denied ports and the maximum cacheable prefix reach the resolver
    // that answers the forwarding path.
    const policy = &runtime.resolver.?.policy;
    try std.testing.expectEqual(@as(usize, 2), policy.deny_ports_len);
    try std.testing.expectEqual(@as(u16, 53), policy.deny_ports[0].first);
    try std.testing.expectEqual(@as(u16, 40100), policy.deny_ports[1].last);
    try std.testing.expectEqual(@as(u8, 24), policy.max_cacheable_prefix.?);
}

/// The zone the IXFR journal tests serve, at the serial the client asks
/// from.
const journal_zone_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

/// The same zone at the next serial, which the operator's replacement zone
/// file carries.
const journal_zone_next_text =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.2
    \\
;

/// An RFC 1995 IXFR request for one.example. from serial 10: the question
/// plus the client's serial in an authority SOA owned by the question name.
const ixfr_query_bytes = [_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    3,    'o',  'n',  'e',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
    0,    0x00, 0xfb, 0x00, 0x01, 3,    'o',  'n',  'e',  7,    'e',  'x',
    'a',  'm',  'p',  'l',  'e',  0,    0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
    0x0e, 0x10, 0x00, 0x3c, 2,    'n',  's',  3,    'o',  'n',  'e',  7,
    'e',  'x',  'a',  'm',  'p',  'l',  'e',  0,    10,   'h',  'o',  's',
    't',  'm',  'a',  's',  't',  'e',  'r',  3,    'o',  'n',  'e',  7,
    'e',  'x',  'a',  'm',  'p',  'l',  'e',  0,    0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x03, 0x84, 0x00, 0x12, 0x75, 0x00,
    0x00, 0x00, 0x0e, 0x10,
};

/// The messages one IXFR exchange answers with, read from the length
/// prefixed frames the transfer path returns.
fn ixfrFrames(allocator: std.mem.Allocator, runtime: *const auth_runtime.Runtime, query: []const u8) ![]dns_message.Message {
    const blob = try runtime.encodeTransferFrames(allocator, query);
    defer allocator.free(blob);
    var frames: std.ArrayList(dns_message.Message) = .empty;
    errdefer frames.deinit(allocator);
    var offset: usize = 0;
    while (offset + 2 <= blob.len) {
        const length = std.mem.readInt(u16, blob[offset..][0..2], .big);
        offset += 2;
        try frames.append(allocator, try dns_message.Message.parse(allocator, blob[offset..][0..length]));
        offset += length;
    }
    return frames.toOwnedSlice(allocator);
}

/// Counts the SOA records of one serial in the answers of every frame. The
/// incremental sequence carries the superseded SOA the client asked from, and
/// a full transfer carries only the current one.
fn countSoaSerial(frames: []const dns_message.Message, serial: u32) usize {
    var count: usize = 0;
    for (frames) |frame| {
        for (frame.answers.slice()) |record| {
            if (!record.rrtype.eql(.SOA)) continue;
            if (record.rdata.SOA.serial != serial) continue;
            count += 1;
        }
    }
    return count;
}

test "the IXFR journal keeps a zone change across a restart" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = journal_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary one.zone\nixfr-journal-file journal.log\n" });

    // The first run: the operator replaces the zone and the server records
    // the transition in the journal.
    {
        var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
        defer context.deinit();
        var runtime = try context.takeRuntime(io);
        defer runtime.deinit();
        try std.testing.expectEqual(auth_runtime.ReloadOutcome.replaced, runtime.replaceZoneText(io, "one.example.", journal_zone_next_text));
    }

    // The journal holds the transition, and nothing but the transition.
    const journal_text = try dir.dir.readFileAlloc(io, "journal.log", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(journal_text);
    // The journal line carries the difference as well as the serials: the
    // records the old zone held and the new one does not, then the records
    // the new zone holds and the old one did not.
    const difference =
        "D one.example. 3600 6 ns.one.example. hostmaster.one.example. 10 3600 900 1209600 3600\n" ++
        "D www.one.example. 3600 1 192.0.2.1\n" ++
        "A one.example. 3600 6 ns.one.example. hostmaster.one.example. 11 3600 900 1209600 3600\n" ++
        "A www.one.example. 3600 1 192.0.2.2\n";
    var hex: [2 * difference.len]u8 = undefined;
    const digits = "0123456789abcdef";
    for (difference, 0..) |byte, index| {
        hex[2 * index] = digits[byte >> 4];
        hex[2 * index + 1] = digits[byte & 0x0f];
    }
    try std.testing.expectEqualStrings("one.example. 10 11 " ++ hex[0..] ++ "\n", journal_text);

    // The operator's replacement zone file is what the restarted server
    // serves.
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = journal_zone_next_text });

    // The second run: the journal gives the delta log back, so the client at
    // the old serial is answered incrementally again.
    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    const frames = try ixfrFrames(arena.allocator(), &runtime, &ixfr_query_bytes);
    try std.testing.expectEqual(@as(usize, 1), countSoaSerial(frames, 10));
    try std.testing.expectEqual(@as(usize, 3), countSoaSerial(frames, 11));
}

test "a corrupt IXFR journal is skipped and the zone falls back to a full transfer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = journal_zone_next_text });
    try dir.dir.writeFile(io, .{ .sub_path = "journal.log", .data = "one.example. 10\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary one.zone\nixfr-journal-file journal.log\n" });

    // The truncated record is refused, and the server starts anyway.
    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    const frames = try ixfrFrames(arena.allocator(), &runtime, &ixfr_query_bytes);
    try std.testing.expectEqual(@as(usize, 0), countSoaSerial(frames, 10));
}

test "without the journal directive no file is written and the delta log stays in memory" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = journal_zone_text });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary one.zone\n" });

    {
        var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
        defer context.deinit();
        var runtime = try context.takeRuntime(io);
        defer runtime.deinit();
        try std.testing.expectEqual(auth_runtime.ReloadOutcome.replaced, runtime.replaceZoneText(io, "one.example.", journal_zone_next_text));
    }

    // No journal file is created, and the client at the old serial gets the
    // full transfer, exactly as it did before the directive existed.
    try std.testing.expectError(error.FileNotFound, dir.dir.statFile(io, "journal.log", .{}));
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = journal_zone_next_text });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    const frames = try ixfrFrames(arena.allocator(), &runtime, &ixfr_query_bytes);
    try std.testing.expectEqual(@as(usize, 0), countSoaSerial(frames, 10));
}
