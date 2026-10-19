/// Contract: Loads one parsed server configuration and its referenced assets, confined to `dir`.
/// Ownership: ServerContext owns its Config, ordered zones, blocklist, and optional TSIG keyring; call deinit.
/// Errors: Parser and referenced-file I/O errors stay typed; missing referenced assets map to MissingReferencedFile.
/// Paths: every loader path (config plus referenced zone/blocklist/TSIG files) must be relative,
/// NUL-free, and without `..` components; symlink-resolved canonical targets must stay beneath `dir`.
const std = @import("std");
const builtin = @import("builtin");
const auth_runtime = @import("../auth/runtime.zig");
const keyring_mod = @import("../auth/keyring.zig");
const blocklist_mod = @import("../blocklist.zig");
const parser = @import("parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");
const resolver_mod = @import("../resolver.zig");
const zonemd = @import("../zone/zonemd.zig");
const signer = @import("../zone/signer.zig");

const validate_mod = @import("../dns/validate.zig");
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
    BadDnssecKey,
    BadTrustAnchorFile,
};

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    config: parser.Config,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},
    keyring: keyring_mod.Keyring = .{},
    /// RFC 4035 section 5.2 trust anchors for the forwarding path. Empty when
    /// no `trust-anchor-file` is configured, which is what keeps the forwarder
    /// a non-validating one.
    anchors: validate_mod.Anchors = .{},

    pub fn load(dir: std.Io.Dir, io: std.Io, config_path: []const u8, allocator: std.mem.Allocator) !ServerContext {
        try ensureConfined(dir, io, config_path);
        const config_text = try dir.readFileAlloc(io, config_path, allocator, .limited(1024 * 1024));
        defer allocator.free(config_text);

        var context = ServerContext{
            .allocator = allocator,
            .config = try parser.Config.parse(config_text),
        };
        errdefer context.deinit();

        if (context.config.tsigKeyFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            context.keyring = parseKeyTextAndClear(key_text) catch |err| return err;
        }

        // The key is read before any zone is loaded, so a bad key file fails
        // startup without leaving a half-signed zone behind. The private
        // scalar is wiped as soon as every zone has been signed.
        var dnssec_key: ?signer.Key = null;
        defer if (dnssec_key) |*key| key.deinit();
        if (context.config.dnssecKeyFileText()) |key_path| {
            const key_text = try readReferencedFile(dir, io, key_path, allocator);
            defer allocator.free(key_text);
            dnssec_key = parseDnssecKeyTextAndClear(key_text) catch return Error.BadDnssecKey;
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

        var zone_index_value: usize = 0;
        while (zone_index_value < context.config.zones.len) : (zone_index_value += 1) {
            const zone_path = context.config.zones.items[zone_index_value].fileText();
            const zone_text = try readReferencedFile(dir, io, zone_path, allocator);
            defer allocator.free(zone_text);

            var zone_file = try zone_parser.ZoneFile.parse(zone_text);
            errdefer zone_file.deinit();
            if (!zoneNamesEqual(context.config.zones.items[zone_index_value].nameText(), zone_file.originText())) {
                return Error.ZoneNameMismatch;
            }
            var zone = try zone_index.Zone.fromZoneFile(&zone_file);
            errdefer zone.deinit();
            // RFC 8976 section 4: refuse to serve a zone whose apex ZONEMD
            // record does not match the loaded data, so a corrupted or
            // tampered zone file fails closed at startup instead of answering
            // queries. The report names the zone and both digests.
            var zonemd_report: [zonemd.report_max_len]u8 = undefined;
            _ = zonemd.verify(&zone, allocator, &zonemd_report) catch {
                // The report names the zone and both digests for the operator
                // who starts the server. A test build has no operator and the
                // test runner fails on any stderr write, so the line is
                // printed by the server build only.
                if (!builtin.is_test) {
                    const written = std.mem.indexOfScalar(u8, &zonemd_report, 0) orelse zonemd_report.len;
                    var stderr_buffer: [256]u8 = undefined;
                    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
                    stderr_writer.interface.print("error: {s}\n", .{zonemd_report[0..written]}) catch {};
                    stderr_writer.interface.flush() catch {};
                }
                return Error.ZonemdMismatch;
            };
            // RFC 4035 section 2.3: signing adds DNSKEY, DS, RRSIG, and NSEC to
            // the loaded zone, so the signed RRsets are served from here on
            // without touching the zone file on disk.
            if (dnssec_key) |*key| {
                signer.signZone(context.allocator, &zone, key, .{
                    .inception = now_seconds,
                    .expiration = now_seconds + signature_validity_seconds,
                }) catch return Error.BadDnssecKey;
            }
            try context.zones.append(allocator, zone);
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
        runtime.answer_policy.zoneversion = self.config.zoneversion;
        if (self.config.minimal_any_ttl) |ttl| runtime.answer_policy.minimal_any_ttl = ttl;
        self.blocklist = .{};
        self.config = .{};
        return runtime;
    }

    pub fn deinit(self: *ServerContext) void {
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.blocklist = .{};
        self.keyring.deinit();
        self.config = .{};
        // Anchors that never reached a policy (load failed, or the context was
        // dropped without takeRuntime) are still owned here.
        self.anchors.deinit(self.allocator);
        self.anchors = .{};
    }
};

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
    try std.testing.expect(context.keyring.find(name) != null);
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
    for (zone.records.items[0..zone.records.len]) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(record.owner, owner)) continue;
        const rdata = zone_parser.parseRData(.RRSIG, record.rdataText()) catch return false;
        const bytes = switch (rdata) {
            .Unknown => |unknown| unknown.bytes(),
            else => return false,
        };
        if (bytes.len < 2) return false;
        if (std.mem.readInt(u16, bytes[0..2], .big) == covered) return true;
    }
    return false;
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
    const RecordType = @import("../dns/types.zig").RecordType;
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
