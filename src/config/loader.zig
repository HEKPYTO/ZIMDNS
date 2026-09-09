/// Contract: Loads one parsed server configuration and its referenced assets, confined to `dir`.
/// Ownership: ServerContext owns its Config, ordered zones, blocklist, and optional TSIG keyring; call deinit.
/// Errors: Parser and referenced-file I/O errors stay typed; missing referenced assets map to MissingReferencedFile.
/// Paths: every loader path (config plus referenced zone/blocklist/TSIG files) must be relative,
/// NUL-free, and without `..` components; symlink-resolved canonical targets must stay beneath `dir`.
const std = @import("std");
const auth_runtime = @import("../auth/runtime.zig");
const keyring_mod = @import("../auth/keyring.zig");
const blocklist_mod = @import("../blocklist.zig");
const parser = @import("parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");
const resolver_mod = @import("../resolver.zig");

pub const Error = error{
    MissingReferencedFile,
    InvalidReferencedPath,
    NoPrimaryZone,
    BadConfiguration,
    ZoneNameMismatch,
};

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    config: parser.Config,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},
    keyring: keyring_mod.Keyring = .{},

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
        const policy = resolver_mod.Policy.fromConfig(&self.config) catch return error.BadConfiguration;
        const runtime = if (self.config.forwarder != null or self.config.recursion_allow.len != 0 or self.config.cookies.enabled)
            try auth_runtime.Runtime.fromZonesWithPolicyAndKeyring(self.allocator, &self.zones, self.blocklist, io, policy, &self.keyring)
        else
            auth_runtime.Runtime.fromZonesWithKeyring(self.allocator, &self.zones, self.blocklist, &self.keyring);
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

fn ensureConfined(dir: std.Io.Dir, io: std.Io, sub_path: []const u8) !void {
    if (!isConfinedPath(sub_path)) return Error.InvalidReferencedPath;
    var base_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const base_len = try dir.realPath(io, &base_buffer);
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
