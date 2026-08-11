/// Contract: Loads one parsed server configuration and its referenced assets.
/// Ownership: ServerContext owns its Config, ordered zones, and aggregate blocklist; call deinit.
/// Errors: Parser and referenced-file I/O errors stay typed; missing referenced assets map to MissingReferencedFile.
const std = @import("std");
const auth_runtime = @import("../auth/runtime.zig");
const blocklist_mod = @import("../blocklist.zig");
const parser = @import("parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");
const resolver_mod = @import("../resolver.zig");

pub const Error = error{
    MissingReferencedFile,
    NoPrimaryZone,
    BadConfiguration,
    ZoneNameMismatch,
};

pub const ServerContext = struct {
    allocator: std.mem.Allocator,
    config: parser.Config,
    zones: std.ArrayList(zone_index.Zone) = .empty,
    blocklist: blocklist_mod.Blocklist = .{},

    pub fn load(dir: std.Io.Dir, io: std.Io, config_path: []const u8, allocator: std.mem.Allocator) !ServerContext {
        const config_text = try dir.readFileAlloc(io, config_path, allocator, .limited(1024 * 1024));
        defer allocator.free(config_text);

        var context = ServerContext{
            .allocator = allocator,
            .config = try parser.Config.parse(config_text),
        };
        errdefer context.deinit();

        var zone_index_value: usize = 0;
        while (zone_index_value < context.config.zones.len) : (zone_index_value += 1) {
            const zone_path = context.config.zones.items[zone_index_value].fileText();
            const zone_text = dir.readFileAlloc(io, zone_path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
                error.FileNotFound => return Error.MissingReferencedFile,
                else => return err,
            };
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
            const blocklist_text = dir.readFileAlloc(io, blocklist_path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
                error.FileNotFound => return Error.MissingReferencedFile,
                else => return err,
            };
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
            try auth_runtime.Runtime.fromZonesWithPolicy(self.allocator, &self.zones, self.blocklist, io, policy)
        else
            auth_runtime.Runtime.fromZones(self.allocator, &self.zones, self.blocklist);
        self.blocklist = .{};
        self.config = .{};
        return runtime;
    }

    pub fn deinit(self: *ServerContext) void {
        for (self.zones.items) |*zone| zone.deinit();
        self.zones.deinit(self.allocator);
        self.zones = .empty;
        self.blocklist = .{};
        self.config = .{};
    }
};

fn zoneNamesEqual(configured: []const u8, parsed: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(configured, parsed)) return true;
    if (std.mem.endsWith(u8, parsed, ".") and std.ascii.eqlIgnoreCase(configured, parsed[0 .. parsed.len - 1])) return true;
    if (std.mem.endsWith(u8, configured, ".") and std.ascii.eqlIgnoreCase(configured[0 .. configured.len - 1], parsed)) return true;
    return false;
}
