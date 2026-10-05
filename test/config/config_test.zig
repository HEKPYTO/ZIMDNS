const std = @import("std");
const zimdns = @import("zimdns");
const Config = zimdns.config_parser.Config;
const ServerContext = zimdns.config_loader.ServerContext;

const zone_one =
    \\$ORIGIN one.example.
    \\$TTL 3600
    \\@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.one.example.
    \\www IN A 192.0.2.1
    \\
;

const zone_two =
    \\$ORIGIN two.example.
    \\$TTL 3600
    \\@ IN SOA ns.two.example. hostmaster.two.example. 1 3600 900 1209600 3600
    \\@ IN NS ns.two.example.
    \\www IN A 192.0.2.2
    \\
;

test "config parser loads bundled example config" {
    const text = @embedFile("config_fixture.gdns");
    const config = try Config.parse(text);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expectEqual(@as(usize, 1), config.zones.len);
    try std.testing.expectEqualStrings("examples/zones/home.arpa.zone", config.zones.items[0].fileText());
    try std.testing.expectEqual(@as(usize, 1), config.blocklists.len);
    try std.testing.expectEqualStrings("examples/blocklists/ads.txt", config.blocklists.items[0].pathText());
}

test "server context loads zones and blocklists in declaration order" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "two.zone", .data = zone_two });
    try dir.dir.writeFile(io, .{ .sub_path = "one.list", .data = "ads.one.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "two.list", .data = "ads.two.example.\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone two.example primary two.zone
        \\blocklist file two.list
        \\zone one.example primary one.zone
        \\blocklist file one.list
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();

    try std.testing.expectEqual(@as(usize, 2), context.zones.items.len);
    try std.testing.expectEqualStrings("two.example.", context.zones.items[0].originText());
    try std.testing.expectEqualStrings("one.example.", context.zones.items[1].originText());
    try std.testing.expectEqualStrings(
        "ads.two.example.",
        context.blocklist.entries[0].bytes[0..context.blocklist.entries[0].len],
    );
    try std.testing.expectEqualStrings(
        "ads.one.example.",
        context.blocklist.entries[1].bytes[0..context.blocklist.entries[1].len],
    );

    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();
    try std.testing.expectEqual(@as(usize, 2), runtime.zones.items.len);
    try std.testing.expectEqualStrings("two.example.", runtime.zones.items[0].originText());
    try std.testing.expect(runtime.blocklist.blocks("ads.one.example."));
    try std.testing.expect(runtime.blocklist.blocks("ads.two.example."));
}

test "server context maps missing referenced zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone missing.example primary missing.zone\n" });

    try std.testing.expectError(
        error.MissingReferencedFile,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context rejects a zone whose origin differs from its declaration" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone two.example primary one.zone\n" });

    try std.testing.expectError(
        error.ZoneNameMismatch,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context compares zone declaration and origin case-insensitively" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone ONE.EXAMPLE. primary one.zone\n" });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectEqual(@as(usize, 1), context.zones.items.len);
}

test "server context wires the strict forwarding policy into Runtime" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\recursion allow 127.0.0.0/8
        \\forwarder 127.0.0.1:5353
        \\cookies validate current-secret previous-secret
        \\zone one.example primary one.zone
        \\
    });
    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();
    try std.testing.expect(runtime.resolver != null);
    const policy = &runtime.resolver.?.policy;
    try std.testing.expectEqual(@as(usize, 1), policy.recursion_allow_len);
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 41003);
    try std.testing.expect(policy.allows(&client));
    try std.testing.expect(policy.forwarder != null);
    try std.testing.expect(policy.cookies.enabled());
}

test "server context keeps locally served zones on by default and honours local-zones off" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "default.gdns", .data = "zone one.example primary one.zone\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "off.gdns", .data =
        \\zone one.example primary one.zone
        \\local-zones off
        \\
    });

    var implicit = try ServerContext.load(dir.dir, io, "default.gdns", std.testing.allocator);
    defer implicit.deinit();
    var implicit_runtime = try implicit.takeRuntime(io);
    defer implicit_runtime.deinit();
    try std.testing.expect(implicit_runtime.local_zones);

    var off = try ServerContext.load(dir.dir, io, "off.gdns", std.testing.allocator);
    defer off.deinit();
    var off_runtime = try off.takeRuntime(io);
    defer off_runtime.deinit();
    try std.testing.expect(!off_runtime.local_zones);
}

test "server context decodes the nsid hex and the zoneversion switch into the runtime EDNS policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "plain.gdns", .data = "zone one.example primary one.zone\n" });
    try dir.dir.writeFile(io, .{ .sub_path = "edns.gdns", .data =
        \\zone one.example primary one.zone
        \\nsid 6e73312e6578616d706c652e
        \\zoneversion off
        \\
    });

    var plain = try ServerContext.load(dir.dir, io, "plain.gdns", std.testing.allocator);
    defer plain.deinit();
    var plain_runtime = try plain.takeRuntime(io);
    defer plain_runtime.deinit();
    try std.testing.expect(plain_runtime.edns.nsid == null);
    try std.testing.expect(plain_runtime.edns.zoneversion);

    var configured = try ServerContext.load(dir.dir, io, "edns.gdns", std.testing.allocator);
    defer configured.deinit();
    var configured_runtime = try configured.takeRuntime(io);
    defer configured_runtime.deinit();
    // RFC 5001 section 2.4: the hex an operator writes is the presentation
    // format for the OPTION-DATA octets, so the payload is the decoded text.
    try std.testing.expectEqualSlices(u8, "ns1.example.", configured_runtime.edns.nsid.?);
    try std.testing.expect(!configured_runtime.edns.zoneversion);
}

test "the shipped local-zones example configuration loads with its zone and forwarder" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var context = try ServerContext.load(std.Io.Dir.cwd(), io, "examples/local-zones.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // The example is operator-reachable documentation, so it is loaded through
    // the real loader rather than duplicated as a fixture.
    try std.testing.expect(runtime.local_zones);
    try std.testing.expectEqual(@as(usize, 1), runtime.zones.items.len);
    try std.testing.expectEqualStrings("one.example.", runtime.zones.items[0].originText());
    try std.testing.expect(runtime.resolver != null);
    try std.testing.expect(runtime.resolver.?.policy.forwarder != null);
}

test "server context maps missing referenced blocklist" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data = "blocklist file missing.list\n" });

    try std.testing.expectError(
        error.MissingReferencedFile,
        ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator),
    );
}

test "server context rejects a referenced zone that escapes the base directory" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var root = std.testing.tmpDir(.{});
    defer root.cleanup();

    // "base-evil" is a sibling of "base" whose name starts with the base's own
    // name, so a containment check that forgets the path-component boundary
    // would accept a target that is not inside the base at all.
    try root.dir.createDir(io, "base", .default_dir);
    try root.dir.createDir(io, "base-evil", .default_dir);
    try root.dir.writeFile(io, .{ .sub_path = "base-evil/outside.zone", .data = zone_one });
    var outside_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const outside_len = try root.dir.realPathFile(io, "base-evil/outside.zone", &outside_buffer);
    const outside = outside_buffer[0..outside_len];

    var base = try root.dir.openDir(io, "base", .{});
    defer base.close(io);
    try base.symLink(io, outside, "escape.zone", .{});
    try base.writeFile(io, .{ .sub_path = "config.gdns", .data = "zone one.example primary escape.zone\n" });

    try std.testing.expectError(
        error.InvalidReferencedPath,
        ServerContext.load(base, io, "config.gdns", std.testing.allocator),
    );
}
