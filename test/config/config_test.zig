const std = @import("std");
const zimdns = @import("zimdns");
const Config = zimdns.config_parser.Config;
const ServerContext = zimdns.config_loader.ServerContext;
const doctor = zimdns.doctor;

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

test "doctor accepts locked down config with valid authoritative zone" {
    const config_text = @embedFile("config_fixture.gdns");
    const zone_text =
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    ;

    const config = try Config.parse(config_text);
    var report = doctor.Report{};
    try doctor.inspectParsedConfig(&config, &report);
    try doctor.inspectZoneText(config.zones.items[0].nameText(), zone_text, &report);

    try std.testing.expect(report.ok());
}

test "doctor reports sparse unsafe config" {
    const config = try Config.parse("cache max-entries 10\n");
    var report = doctor.Report{};
    try doctor.inspectParsedConfig(&config, &report);

    try std.testing.expect(!report.ok());
    try std.testing.expect(report.has(.missing_listener));
    try std.testing.expect(report.has(.missing_zone));
    try std.testing.expect(report.has(.missing_recursion_default_deny));
    try std.testing.expectEqualStrings("missing-listener", doctor.issueName(.missing_listener));
}

test "doctor reports invalid blocklist text" {
    var report = doctor.Report{};
    var long_name: [260]u8 = undefined;
    @memset(&long_name, 'a');
    try doctor.inspectBlocklistText(&long_name, &report);

    try std.testing.expect(!report.ok());
    try std.testing.expect(report.has(.invalid_blocklist));
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

    var runtime = try context.takePrimaryRuntime();
    defer runtime.deinit();
    try std.testing.expectEqualStrings("two.example.", runtime.zone.originText());
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
