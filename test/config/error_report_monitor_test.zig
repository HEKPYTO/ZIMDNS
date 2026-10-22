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

test "the parser takes one RFC 9567 monitored agent domain" {
    const config = try Config.parse("error-report-monitor agent.example.net.\n");
    try std.testing.expectEqualStrings("agent.example.net.", config.errorReportMonitorText().?);

    // A configuration that monitors no domain has none.
    const without = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(without.errorReportMonitorText() == null);
}

test "the parser refuses a second monitored agent domain" {
    try std.testing.expectError(
        error.BadDirective,
        Config.parse(
            \\error-report-monitor agent.example.net.
            \\error-report-monitor other.example.net.
            \\
        ),
    );
}

test "the parser refuses trailing tokens after the monitored agent domain" {
    try std.testing.expectError(
        error.BadDirective,
        Config.parse("error-report-monitor agent.example.net. extra\n"),
    );
}

test "the parser refuses an empty monitored agent domain" {
    try std.testing.expectError(error.BadDirective, Config.parse("error-report-monitor\n"));
}

test "the loader puts the monitored agent domain into the answer policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\error-report-monitor agent.example.net
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // A name written without its trailing dot is completed, and the name the
    // policy holds is the folded one.
    var text: [256]u8 = undefined;
    const monitor = runtime.answer_policy.report_monitor orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("agent.example.net.", try monitor.toText(&text));
}

test "the loader refuses a monitored agent domain that is not a domain name" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\error-report-monitor bad..name.
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectError(error.BadConfiguration, context.takeRuntime(io));
}
