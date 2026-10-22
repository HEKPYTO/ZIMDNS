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

test "the parser takes one RFC 9567 agent domain" {
    const config = try Config.parse("error-report-agent agent.example.net.\n");
    try std.testing.expectEqualStrings("agent.example.net.", config.errorReportAgentText().?);

    // A configuration that names no agent has none.
    const without = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(without.errorReportAgentText() == null);
}

test "the parser refuses a second agent domain" {
    try std.testing.expectError(
        error.BadDirective,
        Config.parse(
            \\error-report-agent agent.example.net.
            \\error-report-agent other.example.net.
            \\
        ),
    );
}

test "the parser refuses trailing tokens after the agent domain" {
    try std.testing.expectError(
        error.BadDirective,
        Config.parse("error-report-agent agent.example.net. extra\n"),
    );
}

test "the loader puts the agent domain into the answer policy" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\error-report-agent agent.example.net
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    var runtime = try context.takeRuntime(io);
    defer runtime.deinit();

    // A name written without its trailing dot is completed, and the name the
    // option carries is the folded one.
    var text: [256]u8 = undefined;
    const agent = runtime.answer_policy.report_agent orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("agent.example.net.", try agent.toText(&text));
}

test "the loader refuses an agent domain that is not a domain name" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "one.zone", .data = zone_one });
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\zone one.example primary one.zone
        \\error-report-agent bad..name.
        \\
    });

    var context = try ServerContext.load(dir.dir, io, "config.gdns", std.testing.allocator);
    defer context.deinit();
    try std.testing.expectError(error.BadConfiguration, context.takeRuntime(io));
}
