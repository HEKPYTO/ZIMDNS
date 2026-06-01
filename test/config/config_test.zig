const std = @import("std");
const gcli_dns = @import("gcli_dns");
const Config = gcli_dns.config_parser.Config;
const doctor = gcli_dns.doctor;

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
