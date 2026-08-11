const std = @import("std");
const config_parser = @import("config/parser.zig");
const zone_parser = @import("zone/parser.zig");
const blocklist = @import("blocklist.zig");

const max_issues = 32;

pub const IssueKind = enum {
    missing_listener,
    missing_zone,
    invalid_listener_port,
    missing_recursion_default_deny,
    invalid_zone,
    invalid_blocklist,
};

pub const Report = struct {
    issues: [max_issues]IssueKind = undefined,
    issue_count: usize = 0,

    pub fn ok(self: *const Report) bool {
        return self.issue_count == 0;
    }

    pub fn has(self: *const Report, kind: IssueKind) bool {
        var index: usize = 0;
        while (index < self.issue_count) : (index += 1) {
            if (self.issues[index] == kind) return true;
        }
        return false;
    }

    pub fn add(self: *Report, kind: IssueKind) !void {
        if (self.issue_count >= self.issues.len) return error.TooManyDoctorIssues;
        self.issues[self.issue_count] = kind;
        self.issue_count += 1;
    }
};

pub fn inspectParsedConfig(config: *const config_parser.Config, report: *Report) !void {
    if (config.listeners.len == 0) try report.add(.missing_listener);
    if (config.zones.len == 0) try report.add(.missing_zone);

    var listener_index: usize = 0;
    while (listener_index < config.listeners.len) : (listener_index += 1) {
        if (config.listeners.items[listener_index].port == 0) try report.add(.invalid_listener_port);
    }

    if (!hasDefaultDeny(config, "0.0.0.0/0") or !hasDefaultDeny(config, "::/0")) {
        try report.add(.missing_recursion_default_deny);
    }
}

pub fn inspectZoneText(name: []const u8, text: []const u8, report: *Report) !void {
    _ = name;
    var zone = zone_parser.ZoneFile.parse(text) catch {
        try report.add(.invalid_zone);
        return;
    };
    defer zone.deinit();
}

pub fn inspectBlocklistText(text: []const u8, report: *Report) !void {
    _ = blocklist.Blocklist.parse(text) catch {
        try report.add(.invalid_blocklist);
        return;
    };
}

pub fn issueName(kind: IssueKind) []const u8 {
    return switch (kind) {
        .missing_listener => "missing-listener",
        .missing_zone => "missing-zone",
        .invalid_listener_port => "invalid-listener-port",
        .missing_recursion_default_deny => "missing-recursion-default-deny",
        .invalid_zone => "invalid-zone",
        .invalid_blocklist => "invalid-blocklist",
    };
}

fn hasDefaultDeny(config: *const config_parser.Config, cidr: []const u8) bool {
    var index: usize = 0;
    while (index < config.recursion_rules.len) : (index += 1) {
        const rule = config.recursion_rules.items[index];
        if (rule.action == .deny and std.mem.eql(u8, rule.cidr.text(), cidr)) return true;
    }
    return false;
}
