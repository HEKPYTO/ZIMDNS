/// Contract: Parses admin command envelopes and renders bounded status responses.
/// Ownership: Inputs and output buffer are borrowed; returned slices borrow caller buffer.
/// Errors: Command and formatting failures are typed; socket I/O is outside this module.
const std = @import("std");
const metrics = @import("../metrics.zig");

pub const StatusSnapshot = struct {
    version: []const u8,
    uptime_seconds: u64,
    metrics: metrics.Counters,
};

pub const Command = enum {
    status,
};

pub const Error = error{
    UnknownAdminCommand,
};

pub fn parseCommand(text: []const u8) Error!Command {
    if (std.mem.indexOf(u8, text, "\"command\":\"status\"") != null) return .status;
    return Error.UnknownAdminCommand;
}

pub fn renderStatus(snapshot: StatusSnapshot, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer,
        \\{{"ok":true,"version":"{s}","uptime_seconds":{d},"queries_total":{d},"responses_total":{d},"bad_queries_total":{d},"encode_failures_total":{d}}}
        \\
    , .{
        snapshot.version,
        snapshot.uptime_seconds,
        snapshot.metrics.queries_total,
        snapshot.metrics.responses_total,
        snapshot.metrics.bad_queries_total,
        snapshot.metrics.encode_failures_total,
    });
}

test "admin protocol renders status with metrics counters" {
    const snapshot = StatusSnapshot{
        .version = "0.0.0",
        .uptime_seconds = 12,
        .metrics = .{
            .queries_total = 3,
            .responses_total = 2,
            .bad_queries_total = 1,
            .encode_failures_total = 0,
        },
    };
    var buffer: [512]u8 = undefined;
    const text = try renderStatus(snapshot, &buffer);

    try std.testing.expectEqualStrings(
        "{\"ok\":true,\"version\":\"0.0.0\",\"uptime_seconds\":12,\"queries_total\":3,\"responses_total\":2,\"bad_queries_total\":1,\"encode_failures_total\":0}\n",
        text,
    );
}

test "admin protocol parses status command envelope" {
    try std.testing.expectEqual(Command.status, try parseCommand("{\"command\":\"status\"}\n"));
    try std.testing.expectError(error.UnknownAdminCommand, parseCommand("{\"command\":\"reload\"}\n"));
}
