const std = @import("std");
const metrics = @import("../metrics.zig");
const protocol = @import("protocol.zig");

pub const Service = struct {
    version: []const u8,
    started_at_seconds: u64,
    metrics: metrics.Counters = .{},

    pub fn handle(self: Service, request: []const u8, now_seconds: u64, buffer: []u8) ![]const u8 {
        const command = protocol.parseCommand(request) catch {
            return renderError("unknown-command", buffer);
        };
        return switch (command) {
            .status => protocol.renderStatus(.{
                .version = self.version,
                .uptime_seconds = now_seconds -| self.started_at_seconds,
                .metrics = self.metrics,
            }, buffer),
        };
    }

    pub fn handleLine(self: Service, input: []const u8, now_seconds: u64, buffer: []u8) ![]const u8 {
        const request = if (std.mem.indexOfScalar(u8, input, '\n')) |newline|
            input[0 .. newline + 1]
        else
            input;
        return self.handle(request, now_seconds, buffer);
    }
};

fn renderError(message: []const u8, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer,
        \\{{"ok":false,"error":"{s}"}}
        \\
    , .{message});
}

test "admin service handles status command" {
    const service = Service{
        .version = "0.0.0",
        .started_at_seconds = 10,
        .metrics = .{ .queries_total = 5, .responses_total = 4, .bad_queries_total = 1 },
    };
    var buffer: [512]u8 = undefined;
    const response = try service.handle("{\"command\":\"status\"}\n", 16, &buffer);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"uptime_seconds\":6") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"queries_total\":5") != null);
}

test "admin service rejects unknown command" {
    const service = Service{ .version = "0.0.0", .started_at_seconds = 0 };
    var buffer: [128]u8 = undefined;
    const response = try service.handle("{\"command\":\"reload\"}\n", 1, &buffer);

    try std.testing.expectEqualStrings("{\"ok\":false,\"error\":\"unknown-command\"}\n", response);
}

test "admin service handles a newline-delimited request buffer" {
    const service = Service{
        .version = "0.0.0",
        .started_at_seconds = 20,
        .metrics = .{ .queries_total = 7 },
    };
    var response_buffer: [512]u8 = undefined;
    const response = try service.handleLine("{\"command\":\"status\"}\nextra ignored", 25, &response_buffer);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"uptime_seconds\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"queries_total\":7") != null);
}
