/// Contract: Serves one admin request over a connected or Unix stream.
/// Ownership: Stream is consumed by the call; Service and path inputs are borrowed; buffers are local.
/// Errors: Stream and address failures are propagated I/O errors; protocol errors remain typed below.
const std = @import("std");
const Service = @import("service.zig").Service;

pub fn serveStreamOnce(stream: std.Io.net.Stream, io: std.Io, service: Service, now_seconds: u64) !void {
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const request = try reader.interface.takeDelimiterInclusive('\n');

    var response_buffer: [1024]u8 = undefined;
    const response = try service.handleLine(request, now_seconds, &response_buffer);

    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(response);
    try writer.interface.flush();
}

pub fn serveUnixOnce(path: []const u8, io: std.Io, service: Service, now_seconds: u64) !void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(io, .{ .kernel_backlog = 1 });
    defer server.deinit(io);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const stream = try server.accept(io);
    defer stream.close(io);
    try serveStreamOnce(stream, io, service, now_seconds);
}

test "admin unix socket serves one status request" {
    if (!std.Io.net.has_unix_sockets) return error.SkipZigTest;

    const io = std.Io.Threaded.global_single_threaded.io();
    const path = ".zig-cache/zimdns-admin-test.sock";
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const service = Service{
        .version = "0.0.0",
        .started_at_seconds = 100,
        .metrics = .{ .queries_total = 11 },
    };

    const address = try std.Io.net.UnixAddress.init(path);
    var server = try address.listen(io, .{ .kernel_backlog = 1 });
    defer server.deinit(io);

    var client = try address.connect(io);
    defer client.close(io);
    var client_write_buffer: [128]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll("{\"command\":\"status\"}\n");
    try client_writer.interface.flush();

    const accepted = try server.accept(io);
    defer accepted.close(io);
    try serveStreamOnce(accepted, io, service, 105);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client.reader(io, &client_read_buffer);
    const line = try client_reader.interface.takeDelimiterInclusive('\n');
    try std.testing.expect(std.mem.indexOf(u8, line, "\"uptime_seconds\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"queries_total\":11") != null);
}
