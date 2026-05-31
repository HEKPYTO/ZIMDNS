const std = @import("std");

pub const golden_fixture = @import("golden_fixture.zig");
pub const zone_parser = @import("zone/parser.zig");
pub const zone_index = @import("zone/index.zig");
pub const auth_response = @import("auth/response.zig");
pub const auth_runtime = @import("auth/runtime.zig");
pub const listener = @import("platform/listener.zig");

test {
    _ = @import("dns/reader.zig");
    _ = @import("dns/writer.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/name.zig");
    _ = @import("dns/types.zig");
    _ = @import("dns/rdata.zig");
    _ = @import("dns/record.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/message.zig");
    _ = golden_fixture;
    _ = zone_parser;
    _ = zone_index;
    _ = auth_response;
    _ = auth_runtime;
    _ = listener;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    const args = try init.minimal.args.toSlice(arena);
    const command = if (args.len > 1) args[1] else {
        try printHelp(stdout);
        return;
    };

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "help")) {
        try printHelp(stdout);
        return;
    }

    if (std.mem.eql(u8, command, "--version")) {
        try stdout.print("gcli-dns 0.0.0\n", .{});
        return;
    }

    if (std.mem.eql(u8, command, "server")) {
        try handleServer(args, io, arena, stdout);
        return;
    }

    try stdout.print("error: command '{s}' is not implemented yet\n\n", .{command});
    try printHelp(stdout);
    std.process.exit(2);
}

fn printHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\gcli-dns - Zig DNS server platform
        \\
        \\Usage:
        \\  gcli-dns --help
        \\  gcli-dns --version
        \\  gcli-dns server run
        \\  gcli-dns server run --zone-file examples/zones/home.arpa.zone --once-udp 1053
        \\  gcli-dns server run --zone-file examples/zones/home.arpa.zone --once-tcp 1053
        \\  gcli-dns query @127.0.0.1 -p 1053 example.com A
        \\  gcli-dns zone list
        \\  gcli-dns record list <zone>
        \\  gcli-dns cache stats
        \\  gcli-dns doctor
        \\  gcli-dns metrics
        \\
        \\Implemented now:
        \\  --help, --version, DNS wire-core modules under test
        \\
    );
}

fn handleServer(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (args.len < 3 or !std.mem.eql(u8, args[2], "run")) {
        try writer.writeAll("error: expected 'server run'\n");
        std.process.exit(2);
    }

    var zone_file: ?[]const u8 = null;
    var mode: enum { none, udp_once, tcp_once } = .none;
    var port: u16 = 1053;

    var index: usize = 3;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--zone-file")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --zone-file requires a path\n");
                std.process.exit(2);
            }
            zone_file = args[index];
        } else if (std.mem.eql(u8, arg, "--once-udp")) {
            mode = .udp_once;
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --once-udp requires a port\n");
                std.process.exit(2);
            }
            port = std.fmt.parseInt(u16, args[index], 10) catch {
                try writer.writeAll("error: invalid UDP port\n");
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--once-tcp")) {
            mode = .tcp_once;
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --once-tcp requires a port\n");
                std.process.exit(2);
            }
            port = std.fmt.parseInt(u16, args[index], 10) catch {
                try writer.writeAll("error: invalid TCP port\n");
                std.process.exit(2);
            };
        } else {
            try writer.print("error: unknown server option '{s}'\n", .{arg});
            std.process.exit(2);
        }
        index += 1;
    }

    const path = zone_file orelse {
        try writer.writeAll("error: server run requires --zone-file\n");
        std.process.exit(2);
    };
    if (mode == .none) {
        try writer.writeAll("error: server run currently requires --once-udp or --once-tcp\n");
        std.process.exit(2);
    }

    const zone_text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    const runtime = try auth_runtime.Runtime.fromZoneText(zone_text);

    switch (mode) {
        .udp_once => try listener.serveUdpOnceOnPort(io, &runtime, port),
        .tcp_once => try listener.serveTcpOnceOnPort(io, &runtime, port),
        .none => unreachable,
    }
}
