const std = @import("std");

pub const golden_fixture = @import("golden_fixture.zig");

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
