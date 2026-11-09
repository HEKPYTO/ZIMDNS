/// Contract: the multi-transport serve path runs against the real binary.
/// One test serves UDP and TCP at once from a single process on two
/// ephemeral loopback ports and answers on both; the other proves the
/// fail-fast rule: a loop that fails after startup prints its error and the
/// process exits nonzero instead of leaving a sibling to serve half the
/// transports. Both drive the binary the build emitted, never an
/// in-process loop, so a regression in process setup or argument plumbing
/// fails here rather than hiding behind unit seams.
/// Ownership: one arena owns every string and child result; every spawned
/// process is reaped before the test returns.
/// Errors: any unexpected child outcome fails with its argv, exit code, and
/// output. Timeouts bound a broken build instead of hanging the suite.
const std = @import("std");
const zimdns = @import("zimdns");
const build_options = @import("build_options");

const cli_query = zimdns.cli_query;

const child_deadline = std.Io.Timeout{ .duration = .{
    .raw = .fromSeconds(20),
    .clock = .awake,
} };

/// How long the harness waits for a freshly spawned server to answer before
/// it concludes the server never will. A dropped datagram costs one budget;
/// the window bounds a broken build, never a passing assertion.
const ready_budget = std.Io.Timeout{ .duration = .{
    .raw = .fromMilliseconds(100),
    .clock = .awake,
} };
const ready_window_s: u64 = 10;

fn readyDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(ready_window_s), .clock = .awake });
}

fn expired(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    return deadline.durationFromNow(io).raw.nanoseconds <= 0;
}

fn exitCode(term: std.process.Child.Term) ?u8 {
    return switch (term) {
        .exited => |code| code,
        else => null,
    };
}

/// Waits for a child that must already be on its way out, killing it after
/// `child_deadline` instead of hanging CI on a join regression.
fn waitDeadline(child: *std.process.Child, io: std.Io) !std.process.Child.Term {
    var group: std.Io.Group = .init;
    const WaitResult = struct {
        term: ?std.process.Child.Term = null,
        // Set release after `term`; the main thread loads acquire and never
        // reads `term` until this is true, so the handoff is race-free.
        done: std.atomic.Value(bool) = .init(false),
        child: *std.process.Child,
        io: std.Io,
        fn run(self: *@This()) void {
            self.term = self.child.wait(self.io) catch null;
            self.done.store(true, .release);
        }
    };
    var waiter = WaitResult{ .child = child, .io = io };
    group.concurrent(io, WaitResult.run, .{&waiter}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            child.kill(io);
            return error.ServerDidNotExit;
        },
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(20), .clock = .awake });
    while (!waiter.done.load(.acquire)) {
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            child.kill(io);
            group.await(io) catch {};
            return error.ServerDidNotExit;
        }
        std.Io.sleep(io, .fromMilliseconds(10), .awake) catch {};
    }
    group.await(io) catch {};
    return waiter.term.?;
}

/// Binds port 0, reads the ephemeral port back, and closes: the caller owns
/// the usual probe race, which a smoke test accepts and a retry would hide.
fn freePort(io: std.Io) !u16 {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var socket = try std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    return socket.address.getPort();
}

const zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

test "one process serves udp and tcp at once on ephemeral ports" {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // Two ephemeral ports, neither the 1053 default: the config carries one
    // listener per transport, and each loop binds exactly its own.
    const udp_port = try freePort(io);
    var tcp_port = try freePort(io);
    if (tcp_port == udp_port) tcp_port = try freePort(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_prefix = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(allocator, "{s}/home.arpa.zone", .{tmp_prefix}), .data = zone_text });
    const config_path = try std.fmt.allocPrint(allocator, "{s}/serving-modes.gdns", .{tmp_prefix});
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = config_path,
        .data = try std.fmt.allocPrint(allocator, "listen dns udp 127.0.0.1:{d}\nlisten dns tcp 127.0.0.1:{d}\nzone home.arpa primary home.arpa.zone\n", .{ udp_port, tcp_port }),
    });

    const argv: []const []const u8 = &.{
        build_options.exe_path, "server",      "run",            "--config", config_path,
        "--serve-udp",          "--serve-tcp", "--max-requests", "1",
    };
    var out_file = try tmp.dir.createFile(io, "out", .{});
    var err_file = try tmp.dir.createFile(io, "err", .{});
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    });
    out_file.close(io);
    err_file.close(io);

    const udp_addr = std.Io.net.IpAddress{ .ip4 = .loopback(udp_port) };
    const tcp_addr = std.Io.net.IpAddress{ .ip4 = .loopback(tcp_port) };
    const got_udp = driveUdp(allocator, io, udp_addr);
    const got_tcp = driveTcp(allocator, io, tcp_addr);
    // Both loops carry `--max-requests 1`, so one answer per transport ends
    // the process on its own. A quota never met means a broken server that
    // would wait forever: kill it instead of hanging the suite.
    // `Child.kill` blocks until the child is reaped, so there is no `wait`
    // after it.
    const code: ?u8 = if (got_udp == 1 and got_tcp == 1) exitCode(try waitDeadline(&child, io)) else blk: {
        child.kill(io);
        break :blk null;
    };
    if (got_udp != 1 or got_tcp != 1 or code != 0) {
        const out = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
        const err = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));
        std.debug.print("udp served={d} tcp served={d} exit={?d}\nstdout={s}\nstderr={s}\n", .{ got_udp, got_tcp, code, out, err });
        return error.ServingModesSmokeFailed;
    }
}

fn driveUdp(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) usize {
    var bind = cli_query.udpClientBindAddress(&address);
    const socket = std.Io.net.IpAddress.bind(&bind, io, .{ .mode = .dgram, .protocol = .udp }) catch return 0;
    defer socket.close(io);
    var packet: [512]u8 = undefined;
    const query = cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false) catch return 0;
    var response: [4096]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const deadline = readyDeadline(io);
    while (!expired(io, deadline)) {
        cli_query.sendUdpQuery(&socket, io, &address, query) catch return 0;
        const incoming = socket.receiveTimeout(io, &response, ready_budget) catch continue;
        if (!incoming.from.eql(&address)) continue;
        // The datagram is already in hand: parse it directly instead of
        // waiting for a second one that never comes.
        const parsed = zimdns.dns_message.Message.parse(arena.allocator(), incoming.data) catch continue;
        if (parsed.header.answer_count == 1) return 1;
    }
    return 0;
}

fn driveTcp(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) usize {
    const deadline = readyDeadline(io);
    while (!expired(io, deadline)) {
        const n = exchangeTcpOnce(allocator, io, address) catch continue;
        return n;
    }
    return 0;
}

fn exchangeTcpOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !usize {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);
    var packet: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false);
    try cli_query.sendTcpQuery(stream, io, query);
    try stream.shutdown(io, .send);
    var response: [4096]u8 = undefined;
    const message = try cli_query.receiveTcpResponse(allocator, stream, io, &response, query, false);
    if (message.header.answer_count != 1) return error.WrongAnswer;
    return 1;
}

test "a loop that fails after startup exits nonzero with its error" {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The TCP port stays bound by this test, so the server's TCP runner
    // fails its bind after the process has started and the UDP loop is
    // already serving: fail-fast must print the loop's error and exit
    // nonzero instead of serving UDP alone.
    const udp_port = try freePort(io);
    const tcp_port = try freePort(io);
    // Held without `reuse_address`: the server binds with reuse set, and
    // the first-bound socket without the flag makes the second bind fail,
    // so the TCP runner fails after the process has started.
    var held_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(tcp_port) };
    var held = try std.Io.net.IpAddress.listen(&held_addr, io, .{});
    defer held.deinit(io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_prefix = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(allocator, "{s}/home.arpa.zone", .{tmp_prefix}), .data = zone_text });
    const config_path = try std.fmt.allocPrint(allocator, "{s}/serving-modes-fail.gdns", .{tmp_prefix});
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = config_path,
        .data = try std.fmt.allocPrint(allocator, "listen dns udp 127.0.0.1:{d}\nlisten dns tcp 127.0.0.1:{d}\nzone home.arpa primary home.arpa.zone\n", .{ udp_port, tcp_port }),
    });

    const argv: []const []const u8 = &.{
        build_options.exe_path, "server",      "run", "--config", config_path,
        "--serve-udp",          "--serve-tcp",
    };
    const result = try std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline });
    const code = exitCode(result.term);
    // Fail-fast: nonzero, names the failed loop, carries the reason.
    // A zero exit would mean the UDP sibling kept serving half the
    // transports; exit 2 would mean a usage refusal instead of a run failure.
    try std.testing.expect(code != null and code.? != 0 and code.? != 2);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "serve-tcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "failed") != null);
}
