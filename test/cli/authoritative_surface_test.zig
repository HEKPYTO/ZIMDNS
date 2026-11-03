/// Contract: the two-command surface answers every authoritative class the
/// matrix promises: positive, NODATA, NXDOMAIN, in-zone alias, wildcard,
/// DNAME, referral and refusal -- through the built binary over loopback UDP,
/// and the same answer over loopback TCP through `query --tcp`.
/// Ownership: one arena owns every printed case and every query result; the
/// temporary zone, the spawned server and its output files are released before
/// the test returns.
/// Errors: a case whose rendered output lacks a promised line, or carries a
/// line the class forbids, fails with its argv and the rendered response. A
/// server that never answers its readiness probe, or that does not exit 0 after
/// its quota, fails with the server's stdout and stderr.
/// Scope: the answer classes over UDP, and the TCP client path. The encrypted
/// transports and the zone transfer channel have their own guards.
const std = @import("std");
const build_options = @import("build_options");

/// Whole-child deadline for one `query`: a child that stops terminating fails
/// loudly instead of hanging the group.
const child_deadline = std.Io.Timeout{ .duration = .{
    .raw = .fromSeconds(20),
    .clock = .awake,
} };
/// The same bound for the server, enforced by the watcher in `reapBounded`.
const reap_deadline_ms: u64 = 20_000;

/// A listener prints nothing when it binds, so a query sent before the bind is
/// simply lost. The first case below doubles as the probe; this window bounds
/// how long a broken build may spend waiting for it.
const ready_window_seconds: u64 = 10;

/// 21400-21499 belongs to the documented-invocation guard, so the candidate
/// ranges start above it. A probe bind retries the list on `AddressInUse`
/// instead of assuming one fixed port is free.
const udp_port_base: u16 = 21600;
const tcp_port_base: u16 = 21700;
const port_candidates: u16 = 8;

/// One answer class: the exact `query` words, the lines the rendered response
/// must carry, and the lines it must not.
const Case = struct {
    name: []const u8,
    qtype: []const u8,
    required: []const []const u8,
    forbidden: []const []const u8 = &.{},
};

const cases = [_]Case{
    // Positive: owner, TTL and data come from the zone.
    .{
        .name = "www.example.",
        .qtype = "A",
        .required = &.{"www.example. 300 IN A 192.0.2.10"},
        .forbidden = &.{"rcode"},
    },
    // NODATA: NOERROR, the apex SOA in AUTHORITY, and no answer RRset. The
    // formatter prints no rcode line for NOERROR.
    .{
        .name = "www.example.",
        .qtype = "TXT",
        .required = &.{ ";; AUTHORITY SECTION:", "IN SOA" },
        .forbidden = &.{ "IN TXT", "rcode" },
    },
    // NXDOMAIN: the name does not exist, proved by the apex SOA.
    .{
        .name = "missing.example.",
        .qtype = "A",
        .required = &.{ "rcode NXDOMAIN", ";; AUTHORITY SECTION:", "IN SOA" },
        .forbidden = &.{"IN A"},
    },
    // In-zone alias: the CNAME is required; the server may also add the
    // target's A record, and does.
    .{
        .name = "alias.example.",
        .qtype = "A",
        .required = &.{"alias.example. 300 IN CNAME www.example."},
    },
    // Wildcard: the owner on the wire is the expanded name, never the '*.'.
    .{
        .name = "x.wild.example.",
        .qtype = "A",
        .required = &.{"x.wild.example. 300 IN A 192.0.2.20"},
        .forbidden = &.{"*.wild"},
    },
    // DNAME: the owner DNAME plus the synthesized CNAME to the substituted
    // name. The target is outside the zone, so no target A is expected.
    .{
        .name = "x.redir.example.",
        .qtype = "A",
        .required = &.{
            "redir.example. 300 IN DNAME target.example.",
            "x.redir.example. 300 IN CNAME x.target.example.",
        },
    },
    // Referral: the delegation in AUTHORITY, glue in ADDITIONAL, and no answer
    // record for the queried name. The query formatter prints no flags, so the
    // absence of an answer stands in for the cleared AA bit.
    .{
        .name = "host.child.example.",
        .qtype = "A",
        .required = &.{
            ";; AUTHORITY SECTION:",
            "child.example. 300 IN NS ns.child.example.",
            ";; ADDITIONAL SECTION:",
            "ns.child.example. 300 IN A 192.0.2.40",
        },
        .forbidden = &.{ "host.child.example.", "rcode" },
    },
    // No recursion configured: a name no zone serves is refused.
    .{
        .name = "outside.example.net.",
        .qtype = "A",
        .required = &.{ "rcode REFUSED", "no answers" },
        .forbidden = &.{"IN A"},
    },
};

const zone =
    \\$ORIGIN example.
    \\$TTL 300
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\ns IN A 192.0.2.53
    \\www IN A 192.0.2.10
    \\alias IN CNAME www.example.
    \\*.wild IN A 192.0.2.20
    \\redir IN DNAME target.example.
    \\child IN NS ns.child.example.
    \\ns.child IN A 192.0.2.40
    \\
;

test "the authoritative answer classes are reachable through server run and query" {
    // `spawn` builds an argv, which `global_single_threaded` cannot do because
    // it allocates from `.failing`.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zone });
    const zone_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/example.zone", .{&tmp.sub_path});

    const port = try pickPort(io, udp_port_base, .dgram, .udp);
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    const quota_text = try std.fmt.allocPrint(allocator, "{d}", .{cases.len});
    const server_argv = [_][]const u8{
        build_options.exe_path, "server",  "run",           "--zone-file", zone_path,
        "--once-udp",           port_text, "--max-queries", quota_text,
    };

    var out_file = try tmp.dir.createFile(io, "out", .{});
    var err_file = try tmp.dir.createFile(io, "err", .{});
    var child = try std.process.spawn(io, .{
        .argv = &server_argv,
        .stdin = .ignore,
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    });
    out_file.close(io);
    err_file.close(io);
    var reaped = false;
    defer if (!reaped) child.kill(io);

    // The query argv every check reports with; the first one also probes
    // readiness, because a datagram sent before the bind is simply dropped.
    const query_argv = try queryArgv(allocator, port_text, cases[0]);
    const ready_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(ready_window_seconds), .clock = .awake });
    while (true) {
        const result = try std.process.run(allocator, io, .{ .argv = query_argv, .timeout = child_deadline });
        if (exitCode(result.term) == 0 and result.stdout.len != 0) {
            try check(0, result.stdout);
            break;
        }
        if (expired(io, ready_deadline)) {
            const stdout = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
            const stderr = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));
            std.debug.print(
                "\n--- server never answered its readiness probe within {d}s\nargv: {s}\nport: {d}\nquery stdout: {s}\nquery stderr: {s}\nserver stdout: {s}\nserver stderr: {s}\n",
                .{ ready_window_seconds, try joinArgv(allocator, &server_argv), port, result.stdout, result.stderr, stdout, stderr },
            );
            return error.ServerNeverAnswered;
        }
    }

    for (cases[1..], 1..) |case, index| {
        const argv = try queryArgv(allocator, port_text, case);
        const result = std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline }) catch |err| {
            std.debug.print("\n--- query did not terminate\nargv: {s}\nerror: {t}\n", .{ try joinArgv(allocator, argv), err });
            return err;
        };
        if (exitCode(result.term) != 0) {
            std.debug.print(
                "\n--- query exited nonzero\nargv: {s}\nstdout: {s}\nstderr: {s}\n",
                .{ try joinArgv(allocator, argv), result.stdout, result.stderr },
            );
            return error.QueryFailed;
        }
        try check(index, result.stdout);
    }

    // Every query got its answer, so the server has served its quota and must
    // leave on its own with the success code.
    const term = try reapBounded(&child, io);
    reaped = true;
    if (exitCode(term) == 0) {
        std.debug.print("authoritative-surface guard: {d} answer classes, 0 failures\n", .{cases.len});
        return;
    }

    const stdout = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
    const stderr = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));
    std.debug.print(
        "\n--- the server did not exit 0 after its {d}-query quota\nargv: {s}\nterm: {?d}\nstdout: {s}\nstderr: {s}\n",
        .{ cases.len, try joinArgv(allocator, &server_argv), exitCode(term), stdout, stderr },
    );
    return error.ServerExitFailed;
}

test "the TCP query command reaches the same answer through server run" {
    // `spawn` and `run` build an argv, which `global_single_threaded` cannot do
    // because it allocates from `.failing`.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "example.zone", .data = zone });
    const zone_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/example.zone", .{&tmp.sub_path});

    const port = try pickPort(io, tcp_port_base, .stream, .tcp);
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    const server_argv = [_][]const u8{
        build_options.exe_path, "server",  "run",           "--zone-file", zone_path,
        "--once-tcp",           port_text, "--max-queries", "1",
    };

    var out_file = try tmp.dir.createFile(io, "tcp-out", .{});
    var err_file = try tmp.dir.createFile(io, "tcp-err", .{});
    var child = try std.process.spawn(io, .{
        .argv = &server_argv,
        .stdin = .ignore,
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    });
    out_file.close(io);
    err_file.close(io);
    var reaped = false;
    defer if (!reaped) child.kill(io);

    const query_argv = [_][]const u8{
        build_options.exe_path, "query", "--tcp", "@127.0.0.1", "-p", port_text, cases[0].name, cases[0].qtype,
    };
    const answer = cases[0].required[0];

    // `--once-tcp` serves one frame, so the first accepted connection must be
    // the query under test. A connect before the bind is refused without
    // consuming the quota, so the query itself is retried; a served answer
    // exits 0 and ends the wait rather than being probed again.
    const ready_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(ready_window_seconds), .clock = .awake });
    var attempt_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer attempt_state.deinit();
    while (true) {
        const result = std.process.run(attempt_state.allocator(), io, .{ .argv = &query_argv, .timeout = child_deadline }) catch |err| {
            std.debug.print("\n--- query did not terminate\nargv: {s}\nerror: {t}\n", .{ try joinArgv(allocator, &query_argv), err });
            return err;
        };
        if (exitCode(result.term) == 0) {
            if (std.mem.indexOf(u8, result.stdout, answer) == null) {
                std.debug.print(
                    "\n--- the TCP response does not carry the answer the zone holds\nargv: {s}\nrequired: {s}\nrendered:\n{s}\n",
                    .{ try joinArgv(allocator, &query_argv), answer, result.stdout },
                );
                return error.AnswerClassMissing;
            }
            break;
        }
        if (expired(io, ready_deadline)) {
            const stdout = try tmp.dir.readFileAlloc(io, "tcp-out", allocator, .limited(1024 * 1024));
            const stderr = try tmp.dir.readFileAlloc(io, "tcp-err", allocator, .limited(1024 * 1024));
            std.debug.print(
                "\n--- the TCP query never reached the server within {d}s\nargv: {s}\nport: {d}\nquery stdout: {s}\nquery stderr: {s}\nserver stdout: {s}\nserver stderr: {s}\n",
                .{ ready_window_seconds, try joinArgv(allocator, &query_argv), port, result.stdout, result.stderr, stdout, stderr },
            );
            return error.ServerNeverAnswered;
        }
        // The refused attempt's captured output is dropped before the next
        // try, so a server that never binds cannot grow the test.
        _ = attempt_state.reset(.retain_capacity);
        std.Io.sleep(io, .fromMilliseconds(10), .awake) catch {};
    }

    // Every query got its answer, so the server has served its quota and must
    // leave on its own with the success code.
    const term = try reapBounded(&child, io);
    reaped = true;
    if (exitCode(term) == 0) {
        std.debug.print("tcp-cli guard: 1 tcp answer through query --tcp, 0 failures\n", .{});
        return;
    }

    const stdout = try tmp.dir.readFileAlloc(io, "tcp-out", allocator, .limited(1024 * 1024));
    const stderr = try tmp.dir.readFileAlloc(io, "tcp-err", allocator, .limited(1024 * 1024));
    std.debug.print(
        "\n--- the server did not exit 0 after its one-query TCP quota\nargv: {s}\nterm: {?d}\nstdout: {s}\nstderr: {s}\n",
        .{ try joinArgv(allocator, &server_argv), exitCode(term), stdout, stderr },
    );
    return error.ServerExitFailed;
}

/// The first candidate whose loopback port can be bound in `mode`. The probe
/// socket is closed before the server binds it; the gap is narrower than a
/// hard-coded port shared with another root.
fn pickPort(io: std.Io, base: u16, mode: std.Io.net.Socket.Mode, protocol: std.Io.net.Protocol) !u16 {
    var offset: u16 = 0;
    while (offset < port_candidates) : (offset += 1) {
        const address = std.Io.net.IpAddress{ .ip4 = .loopback(base + offset) };
        const socket = std.Io.net.IpAddress.bind(&address, io, .{ .mode = mode, .protocol = protocol }) catch |err| switch (err) {
            error.AddressInUse => continue,
            else => return err,
        };
        socket.close(io);
        return base + offset;
    }
    return error.NoFreePort;
}

fn queryArgv(allocator: std.mem.Allocator, port_text: []const u8, case: Case) ![]const []const u8 {
    return allocator.dupe([]const u8, &.{
        build_options.exe_path, "query", "@127.0.0.1", "-p", port_text, case.name, case.qtype,
    });
}

fn check(index: usize, stdout: []const u8) !void {
    const case = cases[index];
    for (case.required) |needle| {
        if (std.mem.indexOf(u8, stdout, needle) != null) continue;
        std.debug.print(
            "\n--- answer class missing from the rendered response\ncase: {s} {s}\nrequired: {s}\nrendered:\n{s}\n",
            .{ case.name, case.qtype, needle, stdout },
        );
        return error.AnswerClassMissing;
    }
    for (case.forbidden) |needle| {
        if (std.mem.indexOf(u8, stdout, needle) == null) continue;
        std.debug.print(
            "\n--- answer class carries a line it must not\ncase: {s} {s}\nforbidden: {s}\nrendered:\n{s}\n",
            .{ case.name, case.qtype, needle, stdout },
        );
        return error.AnswerClassWrong;
    }
}

/// Waits for the server under a deadline. A watcher kills the child once the
/// deadline passes, so a server that never leaves cannot hang the suite.
fn reapBounded(child: *std.process.Child, io: std.Io) !std.process.Child.Term {
    var done = std.atomic.Value(bool).init(false);
    const Watch = struct {
        child: *std.process.Child,
        io: std.Io,
        done: *std.atomic.Value(bool),

        fn run(self: @This()) void {
            var waited_ms: u64 = 0;
            while (waited_ms < reap_deadline_ms) : (waited_ms += 10) {
                if (self.done.load(.acquire)) return;
                std.Io.sleep(self.io, .fromMilliseconds(10), .awake) catch return;
            }
            self.child.kill(self.io);
        }
    };
    const watcher = try std.Thread.spawn(.{}, Watch.run, .{Watch{ .child = child, .io = io, .done = &done }});
    const term = try child.wait(io);
    done.store(true, .release);
    watcher.join();
    return term;
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

/// Joins argv for one failure line; the arena owns the result.
fn joinArgv(allocator: std.mem.Allocator, argv: []const []const u8) ![]const u8 {
    return std.mem.join(allocator, " ", argv);
}
