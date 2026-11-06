/// Contract: every invocation the project documents is executed against the
/// built binary and asserted to end in the outcome class the project promises
/// for it. The set is parsed out of the real sources -- the `Usage:` block of
/// `zimdns --help`, the encrypted-transport flags its prose names, and every
/// `zimdns ...` line in a comment under `examples/` -- so a new example becomes
/// a new case here instead of rotting unnoticed.
/// Ownership: one arena owns every string, buffer, socket and child result for
/// the whole test. Every spawned process is reaped before it returns.
/// Errors: a documented invocation that ends in an undocumented outcome fails
/// with its exact argv, exit code, stdout and stderr. An invocation the harness
/// cannot classify also fails, so a new example is never silently skipped.
/// Scope: this proves the path runs, and refuses where it should. That a path
/// answers *correctly* stays with the integration suite.
const std = @import("std");
const zimdns = @import("zimdns");
const build_options = @import("build_options");

const cli_query = zimdns.cli_query;
const ossl = zimdns.transport_openssl_tls;
const tcp_deadline = zimdns.tcp_deadline;

/// Test-only insecure client: skips verification for loopback fixtures with
/// throwaway identities. MUST NOT be used in production paths.
fn insecureTestClient(
    fd: std.posix.fd_t,
    io: std.Io,
    alpn: []const u8,
    comptime test_only: bool,
) !ossl.Connection {
    comptime if (!test_only) @compileError("insecureTestClient is test-only: production must verify");
    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    const deadline = tcp_deadline.deadline(io, .{ .seconds = 5 });
    return ossl.clientHandshake(ctx, fd, io, deadline, .{
        .verify = .insecure,
        .verify_host = "localhost",
        .sni = "localhost",
        .alpn = alpn,
    });
}

/// `exitUsage` in src/main.zig.
const usage_exit: u8 = 2;

/// The port an invocation with no configurable bind address takes: a
/// `--serve-*` with no `--config`, or a configuration declaring no listener.
/// Both fall back to the CLI default.
const documented_port: u16 = 1053;

/// First high port of the per-case range. Substituted into the executed argv
/// only; a failure message quotes the documented argv.
const port_base: u16 = 21400;

/// A listener prints nothing when it binds, so a request sent before it is
/// ready is lost: a datagram is dropped, and `--once-udp` then dies on its own
/// idle timeout. Readiness is therefore the server's own answer, never a fixed
/// delay. `ready_budget` paces each UDP attempt (a dropped datagram costs one
/// receive timeout) and `ready_window` bounds a *broken* build, turning a hang
/// into a reported failure. It is a liveness bound on the wait, never a
/// threshold on an assertion.
const ready_budget = std.Io.Timeout{ .duration = .{
    .raw = .fromMilliseconds(100),
    .clock = .awake,
} };
const ready_window: u64 = 10;

fn readyDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(ready_window), .clock = .awake });
}

fn expired(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    return deadline.durationFromNow(io).raw.nanoseconds <= 0;
}

/// Whole-child deadline, so an invocation that stops terminating fails loudly
/// instead of hanging the suite.
const child_deadline = std.Io.Timeout{ .duration = .{
    .raw = .fromSeconds(20),
    .clock = .awake,
} };

const Transport = enum { udp, tcp, dot, doh, xfr };

const Kind = enum {
    /// `--help`, `--version`: runs and exits 0.
    informational,
    /// `server run` with no mode: exits `usage_exit` without opening anything.
    usage_refusal,
    /// A transport this build cannot serve: exits `usage_exit`, says why, and
    /// leaves its port unbound.
    encrypted_refusal,
    /// A bounded listener: must serve its quota and exit 0.
    serve,
    /// `zimdns query`: needs a server, must exit 0 with an answer.
    query,
};

const Case = struct {
    /// Exactly what the documentation says.
    documented: []const []const u8,
    /// What runs: the same invocation with the port substituted -- a
    /// configuration that carries its own listeners is copied onto the
    /// per-case port -- and with the project's own `--max-requests` appended
    /// when the documented line carries no bound (`server run --serve-tcp`
    /// otherwise never returns).
    executed: []const []const u8,
    kind: Kind,
    transport: Transport,
    /// Requests the server must serve before it exits.
    quota: usize,
    /// The port the executed server binds or the query targets.
    port: u16,
    /// For a refusal, the port that must still be unbound afterwards.
    refuse_port: u16 = 0,
    /// For a refusal, the text the run must print to say why it refused.
    refusal_text: []const u8 = "",
    /// True when `--print-metrics` promises Prometheus output on stdout.
    metrics: bool = false,
    /// The documented `--config` the executed argv's copy came from, so a
    /// failure report never implies the shipped file ran.
    rewritten_config: ?[]const u8 = null,
};

test "every documented invocation runs and ends in its documented outcome class" {
    // `global_single_threaded` allocates from `.failing`, so `spawn` cannot
    // build an argv with it.
    // `connect` needs concurrency slots, the same bound src/main.zig gives its
    // TCP loop.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const discovered = try discover(allocator, io);
    // Discovery that finds nothing would pass vacuously.
    try std.testing.expect(discovered.help_count > 0);
    try std.testing.expect(discovered.examples_count > 0);

    // The encrypted cases read these at run time, so the fixture must outlive
    // the whole run. The identity is the project's own throwaway certificate,
    // so the DoH case can serve a real listener.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "cert.pem",
        .data = zimdns.transport_tls_server.test_identity.cert_pem,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "key.pem",
        .data = zimdns.transport_tls_server.test_identity.key_pem,
    });
    // Every fixture a child reads lives under the temporary directory, so the
    // one `cleanup` takes a rewritten configuration with it, pass or fail.
    const tmp_prefix = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    const tls_cert = try std.fmt.allocPrint(allocator, "{s}/cert.pem", .{tmp_prefix});
    const tls_key = try std.fmt.allocPrint(allocator, "{s}/key.pem", .{tmp_prefix});

    const cases = try buildCases(allocator, io, tmp_prefix, discovered, tls_cert, tls_key);
    var failures: usize = 0;
    for (cases) |case| {
        if (!try execute(allocator, io, case)) failures += 1;
    }
    std.debug.print("documented-invocation guard: {d} invocations, {d} failures\n", .{ cases.len, failures });

    if (failures != 0) return error.DocumentedInvocationFailed;
}

// ------------------------------------------------------------------ discovery

const Discovery = struct {
    /// Every distinct documented invocation, `--help` first.
    invocations: [][]const []const u8,
    help_count: usize,
    examples_count: usize,
    /// Flags the prose names without a complete invocation of their own.
    prose_flags: []const []const u8,
};

fn discover(allocator: std.mem.Allocator, io: std.Io) !Discovery {
    const help_argv = [_][]const u8{ build_options.exe_path, "--help" };
    const help = try std.process.run(allocator, io, .{ .argv = &help_argv, .timeout = child_deadline });

    var found: std.ArrayList([]const []const u8) = .empty;
    var help_count: usize = 0;
    var help_lines = std.mem.splitScalar(u8, help.stdout, '\n');
    while (help_lines.next()) |line| {
        // Only the indented `Usage:` entries are invocations; the banner line
        // starts with "zimdns " too but is prose. The DoQ and DoH/3 lines are
        // skipped here: the external interop harness proves them (aioquic),
        // and this guard has no QUIC client to drive them with.
        if (line.len == 0 or (line[0] != ' ' and line[0] != '\t')) continue;
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "zimdns ")) continue;
        const tokens = try tokenize(allocator, trimmed);
        if (hasFlag(tokens, "--serve-doq") or hasFlag(tokens, "--serve-doh3")) continue;
        help_count += 1;
        try appendUnique(allocator, &found, tokens);
    }

    var examples_count: usize = 0;
    var examples_dir = try std.Io.Dir.cwd().openDir(io, "examples", .{ .iterate = true });
    defer examples_dir.close(io);
    var walker = try examples_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const text = try examples_dir.readFileAlloc(io, entry.path, allocator, .limited(1024 * 1024));
        var file_lines = std.mem.splitScalar(u8, text, '\n');
        while (file_lines.next()) |raw| {
            var candidate = std.mem.trim(u8, raw, " \t");
            if (candidate.len > 0 and candidate[0] == '#') candidate = std.mem.trim(u8, candidate[1..], " \t");
            if (!std.mem.startsWith(u8, candidate, "zimdns ")) continue;
            examples_count += 1;
            try appendUnique(allocator, &found, try tokenize(allocator, candidate));
        }
    }

    // The prose names flags that never appear as a complete invocation.
    var prose: std.ArrayList([]const u8) = .empty;
    var words = std.mem.tokenizeAny(u8, help.stdout, " \t\r\n,;.");
    while (words.next()) |word| {
        if (!std.mem.startsWith(u8, word, "--serve-")) continue;
        if (argvContains(found.items, word)) continue;
        var already = false;
        for (prose.items) |existing| {
            if (std.mem.eql(u8, existing, word)) already = true;
        }
        if (!already) try prose.append(allocator, word);
    }

    return .{
        .invocations = try found.toOwnedSlice(allocator),
        .help_count = help_count,
        .examples_count = examples_count,
        .prose_flags = try prose.toOwnedSlice(allocator),
    };
}

fn argvContains(list: []const []const []const u8, needle: []const u8) bool {
    for (list) |argv| {
        for (argv) |arg| {
            if (std.mem.eql(u8, arg, needle)) return true;
        }
    }
    return false;
}

/// Drops the `zimdns` program word: the harness always runs the built binary,
/// which is what the documentation's `zimdns` stands for.
fn tokenize(allocator: std.mem.Allocator, line: []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    var words = std.mem.tokenizeAny(u8, line, " \t\r\n");
    _ = words.next() orelse return argv.toOwnedSlice(allocator);
    while (words.next()) |word| {
        if (std.mem.startsWith(u8, word, "#")) break;
        try argv.append(allocator, word);
    }
    return argv.toOwnedSlice(allocator);
}

fn sameArgv(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x, y)) return false;
    }
    return true;
}

fn appendUnique(allocator: std.mem.Allocator, list: *std.ArrayList([]const []const u8), argv: []const []const u8) !void {
    for (list.items) |existing| {
        if (sameArgv(existing, argv)) return;
    }
    try list.append(allocator, argv);
}

// ------------------------------------------------------------- classification

fn buildCases(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, discovered: Discovery, tls_cert: []const u8, tls_key: []const u8) ![]Case {
    var cases: std.ArrayList(Case) = .empty;
    var next_port: u16 = port_base;

    for (discovered.invocations) |argv| {
        const case = classify(allocator, io, tmp_prefix, argv, &next_port, tls_cert, tls_key) catch |err| {
            std.debug.print("\n--- documented invocation the harness cannot classify:\n", .{});
            printArgv("documented: zimdns ", argv);
            return err;
        };
        try cases.append(allocator, case);
    }
    for (discovered.prose_flags) |flag| {
        try cases.append(allocator, try classifyProseFlag(allocator, io, tmp_prefix, flag, tls_cert, tls_key));
        next_port += 2;
    }
    return cases.toOwnedSlice(allocator);
}

const mode_flags = [_][]const u8{
    "--once-udp", "--once-tcp", "--serve-udp", "--serve-tcp", "--serve-dot", "--serve-doh", "--serve-xfr",
};

fn hasFlag(argv: []const []const u8, flag: []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

fn flagCount(argv: []const []const u8) usize {
    var count: usize = 0;
    for (mode_flags) |flag| {
        if (hasFlag(argv, flag)) count += 1;
    }
    return count;
}

fn isInformationalFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h") or
        std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--version");
}

fn classify(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, argv: []const []const u8, next_port: *u16, tls_cert: []const u8, tls_key: []const u8) !Case {
    if (argv.len == 0) return error.UndocumentedInvocation;
    const port = next_port.*;
    next_port.* += 2;

    if (argv.len == 1) {
        if (!isInformationalFlag(argv[0])) return error.UndocumentedInvocation;
        return plain(argv, .informational, port);
    }

    if (std.mem.eql(u8, argv[0], "server")) {
        if (argv.len < 2 or !std.mem.eql(u8, argv[1], "run")) return error.UndocumentedInvocation;

        // The DoH port is served now, so the case runs the real listener and
        // drives a DoH exchange over TLS.
        if (hasFlag(argv, "--serve-doh")) return classifyDoh(allocator, argv, tls_cert, tls_key);

        // The zone-transfer channel is served over TLS too, so the case runs
        // the real listener and drives one transfer over the handshake.
        if (hasFlag(argv, "--serve-xfr")) return classifyXfr(allocator, io, tmp_prefix, argv, tls_cert, tls_key);

        // The DoT port is served now, so the case runs the real listener and
        // drives one DoT exchange over the handshake.
        if (hasFlag(argv, "--serve-dot")) return classifyDot(allocator, argv, tls_cert, tls_key);

        // The transports this build cannot serve refuse; the encrypted ones
        // are served, so their refusal has to come from the identity.

        switch (flagCount(argv)) {
            0 => return plain(argv, .usage_refusal, port),
            1 => {},
            else => return error.UndocumentedInvocation,
        }

        const quota_text = flagValue(argv, "--max-queries") orelse flagValue(argv, "--max-requests") orelse "1";
        const quota = std.fmt.parseInt(usize, quota_text, 10) catch return error.UndocumentedInvocation;
        if (quota == 0 or quota > 2) return error.UndocumentedInvocation;
        // TCP accepts exactly one query per connection.
        if (hasFlag(argv, "--once-tcp") and quota != 1) return error.UndocumentedInvocation;

        const server = try bindServer(allocator, io, tmp_prefix, argv, port, quota);
        return .{
            .documented = argv,
            .executed = server.args,
            .kind = .serve,
            .transport = if (hasFlag(argv, "--once-udp") or hasFlag(argv, "--serve-udp")) .udp else .tcp,
            .quota = quota,
            .port = server.port,
            .rewritten_config = server.rewritten_from,
            .metrics = hasFlag(argv, "--print-metrics"),
        };
    }

    if (std.mem.eql(u8, argv[0], "query")) {
        // A TCP query would need a companion bound to the same port that serves
        // two connections, which the CLI cannot express. Left unclassified
        // rather than silently untested.
        if (hasFlag(argv, "--tcp")) return error.UndocumentedInvocation;
        return .{
            .documented = argv,
            .executed = try rewriteQueryPort(allocator, argv, port),
            .kind = .query,
            .transport = .udp,
            .quota = 1,
            .port = port,
        };
    }

    return error.UndocumentedInvocation;
}

/// `--serve-doh` is served: the case runs the real listener with a loadable
/// identity and drives one DoH exchange over TLS. The documented invocation
/// names no listener, so the port is the CLI default.
fn classifyDoh(allocator: std.mem.Allocator, argv: []const []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(allocator, argv);
    try out.append(allocator, "--enable-encrypted-dns");
    try out.append(allocator, "--tls-cert-file");
    try out.append(allocator, tls_cert);
    try out.append(allocator, "--tls-key-file");
    try out.append(allocator, tls_key);
    // One connection is the whole quota, so the server stops on its own.
    try out.append(allocator, "--max-requests");
    try out.append(allocator, "1");
    return .{
        .documented = argv,
        .executed = try out.toOwnedSlice(allocator),
        .kind = .serve,
        .transport = .doh,
        .quota = 1,
        .port = documented_port,
    };
}

/// `--serve-dot` is served: the case runs the real listener with a loadable
/// identity and drives one DoT exchange over TLS. The documented invocation
/// names no listener, so the port is the CLI default.
fn classifyDot(allocator: std.mem.Allocator, argv: []const []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(allocator, argv);
    try out.append(allocator, "--enable-encrypted-dns");
    try out.append(allocator, "--tls-cert-file");
    try out.append(allocator, tls_cert);
    try out.append(allocator, "--tls-key-file");
    try out.append(allocator, tls_key);
    // One connection is the whole quota, so the server stops on its own.
    try out.append(allocator, "--max-requests");
    try out.append(allocator, "1");
    // The metrics run proves the DoT query counter moves in the server.
    try out.append(allocator, "--print-metrics");
    return .{
        .documented = argv,
        .executed = try out.toOwnedSlice(allocator),
        .kind = .serve,
        .transport = .dot,
        .quota = 1,
        .port = documented_port,
        .metrics = true,
    };
}

/// A flag the prose names without a complete invocation of its own. The
/// transports this build serves run their real listener; a transport that
/// still cannot be served refuses with its own reason.
fn classifyProseFlag(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, flag: []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    if (std.mem.eql(u8, flag, "--serve-xfr")) {
        const argv = [_][]const u8{ "server", "run", "--zone-file", "examples/zones/home.arpa.zone", "--serve-xfr" };
        return classifyXfr(allocator, io, tmp_prefix, &argv, tls_cert, tls_key);
    }
    if (std.mem.eql(u8, flag, "--serve-dot")) {
        const argv = [_][]const u8{ "server", "run", "--zone-file", "examples/zones/home.arpa.zone", "--serve-dot" };
        return classifyDot(allocator, &argv, tls_cert, tls_key);
    }
    return classifyRefusal(allocator, flag, tls_cert, tls_key);
}

/// `--serve-xfr` is served only for zones the transfer ACL grants: the staged
/// config carries `allow-transfer home.arpa. 127.0.0.0/8`, so the loopback
/// driver is permitted and a zone with no matching entry would get REFUSED.
/// The documented invocation names no listener, so the port is the CLI default.
fn classifyXfr(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, argv: []const []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    const zone_data = try std.Io.Dir.cwd().readFileAlloc(io, "examples/zones/home.arpa.zone", allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(zone_data);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(allocator, "{s}/home.arpa.zone", .{tmp_prefix}), .data = zone_data });
    const config_path = try std.fmt.allocPrint(allocator, "{s}/xfr.gdns", .{tmp_prefix});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = "zone home.arpa. primary home.arpa.zone\nallow-transfer home.arpa. 127.0.0.0/8\n" });
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(allocator, &.{ "server", "run", "--config", config_path, "--serve-xfr" });
    try out.append(allocator, "--enable-encrypted-dns");
    try out.append(allocator, "--tls-cert-file");
    try out.append(allocator, tls_cert);
    try out.append(allocator, "--tls-key-file");
    try out.append(allocator, tls_key);
    // One connection is the whole quota, so the server stops on its own.
    try out.append(allocator, "--max-requests");
    try out.append(allocator, "1");
    return .{
        .documented = argv,
        .executed = try out.toOwnedSlice(allocator),
        .kind = .serve,
        .transport = .xfr,
        .quota = 1,
        .port = documented_port,
    };
}

/// The encrypted case the prose documents: the flag plus everything needed to
/// reach the TLS-termination gate, so the harness observes the real refusal
/// rather than an argument-validation stop. The DoT port is served in this
/// build, so its refusal has to come from the identity: a certificate that
/// is not there is the clean way to reach the gate that refuses before the
/// port is bound.
fn classifyRefusal(allocator: std.mem.Allocator, flag: []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/absent-cert.pem", .{std.fs.path.dirname(tls_cert) orelse tls_cert});
    // Arena-owned: a local array literal would dangle once this frame returns.
    const argv = [_][]const u8{
        "server",         "run",                    "--zone-file",     "examples/zones/home.arpa.zone",
        flag,             "--enable-encrypted-dns", "--tls-cert-file", cert_path,
        "--tls-key-file", tls_key,
    };
    const owned = try allocator.dupe([]const u8, argv[0..]);
    return .{
        .documented = owned,
        .executed = owned,
        .kind = .encrypted_refusal,
        .transport = .tcp,
        .quota = 0,
        .port = documented_port,
        .refuse_port = documented_port,
        .refusal_text = "cannot read TLS certificate file",
    };
}

fn plain(argv: []const []const u8, kind: Kind, port: u16) Case {
    return .{
        .documented = argv,
        .executed = argv,
        .kind = kind,
        .transport = .udp,
        .quota = 0,
        .port = port,
    };
}

fn flagValue(argv: []const []const u8, flag: []const u8) ?[]const u8 {
    for (argv, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, flag) and index + 1 < argv.len) return argv[index + 1];
    }
    return null;
}

const BoundServer = struct {
    args: []const []const u8,
    port: u16,
    /// The documented `--config` the executed copy was derived from, when the
    /// case ran one.
    rewritten_from: ?[]const u8,
};

/// Substitutes the per-case port wherever the CLI can express one, and appends
/// the project's own bound when the documented line has none, so every run
/// terminates without the harness killing it. A configuration carrying its own
/// `listen` address is copied with those endpoints moved onto the per-case
/// port; only one declaring no listener keeps the documented default.
fn bindServer(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, argv: []const []const u8, port: u16, quota: usize) !BoundServer {
    var out: std.ArrayList([]const u8) = .empty;
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    var substituted = false;
    var rewritten_from: ?[]const u8 = null;

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--once-udp") or std.mem.eql(u8, arg, "--once-tcp")) {
            const has_port = index + 1 < argv.len and !std.mem.startsWith(u8, argv[index + 1], "--");
            try out.append(allocator, arg);
            try out.append(allocator, port_text);
            substituted = true;
            if (has_port) index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--config") and index + 1 < argv.len) {
            const copy = try rebindConfig(allocator, io, tmp_prefix, argv[index + 1], port);
            try out.append(allocator, arg);
            try out.append(allocator, copy orelse argv[index + 1]);
            if (copy != null) {
                rewritten_from = argv[index + 1];
                substituted = true;
            }
            index += 1;
            continue;
        }
        try out.append(allocator, arg);
    }

    if (!hasFlag(argv, "--max-requests") and !hasFlag(argv, "--max-queries")) {
        const quota_text = try std.fmt.allocPrint(allocator, "{d}", .{quota});
        try out.append(allocator, "--max-requests");
        try out.append(allocator, quota_text);
    }

    return .{
        .args = try out.toOwnedSlice(allocator),
        .port = if (substituted) port else documented_port,
        .rewritten_from = rewritten_from,
    };
}

/// Copies a documented configuration with every `listen` endpoint moved to the
/// per-case port on loopback, and returns the copy's path. A `--serve-*` run
/// takes its address from the configuration: src/main.zig picks the listener
/// whose transport matches the mode and binds exactly that, so a case whose
/// port only exists in a file would bind an address the harness never queries
/// and wait out its readiness window. Rewriting also spares the harness a
/// fixed address it could not safely rebind. Returns null when the
/// configuration declares no listener, which leaves the run on the CLI default.
fn rebindConfig(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, path: []const u8, port: u16) !?[]const u8 {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch return error.UnreadableConfig;
    const endpoint = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
    // The copy lives in the temporary directory, so every file it names is
    // copied beside it and the copy names the copy. Absolute paths pass
    // through untouched; a path that cannot be read is left as its basename
    // (a write path like `odoh-config-out` lands beside the copy, and a
    // missing read fails in the server exactly as it would have).
    const anchor = std.fs.path.dirname(path) orelse ".";

    var out: std.ArrayList(u8) = .empty;
    var listeners: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const bare = commentless(line);
        var words = std.mem.tokenizeAny(u8, bare, " \t");
        var toks: [8][]const u8 = undefined;
        var n: usize = 0;
        while (words.next()) |word| {
            if (n == toks.len) break;
            toks[n] = word;
            n += 1;
        }
        if (n == 0) {
            try out.appendSlice(allocator, line);
            try out.append(allocator, '\n');
            continue;
        }
        if (std.mem.eql(u8, toks[0], "listen")) {
            // `listen dns <transport> <endpoint>` is the one shape
            // src/config/parser.zig accepts, and the only one this rewrite knows
            // where the server will bind. A listener it cannot place fails here,
            // loudly, instead of binding somewhere the harness never looks.
            if (n != 4 or !std.mem.eql(u8, toks[1], "dns")) return error.UnrebindableListener;
            listeners += 1;
            try out.print(allocator, "listen dns {s} {s}\n", .{ toks[2], endpoint });
            continue;
        }
        if (rebindPathIndex(toks[0..n])) |pi| {
            const staged = try stagePath(allocator, io, tmp_prefix, anchor, toks[pi]);
            // Token slices point into `line` (`bare` is its prefix), so the
            // path is spliced in place and comments survive verbatim.
            const off = @intFromPtr(toks[pi].ptr) - @intFromPtr(line.ptr);
            try out.appendSlice(allocator, line[0..off]);
            try out.appendSlice(allocator, staged);
            try out.appendSlice(allocator, line[off + toks[pi].len ..]);
            try out.append(allocator, '\n');
            continue;
        }
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    if (listeners == 0) return null;

    const name = try std.fmt.allocPrint(allocator, "config-{d}.gdns", .{port});
    const copy = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tmp_prefix, name });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = copy, .data = out.items });
    return copy;
}

/// The token index of the referenced file a copied line carries, if any.
/// `zone` names a file only for the `primary` kind; a secondary names an
/// address. `odoh-config-out` may not exist yet, but anchoring a relative
/// path keeps the write in the same directory the operator meant.
fn rebindPathIndex(toks: []const []const u8) ?usize {
    const first = toks[0];
    for ([_][]const u8{
        "tsig-key-file",     "dnssec-key-file",     "dnssec-ksk-file",   "dnssec-new-ksk-file",
        "trust-anchor-file", "managed-anchor-file", "ixfr-journal-file", "tls-cert-file",
        "tls-key-file",      "odoh-key-file",       "odoh-config-out",   "forwarder-ca-file",
        "root-zone",
    }) |directive| {
        if (std.mem.eql(u8, first, directive)) return if (toks.len == 2) 1 else null;
    }
    if (std.mem.eql(u8, first, "zone")) {
        if (toks.len == 4 and std.mem.eql(u8, toks[2], "primary")) return 3;
        return null;
    }
    if (std.mem.eql(u8, first, "blocklist")) {
        if (toks.len == 3 and std.mem.eql(u8, toks[1], "file")) return 2;
        return null;
    }
    if (std.mem.eql(u8, first, "blacklist-zone")) {
        return if (toks.len == 3) 2 else null;
    }
    return null;
}

/// Stages a referenced file beside the copied configuration and returns the
/// staged name. The copy lives in the temporary directory while the
/// referenced files stay beside the documented configuration, so the copy
/// names the staged twin. Absolute paths pass through untouched; a path
/// that cannot be read is staged by basename (a write path like
/// `odoh-config-out` lands beside the copy, and a missing read fails in
/// the server exactly as it would have).
fn stagePath(allocator: std.mem.Allocator, io: std.Io, tmp_prefix: []const u8, anchor: []const u8, path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    const source = if (std.mem.eql(u8, anchor, ".")) try allocator.dupe(u8, path) else try std.fs.path.join(allocator, &.{ anchor, path });
    defer allocator.free(source);
    const staged = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tmp_prefix, std.fs.path.basename(path) });
    defer allocator.free(staged);
    // The copy names the basename: both live in the temporary directory.
    const name = try allocator.dupe(u8, std.fs.path.basename(path));
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, source, allocator, .limited(16 * 1024 * 1024)) catch return name;
    defer allocator.free(bytes);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = staged, .data = bytes });
    return name;
}

/// Everything from the first `#` is a comment, exactly as the config parser
/// reads a line, so a commented-out listener is not one.
fn commentless(line: []const u8) []const u8 {
    const hash = std.mem.indexOfScalar(u8, line, '#') orelse return line;
    return line[0..hash];
}

fn rewriteQueryPort(allocator: std.mem.Allocator, argv: []const []const u8, port: u16) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        if (std.mem.eql(u8, argv[index], "-p") and index + 1 < argv.len) {
            try out.append(allocator, "-p");
            try out.append(allocator, port_text);
            index += 1;
            continue;
        }
        try out.append(allocator, argv[index]);
    }
    return out.toOwnedSlice(allocator);
}

// ------------------------------------------------------------------ execution

fn execute(allocator: std.mem.Allocator, io: std.Io, case: Case) !bool {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(allocator, build_options.exe_path);
    try argv.appendSlice(allocator, case.executed);

    return switch (case.kind) {
        .informational, .usage_refusal => runToCompletion(allocator, io, case, argv.items),
        .encrypted_refusal => runRefusal(allocator, io, case, argv.items),
        .serve => runServe(allocator, io, case, argv.items),
        .query => runQuery(allocator, io, case, argv.items),
    };
}

fn runToCompletion(allocator: std.mem.Allocator, io: std.Io, case: Case, argv: []const []const u8) !bool {
    const result = std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline }) catch |err| {
        report(case, null, "", @errorName(err), "child did not terminate");
        return false;
    };
    const code = exitCode(result.term);
    const ok = switch (case.kind) {
        .informational => code == 0 and std.mem.startsWith(u8, std.mem.trim(u8, result.stdout, " \n"), "zimdns "),
        .usage_refusal => code == usage_exit and std.mem.startsWith(u8, std.mem.trim(u8, result.stdout, " \n"), "error:"),
        else => unreachable,
    };
    if (ok) return true;
    report(case, code, result.stdout, result.stderr, "wrong exit code or output for its documented outcome class");
    return false;
}

/// Spawns the server, drives its quota of requests, then reaps it. Readiness is
/// the answer to a real query, never a sleep. Output goes to files so a child
/// can never block on a full pipe.
fn runServe(allocator: std.mem.Allocator, io: std.Io, case: Case, argv: []const []const u8) !bool {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
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

    const address = std.Io.net.IpAddress{ .ip4 = .loopback(case.port) };
    const drive = switch (case.transport) {
        .udp => Drive{ .served = driveUdp(io, address, case.quota) },
        .tcp => driveTcp(allocator, io, address, case.quota),
        .dot => driveDot(allocator, io, address, case.quota),
        .doh => driveDoh(allocator, io, address, case.quota),
        .xfr => driveXfr(allocator, io, address, case.quota),
    };
    const served = drive.served;
    if (served != case.quota) {
        const dbg_out = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
        const dbg_err = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));
        std.debug.print("DEBUG case port={d} argv={s}\nDEBUG out={s}\nDEBUG err={s}\n", .{ case.port, case.executed[case.executed.len - 1], dbg_out, dbg_err });
    }
    // `--once-tcp` blocks in accept() with no deadline, so a case that never
    // reached its quota must not be waited on forever.
    // `Child.kill` blocks until the child is reaped, so there is no `wait`
    // after it.
    const code: ?u8 = if (served == case.quota) exitCode(try child.wait(io)) else blk: {
        child.kill(io);
        break :blk null;
    };

    const stdout = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
    const stderr = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));

    // The DoT port counts its own queries, so its counter has to move too.
    const metrics_ok = !case.metrics or (std.mem.indexOf(u8, stdout, "zimdns_queries_total") != null and
        (case.transport != .dot or std.mem.indexOf(u8, stdout, "zimdns_dot_queries_total 1") != null));
    if (served == case.quota and code == 0 and metrics_ok) return true;

    const note = if (served != case.quota)
        try std.fmt.allocPrint(
            allocator,
            "harness served {d} of {d} requests within the {d}s readiness window; last transport error: {s}",
            .{ served, case.quota, ready_window, drive.last_error },
        )
    else if (code != 0)
        try std.fmt.allocPrint(allocator, "server served its quota but exited with {?d}", .{code})
    else
        "server exited 0 without the metrics its documented flags promise";
    report(case, code, stdout, stderr, note);
    return false;
}

fn driveUdp(io: std.Io, address: std.Io.net.IpAddress, quota: usize) usize {
    var bind = cli_query.udpClientBindAddress(&address);
    const socket = std.Io.net.IpAddress.bind(&bind, io, .{ .mode = .dgram, .protocol = .udp }) catch return 0;
    defer socket.close(io);

    var packet: [512]u8 = undefined;
    const query = cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false) catch return 0;
    var response: [4096]u8 = undefined;

    const deadline = readyDeadline(io);
    var served: usize = 0;
    while (served < quota and !expired(io, deadline)) {
        cli_query.sendUdpQuery(&socket, io, &address, query) catch return served;
        const incoming = socket.receiveTimeout(io, &response, ready_budget) catch continue;
        if (incoming.from.eql(&address)) served += 1;
    }
    return served;
}

const Drive = struct { served: usize = 0, last_error: []const u8 = "" };

/// One full DNS-over-TCP exchange on a connection of its own: the query, a
/// half-close telling the server no more queries are coming, then a whole
/// length-prefixed response. Reading less than a frame and closing would reset
/// the connection and turn an ordinary client hang-up into a non-zero exit, so
/// the response is read in full or the attempt is abandoned.
fn exchangeTcpOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var packet: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false);
    try cli_query.sendTcpQuery(stream, io, query);
    try stream.shutdown(io, .send);

    var response: [4096]u8 = undefined;
    var message = try cli_query.receiveTcpResponse(allocator, stream, io, &response, query, false);
    message.deinit();
}

fn driveTcp(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, quota: usize) Drive {
    var drive: Drive = .{};
    const deadline = readyDeadline(io);
    // A refused connect returns immediately, so the window, not an attempt
    // count, is what stops this from spinning out before the child binds.
    while (drive.served < quota and !expired(io, deadline)) {
        exchangeTcpOnce(allocator, io, address) catch |err| {
            drive.last_error = @errorName(err);
            continue;
        };
        drive.served += 1;
    }
    return drive;
}

/// One DoT exchange over TLS: the handshake with the "dot" ALPN token, a
/// query in the RFC 7858 section 3.3 framing, and the answer that comes back.
fn exchangeDotOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "dot", true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    var packet: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try connection_writer.interface.writeAll(&prefix);
    try connection_writer.interface.writeAll(query);
    try connection_writer.interface.flush();

    const length_bytes = try connection_reader.interface.takeArray(2);
    const length = std.mem.readInt(u16, length_bytes, .big);
    const body = try connection_reader.interface.take(length);
    const message = try zimdns.dns_message.Message.parse(allocator, body);
    if (message.header.answer_count != 1) return error.DotNoAnswer;
}

fn driveDot(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, quota: usize) Drive {
    var drive: Drive = .{};
    const deadline = readyDeadline(io);
    while (drive.served < quota and !expired(io, deadline)) {
        exchangeDotOnce(allocator, io, address) catch |err| {
            drive.last_error = @errorName(err);
            continue;
        };
        drive.served += 1;
    }
    return drive;
}

/// One DoH exchange over TLS: the handshake with the "http/1.1" ALPN token, a
/// GET request for /dns-query, and the DNS answer in the response body.
fn exchangeDohOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "http/1.1", true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    var packet: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet, 0x5eed, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);
    try connection_writer.interface.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    try connection_writer.interface.flush();

    const status = try takeLine(&connection_reader.interface);
    if (!std.mem.startsWith(u8, status, "HTTP/1.1 200")) return error.DohRefused;
    var content_length: usize = 0;
    while (true) {
        const line = try takeLine(&connection_reader.interface);
        if (line.len == 0) break;
        if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
            content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, line[15..], " "), 10);
        }
    }
    if (content_length == 0) return error.DohNoAnswer;
    const body = try connection_reader.interface.take(content_length);
    const message = try zimdns.dns_message.Message.parse(allocator, body);
    if (message.header.answer_count != 1) return error.DohNoAnswer;
}

/// Reads one CRLF-terminated line without the terminator.
fn takeLine(reader: *std.Io.Reader) ![]u8 {
    const line = try reader.takeDelimiterExclusive('\n');
    // takeDelimiterExclusive leaves the delimiter in the stream.
    _ = try reader.takeByte();
    if (line.len > 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}

fn driveDoh(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, quota: usize) Drive {
    var drive: Drive = .{};
    const deadline = readyDeadline(io);
    while (drive.served < quota and !expired(io, deadline)) {
        exchangeDohOnce(allocator, io, address) catch |err| {
            drive.last_error = @errorName(err);
            continue;
        };
        drive.served += 1;
    }
    return drive;
}

/// The apex SOA, the record that ends a transfer sequence.
const soa_type: @FieldType(zimdns.dns_record.ResourceRecord, "rrtype") = .SOA;

/// One zone transfer over TLS: the handshake with the "dot" ALPN token that
/// RFC 9103 section 7.1 requires, an AXFR query in the RFC 7858 framing, and
/// the transfer frames that come back.
fn exchangeXfrOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "dot", true);
    defer connection.close() catch {};
    // The transfer channel speaks "dot" and nothing else.
    const negotiated = connection.alpnProtocol() orelse return error.XfrAlpnMissing;
    if (!std.mem.eql(u8, negotiated, "dot")) return error.XfrAlpnMismatch;

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    var packet: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet, 0x5eed, "home.arpa.", .AXFR, false);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try connection_writer.interface.writeAll(&prefix);
    try connection_writer.interface.writeAll(query);
    try connection_writer.interface.flush();

    // The sequence ends with the apex SOA, so the message that carries it
    // last is the last one of the transfer.
    var frames: usize = 0;
    while (frames < 16) : (frames += 1) {
        const len_bytes = try connection_reader.interface.takeArray(2);
        const response_len = std.mem.readInt(u16, len_bytes, .big);
        const response_bytes = try connection_reader.interface.take(response_len);
        const message = try zimdns.dns_message.Message.parse(allocator, response_bytes);
        const answers = message.answers.slice();
        if (answers.len == 0) return error.XfrNoAnswer;
        if (answers[answers.len - 1].rrtype.eql(soa_type)) return;
    }
    return error.XfrIncomplete;
}

fn driveXfr(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, quota: usize) Drive {
    var drive: Drive = .{};
    const deadline = readyDeadline(io);
    while (drive.served < quota and !expired(io, deadline)) {
        exchangeXfrOnce(allocator, io, address) catch |err| {
            drive.last_error = @errorName(err);
            continue;
        };
        drive.served += 1;
    }
    return drive;
}

/// A documented `query` needs a server. The companion is the documented
/// `--once-udp` shape bound to the same per-case port; one probe query proves
/// the listener is up, and the documented query consumes the second.
fn runQuery(allocator: std.mem.Allocator, io: std.Io, case: Case, argv: []const []const u8) !bool {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{case.port});
    const companion = [_][]const u8{
        build_options.exe_path, "server",  "run",           "--zone-file", "examples/zones/home.arpa.zone",
        "--once-udp",           port_text, "--max-queries", "2",
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var out_file = try tmp.dir.createFile(io, "out", .{});
    var err_file = try tmp.dir.createFile(io, "err", .{});
    var child = try std.process.spawn(io, .{
        .argv = &companion,
        .stdin = .ignore,
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    });
    out_file.close(io);
    err_file.close(io);

    const address = std.Io.net.IpAddress{ .ip4 = .loopback(case.port) };
    const ready = driveUdp(io, address, 1);

    const result = std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline }) catch |err| {
        child.kill(io);
        _ = child.wait(io) catch {};
        report(case, null, "", @errorName(err), "query child did not terminate");
        return false;
    };

    const server_term = try child.wait(io);
    const server_stdout = try tmp.dir.readFileAlloc(io, "out", allocator, .limited(1024 * 1024));
    const server_stderr = try tmp.dir.readFileAlloc(io, "err", allocator, .limited(1024 * 1024));

    const code = exitCode(result.term);
    // `writeResponse` renders a refusal as "rcode refused / no answers", so any
    // rendered response counts. Correctness of the answer is the integration
    // suite's job, not this guard's.
    const answered = code == 0 and std.mem.trim(u8, result.stdout, " \n").len != 0;
    if (ready == 1 and answered and exitCode(server_term) == 0) return true;

    const note = if (ready == 0)
        "companion server never answered its readiness probe"
    else if (!answered)
        "query did not exit 0 with a DNS answer"
    else
        "companion server did not exit 0";
    report(case, code, result.stdout, result.stderr, note);
    if (ready == 0 or !answered) {
        printArgv("companion: " ++ build_options.exe_path ++ " ", companion[1..]);
        std.debug.print("companion stdout: {s}\ncompanion stderr: {s}\n", .{
            std.mem.trim(u8, server_stdout, " \n"), std.mem.trim(u8, server_stderr, " \n"),
        });
    }
    return false;
}

fn runRefusal(allocator: std.mem.Allocator, io: std.Io, case: Case, argv: []const []const u8) !bool {
    const result = std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline }) catch |err| {
        // The refusal is documented to happen before anything is opened, so a
        // listener that is still running at the deadline has bound its port --
        // the cleartext-on-an-encrypted-port defect this case exists for.
        report(case, null, "", @errorName(err), "the encrypted listener never refused: it kept running, which means it bound its port");
        return false;
    };

    const code = exitCode(result.term);
    const refused = code == usage_exit and case.refusal_text.len != 0 and
        std.mem.indexOf(u8, result.stdout, case.refusal_text) != null;

    // The half of the incident that matters: a refused listener must not leave
    // a socket behind serving cleartext on the encrypted port.
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(case.refuse_port) };
    const listening = blk: {
        const stream = std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp }) catch |err| switch (err) {
            error.ConnectionRefused => break :blk false,
            else => break :blk true,
        };
        stream.close(io);
        break :blk true;
    };

    if (refused and !listening) return true;
    report(case, code, result.stdout, result.stderr, if (listening)
        "refused, but a connection was accepted: a cleartext listener bound the encrypted port"
    else
        "did not refuse with the documented TLS-termination message");
    return false;
}

fn exitCode(term: std.process.Child.Term) ?u8 {
    return switch (term) {
        .exited => |code| code,
        else => null,
    };
}

fn report(case: Case, code: ?u8, stdout: []const u8, stderr: []const u8, note: []const u8) void {
    std.debug.print("\n--- documented invocation did not end in its documented outcome class\n", .{});
    printArgv("documented: zimdns ", case.documented);
    printArgv("executed:    " ++ build_options.exe_path ++ " ", case.executed);
    if (case.rewritten_config) |documented_config| std.debug.print(
        "note: the executed --config is a temporary copy of {s}, every listen endpoint moved to 127.0.0.1:{d}\n",
        .{ documented_config, case.port },
    );
    std.debug.print("outcome class: {s}, exit code: {?d}\n", .{ @tagName(case.kind), code });
    if (note.len != 0) std.debug.print("note: {s}\n", .{note});
    std.debug.print("stdout: {s}\n", .{std.mem.trim(u8, stdout, " \n")});
    std.debug.print("stderr: {s}\n", .{std.mem.trim(u8, stderr, " \n")});
}

/// Prints immediately: a returned slice would point at this frame's buffer.
fn printArgv(label: []const u8, args: []const []const u8) void {
    var buffer: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    for (args, 0..) |arg, index| {
        if (index != 0) writer.writeAll(" ") catch {};
        writer.writeAll(arg) catch {};
    }
    std.debug.print("{s}{s}\n", .{ label, writer.buffered() });
}

test "a copied configuration moves its listeners onto the per-case port" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const prefix = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{&tmp.sub_path});

    const source = try std.fmt.allocPrint(allocator, "{s}/source.gdns", .{prefix});
    const zone_data = "$ORIGIN one.example.\n$TTL 3600\n@ IN SOA ns.one.example. hostmaster.one.example. 1 3600 900 1209600 3600\n@ IN NS ns.one.example.\n";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(allocator, "{s}/one.example.zone", .{prefix}), .data = zone_data });
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = source,
        .data =
        \\# listen dns udp 192.0.2.9:53
        \\listen dns udp 0.0.0.0:1053
        \\listen dns tcp 0.0.0.0:1053
        \\zone one.example primary one.example.zone
        \\
        ,
    });

    const copy = (try rebindConfig(allocator, io, prefix, source, 21499)).?;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, copy, allocator, .limited(1024 * 1024));
    try std.testing.expect(std.mem.indexOf(u8, text, "listen dns udp 127.0.0.1:21499\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "listen dns tcp 127.0.0.1:21499\n") != null);
    // A commented listener stays a comment, and a referenced path is staged
    // beside the copy so the copy resolves it. The synthetic zone file is a
    // real file the harness anchors at the tmp prefix and copies by content.
    try std.testing.expect(std.mem.indexOf(u8, text, "# listen dns udp 192.0.2.9:53") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zone one.example primary one.example.zone\n") != null);
    const staged_zone = try std.fmt.allocPrint(allocator, "{s}/one.example.zone", .{prefix});
    const staged_text = try std.Io.Dir.cwd().readFileAlloc(io, staged_zone, allocator, .limited(1024 * 1024));
    try std.testing.expectEqualStrings(zone_data, staged_text);

    const malformed = try std.fmt.allocPrint(allocator, "{s}/malformed.gdns", .{prefix});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = malformed, .data = "listen dns udp\n" });
    try std.testing.expectError(error.UnrebindableListener, rebindConfig(allocator, io, prefix, malformed, 21499));

    // No listener at all leaves the run on the documented default port.
    const bare = try std.fmt.allocPrint(allocator, "{s}/bare.gdns", .{prefix});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = bare, .data = "zone one.example primary examples/zones/one.example.zone\n" });
    const without_listener = try rebindConfig(allocator, io, prefix, bare, 21499);
    try std.testing.expect(without_listener == null);
}
