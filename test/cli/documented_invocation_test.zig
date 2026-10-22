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
const tls = zimdns.tls;

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

const Transport = enum { udp, tcp, doh };

const Kind = enum {
    /// `--help`, `--version`: runs and exits 0.
    informational,
    /// `server run` with no mode: exits `usage_exit` without opening anything.
    usage_refusal,
    /// `--serve-dot|--serve-doh|--serve-xfr`: exits `usage_exit`, says why, and
    /// leaves its port unbound.
    encrypted_refusal,
    /// A bounded listener: must serve its quota and exit 0.
    serve,
    /// `zimdns query`: needs a server, must exit 0 with an answer.
    query,
    /// `zimdns zonemd publish`: computes the zone digest, must exit 0 with
    /// the ZONEMD record in zone text.
    zonemd,
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
    /// Flags the prose names as always refusing, which never appear as a
    /// complete invocation in the Usage block.
    refusing_flags: []const []const u8,
};

fn discover(allocator: std.mem.Allocator, io: std.Io) !Discovery {
    const help_argv = [_][]const u8{ build_options.exe_path, "--help" };
    const help = try std.process.run(allocator, io, .{ .argv = &help_argv, .timeout = child_deadline });

    var found: std.ArrayList([]const []const u8) = .empty;
    var help_count: usize = 0;
    var help_lines = std.mem.splitScalar(u8, help.stdout, '\n');
    while (help_lines.next()) |line| {
        // Only the indented `Usage:` entries are invocations; the banner line
        // starts with "zimdns " too but is prose.
        if (line.len == 0 or (line[0] != ' ' and line[0] != '\t')) continue;
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "zimdns ")) continue;
        help_count += 1;
        try appendUnique(allocator, &found, try tokenize(allocator, trimmed));
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
    var refusing: std.ArrayList([]const u8) = .empty;
    var words = std.mem.tokenizeAny(u8, help.stdout, " \t\r\n,;.");
    while (words.next()) |word| {
        if (!std.mem.startsWith(u8, word, "--serve-")) continue;
        if (argvContains(found.items, word)) continue;
        var already = false;
        for (refusing.items) |existing| {
            if (std.mem.eql(u8, existing, word)) already = true;
        }
        if (!already) try refusing.append(allocator, word);
    }

    return .{
        .invocations = try found.toOwnedSlice(allocator),
        .help_count = help_count,
        .examples_count = examples_count,
        .refusing_flags = try refusing.toOwnedSlice(allocator),
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
    for (discovered.refusing_flags) |flag| {
        try cases.append(allocator, try classifyRefusal(allocator, flag, tls_cert, tls_key));
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

        // The transports this build cannot serve refuse; `--serve-dot` is
        // served, so its refusal has to come from the identity.
        for ([_][]const u8{ "--serve-dot", "--serve-xfr" }) |flag| {
            if (hasFlag(argv, flag)) return classifyRefusal(allocator, flag, tls_cert, tls_key);
        }

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

    if (std.mem.eql(u8, argv[0], "zonemd")) {
        if (argv.len < 2 or !std.mem.eql(u8, argv[1], "publish")) return error.UndocumentedInvocation;
        return plain(argv, .zonemd, port);
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

/// The encrypted case the prose documents: the flag plus everything needed to
/// reach the TLS-termination gate, so the harness observes the real refusal
/// rather than an argument-validation stop.
fn classifyRefusal(allocator: std.mem.Allocator, flag: []const u8, tls_cert: []const u8, tls_key: []const u8) !Case {
    // The DoT port is served in this build, so its refusal has to come from
    // the identity: a certificate that is not there is the clean way to reach
    // the gate that refuses before the port is bound. The transports this
    // build cannot serve refuse on the transport itself.
    const is_dot = std.mem.eql(u8, flag, "--serve-dot");
    const cert_path = if (is_dot)
        try std.fmt.allocPrint(allocator, "{s}/absent-cert.pem", .{std.fs.path.dirname(tls_cert) orelse tls_cert})
    else
        tls_cert;
    // Arena-owned: a local array literal would dangle once this frame returns.
    const argv = [_][]const u8{
        "server",         "run",                    "--zone-file",     "examples/zones/home.arpa.zone",
        flag,             "--enable-encrypted-dns", "--tls-cert-file", cert_path,
        "--tls-key-file", tls_key,
    };
    const owned = try allocator.dupe([]const u8, argv[0..]);
    // The refusal names its own reason: the transports this build cannot
    // serve say so, and the one it can serve says which identity it could
    // not read.
    const refusal_text = if (is_dot)
        "cannot read TLS certificate file"
    else
        "has no listener in this build";
    return .{
        .documented = owned,
        .executed = owned,
        .kind = .encrypted_refusal,
        .transport = .tcp,
        .quota = 0,
        .port = documented_port,
        .refuse_port = documented_port,
        .refusal_text = refusal_text,
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

    var out: std.ArrayList(u8) = .empty;
    var listeners: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, commentless(line), " \t");
        if (!std.mem.eql(u8, words.next() orelse "", "listen")) {
            try out.appendSlice(allocator, line);
            try out.append(allocator, '\n');
            continue;
        }
        // `listen dns <transport> <endpoint>` is the one shape
        // src/config/parser.zig accepts, and the only one this rewrite knows
        // where the server will bind. A listener it cannot place fails here,
        // loudly, instead of binding somewhere the harness never looks.
        var tokens: [3][]const u8 = undefined;
        var count: usize = 0;
        while (words.next()) |word| {
            if (count == tokens.len) return error.UnrebindableListener;
            tokens[count] = word;
            count += 1;
        }
        if (count != tokens.len or !std.mem.eql(u8, tokens[0], "dns")) return error.UnrebindableListener;
        listeners += 1;
        try out.print(allocator, "listen dns {s} {s}\n", .{ tokens[1], endpoint });
    }
    if (listeners == 0) return null;

    const name = try std.fmt.allocPrint(allocator, "config-{d}.gdns", .{port});
    const copy = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tmp_prefix, name });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = copy, .data = out.items });
    return copy;
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
        .zonemd => runZonemd(allocator, io, case, argv.items),
    };
}

/// A documented `zonemd publish` must publish a digest: the record it prints
/// is the one the zone verifier accepts, so the run must end with a ZONEMD
/// record in zone text.
fn runZonemd(allocator: std.mem.Allocator, io: std.Io, case: Case, argv: []const []const u8) !bool {
    const result = std.process.run(allocator, io, .{ .argv = argv, .timeout = child_deadline }) catch |err| {
        report(case, null, "", @errorName(err), "zonemd child did not terminate");
        return false;
    };
    const code = exitCode(result.term);
    const published = code == 0 and std.mem.indexOf(u8, result.stdout, " IN ZONEMD ") != null;
    if (published) return true;
    report(case, code, result.stdout, result.stderr, "zonemd publish printed no ZONEMD record");
    return false;
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
        .doh => driveDoh(allocator, io, address, case.quota),
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

    const metrics_ok = !case.metrics or std.mem.indexOf(u8, stdout, "zimdns_queries_total") != null;
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
    var message = try cli_query.receiveTcpResponse(allocator, stream, io, &response, query);
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

/// One DoH exchange over TLS: the handshake with the "http/1.1" ALPN token, a
/// GET request for /dns-query, and the DNS answer in the response body.
fn exchangeDohOnce(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress) !void {
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var client_input: [tls.input_buffer_len]u8 = undefined;
    var client_output: [tls.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    var connection = try tls.client(&client_reader.interface, &client_writer.interface, .{
        .rng = rng_source.interface(),
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{"http/1.1"},
    });
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
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = source,
        .data =
        \\# listen dns udp 192.0.2.9:53
        \\listen dns udp 0.0.0.0:1053
        \\listen dns tcp 0.0.0.0:1053
        \\zone one.example primary examples/zones/one.example.zone
        \\
        ,
    });

    const copy = (try rebindConfig(allocator, io, prefix, source, 21499)).?;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, copy, allocator, .limited(1024 * 1024));
    try std.testing.expect(std.mem.indexOf(u8, text, "listen dns udp 127.0.0.1:21499\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "listen dns tcp 127.0.0.1:21499\n") != null);
    // A commented listener stays a comment, and every other line is untouched.
    try std.testing.expect(std.mem.indexOf(u8, text, "# listen dns udp 192.0.2.9:53") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zone one.example primary examples/zones/one.example.zone") != null);

    const malformed = try std.fmt.allocPrint(allocator, "{s}/malformed.gdns", .{prefix});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = malformed, .data = "listen dns udp\n" });
    try std.testing.expectError(error.UnrebindableListener, rebindConfig(allocator, io, prefix, malformed, 21499));

    // No listener at all leaves the run on the documented default port.
    const bare = try std.fmt.allocPrint(allocator, "{s}/bare.gdns", .{prefix});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = bare, .data = "zone one.example primary examples/zones/one.example.zone\n" });
    const without_listener = try rebindConfig(allocator, io, prefix, bare, 21499);
    try std.testing.expect(without_listener == null);
}
