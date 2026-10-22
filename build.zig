const std = @import("std");

// A test root is test/<group>/<name>_test.zig, with <group> one of unit,
// golden, config, fuzz, integration, cli. Roots are discovered, so a new test
// file needs no edit here; a file that does not end in _test.zig is a
// fixture, and a root outside a group directory fails the build.
//
//   unit         -> test               golden -> test-golden
//   config       -> test-config        fuzz   -> test-fuzz
//   integration  -> test-integration   cli    -> test-cli

/// The options module a group's roots import next to "zimdns".
const Extra = enum {
    /// No options module, like the unit, golden, config and integration roots.
    none,
    /// "fuzz_options" with the seed and the iteration budget.
    fuzz,
    /// "build_options" with the version string and the executable path.
    cli,
};

const Group = struct {
    /// Directory under test/ holding the group's roots.
    dir: []const u8,
    /// Build step that runs them.
    step: []const u8,
    /// Description of that step.
    desc: []const u8,
    /// Options module the group's roots import.
    extra: Extra,
};

const groups = [_]Group{
    .{ .dir = "unit", .step = "test", .desc = "Run unit tests", .extra = .none },
    .{ .dir = "golden", .step = "test-golden", .desc = "Run DNS wire-format golden tests", .extra = .none },
    .{ .dir = "config", .step = "test-config", .desc = "Run config file integration tests", .extra = .none },
    .{ .dir = "fuzz", .step = "test-fuzz", .desc = "Run deterministic DNS parser fuzz tests", .extra = .fuzz },
    .{ .dir = "integration", .step = "test-integration", .desc = "Run loopback DNS pipeline integration tests", .extra = .none },
    .{ .dir = "cli", .step = "test-cli", .desc = "Run every invocation documented in --help and examples/", .extra = .cli },
};

/// The known group names, for error messages.
const group_names = blk: {
    var names: []const u8 = "";
    for (groups, 0..) |group, i| {
        names = names ++ (if (i == 0) "" else ", ") ++ group.dir;
    }
    break :blk names;
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Single source of truth for `zimdns --version`; override with -Dversion=x.y.z.
    const version = b.option([]const u8, "version", "Version string reported by --version") orelse "0.1.0";
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    // The DNS-over-TLS server: inic/tls.zig, pinned to one commit in
    // build.zig.zon. Its module is named "tls".
    const tls_dep = b.dependency("tls", .{ .target = target, .optimize = optimize });
    const tls_module = tls_dep.module("tls");

    const app_module = mainModule(b, target, optimize, build_options, tls_module);

    const exe = b.addExecutable(.{
        .name = "zimdns",
        .root_module = app_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    // Zig 0.17 removed `b.args`; `zig build run` takes no extra args.
    // Invoke the binary directly for CLI arguments.
    const run_step = b.step("run", "Run zimdns");
    run_step.dependOn(&run_cmd.step);

    const fuzz_seed = b.option(u64, "fuzz-seed", "Seed for deterministic parser fuzzing") orelse 0x5eed_7a57;
    const fuzz_iterations = b.option(usize, "fuzz-iterations", "Parser fuzz iteration budget") orelse 4096;
    const fuzz_options = b.addOptions();
    fuzz_options.addOption(u64, "seed", fuzz_seed);
    fuzz_options.addOption(usize, "iterations", fuzz_iterations);

    // The documented-CLI guard runs the built binary, so it needs the emitted
    // artifact path and a working directory at the project root, where the
    // example paths in --help resolve.
    const cli_options = b.addOptions();
    cli_options.addOption([]const u8, "version", version);
    cli_options.addOptionPath("exe_path", exe.getEmittedBin());

    var group_steps: [groups.len]*std.Build.Step = undefined;
    for (groups, 0..) |group, i| group_steps[i] = b.step(group.step, group.desc);

    // groups[0] is the unit group: the unit tests embedded in src/main.zig
    // stay the root module of the main test artifact and share that step.
    const unit_test_module = mainModule(b, target, optimize, build_options, tls_module);
    const unit_tests = b.addTest(.{
        .root_module = unit_test_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    group_steps[0].dependOn(&run_unit_tests.step);

    // One test artifact per discovered root, wired to its group's step.
    const roots = discoverTestRoots(b);
    for (groups, roots, group_steps) |group, group_roots, group_step| {
        for (group_roots) |root| {
            const module = b.createModule(.{
                .root_source_file = b.path(root),
                .target = target,
                .optimize = optimize,
            });
            module.addImport("zimdns", mainModule(b, target, optimize, build_options, tls_module));
            switch (group.extra) {
                .none => {},
                .fuzz => module.addOptions("fuzz_options", fuzz_options),
                .cli => module.addOptions("build_options", cli_options),
            }
            const tests = b.addTest(.{
                .root_module = module,
            });
            const run = b.addRunArtifact(tests);
            if (group.extra == .cli) run.setCwd(b.path("."));
            group_step.dependOn(&run.step);
        }
    }
}

/// Every artifact above compiles `src/main.zig`, so the build options it reads
/// are attached here once instead of at every call site.
fn mainModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, build_options: *std.Build.Step.Options, tls_module: *std.Build.Module) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addOptions("build_options", build_options);
    module.addImport("tls", tls_module);
    return module;
}

/// The test roots under test/, one list per group, in directory order.
fn discoverTestRoots(b: *std.Build) [groups.len][]const []const u8 {
    const arena = b.allocator;
    var lists: [groups.len]std.ArrayList([]const u8) = @splat(.empty);

    const io = b.graph.io;
    const test_dir = b.root.openDir(io, "test", .{ .iterate = true }) catch |err| {
        std.process.fatal("cannot open the test directory: {t}", .{err});
    };
    defer test_dir.close(io);

    // A root added later must be picked up without a build.zig edit, so the
    // configure phase is repeated when the test tree changes.
    b.dependOnDirectoryContents(b.path("test"));

    scanTestDir(b, test_dir, "test", null, 0, &lists);

    var roots: [groups.len][]const []const u8 = undefined;
    for (&lists, 0..) |*list, i| {
        roots[i] = list.toOwnedSlice(arena) catch @panic("OOM");
    }
    return roots;
}

/// Collects the test roots of one directory, recursing into sub-directories.
/// `rel` is the path of `dir` relative to the build root, `group` the name of
/// the group directory holding it, and `depth` the distance below test/.
fn scanTestDir(b: *std.Build, dir: std.Io.Dir, rel: []const u8, group: ?[]const u8, depth: usize, lists: *[groups.len]std.ArrayList([]const u8)) void {
    const io = b.graph.io;
    const arena = b.allocator;
    var it = dir.iterate();
    while (it.next(io) catch |err| {
        std.process.fatal("cannot read the test directory {s}: {t}", .{ rel, err });
    }) |entry| {
        if (entry.kind == .directory) {
            // A file added to a group directory later must repeat the
            // configure phase, or the discovery result would go stale.
            if (depth == 0) {
                const path = joinPath(arena, &.{ "test", entry.name }) catch @panic("OOM");
                b.dependOnDirectoryContents(b.path(path));
            }
            const child_rel = joinPath(arena, &.{ rel, entry.name }) catch @panic("OOM");
            const child = dir.openDir(io, entry.name, .{ .iterate = true }) catch |err| {
                std.process.fatal("cannot open the test directory {s}: {t}", .{ child_rel, err });
            };
            defer child.close(io);
            scanTestDir(b, child, child_rel, group orelse entry.name, depth + 1, lists);
            continue;
        }
        if (!std.mem.endsWith(u8, entry.name, "_test.zig")) continue;

        // A test root must sit directly in a known group directory.
        const path = joinPath(arena, &.{ rel, entry.name }) catch @panic("OOM");
        const group_dir = group orelse {
            std.process.fatal("test root {s} must live in a group directory ({s})", .{ path, group_names });
        };
        const index = groupIndex(group_dir) orelse {
            std.process.fatal("unknown test group directory \"{s}\": expected one of {s}", .{ group_dir, group_names });
        };
        if (depth > 1) {
            std.process.fatal("test root {s} must live directly in a group directory", .{path});
        }
        lists[index].append(arena, path) catch @panic("OOM");
    }
}

/// The index of a group directory, or null when the name is not a group.
fn groupIndex(dir: []const u8) ?usize {
    for (groups, 0..) |group, i| {
        if (std.mem.eql(u8, group.dir, dir)) return i;
    }
    return null;
}

fn joinPath(arena: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    return std.mem.join(arena, "/", parts);
}
