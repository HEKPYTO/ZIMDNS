const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const app_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "gcli-dns",
        .root_module = app_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run gcli-dns");
    run_step.dependOn(&run_cmd.step);

    const unit_test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{
        .root_module = unit_test_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const golden_test_module = b.createModule(.{
        .root_source_file = b.path("test/golden/golden_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    golden_test_module.addImport("gcli_dns", b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const golden_tests = b.addTest(.{
        .root_module = golden_test_module,
    });
    const run_golden_tests = b.addRunArtifact(golden_tests);

    const golden_step = b.step("test-golden", "Run DNS wire-format golden tests");
    golden_step.dependOn(&run_golden_tests.step);

    const config_test_module = b.createModule(.{
        .root_source_file = b.path("test/config/config_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    config_test_module.addImport("gcli_dns", b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const config_tests = b.addTest(.{
        .root_module = config_test_module,
    });
    const run_config_tests = b.addRunArtifact(config_tests);

    const config_step = b.step("test-config", "Run config file integration tests");
    config_step.dependOn(&run_config_tests.step);
}
