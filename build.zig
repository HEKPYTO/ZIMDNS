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
        .name = "zimdns",
        .root_module = app_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run zimdns");
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
    golden_test_module.addImport("zimdns", b.createModule(.{
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
    config_test_module.addImport("zimdns", b.createModule(.{
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

    const fuzz_seed = b.option(u64, "fuzz-seed", "Seed for deterministic parser fuzzing") orelse 0x5eed_7a57;
    const fuzz_iterations = b.option(usize, "fuzz-iterations", "Parser fuzz iteration budget") orelse 4096;
    const fuzz_options = b.addOptions();
    fuzz_options.addOption(u64, "seed", fuzz_seed);
    fuzz_options.addOption(usize, "iterations", fuzz_iterations);

    const fuzz_test_module = b.createModule(.{
        .root_source_file = b.path("test/fuzz/fuzz_dns_parser.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_test_module.addOptions("fuzz_options", fuzz_options);
    fuzz_test_module.addImport("zimdns", b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_test_module,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    const fuzz_step = b.step("test-fuzz", "Run deterministic DNS parser fuzz tests");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    const integration_test_module = b.createModule(.{
        .root_source_file = b.path("test/integration/pipeline_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_test_module.addImport("zimdns", b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const integration_tests = b.addTest(.{
        .root_module = integration_test_module,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const integration_step = b.step("test-integration", "Run loopback DNS pipeline integration tests");
    integration_step.dependOn(&run_integration_tests.step);
}
