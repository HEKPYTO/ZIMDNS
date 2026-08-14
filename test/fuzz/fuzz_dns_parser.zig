const std = @import("std");
const fuzz_options = @import("fuzz_options");
const zimdns = @import("zimdns");
const message = zimdns.dns_message;
const name = zimdns.dns_name;
const zone = zimdns.zone_parser;
const config = zimdns.config_parser;
const blocklist = zimdns.blocklist;

const HarnessError = error{
    UnexpectedMessageError,
    UnexpectedNameError,
    UnexpectedZoneError,
    UnexpectedConfigError,
    UnexpectedBlocklistError,
};

const max_input_len = 512;
const max_allocator_bytes = 64 * 1024;

test "deterministic parser fuzz accepts typed errors only" {
    var prng = std.Random.DefaultPrng.init(fuzz_options.seed);
    const random = prng.random();
    var input: [max_input_len]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < fuzz_options.iterations) : (iteration += 1) {
        const input_len = random.uintLessThan(usize, input.len + 1);
        random.bytes(input[0..input_len]);

        fuzzInput(input[0..input_len]) catch |err| {
            std.debug.print("fuzz seed=0x{x} iteration={d} error={s}\n", .{
                fuzz_options.seed,
                iteration,
                @errorName(err),
            });
            return err;
        };
    }
}

fn fuzzInput(input: []const u8) HarnessError!void {
    fuzzMessage(input) catch return HarnessError.UnexpectedMessageError;
    fuzzName(input) catch return HarnessError.UnexpectedNameError;
    fuzzZone(input) catch return HarnessError.UnexpectedZoneError;
    fuzzConfig(input) catch return HarnessError.UnexpectedConfigError;
    fuzzBlocklist(input) catch return HarnessError.UnexpectedBlocklistError;
}

fn fuzzMessage(input: []const u8) !void {
    var storage: [max_allocator_bytes]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&storage);
    var parsed = message.Message.parse(allocator.allocator(), input) catch |err| switch (err) {
        error.EndOfInput,
        error.ResponseNotQuery,
        error.UnsupportedQuestionCount,
        error.BadRecord,
        error.AllocationBudgetExceeded,
        error.TrailingData,
        error.MalformedEdnsOption,
        error.MalformedEcsOption,
        error.EdnsOptionsTooLong,
        error.MultipleOptRecords,
        error.InvalidOptOwner,
        error.OutOfMemory,
        => return,
    };
    defer parsed.deinit();
}

fn fuzzName(input: []const u8) !void {
    _ = name.Name.parse(input, 0) catch |err| switch (err) {
        error.EndOfInput,
        error.LabelTooLong,
        error.NameTooLong,
        error.ReservedLabelBits,
        error.PointerOutOfBounds,
        error.PointerLoop,
        error.NonTerminalPointer,
        error.OutputTooSmall,
        => return,
    };

    _ = name.Name.fromText(input) catch |err| switch (err) {
        error.EndOfInput,
        error.LabelTooLong,
        error.NameTooLong,
        error.ReservedLabelBits,
        error.PointerOutOfBounds,
        error.PointerLoop,
        error.NonTerminalPointer,
        error.OutputTooSmall,
        => return,
    };
}

fn fuzzZone(input: []const u8) !void {
    var parsed = zone.ZoneFile.parse(input) catch |err| switch (err) {
        error.MissingOrigin,
        error.MissingTtl,
        error.MissingSoa,
        error.MissingApexNs,
        error.MultipleApexSoa,
        error.SoaNotAtApex,
        error.CnameConflict,
        error.AllocationBudgetExceeded,
        error.BadDirective,
        error.BadRecord,
        error.BadTtl,
        error.BadName,
        error.OutOfMemory,
        => return,
    };
    defer parsed.deinit();
}

fn fuzzConfig(input: []const u8) !void {
    _ = config.Config.parse(input) catch |err| switch (err) {
        error.UnknownDirective,
        error.BadDirective,
        error.BadPort,
        error.BadAddress,
        error.BadCidr,
        error.TextTooLong,
        error.TooManyItems,
        => return,
    };
}

fn fuzzBlocklist(input: []const u8) !void {
    _ = blocklist.Blocklist.parse(input) catch |err| switch (err) {
        error.TextTooLong,
        error.TooManyEntries,
        => return,
    };
}
