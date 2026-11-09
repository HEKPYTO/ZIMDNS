const std = @import("std");
const fuzz_options = @import("fuzz_options");
const zimdns = @import("zimdns");
const message = zimdns.dns_message;
const name = zimdns.dns_name;
const zone = zimdns.zone_parser;
const config = zimdns.config_parser;
const blocklist = zimdns.blocklist;
const rdata = zimdns.dns_rdata;
const tsig = zimdns.dns_tsig;
const types = zimdns.dns_types;

const HarnessError = error{
    UnexpectedMessageError,
    UnexpectedNameError,
    UnexpectedZoneError,
    UnexpectedConfigError,
    UnexpectedBlocklistError,
    UnexpectedRdataError,
    UnexpectedTsigError,
    UnexpectedEdnsError,
    CoverageGap,
};

// Every typed RDATA branch in RData.parse plus one unimplemented code for the
// RFC 3597 else branch. The guard test asserts each of these was attempted.
const targeted_types = [_]types.RecordType{
    types.RecordType.A,
    types.RecordType.AAAA,
    types.RecordType.NS,
    types.RecordType.CNAME,
    types.RecordType.DNAME,
    types.RecordType.PTR,
    types.RecordType.SOA,
    types.RecordType.MX,
    types.RecordType.RT,
    types.RecordType.RP,
    types.RecordType.AFSDB,
    types.RecordType.X25,
    types.RecordType.ISDN,
    types.RecordType.HINFO,
    types.RecordType.SRV,
    types.RecordType.NAPTR,
    types.RecordType.APL,
    types.RecordType.TXT,
    types.RecordType.CAA,
    types.RecordType.SSHFP,
    types.RecordType.TLSA,
    types.RecordType.URI,
    types.RecordType.SVCB,
    types.RecordType.HTTPS,
    types.RecordType.OPT,
    types.RecordType.TSIG,
    types.RecordType.ZONEMD,
    .{ .value = 65001 },
};

var attempted_rdata: [targeted_types.len]bool = undefined;
fn markAllUnattempted() void {
    for (&attempted_rdata) |*slot| slot.* = false;
}
var attempted_tsig: bool = false;
var attempted_edns: bool = false;
var attempted_svcb: bool = false;
var attempted_find_option: bool = false;

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

test "fuzz driver attempts every targeted entry point" {
    markAllUnattempted();
    // Runs after the fuzz test in file order; each fuzzRdata/fuzzTsig/fuzzEdns
    // helper sets its flag unconditionally, so removing a helper call from
    // fuzzInput leaves its flag false and fails here.
    var prng = std.Random.DefaultPrng.init(fuzz_options.seed);
    const random = prng.random();
    var input: [max_input_len]u8 = undefined;
    const input_len = random.uintLessThan(usize, input.len + 1);
    random.bytes(input[0..input_len]);
    try fuzzInput(input[0..input_len]);

    for (targeted_types, 0..) |rrtype, i| {
        if (!attempted_rdata[i]) {
            std.debug.print("coverage gap: RDATA type {d} never attempted\n", .{rrtype.code()});
            return HarnessError.CoverageGap;
        }
    }
    if (!attempted_tsig) return HarnessError.CoverageGap;
    if (!attempted_edns) return HarnessError.CoverageGap;
    if (!attempted_svcb) return HarnessError.CoverageGap;
    if (!attempted_find_option) return HarnessError.CoverageGap;
}

fn fuzzInput(input: []const u8) HarnessError!void {
    fuzzMessage(input) catch return HarnessError.UnexpectedMessageError;
    fuzzName(input) catch return HarnessError.UnexpectedNameError;
    fuzzZone(input) catch return HarnessError.UnexpectedZoneError;
    fuzzConfig(input) catch return HarnessError.UnexpectedConfigError;
    fuzzBlocklist(input) catch return HarnessError.UnexpectedBlocklistError;
    fuzzRdata(input) catch return HarnessError.UnexpectedRdataError;
    fuzzTsig(input) catch return HarnessError.UnexpectedTsigError;
    fuzzEdns(input) catch return HarnessError.UnexpectedEdnsError;
}

fn fuzzMessage(input: []const u8) !void {
    var storage: [max_allocator_bytes]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&storage);
    var parsed = message.Message.parse(allocator.allocator(), input) catch |err| switch (err) {
        error.EndOfInput,
        error.ResponseNotQuery,
        error.UnsupportedQuestionCount,
        error.TooManyQuestions,
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
    var parsed = config.Config.parse(input) catch |err| switch (err) {
        error.UnknownDirective,
        error.BadDirective,
        error.BadPort,
        error.BadAddress,
        error.BadCidr,
        error.BadNat64Prefix,
        error.BadExcludedRange,
        error.TextTooLong,
        error.TooManyItems,
        error.OutOfMemory,
        => return,
    };
    parsed.deinit();
}

fn fuzzBlocklist(input: []const u8) !void {
    _ = blocklist.Blocklist.parse(input) catch |err| switch (err) {
        error.TextTooLong,
        error.TooManyEntries,
        => return,
    };
}

fn fuzzRdata(input: []const u8) rdata.Error!void {
    for (targeted_types, 0..) |rrtype, i| {
        attempted_rdata[i] = true;
        _ = rdata.RData.parse(rrtype, input, 0, input.len) catch |err| switch (err) {
            error.EndOfInput,
            error.InvalidLength,
            error.TrailingData,
            error.TextTooLong,
            error.UnknownTooLong,
            error.BadName,
            error.MalformedOption,
            error.MalformedEcsOption,
            error.OptionsTooLong,
            => continue,
        };
    }
}

fn fuzzTsig(input: []const u8) tsig.Error!void {
    attempted_tsig = true;
    _ = tsig.parseFinalAdditional(input) catch |err| switch (err) {
        error.EndOfInput,
        error.InvalidClass,
        error.InvalidTtl,
        error.TsigNotFinal,
        error.MalformedTsig,
        error.Formerr,
        error.UnsupportedAlgorithm,
        error.BadMac,
        error.InvalidPriorMac,
        error.InvalidOriginalId,
        => return,
    };
}

fn fuzzEdns(input: []const u8) rdata.Error!void {
    attempted_edns = true;
    rdata.validateEdnsOptions(input, false) catch |err| switch (err) {
        error.EndOfInput,
        error.InvalidLength,
        error.TrailingData,
        error.TextTooLong,
        error.UnknownTooLong,
        error.BadName,
        error.MalformedOption,
        error.MalformedEcsOption,
        error.OptionsTooLong,
        => {},
    };

    attempted_svcb = true;
    const priority: u16 = if (input.len >= 2) std.mem.readInt(u16, input[0..2], .big) else 0;
    rdata.validateSvcParams(input, priority) catch |err| switch (err) {
        error.EndOfInput,
        error.InvalidLength,
        error.TrailingData,
        error.TextTooLong,
        error.UnknownTooLong,
        error.BadName,
        error.MalformedOption,
        error.MalformedEcsOption,
        error.OptionsTooLong,
        => {},
    };

    attempted_find_option = true;
    _ = rdata.findOption(input, 8);
}
