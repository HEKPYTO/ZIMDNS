const std = @import("std");

/// The only list of counters: each name is both the struct field and the
/// Prometheus metric name (after the `zimdns_` prefix). `Counters`,
/// `formatPrometheus`, and the tests below derive from this table.
const counter_table = [_][]const u8{
    "queries_total",
    "responses_total",
    "bad_queries_total",
    "encode_failures_total",
    "dot_queries_total",
    "doh_queries_total",
    "doh3_queries_total",
    "doq_queries_total",
    "xfr_transfers_total",
    "reserved_bit_queries_total",
    "ad_bit_queries_total",
};

/// Counters are written by every transport worker at once and read by the
/// metrics endpoint, so each one is atomic rather than guarded by a lock.
pub const Counters = struct {
    queries_total: std.atomic.Value(u64) = .init(0),
    responses_total: std.atomic.Value(u64) = .init(0),
    bad_queries_total: std.atomic.Value(u64) = .init(0),
    encode_failures_total: std.atomic.Value(u64) = .init(0),
    dot_queries_total: std.atomic.Value(u64) = .init(0),
    doh_queries_total: std.atomic.Value(u64) = .init(0),
    doh3_queries_total: std.atomic.Value(u64) = .init(0),
    doq_queries_total: std.atomic.Value(u64) = .init(0),
    xfr_transfers_total: std.atomic.Value(u64) = .init(0),
    /// Queries received with the reserved Z bit set, which RFC 1035 section
    /// 4.1.1 says must be zero in all queries and responses.
    reserved_bit_queries_total: std.atomic.Value(u64) = .init(0),
    /// Queries received with the AD bit set, which RFC 4035 section 3 says a
    /// name server must ignore in queries.
    ad_bit_queries_total: std.atomic.Value(u64) = .init(0),
};

comptime {
    if (@typeInfo(Counters).@"struct".field_names.len != counter_table.len) @compileError("counter_table and Counters disagree on the number of counters");
    for (counter_table) |name| {
        if (!@hasField(Counters, name)) @compileError("counter_table entry missing from Counters: " ++ name);
    }
}

/// Adds one to a counter. A free function keeps the call sites short: the
/// atomic's own `fetchAdd` returns the previous value, which every caller
/// would otherwise have to discard.
pub fn bump(counter: *std.atomic.Value(u64)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

/// The writer bounds the output by its content, so a new counter cannot overflow it.
pub fn formatPrometheus(counters: *const Counters, writer: *std.Io.Writer) !void {
    inline for (counter_table) |name| {
        try writer.print(
            "# TYPE zimdns_{s} counter\nzimdns_{s} {d}\n",
            .{ name, name, @field(counters, name).load(.monotonic) },
        );
    }
}

test "metrics format emits prometheus counters" {
    const values = std.StaticStringMap(u64).initComptime(.{
        .{ "queries_total", 2 },
        .{ "responses_total", 1 },
        .{ "bad_queries_total", 1 },
        .{ "reserved_bit_queries_total", 3 },
        .{ "ad_bit_queries_total", 4 },
    });
    var counters = Counters{};
    inline for (counter_table) |name| {
        if (values.get(name)) |v| @field(counters, name).store(v, .monotonic);
    }
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try formatPrometheus(&counters, &output.writer);

    var want = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer want.deinit();
    inline for (counter_table) |name| {
        const v = values.get(name) orelse 0;
        try want.writer.print(
            "# TYPE zimdns_{s} counter\nzimdns_{s} {d}\n",
            .{ name, name, v },
        );
    }
    try std.testing.expectEqualStrings(want.written(), output.written());
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "zimdns_queries_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "zimdns_ad_bit_queries_total 4\n") != null);
}

test "metrics text is not bounded by a fixed buffer" {
    // The fixed 512-byte buffer the text used to be formatted into could not
    // hold the widest counters.
    const widest = std.math.maxInt(u64);
    var counters = Counters{};
    inline for (counter_table) |name| @field(counters, name).store(widest, .monotonic);
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try formatPrometheus(&counters, &output.writer);

    const text = output.written();
    try std.testing.expect(text.len > 512);
    try std.testing.expect(std.mem.count(u8, text, "\n") == 2 * counter_table.len);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_queries_total 18446744073709551615\n") != null);
}
