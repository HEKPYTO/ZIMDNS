const std = @import("std");

/// Counters are written by every transport worker at once and read by the
/// metrics endpoint, so each one is atomic rather than guarded by a lock.
pub const Counters = struct {
    queries_total: std.atomic.Value(u64) = .init(0),
    responses_total: std.atomic.Value(u64) = .init(0),
    bad_queries_total: std.atomic.Value(u64) = .init(0),
    encode_failures_total: std.atomic.Value(u64) = .init(0),
    dot_queries_total: std.atomic.Value(u64) = .init(0),
    doh_queries_total: std.atomic.Value(u64) = .init(0),
    doq_queries_total: std.atomic.Value(u64) = .init(0),
    xfr_transfers_total: std.atomic.Value(u64) = .init(0),
    /// Queries received with the reserved Z bit set, which RFC 1035 section
    /// 4.1.1 says must be zero in all queries and responses.
    reserved_bit_queries_total: std.atomic.Value(u64) = .init(0),
    /// Queries received with the AD bit set, which RFC 4035 section 3 says a
    /// name server must ignore in queries.
    ad_bit_queries_total: std.atomic.Value(u64) = .init(0),
};

/// Adds one to a counter. A free function keeps the call sites short: the
/// atomic's own `fetchAdd` returns the previous value, which every caller
/// would otherwise have to discard.
pub fn bump(counter: *std.atomic.Value(u64)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

/// The writer bounds the output by its content, so a new counter cannot overflow it.
pub fn formatPrometheus(counters: Counters, writer: *std.Io.Writer) !void {
    try writer.print(
        \\# TYPE zimdns_queries_total counter
        \\zimdns_queries_total {d}
        \\# TYPE zimdns_responses_total counter
        \\zimdns_responses_total {d}
        \\# TYPE zimdns_bad_queries_total counter
        \\zimdns_bad_queries_total {d}
        \\# TYPE zimdns_encode_failures_total counter
        \\zimdns_encode_failures_total {d}
        \\# TYPE zimdns_dot_queries_total counter
        \\zimdns_dot_queries_total {d}
        \\# TYPE zimdns_doh_queries_total counter
        \\zimdns_doh_queries_total {d}
        \\# TYPE zimdns_doq_queries_total counter
        \\zimdns_doq_queries_total {d}
        \\# TYPE zimdns_xfr_transfers_total counter
        \\zimdns_xfr_transfers_total {d}
        \\# TYPE zimdns_reserved_bit_queries_total counter
        \\zimdns_reserved_bit_queries_total {d}
        \\# TYPE zimdns_ad_bit_queries_total counter
        \\zimdns_ad_bit_queries_total {d}
        \\
    , .{
        counters.queries_total.load(.monotonic),
        counters.responses_total.load(.monotonic),
        counters.bad_queries_total.load(.monotonic),
        counters.encode_failures_total.load(.monotonic),
        counters.dot_queries_total.load(.monotonic),
        counters.doh_queries_total.load(.monotonic),
        counters.doq_queries_total.load(.monotonic),
        counters.xfr_transfers_total.load(.monotonic),
        counters.reserved_bit_queries_total.load(.monotonic),
        counters.ad_bit_queries_total.load(.monotonic),
    });
}

test "metrics format emits prometheus counters" {
    const counters = Counters{
        .queries_total = .init(2),
        .responses_total = .init(1),
        .bad_queries_total = .init(1),
        .encode_failures_total = .init(0),
        .reserved_bit_queries_total = .init(3),
        .ad_bit_queries_total = .init(4),
    };
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try formatPrometheus(counters, &output.writer);

    const expected =
        \\# TYPE zimdns_queries_total counter
        \\zimdns_queries_total 2
        \\# TYPE zimdns_responses_total counter
        \\zimdns_responses_total 1
        \\# TYPE zimdns_bad_queries_total counter
        \\zimdns_bad_queries_total 1
        \\# TYPE zimdns_encode_failures_total counter
        \\zimdns_encode_failures_total 0
        \\# TYPE zimdns_dot_queries_total counter
        \\zimdns_dot_queries_total 0
        \\# TYPE zimdns_doh_queries_total counter
        \\zimdns_doh_queries_total 0
        \\# TYPE zimdns_doq_queries_total counter
        \\zimdns_doq_queries_total 0
        \\# TYPE zimdns_xfr_transfers_total counter
        \\zimdns_xfr_transfers_total 0
        \\# TYPE zimdns_reserved_bit_queries_total counter
        \\zimdns_reserved_bit_queries_total 3
        \\# TYPE zimdns_ad_bit_queries_total counter
        \\zimdns_ad_bit_queries_total 4
        \\
    ;
    try std.testing.expectEqualStrings(expected, output.written());
}

test "metrics text is not bounded by a fixed buffer" {
    // The fixed 512-byte buffer the text used to be formatted into could not
    // hold the widest counters.
    const widest = std.math.maxInt(u64);
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try formatPrometheus(.{
        .queries_total = .init(widest),
        .responses_total = .init(widest),
        .bad_queries_total = .init(widest),
        .encode_failures_total = .init(widest),
        .dot_queries_total = .init(widest),
        .doh_queries_total = .init(widest),
        .doq_queries_total = .init(widest),
        .xfr_transfers_total = .init(widest),
        .reserved_bit_queries_total = .init(widest),
        .ad_bit_queries_total = .init(widest),
    }, &output.writer);

    const text = output.written();
    try std.testing.expect(text.len > 512);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_queries_total 18446744073709551615\n") != null);
}
