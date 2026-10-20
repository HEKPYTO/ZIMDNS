pub const Counters = struct {
    queries_total: u64 = 0,
    responses_total: u64 = 0,
    bad_queries_total: u64 = 0,
    encode_failures_total: u64 = 0,
    dot_queries_total: u64 = 0,
    doh_queries_total: u64 = 0,
    xfr_transfers_total: u64 = 0,
    /// Queries received with the reserved Z bit set, which RFC 1035 section
    /// 4.1.1 says must be zero in all queries and responses.
    reserved_bit_queries_total: u64 = 0,
    /// Queries received with the AD bit set, which RFC 4035 section 3 says a
    /// name server must ignore in queries.
    ad_bit_queries_total: u64 = 0,
};

const std = @import("std");

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
        \\# TYPE zimdns_xfr_transfers_total counter
        \\zimdns_xfr_transfers_total {d}
        \\# TYPE zimdns_reserved_bit_queries_total counter
        \\zimdns_reserved_bit_queries_total {d}
        \\# TYPE zimdns_ad_bit_queries_total counter
        \\zimdns_ad_bit_queries_total {d}
        \\
    , .{
        counters.queries_total,
        counters.responses_total,
        counters.bad_queries_total,
        counters.encode_failures_total,
        counters.dot_queries_total,
        counters.doh_queries_total,
        counters.xfr_transfers_total,
        counters.reserved_bit_queries_total,
        counters.ad_bit_queries_total,
    });
}

test "metrics format emits prometheus counters" {
    const counters = Counters{
        .queries_total = 2,
        .responses_total = 1,
        .bad_queries_total = 1,
        .encode_failures_total = 0,
        .reserved_bit_queries_total = 3,
        .ad_bit_queries_total = 4,
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
        .queries_total = widest,
        .responses_total = widest,
        .bad_queries_total = widest,
        .encode_failures_total = widest,
        .dot_queries_total = widest,
        .doh_queries_total = widest,
        .xfr_transfers_total = widest,
        .reserved_bit_queries_total = widest,
        .ad_bit_queries_total = widest,
    }, &output.writer);

    const text = output.written();
    try std.testing.expect(text.len > 512);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_queries_total 18446744073709551615\n") != null);
}
