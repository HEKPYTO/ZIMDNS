pub const Counters = struct {
    queries_total: u64 = 0,
    responses_total: u64 = 0,
    bad_queries_total: u64 = 0,
    encode_failures_total: u64 = 0,
    dot_queries_total: u64 = 0,
    doh_queries_total: u64 = 0,
    xfr_transfers_total: u64 = 0,
};

const std = @import("std");

pub fn formatPrometheus(counters: Counters, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer,
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
        \\
    , .{
        counters.queries_total,
        counters.responses_total,
        counters.bad_queries_total,
        counters.encode_failures_total,
        counters.dot_queries_total,
        counters.doh_queries_total,
        counters.xfr_transfers_total,
    });
}

test "metrics format emits prometheus counters" {
    const counters = Counters{
        .queries_total = 2,
        .responses_total = 1,
        .bad_queries_total = 1,
        .encode_failures_total = 0,
    };
    var buffer: [512]u8 = undefined;
    const text = try formatPrometheus(counters, &buffer);

    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_queries_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_responses_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_bad_queries_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_encode_failures_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_dot_queries_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_doh_queries_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zimdns_xfr_transfers_total 0\n") != null);
}
