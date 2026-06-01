pub const Counters = struct {
    queries_total: u64 = 0,
    responses_total: u64 = 0,
    bad_queries_total: u64 = 0,
    encode_failures_total: u64 = 0,
};

const std = @import("std");

pub fn formatPrometheus(counters: Counters, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer,
        \\# TYPE gcli_dns_queries_total counter
        \\gcli_dns_queries_total {d}
        \\# TYPE gcli_dns_responses_total counter
        \\gcli_dns_responses_total {d}
        \\# TYPE gcli_dns_bad_queries_total counter
        \\gcli_dns_bad_queries_total {d}
        \\# TYPE gcli_dns_encode_failures_total counter
        \\gcli_dns_encode_failures_total {d}
        \\
    , .{
        counters.queries_total,
        counters.responses_total,
        counters.bad_queries_total,
        counters.encode_failures_total,
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

    try std.testing.expect(std.mem.indexOf(u8, text, "gcli_dns_queries_total 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "gcli_dns_responses_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "gcli_dns_bad_queries_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "gcli_dns_encode_failures_total 0\n") != null);
}
