const std = @import("std");

extern fn ngtcp2_version(age: c_int, version_num: [*c]c_int) ?[*:0]const u8;
extern fn nghttp3_version(age: c_int, version_num: [*c]c_int) ?[*:0]const u8;
extern fn gnutls_check_version(req_version: ?[*:0]const u8) ?[*:0]const u8;

test "ngtcp2, nghttp3 and gnutls link" {
    var num: c_int = 0;
    const ngtcp2 = ngtcp2_version(0, &num) orelse return error.Ngtcp2VersionNull;
    try std.testing.expect(std.mem.len(ngtcp2) > 0);

    const nghttp3 = nghttp3_version(0, &num) orelse return error.Nghttp3VersionNull;
    try std.testing.expect(std.mem.len(nghttp3) > 0);

    const gnutls = gnutls_check_version(null) orelse return error.GnuTlsVersionNull;
    try std.testing.expect(std.mem.len(gnutls) > 0);
}
