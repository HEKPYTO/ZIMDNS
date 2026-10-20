const std = @import("std");
const zimdns = @import("zimdns");

const Runtime = zimdns.auth_runtime.Runtime;
const auth_keyring = zimdns.auth_keyring;
const dns_message = zimdns.dns_message;
const dns_name = zimdns.dns_name;
const dns_rdata = zimdns.dns_rdata;
const dns_record = zimdns.dns_record;
const dns_tsig = zimdns.dns_tsig;
const dns_writer = zimdns.dns_writer;

const secret = "0123456789012345678901234567890123456789012345678901234567890123";
const secret_base64 = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==";

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2026053001 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\ns1 IN A 192.168.1.1
    \\dns IN A 192.168.1.1
;

const SignedQuery = struct {
    bytes: [512]u8,
    len: usize,
    mac_offset: usize,
};

fn buildSignedQuery(time_signed: u64, algorithm: []const u8) !SignedQuery {
    const algorithm_name = try dns_name.Name.fromText(algorithm);
    const owner = try dns_name.Name.fromText("key.");
    var packet: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&packet);
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try writer.writeBytes(&.{ 3, 'd', 'n', 's', 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    var zeros: [64]u8 = @splat(0);
    const digest_len = dns_tsig.digestLength(try dns_tsig.algorithmForName(&algorithm_name));
    const value = try dns_rdata.Tsig.init(algorithm_name, time_signed, 300, zeros[0..digest_len], 0x1234, 0, &.{});
    try (dns_record.ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(&writer);
    const final = (try dns_tsig.parseFinalAdditional(writer.written())).?;
    const signed = try dns_tsig.sign(writer.written(), secret, final.owner, final.tsig, null);
    try dns_tsig.patchMac(packet[0..writer.len()], final, signed.slice());
    return .{
        .bytes = packet,
        .len = writer.len(),
        .mac_offset = final.rdata_start + final.tsig.algorithm.asWire().len + 10,
    };
}

test "an hmac-sha512 request authenticates and the answer is signed with hmac-sha512" {
    var keyring = try auth_keyring.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha512; secret \"" ++ secret_base64 ++ "\"; };",
    );
    var runtime = try Runtime.fromZoneTextWithKeyring(test_zone, &keyring);
    defer runtime.deinit();
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    var query = try buildSignedQuery(now, "hmac-sha512.");
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.bytes[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    const request_final = (try dns_tsig.parseFinalAdditional(query.bytes[0..query.len])).?;
    const response_final = (try dns_tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 0), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 64), response_final.tsig.macBytes().len);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hmac-sha512.", try response_final.tsig.algorithm.toText(&text));

    // RFC 8945 section 5.3: the answer is signed with the request MAC as the
    // prior MAC, so the client verifies the reply the same way. The expected
    // bytes come from an independent HMAC over the section 4.3 digest input.
    const verified = try dns_tsig.verify(response_bytes, secret, request_final.tsig.macBytes(), 64);
    try std.testing.expectEqualSlices(u8, response_final.tsig.macBytes(), verified.slice());
    try std.testing.expectEqualSlices(u8, &.{
        0xcf, 0x46, 0x0a, 0x47, 0x14, 0xef, 0x47, 0x83, 0x5b, 0xc4, 0x12, 0x5c, 0x44, 0xdc, 0x93, 0x7c,
        0x52, 0xfd, 0x88, 0x57, 0x88, 0xaa, 0x16, 0xd2, 0x1d, 0xf9, 0x17, 0x6b, 0x6f, 0x30, 0x82, 0xf1,
        0xf8, 0x27, 0xdc, 0xf7, 0x83, 0x81, 0x81, 0x3a, 0xa7, 0x77, 0x63, 0x8d, 0x35, 0x43, 0x59, 0x0a,
        0x4c, 0x05, 0x50, 0x0f, 0x10, 0xdf, 0xfd, 0xcf, 0xd4, 0xf1, 0x4a, 0xc6, 0xf5, 0x29, 0xd7, 0x58,
    }, verified.slice());
}

test "an hmac-sha512 request with an altered MAC is refused" {
    var keyring = try auth_keyring.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha512; secret \"" ++ secret_base64 ++ "\"; };",
    );
    var runtime = try Runtime.fromZoneTextWithKeyring(test_zone, &keyring);
    defer runtime.deinit();
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    var query = try buildSignedQuery(now, "hmac-sha512.");
    query.bytes[query.mac_offset] ^= 0xff;
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.bytes[0..query.len], &output);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .notauth), response.header.rcode);
    const response_final = (try dns_tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 16), response_final.tsig.error_code);
    try std.testing.expectEqual(@as(usize, 0), response_final.tsig.macBytes().len);
}

test "a request signed with another algorithm than the key names is refused" {
    var keyring = try auth_keyring.Keyring.parse(
        "key \"key.\" { algorithm hmac-sha512; secret \"" ++ secret_base64 ++ "\"; };",
    );
    var runtime = try Runtime.fromZoneTextWithKeyring(test_zone, &keyring);
    defer runtime.deinit();
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    const query = try buildSignedQuery(now, "hmac-sha256.");
    var output: [1024]u8 = undefined;
    const response_bytes = try runtime.answer(query.bytes[0..query.len], &output);

    const response_final = (try dns_tsig.parseFinalAdditional(response_bytes)).?;
    try std.testing.expectEqual(@as(u16, 17), response_final.tsig.error_code);
}
