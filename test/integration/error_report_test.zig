/// Contract: the authoritative side of RFC 9567 — the Report-Channel option
/// in an answer and the monitoring agent's answers — proven on a real
/// loopback socket.
/// Ownership: one arena owns the parsed responses; the runtime owns the zone.
/// Errors: a failed exchange or a mismatched answer fails the test.
const std = @import("std");
const zimdns = @import("zimdns");

const cli_query = zimdns.cli_query;
const listener = zimdns.listener;
const Runtime = zimdns.auth_runtime.Runtime;
const dns_name = zimdns.dns_name;
const dns_rdata = zimdns.dns_rdata;

/// The zone the server is authoritative for. It holds no report name, so the
/// monitoring agent's answer is the one under test.
const fixture_zone =
    \\$ORIGIN example.net.
    \\$TTL 3600
    \\@ IN SOA ns1.example.net. hostmaster.example.net. 2026053001 3600 900 1209600 3600
    \\@ IN NS ns1.example.net.
    \\ns1 IN A 192.168.1.1
    \\www IN A 192.168.1.1
    \\
;

/// RFC 9567 section 5: the agent domain the Report-Channel option names.
const agent_domain = "a01.agent-domain.example.";

/// RFC 9567 section 6.3: the agent domain the monitoring agent watches.
const monitored_domain = "agent.example.net.";

/// RFC 9567 section 6.1.1: the report query name of a failed A lookup of
/// "broken.test." with the extended DNS error code 7, under the monitored
/// agent domain: the "_er" label, the QTYPE, the labels of the failed name,
/// the error code, the "_er" label again, and the agent domain.
const report_query_name = "_er.1.broken.test.7._er.agent.example.net.";

/// The number of times an EDNS(0) option code appears in an option list.
fn countOption(options: []const u8, code: u16) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (offset + 4 <= options.len) {
        const option_code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const option_len = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        if (option_len > options.len - offset - 4) break;
        if (option_code == code) count += 1;
        offset += 4 + option_len;
    }
    return count;
}

test "RFC 9567: the authoritative answer carries the Report-Channel option" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.report_agent = try dns_name.Name.fromText(agent_domain);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    // Hand-built query: A for www.example.net. plus an OPT record with no
    // option in it, so the answer's OPT holds the Report-Channel option and
    // nothing else.
    const query = &[_]u8{
        0x43, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'n',  'e',  't',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
        0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);
    try std.testing.expect(response.header.qr);
    // The answer is the zone's own answer, not a refusal: the option rides
    // with an authoritative answer.
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    // Section 5: the option carries the agent domain as an uncompressed
    // domain name, which is the name's wire form.
    const agent = try dns_name.Name.fromText(agent_domain);
    var found = false;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        found = true;
        const options = record.rdata.OPT.bytes();
        // RFC 9567 section 6.2: the option appears at most once.
        try std.testing.expectEqual(@as(usize, 1), countOption(options, dns_rdata.EDNS_REPORT_CHANNEL_OPTION_CODE));
        try std.testing.expectEqualSlices(
            u8,
            agent.asWire(),
            dns_rdata.findOption(options, dns_rdata.EDNS_REPORT_CHANNEL_OPTION_CODE).?,
        );
    }
    try std.testing.expect(found);

    // RFC 6891 sections 6.1.1 and 7: a query that carried no OPT record is
    // answered with no OPT record, so the option has nowhere to ride.
    var plain_buffer: [512]u8 = undefined;
    const plain_query = try cli_query.buildQueryPacket(&plain_buffer, 0x4302, "www.example.net.", .A, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, plain_query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var plain_response_buffer: [512]u8 = undefined;
    const plain_response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &plain_response_buffer, &server_socket.address, plain_query, false);
    try std.testing.expect(plain_response.edns == null);
    for (plain_response.additionals.slice()) |record| {
        try std.testing.expect(!record.rrtype.eql(.OPT));
    }
}

test "RFC 9567: the monitoring agent answers a report query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.report_monitor = try dns_name.Name.fromText(monitored_domain);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4303, report_query_name, .TXT, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);

    // RFC 9567 section 6.3: the report query is answered with NOERROR, by the
    // server that holds the zone.
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expect(response.header.authoritative);
    // One TXT record, owned by the queried name.
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    const answer = response.answers.items[0];
    try std.testing.expect(answer.rrtype.eql(.TXT));
    var owner_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings(report_query_name, try answer.owner.toText(&owner_text));
    try std.testing.expectEqual(@as(u32, 60), answer.ttl);
    // The report itself is in the query name, so the record only says what it
    // is.
    try std.testing.expectEqualStrings("RFC 9567 error report", answer.rdata.TXT.text());
    // Section 6.3: a monitoring agent answers a UDP query that carries no DNS
    // Cookie with the truncation bit set, so the reporting resolver requeries
    // over TCP.
    try std.testing.expect(response.header.truncated);
}

test "RFC 9567: the monitoring agent never denies a monitored name" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(fixture_zone);
    defer runtime.deinit();
    runtime.answer_policy.report_monitor = try dns_name.Name.fromText(monitored_domain);

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    // A name at or below the monitored domain that is not a report query.
    var query_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&query_buffer, 0x4304, "nothing.agent.example.net.", .TXT, false);
    try cli_query.sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var response_buffer: [512]u8 = undefined;
    const response = try cli_query.receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query, false);

    // RFC 9567 section 8.2: a name at or below a monitored domain is never a
    // name error, because a resolver that cached the name error treats
    // everything below that domain as unreachable and the reports stop
    // arriving.
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .no_error), response.header.rcode);
    try std.testing.expect(response.header.rcode != .nxdomain);
    try std.testing.expectEqual(@as(usize, 0), response.answers.len);
    // The zone's SOA rides in the authority section, so the negative answer is
    // cacheable with the zone's own negative TTL.
    try std.testing.expectEqual(@as(usize, 1), response.authorities.len);
    try std.testing.expect(response.authorities.items[0].rrtype.eql(.SOA));
}
