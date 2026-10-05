/// Contract: Answers the locally served DNS zones of RFC 6303, RFC 7793,
/// RFC 6761, and RFC 8375 from one comptime table. There is no zone store, no
/// zone parser, and no per-query state: the caller owns the message allocator.
/// Ownership: Every apex returned here is a comptime string constant and every
/// record is appended into the caller's arena-backed sections, so answering one
/// query under the Runtime lock performs no allocation of its own.
/// Errors: Message construction failures only; no file or socket I/O occurs.
const std = @import("std");
const dns_message = @import("dns/message.zig");
const dns_name = @import("dns/name.zig");
const dns_record = @import("dns/record.zig");
const dns_question = @import("dns/question.zig");
const dns_types = @import("dns/types.zig");

/// RFC 6303 section 3 example empty zone, verbatim:
///   @ 10800 IN SOA @ nobody.invalid. 1 3600 1200 604800 10800
///   @ 10800 IN NS @
/// MNAME is the zone name and RNAME is nobody.invalid. (RFC 2606), the NS
/// target is the zone name with no address records, and the record TTL and the
/// SOA MINIMUM both carry the same 3-hour negative TTL.
pub const RECORD_TTL: u32 = 10800;
const SOA_SERIAL: u32 = 1;
const SOA_REFRESH: u32 = 3600;
const SOA_RETRY: u32 = 1200;
const SOA_EXPIRE: u32 = 604800;
const SOA_RNAME = "nobody.invalid.";
/// RFC 6761 section 6.3 item 1: localhost names resolve to the IP loopback
/// address.
const LOOPBACK_V4 = [_]u8{ 127, 0, 0, 1 };
const LOOPBACK_V6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

/// RFC 6303 section 4.3 prints these two names wrapped mid-name, so they are
/// built from the nibble count instead of retyped. An IPv6 reverse name is the
/// address nibbles in reverse order (RFC 3596 section 2.5), so the zones for
/// :: and ::1 are 32 zeros and a 1 followed by 31 zeros.
fn ipv6ReverseZone(comptime first: u8) []const u8 {
    comptime {
        var text: []const u8 = if (first == '0') "0" else "1";
        var nibble: usize = 1;
        while (nibble < 32) : (nibble += 1) text = text ++ ".0";
        return text ++ ".ip6.arpa.";
    }
}

const ipv6_unspecified_zone = ipv6ReverseZone('0');
const ipv6_loopback_zone = ipv6ReverseZone('1');
/// RFC 8375 section 4.4 B carves one question out of the RFC 6303 section 3
/// rule for home.arpa: a DS question carrying DO must be forwarded so the
/// delegation's own denial can be proved.
pub const HOME_ARPA = "home.arpa.";

/// Locally served zones answered as an empty authoritative zone: RFC 6303
/// section 4.1 (RFC 1918), 4.2 (RFC 5735/5737), 4.3 (IPv6 :: and ::1), 4.4
/// (RFC 4193 D.F), 4.5 (IPv6 link-local), 4.6 (RFC 3849 example prefix), the
/// RFC 7793 section 2.1 shared-address-space additions, and home.arpa from
/// RFC 8375 section 4.4 B. Space-separated so a match is one token compare.
/// The two 32-nibble IPv6 names are built from the nibble count above, because
/// the RFC table wraps them mid-name.
pub const empty_zone_text =
    // RFC 6303 section 4.1
    "10.in-addr.arpa. 16.172.in-addr.arpa. 17.172.in-addr.arpa. 18.172.in-addr.arpa. " ++
    "19.172.in-addr.arpa. 20.172.in-addr.arpa. 21.172.in-addr.arpa. 22.172.in-addr.arpa. " ++
    "23.172.in-addr.arpa. 24.172.in-addr.arpa. 25.172.in-addr.arpa. 26.172.in-addr.arpa. " ++
    "27.172.in-addr.arpa. 28.172.in-addr.arpa. 29.172.in-addr.arpa. 30.172.in-addr.arpa. " ++
    "31.172.in-addr.arpa. 168.192.in-addr.arpa. " ++
    // RFC 6303 section 4.2
    "0.in-addr.arpa. 127.in-addr.arpa. 254.169.in-addr.arpa. 2.0.192.in-addr.arpa. " ++
    "100.51.198.in-addr.arpa. 113.0.203.in-addr.arpa. 255.255.255.255.in-addr.arpa. " ++
    // RFC 6303 section 4.3, the 32-nibble reverse zones of :: and ::1
    ipv6_unspecified_zone ++ " " ++ ipv6_loopback_zone ++ " " ++
    // RFC 6303 section 4.4 (RFC 4193) and 4.5 (IPv6 link-local)
    "d.f.ip6.arpa. 8.e.f.ip6.arpa. 9.e.f.ip6.arpa. a.e.f.ip6.arpa. b.e.f.ip6.arpa. " ++
    // RFC 6303 section 4.6 (RFC 3849 example prefix) and RFC 8375
    "8.b.d.0.1.0.0.2.ip6.arpa. " ++ HOME_ARPA ++ " " ++
    // RFC 7793 section 2.1: the 64 reverse zones of 100.64.0.0/10
    "64.100.in-addr.arpa. 65.100.in-addr.arpa. 66.100.in-addr.arpa. 67.100.in-addr.arpa. " ++
    "68.100.in-addr.arpa. 69.100.in-addr.arpa. 70.100.in-addr.arpa. 71.100.in-addr.arpa. " ++
    "72.100.in-addr.arpa. 73.100.in-addr.arpa. 74.100.in-addr.arpa. 75.100.in-addr.arpa. " ++
    "76.100.in-addr.arpa. 77.100.in-addr.arpa. 78.100.in-addr.arpa. 79.100.in-addr.arpa. " ++
    "80.100.in-addr.arpa. 81.100.in-addr.arpa. 82.100.in-addr.arpa. 83.100.in-addr.arpa. " ++
    "84.100.in-addr.arpa. 85.100.in-addr.arpa. 86.100.in-addr.arpa. 87.100.in-addr.arpa. " ++
    "88.100.in-addr.arpa. 89.100.in-addr.arpa. 90.100.in-addr.arpa. 91.100.in-addr.arpa. " ++
    "92.100.in-addr.arpa. 93.100.in-addr.arpa. 94.100.in-addr.arpa. 95.100.in-addr.arpa. " ++
    "96.100.in-addr.arpa. 97.100.in-addr.arpa. 98.100.in-addr.arpa. 99.100.in-addr.arpa. " ++
    "100.100.in-addr.arpa. 101.100.in-addr.arpa. 102.100.in-addr.arpa. 103.100.in-addr.arpa. " ++
    "104.100.in-addr.arpa. 105.100.in-addr.arpa. 106.100.in-addr.arpa. 107.100.in-addr.arpa. " ++
    "108.100.in-addr.arpa. 109.100.in-addr.arpa. 110.100.in-addr.arpa. 111.100.in-addr.arpa. " ++
    "112.100.in-addr.arpa. 113.100.in-addr.arpa. 114.100.in-addr.arpa. 115.100.in-addr.arpa. " ++
    "116.100.in-addr.arpa. 117.100.in-addr.arpa. 118.100.in-addr.arpa. 119.100.in-addr.arpa. " ++
    "120.100.in-addr.arpa. 121.100.in-addr.arpa. 122.100.in-addr.arpa. 123.100.in-addr.arpa. " ++
    "124.100.in-addr.arpa. 125.100.in-addr.arpa. 126.100.in-addr.arpa. 127.100.in-addr.arpa.";

/// RFC 6761 section 6.4 ("invalid.") demands NXDOMAIN for every query, and
/// section 6.2 ("test.") demands an immediate negative response for every
/// query, so these two skip the RFC 6303 section 3 apex exception entirely.
pub const nxdomain_zone_text = "test. invalid.";

/// RFC 6761 section 6.3: address questions resolve to the IP loopback address
/// and every other question type gets an immediate negative response.
pub const loopback_zone_text = "localhost.";

pub const Kind = enum {
    /// RFC 6303 section 3 empty zone: NXDOMAIN below the apex, SOA/NS/NODATA
    /// at the apex.
    empty_zone,
    /// RFC 6761 sections 6.2 and 6.4: NXDOMAIN for every question.
    nxdomain,
    /// RFC 6761 section 6.3: loopback address answers, negative otherwise.
    loopback,
};

pub const Zone = struct {
    /// Enclosing zone apex in lowercase presentation form with its trailing
    /// dot. Borrows the query's own name text, never a copy.
    apex: []const u8,
    kind: Kind,
    /// True when the question is for the apex itself rather than a name below.
    is_apex: bool,
};

/// Returns the innermost locally served zone containing `qname`, which must be
/// lowercase and carry its trailing dot. Suffixes are tried longest first on
/// label boundaries only, so `1.2.0.192.in-addr.arpa.` reports the enclosing
/// `2.0.192.in-addr.arpa.` and never the non-zone `0.192.in-addr.arpa.`.
pub fn match(qname: []const u8) ?Zone {
    var start: usize = 0;
    while (start < qname.len) {
        const suffix = qname[start..];
        const kind = kindOf(suffix) orelse {
            const dot = std.mem.indexOfScalarPos(u8, qname, start, '.') orelse break;
            start = dot + 1;
            continue;
        };
        return .{ .apex = suffix, .kind = kind, .is_apex = start == 0 };
    }
    return null;
}

fn kindOf(suffix: []const u8) ?Kind {
    if (contains(empty_zone_text, suffix)) return .empty_zone;
    if (contains(nxdomain_zone_text, suffix)) return .nxdomain;
    if (contains(loopback_zone_text, suffix)) return .loopback;
    return null;
}

/// RFC 8375 section 4.4 B: a DS question carrying DO is the one `home.arpa.`
/// question that must still be forwarded. Returns false only for that case,
/// so every other question is answered locally.
pub fn forwardsUpstream(zone: Zone, qtype: dns_types.RecordType, dnssec_ok: bool) bool {
    return zone.kind == .empty_zone and
        std.mem.eql(u8, zone.apex, HOME_ARPA) and
        qtype.eql(.DS) and
        dnssec_ok;
}

pub fn build(request: dns_message.Message, zone: Zone) !dns_message.Message {
    const q = request.question orelse return error.MissingQuestion;
    const apex = dns_name.Name.fromText(zone.apex) catch return error.BadZoneName;
    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .opcode = request.header.opcode,
            .authoritative = true,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (request.edns) |edns| .{
            .udp_payload_size = negotiatePayload(edns.udp_payload_size),
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer response.deinit();
    if (response.edns != null) try appendOpt(&response);
    try fill(&response, q, apex, zone);
    try setHeaderCounts(&response);
    return response;
}

fn fill(
    response: *dns_message.Message,
    q: dns_question.Question,
    apex: dns_name.Name,
    zone: Zone,
) !void {
    switch (zone.kind) {
        .nxdomain => {
            // RFC 6761 sections 6.2 and 6.4 name no apex exception, so even the
            // zone name itself is NXDOMAIN. The SOA carries the negative TTL.
            response.header.rcode = .nxdomain;
            try response.authorities.append(soaRecord(apex));
        },
        .loopback => {
            // RFC 6761 section 6.3 item 3: address questions get the IP
            // loopback address, every other type a negative response. The
            // answer owner is the question name because item 3 covers
            // "localhost names", not only the zone apex.
            if (q.qtype.eql(.A)) {
                try response.answers.append(.{
                    .owner = q.name,
                    .rrtype = .A,
                    .class = dns_types.Class.IN,
                    .ttl = RECORD_TTL,
                    .rdata = .{ .A = LOOPBACK_V4 },
                });
            } else if (q.qtype.eql(.AAAA)) {
                try response.answers.append(.{
                    .owner = q.name,
                    .rrtype = .AAAA,
                    .class = dns_types.Class.IN,
                    .ttl = RECORD_TTL,
                    .rdata = .{ .AAAA = LOOPBACK_V6 },
                });
            }
        },
        .empty_zone => {
            if (!zone.is_apex) {
                // RFC 6303 section 3: authoritatively NXDOMAIN inside the zone.
                response.header.rcode = .nxdomain;
                try response.authorities.append(soaRecord(apex));
                return;
            }
            // RFC 6303 section 3: at the zone name itself, answer SOA and NS
            // questions and give a "no data" answer for anything else.
            if (q.qtype.eql(.SOA)) {
                try response.answers.append(soaRecord(apex));
                try response.authorities.append(nsRecord(apex));
            } else if (q.qtype.eql(.NS)) {
                try response.answers.append(nsRecord(apex));
                try response.authorities.append(soaRecord(apex));
            } else {
                try response.authorities.append(soaRecord(apex));
                try response.authorities.append(nsRecord(apex));
            }
        },
    }
}

fn soaRecord(apex: dns_name.Name) dns_record.ResourceRecord {
    return .{
        .owner = apex,
        .rrtype = .SOA,
        .class = dns_types.Class.IN,
        .ttl = RECORD_TTL,
        .rdata = .{ .SOA = .{
            .mname = apex,
            .rname = dns_name.Name.fromText(SOA_RNAME) catch unreachable,
            .serial = SOA_SERIAL,
            .refresh = SOA_REFRESH,
            .retry = SOA_RETRY,
            .expire = SOA_EXPIRE,
            .minimum = RECORD_TTL,
        } },
    };
}

fn nsRecord(apex: dns_name.Name) dns_record.ResourceRecord {
    return .{
        .owner = apex,
        .rrtype = .NS,
        .class = dns_types.Class.IN,
        .ttl = RECORD_TTL,
        .rdata = .{ .NS = apex },
    };
}

fn negotiatePayload(advertised: u16) u16 {
    if (advertised < dns_message.CLASSIC_UDP_PAYLOAD_SIZE) return dns_message.CLASSIC_UDP_PAYLOAD_SIZE;
    return @min(advertised, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
}

fn appendOpt(message: *dns_message.Message) !void {
    const edns = message.edns orelse return;
    try message.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(edns.udp_payload_size),
        .ttl = (@as(u32, edns.extended_rcode) << 24) |
            (@as(u32, edns.version) << 16) |
            (if (edns.dnssec_ok) @as(u32, 0x8000) else 0),
        .rdata = .{ .OPT = .{} },
    });
}

fn setHeaderCounts(response: *dns_message.Message) !void {
    const max_count = @as(usize, std.math.maxInt(u16));
    if (response.answers.len > max_count or response.authorities.len > max_count or response.additionals.len > max_count) {
        return error.TooManyRecords;
    }
    response.header.answer_count = @intCast(response.answers.len);
    response.header.authority_count = @intCast(response.authorities.len);
    response.header.additional_count = @intCast(response.additionals.len);
}

/// Exact token match: `token` counts only where it is delimited by spaces, so
/// `0.in-addr.arpa.` never matches inside `10.in-addr.arpa.`.
fn contains(haystack: []const u8, token: []const u8) bool {
    var rest = haystack;
    while (std.mem.indexOf(u8, rest, token)) |at| {
        const opens = at == 0 or rest[at - 1] == ' ';
        const closes = at + token.len == rest.len or rest[at + token.len] == ' ';
        if (opens and closes) return true;
        rest = rest[at + 1 ..];
    }
    return false;
}

test "zone table carries every RFC 6303, RFC 7793, RFC 6761, and RFC 8375 entry" {
    // RFC 6303 section 4.1, the RFC 1918 reverse zones.
    const rfc1918 = [_][]const u8{
        "10.in-addr.arpa.",     "16.172.in-addr.arpa.", "17.172.in-addr.arpa.",
        "18.172.in-addr.arpa.", "19.172.in-addr.arpa.", "20.172.in-addr.arpa.",
        "21.172.in-addr.arpa.", "22.172.in-addr.arpa.", "23.172.in-addr.arpa.",
        "24.172.in-addr.arpa.", "25.172.in-addr.arpa.", "26.172.in-addr.arpa.",
        "27.172.in-addr.arpa.", "28.172.in-addr.arpa.", "29.172.in-addr.arpa.",
        "30.172.in-addr.arpa.", "31.172.in-addr.arpa.", "168.192.in-addr.arpa.",
    };

    // RFC 6303 section 4.2, RFC 5735 and RFC 5737.
    const special_v4 = [_][]const u8{
        "0.in-addr.arpa.",               "127.in-addr.arpa.",        "254.169.in-addr.arpa.",
        "2.0.192.in-addr.arpa.",         "100.51.198.in-addr.arpa.", "113.0.203.in-addr.arpa.",
        "255.255.255.255.in-addr.arpa.",
    };

    // RFC 6303 sections 4.3 to 4.6 and RFC 4193 section 3.

    const special_v6 = [_][]const u8{
        "d.f.ip6.arpa.",
        "8.e.f.ip6.arpa.",
        "9.e.f.ip6.arpa.",
        "a.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
        "8.b.d.0.1.0.0.2.ip6.arpa.",
    };

    // RFC 8375 section 4.4 B and RFC 7793 section 2.1 endpoints; the loop below
    // covers the rest of 100.64.0.0/10.
    for ([_][]const u8{ HOME_ARPA, "64.100.in-addr.arpa.", "127.100.in-addr.arpa." }) |name| {
        const zone = match(name) orelse return error.MissingZone;
        try std.testing.expectEqualStrings(name, zone.apex);
        try std.testing.expect(zone.is_apex);
        try std.testing.expectEqual(Kind.empty_zone, zone.kind);
    }

    for (rfc1918 ++ special_v4 ++ special_v6) |name| {
        const zone = match(name) orelse return error.MissingZone;
        try std.testing.expectEqualStrings(name, zone.apex);
        try std.testing.expect(zone.is_apex);
        try std.testing.expectEqual(Kind.empty_zone, zone.kind);
    }

    // Every 100.64.0.0/10 reverse zone is present, not only the endpoints.
    var octet: u32 = 64;
    while (octet <= 127) : (octet += 1) {
        var buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "{d}.100.in-addr.arpa.", .{octet});
        try std.testing.expect(match(name) != null);
    }
}
test "RFC 6303 section 4.3 zones hold exactly the 32 nibbles of :: and ::1" {
    // The RFC table wraps these names mid-name, so the expected strings are
    // built from the nibble count the RFC requires rather than copied from the
    // zone table, which is the only place a wrong count could hide.
    var unspecified_buffer: [128]u8 = undefined;
    var loopback_buffer: [128]u8 = undefined;
    const unspecified = try std.fmt.bufPrint(&unspecified_buffer, "0{s}.ip6.arpa.", .{".0" ** 31});
    const loopback = try std.fmt.bufPrint(&loopback_buffer, "1{s}.ip6.arpa.", .{".0" ** 31});
    for ([_][]const u8{ unspecified, loopback }) |name| {
        const zone = match(name) orelse return error.MissingZone;
        try std.testing.expectEqualStrings(name, zone.apex);
        try std.testing.expect(zone.is_apex);
        const nibbles = name[0 .. name.len - ".ip6.arpa.".len];
        try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, nibbles, ".") + 1);
    }
    // A 31-nibble name is a different, unregistered name and must not match.
    var short_buffer: [128]u8 = undefined;
    const short = try std.fmt.bufPrint(&short_buffer, "1{s}.ip6.arpa.", .{".0" ** 30});
    try std.testing.expect(match(short) == null);
}

test "RFC 6761 names use their own treatments and never a nearby zone" {
    try std.testing.expectEqual(Kind.nxdomain, (match("test.") orelse return error.MissingZone).kind);
    try std.testing.expectEqual(Kind.nxdomain, (match("invalid.") orelse return error.MissingZone).kind);
    try std.testing.expectEqual(Kind.loopback, (match("localhost.") orelse return error.MissingZone).kind);
    try std.testing.expectEqual(Kind.nxdomain, (match("host.example.test.") orelse return error.MissingZone).kind);
    // RFC 6761 section 6.3 covers "any names falling within .localhost.".
    const below = match("db.localhost.") orelse return error.MissingZone;
    try std.testing.expectEqual(Kind.loopback, below.kind);
    try std.testing.expectEqualStrings("localhost.", below.apex);

    // RFC 6761 section 6.5 requires example names to resolve normally, so no
    // example name may be claimed.
    for ([_][]const u8{ "example.", "example.com.", "example.net.", "example.org.", "www.example.com." }) |name| {
        try std.testing.expect(match(name) == null);
    }
}

test "matching walks label boundaries and reports the enclosing apex" {
    const below = match("137.10.in-addr.arpa.") orelse return error.MissingZone;
    try std.testing.expectEqualStrings("10.in-addr.arpa.", below.apex);
    try std.testing.expect(!below.is_apex);

    const test_net = match("1.2.0.192.in-addr.arpa.") orelse return error.MissingZone;
    try std.testing.expectEqualStrings("2.0.192.in-addr.arpa.", test_net.apex);

    const broadcast = match("255.255.255.255.in-addr.arpa.") orelse return error.MissingZone;
    try std.testing.expectEqualStrings("255.255.255.255.in-addr.arpa.", broadcast.apex);
    try std.testing.expect(broadcast.is_apex);

    // The 32-nibble reverse name of fd00::3, which sits below d.f.ip6.arpa.
    var unique_buffer: [128]u8 = undefined;
    const unique_name = try std.fmt.bufPrint(&unique_buffer, "3{s}.d.f.ip6.arpa.", .{".0" ** 29});
    const unique_local = match(unique_name) orelse return error.MissingZone;
    try std.testing.expectEqualStrings("d.f.ip6.arpa.", unique_local.apex);
    try std.testing.expectEqual(@as(usize, 32), std.mem.count(u8, unique_name, ".") - 2);

    // A label that merely ends in a zone token is outside every zone.
    for ([_][]const u8{
        "example.com.",     "0.192.in-addr.arpa.", "163.100.in-addr.arpa.", "63.100.in-addr.arpa.",
        "11.in-addr.arpa.", "notlocalhost.",       "testing.",              "8.b.d.0.1.0.0.3.ip6.arpa.",
        ".",
    }) |name| {
        try std.testing.expect(match(name) == null);
    }
}

test "only the RFC 8375 DS question with DO set is forwarded" {
    const home = match(HOME_ARPA) orelse return error.MissingZone;
    try std.testing.expect(forwardsUpstream(home, .DS, true));
    try std.testing.expect(!forwardsUpstream(home, .DS, false));
    try std.testing.expect(!forwardsUpstream(home, .A, true));

    const private = match("10.in-addr.arpa.") orelse return error.MissingZone;
    try std.testing.expect(!forwardsUpstream(private, .DS, true));
    // RFC 8375 section 4.4 B covers home.arpa and its subdomains.
    try std.testing.expect(forwardsUpstream(match("a.home.arpa.") orelse return error.MissingZone, .DS, true));
}

test "RFC 6303 section 3 empty zone: NXDOMAIN below the apex, SOA/NS/NODATA at it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const below = try roundTrip(arena.allocator(), "1.2.3.10.in-addr.arpa.", .A);
    // No address records for the nameserver are emitted (RFC 6303 section 3).
    try std.testing.expectEqual(@as(u16, 0), below.header.additional_count);
    try std.testing.expect(below.header.authoritative);
    try std.testing.expectEqual(@as(@TypeOf(below.header.rcode), .nxdomain), below.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), below.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), below.header.authority_count);
    try expectZoneSoa(below.authorities.items[0], "10.in-addr.arpa.");

    const apex_soa = try roundTrip(arena.allocator(), "10.in-addr.arpa.", .SOA);
    try std.testing.expectEqual(@as(@TypeOf(apex_soa.header.rcode), .no_error), apex_soa.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), apex_soa.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), apex_soa.header.authority_count);
    try expectZoneSoa(apex_soa.answers.items[0], "10.in-addr.arpa.");
    try expectZoneNs(apex_soa.authorities.items[0], "10.in-addr.arpa.");

    const apex_ns = try roundTrip(arena.allocator(), "10.in-addr.arpa.", .NS);
    try std.testing.expectEqual(@as(u16, 1), apex_ns.header.answer_count);
    try expectZoneNs(apex_ns.answers.items[0], "10.in-addr.arpa.");
    try expectZoneSoa(apex_ns.authorities.items[0], "10.in-addr.arpa.");

    // "no data" at the zone name itself: no answer, SOA plus NS authority.
    const apex_a = try roundTrip(arena.allocator(), "10.in-addr.arpa.", .A);
    try std.testing.expectEqual(@as(@TypeOf(apex_a.header.rcode), .no_error), apex_a.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), apex_a.header.answer_count);
    try std.testing.expectEqual(@as(u16, 2), apex_a.header.authority_count);
    try expectZoneSoa(apex_a.authorities.items[0], "10.in-addr.arpa.");
    try expectZoneNs(apex_a.authorities.items[1], "10.in-addr.arpa.");
}

test "RFC 6761 test. and invalid. are NXDOMAIN even at the zone name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const probes = [_]struct { qname: []const u8, apex: []const u8 }{
        .{ .qname = "test.", .apex = "test." },
        .{ .qname = "host.example.test.", .apex = "test." },
        .{ .qname = "invalid.", .apex = "invalid." },
        .{ .qname = "nope.invalid.", .apex = "invalid." },
    };
    for (probes) |probe| {
        const response = try roundTrip(arena.allocator(), probe.qname, .SOA);
        try std.testing.expect(response.header.authoritative);
        try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .nxdomain), response.header.rcode);
        try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
        try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);
        try expectZoneSoa(response.authorities.items[0], probe.apex);
    }
}

test "RFC 6761 localhost. answers the IP loopback address and nothing else" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const v4 = try roundTrip(arena.allocator(), "localhost.", .A);
    try std.testing.expectEqual(@as(u16, 1), v4.header.answer_count);
    try std.testing.expectEqual(@as(@TypeOf(v4.header.rcode), .no_error), v4.header.rcode);
    try std.testing.expectEqualSlices(u8, &LOOPBACK_V4, &v4.answers.items[0].rdata.A);
    try expectOwner(v4.answers.items[0], "localhost.");

    const v6 = try roundTrip(arena.allocator(), "localhost.", .AAAA);
    try std.testing.expectEqual(@as(u16, 1), v6.header.answer_count);
    try std.testing.expectEqualSlices(u8, &LOOPBACK_V6, &v6.answers.items[0].rdata.AAAA);

    // Item 3 covers "localhost names", so a name below the zone answers too.
    const below = try roundTrip(arena.allocator(), "db.localhost.", .A);
    try std.testing.expectEqual(@as(u16, 1), below.header.answer_count);
    try std.testing.expectEqualSlices(u8, &LOOPBACK_V4, &below.answers.items[0].rdata.A);
    try expectOwner(below.answers.items[0], "db.localhost.");

    const other = try roundTrip(arena.allocator(), "localhost.", .MX);
    try std.testing.expectEqual(@as(u16, 0), other.header.answer_count);
    try std.testing.expectEqual(@as(@TypeOf(other.header.rcode), .no_error), other.header.rcode);
}

fn roundTrip(allocator: std.mem.Allocator, name: []const u8, qtype: dns_types.RecordType) !dns_message.Message {
    var request = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x4242, .recursion_desired = true },
        .question = .{
            .name = try dns_name.Name.fromText(name),
            .qtype = qtype,
            .qclass = dns_types.Class.IN,
        },
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
    };
    errdefer request.deinit();
    const zone = match(name) orelse return error.MissingZone;
    var response = try build(request, zone);
    defer response.deinit();
    var bytes: [1024]u8 = undefined;
    var writer = @import("dns/writer.zig").Writer.init(&bytes);
    try response.encode(&writer);
    return dns_message.Message.parse(allocator, writer.written());
}

fn expectZoneSoa(record: dns_record.ResourceRecord, apex: []const u8) !void {
    try std.testing.expect(record.rrtype.eql(.SOA));
    try expectOwner(record, apex);
    try std.testing.expectEqual(RECORD_TTL, record.ttl);
    var mname_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(apex, try record.rdata.SOA.mname.toText(&mname_buffer));
    var rname_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings("nobody.invalid.", try record.rdata.SOA.rname.toText(&rname_buffer));
    // The SOA TTL and MINIMUM both carry the negative TTL (RFC 6303 section 3).
    try std.testing.expectEqual(RECORD_TTL, record.rdata.SOA.minimum);
}

fn expectZoneNs(record: dns_record.ResourceRecord, apex: []const u8) !void {
    try std.testing.expect(record.rrtype.eql(.NS));
    try expectOwner(record, apex);
    try std.testing.expectEqual(RECORD_TTL, record.ttl);
    var target_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(apex, try record.rdata.NS.toText(&target_buffer));
}

fn expectOwner(record: dns_record.ResourceRecord, expected: []const u8) !void {
    var owner_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(expected, try record.owner.toText(&owner_buffer));
}
