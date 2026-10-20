/// Contract: Builds authoritative DNS responses from parsed requests and one zone.
/// Ownership: Inputs and zone are borrowed; returned Message owns allocator-backed sections and requires deinit.
/// Errors: Response and wire failures are typed; network and file I/O are outside this module.
const std = @import("std");
const dns_message = @import("../dns/message.zig");
const header = @import("../dns/header.zig");
const question = @import("../dns/question.zig");
const dns_name = @import("../dns/name.zig");
const dns_record = @import("../dns/record.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_types = @import("../dns/types.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_signer = @import("../zone/signer.zig");
const dns_validate = @import("../dns/validate.zig");
const dns_dnssec = @import("../dns/dnssec.zig");

pub const CLASSIC_UDP_MESSAGE_SIZE: usize = 512;
pub const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

pub const Error = error{
    MissingQuestion,
    BadQName,
    BadZoneRecord,
    TooManyRecords,
    BadResponse,
    ResponseTooLarge,
};

/// What this server may answer an EDNS(0) request with. Both options are
/// hop-by-hop: RFC 5001 section 2.2 and RFC 9660 section 3.2.2 forbid sending
/// either to a client that did not ask, so a request for one is answered and
/// an absent request is silence.
pub const AnswerPolicy = struct {
    /// RFC 5001 section 3.1 leaves the NSID payload to the operator, so there
    /// is no default: without a configured identifier the server never answers
    /// with one.
    nsid: ?[]const u8 = null,
    /// RFC 9660 section 3.2 makes answering optional. On by default because
    /// the value is the answer's own SOA serial, with nothing to leak.
    zoneversion: bool = true,
    /// RFC 8482 section 4.2: the TTL of the synthesized HINFO in a minimal
    /// ANY answer. The RFC leaves it to the operator; a day is the default.
    minimal_any_ttl: u32 = 86400,
};

pub fn truncateClassicUdpResponse(response_bytes: []const u8, output: []u8) Error![]const u8 {
    const payload_limit = responsePayloadLimit(response_bytes);
    if (response_bytes.len <= payload_limit) {
        if (response_bytes.len > output.len) return Error.ResponseTooLarge;
        @memcpy(output[0..response_bytes.len], response_bytes);
        return output[0..response_bytes.len];
    }
    if (response_bytes.len < 12 or output.len < 12) return Error.BadResponse;

    var reader = @import("../dns/reader.zig").Reader.init(response_bytes);
    const parsed_header = header.Header.parse(&reader) catch return Error.BadResponse;
    if (parsed_header.question_count > 1) return Error.BadResponse;

    var question_end: usize = 12;
    if (parsed_header.question_count == 1) {
        const parsed_question = question.Question.parse(response_bytes, question_end) catch return Error.BadResponse;
        question_end = parsed_question.next_offset;
    }
    if (question_end > output.len) return Error.ResponseTooLarge;

    @memcpy(output[0..question_end], response_bytes[0..question_end]);
    var flags = std.mem.readInt(u16, output[2..4], .big);
    flags |= 0x0200;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    if (findEdnsOpt(response_bytes)) |opt| {
        std.mem.writeInt(u16, output[10..12], 1, .big);
        opt.encode(&writer) catch return Error.ResponseTooLarge;
    } else {
        std.mem.writeInt(u16, output[10..12], 0, .big);
    }
    return writer.written();
}

/// Truncate a signed response while retaining its final TSIG RR.
/// The caller must recompute the response MAC after this wire-level rewrite.
pub fn truncateSignedClassicUdpResponse(response_bytes: []const u8, output: []u8) Error![]const u8 {
    const payload_limit = responsePayloadLimit(response_bytes);
    if (response_bytes.len <= payload_limit) {
        if (response_bytes.len > output.len) return Error.ResponseTooLarge;
        @memcpy(output[0..response_bytes.len], response_bytes);
        return output[0..response_bytes.len];
    }
    if (response_bytes.len < 12 or output.len < 12) return Error.BadResponse;

    const final = (@import("../dns/tsig.zig").parseFinalAdditional(response_bytes) catch return Error.BadResponse) orelse return Error.BadResponse;
    var reader = @import("../dns/reader.zig").Reader.init(response_bytes);
    const parsed_header = header.Header.parse(&reader) catch return Error.BadResponse;
    if (parsed_header.question_count > 1) return Error.BadResponse;

    var question_end: usize = 12;
    if (parsed_header.question_count == 1) {
        const parsed_question = question.Question.parse(response_bytes, question_end) catch return Error.BadResponse;
        question_end = parsed_question.next_offset;
    }
    if (question_end > output.len) return Error.ResponseTooLarge;

    @memcpy(output[0..question_end], response_bytes[0..question_end]);
    var flags = std.mem.readInt(u16, output[2..4], .big);
    flags = (flags | 0x0200) & 0xfff0;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);

    std.mem.writeInt(u16, output[10..12], 1, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    writer.writeBytes(response_bytes[final.record_start..final.record_end]) catch return Error.ResponseTooLarge;
    if (writer.len() > payload_limit) return Error.ResponseTooLarge;
    return writer.written();
}

fn responsePayloadLimit(response_bytes: []const u8) usize {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), response_bytes) catch return CLASSIC_UDP_MESSAGE_SIZE;
    if (parsed.edns) |edns| return @max(CLASSIC_UDP_MESSAGE_SIZE, @as(usize, edns.udp_payload_size));
    return CLASSIC_UDP_MESSAGE_SIZE;
}

fn findEdnsOpt(response_bytes: []const u8) ?dns_record.ResourceRecord {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = dns_message.Message.parse(arena.allocator(), response_bytes) catch return null;
    for (parsed.additionals.slice()) |record| {
        if (record.rrtype.eql(.OPT)) return record;
    }
    return null;
}

/// Answer from the shipping default EDNS policy: no NSID identifier to give
/// and ZONEVERSION answered whenever a query asks for it.
pub fn buildResponse(request: dns_message.Message, zone: *const zone_index.Zone) !dns_message.Message {
    return buildResponseWithPolicy(request, zone, .{});
}

/// `policy` is the operator's EDNS answer policy, from the `nsid` and
/// `zoneversion` directives.
pub fn buildResponseWithPolicy(request: dns_message.Message, zone: *const zone_index.Zone, policy: AnswerPolicy) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    if (request.header.opcode != .query) return buildNotImplementedResponse(request);
    if (!q.qclass.eql(dns_types.Class.IN)) return buildEmptyResponse(request, q, .notimp);
    if (request.edns) |edns| {
        if (edns.version != dns_message.EDNS_VERSION) {
            return buildBadVersionResponse(request, q);
        }
    }
    // RFC 9660 section 3.2.1: a ZONEVERSION option is empty in a query and
    // appears at most once. A server that understands the option answers
    // FORMERR to anything else rather than ignoring it.
    if (zoneversionIsMalformed(&request)) return buildFormerrResponse(request);
    var qname_text_buffer: [256]u8 = undefined;
    const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQName;
    var lookup = zone.lookup(request.allocator, qname_text, q.qtype);
    defer lookup.deinit(request.allocator);

    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .authoritative = lookup.kind != .not_authoritative and lookup.kind != .referral and lookup.kind != .servfail,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            // RFC 4035 section 3.2: the CD bit of the query is copied into
            // the response.
            .checking_disabled = request.header.checking_disabled,
            .rcode = switch (lookup.kind) {
                .nxdomain => .nxdomain,
                .yxdomain => .yxdomain,
                .servfail => .servfail,
                .not_authoritative => .refused,
                else => .no_error,
            },
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (request.edns) |edns| .{
            .udp_payload_size = negotiateEdnsPayload(edns.udp_payload_size),
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer response.deinit();

    if (response.edns != null) {
        try appendOpt(&response);
        appendRequestedEdnsOptions(&response, &request, zone, policy);
    }

    switch (lookup.kind) {
        .answer, .cname, .dname, .yxdomain => {
            var index: usize = 0;
            while (index < lookup.records.len) : (index += 1) {
                try response.answers.append(try toResourceRecord(lookup.records.items[index], lookup.answer_owner));
            }
            if (lookup.synthesized_cname) |synthetic| {
                try response.answers.append(synthesizedCnameRecord(synthetic));
            }
        },
        .referral => {
            var index: usize = 0;
            while (index < lookup.authorities.len) : (index += 1) {
                try response.authorities.append(try toResourceRecord(lookup.authorities.items[index], null));
            }
            index = 0;
            while (index < lookup.additionals.len) : (index += 1) {
                try response.additionals.append(try toResourceRecord(lookup.additionals.items[index], null));
            }
        },
        .nodata, .nxdomain => {
            const alias_chain = lookup.records.len != 0 or lookup.synthesized_cname != null;
            // RFC 8482 section 4.2: an ANY query at an existing owner with no
            // CNAME gets one synthesized HINFO instead of the conventional
            // all-RRsets answer, which unmodified resolvers cache and reuse.
            // An empty non-terminal has no RRset to summarize so it keeps
            // NODATA, and an alias chain keeps its own denial below.
            const minimal_any = !alias_chain and
                q.qtype.eql(dns_types.RecordType.ANY) and
                zone.hasOwner(qname_text);
            if (minimal_any) {
                try response.answers.append(anyMinimalAnswer(q.name, policy.minimal_any_ttl));
            } else {
                // RFC 8020 section 2 Warning: a denial reached through a CNAME
                // or DNAME chain is for the last name of the chain, so the
                // alias records ride in the answer and the SOA in the
                // authority section carries the negative TTL.
                var index: usize = 0;
                while (index < lookup.records.len) : (index += 1) {
                    try response.answers.append(try toResourceRecord(lookup.records.items[index], lookup.answer_owner));
                }
                if (lookup.synthesized_cname) |synthetic| try response.answers.append(synthesizedCnameRecord(synthetic));
                if (lookup.soa) |soa| try response.authorities.append(try toNegativeSoa(soa));
            }
        },

        .servfail, .not_authoritative => {},
    }

    // DNSSEC minimum (RFC 4035 section 3.1, RFC 5155): RRSIGs covering the
    // answer RRsets and NSEC/NSEC3 denial proofs ride along only when the
    // query set DO=1; without DO, proof RRsets are stripped unless the
    // QTYPE asked for them explicitly. The AD bit is never set here: the
    // authoritative path does not validate (validation lives on the
    // forwarding path in `src/dns/validate.zig`).
    const dnssec_ok = if (request.edns) |edns| edns.dnssec_ok else false;
    if (dnssec_ok) {
        appendCoveringRrsigs(&response, zone, q.qtype, lookup.answer_owner) catch {};
        if (lookup.kind == .nodata or lookup.kind == .nxdomain) {
            appendDenialProofs(&response, zone, qname_text, q.qtype) catch {};
        }
    } else {
        dns_dnssec.stripProofRecords(&response, q.qtype);
    }

    try setHeaderCounts(&response);
    return response;
}

/// Synthesized CNAME that a DNAME substitution adds after the DNAME itself.
fn synthesizedCnameRecord(synthetic: zone_index.SynthesizedCname) dns_record.ResourceRecord {
    return .{
        .owner = synthetic.owner,
        .rrtype = .CNAME,
        .class = dns_types.Class.IN,
        .ttl = synthetic.ttl,
        .rdata = .{ .CNAME = synthetic.target },
    };
}

/// RFC 8482 section 4.2 minimal ANY answer: one HINFO whose CPU field is
/// "RFC8482" and whose OS field is the null string, so the response stays as
/// small as possible. Its TTL is the operator's choice (RFC 8482 section 4.2);
/// the AnswerPolicy carries it, defaulting to a day.
const hinfo_type: dns_types.RecordType = .{ .value = 13 };

fn anyMinimalAnswer(owner: dns_name.Name, ttl: u32) dns_record.ResourceRecord {
    const payload = [_]u8{ 0x07, 'R', 'F', 'C', '8', '4', '8', '2', 0x00 };
    var rdata = dns_rdata.Unknown{ .len = @intCast(payload.len) };
    @memcpy(rdata.data[0..payload.len], &payload);
    return .{
        .owner = owner,
        .rrtype = hinfo_type,
        .class = dns_types.Class.IN,
        .ttl = ttl,
        .rdata = .{ .Unknown = rdata },
    };
}

/// Maximum RRSIGs attached to one response. Answers name few RRsets, so this
/// bounds amplification from a zone packed with signatures.
const max_covering_rrsigs: usize = 8;

/// Append zone RRSIGs whose owner matches an answer record and whose
/// type-covered field equals that record's type. Malformed candidates are
/// skipped so one bad RRSIG cannot fail the whole response.
/// An RRSIG at `rrsig_owner` covers an answer owned by `answer_owner` when
/// the owners match, or when the RRSIG sits at a wildcard (`*.example.`)
/// whose parent suffix-matches the answer owner.
fn coversOwner(rrsig_owner: []const u8, answer_owner: dns_name.Name) bool {
    var answer_text: [256]u8 = undefined;
    const answer = answer_owner.toText(&answer_text) catch return false;
    if (std.ascii.eqlIgnoreCase(rrsig_owner, answer)) return true;
    if (rrsig_owner.len < 3 or rrsig_owner[0] != '*' or rrsig_owner[1] != '.') return false;
    const parent = rrsig_owner[2..];
    if (answer.len <= parent.len) return false;
    if (!std.ascii.eqlIgnoreCase(answer[answer.len - parent.len ..], parent)) return false;
    return answer[answer.len - parent.len - 1] == '.';
}
fn wildcardOwnerIsAnswer(owner: []const u8, answers: []const dns_record.ResourceRecord) bool {
    const wildcard = dns_name.Name.fromText(owner) catch return false;
    for (answers) |answer| {
        if (answer.owner.eql(&wildcard)) return true;
    }
    return false;
}

fn appendCoveringRrsigs(response: *dns_message.Message, zone: *const zone_index.Zone, qtype: dns_types.RecordType, answer_owner: ?[]const u8) !void {
    _ = qtype;
    // Snapshot the pre-proof length: appended RRSIGs must not be rescanned,
    // and section storage may move on append.
    const original_len = response.answers.len;
    var appended: usize = 0;
    var index: usize = 0;
    // Single pass over the zone: each RRSIG candidate is decoded once and
    // attached at most once when it covers a snapshotted answer RRset.
    while (index < zone.records.len and appended < max_covering_rrsigs) : (index += 1) {
        const candidate = zone.records.items[index];
        if (!candidate.rrtype.eql(.RRSIG)) continue;
        const is_wildcard = candidate.ownerText().len > 2 and candidate.ownerText()[0] == '*' and candidate.ownerText()[1] == '.';
        // A wildcard RRSIG is emitted under the expanded answer owner (RFC
        // 4035 §3.1.3.3). Without an expansion the answer can still be the
        // wildcard owner itself (RFC 4592 §2.3: no special processing when
        // the QNAME is the wildcard), and its RRSIG keeps that owner.
        if (is_wildcard and answer_owner == null and
            !wildcardOwnerIsAnswer(candidate.ownerText(), response.answers.items[0..original_len])) continue;
        const owner_override = if (is_wildcard) answer_owner else null;
        const rr = toResourceRecord(candidate, owner_override) catch continue;
        const raw = switch (rr.rdata) {
            .Unknown => |unknown| unknown.bytes(),
            else => continue,
        };
        const covers = @import("../dns/dnssec.zig").rrsigCovers(raw) catch continue;
        var answer_index: usize = 0;
        var covers_answer = false;
        while (answer_index < original_len) : (answer_index += 1) {
            const answer = response.answers.items[answer_index];
            if (answer.rrtype.eql(.RRSIG)) continue;
            if (covers != answer.rrtype.code()) continue;
            if (!coversOwner(candidate.ownerText(), answer.owner)) continue;
            covers_answer = true;
            break;
        }
        if (!covers_answer) continue;
        if (response.answers.len >= std.math.maxInt(u16)) return Error.TooManyRecords;
        try response.answers.append(rr);
        appended += 1;
    }
}

/// Best-effort authenticated denial for NODATA/NXDOMAIN when DO=1: attach an
/// exact-owner NSEC that denies the QTYPE, else any zone NSEC whose span
/// covers the QNAME, plus apex NSEC3PARAM RRsets. Capped so denial proofs
/// cannot amplify a small query into a large response.
fn appendDenialProofs(response: *dns_message.Message, zone: *const zone_index.Zone, qname_text: []const u8, qtype: dns_types.RecordType) !void {
    const dnssec = @import("../dns/dnssec.zig");
    const qname = dns_name.Name.fromText(qname_text) catch return;
    var attached: usize = 0;
    var index: usize = 0;
    while (index < zone.records.len and attached < 4) : (index += 1) {
        const candidate = zone.records.items[index];
        if (!candidate.rrtype.eql(.NSEC)) continue;
        const rr = toResourceRecord(candidate, null) catch continue;
        const raw = switch (rr.rdata) {
            .Unknown => |unknown| unknown.bytes(),
            else => continue,
        };
        const denies = dnssec.nsecDeniesType(raw, qtype.code()) catch continue;
        if (!denies) continue;
        const owner = dns_name.Name.fromText(candidate.ownerText()) catch continue;
        if (owner.eql(&qname)) {
            try response.authorities.append(rr);
            attached += 1;
            continue;
        }
        const next = dns_name.Name.parse(raw, 0) catch continue;
        if (dnssec.nsecCovers(owner, next.name, qname)) {
            try response.authorities.append(rr);
            attached += 1;
        }
    }
    index = 0;
    while (index < zone.records.len and attached < 6) : (index += 1) {
        const candidate = zone.records.items[index];
        if (!candidate.rrtype.eql(.NSEC3PARAM)) continue;
        if (!std.ascii.eqlIgnoreCase(candidate.ownerText(), zone.originText())) continue;
        const rr = toResourceRecord(candidate, null) catch continue;
        try response.authorities.append(rr);
        attached += 1;
    }
}
// The proof-record strip moved to src/dns/dnssec.zig (RFC 3225/RFC 3597);
// the authoritative path calls dns_dnssec.stripProofRecords below.

pub fn buildRefusedResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    return buildEmptyResponse(request, q, if (q.qclass.eql(dns_types.Class.IN)) .refused else .notimp);
}

pub fn buildFormerrResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    var response = try buildEmptyResponse(request, q, .formerr);
    response.edns = null;
    response.additionals.len = 0;
    response.header.additional_count = 0;
    return response;
}

pub fn buildNotImplementedResponse(request: dns_message.Message) !dns_message.Message {
    // An RFC 2136 UPDATE may carry no zone section, so the question is
    // optional and QDCOUNT is answered as sent.
    return buildEmptyResponse(request, request.question, .notimp);
}

fn buildEmptyResponse(request: dns_message.Message, q: ?question.Question, rcode: header.Rcode) !dns_message.Message {
    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .opcode = request.header.opcode,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .checking_disabled = request.header.checking_disabled,
            .question_count = if (q == null) 0 else 1,
            .rcode = rcode,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (request.edns) |edns| .{
            .udp_payload_size = negotiateEdnsPayload(edns.udp_payload_size),
            .extended_rcode = 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer response.deinit();
    if (response.edns != null) try appendOpt(&response);
    try setHeaderCounts(&response);
    return response;
}

pub fn negotiateEdnsPayload(advertised: u16) u16 {
    if (advertised < dns_message.CLASSIC_UDP_PAYLOAD_SIZE) return dns_message.CLASSIC_UDP_PAYLOAD_SIZE;
    return @min(advertised, DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
}

pub fn buildBadVersionResponse(request: dns_message.Message, q: question.Question) !dns_message.Message {
    const request_edns = request.edns orelse return Error.BadResponse;
    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = false,
            .checking_disabled = request.header.checking_disabled,
            .rcode = .no_error,
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = .{
            .udp_payload_size = negotiateEdnsPayload(request_edns.udp_payload_size),
            .extended_rcode = 1,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = request_edns.dnssec_ok,
        },
    };
    errdefer response.deinit();
    try appendOpt(&response);
    try setHeaderCounts(&response);
    return response;
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

/// The OPTION-DATA bytes of a message's OPT record, or null when it carries no
/// EDNS(0) at all. RFC 6891 section 6.1.1 permits one OPT record, so the first
/// is the only one.
fn ednsOptions(message: *const dns_message.Message) ?[]const u8 {
    for (message.additionals.slice()) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return switch (record.rdata) {
            .OPT => |*opt| opt.bytes(),
            else => unreachable,
        };
    }
    return null;
}

/// RFC 9660 section 3.2.1: OPTION-LENGTH must be zero in a query, and a query
/// must not carry the option more than once.
fn zoneversionIsMalformed(request: *const dns_message.Message) bool {
    const options = ednsOptions(request) orelse return false;
    var offset: usize = 0;
    var seen: usize = 0;
    while (offset + 4 <= options.len) {
        const code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const option_len = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        offset += 4;
        if (option_len > options.len - offset) return false;
        if (code == dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) {
            seen += 1;
            if (seen > 1 or option_len != 0) return true;
        }
        offset += option_len;
    }
    return false;
}

/// Answer the EDNS(0) options this server understands and the query asked for.
/// Neither option is ever sent unsolicited (RFC 5001 section 2.2, RFC 9660
/// section 3.2.2), and neither is worth failing an answer over: an OPT that
/// cannot hold the option simply leaves it out.
fn appendRequestedEdnsOptions(
    response: *dns_message.Message,
    request: *const dns_message.Message,
    zone: *const zone_index.Zone,
    policy: AnswerPolicy,
) void {
    const options = ednsOptions(request) orelse return;
    if (policy.nsid) |nsid| {
        // RFC 5001 section 2.2: query NSID payload data is ignored, so the
        // option's presence is the whole request.
        if (dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE) != null) {
            _ = optOf(response).appendOption(dns_rdata.EDNS_NSID_OPTION_CODE, nsid);
        }
    }
    if (!policy.zoneversion) return;
    if (dns_rdata.findOption(options, dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) == null) return;
    // RFC 9660 section 3.2 lists the responses that carry the option, including
    // NXDOMAIN, NODATA, referrals, and SERVFAIL, so this runs for every answer
    // the zone produced rather than only for a positive one. A referral gets
    // the referring zone's serial, which is the zone that answered.
    const serial = zone.soaSerial() orelse return;
    // RFC 9660 sections 2.1 and 4: LABELCOUNT, TYPE, then the opaque VERSION.
    // SOA-SERIAL is TYPE 0 and its VERSION is the 4-octet SOA SERIAL.
    var data: [6]u8 = undefined;
    data[0] = labelCount(zone.originText());
    data[1] = 0;
    std.mem.writeInt(u32, data[2..6], serial, .big);
    _ = optOf(response).appendOption(dns_rdata.EDNS_ZONEVERSION_OPTION_CODE, &data);
}

fn optOf(message: *dns_message.Message) *dns_rdata.Opt {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (record.rrtype.eql(.OPT)) return &record.rdata.OPT;
    }
    unreachable; // appendOpt ran before any option is added.
}

/// RFC 9660 section 2.1 LABELCOUNT: the labels of the zone name, counted from
/// the fully qualified text. The root zone has none.
fn labelCount(name: []const u8) u8 {
    const trimmed = if (name.len != 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    var labels: u8 = 0;
    for (trimmed) |byte| {
        if (byte == '.') labels += 1;
    }
    return labels + @intFromBool(trimmed.len != 0);
}

fn setHeaderCounts(response: *dns_message.Message) Error!void {
    const max_count = @as(usize, std.math.maxInt(u16));
    if (response.answers.len > max_count or response.authorities.len > max_count or response.additionals.len > max_count) {
        return Error.TooManyRecords;
    }
    response.header.answer_count = @intCast(response.answers.len);
    response.header.authority_count = @intCast(response.authorities.len);
    response.header.additional_count = @intCast(response.additionals.len);
}

pub fn zoneRecordToResourceRecord(record: zone_parser.ZoneRecord, owner_override: ?[]const u8) !dns_record.ResourceRecord {
    return toResourceRecord(record, owner_override);
}

fn toResourceRecord(record: zone_parser.ZoneRecord, owner_override: ?[]const u8) !dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(owner_override orelse record.ownerText()) catch return Error.BadZoneRecord,
        .rrtype = record.rrtype,
        .class = dns_types.Class.IN,
        .ttl = record.ttl,
        .rdata = try parseZoneRData(record),
    };
}

fn toNegativeSoa(record: zone_parser.ZoneRecord) !dns_record.ResourceRecord {
    var rr = try toResourceRecord(record, null);
    if (rr.rdata == .SOA) rr.ttl = @min(rr.ttl, rr.rdata.SOA.minimum);
    return rr;
}

fn parseZoneRData(record: zone_parser.ZoneRecord) !dns_rdata.RData {
    return zone_parser.parseRData(record.rrtype, record.rdataText()) catch Error.BadZoneRecord;
}

test "authoritative response builder answers exact A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.header.qr);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &response.answers.items[0].rdata.A);

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(@as(u16, 0x1234), round_trip.header.id);
    try std.testing.expectEqual(@as(u16, 1), round_trip.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &round_trip.answers.items[0].rdata.A);
}

test "authoritative response builder returns CNAME and SOA-backed negatives" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const cname_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        5,    'a',  'l',  'i',  'a',  's',  4,    'h',  'o',  'm',  'e',  4,
        'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const cname_response = try buildResponse(cname_request, &zone);
    try std.testing.expectEqual(@as(u16, 2), cname_response.header.answer_count);
    try std.testing.expect(cname_response.answers.items[0].rrtype.eql(.CNAME));

    const missing_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x36, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'm',  'i',  's',  's',  'i',  'n',  'g',  4,    'h',  'o',  'm',
        'e',  4,    'a',  'r',  'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    const missing_response = try buildResponse(missing_request, &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, missing_response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), missing_response.header.authority_count);
}

test "non-IN queries return NOTIMP with the question and EDNS OPT preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "dns.home.arpa.", .A);
    request.question.?.qclass = dns_types.Class.fromCode(3);
    request.edns = .{
        .udp_payload_size = 1232,
        .extended_rcode = 0,
        .version = 0,
        .dnssec_ok = false,
    };
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expectEqual(header.Rcode.notimp, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
    try std.testing.expectEqual(@as(u16, 1), response.header.additional_count);
    try std.testing.expectEqual(dns_types.Class.fromCode(3), response.question.?.qclass);
    try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
}

test "authoritative response builder converts phase-one zone record types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.test.
        \\$TTL 3600
        \\@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 900 1209600 3600
        \\@ IN NS ns1.example.test.
        \\www IN AAAA 2001:db8::1
        \\mail IN MX 10 mail.example.test.
        \\txt IN TXT "hello world"
        \\sip IN SRV 10 20 8443 sip.example.test.
        \\@ IN CAA 0 issue letsencrypt.org
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const txt_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    't',  'x',  't',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        4,    't',  'e',  's',  't',  0,    0x00, 0x10, 0x00, 0x01,
    });
    const txt_response = try buildResponse(txt_request, &zone);
    try std.testing.expectEqualStrings("hello world", txt_response.answers.items[0].rdata.TXT.text());

    const aaaa_record = try toResourceRecord(zone.records.items[2], null);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &aaaa_record.rdata.AAAA);
    const mx_record = try toResourceRecord(zone.records.items[3], null);
    try std.testing.expectEqual(@as(u16, 10), mx_record.rdata.MX.preference);
    const srv_record = try toResourceRecord(zone.records.items[5], null);
    try std.testing.expectEqual(@as(u16, 8443), srv_record.rdata.SRV.port);
    const caa_record = try toResourceRecord(zone.records.items[6], null);
    try std.testing.expectEqualStrings("issue", caa_record.rdata.CAA.tagText());
}

test "authoritative response builder converts PTR zone records" {
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\reverse IN PTR target
        \\
    );
    defer zone_file.deinit();

    const ptr_record = try toResourceRecord(zone_file.records.items[2], null);
    try std.testing.expect(ptr_record.rrtype.eql(.PTR));
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.", try ptr_record.rdata.PTR.toText(&target));
}

test "authoritative response builder serves typed SVCB and HTTPS records" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.test.
        \\$TTL 3600
        \\@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 900 1209600 3600
        \\@ IN NS ns1.example.test.
        \\svc IN SVCB 1 target alpn=h2 port=443
        \\alias IN HTTPS 0 target
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const svcb_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 's',  'v',  'c',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x04, 't',  'e',  's',  't',  0x00, 0x00, 0x40, 0x00, 0x01,
    });
    const svcb_response = try buildResponse(svcb_request, &zone);
    try std.testing.expectEqual(@as(u16, 1), svcb_response.header.answer_count);
    const svcb_answer = svcb_response.answers.items[0];
    try std.testing.expect(svcb_answer.rrtype.eql(.SVCB));
    try std.testing.expectEqual(@as(u16, 1), svcb_answer.rdata.SVCB.priority);
    var target: [64]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.test.", try svcb_answer.rdata.SVCB.target.toText(&target));

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try svcb_response.encode(&writer);
    const expected = [_]u8{
        0xab, 0xcd, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 's',  'v',  'c',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x04, 't',  'e',  's',  't',  0x00, 0x00, 0x40, 0x00, 0x01, 0xc0, 0x0c,
        0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x24, 0x00, 0x01,
        0x06, 't',  'a',  'r',  'g',  'e',  't',  0x07, 'e',  'x',  'a',  'm',
        'p',  'l',  'e',  0x04, 't',  'e',  's',  't',  0x00, 0x00, 0x01, 0x00,
        0x03, 0x02, 'h',  '2',  0x00, 0x03, 0x00, 0x02, 0x01, 0xbb,
    };
    try std.testing.expectEqualSlices(u8, &expected, writer.written());
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expect(round_trip.answers.items[0].rrtype.eql(.SVCB));
    try std.testing.expectEqual(@as(u16, 1), round_trip.answers.items[0].rdata.SVCB.priority);

    const https_request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0xab, 0xce, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 'a',  'l',  'i',  'a',  's',  0x07, 'e',  'x',  'a',  'm',  'p',
        'l',  'e',  0x04, 't',  'e',  's',  't',  0x00, 0x00, 0x41, 0x00, 0x01,
    });
    const https_response = try buildResponse(https_request, &zone);
    try std.testing.expectEqual(@as(u16, 1), https_response.header.answer_count);
    try std.testing.expect(https_response.answers.items[0].rrtype.eql(.HTTPS));
    try std.testing.expectEqual(@as(u16, 0), https_response.answers.items[0].rdata.HTTPS.priority);
}

test "rejects response section counts beyond the DNS wire limit" {
    var response = dns_message.Message{ .header = .{ .id = 0x1234 } };
    response.answers.len = @as(usize, std.math.maxInt(u16)) + 1;

    try std.testing.expectError(Error.TooManyRecords, setHeaderCounts(&response));
}

const dnssec_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\www IN A 192.0.2.1
    \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\www IN NSEC www.example. A RRSIG NSEC
    \\
;

fn testDoQuery(allocator: std.mem.Allocator, id: u16, name_text: []const u8, qtype: dns_types.RecordType, dnssec_ok: bool) !dns_message.Message {
    var message = try testQuery(allocator, name_text, qtype);
    message.header.id = id;
    message.edns = .{
        .udp_payload_size = 1232,
        .extended_rcode = 0,
        .version = 0,
        .dnssec_ok = dnssec_ok,
    };
    try message.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = if (dnssec_ok) 0x8000 else 0,
        .rdata = .{ .OPT = .{} },
    });
    message.header.additional_count = 1;
    return message;
}

test "DO-bit query receives covering RRSIGs, plain query does not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(dnssec_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const do_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4401, "www.example.", .A, true), &zone);
    try std.testing.expectEqual(@as(u16, 2), do_response.header.answer_count);
    try std.testing.expect(do_response.answers.items[0].rrtype.eql(.A));
    try std.testing.expect(do_response.answers.items[1].rrtype.eql(.RRSIG));
    try std.testing.expect(do_response.edns.?.dnssec_ok);

    const plain_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4402, "www.example.", .A, false), &zone);
    try std.testing.expectEqual(@as(u16, 1), plain_response.header.answer_count);
    try std.testing.expect(plain_response.answers.items[0].rrtype.eql(.A));

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try do_response.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(@as(u16, 2), round_trip.header.answer_count);
    try std.testing.expect(round_trip.answers.items[1].rrtype.eql(.RRSIG));
    try std.testing.expectEqual(@as(u16, 1), try @import("../dns/dnssec.zig").rrsigCovers(round_trip.answers.items[1].rdata.Unknown.bytes()));
}
test "wildcard RRSIGs are emitted under the expanded owner, never as wildcard" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\* IN A 192.0.2.9
        \\* IN RRSIG A 8 2 3600 2000000000 1000000000 1234 example. QUJD
        \\www IN A 192.0.2.1
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1235 example. QUJD
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Wildcard expansion: the RRSIG rides under the QNAME, not `*.example.`.
    const expanded = try buildResponse(try testDoQuery(arena.allocator(), 0x4450, "other.example.", .A, true), &zone);
    var expanded_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("other.example.", try expanded.answers.items[0].owner.toText(&expanded_text));
    var rrsig_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("other.example.", try expanded.answers.items[1].owner.toText(&rrsig_text));

    // Exact answer: the wildcard RRSIG never attaches, only the exact one.
    const exact = try buildResponse(try testDoQuery(arena.allocator(), 0x4451, "www.example.", .A, true), &zone);
    try std.testing.expectEqual(@as(u16, 2), exact.header.answer_count);
    var exact_rrsig: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.", try exact.answers.items[1].owner.toText(&exact_rrsig));
}
test "a query for the wildcard owner itself keeps its RRSIG (RFC 4592 §2.3)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\* IN A 192.0.2.9
        \\* IN RRSIG A 8 2 3600 2000000000 1000000000 1234 example. QUJD
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // No expansion: the QNAME is the wildcard, so answer_owner is null and
    // the RRSIG keeps its wildcard owner instead of being dropped.
    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4452, "*.example.", .A, true), &zone);
    try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
    var owner_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("*.example.", try response.answers.items[1].owner.toText(&owner_text));
}

test "covering RRSIGs are capped so packed zones cannot amplify" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1234 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1235 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1236 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1237 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1238 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1239 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1240 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1241 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1242 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1243 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1244 example. QUJD
        \\www IN RRSIG A 8 2 3600 2000000000 1000000000 1245 example. QUJD
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4410, "www.example.", .A, true), &zone);
    try std.testing.expectEqual(@as(usize, 1 + max_covering_rrsigs), response.answers.len);
    try std.testing.expectEqual(@as(u16, 1 + max_covering_rrsigs), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.A));
    for (response.answers.slice()[1..]) |answer| {
        try std.testing.expect(answer.rrtype.eql(.RRSIG));
        try std.testing.expectEqual(@as(u16, 1), try @import("../dns/dnssec.zig").rrsigCovers(answer.rdata.Unknown.bytes()));
    }
}

test "explicit DNSKEY query is answered with or without DO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(dnssec_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const plain = try buildResponse(try testDoQuery(arena.allocator(), 0x4403, "example.", .DNSKEY, false), &zone);
    try std.testing.expectEqual(@as(u16, 1), plain.header.answer_count);
    try std.testing.expect(plain.answers.items[0].rrtype.eql(.DNSKEY));

    const flagged = try buildResponse(try testDoQuery(arena.allocator(), 0x4404, "example.", .DNSKEY, true), &zone);
    try std.testing.expectEqual(@as(u16, 1), flagged.header.answer_count);
}

test "NODATA with DO carries an NSEC denial proof, without DO only SOA" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(dnssec_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const do_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4405, "www.example.", .AAAA, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, do_response.header.rcode);
    try std.testing.expect(do_response.header.authority_count >= 2);
    var saw_nsec = false;
    for (do_response.authorities.slice()) |record| {
        if (record.rrtype.eql(.NSEC)) saw_nsec = true;
    }
    try std.testing.expect(saw_nsec);

    const plain_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4406, "www.example.", .AAAA, false), &zone);
    try std.testing.expectEqual(@as(u16, 1), plain_response.header.authority_count);
    try std.testing.expect(plain_response.authorities.items[0].rrtype.eql(.SOA));
}

fn testQuery(allocator: std.mem.Allocator, name_text: []const u8, qtype: dns_types.RecordType) !dns_message.Message {
    return .{
        .allocator = allocator,
        .header = .{ .id = 0x1234 },
        .question = .{
            .name = try dns_name.Name.fromText(name_text),
            .qtype = qtype,
            .qclass = dns_types.Class.IN,
        },
    };
}

test "RFC 4343 4.1: the response echoes the question in the case the client sent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var query = try testQuery(arena.allocator(), "www.example.", .A);
    query.question.?.name = (try dns_name.Name.parsePreservingCase(
        &.{ 3, 'W', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        0,
    )).name;

    const response = try buildResponse(query, &zone);
    var text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("Www.Example.", try response.question.?.name.toText(&text));
    // The answer still carries the owner the zone file holds.
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &response.answers.items[0].rdata.A);
}

test "authoritative response rewrites wildcard owners and preserves negative SOA TTL" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\*.example. IN A 192.0.2.3
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const wildcard = try buildResponse(try testQuery(arena.allocator(), "other.example.", .A), &zone);
    try std.testing.expectEqual(@as(u16, 1), wildcard.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, &wildcard.answers.items[0].rdata.A);
    var wildcard_owner: [256]u8 = undefined;
    try std.testing.expectEqualStrings("other.example.", try wildcard.answers.items[0].owner.toText(&wildcard_owner));

    const nodata = try buildResponse(try testQuery(arena.allocator(), "www.example.", .AAAA), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, nodata.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), nodata.header.authority_count);
    try std.testing.expectEqual(@as(u32, 300), nodata.authorities.items[0].ttl);
}

test "authoritative response emits referral glue and uncompressed DNAME CNAME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.external.example.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.external.example. IN A 192.0.2.11
        \\legacy IN DNAME target.example.
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const referral = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    try std.testing.expect(!referral.header.authoritative);
    try std.testing.expectEqual(@as(u16, 2), referral.header.authority_count);
    try std.testing.expectEqual(@as(u16, 2), referral.header.additional_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, &referral.additionals.items[0].rdata.A);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 11 }, &referral.additionals.items[1].rdata.A);

    const dname = try buildResponse(try testQuery(arena.allocator(), "www.legacy.example.", .A), &zone);
    try std.testing.expectEqual(@as(u16, 2), dname.header.answer_count);
    try std.testing.expectEqual(dns_types.RecordType.DNAME, dname.answers.items[0].rrtype);
    try std.testing.expectEqual(dns_types.RecordType.CNAME, dname.answers.items[1].rrtype);
    var target: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.target.example.", try dname.answers.items[1].rdata.CNAME.toText(&target));
}

test "unsupported EDNS version returns BADVERS" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.edns != null);
    try std.testing.expectEqual(@as(u8, 1), response.edns.?.extended_rcode);
    var output: [256]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&output);
    try response.encode(&writer);
    const parsed = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expectEqual(@as(u8, 1), parsed.edns.?.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
}

test "EDNS payload negotiation is bounded and preserves the classic floor" {
    try std.testing.expectEqual(@as(u16, 512), negotiateEdnsPayload(0));
    try std.testing.expectEqual(@as(u16, 512), negotiateEdnsPayload(300));
    try std.testing.expectEqual(@as(u16, 600), negotiateEdnsPayload(600));
    try std.testing.expectEqual(@as(u16, 1232), negotiateEdnsPayload(4096));
}

test "EDNS truncation uses negotiated payload and retains OPT" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x1234, .qr = true, .answer_count = 40 },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
        .edns = .{ .udp_payload_size = 600, .extended_rcode = 0, .version = 0, .dnssec_ok = false },
    };
    defer message.deinit();
    const owner = try dns_name.Name.fromText("many.example.");
    var index: usize = 0;
    while (index < 40) : (index += 1) {
        try message.answers.append(.{
            .owner = owner,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, @intCast(index + 1) } },
        });
    }
    try appendOpt(&message);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > 600);

    var output: [1232]u8 = undefined;
    const truncated = try truncateClassicUdpResponse(writer.written(), &output);
    try std.testing.expect(truncated.len <= 600);
    const parsed = try dns_message.Message.parse(arena.allocator(), truncated);
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), parsed.additionals.len);
    try std.testing.expectEqual(@as(u16, 600), parsed.edns.?.udp_payload_size);
}

test "authoritative response ignores unknown EDNS options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const request = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xea, 0x60, 0x00, 0x03, 0x01, 0x02,
        0x03,
    });
    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.edns != null);
    try std.testing.expectEqual(@as(u16, 1232), response.edns.?.udp_payload_size);
    try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
    try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
}

test "authoritative response emits bare OPT for Padding and ECS /0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const padding_query = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x0c, 0x00, 0x03, 0xaa, 0xbb,
        0xcc,
    };
    const ecs_zero_query = [_]u8{
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01,
        0x00, 0x00,
    };

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    for ([_][]const u8{ &padding_query, &ecs_zero_query }) |wire| {
        const request = try dns_message.Message.parseQuery(arena.allocator(), wire);
        const response = try buildResponse(request, &zone);
        try std.testing.expect(response.edns != null);
        try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
        try std.testing.expectEqual(@as(usize, 0), response.additionals.items[0].rdata.OPT.bytes().len);
    }
}

/// RFC 9660 section 5's own example zone: a two-label apex whose SOA serial is
/// the version the option carries.
const zoneversion_test_zone =
    \\$ORIGIN example.com.
    \\$TTL 3600
    \\@ IN SOA ns.example.com. hostmaster.example.com. 2023073001 3600 900 1209600 300
    \\@ IN NS ns.example.com.
    \\ns IN A 192.0.2.53
    \\www IN A 192.0.2.1
    \\child IN NS ns.child.example.com.
    \\ns.child IN A 192.0.2.60
    \\
;

const TestOption = struct { code: u16, data: []const u8 };

/// An EDNS query whose OPT record carries `options` in RFC 6891 framing, built
/// through the same append path the resolver uses so the bytes on the wire are
/// the real ones.
fn testOptionsQuery(
    allocator: std.mem.Allocator,
    name_text: []const u8,
    qtype: dns_types.RecordType,
    options: []const TestOption,
) !dns_message.Message {
    var message = try testDoQuery(allocator, 0x4400, name_text, qtype, false);
    for (options) |option| {
        std.debug.assert(message.additionals.items[0].rdata.OPT.appendOption(option.code, option.data));
    }
    return message;
}

test "RFC 9660: a ZONEVERSION request is answered with the responding zone's SOA serial" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request_options = [_]TestOption{.{
        .code = dns_rdata.EDNS_ZONEVERSION_OPTION_CODE,
        .data = &.{},
    }};
    // RFC 9660 section 5: LABELCOUNT 2 for example.com., TYPE 0 (SOA-SERIAL),
    // then the 4-octet SOA SERIAL.
    const expected = [_]u8{ 2, 0, 0x78, 0x95, 0xa4, 0xe9 };

    // A positive answer, NXDOMAIN, and a referral all carry the option: section
    // 3.2 names them, and the referral reports the referring zone's version.
    for ([_][]const u8{ "www.example.com.", "missing.example.com.", "www.child.example.com." }) |name_text| {
        const request = try testOptionsQuery(arena.allocator(), name_text, .A, &request_options);
        const response = try buildResponseWithPolicy(request, &zone, .{});
        const option = ednsOptions(&response) orelse return error.TestExpectedEqual;
        try std.testing.expectEqualSlices(u8, &expected, dns_rdata.findOption(option, dns_rdata.EDNS_ZONEVERSION_OPTION_CODE).?);
    }
}

test "RFC 9660: a ZONEVERSION request is never answered unless it was asked for" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 3.2.2: the option is not transitive, so a query without it gets
    // none back even from a server that would answer one.
    const plain = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{}), &zone);
    const plain_options = ednsOptions(&plain) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 0), plain_options.len);

    // `zoneversion off` is the operator declining the section 3.2 choice.
    const declined = try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{
        .{ .code = dns_rdata.EDNS_ZONEVERSION_OPTION_CODE, .data = &.{} },
    });
    const declined_response = try buildResponseWithPolicy(declined, &zone, .{ .zoneversion = false });
    const declined_options = ednsOptions(&declined_response) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 0), declined_options.len);
}

test "RFC 9660 section 3.2.1: a malformed ZONEVERSION query is answered FORMERR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const empty = TestOption{ .code = dns_rdata.EDNS_ZONEVERSION_OPTION_CODE, .data = &.{} };
    const two_options = [_]TestOption{ empty, empty };
    const payload_in_query = [_]TestOption{.{
        .code = dns_rdata.EDNS_ZONEVERSION_OPTION_CODE,
        .data = &.{ 2, 0, 0x78, 0x95, 0xa4, 0xe9 },
    }};
    for ([_][]const TestOption{ &two_options, &payload_in_query }) |options| {
        const response = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, options), &zone);
        try std.testing.expectEqual(header.Rcode.formerr, response.header.rcode);
        try std.testing.expectEqual(@as(usize, 0), response.answers.len);
    }

    // One empty option is the well-formed request and is answered normally.
    const ok = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{empty}), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, ok.header.rcode);
}

test "RFC 5001: NSID is echoed only when configured and only when requested" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const nsid = [_]TestOption{.{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{} }};
    const policy = AnswerPolicy{ .nsid = "ns1.example.com." };

    const answered = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &nsid), &zone, policy);
    const answered_options = ednsOptions(&answered) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, policy.nsid.?, dns_rdata.findOption(answered_options, dns_rdata.EDNS_NSID_OPTION_CODE).?);

    // Section 2.2: the option is never sent to a resolver that did not ask.
    const unsolicited = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{}), &zone, policy);
    const unsolicited_options = ednsOptions(&unsolicited) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(unsolicited_options, dns_rdata.EDNS_NSID_OPTION_CODE) == null);

    // The server has no identifier of its own to give until one is configured.
    const unconfigured = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &nsid), &zone);
    const unconfigured_options = ednsOptions(&unconfigured) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(unconfigured_options, dns_rdata.EDNS_NSID_OPTION_CODE) == null);

    // Section 2.2: NSID payload data in a query is ignored, and answering with
    // the server's own identifier is what the option's presence asked for.
    const with_payload = [_]TestOption{.{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{ 0xde, 0xad } }};
    const ignored = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &with_payload), &zone, policy);
    const ignored_options = ednsOptions(&ignored) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, policy.nsid.?, dns_rdata.findOption(ignored_options, dns_rdata.EDNS_NSID_OPTION_CODE).?);
}

test "RFC 8145 section 4.3: a responder never answers with the edns-key-tag option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const key_tag = [_]TestOption{.{ .code = dns_rdata.EDNS_KEY_TAG_OPTION_CODE, .data = &.{ 0x4a, 0x4c } }};
    const response = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &key_tag), &zone, .{ .nsid = "ns1" });
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_KEY_TAG_OPTION_CODE) == null);
    // Section 4.3 forbids the answer outright, and RFC 5001 section 2.2 means
    // the configured identifier does not ride along in its place: this query
    // asked for neither option, so the OPT record comes back empty.
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE) == null);
    try std.testing.expectEqual(@as(usize, 0), options.len);
}

test "RFC 8020: an alias chain ending at a missing in-zone name denies the last name of the chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME missing
        \\external IN CNAME host.elsewhere.test.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 2 Warning: "if there is a chain of CNAME (or DNAME), the name
    // that does not exist is the last of the chain and not the QNAME." The
    // chain still rides in the answer so the client can see where it stopped.
    const denied = try buildResponse(try testQuery(arena.allocator(), "alias.home.arpa.", .A), &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, denied.header.rcode);
    try std.testing.expect(denied.header.authoritative);
    try std.testing.expectEqual(@as(u16, 1), denied.header.answer_count);
    try std.testing.expect(denied.answers.items[0].rrtype.eql(.CNAME));
    try std.testing.expectEqual(@as(u16, 1), denied.header.authority_count);
    try std.testing.expect(denied.authorities.items[0].rrtype.eql(.SOA));

    // An alias target outside this zone is not this server's to deny.
    const external = try buildResponse(try testQuery(arena.allocator(), "external.home.arpa.", .A), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, external.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), external.header.answer_count);
    try std.testing.expect(external.answers.items[0].rrtype.eql(.CNAME));
}

test "RFC 8020: an empty non-terminal is NODATA, never NXDOMAIN" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\deep.branch IN A 192.168.1.7
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 3.1: "The correct response to ENTs is NODATA (i.e., a response
    // code of NOERROR and an empty answer section)."
    const response = try buildResponse(try testQuery(arena.allocator(), "branch.home.arpa.", .A), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);
    try std.testing.expect(response.authorities.items[0].rrtype.eql(.SOA));
}

test "RFC 8482: ANY at an existing owner answers one synthesized HINFO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\dns IN TXT "hello"
        \\alias IN CNAME dns
        \\deep.branch IN A 192.168.1.7
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 4.2: one HINFO whose CPU field is "RFC8482" and whose OS field
    // is the null string. Section 7 requires TC to stay clear.
    const response = try buildResponse(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expect(!response.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
    try std.testing.expectEqual(@as(u32, 86400), response.answers.items[0].ttl);
    try std.testing.expect(response.answers.items[0].rrtype.eql(hinfo_type));
    try std.testing.expectEqualSlices(
        u8,
        // CPU "RFC8482" then the null OS string: 07 + 7 octets + 00, nine in
        // all. Anything longer would be octets past the end of both strings.
        &.{ 0x07, 'R', 'F', 'C', '8', '4', '8', '2', 0x00 },
        response.answers.items[0].rdata.Unknown.bytes(),
    );

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expect(!round_trip.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), round_trip.header.answer_count);
    try std.testing.expect(round_trip.answers.items[0].rrtype.eql(hinfo_type));

    // Decode the answer straight off the wire from the RFC 1035 section 3.3.2
    // layout — CPU then OS, each a length octet plus that many octets, with
    // nothing after. Deliberately not the project's own HINFO reader, so the
    // two fields being swapped or a trailing octet fails here rather than
    // passing an encoder/decoder round trip that would agree with itself.
    const hinfo_wire = round_trip.answers.items[0].rdata.Unknown.bytes();
    var at: usize = 0;
    var fields: [2][]const u8 = undefined;
    for (&fields) |*field| {
        try std.testing.expect(at < hinfo_wire.len);
        const len = hinfo_wire[at];
        at += 1;
        try std.testing.expect(at + len <= hinfo_wire.len);
        field.* = hinfo_wire[at..][0..len];
        at += len;
    }
    try std.testing.expectEqual(hinfo_wire.len, at);
    try std.testing.expectEqualStrings("RFC8482", fields[0]);
    try std.testing.expectEqualStrings("", fields[1]);

    // A CNAME at the owner is not synthesized over: section 4.1 answers the
    // single CNAME RRset instead.
    const aliased = try buildResponse(try testQuery(arena.allocator(), "alias.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(@as(u16, 1), aliased.header.answer_count);
    try std.testing.expect(aliased.answers.items[0].rrtype.eql(.CNAME));

    // An empty non-terminal has no RRset to summarize and keeps NODATA.
    const empty = try buildResponse(try testQuery(arena.allocator(), "branch.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, empty.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), empty.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), empty.header.authority_count);
    try std.testing.expect(empty.authorities.items[0].rrtype.eql(.SOA));

    // A name that does not exist keeps NXDOMAIN; it is never answered with a
    // synthesized HINFO.
    const missing = try buildResponse(try testQuery(arena.allocator(), "gone.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, missing.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), missing.header.answer_count);
}

test "RFC 8482: a configured TTL reaches the synthesized HINFO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const configured = try buildResponseWithPolicy(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone, .{ .minimal_any_ttl = 300 });
    try std.testing.expectEqual(@as(u32, 300), configured.answers.items[0].ttl);

    const default = try buildResponse(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(@as(u32, 86400), default.answers.items[0].ttl);
}

test "RFC 9471: a referral carries in-domain and sibling-domain glue" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns1.child.example.
        \\child IN NS ns2.child.example.
        \\ns1.child IN A 192.0.2.10
        \\ns1.child IN AAAA 2001:db8::10
        \\ns1.child IN A 192.0.2.11
        \\ns2.child IN A 192.0.2.12
        \\ns2.child IN AAAA 2001:db8::12
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 3.1: "MUST include all available glue records for in-domain
    // name servers in the additional section".
    const response = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(!response.header.authoritative);
    try std.testing.expectEqual(@as(usize, 2), response.authorities.len);
    try std.testing.expectEqual(@as(usize, 5), response.additionals.len);

    var addresses: usize = 0;
    for (response.additionals.slice()) |record| {
        if (record.rrtype.eql(.A) or record.rrtype.eql(.AAAA)) addresses += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), addresses);
}

test "RFC 9471: a referral too large for the datagram limit sets TC=1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Enough in-domain glue that the encoded referral cannot fit the
    // 512-octet classic UDP limit.
    var zone_buffer: [8192]u8 = undefined;
    var zone_len: usize = 0;
    zone_len += (try std.fmt.bufPrint(zone_buffer[zone_len..],
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\
    , .{})).len;
    var address_index: usize = 10;
    while (address_index < 50) : (address_index += 1) {
        zone_len += (try std.fmt.bufPrint(zone_buffer[zone_len..], "ns.child IN A 192.0.2.{d}\n", .{address_index})).len;
    }
    var zone_file = try zone_parser.ZoneFile.parse(zone_buffer[0..zone_len]);
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    // Section 3.1: an incomplete referral must set TC rather than ship a
    // silently missing-glue answer, so the client retries over TCP.
    var output: [2048]u8 = undefined;
    const truncated = try truncateClassicUdpResponse(writer.written(), &output);
    const round_trip = try dns_message.Message.parse(arena.allocator(), truncated);
    try std.testing.expect(round_trip.header.truncated);
    try std.testing.expect(truncated.len <= CLASSIC_UDP_MESSAGE_SIZE);
}

// RFC 4035 section 3.1.6: "A security-aware name server does not perform
// signature validation for authoritative data during query processing, even
// when the CD bit is clear", and it "MUST NOT set the AD bit in a response
// unless the name server considers all RRsets ... to be authentic". Clearing
// AD is only permitted when the zone data itself arrived over a secure channel
// and the operator configured it, so an authoritative answer never carries it.
test "an authoritative answer to a signed and valid zone never sets AD" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\
    );
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var key = try zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(arena.allocator());
    try zone_signer.signZone(arena.allocator(), &zone, &key, .{ .inception = 1_000_000_000, .expiration = 2_000_000_000 });

    const query = try testDoQuery(arena.allocator(), 0x4a01, "www.example.", .A, true);
    const answer = try buildResponse(query, &zone);

    // The data really is valid: the same bytes validate secure against the
    // zone's own key. Without this the assertion below would pass for the
    // wrong reason, on an answer that was never good enough to set AD.
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{ .owner = try dns_name.Name.fromText("example."), .rrtype = .DNSKEY, .rdata = dnskey_rdata };
    anchors.len = 1;
    try std.testing.expectEqual(dns_validate.Status.secure, (try dns_validate.validate(arena.allocator(), &anchors, query, answer, &.{}, 1_500_000_000)).status);

    // Valid or not, this server did no validation and obtained the zone from
    // a file on local disk, so AD stays clear.
    try std.testing.expect(!answer.header.authenticated_data);
    try std.testing.expect(!query.header.authenticated_data);
}

// RFC 4035 section 3.2: the CD bit of the query is copied into the response.
test "the CD bit is copied from the query into the authoritative response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // A query received on the wire with CD set (flags 0x0110: RD and CD).
    const cd_query = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try std.testing.expect(cd_query.header.checking_disabled);

    const cd_answer = try buildResponse(cd_query, &zone);
    try std.testing.expect(cd_answer.header.checking_disabled);

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try cd_answer.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expect(round_trip.header.checking_disabled);

    // The error answers carry it too.
    try std.testing.expect((try buildFormerrResponse(cd_query)).header.checking_disabled);
    try std.testing.expect((try buildRefusedResponse(cd_query)).header.checking_disabled);

    // A query without CD keeps it clear.
    const plain_query = try testQuery(arena.allocator(), "www.example.", .A);
    const plain_answer = try buildResponse(plain_query, &zone);
    try std.testing.expect(!plain_answer.header.checking_disabled);
    try std.testing.expect(!(try buildFormerrResponse(plain_query)).header.checking_disabled);
}
