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
const dns_writer = @import("../dns/writer.zig");
const dns_types = @import("../dns/types.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_index = @import("../zone/index.zig");
const zone_signer = @import("../zone/signer.zig");
const dns_validate = @import("../dns/validate.zig");
const dns_dnssec = @import("../dns/dnssec.zig");

pub const CLASSIC_UDP_MESSAGE_SIZE: usize = 512;
pub const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;
/// RFC 7828 section 3.1: the option's TIMEOUT is an idle timeout counted in
/// units of 100 milliseconds.
pub const TCP_KEEPALIVE_UNITS_PER_SECOND: u16 = 10;
/// The idle timeout this server applies to a TCP session, in the units of
/// RFC 7828 section 3.1: the listener closes an idle connection when its
/// five-second per-frame deadline expires.
pub const TCP_IDLE_TIMEOUT_UNITS: u16 = 5 * TCP_KEEPALIVE_UNITS_PER_SECOND;

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
    /// RFC 8482 section 4.4 lets a responder answer an ANY query differently
    /// per transport. This is the TTL of the synthesized HINFO when the query
    /// arrived over TCP; null means the same TTL as over UDP.
    minimal_any_ttl_tcp: ?u32 = null,
    /// RFC 7828 section 3.3.2: the idle timeout signalled in the option, in
    /// units of 100 milliseconds. Zero asks the client to close the session.
    tcp_keepalive_timeout: u16 = TCP_IDLE_TIMEOUT_UNITS,
};

pub fn truncateClassicUdpResponse(response_bytes: []const u8, output: []u8) Error![]const u8 {
    const payload_limit = responsePayloadLimit(response_bytes);
    if (response_bytes.len <= payload_limit) {
        if (response_bytes.len > output.len) return Error.ResponseTooLarge;
        @memcpy(output[0..response_bytes.len], response_bytes);
        return output[0..response_bytes.len];
    }
    if (response_bytes.len < 12 or output.len < 12) return Error.BadResponse;

    // RFC 8914 section 3: a message that must be shortened drops its EDE
    // option before any other data.
    const shortened = shortenedOpt(response_bytes);

    // RFC 2181 section 9: data that is not required in the reply is omitted
    // when it does not fit, and the reply then carries no TC bit.
    if (replyWithoutAdditionalSection(response_bytes, output, payload_limit, null, shortened)) |reply| return reply;

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
    flags |= header.Flags.tc;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    if (shortened.record) |opt| {
        std.mem.writeInt(u16, output[10..12], 1, .big);
        opt.encode(&writer) catch return Error.ResponseTooLarge;
    } else {
        std.mem.writeInt(u16, output[10..12], 0, .big);
    }
    return writer.written();
}

/// Truncate a signed response while retaining its OPT record and its final TSIG RR.
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

    // RFC 8914 section 3: a message that must be shortened drops its EDE
    // option before any other data.
    const shortened = shortenedOpt(response_bytes);

    // RFC 2181 section 9: data that is not required in the reply is omitted
    // when it does not fit, and the reply then carries no TC bit. The TSIG
    // stays: a signed message ends with it.
    if (replyWithoutAdditionalSection(response_bytes, output, payload_limit, response_bytes[final.record_start..final.record_end], shortened)) |reply| return reply;

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
    // The RCODE stays: the OPT record's extended-rcode byte holds the upper eight bits of the twelve-bit code.
    flags |= header.Flags.tc;
    std.mem.writeInt(u16, output[2..4], flags, .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    std.mem.writeInt(u16, output[8..10], 0, .big);

    // RFC 6891 section 6.1.1: the request carried an OPT record, so the
    // reply must carry one too, and its DO bit, its payload size, and its
    // extended RCODE are header fields of the record, not of the option.
    const opt = shortened.record;
    std.mem.writeInt(u16, output[10..12], if (opt != null) 2 else 1, .big);
    var writer = @import("../dns/writer.zig").Writer.init(output);
    writer.rewind(question_end);
    if (opt) |record| record.encode(&writer) catch return Error.ResponseTooLarge;
    // RFC 8945 section 4.2: the TSIG is the last record of the message.
    writer.writeBytes(response_bytes[final.record_start..final.record_end]) catch return Error.ResponseTooLarge;
    if (writer.len() > payload_limit) return Error.ResponseTooLarge;
    return writer.written();
}

/// RFC 2181 section 9: the TC bit marks an RRSet that could not be included
/// in a reply in its entirety, so a reply whose answer and authority
/// sections fit is sent with the extra data of the additional section
/// omitted and no TC bit. A referral keeps TC: RFC 9471 section 3.1 asks
/// for it when the glue of an in-domain name server does not fit.
/// `final_tsig` is the TSIG record a signed message ends with, which the
/// signed path keeps. `shortened` is the OPT record without its EDE option.
fn replyWithoutAdditionalSection(
    response_bytes: []const u8,
    output: []u8,
    payload_limit: usize,
    final_tsig: ?[]const u8,
    shortened: ShortenedOpt,
) ?[]const u8 {
    if (response_bytes.len < 12) return null;
    const flags = std.mem.readInt(u16, response_bytes[2..4], .big);
    if ((flags & header.Flags.aa) == 0) return null;
    const core_len = coreLength(response_bytes) orelse return null;
    // RFC 6891 section 6.1.1: a response to a request that carried an OPT
    // record must carry one too, so the OPT stays and only the data records
    // of the additional section are dropped.
    const opt = shortened.record;
    const opt_len: usize = if (opt) |record| ednsOptWireLength(record) else 0;
    const tsig_len: usize = if (final_tsig) |record| record.len else 0;
    const kept = opt_len + tsig_len;
    if (core_len + kept > payload_limit) return null;
    if (core_len + kept > output.len) return null;

    @memcpy(output[0..core_len], response_bytes[0..core_len]);
    var offset = core_len;
    if (opt) |record| {
        var opt_writer = dns_writer.Writer.init(output[offset..]);
        record.encode(&opt_writer) catch return null;
        offset += opt_writer.len();
    }
    // RFC 8945 section 4.2: the TSIG is the last record of the message.
    if (final_tsig) |record| {
        @memcpy(output[offset..][0..record.len], record);
        offset += record.len;
    }
    var reply_flags = std.mem.readInt(u16, output[2..4], .big) & ~header.Flags.tc;
    // RFC 8914 section 3: the truncation bit is set when an EDE option is
    // dropped, so the client knows the message it holds is not the whole one.
    if (shortened.dropped_ede) reply_flags |= header.Flags.tc;
    std.mem.writeInt(u16, output[2..4], reply_flags, .big);
    const additional_count: u16 = @intCast((if (opt != null) @as(u16, 1) else 0) +
        (if (final_tsig != null) @as(u16, 1) else 0));
    std.mem.writeInt(u16, output[10..12], additional_count, .big);
    return output[0..offset];
}

/// The wire length of an OPT record: the root owner name, the type, class,
/// TTL, and RDLENGTH fields, and the option bytes themselves.
fn ednsOptWireLength(record: dns_record.ResourceRecord) usize {
    const rdata_len: usize = switch (record.rdata) {
        .OPT => |*opt| opt.bytes().len,
        else => 0,
    };
    return 11 + rdata_len;
}

/// The OPT record of a message that has to be shortened, without its EDE
/// option, and whether the record carried one at all.
const ShortenedOpt = struct {
    record: ?dns_record.ResourceRecord,
    dropped_ede: bool,
};

/// RFC 8914 section 3: "servers SHOULD truncate messages by dropping EDE
/// options before dropping other data from packets". The OPT record itself
/// stays: its extended RCODE, its DO bit, and its payload size are header
/// fields of the record, not the option.
fn shortenedOpt(response_bytes: []const u8) ShortenedOpt {
    const record = findEdnsOpt(response_bytes) orelse return .{ .record = null, .dropped_ede = false };
    const options = switch (record.rdata) {
        .OPT => |*opt| opt.bytes(),
        else => return .{ .record = record, .dropped_ede = false },
    };
    var kept = dns_rdata.Opt{};
    var offset: usize = 0;
    while (offset + 4 <= options.len) {
        const code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const length = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        if (length > options.len - offset - 4) break;
        if (code != ede_option_code) _ = kept.appendOption(code, options[offset + 4 ..][0..length]);
        offset += 4 + length;
    }
    var shortened = record;
    shortened.rdata = .{ .OPT = kept };
    return .{
        .record = shortened,
        .dropped_ede = ednsOptWireLength(shortened) != ednsOptWireLength(record),
    };
}

/// The wire length of the header, the question, and the answer and authority
/// sections: the records a reply is required to carry.
fn coreLength(response_bytes: []const u8) ?usize {
    var reader = @import("../dns/reader.zig").Reader.init(response_bytes);
    const parsed_header = header.Header.parse(&reader) catch return null;
    if (parsed_header.question_count > 1) return null;
    var offset: usize = 12;
    if (parsed_header.question_count == 1) {
        const parsed_question = question.Question.parse(response_bytes, offset) catch return null;
        offset = parsed_question.next_offset;
    }
    offset = sectionEnd(response_bytes, offset, parsed_header.answer_count) orelse return null;
    offset = sectionEnd(response_bytes, offset, parsed_header.authority_count) orelse return null;
    return offset;
}

/// The wire offset after `count` resource records.
fn sectionEnd(response_bytes: []const u8, start: usize, count: u16) ?usize {
    var offset = start;
    var index: u16 = 0;
    while (index < count) : (index += 1) {
        const owner = dns_name.Name.parse(response_bytes, offset) catch return null;
        offset = owner.next_offset;
        if (response_bytes.len -| offset < 10) return null;
        const rdlength = std.mem.readInt(u16, response_bytes[offset + 8 ..][0..2], .big);
        offset += 10 + @as(usize, rdlength);
        if (offset > response_bytes.len) return null;
    }
    return offset;
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
    return buildResponseWithPolicy(request, zone, .{}, null, false);
}

/// `policy` is the operator's EDNS answer policy, from the `nsid` and
/// `zoneversion` directives. `session` is the signing material of a signed
/// zone, and is null when the zone carries no key to sign with. `over_tcp`
/// says the request arrived on a TCP session, which is the only transport
/// RFC 7828 section 3.3.2 lets the keepalive option answer on.
pub fn buildResponseWithPolicy(
    request: dns_message.Message,
    zone: *const zone_index.Zone,
    policy: AnswerPolicy,
    session: ?*const zone_signer.Session,
    over_tcp: bool,
) !dns_message.Message {
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
    // FORMERR to anything else rather than ignoring it. RFC 7314 section 2
    // gives the EXPIRE option the same zero-length query form.
    if (ednsOptionIsMalformed(&request)) return buildFormerrResponse(request);
    var qname_text_buffer: [256]u8 = undefined;
    const qname_text = q.name.toText(&qname_text_buffer) catch return Error.BadQName;
    var lookup = zone.lookup(request.allocator, qname_text, q.qtype);
    defer lookup.deinit(request.allocator);

    var response = dns_message.Message{
        .allocator = request.allocator,
        .header = (header.ResponseFlags{
            .authoritative = lookup.kind != .not_authoritative and lookup.kind != .referral and lookup.kind != .servfail,
            .rcode = switch (lookup.kind) {
                .nxdomain => .nxdomain,
                .yxdomain => .yxdomain,
                .servfail => .servfail,
                .not_authoritative => .refused,
                else => .no_error,
            },
        }).header(request.header),
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
        appendRequestedEdnsOptions(&response, &request, zone, policy, over_tcp);
    }

    // DNSSEC minimum (RFC 4035 section 3.1, RFC 5155): RRSIGs covering the
    // answer RRsets and NSEC/NSEC3 denial proofs ride along only when the
    // query set DO=1; without DO, proof RRsets are stripped unless the
    // QTYPE asked for them explicitly. The AD bit is never set here: the
    // authoritative path does not validate (validation lives on the
    // forwarding path in `src/dns/validate.zig`).
    const dnssec_ok = if (request.edns) |edns| edns.dnssec_ok else false;

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
                // RFC 8482 section 4.4: the operator may answer an ANY query
                // differently per transport. The TCP TTL applies to a query
                // that arrived over TCP, the base TTL everywhere else.
                const any_ttl = if (over_tcp) (policy.minimal_any_ttl_tcp orelse policy.minimal_any_ttl) else policy.minimal_any_ttl;
                const answer = anyMinimalAnswer(q.name, any_ttl);
                try response.answers.append(answer);
                // RFC 8482 section 4.1: the answer may carry a subset of the
                // owner's RRsets. The RRset that joins the HINFO is the
                // zone's own and keeps the zone's own TTL.
                if (anySubsetType(zone, qname_text)) |subset_type| {
                    var index: usize = 0;
                    while (index < zone.records.len) : (index += 1) {
                        const record = zone.records.items[index];
                        if (!record.rrtype.eql(subset_type)) continue;
                        if (!std.ascii.eqlIgnoreCase(record.ownerText(), qname_text)) continue;
                        try response.answers.append(try toResourceRecord(record, null));
                    }
                }
                // RFC 8482 section 4.2: a signed zone must return a valid
                // RRSIG for the RRsets in the answer when the query sets DO=1.
                // The HINFO is synthesized, so no signature over it exists in
                // the zone and one is made here; the RRset that joined it is
                // the zone's own, and its RRSIG rides along with the answer.
                if (dnssec_ok) {
                    if (session) |signing| try appendMinimalAnyRrsig(&response, zone, signing, answer);
                }
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
    if (dnssec_ok) {
        appendCoveringRrsigs(&response, zone, q.qtype, lookup.answer_owner) catch {};
        if (lookup.kind == .nodata or lookup.kind == .nxdomain) {
            const proved = appendDenialProofs(&response, zone, qname_text, q.qtype, lookup.kind) catch false;
            if (!proved) refuseUnprovenDenial(&response);
        } else if (lookup.kind == .referral) {
            appendReferralProofs(&response, zone, lookup.authorities.items) catch {};
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
const hinfo_type: dns_types.RecordType = dns_types.RecordType.HINFO;

fn anyMinimalAnswer(owner: dns_name.Name, ttl: u32) dns_record.ResourceRecord {
    // The two strings are constants, so the typed constructor cannot fail.
    const rdata = dns_rdata.Hinfo.init("RFC8482", "") catch unreachable;
    return .{
        .owner = owner,
        .rrtype = hinfo_type,
        .class = dns_types.Class.IN,
        .ttl = ttl,
        .rdata = .{ .HINFO = rdata },
    };
}

/// The RRset that joins the HINFO in a minimal ANY answer, or null when the
/// owner holds a single RRset and the HINFO answers alone. RFC 8482 section
/// 4.1 lets the answer carry a subset of the owner's RRsets and leaves the
/// choice to the responder; section 4.3 names the types an initiator most
/// often wants (CNAME, MX, A, AAAA), and the order it lists them in is the
/// project's preference order. Every other type follows, in type-code order.
fn anySubsetType(zone: *const zone_index.Zone, owner_text: []const u8) ?dns_types.RecordType {
    var selected: ?dns_types.RecordType = null;
    var selected_rank: u32 = std.math.maxInt(u32);
    var selected_records: usize = 0;
    var total: usize = 0;
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const record = zone.records.items[index];
        if (!std.ascii.eqlIgnoreCase(record.ownerText(), owner_text)) continue;
        if (!isAnySubsetCandidate(record.rrtype)) continue;
        total += 1;
        const rank = anySubsetRank(record.rrtype);
        if (rank < selected_rank) {
            selected_rank = rank;
            selected = record.rrtype;
            selected_records = 1;
        } else if (rank == selected_rank) {
            selected_records += 1;
        }
    }
    // Only the selected type's own records share its rank, so a total above
    // the selected count means the owner holds more than one RRset.
    if (total <= selected_records) return null;
    return selected;
}

/// The DNSSEC proof records are not data the owner publishes, and the answer
/// already carries a synthesized HINFO at that owner.
fn isAnySubsetCandidate(rrtype: dns_types.RecordType) bool {
    return !rrtype.eql(.RRSIG) and !rrtype.eql(.NSEC) and
        !rrtype.eql(.NSEC3) and !rrtype.eql(.HINFO);
}

/// RFC 8482 section 4.3 lists the types it keeps in the order the project
/// prefers them; every other type follows, in type-code order.
fn anySubsetRank(rrtype: dns_types.RecordType) u32 {
    if (rrtype.eql(.CNAME)) return 0;
    if (rrtype.eql(.MX)) return 1;
    if (rrtype.eql(.A)) return 2;
    if (rrtype.eql(.AAAA)) return 3;
    return 4 + @as(u32, rrtype.code());
}

/// RFC 8482 section 4.2: the minimal ANY answer is synthesized, so it is not
/// in the zone file and no signature over it exists. The clause "a valid RRSIG
/// for the RRsets in the answer ... MUST be returned" is met by signing the
/// RRset the answer carries, over the canonical form RFC 4034 section 6.2
/// asks for: the owner name, the type, the class, the original TTL, and the
/// RDATA.
fn appendMinimalAnyRrsig(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    session: *const zone_signer.Session,
    answer: dns_record.ResourceRecord,
) !void {
    var rdata_buffer: [dns_rdata.max_unknown_len]u8 = undefined;
    var rdata_writer = dns_writer.Writer.init(&rdata_buffer);
    answer.rdata.encode(&rdata_writer) catch return Error.BadResponse;
    const rdata = rdata_writer.written();

    // RFC 4034 section 3.1.7: the Signer's Name is the zone of the covered
    // RRset, which is the zone that answered.
    const signer_name = dns_name.Name.fromText(zone.originText()) catch return Error.BadQName;

    const rrsig_rdata = try zone_signer.signRrset(
        response.allocator,
        answer.owner,
        signer_name,
        answer.rrtype.code(),
        &.{rdata},
        answer.ttl,
        &session.key,
        session.options,
    );
    defer response.allocator.free(rrsig_rdata);
    if (rrsig_rdata.len > dns_rdata.max_unknown_len) return Error.BadResponse;

    var unknown = dns_rdata.Unknown{ .len = @intCast(rrsig_rdata.len) };
    @memcpy(unknown.data[0..rrsig_rdata.len], rrsig_rdata);
    try response.answers.append(.{
        .owner = answer.owner,
        .rrtype = .RRSIG,
        .class = dns_types.Class.IN,
        .ttl = answer.ttl,
        .rdata = .{ .Unknown = unknown },
    });
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

/// Authenticated denial for NODATA/NXDOMAIN when DO=1. A zone that
/// publishes an NSEC3 chain proves its denials with NSEC3 records
/// (RFC 5155 section 7.2); a zone without one answers with the NSEC proofs
/// it has always served. The result is false when the chain cannot prove the
/// denial: a wrong proof is worse than none, so the caller answers server
/// failure instead.
fn appendDenialProofs(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    qname_text: []const u8,
    qtype: dns_types.RecordType,
    kind: zone_index.LookupKind,
) !bool {
    const dnssec = @import("../dns/dnssec.zig");
    const qname = dns_name.Name.fromText(qname_text) catch return true;
    var chain = try nsec3Chain(response.allocator, zone);
    defer chain.deinit(response.allocator);
    if (chain.entries != null) {
        if (!chain.consistent) return false;
        if (!try appendNsec3Proofs(response, zone, &chain, qname, qtype, kind == .nxdomain)) return false;
        // RFC 5155 section 7.3: the apex NSEC3PARAM states the parameters of
        // the chain, so a validator can check the hash the proof was built with.
        try appendApexNsec3Param(response, zone);
        return true;
    }
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
    try appendApexNsec3Param(response, zone);
    return true;
}

/// The apex NSEC3PARAM of the zone: the parameters every record of the chain
/// shares (RFC 5155 section 7.3), so a validator can check the hash a proof
/// was built with.
fn appendApexNsec3Param(response: *dns_message.Message, zone: *const zone_index.Zone) !void {
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const candidate = zone.records.items[index];
        if (!candidate.rrtype.eql(.NSEC3PARAM)) continue;
        if (!std.ascii.eqlIgnoreCase(candidate.ownerText(), zone.originText())) continue;
        const rr = toResourceRecord(candidate, null) catch continue;
        try response.authorities.append(rr);
        return;
    }
}

/// A denial the zone cannot prove is answered with server failure
/// (RFC 5155 section 7.2.9): the zone claims the name does not exist, and
/// the only honest answer is that the server cannot prove it.
fn refuseUnprovenDenial(response: *dns_message.Message) void {
    response.header.rcode = .servfail;
    response.answers.len = 0;
    response.authorities.len = 0;
}

// ------------------------------------------------------------------- NSEC3

/// One NSEC3 record of a zone's chain (RFC 5155 section 3).
const Nsec3Entry = struct {
    /// The hash of the original owner name, decoded from the NSEC3 owner.
    owner_hash: [20]u8,
    /// The next hashed owner name the record points at.
    next_hash: [20]u8,
    /// True when the record carries the Opt-Out flag (RFC 5155 section
    /// 3.1.2.1): it may cover an unsigned delegation.
    opt_out: bool,
    /// The zone record, so the proof can carry the record itself.
    record: zone_parser.ZoneRecord,
};

/// The NSEC3 chain a zone publishes (RFC 5155 section 7.1) with the
/// parameters every record of the chain shares.
const Nsec3Chain = struct {
    /// The records of the chain, or null when the zone publishes no NSEC3.
    entries: ?[]Nsec3Entry = null,
    salt_buffer: [255]u8 = undefined,
    salt_len: u8 = 0,
    iterations: u16 = 0,
    /// False when the chain mixes the salt or the iteration count RFC 5155
    /// section 7.2 forbids, so no proof can be built from it.
    consistent: bool = true,

    fn salt(self: *const Nsec3Chain) []const u8 {
        return self.salt_buffer[0..self.salt_len];
    }

    fn deinit(self: *Nsec3Chain, allocator: std.mem.Allocator) void {
        if (self.entries) |entries| allocator.free(entries);
        self.entries = null;
    }
};

/// Read the NSEC3 chain the zone publishes. A zone with no NSEC3 record has
/// no chain, and the caller keeps serving the NSEC proofs.
fn nsec3Chain(allocator: std.mem.Allocator, zone: *const zone_index.Zone) !Nsec3Chain {
    var entries: std.ArrayList(Nsec3Entry) = .empty;
    errdefer entries.deinit(allocator);
    var chain = Nsec3Chain{};
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const record = zone.records.items[index];
        if (!record.rrtype.eql(.NSEC3)) continue;
        const raw = zone_parser.parseRData(record.rrtype, record.rdataText()) catch continue;
        const bytes = switch (raw) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const rdata = dns_validate.parseNsec3Rdata(bytes) orelse continue;
        const owner = dns_name.Name.fromText(record.ownerText()) catch continue;
        const owner_hash = dns_validate.nsec3OwnerHash(owner) orelse continue;
        if (entries.items.len == 0) {
            chain.salt_len = @intCast(rdata.salt.len);
            @memcpy(chain.salt_buffer[0..rdata.salt.len], rdata.salt);
            chain.iterations = rdata.iterations;
        } else {
            // RFC 5155 section 7.2: every NSEC3 in a response uses the same
            // hash algorithm, iteration count, and salt.
            if (rdata.iterations != chain.iterations) chain.consistent = false;
            if (!std.mem.eql(u8, rdata.salt, chain.salt())) chain.consistent = false;
        }
        try entries.append(allocator, .{
            .owner_hash = owner_hash,
            .next_hash = rdata.next_hash[0..20].*,
            .opt_out = (rdata.flags & dns_validate.nsec3_opt_out) != 0,
            .record = record,
        });
    }
    if (entries.items.len == 0) return chain;
    chain.entries = entries.items;
    return chain;
}

/// The hash the chain computes for a name (RFC 5155 section 5).
fn nsec3HashOf(chain: *const Nsec3Chain, name: dns_name.Name) [20]u8 {
    var out: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(name, chain.salt(), chain.iterations, &out);
    return out;
}

/// The chain entry whose owner hash is `target` (RFC 5155 section 8.3).
fn nsec3Match(chain: *const Nsec3Chain, target: [20]u8) ?usize {
    const entries = chain.entries orelse return null;
    for (entries, 0..) |entry, index| {
        if (std.mem.eql(u8, &entry.owner_hash, &target)) return index;
    }
    return null;
}

/// The chain entry whose span covers `target` (RFC 5155 section 7.2.1).
fn nsec3Cover(chain: *const Nsec3Chain, target: [20]u8) ?usize {
    const entries = chain.entries orelse return null;
    for (entries, 0..) |entry, index| {
        if (dns_validate.nsec3Covers(entry.owner_hash, entry.next_hash, target)) return index;
    }
    return null;
}

/// True when the NSEC3 record's bitmap leaves the QTYPE and CNAME bits clear
/// (RFC 5155 section 7.2.3, section 8.5).
fn nsec3DeniesType(chain: *const Nsec3Chain, index: usize, qtype: u16) bool {
    const entries = chain.entries orelse return false;
    const raw = zone_parser.parseRData(entries[index].record.rrtype, entries[index].record.rdataText()) catch return false;
    const bytes = switch (raw) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return false,
    };
    const rdata = dns_validate.parseNsec3Rdata(bytes) orelse return false;
    return dns_dnssec.bitmapDeniesTypeAndCname(rdata.bitmap, qtype) catch false;
}

/// The closest encloser the chain proves (RFC 5155 section 7.2.1): the
/// longest ancestor with an NSEC3 that matches it, the "next closer" name one
/// label longer, and the NSEC3 that covers the next closer.
const ClosestEncloser = struct {
    name: dns_name.Name,
    match: usize,
    cover: usize,
};

fn nsec3ClosestEncloser(chain: *const Nsec3Chain, qname: dns_name.Name, origin: dns_name.Name) ?ClosestEncloser {
    var next_closer = qname;
    var candidate = parentName(qname) orelse return null;
    while (true) {
        if (nsec3Match(chain, nsec3HashOf(chain, candidate))) |index| {
            const cover = nsec3Cover(chain, nsec3HashOf(chain, next_closer)) orelse return null;
            return .{ .name = candidate, .match = index, .cover = cover };
        }
        // The apex is the last ancestor the zone can prove.
        if (candidate.asWire().len <= origin.asWire().len) return null;
        next_closer = candidate;
        candidate = parentName(candidate) orelse return null;
    }
}

/// The parent of a name: the same name with its leftmost label removed.
fn parentName(name: dns_name.Name) ?dns_name.Name {
    const wire = name.asWire();
    if (wire.len < 2) return null;
    const label_len = wire[0];
    if (label_len == 0 or (label_len & 0xc0) != 0) return null;
    const rest = wire[1 + label_len ..];
    if (rest.len == 0 or rest[rest.len - 1] != 0) return null;
    const parsed = dns_name.Name.parse(rest, 0) catch return null;
    return parsed.name;
}

/// The NSEC3 records that prove one denial (RFC 5155 sections 7.2.1 to
/// 7.2.5), each with the RRSIG that covers it. False when the chain cannot
/// prove the denial.
fn appendNsec3Proofs(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    chain: *const Nsec3Chain,
    qname: dns_name.Name,
    qtype: dns_types.RecordType,
    nxdomain: bool,
) !bool {
    const digest = nsec3HashOf(chain, qname);

    // RFC 5155 section 7.2.3: a NODATA answer carries the NSEC3 that matches
    // the QNAME, and that record leaves the QTYPE and CNAME bits clear.
    if (nsec3Match(chain, digest)) |index| {
        if (nxdomain) return false;
        if (!nsec3DeniesType(chain, index, qtype.code())) return false;
        return try appendNsec3(response, zone, chain, index);
    }

    const origin = dns_name.Name.fromText(zone.originText()) catch return false;

    // RFC 5155 section 7.2.4: a DS NODATA with no matching NSEC3 is proved
    // by the closest provable encloser proof, and the NSEC3 that covers the
    // next closer name must carry the Opt-Out flag (RFC 5155 section 6).
    // A DS query for a name that does not exist is a name error and carries
    // the proof of section 7.2.2, not the no-data proof of this section.
    if (qtype.eql(.DS) and !nxdomain) {
        const encloser = nsec3ClosestEncloser(chain, qname, origin) orelse return false;
        const entries = chain.entries orelse return false;
        if (!entries[encloser.cover].opt_out) return false;
        const proof = [_]usize{ encloser.match, encloser.cover };
        return try appendNsec3Set(response, zone, chain, proof[0..]);
    }

    const encloser = nsec3ClosestEncloser(chain, qname, origin) orelse return false;

    // The wildcard at the closest encloser (RFC 5155 section 7.2.2).
    var encloser_buffer: [256]u8 = undefined;
    const encloser_text = encloser.name.toText(&encloser_buffer) catch return false;
    var wildcard_buffer: [260]u8 = undefined;
    const wildcard_text = std.fmt.bufPrint(&wildcard_buffer, "*.{s}", .{encloser_text}) catch return false;
    const wildcard = dns_name.Name.fromText(wildcard_text) catch return false;
    const wildcard_digest = nsec3HashOf(chain, wildcard);

    var proof: [3]usize = undefined;
    var proof_len: usize = 0;
    if (nxdomain) {
        // RFC 5155 section 7.2.2: the closest encloser proof plus the NSEC3
        // that covers the wildcard at the closest encloser.
        proof[proof_len] = encloser.match;
        proof_len += 1;
        proof[proof_len] = encloser.cover;
        proof_len += 1;
        if (nsec3Match(chain, wildcard_digest)) |wildcard_match| {
            // RFC 5155 section 7.2.2 asks for the NSEC3 that covers the
            // (nonexistent) wildcard; the chain holds the wildcard, so the
            // proof carries the NSEC3 that matches it instead.
            proof[proof_len] = wildcard_match;
            proof_len += 1;
        } else {
            const wildcard_cover = nsec3Cover(chain, wildcard_digest) orelse return false;
            proof[proof_len] = wildcard_cover;
            proof_len += 1;
        }
    } else {
        // RFC 5155 section 7.2.5: a wildcard NODATA carries the closest
        // encloser proof and the NSEC3 that matches the wildcard.
        if (!zone.hasOwner(wildcard_text)) return false;
        const wildcard_match = nsec3Match(chain, wildcard_digest) orelse return false;
        if (!nsec3DeniesType(chain, wildcard_match, qtype.code())) return false;
        proof[proof_len] = encloser.match;
        proof_len += 1;
        proof[proof_len] = encloser.cover;
        proof_len += 1;
        proof[proof_len] = wildcard_match;
        proof_len += 1;
    }
    return try appendNsec3Set(response, zone, chain, proof[0..proof_len]);
}

/// Append the NSEC3 records of a proof, each one once. False when a record
/// of the proof carries no signature, so the proof is refused rather than
/// sent half-signed.
fn appendNsec3Set(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    chain: *const Nsec3Chain,
    indices: []const usize,
) !bool {
    for (indices, 0..) |index, position| {
        var repeated = false;
        for (indices[0..position]) |earlier| {
            if (earlier == index) repeated = true;
        }
        if (repeated) continue;
        if (!try appendNsec3(response, zone, chain, index)) return false;
    }
    return true;
}

/// Append one NSEC3 record and the RRSIG that covers it: a proof RRset that
/// carries no signature authenticates nothing (RFC 4035 section 5.4). False
/// when the zone holds no RRSIG over the record: an unsigned proof is worse
/// than no proof, so the caller answers server failure instead.
fn appendNsec3(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    chain: *const Nsec3Chain,
    index: usize,
) !bool {
    const entries = chain.entries orelse return false;
    const record = entries[index].record;
    const signature = nsec3Signature(zone, record.ownerText()) orelse return false;
    const rr = try toResourceRecord(record, null);
    try response.authorities.append(rr);
    try response.authorities.append(signature);
    return true;
}

/// RFC 5155 section 7.2.7: a referral to an unsigned subzone carries the
/// proof that the delegation may be unsigned. Under an Opt-Out chain the
/// delegation has no NSEC3 of its own, so the proof is the closest provable
/// encloser proof of the delegation name, whose NSEC3 that covers the next
/// closer name carries the Opt-Out flag. A chain that cannot prove that
/// leaves the referral the way it was.
fn appendReferralProofs(
    response: *dns_message.Message,
    zone: *const zone_index.Zone,
    authorities: []const zone_parser.ZoneRecord,
) !void {
    const delegation = delegationOwner(authorities) orelse return;
    var chain = try nsec3Chain(response.allocator, zone);
    defer chain.deinit(response.allocator);
    const entries = chain.entries orelse return;
    if (!chain.consistent) return;
    const name = dns_name.Name.fromText(delegation) catch return;
    const origin = dns_name.Name.fromText(zone.originText()) catch return;
    const encloser = nsec3ClosestEncloser(&chain, name, origin) orelse return;
    // RFC 5155 section 7.2.7: the NSEC3 that covers the next closer name
    // for the delegation must carry the Opt-Out flag.
    if (!entries[encloser.cover].opt_out) return;
    const proof = [_]usize{ encloser.match, encloser.cover };
    const before = response.authorities.len;
    if (!try appendNsec3Set(response, zone, &chain, proof[0..])) {
        response.authorities.len = before;
        return;
    }
    // RFC 5155 section 7.3: the apex NSEC3PARAM states the parameters of the
    // chain, so a validator can check the hash the proof was built with.
    try appendApexNsec3Param(response, zone);
}

/// The owner of the NS RRset a referral carries: the delegation the referral
/// points at (RFC 5155 section 8.9).
fn delegationOwner(authorities: []const zone_parser.ZoneRecord) ?[]const u8 {
    for (authorities) |record| {
        if (!record.rrtype.eql(.NS)) continue;
        return record.ownerText();
    }
    return null;
}

/// The RRSIG that covers an NSEC3 RRset (RFC 4035 section 5.4).
fn nsec3Signature(zone: *const zone_index.Zone, owner_text: []const u8) ?dns_record.ResourceRecord {
    var index: usize = 0;
    while (index < zone.records.len) : (index += 1) {
        const candidate = zone.records.items[index];
        if (!candidate.rrtype.eql(.RRSIG)) continue;
        if (!std.ascii.eqlIgnoreCase(candidate.ownerText(), owner_text)) continue;
        const rr = toResourceRecord(candidate, null) catch continue;
        const raw = switch (rr.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const covered = dns_dnssec.rrsigCovers(raw) catch continue;
        if (covered != dns_types.RecordType.NSEC3.code()) continue;
        return rr;
    }
    return null;
}

// The proof-record strip moved to src/dns/dnssec.zig (RFC 3225/RFC 3597);
// the authoritative path calls dns_dnssec.stripProofRecords below.

pub fn buildRefusedResponse(request: dns_message.Message) !dns_message.Message {
    const q = request.question orelse return Error.MissingQuestion;
    return buildEmptyResponse(request, q, if (q.qclass.eql(dns_types.Class.IN)) .refused else .notimp);
}

/// RFC 8914 section 4.16: "The server is unable to respond to the request
/// because the domain is on a blocklist due to an internal security policy
/// imposed by the operator of the server resolving or forwarding the query."
pub const EDE_BLOCKED: u16 = 15;
/// RFC 8914 section 2: the EDE EDNS0 option code is 15.
const ede_option_code: u16 = 15;
/// RFC 8914 section 3: the EXTRA-TEXT says why the answer is what it is.
/// It names the operator's policy and nothing else, so it tells the client
/// no more than the INFO-CODE already does.
const ede_blocked_text: []const u8 = "blocked by policy";

/// A refusal that says why: the operator's blocklist refused the name, which
/// is a policy decision and not a broken server.
pub fn buildBlockedResponse(request: dns_message.Message) !dns_message.Message {
    var response = try buildRefusedResponse(request);
    errdefer response.deinit();
    appendEde(&response, EDE_BLOCKED, ede_blocked_text);
    return response;
}

/// RFC 8914 section 4.19: "An authoritative server or recursive resolver that
/// receives a query from an 'unauthorized' client can annotate its REFUSED
/// message with this code. Examples of 'unauthorized' clients are recursive
/// queries from IP addresses outside the network, blocklisted IP addresses,
/// local policy, etc."
pub const EDE_PROHIBITED: u16 = 18;
/// RFC 8914 section 3: the EXTRA-TEXT says why the answer is what it is.
/// It names the operator's policy and nothing else, the way the Blocked
/// refusal's text does.
const ede_prohibited_text: []const u8 = "prohibited by policy";

/// A refusal that says why: the operator's recursion ACL refused the client.
pub fn buildProhibitedResponse(request: dns_message.Message) !dns_message.Message {
    var response = try buildRefusedResponse(request);
    errdefer response.deinit();
    appendEde(&response, EDE_PROHIBITED, ede_prohibited_text);
    return response;
}

/// RFC 8914 section 2: the EDE option rides in the OPT record, and the RFC
/// allows it "in any response ... to a query that includes an OPT pseudo-RR",
/// so a query that carried no OPT gets no EDE option. The OPTION-DATA is the
/// 16-bit INFO-CODE followed by the EXTRA-TEXT, so the OPTION-LENGTH is two
/// plus the text's length.
fn appendEde(message: *dns_message.Message, code: u16, text: []const u8) void {
    if (message.edns == null) return;
    var data: [2 + 32]u8 = undefined;
    std.debug.assert(text.len <= 32);
    std.mem.writeInt(u16, data[0..2], code, .big);
    @memcpy(data[2..][0..text.len], text);
    _ = optOf(message).appendOption(ede_option_code, data[0 .. 2 + text.len]);
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
        .header = (header.ResponseFlags{ .rcode = rcode }).header(request.header),
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
        .header = (header.ResponseFlags{ .rcode = .no_error }).header(request.header),
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
/// must not carry the option more than once. RFC 7314 section 2 defines only
/// the zero-length query form of the EXPIRE option, so any other length is
/// malformed in the same way.
fn ednsOptionIsMalformed(request: *const dns_message.Message) bool {
    const options = ednsOptions(request) orelse return false;
    var offset: usize = 0;
    var zoneversion_seen: usize = 0;
    while (offset + 4 <= options.len) {
        const code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const option_len = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        offset += 4;
        if (option_len > options.len - offset) return false;
        switch (code) {
            dns_rdata.EDNS_ZONEVERSION_OPTION_CODE => {
                zoneversion_seen += 1;
                if (zoneversion_seen > 1 or option_len != 0) return true;
            },
            dns_rdata.EDNS_EXPIRE_OPTION_CODE => {
                if (option_len != 0) return true;
            },
            dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE => {
                // RFC 7828 section 3.2.1: the query form of the option is
                // empty, so any other length is malformed in the same way.
                if (option_len != 0) return true;
            },
            else => {},
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
    over_tcp: bool,
) void {
    const options = ednsOptions(request) orelse return;
    if (policy.nsid) |nsid| {
        // RFC 5001 section 2.2: query NSID payload data is ignored, so the
        // option's presence is the whole request.
        if (dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE) != null) {
            _ = optOf(response).appendOption(dns_rdata.EDNS_NSID_OPTION_CODE, nsid);
        }
    }
    // RFC 7314 section 3.1: the primary answers the EXPIRE option with the
    // zone's SOA EXPIRE field in seconds, network byte order. Section 3.3
    // keeps the option out of every answer this server is not authoritative
    // for, so a referral carries none.
    if (response.header.authoritative and
        dns_rdata.findOption(options, dns_rdata.EDNS_EXPIRE_OPTION_CODE) != null)
    {
        if (soaExpire(zone)) |expire| {
            var data: [4]u8 = undefined;
            std.mem.writeInt(u32, data[0..4], expire, .big);
            _ = optOf(response).appendOption(dns_rdata.EDNS_EXPIRE_OPTION_CODE, &data);
        }
    }
    // RFC 7828 section 3.3.2: a server that received the option on a TCP
    // session answers it with the idle timeout it applies to that session,
    // counted in units of 100 milliseconds. Section 3.3.1 says the option in
    // a UDP query is ignored, so only a TCP session is answered.
    if (over_tcp and dns_rdata.findOption(options, dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE) != null) {
        var data: [2]u8 = undefined;
        std.mem.writeInt(u16, data[0..2], policy.tcp_keepalive_timeout, .big);
        _ = optOf(response).appendOption(dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE, &data);
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

/// RFC 7314 section 3.1: the zone's SOA EXPIRE field, in seconds.
fn soaExpire(zone: *const zone_index.Zone) ?u32 {
    const record = zone.soa orelse return null;
    const rdata = zone_parser.parseRData(.SOA, record.rdataText()) catch return null;
    if (rdata != .SOA) return null;
    return rdata.SOA.expire;
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
    response.header.question_count = if (response.question == null) 0 else 1;
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

/// A zone that publishes an NSEC3 chain (RFC 5155 section 7.1). The chain
/// holds the two owner names the zone has, and every hash is the one the
/// python hashlib oracle produced: the iterated salted SHA-1 of the canonical
/// wire name, with salt "salt" and 2 iterations.
const nsec3_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\www IN A 192.0.2.1
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN NSEC3 1 0 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g A RRSIG
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 0 2 73616c74 65fkkv52vjbvs8mj22eis3lq4enpnpcf SOA NS DNSKEY RRSIG
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN RRSIG NSEC3 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN RRSIG NSEC3 8 1 3600 2000000000 1000000000 1234 example. QUJD
    \\
;

/// The same zone without the NSEC3 of "www.example.": the chain no longer
/// holds the name the query asks about.
const nsec3_incomplete_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\www IN A 192.0.2.1
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 0 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g SOA NS DNSKEY RRSIG
    \\
;

/// The same chain with no RRSIG over the NSEC3 records: a proof RRset that
/// carries no signature authenticates nothing (RFC 4035 section 5.4).
const nsec3_unsigned_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\www IN A 192.0.2.1
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN NSEC3 1 0 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g A RRSIG
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 0 2 73616c74 65fkkv52vjbvs8mj22eis3lq4enpnpcf SOA NS DNSKEY RRSIG
    \\
;

/// A zone with a wildcard at the apex whose chain holds the NSEC3 of the apex
/// and of the wildcard, but not the NSEC3 of "b.example.": the chain's
/// closest encloser is then the apex while the zone knows the deeper name.
const nsec3_wildcard_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\b IN A 192.0.2.5
    \\*.example. IN A 192.0.2.9
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 0 2 73616c74 mj2i9hhr1es2j0u1on9bhgvdkepn9sgk SOA NS DNSKEY RRSIG
    \\mj2i9hhr1es2j0u1on9bhgvdkepn9sgk IN NSEC3 1 0 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g A RRSIG
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN RRSIG NSEC3 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\mj2i9hhr1es2j0u1on9bhgvdkepn9sgk IN RRSIG NSEC3 8 1 3600 2000000000 1000000000 1234 example. QUJD
    \\
;

/// A zone whose NSEC3 chain carries the Opt-Out flag (RFC 5155 section 6):
/// the unsigned delegation "unsigned-sub.example." has no NSEC3 of its own,
/// and the chain covers its hash with the Opt-Out NSEC3 of "www.example.".
/// Every hash is the one the python hashlib oracle produced.
const nsec3_optout_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\www IN A 192.0.2.1
    \\unsigned-sub IN NS ns.unsigned-sub.example.
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN NSEC3 1 1 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g A RRSIG
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 1 2 73616c74 65fkkv52vjbvs8mj22eis3lq4enpnpcf SOA NS DNSKEY RRSIG
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN RRSIG NSEC3 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN RRSIG NSEC3 8 1 3600 2000000000 1000000000 1234 example. QUJD
    \\
;

/// The same chain with the Opt-Out flag clear: an NSEC3 without the flag
/// covers no unsigned delegation (RFC 5155 section 3.1.2.1), so the chain
/// denies the delegation instead of covering it and cannot prove the DS
/// NODATA (RFC 5155 section 6).
const nsec3_optout_clear_test_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
    \\@ IN NS ns.example.
    \\@ IN DNSKEY 257 3 8 QUJDRA==
    \\@ IN NSEC3PARAM 1 0 2 73616c74
    \\www IN A 192.0.2.1
    \\unsigned-sub IN NS ns.unsigned-sub.example.
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN NSEC3 1 0 2 73616c74 ermpp7q2mj4h4amfotejjmbehlb6k56g A RRSIG
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN NSEC3 1 0 2 73616c74 65fkkv52vjbvs8mj22eis3lq4enpnpcf SOA NS DNSKEY RRSIG
    \\65fkkv52vjbvs8mj22eis3lq4enpnpcf IN RRSIG NSEC3 8 2 3600 2000000000 1000000000 1234 example. QUJD
    \\ermpp7q2mj4h4amfotejjmbehlb6k56g IN RRSIG NSEC3 8 1 3600 2000000000 1000000000 1234 example. QUJD
    \\
;

/// The NSEC3 hashes of the zone above, as the hashlib oracle computed them.
const nsec3_apex_hash = [_]u8{ 0x76, 0xed, 0x9c, 0x9f, 0x42, 0xb4, 0xc9, 0x12, 0x2a, 0xcf, 0xc7, 0x5d, 0x39, 0xd9, 0x6e, 0x8d, 0x56, 0x6a, 0x14, 0xd0 };
const nsec3_www_hash = [_]u8{ 0x31, 0x5f, 0x4a, 0x7c, 0xa2, 0xfc, 0xd7, 0xfe, 0x22, 0xd3, 0x10, 0x9d, 0x2e, 0x0e, 0xba, 0x23, 0xaf, 0x9b, 0xe5, 0x8f };
const nsec3_missing_hash = [_]u8{ 0x52, 0xda, 0xc1, 0x03, 0x1c, 0x8a, 0xc4, 0x10, 0x94, 0x25, 0x7e, 0x33, 0xd2, 0x97, 0xb3, 0x00, 0x63, 0x65, 0xfb, 0x50 };
const nsec3_wildcard_hash = [_]u8{ 0xb4, 0xc5, 0x24, 0xc6, 0x3b, 0x0b, 0xb8, 0x29, 0x83, 0xc1, 0xc5, 0xd2, 0xb8, 0xc3, 0xed, 0xa3, 0xb3, 0x74, 0xf2, 0x14 };
const nsec3_unsigned_sub_hash = [_]u8{ 0x61, 0xb9, 0xf0, 0x9a, 0xcd, 0x45, 0x1c, 0x93, 0x07, 0xf7, 0x77, 0xb1, 0xb8, 0x67, 0x9a, 0xc1, 0x58, 0x83, 0xe0, 0xc4 };

/// The next hashed owner name an NSEC3 record names.
fn servedNextHash(record: dns_record.ResourceRecord) ?[20]u8 {
    const raw = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return null,
    };
    const rdata = dns_validate.parseNsec3Rdata(raw) orelse return null;
    if (rdata.next_hash.len != 20) return null;
    return rdata.next_hash[0..20].*;
}

/// The NSEC3 record a response carries whose owner hash is `target`.
fn servedNsec3Match(response: *const dns_message.Message, target: [20]u8) ?dns_record.ResourceRecord {
    for (response.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NSEC3)) continue;
        const owner = dns_validate.nsec3OwnerHash(record.owner) orelse continue;
        if (!std.mem.eql(u8, &owner, &target)) continue;
        return record;
    }
    return null;
}

/// The NSEC3 record a response carries whose span covers `target`.
fn servedNsec3Cover(response: *const dns_message.Message, target: [20]u8) ?dns_record.ResourceRecord {
    for (response.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NSEC3)) continue;
        const owner = dns_validate.nsec3OwnerHash(record.owner) orelse continue;
        const next = servedNextHash(record) orelse continue;
        if (!dns_validate.nsec3Covers(owner, next, target)) continue;
        return record;
    }
    return null;
}

/// The type bitmap an NSEC3 record carries.
fn servedNsec3Bitmap(record: dns_record.ResourceRecord) ?[]const u8 {
    const raw = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return null,
    };
    const rdata = dns_validate.parseNsec3Rdata(raw) orelse return null;
    return rdata.bitmap;
}

/// The Opt-Out flag of a served NSEC3 record (RFC 5155 section 3.1.2.1).
fn servedNsec3OptOut(record: dns_record.ResourceRecord) bool {
    const raw = switch (record.rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return false,
    };
    const rdata = dns_validate.parseNsec3Rdata(raw) orelse return false;
    return (rdata.flags & dns_validate.nsec3_opt_out) != 0;
}

test "an NSEC3 zone proves NODATA with the NSEC3 that matches the name (RFC 5155 7.2.3)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4470, "www.example.", .MX, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);

    // The proof is the NSEC3 whose owner hash is the hash of the queried name.
    const proof = servedNsec3Match(&response, nsec3_www_hash) orelse return error.TestExpectedEqual;
    const bitmap = servedNsec3Bitmap(proof) orelse return error.TestExpectedEqual;
    // Its bitmap names the types the name has and leaves the queried type and
    // CNAME clear, which is what makes it a denial (RFC 5155 section 7.2.3).
    try std.testing.expect(dns_dnssec.nsecBitmapHasType(bitmap, dns_types.RecordType.A.code()));
    try std.testing.expect(!dns_dnssec.nsecBitmapHasType(bitmap, dns_types.RecordType.MX.code()));
    try std.testing.expect(!dns_dnssec.nsecBitmapHasType(bitmap, dns_types.RecordType.CNAME.code()));

    // The proof RRset must be authenticated too (RFC 4035 section 5.4).
    var saw_signature = false;
    for (response.authorities.slice()) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const covered = dns_dnssec.rrsigCovers(raw) catch continue;
        if (covered == dns_types.RecordType.NSEC3.code()) saw_signature = true;
    }
    try std.testing.expect(saw_signature);
}

test "an NSEC3 zone proves NXDOMAIN with the closest encloser proof (RFC 5155 7.2.1, 7.2.2)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4471, "nothere.example.", .A, true), &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, response.header.rcode);

    // The closest encloser is "example.", proved by the NSEC3 that matches it.
    const encloser = servedNsec3Match(&response, nsec3_apex_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(encloser.rrtype.eql(.NSEC3));
    // The next closer "nothere.example." and the wildcard at the closest
    // encloser are covered by the NSEC3 that spans them.
    const cover = servedNsec3Cover(&response, nsec3_missing_hash) orelse return error.TestExpectedEqual;
    const cover_owner = dns_validate.nsec3OwnerHash(cover.owner) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &nsec3_www_hash, &cover_owner);
    // The wildcard at the closest encloser is "*.example.", and RFC 5155
    // section 7.2.2 proves the name with the hash of that unexpanded name.
    var wildcard_digest: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try dns_name.Name.fromText("*.example."), &[_]u8{ 0x73, 0x61, 0x6c, 0x74 }, 2, &wildcard_digest);
    try std.testing.expectEqualSlices(u8, &nsec3_wildcard_hash, &wildcard_digest);
    // The wildcard hash falls in the other arc of the chain than the hash of
    // the expanded name, so the record that covers it names the apex: the
    // proof carried the unexpanded wildcard, not the expanded one.
    const wildcard_cover = servedNsec3Cover(&response, nsec3_wildcard_hash) orelse return error.TestExpectedEqual;
    const wildcard_cover_owner = dns_validate.nsec3OwnerHash(wildcard_cover.owner) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, &wildcard_cover_owner);
    // The proof never claims the queried name exists.
    try std.testing.expect(servedNsec3Match(&response, nsec3_missing_hash) == null);
}

/// Every NSEC3 record of a proof must ride with the RRSIG that covers it
/// (RFC 4035 section 5.4): a proof that carries no signature authenticates
/// nothing.
fn expectNsec3ProofsSigned(response: *const dns_message.Message) !void {
    for (response.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NSEC3)) continue;
        var owner: [256]u8 = undefined;
        const owner_text = try record.owner.toText(&owner);
        var signed = false;
        for (response.authorities.slice()) |candidate| {
            if (!candidate.rrtype.eql(.RRSIG)) continue;
            var candidate_owner: [256]u8 = undefined;
            if (!std.ascii.eqlIgnoreCase(try candidate.owner.toText(&candidate_owner), owner_text)) continue;
            const raw = switch (candidate.rdata) {
                .Unknown => |*unknown| unknown.bytes(),
                else => continue,
            };
            const covered = dns_dnssec.rrsigCovers(raw) catch continue;
            if (covered == dns_types.RecordType.NSEC3.code()) signed = true;
        }
        try std.testing.expect(signed);
    }
}

test "a query for an NSEC3 owner name is a name error (RFC 5155 7.2.8)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The owner of an NSEC3 record is a hash of another name, so the name it
    // names does not exist in the zone (RFC 5155 section 7.2.8).
    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4478, "ermpp7q2mj4h4amfotejjmbehlb6k56g.example.", .A, true), &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, response.header.rcode);

    // The name error carries the closest encloser proof: the NSEC3 that
    // matches the closest encloser and the NSEC3 that covers the next closer.
    const encloser = servedNsec3Match(&response, nsec3_apex_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(encloser.rrtype.eql(.NSEC3));
    var next_closer: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try dns_name.Name.fromText("ermpp7q2mj4h4amfotejjmbehlb6k56g.example."), &[_]u8{ 0x73, 0x61, 0x6c, 0x74 }, 2, &next_closer);
    try std.testing.expect(servedNsec3Cover(&response, next_closer) != null);
    // And the NSEC3 that covers the wildcard at the closest encloser.
    const wildcard_cover = servedNsec3Cover(&response, nsec3_wildcard_hash) orelse return error.TestExpectedEqual;
    const wildcard_cover_owner = dns_validate.nsec3OwnerHash(wildcard_cover.owner) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &nsec3_apex_hash, &wildcard_cover_owner);
    // The proof never claims the hashed name exists.
    try std.testing.expect(servedNsec3Match(&response, next_closer) == null);

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);
}

test "an NXDOMAIN under a wildcard carries the wildcard proof (RFC 5155 7.2.2)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_wildcard_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The chain's closest encloser is the apex, where the wildcard lives, and
    // a wildcard matches only the name one label below it.
    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4479, "x.b.example.", .A, true), &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, response.header.rcode);

    // The proof carries the NSEC3 that matches the wildcard at the closest
    // encloser, which no other record can state (RFC 5155 section 7.2.2).
    const wildcard = servedNsec3Match(&response, nsec3_wildcard_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(wildcard.rrtype.eql(.NSEC3));
    // And the NSEC3 that covers the next closer below the closest encloser.
    var next_closer: [20]u8 = undefined;
    dns_dnssec.nsec3Hash(try dns_name.Name.fromText("b.example."), &[_]u8{ 0x73, 0x61, 0x6c, 0x74 }, 2, &next_closer);
    try std.testing.expect(servedNsec3Cover(&response, next_closer) != null);

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);
}

test "an NSEC3 denial carries the apex NSEC3PARAM (RFC 5155 7.3)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4476, "www.example.", .MX, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    // The parameters of the chain travel with the proof, so a validator can
    // check the hash the proof was built with.
    var saw_param = false;
    for (response.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NSEC3PARAM)) continue;
        saw_param = true;
        var owner: [256]u8 = undefined;
        try std.testing.expectEqualStrings("example.", try record.owner.toText(&owner));
    }
    try std.testing.expect(saw_param);
}

test "an NSEC3 proof without a covering RRSIG is refused, not sent unsigned" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_unsigned_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4477, "www.example.", .MX, true), &zone);
    // RFC 4035 section 5.4: a proof RRset that carries no signature
    // authenticates nothing, so the denial is refused rather than proved
    // with an unsigned record.
    try std.testing.expectEqual(header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
    for (response.authorities.slice()) |record| {
        try std.testing.expect(!record.rrtype.eql(.NSEC3));
    }
}

test "the NSEC3 proof rides along only when the query sets DO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const do_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4472, "nothere.example.", .A, true), &zone);
    try std.testing.expect(servedNsec3Match(&do_response, nsec3_apex_hash) != null);

    const plain_response = try buildResponse(try testDoQuery(arena.allocator(), 0x4473, "nothere.example.", .A, false), &zone);
    try std.testing.expectEqual(@as(u16, 1), plain_response.header.authority_count);
    try std.testing.expect(plain_response.authorities.items[0].rrtype.eql(.SOA));
    try std.testing.expect(servedNsec3Match(&plain_response, nsec3_apex_hash) == null);
}

test "an NSEC3 chain that does not cover the name is refused, not proved wrongly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_incomplete_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4474, "www.example.", .MX, true), &zone);
    try std.testing.expectEqual(header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
}

test "a DS query against an Opt-Out chain is answered with the closest provable encloser proof (RFC 5155 7.2.4)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_optout_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The delegation is unsigned and the chain holds no NSEC3 for it, so the
    // answer is a NODATA proved by the Opt-Out span that covers it.
    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4480, "unsigned-sub.example.", .DS, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);

    // The closest provable encloser is the apex, proved by the NSEC3 that
    // matches it (RFC 5155 section 7.2.1).
    const encloser = servedNsec3Match(&response, nsec3_apex_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(encloser.rrtype.eql(.NSEC3));
    // The next closer "unsigned-sub.example." is covered by the NSEC3 whose
    // Opt-Out flag the section 7.2.4 proof requires.
    const cover = servedNsec3Cover(&response, nsec3_unsigned_sub_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(servedNsec3OptOut(cover));
    // The chain never claims the delegation itself exists.
    try std.testing.expect(servedNsec3Match(&response, nsec3_unsigned_sub_hash) == null);

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);
}

test "a DS NODATA in a chain without the Opt-Out flag is refused, not proved wrongly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_optout_clear_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4481, "unsigned-sub.example.", .DS, true), &zone);
    // RFC 5155 section 7.2.4: the proof needs the NSEC3 that covers the next
    // closer to carry the Opt-Out flag, so a chain without one proves nothing.
    try std.testing.expectEqual(header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);
}

test "a DS NODATA at a name the chain holds keeps the matching NSEC3 proof (RFC 5155 7.2.4)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4482, "www.example.", .DS, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    // The chain holds the name, so the proof is the NSEC3 that matches it.
    const proof = servedNsec3Match(&response, nsec3_www_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(proof.rrtype.eql(.NSEC3));

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);
}

test "a DS query for a name that does not exist is answered with the name error proof (RFC 5155 7.2.2)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The name does not exist, so the answer is a name error and not a
    // no-data answer: RFC 5155 section 7.2.2 gives the name error proof.
    const query = try testDoQuery(arena.allocator(), 0x4483, "nothere.example.", .DS, true);
    const response = try buildResponse(query, &zone);
    try std.testing.expectEqual(header.Rcode.nxdomain, response.header.rcode);

    // The closest encloser is the apex, proved by the NSEC3 that matches it.
    const encloser = servedNsec3Match(&response, nsec3_apex_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(encloser.rrtype.eql(.NSEC3));
    // The NSEC3 that covers the next closer "nothere.example.".
    try std.testing.expect(servedNsec3Cover(&response, nsec3_missing_hash) != null);
    // And the NSEC3 that covers the wildcard at the closest encloser.
    try std.testing.expect(servedNsec3Cover(&response, nsec3_wildcard_hash) != null);
    // The proof never claims the queried name exists.
    try std.testing.expect(servedNsec3Match(&response, nsec3_missing_hash) == null);

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);

    // The project's own validator accepts the answer: it is a name error
    // proof (RFC 5155 section 8.4), so it validates, and without an anchor
    // the answer is insecure rather than secure.
    var anchors = dns_validate.Anchors{};
    const result = try dns_validate.validate(arena.allocator(), &anchors, query, response, &.{}, 1_500_000_000);
    try std.testing.expectEqual(dns_validate.Status.insecure, result.status);
}

test "a referral to an unsigned subzone carries the Opt-Out closest provable encloser proof (RFC 5155 7.2.7)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_optout_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The delegation is unsigned and the chain holds no NSEC3 for it, so the
    // referral says the delegation may be unsigned with the closest provable
    // encloser proof of section 7.2.7.
    const query = try testDoQuery(arena.allocator(), 0x4484, "unsigned-sub.example.", .A, true);
    const response = try buildResponse(query, &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(!response.header.authoritative);

    // The closest provable encloser is the apex, proved by the NSEC3 that
    // matches it (RFC 5155 section 7.2.1).
    const encloser = servedNsec3Match(&response, nsec3_apex_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(encloser.rrtype.eql(.NSEC3));
    // The next closer "unsigned-sub.example." is covered by the NSEC3 whose
    // Opt-Out flag section 7.2.7 requires.
    const cover = servedNsec3Cover(&response, nsec3_unsigned_sub_hash) orelse return error.TestExpectedEqual;
    try std.testing.expect(servedNsec3OptOut(cover));
    // The chain never claims the delegation itself exists.
    try std.testing.expect(servedNsec3Match(&response, nsec3_unsigned_sub_hash) == null);

    // Every proof record rides with the RRSIG that covers it.
    try expectNsec3ProofsSigned(&response);

    // The project's own validator accepts the answer: the referral proves the
    // delegation unsigned (RFC 5155 section 8.9).
    var anchors = dns_validate.Anchors{};
    const result = try dns_validate.validate(arena.allocator(), &anchors, query, response, &.{}, 1_500_000_000);
    try std.testing.expectEqual(dns_validate.Status.insecure, result.status);
}

test "a referral under a chain with no Opt-Out flag keeps the answer it had" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(nsec3_optout_clear_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const query = try testDoQuery(arena.allocator(), 0x4485, "unsigned-sub.example.", .A, true);
    const response = try buildResponse(query, &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(!response.header.authoritative);

    // The chain cannot prove the delegation unsigned: the NSEC3 that covers
    // the next closer name carries no Opt-Out flag (RFC 5155 section 6), so
    // the referral is the one the zone always answered, with no proof.
    try std.testing.expect(servedNsec3Match(&response, nsec3_apex_hash) == null);
    for (response.authorities.slice()) |record| {
        try std.testing.expect(!record.rrtype.eql(.NSEC3));
    }
}

test "a zone without an NSEC3 chain keeps its NSEC denial proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(dnssec_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const response = try buildResponse(try testDoQuery(arena.allocator(), 0x4475, "www.example.", .AAAA, true), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    var saw_nsec = false;
    for (response.authorities.slice()) |record| {
        if (record.rrtype.eql(.NSEC)) saw_nsec = true;
        try std.testing.expect(!record.rrtype.eql(.NSEC3));
    }
    try std.testing.expect(saw_nsec);

    // The bytes this zone has always answered with do not move.
    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    try std.testing.expectEqualSlices(u8, &nsec_zone_denial_bytes, writer.written());
}

/// The bytes the NSEC-only zone answered a NODATA query with before the
/// NSEC3 denial path existed: the negative SOA and the NSEC proof.
const nsec_zone_denial_bytes = [_]u8{
    0x44, 0x75, 0x84, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x10, 0x00, 0x06, 0x00, 0x01, 0x00,
    0x00, 0x01, 0x2c, 0x00, 0x26, 0x02, 0x6e, 0x73, 0xc0, 0x10, 0x0a, 0x68,
    0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x10, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x03, 0x84, 0x00,
    0x12, 0x75, 0x00, 0x00, 0x00, 0x01, 0x2c, 0xc0, 0x0c, 0x00, 0x2f, 0x00,
    0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x15, 0x03, 0x77, 0x77, 0x77, 0x07,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x00, 0x06, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00,
};

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

/// A reply for the truncation tests: `answers` A records in the answer
/// section, `authorities` A records in the authority section, and
/// `additionals` A records of extra data in the additional section.
fn truncationTestMessage(
    allocator: std.mem.Allocator,
    authoritative: bool,
    answers: usize,
    authorities: usize,
    additionals: usize,
) !dns_message.Message {
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = 0x1234, .qr = true, .authoritative = authoritative },
        .question = .{
            .name = try dns_name.Name.fromText("www.example."),
            .qtype = .A,
            .qclass = .IN,
        },
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
    };
    errdefer message.deinit();
    const owner = try dns_name.Name.fromText("www.example.");
    var index: usize = 0;
    while (index < answers) : (index += 1) {
        try message.answers.append(.{
            .owner = owner,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 1 } },
        });
    }
    index = 0;
    while (index < authorities) : (index += 1) {
        try message.authorities.append(.{
            .owner = owner,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 2 } },
        });
    }
    index = 0;
    while (index < additionals) : (index += 1) {
        try message.additionals.append(.{
            .owner = owner,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 3 } },
        });
    }
    try setHeaderCounts(&message);
    return message;
}

test "RFC 2181 section 9: an answer whose additional section does not fit is sent without it and without TC" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 40);
    defer message.deinit();

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // "The TC bit should not be set merely because some extra information
    // could have been included, but there was insufficient room."
    try std.testing.expect(!parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.additional_count);
    try std.testing.expectEqual(@as(usize, 0), parsed.additionals.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &parsed.answers.items[0].rdata.A);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &parsed.authorities.items[0].rdata.A);
    try std.testing.expect(reply.len <= CLASSIC_UDP_MESSAGE_SIZE);
}

test "RFC 6891 section 6.1.1: a reply without the additional section keeps the OPT record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 40);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The data records of the additional section are gone and the TC bit is
    // clear, but the OPT stays: the request carried one, so the reply must
    // carry one too.
    try std.testing.expect(!parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expect(parsed.additionals.items[0].rrtype.eql(.OPT));
    try std.testing.expectEqual(@as(u16, 512), parsed.edns.?.udp_payload_size);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
}

test "RFC 2181 section 9: an answer whose answer section does not fit still sets TC" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 40, 0, 0);
    defer message.deinit();

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The whole RRSet is required in the reply, so the client must retry
    // over TCP.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expect(reply.len <= CLASSIC_UDP_MESSAGE_SIZE);
}

test "RFC 2181 section 9: a referral whose glue does not fit keeps TC" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), false, 0, 1, 40);
    defer message.deinit();

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // RFC 9471 section 3.1: a referral that cannot hold the glue of its
    // in-domain name servers sets TC.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    try std.testing.expect(reply.len <= CLASSIC_UDP_MESSAGE_SIZE);
}

test "RFC 2181 section 9: a reply that fits is sent byte for byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 1);
    defer message.deinit();

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    try std.testing.expectEqualSlices(u8, writer.written(), reply);
}

test "RFC 2181 section 9: the signed path omits the additional section the same way" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const tsig = @import("../dns/tsig.zig");

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 40);
    defer message.deinit();
    var mac_bytes: [32]u8 = undefined;
    @memset(&mac_bytes, 0);
    try message.additionals.append(.{
        .owner = try dns_name.Name.fromText("key."),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = try dns_rdata.Tsig.init(
            try dns_name.Name.fromText("hmac-sha256."),
            1_700_000_000,
            300,
            &mac_bytes,
            0x1234,
            0,
            &.{},
        ) },
    });
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    const signed = try tsig.sign(writer.written(), secret, final.owner, final.tsig, null);
    try tsig.patchMac(encoded[0..writer.len()], final, signed.slice());

    var output: [2048]u8 = undefined;
    const reply = try truncateSignedClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    try std.testing.expect(!parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    // The extra data is gone; the TSIG a signed message ends with stays.
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expect(parsed.additionals.items[0].rrtype.eql(.TSIG));

    // The MAC is computed over the reply as it goes on the wire, so the
    // caller recomputes it and the message still authenticates.
    const reply_final = (try tsig.parseFinalAdditional(reply)).?;
    const resigned = try tsig.sign(reply, secret, reply_final.owner, reply_final.tsig, null);
    try tsig.patchMac(@constCast(reply), reply_final, resigned.slice());
    _ = try tsig.verify(reply, secret, null, tsig.minimumMacLength(.hmac_sha256));
}

/// The EDE option a message carries, or null when it carries none.
fn edeOptionOf(message: *const dns_message.Message) ?[]const u8 {
    const options = ednsOptions(message) orelse return null;
    return dns_rdata.findOption(options, ede_option_code);
}

test "RFC 8914 section 3: a truncated answer drops its EDE option and sets TC" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 40, 0, 0);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    appendEde(&message, EDE_BLOCKED, ede_blocked_text);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The EDE option is the first thing a shortened message drops, and the
    // TC bit says the message is not the whole one.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expect(edeOptionOf(&parsed) == null);
    // The OPT record stays: the DO bit and the payload size are header
    // fields of the record, not the option.
    try std.testing.expect(parsed.edns != null);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u16, 512), parsed.edns.?.udp_payload_size);
}

test "RFC 8914 section 3: the answer and authority section survive the EDE drop" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 40);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    appendEde(&message, EDE_BLOCKED, ede_blocked_text);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The answer and the authority section stay, the EDE option goes, and
    // the TC bit says the message was shortened.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    try std.testing.expect(edeOptionOf(&parsed) == null);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
}

test "RFC 8914 section 3: an answer that fits keeps its EDE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 0);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    appendEde(&message, EDE_BLOCKED, ede_blocked_text);
    try setHeaderCounts(&message);

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);

    var output: [512]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);

    // A message that fits goes out byte for byte, the EDE option and all.
    try std.testing.expectEqualSlices(u8, writer.written(), reply);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);
    try std.testing.expect(!parsed.header.truncated);
    try std.testing.expect(edeOptionOf(&parsed) != null);
}

test "RFC 8914 section 3: the signed path drops the EDE option the same way" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const tsig = @import("../dns/tsig.zig");

    var message = try truncationTestMessage(arena.allocator(), true, 1, 1, 40);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    appendEde(&message, EDE_BLOCKED, ede_blocked_text);
    var mac_bytes: [32]u8 = undefined;
    @memset(&mac_bytes, 0);
    try message.additionals.append(.{
        .owner = try dns_name.Name.fromText("key."),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = try dns_rdata.Tsig.init(
            try dns_name.Name.fromText("hmac-sha256."),
            1_700_000_000,
            300,
            &mac_bytes,
            0x1234,
            0,
            &.{},
        ) },
    });
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    const final = (try tsig.parseFinalAdditional(writer.written())).?;
    const secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    const signed = try tsig.sign(writer.written(), secret, final.owner, final.tsig, null);
    try tsig.patchMac(encoded[0..writer.len()], final, signed.slice());

    var output: [2048]u8 = undefined;
    const reply = try truncateSignedClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The EDE option goes, the answer and the authority section stay, and
    // the TSIG a signed message ends with stays.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    try std.testing.expect(edeOptionOf(&parsed) == null);
    try std.testing.expectEqual(@as(usize, 2), parsed.additionals.len);
    try std.testing.expect(parsed.additionals.items[0].rrtype.eql(.OPT));
    try std.testing.expect(parsed.additionals.items[1].rrtype.eql(.TSIG));

    // The MAC is computed over the reply as it goes on the wire, so the
    // caller recomputes it and the message still authenticates.
    const reply_final = (try tsig.parseFinalAdditional(reply)).?;
    const resigned = try tsig.sign(reply, secret, reply_final.owner, reply_final.tsig, null);
    try tsig.patchMac(@constCast(reply), reply_final, resigned.slice());
    _ = try tsig.verify(reply, secret, null, tsig.minimumMacLength(.hmac_sha256));
}

/// The secret the truncation tests sign the reply with.
const truncation_test_secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";

/// A signed reply for the truncation tests: the OPT record a request with
/// EDNS(0) is answered with, the TSIG record the signed path ends with, and
/// `answers` A records in the answer section.
fn signedTruncationTestMessage(allocator: std.mem.Allocator, answers: usize) !dns_message.Message {
    var message = try truncationTestMessage(allocator, true, answers, 0, 0);
    errdefer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    var mac_bytes: [32]u8 = undefined;
    @memset(&mac_bytes, 0);
    try message.additionals.append(.{
        .owner = try dns_name.Name.fromText("key."),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = try dns_rdata.Tsig.init(
            try dns_name.Name.fromText("hmac-sha256."),
            1_700_000_000,
            300,
            &mac_bytes,
            0x1234,
            0,
            &.{},
        ) },
    });
    try setHeaderCounts(&message);
    return message;
}

/// Sign the message the way the server signs a reply, so the truncation
/// tests start from a message a client would accept.
fn signTruncationTestMessage(encoded: []u8, length: usize) !void {
    const tsig = @import("../dns/tsig.zig");
    const final = (try tsig.parseFinalAdditional(encoded[0..length])).?;
    const signed = try tsig.sign(encoded[0..length], truncation_test_secret, final.owner, final.tsig, null);
    try tsig.patchMac(encoded[0..length], final, signed.slice());
}

test "RFC 6891 section 6.1.1: a signed answer too large for the datagram keeps its OPT record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try signedTruncationTestMessage(arena.allocator(), 40);
    defer message.deinit();
    message.header.rcode = .nxdomain;

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);
    try signTruncationTestMessage(&encoded, writer.len());

    var output: [2048]u8 = undefined;
    const reply = try truncateSignedClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The answer section does not fit, so it is gone and the TC bit says
    // the message is not the whole one.
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    // The RCODE is what the client sees, so it stays: the OPT record's
    // extended-rcode byte holds the upper eight bits of the twelve-bit code.
    try std.testing.expectEqual(header.Rcode.nxdomain, parsed.header.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.extended_rcode);
    // The OPT record stays: the request carried one, so the reply must
    // carry one too, and the DO bit and the payload size are header fields
    // of that record.
    try std.testing.expectEqual(@as(u16, 2), parsed.header.additional_count);
    try std.testing.expect(parsed.additionals.items[0].rrtype.eql(.OPT));
    try std.testing.expect(parsed.edns != null);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u16, 512), parsed.edns.?.udp_payload_size);
}

test "RFC 8945 section 4.2: the TSIG is the last record of a truncated signed reply" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const tsig = @import("../dns/tsig.zig");

    var message = try signedTruncationTestMessage(arena.allocator(), 40);
    defer message.deinit();

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);
    try signTruncationTestMessage(&encoded, writer.len());

    var output: [2048]u8 = undefined;
    const reply = try truncateSignedClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The additional section is the OPT record and the TSIG a signed
    // message ends with.
    try std.testing.expectEqual(@as(usize, 2), parsed.additionals.len);
    try std.testing.expect(parsed.additionals.items[1].rrtype.eql(.TSIG));

    // The MAC is computed over the reply as it goes on the wire, so the
    // caller recomputes it and the message still authenticates.
    const reply_final = (try tsig.parseFinalAdditional(reply)).?;
    const resigned = try tsig.sign(reply, truncation_test_secret, reply_final.owner, reply_final.tsig, null);
    try tsig.patchMac(@constCast(reply), reply_final, resigned.slice());
    _ = try tsig.verify(reply, truncation_test_secret, null, tsig.minimumMacLength(.hmac_sha256));
}

test "RFC 8914 section 3: the signed truncation drops the EDE option and keeps the OPT record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try signedTruncationTestMessage(arena.allocator(), 40);
    defer message.deinit();
    appendEde(&message, EDE_BLOCKED, ede_blocked_text);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);
    try signTruncationTestMessage(&encoded, writer.len());

    var output: [2048]u8 = undefined;
    const reply = try truncateSignedClassicUdpResponse(writer.written(), &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), reply);

    // The EDE option is the first thing a shortened message drops, and the
    // OPT record it rode in stays.
    try std.testing.expect(edeOptionOf(&parsed) == null);
    try std.testing.expect(parsed.header.truncated);
    try std.testing.expectEqual(@as(u16, 2), parsed.header.additional_count);
    try std.testing.expect(parsed.edns != null);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u16, 512), parsed.edns.?.udp_payload_size);
}

test "the unsigned truncation sends the bytes it has always sent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try truncationTestMessage(arena.allocator(), true, 40, 0, 0);
    defer message.deinit();
    message.edns = .{ .udp_payload_size = 512, .extended_rcode = 0, .version = 0, .dnssec_ok = true };
    try appendOpt(&message);
    try setHeaderCounts(&message);

    var encoded: [2048]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try message.encode(&writer);
    try std.testing.expect(writer.len() > CLASSIC_UDP_MESSAGE_SIZE);

    var output: [2048]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);

    // The header with the TC bit set, the question, and the OPT record.
    const expected = [_]u8{
        0x12, 0x34, 0x86, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, reply);
}

test "RFC 8914 section 3: the RRSIGs over the records that remain still verify" {
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
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var key = try zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(arena.allocator());
    try zone_signer.signZone(arena.allocator(), &zone, &key, .{ .inception = 1_000_000_000, .expiration = 2_000_000_000 });

    const query = try testDoQuery(arena.allocator(), 0x4a10, "www.example.", .A, true);
    var answer = try buildResponse(query, &zone);
    defer answer.deinit();
    appendEde(&answer, EDE_BLOCKED, ede_blocked_text);
    // The extra data of the additional section is what does not fit.
    var index: usize = 0;
    while (index < 100) : (index += 1) {
        try answer.additionals.append(.{
            .owner = try dns_name.Name.fromText("www.example."),
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 3 } },
        });
    }
    try setHeaderCounts(&answer);

    var encoded: [4096]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try answer.encode(&writer);
    try std.testing.expect(writer.len() > answer.edns.?.udp_payload_size);

    var output: [4096]u8 = undefined;
    const reply = try truncateClassicUdpResponse(writer.written(), &output);
    const truncated = try dns_message.Message.parse(arena.allocator(), reply);

    // The answer keeps its A record and the RRSIG over it, and the EDE
    // option is gone.
    try std.testing.expectEqual(@as(u16, 2), truncated.header.answer_count);
    try std.testing.expect(truncated.answers.items[1].rrtype.eql(.RRSIG));
    try std.testing.expect(edeOptionOf(&truncated) == null);

    // The signature over the record that remains still verifies: the
    // truncation dropped an option, not a record.
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{ .owner = try dns_name.Name.fromText("example."), .rrtype = .DNSKEY, .rdata = dnskey_rdata };
    anchors.len = 1;
    try std.testing.expectEqual(dns_validate.Status.secure, (try dns_validate.validate(arena.allocator(), &anchors, query, truncated, &.{}, 1_500_000_000)).status);
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
        const response = try buildResponseWithPolicy(request, &zone, .{}, null, false);
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
    const declined_response = try buildResponseWithPolicy(declined, &zone, .{ .zoneversion = false }, null, false);
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

test "RFC 7314 section 3.1: an EXPIRE request is answered with the zone's SOA EXPIRE value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request_options = [_]TestOption{.{
        .code = dns_rdata.EDNS_EXPIRE_OPTION_CODE,
        .data = &.{},
    }};
    const request = try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &request_options);
    const response = try buildResponse(request, &zone);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    // Section 3.1: a length-4 option with the zone's SOA EXPIRE field, 1209600
    // seconds, in network byte order.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x12, 0x75, 0x00 }, dns_rdata.findOption(options, dns_rdata.EDNS_EXPIRE_OPTION_CODE).?);
}

test "RFC 7314 section 2: the EXPIRE option is answered only when it was asked for" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // A query without the option is answered exactly as before: the OPT record
    // carries no option at all.
    const plain = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{}), &zone);
    const plain_options = ednsOptions(&plain) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 0), plain_options.len);
}

test "RFC 7314 section 3.3: a non-authoritative answer carries no EXPIRE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request_options = [_]TestOption{.{
        .code = dns_rdata.EDNS_EXPIRE_OPTION_CODE,
        .data = &.{},
    }};
    // The delegation to child.example.com. is a referral: this server is not
    // authoritative for that zone, so the option stays out of the answer.
    const request = try testOptionsQuery(arena.allocator(), "www.child.example.com.", .A, &request_options);
    const response = try buildResponse(request, &zone);
    try std.testing.expect(!response.header.authoritative);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_EXPIRE_OPTION_CODE) == null);
}

test "RFC 7314 section 2: a malformed EXPIRE query is answered FORMERR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const empty = TestOption{ .code = dns_rdata.EDNS_EXPIRE_OPTION_CODE, .data = &.{} };
    const payload_in_query = [_]TestOption{.{
        .code = dns_rdata.EDNS_EXPIRE_OPTION_CODE,
        .data = &.{ 0x00, 0x12, 0x75, 0x00 },
    }};
    const response = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &payload_in_query), &zone);
    try std.testing.expectEqual(header.Rcode.formerr, response.header.rcode);
    try std.testing.expectEqual(@as(usize, 0), response.answers.len);

    // The zero-length query form is the well-formed request and is answered
    // normally.
    const ok = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{empty}), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, ok.header.rcode);
}

test "RFC 7828 section 3.3.2: a TCP query with the keepalive option is answered with the server's idle timeout" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request_options = [_]TestOption{.{
        .code = dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE,
        .data = &.{},
    }};
    const request = try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &request_options);
    const response = try buildResponseWithPolicy(request, &zone, .{}, null, true);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    // Section 3.1: the option carries the idle timeout in units of 100
    // milliseconds, so five seconds is 50, in network byte order.
    try std.testing.expectEqualSlices(u8, &.{ 0, 50 }, dns_rdata.findOption(options, dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE).?);
    // The framing is the code, the length, and the timeout, and nothing else.
    try std.testing.expectEqualSlices(u8, &.{ 0, 11, 0, 2, 0, 50 }, options);
}

test "RFC 7828 section 3.3.1: the keepalive option is answered only on a TCP session" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request_options = [_]TestOption{.{
        .code = dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE,
        .data = &.{},
    }};
    // Section 3.3.1: a server that receives the option in a UDP query ignores
    // it, so the answer carries no such option.
    const request = try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &request_options);
    const response = try buildResponseWithPolicy(request, &zone, .{}, null, false);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE) == null);
}

test "RFC 7828 section 3.3.2: a query without the keepalive option is answered with none" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const request = try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{});
    const response = try buildResponseWithPolicy(request, &zone, .{}, null, true);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE) == null);
}

test "RFC 7828 section 3.2.1: a malformed keepalive query is answered FORMERR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 3.2.1: the query form of the option is empty, so a query that
    // carries a timeout in it is malformed and is answered FORMERR.
    const payload_in_query = [_]TestOption{.{
        .code = dns_rdata.EDNS_TCP_KEEPALIVE_OPTION_CODE,
        .data = &.{ 0x00, 0x32 },
    }};
    const response = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &payload_in_query), &zone, .{}, null, true);
    try std.testing.expectEqual(header.Rcode.formerr, response.header.rcode);
    try std.testing.expectEqual(@as(usize, 0), response.answers.len);
}

test "RFC 5001: NSID is echoed only when configured and only when requested" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const nsid = [_]TestOption{.{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{} }};
    const policy = AnswerPolicy{ .nsid = "ns1.example.com." };

    const answered = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &nsid), &zone, policy, null, false);
    const answered_options = ednsOptions(&answered) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, policy.nsid.?, dns_rdata.findOption(answered_options, dns_rdata.EDNS_NSID_OPTION_CODE).?);

    // Section 2.2: the option is never sent to a resolver that did not ask.
    const unsolicited = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &.{}), &zone, policy, null, false);
    const unsolicited_options = ednsOptions(&unsolicited) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(unsolicited_options, dns_rdata.EDNS_NSID_OPTION_CODE) == null);

    // The server has no identifier of its own to give until one is configured.
    const unconfigured = try buildResponse(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &nsid), &zone);
    const unconfigured_options = ednsOptions(&unconfigured) orelse return error.TestExpectedEqual;
    try std.testing.expect(dns_rdata.findOption(unconfigured_options, dns_rdata.EDNS_NSID_OPTION_CODE) == null);

    // Section 2.2: NSID payload data in a query is ignored, and answering with
    // the server's own identifier is what the option's presence asked for.
    const with_payload = [_]TestOption{.{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{ 0xde, 0xad } }};
    const ignored = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &with_payload), &zone, policy, null, false);
    const ignored_options = ednsOptions(&ignored) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, policy.nsid.?, dns_rdata.findOption(ignored_options, dns_rdata.EDNS_NSID_OPTION_CODE).?);
}

test "RFC 5001: a repeated NSID request is answered with one identifier, not an error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 2.2 makes an unsolicited option the only error this option
    // carries, so a request that repeats it is answered, not refused.
    const repeated = [_]TestOption{
        .{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{} },
        .{ .code = dns_rdata.EDNS_NSID_OPTION_CODE, .data = &.{} },
    };
    const policy = AnswerPolicy{ .nsid = "ns1.example.com." };
    const response = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &repeated), &zone, policy, null, false);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    const options = ednsOptions(&response) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, policy.nsid.?, dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE).?);
    // One option and nothing else: the answer carries the identifier once, and
    // no option the query did not ask for rides along with it.
    try std.testing.expectEqual(4 + policy.nsid.?.len, options.len);
}

test "RFC 8145 section 4.3: a responder never answers with the edns-key-tag option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(zoneversion_test_zone);
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    const key_tag = [_]TestOption{.{ .code = dns_rdata.EDNS_KEY_TAG_OPTION_CODE, .data = &.{ 0x4a, 0x4c } }};
    const response = try buildResponseWithPolicy(try testOptionsQuery(arena.allocator(), "www.example.com.", .A, &key_tag), &zone, .{ .nsid = "ns1" }, null, false);
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
    const answer_hinfo = response.answers.items[0].rdata.HINFO;
    // Section 4.2: the CPU field is "RFC8482" and the OS field is the null
    // string.
    try std.testing.expectEqualStrings("RFC8482", answer_hinfo.cpuText());
    try std.testing.expectEqualStrings("", answer_hinfo.osText());

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    const round_trip = try dns_message.Message.parse(arena.allocator(), writer.written());
    try std.testing.expect(!round_trip.header.truncated);
    try std.testing.expectEqual(@as(u16, 1), round_trip.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), round_trip.header.additional_count);
    try std.testing.expect(round_trip.answers.items[0].rrtype.eql(hinfo_type));

    // Decode the answer straight off the wire from the RFC 1035 section 3.3.2
    // layout — CPU then OS, each a length octet plus that many octets, with
    // nothing after. Deliberately not the project's own HINFO reader, so the
    // two fields being swapped or a trailing octet fails here rather than
    // passing an encoder/decoder round trip that would agree with itself.
    // The answer is the last record in the message, so its RDATA is the tail
    // and the two octets before that tail are its RDLENGTH.
    const wire = writer.written();
    const hinfo = round_trip.answers.items[0].rdata.HINFO;
    const cpu = hinfo.cpuText();
    const os = hinfo.osText();
    const rdata_len = 1 + cpu.len + 1 + os.len;
    try std.testing.expectEqual(
        @as(u16, 9),
        std.mem.readInt(u16, wire[wire.len - rdata_len - 2 ..][0..2], .big),
    );
    const hinfo_wire = wire[wire.len - rdata_len ..];
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

    // The typed fields rebuild to the octets the answer carries: the CPU
    // length, the CPU, the OS length, and the OS.
    var rebuilt: [16]u8 = undefined;
    var rebuilt_len: usize = 0;
    rebuilt[rebuilt_len] = @intCast(cpu.len);
    rebuilt_len += 1;
    @memcpy(rebuilt[rebuilt_len..][0..cpu.len], cpu);
    rebuilt_len += cpu.len;
    rebuilt[rebuilt_len] = @intCast(os.len);
    rebuilt_len += 1;
    @memcpy(rebuilt[rebuilt_len..][0..os.len], os);
    rebuilt_len += os.len;
    try std.testing.expectEqualSlices(u8, rebuilt[0..rebuilt_len], hinfo_wire);

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

    const configured = try buildResponseWithPolicy(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone, .{ .minimal_any_ttl = 300 }, null, false);
    try std.testing.expectEqual(@as(u32, 300), configured.answers.items[0].ttl);

    const default = try buildResponse(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(@as(u32, 86400), default.answers.items[0].ttl);
}

test "RFC 8482: the minimal ANY answer takes the TTL of the transport it arrived over" {
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

    // Section 4.4: the operator's TCP TTL answers a query that arrived over
    // TCP, the base TTL answers it over UDP.
    const policy = AnswerPolicy{ .minimal_any_ttl = 300, .minimal_any_ttl_tcp = 3600 };
    const udp = try buildResponseWithPolicy(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone, policy, null, false);
    const tcp = try buildResponseWithPolicy(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone, policy, null, true);
    try std.testing.expectEqual(@as(u32, 300), udp.answers.items[0].ttl);
    try std.testing.expectEqual(@as(u32, 3600), tcp.answers.items[0].ttl);

    // Without a TCP TTL the base TTL serves both transports.
    const both = try buildResponseWithPolicy(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone, .{ .minimal_any_ttl = 300 }, null, true);
    try std.testing.expectEqual(@as(u32, 300), both.answers.items[0].ttl);

    // Section 4.2: the synthesized HINFO is untouched, CPU "RFC8482" and the
    // null OS string.
    const hinfo = tcp.answers.items[0].rdata.HINFO;
    try std.testing.expectEqualStrings("RFC8482", hinfo.cpuText());
    try std.testing.expectEqualStrings("", hinfo.osText());

    // Nothing but the TTL changes between the two answers.
    var udp_wire: [512]u8 = undefined;
    var udp_writer = dns_writer.Writer.init(&udp_wire);
    try udp.encode(&udp_writer);
    var tcp_wire: [512]u8 = undefined;
    var tcp_writer = dns_writer.Writer.init(&tcp_wire);
    try tcp.encode(&tcp_writer);
    try std.testing.expectEqual(udp_writer.len(), tcp_writer.len());
    const udp_ttl = [_]u8{ 0x00, 0x00, 0x01, 0x2C };
    const ttl_at = std.mem.indexOf(u8, udp_writer.written(), &udp_ttl) orelse return error.TestUnexpectedResult;
    for (udp_writer.written(), tcp_writer.written(), 0..) |udp_byte, tcp_byte, index| {
        if (index >= ttl_at and index < ttl_at + 4) continue;
        try std.testing.expectEqual(udp_byte, tcp_byte);
    }
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, tcp_writer.written()[ttl_at..][0..4], .big));
}

test "RFC 8482: a DO=1 ANY query on a signed zone answers the HINFO with a valid RRSIG" {
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
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The RFC 8080 section 6.1 Ed25519 key, so nothing secret enters the
    // repository and the DNSKEY it derives is the one the RFC pins.
    var key = try zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(arena.allocator());
    const window = zone_signer.Options{ .inception = 1_000_000_000, .expiration = 2_000_000_000 };
    try zone_signer.signZone(arena.allocator(), &zone, &key, window);
    var session = zone_signer.Session.start(&key, window);
    defer session.deinit();

    const query = try testDoQuery(arena.allocator(), 0x4a02, "www.example.", .ANY, true);
    const answer = try buildResponseWithPolicy(query, &zone, .{}, &session, false);

    // Section 4.2: the synthesized HINFO, and -- because the zone is signed
    // and the query set DO=1 -- a valid RRSIG for the RRsets in the answer.
    try std.testing.expectEqual(@as(u16, 2), answer.header.answer_count);
    try std.testing.expect(answer.answers.items[0].rrtype.eql(hinfo_type));
    try std.testing.expect(answer.answers.items[1].rrtype.eql(.RRSIG));

    const rrsig = switch (answer.answers.items[1].rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return error.TestUnexpectedResult,
    };
    // RFC 4034 section 3.1.1: the type covered is the HINFO.
    try std.testing.expectEqual(hinfo_type.code(), std.mem.readInt(u16, rrsig[0..2], .big));
    // RFC 4034 section 3.1.3: the Labels field counts the owner name's
    // labels without the root label, so "www.example." is 2.
    try std.testing.expectEqual(@as(u8, 2), rrsig[3]);
    // RFC 4034 section 3.1.4: the original TTL is the TTL the answer carries.
    try std.testing.expectEqual(answer.answers.items[0].ttl, std.mem.readInt(u32, rrsig[4..8], .big));
    // RFC 4034 section 3.1.6 and Appendix B: the key tag is the one of the
    // DNSKEY that validates the signature.
    try std.testing.expectEqual(dns_dnssec.keyTag(dnskey_rdata), std.mem.readInt(u16, rrsig[16..18], .big));

    // The signature itself is checked by the project's own validator, which
    // rebuilds the canonical RR form from the answer and verifies it against
    // the zone's own DNSKEY.
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{ .owner = try dns_name.Name.fromText("example."), .rrtype = .DNSKEY, .rdata = dnskey_rdata };
    anchors.len = 1;
    const result = try dns_validate.validate(arena.allocator(), &anchors, query, answer, &.{}, 1_500_000_000);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);

    // Without DO the answer carries no RRSIG, the rule the rest of the
    // authoritative path follows.
    const plain_query = try testDoQuery(arena.allocator(), 0x4a03, "www.example.", .ANY, false);
    const plain_answer = try buildResponseWithPolicy(plain_query, &zone, .{}, &session, false);
    try std.testing.expectEqual(@as(u16, 1), plain_answer.header.answer_count);
    try std.testing.expect(plain_answer.answers.items[0].rrtype.eql(hinfo_type));

    // The signed path takes the transport's TTL too, and the RRSIG carries
    // that TTL as its original TTL.
    const tcp_query = try testDoQuery(arena.allocator(), 0x4a04, "www.example.", .ANY, true);
    const tcp_answer = try buildResponseWithPolicy(tcp_query, &zone, .{ .minimal_any_ttl_tcp = 120 }, &session, true);
    try std.testing.expectEqual(@as(u32, 120), tcp_answer.answers.items[0].ttl);
    const tcp_rrsig = switch (tcp_answer.answers.items[1].rdata) {
        .Unknown => |*unknown| unknown.bytes(),
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(u32, 120), std.mem.readInt(u32, tcp_rrsig[4..8], .big));
}

test "RFC 8482: an unsigned zone answers the HINFO with no RRSIG" {
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
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // A zone that is not signed has no key to sign with, so the answer is the
    // synthesized HINFO alone.
    const query = try testDoQuery(arena.allocator(), 0x4a04, "www.example.", .ANY, true);
    const answer = try buildResponseWithPolicy(query, &zone, .{}, null, false);
    try std.testing.expectEqual(@as(u16, 1), answer.header.answer_count);
    try std.testing.expect(answer.answers.items[0].rrtype.eql(hinfo_type));
}

test "RFC 8482 section 4.1: an ANY query at an owner with more than one RRset answers a subset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\multi IN A 192.0.2.1
        \\multi IN AAAA 2001:db8::1
        \\multi IN TXT "hello"
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Section 4.1: the answer carries a subset of the owner's RRsets, and
    // section 7 keeps TC clear because the subset is not a truncation.
    const response = try buildResponse(try testQuery(arena.allocator(), "multi.home.arpa.", .ANY), &zone);
    try std.testing.expectEqual(header.Rcode.no_error, response.header.rcode);
    try std.testing.expect(!response.header.truncated);
    try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), response.header.authority_count);

    // The HINFO is the first RRset of the answer and keeps its own TTL.
    try std.testing.expect(response.answers.items[0].rrtype.eql(hinfo_type));
    try std.testing.expectEqual(@as(u32, 86400), response.answers.items[0].ttl);
    const hinfo = response.answers.items[0].rdata.HINFO;
    try std.testing.expectEqualStrings("RFC8482", hinfo.cpuText());
    try std.testing.expectEqualStrings("", hinfo.osText());

    // The second RRset is the one the rule selects: section 4.3's list puts A
    // ahead of AAAA, and the TXT is not in it. No other RRset comes with it.
    try std.testing.expect(response.answers.items[1].rrtype.eql(.A));
    try std.testing.expectEqual(@as(u32, 3600), response.answers.items[1].ttl);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &response.answers.items[1].rdata.A);
}

test "RFC 8482 section 4.1: the RRset that joins the HINFO keeps the zone's own TTL" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\multi 120 IN A 192.0.2.1
        \\multi 120 IN TXT "hello"
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The operator's TTL belongs to the synthesized HINFO alone; the RRset
    // that joins it is the zone's own and keeps the zone's own TTL.
    const udp = try buildResponseWithPolicy(try testQuery(arena.allocator(), "multi.home.arpa.", .ANY), &zone, .{ .minimal_any_ttl = 300 }, null, false);
    try std.testing.expectEqual(@as(u16, 2), udp.header.answer_count);
    try std.testing.expectEqual(@as(u32, 300), udp.answers.items[0].ttl);
    try std.testing.expectEqual(@as(u32, 120), udp.answers.items[1].ttl);

    // Section 4.4: the transport moves the HINFO's TTL, not the RRset's.
    const tcp = try buildResponseWithPolicy(try testQuery(arena.allocator(), "multi.home.arpa.", .ANY), &zone, .{ .minimal_any_ttl = 300, .minimal_any_ttl_tcp = 3600 }, null, true);
    try std.testing.expectEqual(@as(u16, 2), tcp.header.answer_count);
    try std.testing.expectEqual(@as(u32, 3600), tcp.answers.items[0].ttl);
    try std.testing.expectEqual(@as(u32, 120), tcp.answers.items[1].ttl);
}

test "RFC 8482 section 4.1: a DO=1 ANY query on a signed zone signs every RRset of the subset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\www IN TXT "hello"
        \\
    );
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The RFC 8080 section 6.1 Ed25519 key, so nothing secret enters the
    // repository and the DNSKEY it derives is the one the RFC pins.
    var key = try zone_signer.parseKey("ed25519 DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=\n");
    defer key.deinit();
    const dnskey_rdata = try key.dnskeyRdata(arena.allocator());
    const window = zone_signer.Options{ .inception = 1_000_000_000, .expiration = 2_000_000_000 };
    try zone_signer.signZone(arena.allocator(), &zone, &key, window);
    var session = zone_signer.Session.start(&key, window);
    defer session.deinit();

    const query = try testDoQuery(arena.allocator(), 0x4a05, "www.example.", .ANY, true);
    const answer = try buildResponseWithPolicy(query, &zone, .{}, &session, false);

    // The HINFO, the RRset that joined it, and an RRSIG over each of them:
    // section 4.2 asks for a valid RRSIG for the RRsets in the answer.
    try std.testing.expectEqual(@as(u16, 4), answer.header.answer_count);
    try std.testing.expect(answer.answers.items[0].rrtype.eql(hinfo_type));
    try std.testing.expect(answer.answers.items[1].rrtype.eql(.A));

    var hinfo_rrsig: ?[]const u8 = null;
    var a_rrsig: ?[]const u8 = null;
    for (answer.answers.items) |record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return error.TestUnexpectedResult,
        };
        // RFC 4034 section 3.1.1: the type covered is the RRset's own type.
        const covered = std.mem.readInt(u16, raw[0..2], .big);
        if (covered == hinfo_type.code()) hinfo_rrsig = raw;
        if (covered == dns_types.RecordType.A.code()) a_rrsig = raw;
    }
    try std.testing.expect(hinfo_rrsig != null);
    try std.testing.expect(a_rrsig != null);

    // The signatures are checked by the project's own validator, which
    // rebuilds the canonical RR form from the answer and verifies it against
    // the zone's own DNSKEY.
    var anchors = dns_validate.Anchors{};
    anchors.items[0] = .{ .owner = try dns_name.Name.fromText("example."), .rrtype = .DNSKEY, .rdata = dnskey_rdata };
    anchors.len = 1;
    const result = try dns_validate.validate(arena.allocator(), &anchors, query, answer, &.{}, 1_500_000_000);
    try std.testing.expectEqual(dns_validate.Status.secure, result.status);
}

test "RFC 8482: the answers the subset does not reach keep their bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\alias IN CNAME dns
        \\deep.branch IN A 192.168.1.7
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // An owner with a single RRset answers the HINFO alone, a CNAME owner
    // answers with the CNAME RRset, an empty non-terminal keeps NODATA, and a
    // name that does not exist keeps NXDOMAIN. The bytes are the ones the
    // server sent before the subset existed.
    try expectAnswerHex(
        "12348400000100010000000003646e7304686f6d6504617270610000ff0001c00c000d0001000151800009075246433834383200",
        try buildResponse(try testQuery(arena.allocator(), "dns.home.arpa.", .ANY), &zone),
    );
    try expectAnswerHex(
        "12348400000100010000000005616c69617304686f6d6504617270610000ff0001c00c0005000100000e10000603646e73c012",
        try buildResponse(try testQuery(arena.allocator(), "alias.home.arpa.", .ANY), &zone),
    );
    try expectAnswerHex(
        "123484000001000000010000066272616e636804686f6d6504617270610000ff0001c0130006000100000e100027036e7331c0130a686f73746d6173746572c0130000000100000e10000003840012750000000e10",
        try buildResponse(try testQuery(arena.allocator(), "branch.home.arpa.", .ANY), &zone),
    );
    try expectAnswerHex(
        "12348403000100000001000004676f6e6504686f6d6504617270610000ff0001c0110006000100000e100027036e7331c0110a686f73746d6173746572c0110000000100000e10000003840012750000000e10",
        try buildResponse(try testQuery(arena.allocator(), "gone.home.arpa.", .ANY), &zone),
    );
}

/// Asserts the wire bytes of an answer against their hexadecimal form.
fn expectAnswerHex(expected_hex: []const u8, response: dns_message.Message) !void {
    var encoded: [512]u8 = undefined;
    var writer = dns_writer.Writer.init(&encoded);
    try response.encode(&writer);
    var expected: [512]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, decoded, writer.written());
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

// RFC 1035 section 4.1.1: the Z bit must be zero in all queries and
// responses, so a query that arrives with it set is answered with it clear.
test "a query with the reserved bit set is answered with the reserved bit clear" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.2
        \\
    );
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // A query received on the wire with the reserved Z bit set (flags
    // 0x0140: RD and Z).
    const query = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try std.testing.expect(query.header.reserved);

    const answer = try buildResponse(query, &zone);
    try std.testing.expect(answer.header.authoritative);
    try std.testing.expect(!answer.header.reserved);

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try answer.encode(&writer);
    const flags = std.mem.readInt(u16, encoded[2..4], .big);
    try std.testing.expectEqual(@as(u16, 0), flags & header.Flags.reserved);
}

// RFC 4035 section 3.1.6: a name server MUST NOT set AD unless it considers
// every RRset in the answer and authority sections authentic, so an
// authoritative answer never carries the AD bit of the query.
test "a query with the AD bit set is answered with AD clear" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.2
        \\
    );
    defer zone_file.deinit();
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // A query received on the wire with AD set (flags 0x0120: RD and AD).
    const query = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try std.testing.expect(query.header.authenticated_data);

    const answer = try buildResponse(query, &zone);
    try std.testing.expect(answer.header.authoritative);
    try std.testing.expect(!answer.header.authenticated_data);
    try std.testing.expect(!(try buildFormerrResponse(query)).header.authenticated_data);
    try std.testing.expect(!(try buildRefusedResponse(query)).header.authenticated_data);
}

/// The one header flag policy every answer of this module follows.
fn expectHeaderFlagPolicy(answer: dns_message.Message, rcode: header.Rcode) !void {
    try std.testing.expect(answer.header.qr);
    try std.testing.expectEqual(header.Opcode.query, answer.header.opcode);
    try std.testing.expect(answer.header.recursion_desired);
    // RFC 4035 section 3.2.2: the CD bit of the query is copied.
    try std.testing.expect(answer.header.checking_disabled);
    // RFC 4035 section 3.1.6: AD is the responder's own claim about the
    // answer, never a bit taken from the query.
    try std.testing.expect(!answer.header.authenticated_data);
    // RFC 1035 section 4.1.1: the reserved Z bit is never copied.
    try std.testing.expect(!answer.header.reserved);
    try std.testing.expectEqual(rcode, answer.header.rcode);
}

test "the empty, refused, and FORMERR answers follow the same header flag policy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // A query received on the wire with RD, AD, CD, and the reserved Z bit
    // set (flags 0x0170).
    const query = try dns_message.Message.parseQuery(arena.allocator(), &.{
        0x12, 0x34, 0x01, 0x70, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try std.testing.expect(query.header.reserved);
    try std.testing.expect(query.header.authenticated_data);
    try std.testing.expect(query.header.checking_disabled);

    try expectHeaderFlagPolicy(try buildEmptyResponse(query, query.question, .no_error), .no_error);
    try expectHeaderFlagPolicy(try buildRefusedResponse(query), .refused);
    try expectHeaderFlagPolicy(try buildFormerrResponse(query), .formerr);
}

test "a referral carries only the glue of the delegation it names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.sibling.example.
        \\child IN NS ns.evil.other.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.sibling.example. IN A 192.0.2.11
        \\ns.evil.other. IN A 192.0.2.99
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // RFC 9471 section 3.1: the glue of the delegation's own name servers
    // rides along; RFC 5452 section 6: the address of a name this server is
    // not authoritative for never does.
    const response = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    try std.testing.expect(!response.header.authoritative);
    try std.testing.expectEqual(@as(usize, 2), response.additionals.len);
    var owner: [256]u8 = undefined;
    try std.testing.expectEqualStrings("ns.child.example.", try response.additionals.items[0].owner.toText(&owner));
    try std.testing.expectEqualStrings("ns.sibling.example.", try response.additionals.items[1].owner.toText(&owner));
}

test "a referral carries the glue of a name server of a sibling zone" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.sibling.example.
        \\sibling IN NS ns.sibling.example.
        \\ns.sibling.example. IN A 192.0.2.11
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // RFC 9471 section 2.2: a name server of another zone delegated from the
    // same parent is a sibling domain name server, and section 3.2 asks for
    // its glue in the additional section.
    const response = try buildResponse(try testQuery(arena.allocator(), "www.child.example.", .A), &zone);
    try std.testing.expect(!response.header.authoritative);
    try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
    var owner: [256]u8 = undefined;
    try std.testing.expectEqualStrings("ns.sibling.example.", try response.additionals.items[0].owner.toText(&owner));
}

test "an authoritative answer keeps its additional section byte for byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try zone_parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\alias IN CNAME www
        \\www IN A 192.0.2.2
        \\
    );
    var zone = try zone_index.Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var request = try testQuery(arena.allocator(), "alias.example.", .A);
    request.header.id = 0x4405;
    request.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try request.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });

    // The alias answer and its address keep the bytes they have always had,
    // and the EDNS OPT record stays in the additional section.
    const response = try buildResponse(request, &zone);
    try std.testing.expect(response.header.authoritative);
    try std.testing.expectEqual(@as(usize, 2), response.answers.len);
    try std.testing.expectEqual(@as(usize, 1), response.additionals.len);
    try std.testing.expect(response.additionals.items[0].rrtype.eql(.OPT));

    var encoded: [512]u8 = undefined;
    var writer = @import("../dns/writer.zig").Writer.init(&encoded);
    try response.encode(&writer);
    try std.testing.expectEqualSlices(u8, &authoritative_alias_answer_bytes, writer.written());
}

/// The bytes an authoritative alias answer with an EDNS(0) request has always
/// carried: the CNAME, the address it points at, and the OPT record.
const authoritative_alias_answer_bytes = [_]u8{
    0x44, 0x05, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00,
    0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x06, 0x03, 0x77, 0x77, 0x77, 0xc0,
    0x12, 0xc0, 0x2b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00,
    0x04, 0xc0, 0x00, 0x02, 0x02, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

test "RFC 8914: a blocked refusal differs from a plain refusal only by the EDE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "ads.home.arpa.", .A);
    request.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try request.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });

    const plain = try buildRefusedResponse(request);
    const blocked = try buildBlockedResponse(request);
    try std.testing.expectEqual(header.Rcode.refused, plain.header.rcode);
    try std.testing.expectEqual(header.Rcode.refused, blocked.header.rcode);

    var plain_bytes: [512]u8 = undefined;
    var plain_writer = dns_writer.Writer.init(&plain_bytes);
    try plain.encode(&plain_writer);
    var blocked_bytes: [512]u8 = undefined;
    var blocked_writer = dns_writer.Writer.init(&blocked_bytes);
    try blocked.encode(&blocked_writer);

    // The OPT record ends the answer, so its RDLENGTH is the last two octets:
    // the blocked answer is the plain one with the twenty-three octets of the
    // EDE option and the RDLENGTH that counts them.
    const plain_wire = plain_writer.written();
    const blocked_wire = blocked_writer.written();
    try std.testing.expectEqual(plain_wire.len + 23, blocked_wire.len);
    try std.testing.expectEqualSlices(u8, plain_wire[0 .. plain_wire.len - 2], blocked_wire[0 .. plain_wire.len - 2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x17 }, blocked_wire[plain_wire.len - 2 ..][0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0f, 0x00, 0x13, 0x00, 0x0f }, blocked_wire[plain_wire.len..][0..6]);
    try std.testing.expectEqualStrings("blocked by policy", blocked_wire[plain_wire.len + 6 ..]);
}

test "RFC 8914: the blocked refusal's EDE option carries its Extra Text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "ads.home.arpa.", .A);
    request.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try request.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });

    const blocked = try buildBlockedResponse(request);
    const options = ednsOptions(&blocked).?;
    // RFC 8914 section 2: the OPTION-CODE is 15 and the OPTION-LENGTH is two
    // plus the length of the EXTRA-TEXT.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0f }, options[0..2]);
    try std.testing.expectEqual(@as(usize, 2 + "blocked by policy".len), std.mem.readInt(u16, options[2..4], .big));
    // The INFO-CODE is the 16-bit Blocked code in network byte order, and the
    // EXTRA-TEXT says why the name was refused.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0f }, options[4..6]);
    try std.testing.expectEqualStrings("blocked by policy", options[6..]);
}

test "RFC 8914: a prohibited refusal differs from a plain refusal only by the EDE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "ads.home.arpa.", .A);
    request.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try request.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });

    const plain = try buildRefusedResponse(request);
    const prohibited = try buildProhibitedResponse(request);
    try std.testing.expectEqual(header.Rcode.refused, plain.header.rcode);
    try std.testing.expectEqual(header.Rcode.refused, prohibited.header.rcode);

    var plain_bytes: [512]u8 = undefined;
    var plain_writer = dns_writer.Writer.init(&plain_bytes);
    try plain.encode(&plain_writer);
    var prohibited_bytes: [512]u8 = undefined;
    var prohibited_writer = dns_writer.Writer.init(&prohibited_bytes);
    try prohibited.encode(&prohibited_writer);

    // The OPT record ends the answer, so its RDLENGTH is the last two octets:
    // the prohibited answer is the plain one with the twenty-six octets of
    // the EDE option and the RDLENGTH that counts them.
    const plain_wire = plain_writer.written();
    const prohibited_wire = prohibited_writer.written();
    try std.testing.expectEqual(plain_wire.len + 26, prohibited_wire.len);
    try std.testing.expectEqualSlices(u8, plain_wire[0 .. plain_wire.len - 2], prohibited_wire[0 .. plain_wire.len - 2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1a }, prohibited_wire[plain_wire.len - 2 ..][0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0f, 0x00, 0x16, 0x00, 0x12 }, prohibited_wire[plain_wire.len..][0..6]);
    try std.testing.expectEqualStrings("prohibited by policy", prohibited_wire[plain_wire.len + 6 ..]);
}

test "RFC 8914: a plain refusal carries no EDE option" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var request = try testQuery(arena.allocator(), "ads.home.arpa.", .A);
    request.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try request.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });

    const refused = try buildRefusedResponse(request);
    const options = ednsOptions(&refused).?;
    try std.testing.expectEqualSlices(u8, &.{}, options);
    try std.testing.expect(dns_rdata.findOption(options, ede_option_code) == null);
}
