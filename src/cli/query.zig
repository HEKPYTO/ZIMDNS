const std = @import("std");
const dns_header = @import("../dns/header.zig");
const dns_message = @import("../dns/message.zig");
const dns_name = @import("../dns/name.zig");
const dns_question = @import("../dns/question.zig");
const dns_types = @import("../dns/types.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_dnssec = @import("../dns/dnssec.zig");
const dns_writer = @import("../dns/writer.zig");
const dns_record = @import("../dns/record.zig");
const listener = @import("../platform/listener.zig");
const resolver = @import("../resolver.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const builtin = @import("builtin");
const Runtime = @import("../auth/runtime.zig").Runtime;

pub const Error = error{
    BadName,
    UnsupportedType,
    BadResponse,
    UnsupportedPlatform,
};

pub const TCP_IO_TIMEOUT = tcp_deadline.Timeout{ .seconds = 5 };
pub const TCP_DEADLINES_SUPPORTED = switch (builtin.os.tag) {
    .linux, .macos => true,
    else => false,
};

/// The EDNS(0) options a query asks for.
pub const EdnsRequest = struct {
    /// RFC 6891 section 6.1.1 DO bit: the server returns its RRSIG and NSEC
    /// records. Without it the server strips them, so an operator could never
    /// ask for the proofs this server signs.
    dnssec_ok: bool = false,
    /// RFC 9660 section 3.1: an empty ZONEVERSION option asks an
    /// authoritative server for the version of the zone it answered from.
    zoneversion: bool = false,
    /// RFC 5001 section 2.1: an empty NSID option asks a server for its own
    /// identifier. The request carries no payload data of its own.
    nsid: bool = false,
};

/// Builds the query packet. `dnssec_ok` sets the RFC 6891 section 6.1.1 DO
/// bit: one OPT pseudo-record in the additional section whose CLASS carries
/// the requestor's UDP payload size and whose TTL carries DO, version, and
/// extended RCODE. Without it the server strips RRSIG and NSEC, so an
/// operator could never ask for the proofs this server signs.
pub fn buildQueryPacket(
    buffer: []u8,
    id: u16,
    name_text: []const u8,
    qtype: dns_types.RecordType,
    dnssec_ok: bool,
) ![]const u8 {
    return buildQueryPacketWithEdns(buffer, id, name_text, qtype, .{ .dnssec_ok = dnssec_ok });
}

/// The same packet, with the EDNS(0) options the operator asked for. The OPT
/// pseudo-record carries them: CLASS is the requestor's UDP payload size,
/// TTL carries extended RCODE, version, and DO, and RDLENGTH covers the
/// RFC 6891 section 6.1.2 option framing that follows.
pub fn buildQueryPacketWithEdns(
    buffer: []u8,
    id: u16,
    name_text: []const u8,
    qtype: dns_types.RecordType,
    edns: EdnsRequest,
) ![]const u8 {
    const qname = dns_name.Name.fromText(name_text) catch return Error.BadName;
    return buildQueryPacketForName(buffer, id, qname, qtype, edns);
}

/// The same packet, with the question name the caller built. The 0x20
/// mechanism randomizes the name's label-first letters before this call, so
/// the packet carries the case the client chose.
pub fn buildQueryPacketForName(
    buffer: []u8,
    id: u16,
    qname: dns_name.Name,
    qtype: dns_types.RecordType,
    edns: EdnsRequest,
) ![]const u8 {
    // RFC 1123 section 2.1 keeps the RFC 952 host name syntax, so a label
    // may neither begin nor end with a hyphen; the zone side refuses such a
    // label, so the query must not ask about a name no zone can hold.
    if (qname.hasHyphenEdgeLabel()) return Error.BadName;
    var writer = dns_writer.Writer.init(buffer);
    const want_opt = edns.dnssec_ok or edns.zoneversion or edns.nsid;
    const message = dns_message.Message{
        .header = dns_header.Header{
            .id = id,
            .recursion_desired = true,
            .question_count = 1,
            .additional_count = @intFromBool(want_opt),
        },
        .question = dns_question.Question{
            .name = qname,
            .qtype = qtype,
            .qclass = .IN,
        },
    };
    try message.encode(&writer);
    if (want_opt) {
        // RFC 6891 section 6.1.2 option framing: code, length, payload. The
        // shared builder writes it and keeps the bound in one place.
        var opt = dns_rdata.Opt{};
        if (edns.zoneversion) {
            // RFC 9660 section 3.1: the query's ZONEVERSION option is empty,
            // and a query carries it at most once.
            _ = opt.appendOption(dns_rdata.EDNS_ZONEVERSION_OPTION_CODE, &.{});
        }
        if (edns.nsid) {
            // RFC 5001 section 2.1: the querier signals with an empty NSID
            // option and must not send payload data of its own.
            _ = opt.appendOption(dns_rdata.EDNS_NSID_OPTION_CODE, &.{});
        }
        // owner is root, type OPT, CLASS is the payload size, TTL carries
        // extended RCODE (high byte), version, and DO (0x8000).
        try writer.writeU8(0);
        try writer.writeU16(dns_types.RecordType.OPT.code());
        try writer.writeU16(dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
        try writer.writeU32(if (edns.dnssec_ok) 0x8000 else 0);
        try writer.writeU16(@intCast(opt.bytes().len));
        try writer.writeBytes(opt.bytes());
    }
    return writer.written();
}

/// Prints the question the server echoed. The 0x20 mechanism puts its random
/// case in the question name, and RFC 4343 section 4.1 has the server copy
/// that name into the response, so the echoed name is what shows the client
/// what went on the wire.
pub fn writeQuestion(response: dns_message.Message, writer: *std.Io.Writer) !void {
    const question = response.question orelse return;
    var name_buffer: [256]u8 = undefined;
    const name = question.name.toText(&name_buffer) catch return Error.BadResponse;
    try writer.writeAll(";; QUESTION SECTION:\n");
    try writer.print("{s}\n", .{name});
}

pub fn writeResponse(response: dns_message.Message, writer: *std.Io.Writer) !void {
    // RFC 6891 section 6.1.3: the OPT record is an EDNS(0) pseudo-record with
    // its own presentation, so it gets a pseudosection instead of being shown
    // as an RRset (which is why writeSection skips it).
    try writeOptPseudoSection(response, writer);

    // Proof and glue records are rendered by the same per-type renderer the
    // answer section uses, so one format covers every record in a response.
    if (response.answers.len == 0) {
        if (response.header.rcode != .no_error) {
            try writer.writeAll("rcode ");
            try writer.writeAll(rcodeName(response.header.rcode));
            try writer.writeAll("\n");
        }
        if (response.authorities.len == 0 and !hasRecordAdditionals(response)) {
            try writer.writeAll("no answers\n");
            return;
        }
    }

    for (response.answers.slice()) |record| {
        try writeRecord(record, writer);
    }
    // RFC 4035 section 3.1.6: a signature for an answer arrives beside it, and
    // RFC 4035 section 3.1.4 puts the NSEC proof of a negative answer in the
    // authority section. Printing answers alone therefore hid every signed
    // record a DO=1 client asked for.
    try writeSection(writer, "AUTHORITY", response.authorities.slice());
    try writeSection(writer, "ADDITIONAL", response.additionals.slice());
}
/// Render the response's EDNS(0) pseudo-record as a separate pseudosection.
/// RFC 6891 section 6.1.3 makes OPT a pseudo-record, so printing it as an
/// ordinary RR would show a meaningless TYPE41 with no owner name.
fn writeOptPseudoSection(response: dns_message.Message, writer: *std.Io.Writer) !void {
    const edns = response.edns orelse return;
    try writer.writeAll(";; OPT PSEUDOSECTION:\n");
    try writer.print("; EDNS: version: {d}, flags:{s} udp: {d}", .{
        edns.version,
        if (edns.dnssec_ok) "do" else "",
        edns.udp_payload_size,
    });
    if (edns.extended_rcode != 0) {
        try writer.print(", ext-rcode: {d}", .{edns.extended_rcode});
    }
    try writer.writeAll("\n");
    const options = optOptions(response) orelse return;
    var offset: usize = 0;
    while (offset + 4 <= options.len) {
        const code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const length = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        offset += 4;
        if (length > options.len - offset) break;
        try writeEdnsOption(code, options[offset..][0..length], response.question, writer);
        offset += length;
    }
}

fn optOptions(response: dns_message.Message) ?[]const u8 {
    // The OPT payload is read through a pointer into the message: a
    // by-value capture copies the record, and the slice would then point into
    // a temporary that is gone before the caller reads the bytes.
    for (response.additionals.slice()) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return switch (record.rdata) {
            .OPT => |*opt| opt.bytes(),
            else => unreachable,
        };
    }
    return null;
}

/// The OPT pseudo-record does not count as an RRset, so the answerless path
/// ignores it.
fn hasRecordAdditionals(response: dns_message.Message) bool {
    for (response.additionals.slice()) |record| {
        if (record.rrtype.eql(.OPT)) continue;
        return true;
    }
    return false;
}

fn writeEdnsOption(code: u16, data: []const u8, question: ?dns_question.Question, writer: *std.Io.Writer) !void {
    switch (code) {
        dns_rdata.EDNS_ZONEVERSION_OPTION_CODE => try writeZoneversion(data, question, writer),
        dns_rdata.EDNS_NSID_OPTION_CODE => {
            // RFC 5001 section 2.4: a user interface reads the payload as a
            // sequence of hexadecimal digits, two per octet.
            try writer.writeAll("; NSID: ");
            for (data) |byte| try writer.print("{x:0>2}", .{byte});
            try writer.writeAll("\n");
        },
        else => try writer.print("; EDNS-OPTION: {d} ({d} octets)\n", .{ code, data.len }),
    }
}

fn writeZoneversion(data: []const u8, question: ?dns_question.Question, writer: *std.Io.Writer) !void {
    try writer.writeAll("; ZONEVERSION: ");
    // RFC 9660 section 2.1: LABELCOUNT, TYPE, then the opaque VERSION.
    if (data.len < 6) {
        try writer.writeAll("(malformed option data)\n");
        return;
    }
    const label_count = data[0];
    const version_type = data[1];
    if (version_type == 0) {
        // RFC 9660 section 4.1: TYPE is the mnemonic "SOA-SERIAL", and
        // VERSION is the zone's SOA serial as an unsigned decimal integer.
        try writer.print("SOA-SERIAL {d}", .{std.mem.readInt(u32, data[2..6], .big)});
    } else {
        try writer.print("TYPE {d} ", .{version_type});
        for (data[2..]) |byte| try writer.print("{x:0>2}", .{byte});
    }
    if (question) |q| {
        var name_buffer: [512]u8 = undefined;
        if (zoneNameFromLabelCount(q.name, label_count, &name_buffer)) |zone| {
            try writer.print(" ({s})", .{zone});
        }
    }
    try writer.writeAll("\n");
}

fn zoneNameFromLabelCount(name: dns_name.Name, label_count: u8, buffer: []u8) ?[]const u8 {
    // RFC 9660 section 2.1: the zone name is the last LABELCOUNT labels of the
    // original QNAME, with LABELCOUNT 0 naming the root.
    const wire = name.asWire();
    var total: usize = 0;
    var cursor: usize = 0;
    while (cursor < wire.len) {
        const len = wire[cursor];
        if (len == 0) break;
        total += 1;
        cursor += 1 + len;
    }
    if (label_count > total) return null;
    if (label_count == 0) {
        if (buffer.len < 1) return null;
        buffer[0] = '.';
        return buffer[0..1];
    }
    const skip = total - label_count;
    cursor = 0;
    var index: usize = 0;
    while (index < skip) : (index += 1) {
        const len = wire[cursor];
        if (len == 0) return null;
        cursor += 1 + len;
    }
    const parsed = dns_name.Name.parse(wire, cursor) catch return null;
    return parsed.name.toText(buffer) catch null;
}

fn writeSection(writer: *std.Io.Writer, label: []const u8, records: []const dns_record.ResourceRecord) !void {
    var printed = false;
    for (records) |record| {
        // OPT is an EDNS pseudo-record, not an RRset: printing it would show
        // an operator a TYPE41 with no RDATA and no meaning.
        if (record.rrtype.eql(.OPT)) continue;
        if (!printed) {
            try writer.print(";; {s} SECTION:\n", .{label});
            printed = true;
        }
        try writeRecord(record, writer);
    }
}

fn writeRecord(record: dns_record.ResourceRecord, writer: *std.Io.Writer) !void {
    var name_buffer: [256]u8 = undefined;
    var value_buffer: [256]u8 = undefined;
    const owner = record.owner.toText(&name_buffer) catch return Error.BadResponse;
    try writer.writeAll(owner);
    try writer.writeAll(" ");
    try writer.print("{}", .{record.ttl});
    try writer.writeAll(" IN ");
    if (record.rrtype.eql(.A)) {
        try writer.writeAll("A ");
        try writer.print("{}.{}.{}.{}", .{ record.rdata.A[0], record.rdata.A[1], record.rdata.A[2], record.rdata.A[3] });
    } else if (record.rrtype.eql(.AAAA)) {
        try writer.writeAll("AAAA ");
        try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            record.rdata.AAAA[0],  record.rdata.AAAA[1],  record.rdata.AAAA[2],  record.rdata.AAAA[3],
            record.rdata.AAAA[4],  record.rdata.AAAA[5],  record.rdata.AAAA[6],  record.rdata.AAAA[7],
            record.rdata.AAAA[8],  record.rdata.AAAA[9],  record.rdata.AAAA[10], record.rdata.AAAA[11],
            record.rdata.AAAA[12], record.rdata.AAAA[13], record.rdata.AAAA[14], record.rdata.AAAA[15],
        });
    } else if (record.rrtype.eql(.CNAME)) {
        const target = record.rdata.CNAME.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll("CNAME ");
        try writer.writeAll(target);
    } else if (record.rrtype.eql(.NS)) {
        const target = record.rdata.NS.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll("NS ");
        try writer.writeAll(target);
    } else if (record.rrtype.eql(.MX)) {
        const mx = record.rdata.MX;
        const exchange = mx.exchange.toText(&value_buffer) catch return Error.BadResponse;
        try writer.print("MX {} {s}", .{ mx.preference, exchange });
    } else if (record.rrtype.eql(.SOA)) {
        const soa = record.rdata.SOA;
        const mname = soa.mname.toText(&value_buffer) catch return Error.BadResponse;
        var rname_buffer: [256]u8 = undefined;
        const rname = soa.rname.toText(&rname_buffer) catch return Error.BadResponse;
        try writer.print("SOA {s} {s} {} {} {} {} {}", .{ mname, rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum });
    } else if (record.rrtype.eql(.PTR)) {
        const target = record.rdata.PTR.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll("PTR ");
        try writer.writeAll(target);
    } else if (record.rrtype.eql(.DNAME)) {
        const target = record.rdata.DNAME.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll("DNAME ");
        try writer.writeAll(target);
    } else if (record.rrtype.eql(.TXT)) {
        try writer.writeAll("TXT \"");
        try writer.writeAll(record.rdata.TXT.text());
        try writer.writeAll("\"");
    } else if (record.rrtype.eql(.NAPTR)) {
        const naptr = record.rdata.NAPTR;
        try writer.print("NAPTR {} {} ", .{ naptr.order, naptr.preference });
        try writeQuoted(writer, naptr.flagsText(), false);
        try writer.writeAll(" ");
        try writeQuoted(writer, naptr.servicesText(), false);
        try writer.writeAll(" ");
        try writeQuoted(writer, naptr.regexpText(), false);
        try writer.writeAll(" ");
        const replacement = naptr.replacement.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll(replacement);
    } else if (record.rrtype.eql(.SSHFP)) {
        const sshfp = record.rdata.SSHFP;
        try writer.writeAll("SSHFP ");
        try writer.print("{} {} ", .{ sshfp.algorithm, sshfp.fingerprint_type });
        for (sshfp.fingerprintBytes()) |byte| try writer.print("{x:0>2}", .{byte});
    } else if (record.rrtype.eql(.TLSA)) {
        const tlsa = record.rdata.TLSA;
        const usage = dns_rdata.tlsaUsageAcronym(tlsa.usage) orelse return Error.BadResponse;
        const selector = dns_rdata.tlsaSelectorAcronym(tlsa.selector) orelse return Error.BadResponse;
        const matching_type = dns_rdata.tlsaMatchingTypeAcronym(tlsa.matching_type) orelse return Error.BadResponse;
        try writer.print("TLSA {s} {s} {s} ", .{ usage, selector, matching_type });
        for (tlsa.association[0..tlsa.association_len]) |byte| try writer.print("{x:0>2}", .{byte});
    } else if (record.rrtype.eql(.URI)) {
        const uri = record.rdata.URI;
        try writer.print("URI {} {} ", .{ uri.priority, uri.weight });
        try writeQuoted(writer, uri.targetBytes(), true);
    } else if (record.rrtype.eql(.AFSDB)) {
        const afsdb = record.rdata.AFSDB;
        const hostname = afsdb.exchange.toText(&value_buffer) catch return Error.BadResponse;
        try writer.print("AFSDB {} {s}", .{ afsdb.preference, hostname });
    } else if (record.rrtype.eql(.RP)) {
        const rp = record.rdata.RP;
        const mbox = rp.mbox.toText(&value_buffer) catch return Error.BadResponse;
        var txt_buffer: [256]u8 = undefined;
        const txt = rp.txt.toText(&txt_buffer) catch return Error.BadResponse;
        try writer.print("RP {s} {s}", .{ mbox, txt });
    } else if (record.rrtype.eql(.RT)) {
        const rt = record.rdata.RT;
        const exchange = rt.exchange.toText(&value_buffer) catch return Error.BadResponse;
        try writer.print("RT {} {s}", .{ rt.preference, exchange });
    } else if (record.rrtype.eql(.SRV)) {
        const srv = record.rdata.SRV;
        const target = srv.target.toText(&value_buffer) catch return Error.BadResponse;
        try writer.print("SRV {} {} {} {s}", .{ srv.priority, srv.weight, srv.port, target });
    } else if (record.rrtype.eql(.CAA)) {
        const caa = record.rdata.CAA;
        try writer.print("CAA {} ", .{caa.flags});
        for (caa.tagText()) |byte| try writer.print("{c}", .{std.ascii.toLower(byte)});
        try writer.writeAll(" ");
        try writeQuoted(writer, caa.valueText(), true);
    } else if (record.rrtype.eql(.X25)) {
        try writer.writeAll("X25 ");
        try writeQuoted(writer, record.rdata.X25.text(), false);
    } else if (record.rrtype.eql(.ISDN)) {
        const isdn = record.rdata.ISDN;
        try writer.writeAll("ISDN ");
        try writeQuoted(writer, isdn.addressText(), false);
        if (isdn.has_subaddress) {
            try writer.writeAll(" ");
            try writeQuoted(writer, isdn.subaddressText(), false);
        }
    } else if (record.rrtype.eql(.HINFO)) {
        const hinfo = record.rdata.HINFO;
        try writer.writeAll("HINFO ");
        try writeQuoted(writer, hinfo.cpuText(), false);
        try writer.writeAll(" ");
        try writeQuoted(writer, hinfo.osText(), false);
    } else if (record.rrtype.eql(.APL)) {
        try writer.writeAll("APL");
        try writeApl(writer, record.rdata.APL.bytes());
    } else if (record.rrtype.eql(.SVCB) or record.rrtype.eql(.HTTPS)) {
        const svcb = if (record.rrtype.eql(.SVCB)) record.rdata.SVCB else record.rdata.HTTPS;
        try writer.writeAll(if (record.rrtype.eql(.SVCB)) "SVCB " else "HTTPS ");
        try writer.print("{} ", .{svcb.priority});
        const target = svcb.target.toText(&value_buffer) catch return Error.BadResponse;
        try writer.writeAll(target);
        try writeSvcbParams(writer, svcb.paramsBytes());
    } else if (dns_dnssec.isDnssecType(record.rrtype)) {
        // DNSSEC RRs are served opaque: render RFC 3597 generic form.
        try writer.writeAll("TYPE");
        try writer.print("{} \\# ", .{record.rrtype.code()});
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.BadResponse,
        };
        if (raw.len > 2048) return Error.BadResponse;
        for (raw) |byte| try writer.print("{x:0>2}", .{byte});
    } else {
        // Untyped RRs (HINFO and future types) are served opaque: render
        // RFC 3597 generic form so the fallback never drops RDATA.
        try writer.writeAll("TYPE");
        try writer.print("{} \\# ", .{record.rrtype.code()});
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => return Error.BadResponse,
        };
        if (raw.len > 2048) return Error.BadResponse;
        for (raw) |byte| try writer.print("{x:0>2}", .{byte});
    }
    try writer.writeAll("\n");
}

fn writeApl(writer: *std.Io.Writer, bytes: []const u8) !void {
    if (bytes.len != 0) try writer.writeAll(" ");
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes.len - offset < 4) return Error.BadResponse;
        const afi = std.mem.readInt(u16, bytes[offset..][0..2], .big);
        const prefix = bytes[offset + 2];
        const negated = bytes[offset + 3] & 0x80 != 0;
        const afd_len = bytes[offset + 3] & 0x7f;
        if (bytes.len - offset - 4 < afd_len) return Error.BadResponse;
        if (afi != 1 and afi != 2) return Error.BadResponse;
        const address_len: usize = if (afi == 1) 4 else 16;
        if (afd_len > address_len) return Error.BadResponse;

        var address: [16]u8 = @splat(0);
        @memcpy(address[0..afd_len], bytes[offset + 4 ..][0..afd_len]);
        if (offset != 0) try writer.writeAll(" ");
        if (negated) try writer.writeAll("!");
        try writer.print("{}:", .{afi});
        if (afi == 1) {
            try writer.print("{}.{}.{}.{}", .{ address[0], address[1], address[2], address[3] });
        } else {
            const ip6 = std.Io.net.Ip6Address.Unresolved{ .bytes = address, .interface_name = null };
            try writer.print("{f}", .{ip6});
        }
        try writer.print("/{}", .{prefix});
        offset += 4 + afd_len;
    }
}

/// Print SVCB/HTTPS SvcParams in zone-file shape: ` alpn="h2" port=443` with a
/// bare ` no-default-alpn` flag, base64 `ech`, and hex `keyNNNN` values.
fn writeSvcbParams(writer: *std.Io.Writer, params: []const u8) !void {
    var offset: usize = 0;
    while (offset < params.len) {
        if (params.len - offset < 4) return Error.BadResponse;
        const key = std.mem.readInt(u16, params[offset..][0..2], .big);
        const value_len = std.mem.readInt(u16, params[offset + 2 ..][0..2], .big);
        if (value_len > params.len - offset - 4) return Error.BadResponse;
        const value = params[offset + 4 .. offset + 4 + value_len];

        try writer.writeAll(" ");
        try writeSvcbKeyName(writer, key);
        switch (key) {
            dns_rdata.SVCB_NO_DEFAULT_ALPN_KEY => {
                if (value.len != 0) return Error.BadResponse;
            },
            dns_rdata.SVCB_MANDATORY_KEY => {
                if (value.len == 0 or value.len % 2 != 0) return Error.BadResponse;
                try writer.writeAll("=");
                var index: usize = 0;
                while (index < value.len) : (index += 2) {
                    if (index != 0) try writer.writeAll(",");
                    try writeSvcbKeyName(writer, std.mem.readInt(u16, value[index..][0..2], .big));
                }
            },
            dns_rdata.SVCB_ALPN_KEY => {
                var joined: [512]u8 = undefined;
                var joined_len: usize = 0;
                var cursor: usize = 0;
                var first = true;
                while (cursor < value.len) {
                    const id_len = value[cursor];
                    if (id_len == 0 or @as(usize, id_len) > value.len - cursor - 1) return Error.BadResponse;
                    if (joined_len + @as(usize, id_len) + @intFromBool(!first) > joined.len) return Error.BadResponse;
                    if (!first) {
                        joined[joined_len] = ',';
                        joined_len += 1;
                    }
                    first = false;
                    @memcpy(joined[joined_len..][0..id_len], value[cursor + 1 ..][0..id_len]);
                    joined_len += id_len;
                    cursor += 1 + id_len;
                }
                if (first) return Error.BadResponse;
                try writer.writeAll("=");
                try writeQuoted(writer, joined[0..joined_len], false);
            },
            dns_rdata.SVCB_PORT_KEY => {
                if (value.len != 2) return Error.BadResponse;
                try writer.print("={}", .{std.mem.readInt(u16, value[0..2], .big)});
            },
            dns_rdata.SVCB_IPV4HINT_KEY => {
                if (value.len == 0 or value.len % 4 != 0) return Error.BadResponse;
                try writer.writeAll("=");
                var index: usize = 0;
                while (index < value.len) : (index += 4) {
                    if (index != 0) try writer.writeAll(",");
                    try writer.print("{}.{}.{}.{}", .{ value[index], value[index + 1], value[index + 2], value[index + 3] });
                }
            },
            dns_rdata.SVCB_ECH_KEY => {
                if (value.len == 0) return Error.BadResponse;
                const encoder = std.base64.standard.Encoder;
                var encoded: [676]u8 = undefined;
                if (encoder.calcSize(value.len) > encoded.len) return Error.BadResponse;
                try writer.writeAll("=");
                try writer.writeAll(encoder.encode(&encoded, value));
            },
            dns_rdata.SVCB_IPV6HINT_KEY => {
                if (value.len == 0 or value.len % 16 != 0) return Error.BadResponse;
                try writer.writeAll("=");
                var index: usize = 0;
                while (index < value.len) : (index += 16) {
                    if (index != 0) try writer.writeAll(",");
                    const address = value[index..][0..16];
                    try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                        address[0],  address[1],  address[2],  address[3],
                        address[4],  address[5],  address[6],  address[7],
                        address[8],  address[9],  address[10], address[11],
                        address[12], address[13], address[14], address[15],
                    });
                }
            },
            dns_rdata.SVCB_DOHPATH_KEY => {
                try writer.writeAll("=");
                try writeQuoted(writer, value, true);
            },
            else => {
                try writer.writeAll("=");
                for (value) |byte| try writer.print("{x:0>2}", .{byte});
            },
        }
        offset += 4 + value_len;
    }
}

fn writeSvcbKeyName(writer: *std.Io.Writer, key: u16) !void {
    switch (key) {
        dns_rdata.SVCB_MANDATORY_KEY => try writer.writeAll("mandatory"),
        dns_rdata.SVCB_ALPN_KEY => try writer.writeAll("alpn"),
        dns_rdata.SVCB_NO_DEFAULT_ALPN_KEY => try writer.writeAll("no-default-alpn"),
        dns_rdata.SVCB_PORT_KEY => try writer.writeAll("port"),
        dns_rdata.SVCB_IPV4HINT_KEY => try writer.writeAll("ipv4hint"),
        dns_rdata.SVCB_ECH_KEY => try writer.writeAll("ech"),
        dns_rdata.SVCB_IPV6HINT_KEY => try writer.writeAll("ipv6hint"),
        dns_rdata.SVCB_DOHPATH_KEY => try writer.writeAll("dohpath"),
        else => try writer.print("key{}", .{key}),
    }
}

fn writeQuoted(writer: *std.Io.Writer, bytes: []const u8, escape_non_ascii: bool) !void {
    try writer.writeAll("\"");
    for (bytes) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0...31, 127 => try writer.print("\\{d:0>3}", .{byte}),
            else => {
                if (escape_non_ascii and byte >= 128) {
                    try writer.print("\\{d:0>3}", .{byte});
                } else {
                    try writer.writeAll(&.{byte});
                }
            },
        }
    }
    try writer.writeAll("\"");
}

fn rcodeName(rcode: dns_header.Rcode) []const u8 {
    return switch (rcode) {
        .no_error => "NOERROR",
        .formerr => "FORMERR",
        .servfail => "SERVFAIL",
        .nxdomain => "NXDOMAIN",
        .notimp => "NOTIMP",
        .refused => "REFUSED",
        .yxdomain => "YXDOMAIN",
        .yxrrset => "YXRRSET",
        .badcookie => "BADCOOKIE",
        .nxrrset => "NXRRSET",
        .notauth => "NOTAUTH",
        .notzone => "NOTZONE",
    };
}

pub fn sendUdpQuery(socket: *const std.Io.net.Socket, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8) !void {
    try socket.send(io, server, query);
}

pub fn validateResponse(response: dns_message.Message, expected_id: u16, expected_opcode: dns_header.Opcode, expected_question: dns_question.Question) Error!void {
    if (!response.header.qr or response.header.id != expected_id or response.header.opcode != expected_opcode or response.header.question_count != 1) return Error.BadResponse;
    const actual_question = response.question orelse return Error.BadResponse;
    if (!actual_question.name.eql(&expected_question.name) or
        !actual_question.qtype.eql(expected_question.qtype) or
        !actual_question.qclass.eql(expected_question.qclass)) return Error.BadResponse;
}

pub fn udpClientBindAddress(server: *const std.Io.net.IpAddress) std.Io.net.IpAddress {
    return switch (server.*) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
}

pub fn receiveUdpResponse(allocator: std.mem.Allocator, socket: *const std.Io.net.Socket, io: std.Io, buffer: []u8, expected_server: *const std.Io.net.IpAddress, query: []const u8) !dns_message.Message {
    var expected = dns_message.Message.parseQuery(allocator, query) catch return Error.BadResponse;
    defer expected.deinit();
    const deadline = tcp_deadline.deadlineFromTimeout(io, resolver.UDP_TIMEOUT) orelse return error.Timeout;
    while (true) {
        const remaining = deadline.durationFromNow(io);
        if (remaining.raw.nanoseconds <= 0) return error.Timeout;
        const incoming = try socket.receiveTimeout(io, buffer, .{ .duration = remaining });
        if (!incoming.from.eql(expected_server)) continue;
        var response = dns_message.Message.parse(allocator, incoming.data) catch continue;
        validateResponse(response, expected.header.id, expected.header.opcode, expected.question.?) catch {
            response.deinit();
            continue;
        };
        return response;
    }
}

pub fn sendTcpQuery(stream: std.Io.net.Stream, io: std.Io, query: []const u8) !void {
    tcp_deadline.setSocketTimeout(stream.socket.handle, TCP_IO_TIMEOUT);
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try writer.interface.writeAll(&prefix);
    try writer.interface.writeAll(query);
    try writer.interface.flush();
}

pub fn receiveTcpResponse(allocator: std.mem.Allocator, stream: std.Io.net.Stream, io: std.Io, buffer: []u8, query: []const u8) !dns_message.Message {
    var expected = dns_message.Message.parseQuery(allocator, query) catch return Error.BadResponse;
    defer expected.deinit();
    tcp_deadline.setSocketTimeout(stream.socket.handle, TCP_IO_TIMEOUT);
    // Exact-read under one deadline: a dripping peer cannot stall the client
    // past TCP_IO_TIMEOUT, and short reads loop instead of truncating.
    const frame_deadline = tcp_deadline.deadline(io, TCP_IO_TIMEOUT);
    var response_len_bytes: [2]u8 = undefined;
    tcp_deadline.readExact(stream.socket.handle, io, &response_len_bytes, frame_deadline) catch return Error.BadResponse;
    const response_len = std.mem.readInt(u16, &response_len_bytes, .big);
    if (response_len == 0 or response_len > buffer.len) return Error.BadResponse;
    tcp_deadline.readExact(stream.socket.handle, io, buffer[0..response_len], frame_deadline) catch return Error.BadResponse;
    const response = try dns_message.Message.parse(allocator, buffer[0..response_len]);
    try validateResponse(response, expected.header.id, expected.header.opcode, expected.question.?);
    return response;
}

pub fn exchangeTcpQuery(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8) !dns_message.Message {
    if (comptime !TCP_DEADLINES_SUPPORTED) return Error.UnsupportedPlatform;
    return unix_tcp_query.exchange(allocator, io, server, query, response_buffer);
}

const unix_tcp_query = if (TCP_DEADLINES_SUPPORTED) struct {
    fn exchange(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8) !dns_message.Message {
        var expected = dns_message.Message.parseQuery(allocator, query) catch return Error.BadResponse;
        defer expected.deinit();
        if (query.len == 0 or query.len > std.math.maxInt(u16)) return Error.BadResponse;

        var stream = resolver.connectTcpWithTimeout(io, server, .{
            .mode = .stream,
            .protocol = .tcp,
            .timeout = .{ .duration = .{
                .raw = .fromSeconds(TCP_IO_TIMEOUT.seconds),
                .clock = .awake,
            } },
        }) catch return Error.BadResponse;
        defer stream.close(io);

        const frame_deadline = tcp_deadline.deadline(io, TCP_IO_TIMEOUT);
        tcp_deadline.setSocketTimeout(stream.socket.handle, TCP_IO_TIMEOUT);

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
        try tcp_deadline.writeExact(stream.socket.handle, io, &prefix, frame_deadline);
        try tcp_deadline.writeExact(stream.socket.handle, io, query, frame_deadline);

        var response_len_bytes: [2]u8 = undefined;
        try tcp_deadline.readExact(stream.socket.handle, io, &response_len_bytes, frame_deadline);
        const response_len = std.mem.readInt(u16, &response_len_bytes, .big);
        if (response_len == 0 or response_len > response_buffer.len) return Error.BadResponse;
        try tcp_deadline.readExact(stream.socket.handle, io, response_buffer[0..response_len], frame_deadline);

        const response = try dns_message.Message.parse(allocator, response_buffer[0..response_len]);
        try validateResponse(response, expected.header.id, expected.header.opcode, expected.question.?);
        return response;
    }
} else struct {};

test "query builder encodes standard A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacket(&buffer, 0x1234, "example.com.", .A, false);
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try std.testing.expect(parsed.header.recursion_desired);
    try std.testing.expect(parsed.question.?.qtype.eql(.A));
}

test "the query packet carries the RFC 6891 DO bit only when the operator asks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var plain_buffer: [512]u8 = undefined;
    const plain = try buildQueryPacket(&plain_buffer, 0x1234, "www.example.", .A, false);
    const parsed_plain = try dns_message.Message.parseQuery(arena.allocator(), plain);
    try std.testing.expectEqual(@as(u16, 0), parsed_plain.header.additional_count);
    try std.testing.expect(parsed_plain.edns == null);

    var do_buffer: [512]u8 = undefined;
    const packet = try buildQueryPacket(&do_buffer, 0x1234, "www.example.", .A, true);
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expect(parsed.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u8, 0), parsed.edns.?.version);
    try std.testing.expectEqual(@as(u16, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE), parsed.edns.?.udp_payload_size);
    try std.testing.expect(parsed.additionals.items[0].rrtype.eql(.OPT));
}

/// The question name the packet carries: the header is 12 octets and the
/// name comes first in the question section.
fn qnameWire(packet: []const u8) []const u8 {
    var index: usize = 12;
    while (index < packet.len) {
        const len = packet[index];
        if (len == 0) return packet[12 .. index + 1];
        index += 1 + @as(usize, len);
    }
    return packet[12..];
}

test "the query packet carries the question name as typed" {
    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacket(&buffer, 0x1234, "www.example.com.", .A, false);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 },
        qnameWire(packet),
    );
}

test "0x20: the question name on the wire varies only in the case of the label-first letters" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var random_source = std.Random.IoSource{ .io = io };
    const random = random_source.interface();
    const base = try dns_name.Name.fromText("www.example.com.");

    var previous: [64]u8 = undefined;
    var differs = false;
    for (0..32) |_| {
        var buffer: [512]u8 = undefined;
        const randomized = base.withRandomizedLabelFirstCase(random);
        const packet = try buildQueryPacketForName(&buffer, 0x1234, randomized, .A, .{});
        const wire = qnameWire(packet);

        // RFC 1035 section 2.3.3: the name still compares equal to the typed
        // one, whatever case the labels carry.
        try std.testing.expect(randomized.eql(&base));

        // Only the first letter of a label moves, and only in case.
        var index: usize = 0;
        while (index < base.asWire().len) {
            const len: usize = base.asWire()[index];
            if (len == 0) break;
            try std.testing.expectEqual(
                std.ascii.toLower(base.asWire()[index + 1]),
                std.ascii.toLower(wire[index + 1]),
            );
            try std.testing.expectEqualSlices(
                u8,
                base.asWire()[index + 2 .. index + 1 + len],
                wire[index + 2 .. index + 1 + len],
            );
            index += 1 + len;
        }

        if (!std.mem.eql(u8, previous[0..wire.len], wire)) differs = true;
        @memcpy(previous[0..wire.len], wire);
    }
    // The case is drawn, so the name on the wire is not the same every time.
    try std.testing.expect(differs);
}

test "the question the server echoed is printed with the case it carries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'W',  'w',  'w',  7,    'E',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeQuestion(response, &output.writer);
    try std.testing.expectEqualStrings(";; QUESTION SECTION:\nWww.Example.\n", output.written());
}

test "response validation requires QR and the exact question" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try buildQueryPacket(&query_buffer, 0x1234, "example.com.", .A, false);
    const expected = try dns_message.Message.parseQuery(arena.allocator(), query);
    const question = expected.question.?;

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    });
    try validateResponse(response, expected.header.id, expected.header.opcode, question);

    var not_response = response;
    not_response.header.qr = false;
    try std.testing.expectError(Error.BadResponse, validateResponse(not_response, expected.header.id, expected.header.opcode, question));

    const wrong_id = response;
    try std.testing.expectError(Error.BadResponse, validateResponse(wrong_id, expected.header.id + 1, expected.header.opcode, question));

    var other_question = question;
    other_question.qtype = .AAAA;
    try std.testing.expectError(Error.BadResponse, validateResponse(response, expected.header.id, expected.header.opcode, other_question));

    var wrong_opcode = response;
    wrong_opcode.header.opcode = .status;
    try std.testing.expectError(Error.BadResponse, validateResponse(wrong_opcode, expected.header.id, expected.header.opcode, question));
}

test "UDP client bind address uses an unspecified ephemeral endpoint per server family" {
    const ip4 = std.Io.net.IpAddress{ .ip4 = .loopback(53) };
    const ip6 = std.Io.net.IpAddress{ .ip6 = .loopback(53) };
    const expected_ip4 = std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
    const expected_ip6 = std.Io.net.IpAddress{ .ip6 = .unspecified(0) };
    try std.testing.expect(udpClientBindAddress(&ip4).eql(&expected_ip4));
    try std.testing.expect(udpClientBindAddress(&ip6).eql(&expected_ip6));
}

test "query formatter prints A and CNAME answers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0,    0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192,  0,    2,    1,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "www.example.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "CNAME example.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "A 192.0.2.1") != null);
}

test "query formatter prints DNSSEC RRs in RFC 3597 generic form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x44, 0x01, 0x85, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x3c, 0x00, 0x04, 192,  0,    2,    1,    0xc0, 0x0c, 0x00,
        0x2e, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x00, 0x01, 0x08,
        0x02,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "A 192.0.2.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "TYPE46 \\# 00010802") != null);
}

test "query formatter prints SSHFP selectors and lowercase fingerprint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x22, 0x04, 0x02, 0xa8, 0x7f, 0x1b, 0x68, 0x7a, 0xc0, 0xe5, 0x7d,
        0x2a, 0x08, 0x1a, 0x2f, 0x28, 0x26, 0x72, 0x33, 0x4d, 0x90, 0xed, 0x31,
        0x6d, 0x2b, 0x81, 0x8c, 0xa9, 0x58, 0x0e, 0xa3, 0x84, 0xd9, 0x24, 0x01,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN SSHFP 4 2 a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401\n",
        text,
    );
}

test "query formatter prints RFC 7218 TLSA acronyms and lowercase association" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x23, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04,
        'a',  'r',  'p',  'a',  0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x0e,
        0x10, 0x00, 0x05, 0x03, 0x01, 0x00, 0xaa, 0xbb,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN TLSA PKIX-TA Cert SHA2-256 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n" ++
            "host.home.arpa. 3600 IN TLSA DANE-EE SPKI Full aabb\n",
        text,
    );
}

test "query formatter prints URI target with zone escapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x13, 0x00, 0x0a, 0x00, 0x01, 'h',  't',  't',  'p',  's',  ':',
        '/',  '/',  'a',  '"',  'b',  '\\', 'c',  0x00, 0xff,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN URI 10 1 \"https://a\\\"b\\\\c\\000\\255\"\n",
        text,
    );
}

test "query formatter prints NAPTR fields as escaped zone text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x23, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x23,
        0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x17, 0x00, 0x64, 0x00, 0x0a,
        0x01, 'U',  0x0c, 'E',  '2',  'U',  '+',  '"',  '\\', 0xe6, 0x9c, 0x8d,
        0xe5, 0x8a, 0xa1, 0x02, 0xc3, 0xa9, 0x00,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN NAPTR 100 10 \"U\" \"E2U+\\\"\\\\服务\" \"é\" .\n",
        output.written(),
    );
}

test "query formatter prints APL items in wire order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x2a, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x2a,
        0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x18, 0x00, 0x01, 0x18, 0x83,
        0xc0, 0x00, 0x02, 0x00, 0x02, 0x30, 0x06, 0x20, 0x01, 0x0d, 0xb8, 0x00,
        0x01, 0x00, 0x01, 0x18, 0x03, 0xc0, 0x00, 0x02,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN APL !1:192.0.2.0/24 2:2001:db8:1::/48 1:192.0.2.0/24\n",
        output.written(),
    );
}

test "query formatter prints HTTPS service mode in zone shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 's',  'v',  'c',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x00, 0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x2a, 0x00, 0x01, 0x06, 't',  'a',  'r',  'g',
        'e',  't',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00,
        0x01, 0x00, 0x06, 0x02, 'h',  '2',  0x02, 'h',  '3',  0x00, 0x03, 0x00,
        0x02, 0x01, 0xbb, 0x00, 0x04, 0x00, 0x04, 192,  0,    2,    1,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "svc.example. 3600 IN HTTPS 1 target.example. alpn=\"h2,h3\" port=443 ipv4hint=192.0.2.1\n",
        output.written(),
    );
}

test "query formatter prints SVCB flags mandatory list and generic keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 's',  'v',  'c',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x00, 0x00, 0x40, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x40, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x15, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x02, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02,
        0x00, 0xff,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "svc.example. 3600 IN SVCB 1 . mandatory=no-default-alpn,key10 no-default-alpn key10=00ff\n",
        output.written(),
    );
}

test "query formatter prints AFSDB subtype and hostname" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x05, 'a',  'f',  's',  'd',  'b',  0x04, 'h',  'o',  'm',  'e',  0x04,
        'a',  'r',  'p',  'a',  0x00, 0x00, 0x12, 0x00, 0x01, 0xc0, 0x0c, 0x00,
        0x12, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0b, 0x00, 0x2a, 0x06,
        's',  'e',  'r',  'v',  'e',  'r',  0xc0, 0x12,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "afsdb.home.arpa. 3600 IN AFSDB 42 server.home.arpa.\n",
        output.written(),
    );
}

test "query formatter prints RP mailbox and TXT names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'r',  'p',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',  'p',
        'a',  0x00, 0x00, 0x11, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x11, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x10, 0x00, 0x13, 0x04, 'm',  'b',  'o',  'x',  0xc0,
        0x0f, 0x09, 't',  'x',  't',  '-',  'd',  'n',  'a',  'm',  'e',  0xc0,
        0x0f,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "rp.home.arpa. 3600 IN RP mbox.home.arpa. txt-dname.home.arpa.\n",
        output.written(),
    );
}

test "query formatter prints RT preference and intermediate hostname" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'r',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',  'p',
        'a',  0x00, 0x00, 0x15, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x15, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x10, 0x00, 0x14, 0x00, 0x64, 0x06, 't',  'a',  'r',
        'g',  'e',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',  'p',
        'a',  0x00,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "rt.home.arpa. 3600 IN RT 100 target.home.arpa.\n",
        output.written(),
    );
}

test "query formatter prints MX SOA PTR DNAME and typed HINFO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x04, 'm',  'a',  'i',  'l',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',
        'e',  0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x00, 0x0a, 0xc0, 0x0c, 0xc0, 0x11,
        0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x27, 0x03, 'n',
        's',  '1',  0xc0, 0x11, 0x0a, 'h',  'o',  's',  't',  'm',  'a',  's',
        't',  'e',  'r',  0xc0, 0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e,
        0x10, 0x00, 0x00, 0x03, 0x84, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x01,
        0x2c, 0x03, 'p',  't',  'r',  0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x07, 0x04, 'h',  'o',  's',  't',  0xc0, 0x11,
        0x05, 'a',  'l',  'i',  'a',  's',  0xc0, 0x11, 0x00, 0x27, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x10, 0x00, 0x10, 0x06, 't',  'a',  'r',  'g',  'e',
        't',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x04, 'i',
        'n',  'f',  'o',  0xc0, 0x11, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x0e,
        0x10, 0x00, 0x08, 0x02, 'P',  'C',  0x04, 'U',  'N',  'I',  'X',
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "mail.example. 3600 IN MX 10 mail.example.\n" ++
            "example. 3600 IN SOA ns1.example. hostmaster.example. 1 3600 900 1209600 300\n" ++
            "ptr.example. 3600 IN PTR host.example.\n" ++
            "alias.example. 3600 IN DNAME target.example.\n" ++
            "info.example. 3600 IN HINFO \"PC\" \"UNIX\"\n",
        output.written(),
    );
}

test "query formatter keeps unknown TYPE fallback lossless in RFC 3597 form" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x63, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x63,
        0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN TYPE99 \\# aabbcc\n",
        output.written(),
    );
}

test "query formatter prints SRV priority weight port and target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 's',  'r',  'v',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',
        'p',  'a',  0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x21, 0x00,
        0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x18, 0x00, 0x0a, 0x00, 0x14, 0x20,
        0xfb, 0x06, 't',  'a',  'r',  'g',  'e',  't',  0x04, 'h',  'o',  'm',
        'e',  0x04, 'a',  'r',  'p',  'a',  0x00,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "srv.home.arpa. 3600 IN SRV 10 20 8443 target.home.arpa.\n",
        output.written(),
    );
}

test "query formatter prints CAA with canonical tag and raw value escapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x01, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0b, 0x80, 0x05, 'I',  's',
        'S',  'u',  'E',  'a',  0x00, 0x80, 0xff,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN CAA 128 issue \"a\\000\\128\\255\"\n",
        output.written(),
    );
}

test "query formatter prints X25 as a quoted decimal address" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x44, 0x63, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 'x',  '2',  '5',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',  'r',
        'p',  'a',  0x00, 0x00, 0x13, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x13, 0x00,
        0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x05, 0x04, '1',  '2',  '3',  '4',
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "x25.home.arpa. 3600 IN X25 \"1234\"\n",
        output.written(),
    );
}

test "query formatter prints ISDN address and optional subaddress" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x44, 0x64, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'i',  's',  'd',  'n',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x14, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x09, 0x04, '1',  '2',  '3',
        '4',  0x03, 'a',  'B',  'f',
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "isdn.home.arpa. 3600 IN ISDN \"1234\" \"aBf\"\n",
        output.written(),
    );
}

test "query formatter prints HINFO as two quoted strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x44, 0x65, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x05, 'h',  'i',  'n',  'f',  'o',  0x04, 'h',  'o',  'm',  'e',  0x04,
        'a',  'r',  'p',  'a',  0x00, 0x00, 0x0d, 0x00, 0x01, 0xc0, 0x0c, 0x00,
        0x0d, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0c, 0x05, 'I',  'n',
        't',  'e',  'l',  0x05, 'L',  'i',  'n',  'u',  'x',
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        "hinfo.home.arpa. 3600 IN HINFO \"Intel\" \"Linux\"\n",
        output.written(),
    );
}

test "query formatter streams multi-answer output beyond 4096 bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var bytes: [6000]u8 = undefined;
    bytes[0..12].* = .{ 0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00 };
    @memcpy(bytes[12..25], &[_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    std.mem.writeInt(u16, bytes[25..27], 1, .big);
    std.mem.writeInt(u16, bytes[27..29], 1, .big);
    const answer = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1 };
    var offset: usize = 29;
    var index: usize = 0;
    while (index < 300) : (index += 1) {
        @memcpy(bytes[offset .. offset + answer.len], &answer);
        offset += answer.len;
    }

    const response = try dns_message.Message.parse(arena.allocator(), bytes[0..offset]);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expect(output.written().len > 4096);
}

test "query formatter prints response code when there are no answers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x81, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expectEqualStrings("rcode REFUSED\nno answers\n", text);
}

test "query formatter prints YXRRSET and BADCOOKIE for the shared low nibble" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // RFC 2136 section 1.3: a bare low nibble 7 is YXRRSET.
    const yxrrset = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x81, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(yxrrset, &output.writer);
    try std.testing.expectEqualStrings("rcode YXRRSET\nno answers\n", output.written());

    // RFC 7873 section 8: the same low nibble with an OPT extended-rcode of 1
    // is BADCOOKIE.
    const badcookie = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x81, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    var extended_output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer extended_output.deinit();
    try writeResponse(badcookie, &extended_output.writer);
    try std.testing.expectEqualStrings(
        ";; OPT PSEUDOSECTION:\n" ++
            "; EDNS: version: 0, flags: udp: 1232, ext-rcode: 1\n" ++
            "rcode BADCOOKIE\n" ++
            "no answers\n",
        extended_output.written(),
    );
}

test "query formatter prints the authority section a signature proof lives in" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // One A answer, one NSEC in the authority section where RFC 4035 section
    // 3.1.4 denial-of-existence proofs arrive, and the EDNS OPT pseudo-record
    // that is not an RRset and must not be printed.
    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x44, 0x01, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x0e, 0x10, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x50, 0x07, 'e',  'x',
        'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00,
        0x0e, 0x10, 0x00, 0x15, 0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    try std.testing.expectEqualStrings(
        ";; OPT PSEUDOSECTION:\n" ++
            "; EDNS: version: 0, flags:do udp: 1232\n" ++
            "www.example. 3600 IN A 192.0.2.80\n" ++
            ";; AUTHORITY SECTION:\n" ++
            "example. 3600 IN TYPE47 \\# 03777777076578616d706c650000060000000000c0\n",
        output.written(),
    );
}

test "UDP query client ignores invalid datagrams before a valid response" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    var attacker_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var attacker_socket = try std.Io.net.IpAddress.bind(&attacker_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer attacker_socket.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try buildQueryPacket(&query_buffer, 0x9999, "dns.home.arpa.", .A, false);

    // The first datagram has the wrong source. The second has the expected
    // source but is a query (QR=0), so both must be ignored before the real
    // response is accepted.
    try attacker_socket.send(io, &client_socket.address, query);
    try server_socket.send(io, &client_socket.address, query);
    try sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var response_buffer: [512]u8 = undefined;
    const response = try receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, &server_socket.address, query);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "TCP query client talks to authoritative stream handler" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try buildQueryPacket(&query_buffer, 0x999a, "dns.home.arpa.", .A, false);
    try sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);
    try listener.serveTcpStreamOnce(server_stream, io, &runtime);
    var response_buffer: [512]u8 = undefined;
    const response = try receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, query);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

test "the query packet carries an empty ZONEVERSION option when the operator asks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacketWithEdns(&buffer, 0x1234, "target.home.arpa.", .A, .{ .zoneversion = true });
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    try std.testing.expect(parsed.edns != null);
    try std.testing.expectEqual(@as(u16, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE), parsed.edns.?.udp_payload_size);
    const options = optOptions(parsed) orelse return error.NoEdnsOptions;
    const opt_data = dns_rdata.findOption(options, dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) orelse return error.ZoneversionMissing;
    try std.testing.expectEqual(@as(usize, 0), opt_data.len);
}
test "the query packet carries an empty NSID option when the operator asks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacketWithEdns(&buffer, 0x1234, "target.home.arpa.", .A, .{ .nsid = true });
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.additional_count);
    const options = optOptions(parsed) orelse return error.NoEdnsOptions;
    const opt_data = dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE) orelse return error.NsidMissing;
    // RFC 5001 section 2.1: the request carries no payload data of its own.
    try std.testing.expectEqual(@as(usize, 0), opt_data.len);
}
test "the query packet carries both EDNS options in one OPT record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacketWithEdns(&buffer, 0x1234, "target.home.arpa.", .A, .{ .zoneversion = true, .nsid = true });
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    const options = optOptions(parsed) orelse return error.NoEdnsOptions;
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_ZONEVERSION_OPTION_CODE) != null);
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_NSID_OPTION_CODE) != null);
}
test "query formatter prints the OPT pseudosection with the RFC 9660 zone version" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x13, 0x00, 0x06,
        0x02, 0x00, 0x78, 0x95, 0xa4, 0xe9,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, ";; OPT PSEUDOSECTION:") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "; ZONEVERSION: SOA-SERIAL 2023073001 (example.com.)") != null);
}

test "query formatter prints the NSID payload as hexadecimal per RFC 5001 section 2.4" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // A response whose OPT carries an NSID option (code 3) with the payload
    // octets 0x0a 0xff 0x6e. Section 2.4 presents every octet as two
    // hexadecimal digits, so an octet below 0x10 keeps its leading zero.
    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
        0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x03, 0x00, 0x03,
        0x0a, 0xff, 0x6e,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "; NSID: 0aff6e") != null);
}
