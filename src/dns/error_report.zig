/// Contract: Builds the RFC 9567 Report-Channel agent domain and the report query name.
/// Ownership: Every value is inline or borrowed from the caller's Name; the module allocates nothing.
/// Errors: A malformed payload yields null rather than an error; no file or socket I/O occurs.
const std = @import("std");
const dns_name = @import("name.zig");
const dns_rdata = @import("rdata.zig");

const Name = dns_name.Name;

/// RFC 9567 section 5: the Report-Channel option code. The value lives with
/// the other EDNS(0) option codes; this is the name the error reporting
/// path uses.
pub const option_code: u16 = dns_rdata.EDNS_REPORT_CHANNEL_OPTION_CODE;

/// RFC 1035 section 2.3.4: a domain name is at most 255 octets in wire form.
const max_wire_len = 255;

/// RFC 1035 section 2.3.4: a label is at most 63 octets.
const max_label_len = 63;

/// The label RFC 9567 section 6.1.1 puts at both ends of a report query name.
const report_label = "_er";

/// RFC 9567 section 5: the AGENT DOMAIN field of the Report-Channel option
/// is a fully qualified, uncompressed domain name in DNS wire format.
pub fn agentDomainWire(agent: *const Name) []const u8 {
    return agent.asWire();
}

/// RFC 9567 section 5: the agent domain an option payload carries, or null
/// when the payload is not a domain name in uncompressed wire form. The
/// payload is parsed as its own buffer, so a compression pointer can never
/// reach outside it, and a payload that is not exactly one name, or that
/// carries a pointer, is refused.
pub fn parseAgentDomain(payload: []const u8) ?Name {
    var offset: usize = 0;
    var complete = false;
    while (offset < payload.len) {
        const label_len = payload[offset];
        // A byte with the top two bits set is a compression pointer, and the
        // other reserved label types are not a name at all. The option
        // carries an uncompressed name, so both are refused.
        if (label_len & 0xc0 != 0) return null;
        if (label_len == 0) {
            offset += 1;
            complete = true;
            break;
        }
        offset += 1 + label_len;
        if (offset > payload.len) return null;
    }
    // The payload holds one name and nothing else.
    if (!complete or offset != payload.len) return null;
    const parsed = Name.parse(payload, 0) catch return null;
    if (parsed.next_offset != payload.len) return null;
    return parsed.name;
}

/// RFC 9567 section 6.1.1: the report query name that carries an error
/// report, or null when the name would exceed 255 octets. The name is the
/// "_er" label, the QTYPE as a decimal label, the labels of the name that
/// failed, the extended DNS error code as a decimal label, the "_er" label
/// again, and the agent domain.
pub fn buildReportName(qtype: u16, failed: *const Name, ede_code: u16, agent: *const Name) ?Name {
    var buffer: [max_wire_len]u8 = undefined;
    var len: usize = 0;

    if (!pushLabel(&buffer, &len, report_label)) return null;
    var number_buffer: [8]u8 = undefined;
    const qtype_text = std.fmt.bufPrint(&number_buffer, "{d}", .{qtype}) catch return null;
    if (!pushLabel(&buffer, &len, qtype_text)) return null;

    var offset: usize = 0;
    const failed_wire = failed.asWire();
    while (offset < failed_wire.len) {
        const label_len = failed_wire[offset];
        if (label_len == 0) break;
        if (!pushLabel(&buffer, &len, failed_wire[offset + 1 ..][0..label_len])) return null;
        offset += 1 + label_len;
    }

    const ede_text = std.fmt.bufPrint(&number_buffer, "{d}", .{ede_code}) catch return null;
    if (!pushLabel(&buffer, &len, ede_text)) return null;
    if (!pushLabel(&buffer, &len, report_label)) return null;

    offset = 0;
    const agent_wire = agent.asWire();
    while (offset < agent_wire.len) {
        const label_len = agent_wire[offset];
        if (label_len == 0) break;
        if (!pushLabel(&buffer, &len, agent_wire[offset + 1 ..][0..label_len])) return null;
        offset += 1 + label_len;
    }

    // The root label still has to fit.
    if (len >= max_wire_len) return null;
    buffer[len] = 0;
    return nameFromWire(buffer[0 .. len + 1]);
}

/// RFC 9567 section 6.1.1: whether the name is a report query for the given
/// agent domain. The first label is "_er", the last labels are "_er" and the
/// agent domain, the label right after the first "_er" is the decimal QTYPE,
/// and the label right before the trailing "_er" is the decimal extended DNS
/// error code.
pub fn isReportName(name: *const Name, agent: *const Name) bool {
    const wire = name.asWire();
    const agent_wire = agent.asWire();
    const count = labelCount(wire);
    const agent_count = labelCount(agent_wire);
    // The "_er" label, the QTYPE, the extended DNS error code, the "_er"
    // label, and the agent domain.
    if (agent_count == 0 or count < agent_count + 4) return false;

    const first = labelAt(wire, 0) orelse return false;
    if (!std.mem.eql(u8, first, report_label)) return false;
    const qtype = labelAt(wire, 1) orelse return false;
    if (!isDecimal(qtype)) return false;

    const report_index = count - agent_count - 1;
    const trailing = labelAt(wire, report_index) orelse return false;
    if (!std.mem.eql(u8, trailing, report_label)) return false;
    const ede_code = labelAt(wire, report_index - 1) orelse return false;
    if (!isDecimal(ede_code)) return false;

    // The last labels are the agent domain, compared label by label so the
    // names match on label boundaries.
    var agent_offset: usize = 0;
    var index = report_index + 1;
    while (agent_offset < agent_wire.len) {
        const label_len = agent_wire[agent_offset];
        if (label_len == 0) break;
        const label = labelAt(wire, index) orelse return false;
        if (!std.ascii.eqlIgnoreCase(label, agent_wire[agent_offset + 1 ..][0..label_len])) return false;
        agent_offset += 1 + label_len;
        index += 1;
    }
    return true;
}

/// The number of labels in a wire name, without the root label.
fn labelCount(wire: []const u8) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (offset < wire.len) {
        const label_len = wire[offset];
        if (label_len == 0) break;
        offset += 1 + label_len;
        count += 1;
    }
    return count;
}

/// The bytes of the label at `index` in a wire name, or null when the name
/// holds no such label.
fn labelAt(wire: []const u8, index: usize) ?[]const u8 {
    var offset: usize = 0;
    var current: usize = 0;
    while (offset < wire.len) {
        const label_len = wire[offset];
        if (label_len == 0) return null;
        if (current == index) return wire[offset + 1 ..][0..label_len];
        offset += 1 + label_len;
        current += 1;
    }
    return null;
}

/// Whether the label is a decimal number.
fn isDecimal(label: []const u8) bool {
    if (label.len == 0) return false;
    for (label) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

/// Append one label to a wire name under construction. False when the label
/// or the name does not fit.
fn pushLabel(buffer: *[max_wire_len]u8, len: *usize, label: []const u8) bool {
    if (label.len == 0 or label.len > max_label_len) return false;
    // The root label still has to fit.
    if (len.* + 1 + label.len + 1 > max_wire_len) return false;
    buffer[len.*] = @intCast(label.len);
    @memcpy(buffer[len.* + 1 ..][0..label.len], label);
    len.* += 1 + label.len;
    return true;
}

/// The name a wire form holds.
fn nameFromWire(bytes: []const u8) Name {
    var name = Name{ .wire_len = 0 };
    @memcpy(name.wire[0..bytes.len], bytes);
    name.wire_len = @intCast(bytes.len);
    return name;
}

test "RFC 9567 6.1.1: the report name is the section 4.1 example" {
    const failed = try Name.fromText("broken.test.");
    const agent = try Name.fromText("a01.agent-domain.example.");

    const report = buildReportName(1, &failed, 7, &agent).?;
    var text: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "_er.1.broken.test.7._er.a01.agent-domain.example.",
        try report.toText(&text),
    );
}

test "RFC 9567 6.1.1: a report name over 255 octets is not built" {
    // A name of 63-octet labels fills the wire bound, so the report name
    // that carries it cannot fit.
    var text: [300]u8 = undefined;
    @memset(text[0..63], 'a');
    text[63] = '.';
    @memset(text[64..127], 'a');
    text[127] = '.';
    @memset(text[128..191], 'a');
    text[191] = '.';
    @memset(text[192..253], 'a');
    text[253] = '.';
    const failed = try Name.fromText(text[0..254]);
    const agent = try Name.fromText("a01.agent-domain.example.");

    try std.testing.expect(buildReportName(1, &failed, 7, &agent) == null);
}

test "the agent domain round-trips through the option payload" {
    const agent = try Name.fromText("a01.agent-domain.example.");
    const payload = agentDomainWire(&agent);

    const parsed = parseAgentDomain(payload).?;
    try std.testing.expect(parsed.eql(&agent));
    try std.testing.expectEqualSlices(u8, agent.asWire(), parsed.asWire());
}

test "a payload that is not one name, or that carries a pointer, is refused" {
    const agent = try Name.fromText("a01.agent-domain.example.");
    const payload = agentDomainWire(&agent);

    // A name with trailing octets is not one name.
    try std.testing.expect(parseAgentDomain("") == null);
    var trailing: [64]u8 = undefined;
    @memcpy(trailing[0..payload.len], payload);
    trailing[payload.len] = 0;
    try std.testing.expect(parseAgentDomain(trailing[0 .. payload.len + 1]) == null);

    // A compression pointer is not the uncompressed wire form the option
    // carries, and it must not reach outside the payload.
    const pointed = [_]u8{ 0xc0, 0x00 };
    try std.testing.expect(parseAgentDomain(&pointed) == null);
    const inside = [_]u8{ 3, 'a', 'b', 'c', 0xc0, 0x00 };
    try std.testing.expect(parseAgentDomain(&inside) == null);
}

test "a report name is recognized for its agent domain" {
    const failed = try Name.fromText("broken.test.");
    const agent = try Name.fromText("a01.agent-domain.example.");
    const report = buildReportName(1, &failed, 7, &agent).?;

    try std.testing.expect(isReportName(&report, &agent));

    // A different agent domain is not the report of this one.
    const other = try Name.fromText("a02.agent-domain.example.");
    try std.testing.expect(!isReportName(&report, &other));

    // A name that is not a report query is not one.
    const plain = try Name.fromText("broken.test.");
    try std.testing.expect(!isReportName(&plain, &agent));
}
