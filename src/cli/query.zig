const std = @import("std");
const dns_header = @import("../dns/header.zig");
const dns_message = @import("../dns/message.zig");
const dns_name = @import("../dns/name.zig");
const dns_question = @import("../dns/question.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
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

pub fn buildQueryPacket(buffer: []u8, id: u16, name_text: []const u8, qtype: dns_types.RecordType) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    const qname = dns_name.Name.fromText(name_text) catch return Error.BadName;
    const message = dns_message.Message{
        .header = dns_header.Header{
            .id = id,
            .recursion_desired = true,
            .question_count = 1,
        },
        .question = dns_question.Question{
            .name = qname,
            .qtype = qtype,
            .qclass = .IN,
        },
    };
    try message.encode(&writer);
    return writer.written();
}

pub fn writeResponse(response: dns_message.Message, writer: *std.Io.Writer) !void {
    var name_buffer: [256]u8 = undefined;
    var value_buffer: [256]u8 = undefined;

    if (response.answers.len == 0) {
        if (response.header.rcode != .no_error) {
            try writer.writeAll("rcode ");
            try writer.writeAll(rcodeName(response.header.rcode));
            try writer.writeAll("\n");
        }
        try writer.writeAll("no answers\n");
        return;
    }

    for (response.answers.slice()) |record| {
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
            try writer.writeAll("TLSA ");
            try writer.print("{} {} {} ", .{ tlsa.usage, tlsa.selector, tlsa.matching_type });
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
        } else if (record.rrtype.eql(.APL)) {
            try writer.writeAll("APL");
            try writeApl(writer, record.rdata.APL.bytes());
        } else {
            try writer.writeAll("TYPE");
            try writer.print("{}", .{record.rrtype.code()});
        }
        try writer.writeAll("\n");
    }
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
        .badcookie => "BADCOOKIE",
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
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const len_bytes = try reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, len_bytes, .big);
    if (response_len == 0 or response_len > buffer.len) return Error.BadResponse;
    const response_bytes = try reader.interface.take(response_len);
    @memcpy(buffer[0..response_bytes.len], response_bytes);
    const response = try dns_message.Message.parse(allocator, buffer[0..response_bytes.len]);
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
        setSocketTimeout(stream, TCP_IO_TIMEOUT);

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

    fn setSocketTimeout(stream: std.Io.net.Stream, timeout: tcp_deadline.Timeout) void {
        const posix_timeout: std.posix.timeval = .{
            .sec = @intCast(timeout.seconds),
            .usec = @intCast(timeout.microseconds),
        };
        const timeout_bytes = std.mem.asBytes(&posix_timeout);
        _ = std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, timeout_bytes) catch {};
        _ = std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, timeout_bytes) catch {};
    }
} else struct {};

test "query builder encodes standard A query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var buffer: [512]u8 = undefined;
    const packet = try buildQueryPacket(&buffer, 0x1234, "example.com.", .A);
    const parsed = try dns_message.Message.parseQuery(arena.allocator(), packet);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try std.testing.expect(parsed.header.recursion_desired);
    try std.testing.expect(parsed.question.?.qtype.eql(.A));
}

test "response validation requires QR and the exact question" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try buildQueryPacket(&query_buffer, 0x1234, "example.com.", .A);
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

test "query formatter prints TLSA selectors and lowercase association" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 'h',  'o',  's',  't',  0x04, 'h',  'o',  'm',  'e',  0x04, 'a',
        'r',  'p',  'a',  0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x23, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    });
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeResponse(response, &output.writer);
    const text = output.written();
    try std.testing.expectEqualStrings(
        "host.home.arpa. 3600 IN TLSA 0 0 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
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
    const query = try buildQueryPacket(&query_buffer, 0x9999, "dns.home.arpa.", .A);

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
    const query = try buildQueryPacket(&query_buffer, 0x999a, "dns.home.arpa.", .A);
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
