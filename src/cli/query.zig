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
    OutputTooSmall,
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

pub fn formatResponse(response: dns_message.Message, buffer: []u8) ![]const u8 {
    var writer = TextWriter.init(buffer);
    var name_buffer: [256]u8 = undefined;
    var value_buffer: [256]u8 = undefined;

    if (response.answers.len == 0) {
        if (response.header.rcode != .no_error) {
            try writer.writeBytes("rcode ");
            try writer.writeBytes(rcodeName(response.header.rcode));
            try writer.writeBytes("\n");
        }
        try writer.writeBytes("no answers\n");
        return writer.written();
    }

    var index: usize = 0;
    while (index < response.answers.len) : (index += 1) {
        const record = response.answers.items[index];
        const owner = record.owner.toText(&name_buffer) catch return Error.OutputTooSmall;
        try writer.writeBytes(owner);
        try writer.writeBytes(" ");
        try writer.print("{}", .{record.ttl});
        try writer.writeBytes(" IN ");
        if (record.rrtype.eql(.A)) {
            try writer.writeBytes("A ");
            try writer.print("{}.{}.{}.{}", .{ record.rdata.A[0], record.rdata.A[1], record.rdata.A[2], record.rdata.A[3] });
        } else if (record.rrtype.eql(.AAAA)) {
            try writer.writeBytes("AAAA ");
            try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                record.rdata.AAAA[0],  record.rdata.AAAA[1],  record.rdata.AAAA[2],  record.rdata.AAAA[3],
                record.rdata.AAAA[4],  record.rdata.AAAA[5],  record.rdata.AAAA[6],  record.rdata.AAAA[7],
                record.rdata.AAAA[8],  record.rdata.AAAA[9],  record.rdata.AAAA[10], record.rdata.AAAA[11],
                record.rdata.AAAA[12], record.rdata.AAAA[13], record.rdata.AAAA[14], record.rdata.AAAA[15],
            });
        } else if (record.rrtype.eql(.CNAME)) {
            const target = record.rdata.CNAME.toText(&value_buffer) catch return Error.OutputTooSmall;
            try writer.writeBytes("CNAME ");
            try writer.writeBytes(target);
        } else if (record.rrtype.eql(.NS)) {
            const target = record.rdata.NS.toText(&value_buffer) catch return Error.OutputTooSmall;
            try writer.writeBytes("NS ");
            try writer.writeBytes(target);
        } else if (record.rrtype.eql(.TXT)) {
            try writer.writeBytes("TXT \"");
            try writer.writeBytes(record.rdata.TXT.text());
            try writer.writeBytes("\"");
        } else {
            try writer.writeBytes("TYPE");
            try writer.print("{}", .{record.rrtype.code()});
        }
        try writer.writeBytes("\n");
    }
    return writer.written();
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

const TextWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn init(buffer: []u8) TextWriter {
        return .{ .buffer = buffer };
    }

    fn written(self: TextWriter) []const u8 {
        return self.buffer[0..self.offset];
    }

    fn writeBytes(self: *TextWriter, bytes: []const u8) Error!void {
        if (self.buffer.len - self.offset < bytes.len) return Error.OutputTooSmall;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn print(self: *TextWriter, comptime fmt: []const u8, args: anytype) Error!void {
        const out = std.fmt.bufPrint(self.buffer[self.offset..], fmt, args) catch return Error.OutputTooSmall;
        self.offset += out.len;
    }
};

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
    var output: [256]u8 = undefined;
    const text = try formatResponse(response, &output);
    try std.testing.expect(std.mem.indexOf(u8, text, "www.example.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "CNAME example.") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "A 192.0.2.1") != null);
}

test "query formatter prints response code when there are no answers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const response = try dns_message.Message.parse(arena.allocator(), &.{
        0x12, 0x34, 0x81, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'a',  'd',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
        'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
    });
    var output: [256]u8 = undefined;
    const text = try formatResponse(response, &output);
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
