const std = @import("std");
const dns_header = @import("../dns/header.zig");
const dns_message = @import("../dns/message.zig");
const dns_name = @import("../dns/name.zig");
const dns_question = @import("../dns/question.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const listener = @import("../platform/listener.zig");
const Runtime = @import("../auth/runtime.zig").Runtime;

pub const Error = error{
    OutputTooSmall,
    BadName,
    UnsupportedType,
    BadResponse,
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
    };
}

pub fn sendUdpQuery(socket: *const std.Io.net.Socket, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8) !void {
    try socket.send(io, server, query);
}

pub fn receiveUdpResponse(allocator: std.mem.Allocator, socket: *const std.Io.net.Socket, io: std.Io, buffer: []u8, expected_id: u16) !dns_message.Message {
    const incoming = try socket.receiveTimeout(io, buffer, .{ .duration = .{
        .raw = .fromMilliseconds(1000),
        .clock = .awake,
    } });
    const response = try dns_message.Message.parse(allocator, incoming.data);
    if (response.header.id != expected_id) return Error.BadResponse;
    return response;
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

pub fn receiveTcpResponse(allocator: std.mem.Allocator, stream: std.Io.net.Stream, io: std.Io, buffer: []u8, expected_id: u16) !dns_message.Message {
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const len_bytes = try reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, len_bytes, .big);
    if (response_len == 0 or response_len > buffer.len) return Error.BadResponse;
    const response_bytes = try reader.interface.take(response_len);
    @memcpy(buffer[0..response_bytes.len], response_bytes);
    const response = try dns_message.Message.parse(allocator, buffer[0..response_bytes.len]);
    if (response.header.id != expected_id) return Error.BadResponse;
    return response;
}

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

test "UDP query client talks to authoritative listener socket" {
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

    var query_buffer: [512]u8 = undefined;
    const query = try buildQueryPacket(&query_buffer, 0x9999, "dns.home.arpa.", .A);
    try sendUdpQuery(&client_socket, io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);
    var response_buffer: [512]u8 = undefined;
    const response = try receiveUdpResponse(arena.allocator(), &client_socket, io, &response_buffer, 0x9999);
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
    try listener.serveTcpStreamOnce(server_stream, io, &runtime);
    var response_buffer: [512]u8 = undefined;
    const response = try receiveTcpResponse(arena.allocator(), client_stream, io, &response_buffer, 0x999a);
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
