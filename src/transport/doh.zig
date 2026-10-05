/// Contract: Serves the RFC 8484 DNS-over-HTTPS message mapping (GET
/// /dns-query?dns=<base64url> and POST /dns-query with application/dns-message
/// bodies) on an already-TLS-terminated HTTP/1.1 byte channel, sharing
/// runtime.answer with the Do53/DoT paths. ZIMDNS has no TLS server, so nothing
/// in this repository can produce such a channel: there is deliberately no
/// bind/accept entry point here, and the --serve-doh startup gate refuses
/// before opening a socket (tls.zig, docs/decisions/encrypted-transport.md).
/// HTTP/2 framing additionally needs the reviewed HTTP/2 dependency, so this
/// module is the HTTP/1.1 mapping subset, not a full RFC 8484 transport claim.
/// Ownership: Request/response scratch lives in caller buffers or a
/// per-exchange arena; runtime zones stay borrowed.
/// Errors: HTTP mapping failures map to HTTP status codes and never reach
/// the resolver; socket failures propagate as I/O errors.
const std = @import("std");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const dns_message = @import("../dns/message.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("tls.zig");

pub const doh_path = "/dns-query";
pub const dns_message_media_type = "application/dns-message";
pub const DOH_PORT = tls_policy.doh_port;
pub const MAX_BODY_LEN: usize = 65535;
pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_EXCHANGES_PER_CONNECTION: usize = 16;
/// Five-second socket I/O budget shared with the Do53/DoT TCP paths.
pub const DOH_IO_TIMEOUT = tcp_deadline.Timeout{ .seconds = 5 };
/// HTTP/1.1 stream write buffering. The writer flushes incrementally, so a
/// full 64KB DNS body never needs to sit in the stack write buffer.
pub const DOH_WRITE_BUFFER_SIZE: usize = 8192;

comptime {
    std.debug.assert(DOH_WRITE_BUFFER_SIZE < MAX_BODY_LEN);
}

pub const Error = error{
    BadRequestLine,
    UnsupportedMethod,
    BadTarget,
    HeadersTooLarge,
    BodyTooLarge,
    TruncatedBody,
    BadContentType,
    BadBase64,
    BadDnsMessage,
    EncodeFailed,
};

const Status = enum(u16) {
    ok = 200,
    bad_request = 400,
    not_found = 404,
    method_not_allowed = 405,
    uri_too_long = 414,
    unsupported_media_type = 415,
    request_header_fields_too_large = 431,
    payload_too_large = 413,
    internal_error = 500,

    fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .bad_request => "Bad Request",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .payload_too_large => "Payload Too Large",
            .internal_error => "Internal Server Error",
        };
    }
};

fn statusForError(err: anyerror) Status {
    return switch (err) {
        Error.UnsupportedMethod => .method_not_allowed,
        Error.BadTarget => .not_found,
        Error.HeadersTooLarge => .request_header_fields_too_large,
        Error.BodyTooLarge => .payload_too_large,
        Error.BadContentType => .unsupported_media_type,
        else => .bad_request,
    };
}

const ParsedRequest = struct {
    method_is_get: bool,
    method_is_post: bool,
    target: []u8,
    content_type: ?[]u8,
    content_length: ?usize,
    close: bool,
};

fn trimCr(line: []u8) []u8 {
    if (line.len != 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}

/// Takes one CRLF-terminated line without the terminator. A clean EOF on the
/// first line propagates as EndOfStream so keep-alive loops can end quietly;
/// any other framing failure is a BadRequestLine.
fn readLine(reader: *std.Io.Reader, arena: std.mem.Allocator) ![]u8 {
    const raw = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => return Error.BadRequestLine,
    };
    const nl = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return Error.TruncatedBody,
        else => return Error.BadRequestLine,
    };
    if (nl != '\n') return Error.BadRequestLine;
    return arena.dupe(u8, trimCr(raw)) catch return Error.BadRequestLine;
}

/// Reads one HTTP/1.1 request head plus body. Bodies are bounded by
/// MAX_BODY_LEN; heads are bounded by MAX_HEADER_BYTES.
fn readRequest(reader: *std.Io.Reader, arena: std.mem.Allocator) !struct { head: ParsedRequest, body: []u8 } {
    const request_line = try readLine(reader, arena);
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return Error.BadRequestLine;
    const target = parts.next() orelse return Error.BadRequestLine;
    const version = parts.next() orelse return Error.BadRequestLine;
    if (parts.next() != null) return Error.BadRequestLine;
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return Error.BadRequestLine;

    const method_is_get = std.mem.eql(u8, method, "GET");
    const method_is_post = std.mem.eql(u8, method, "POST");
    if (!method_is_get and !method_is_post) return Error.UnsupportedMethod;

    var head = ParsedRequest{
        .method_is_get = method_is_get,
        .method_is_post = method_is_post,
        .target = arena.dupe(u8, target) catch return Error.BadRequestLine,
        .content_type = null,
        .content_length = null,
        .close = std.mem.eql(u8, version, "HTTP/1.0"),
    };
    var header_bytes: usize = request_line.len;
    while (true) {
        const line = try readLine(reader, arena);
        header_bytes += line.len;
        if (header_bytes > MAX_HEADER_BYTES) return Error.HeadersTooLarge;
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.BadRequestLine;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            head.content_type = arena.dupe(u8, value) catch return Error.BadRequestLine;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            head.content_length = std.fmt.parseInt(usize, value, 10) catch return Error.BadRequestLine;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.eqlIgnoreCase(value, "close")) head.close = true;
        }
    }

    var body: []u8 = &.{};
    if (method_is_post) {
        const length = head.content_length orelse return Error.BadRequestLine;
        if (length > MAX_BODY_LEN) return Error.BodyTooLarge;
        if (length == 0) return Error.BadRequestLine;
        body = arena.alloc(u8, length) catch return Error.BadRequestLine;
        reader.readSliceAll(body) catch return Error.TruncatedBody;
    }
    return .{ .head = head, .body = body };
}

fn pathOf(target: []const u8) []const u8 {
    var rest = target;
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        rest = rest[scheme_end + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
            rest = rest[slash..];
        } else {
            return rest;
        }
    }
    if (std.mem.indexOfScalar(u8, rest, '?')) |query_start| return rest[0..query_start];
    return rest;
}

fn queryOf(target: []const u8) []const u8 {
    var rest = target;
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        rest = rest[scheme_end + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
            rest = rest[slash..];
        } else {
            return &.{};
        }
    }
    const query_start = std.mem.indexOfScalar(u8, rest, '?') orelse return &.{};
    return rest[query_start + 1 ..];
}

/// Extracts the single RFC 8484 section 4.1 `dns` query parameter.
fn dnsParam(query: []const u8) Error![]const u8 {
    var found: ?[]const u8 = null;
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        if (!std.mem.startsWith(u8, pair, "dns=")) continue;
        if (found != null) return Error.BadDnsMessage;
        found = pair["dns=".len..];
    }
    const value = found orelse return Error.BadDnsMessage;
    if (value.len == 0 or value.len > MAX_HEADER_BYTES) return Error.BadDnsMessage;
    return value;
}

fn decodeQueryParam(arena: std.mem.Allocator, value: []const u8) Error![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const out_len = decoder.calcSizeForSlice(value) catch return Error.BadBase64;
    if (out_len == 0 or out_len > MAX_BODY_LEN) return Error.BadDnsMessage;
    const out = arena.alloc(u8, out_len) catch return Error.BadDnsMessage;
    decoder.decode(out, value) catch return Error.BadBase64;
    return out;
}

/// Maps one parsed request to DNS wire bytes per RFC 8484 sections 4.1/4.2.
pub fn dnsQueryFromRequest(arena: std.mem.Allocator, head: ParsedRequest, body: []u8) Error![]u8 {
    if (!std.mem.eql(u8, pathOf(head.target), doh_path)) return Error.BadTarget;
    if (head.method_is_get) {
        if (head.target.len > MAX_HEADER_BYTES) return Error.BadDnsMessage;
        return decodeQueryParam(arena, try dnsParam(queryOf(head.target)));
    }
    const content_type = head.content_type orelse return Error.BadContentType;
    if (!std.mem.eql(u8, content_type, dns_message_media_type)) return Error.BadContentType;
    if (body.len == 0 or body.len > MAX_BODY_LEN) return Error.BadDnsMessage;
    return body;
}

fn minTtl(message: *const dns_message.Message) u32 {
    var floor: ?u32 = null;
    for ([2][]const @import("../dns/record.zig").ResourceRecord{ message.answers.slice(), message.authorities.slice() }) |section| {
        for (section) |record| {
            floor = if (floor) |current| @min(current, record.ttl) else record.ttl;
        }
    }
    return floor orelse 0;
}

fn writeError(writer: *std.Io.Writer, status: Status) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n", .{
        @intFromEnum(status),
        status.reason(),
    });
}

fn writeDnsResponse(writer: *std.Io.Writer, body: []const u8, max_age: u32, close: bool) !void {
    try writer.print("HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {d}\r\ncache-control: max-age={d}\r\nconnection: {s}\r\n\r\n", .{
        body.len,
        max_age,
        if (close) "close" else "keep-alive",
    });
    try writer.writeAll(body);
}

/// Serves one HTTP/1.1 exchange. Returns true when the connection must close.
pub fn serveDohExchange(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    arena: std.mem.Allocator,
    runtime: *const Runtime,
    counters: ?*metrics.Counters,
) !bool {
    const parsed = readRequest(reader, arena) catch |err| {
        if (err == error.EndOfStream) return error.EndOfStream;
        try writeError(writer, statusForError(err));
        try writer.flush();
        return true;
    };
    const query = dnsQueryFromRequest(arena, parsed.head, parsed.body) catch |err| {
        try writeError(writer, statusForError(err));
        try writer.flush();
        return true;
    };
    if (counters) |value| {
        value.queries_total += 1;
        value.doh_queries_total += 1;
    }

    // Everything below lives in the per-exchange arena: one heap allocation
    // per exchange, freed together when the exchange ends. No 64KB stack
    // buffers and no page_allocator arenas escape this exchange.
    const request_message = dns_message.Message.parseQuery(arena, query) catch {
        try writeError(writer, .bad_request);
        try writer.flush();
        return true;
    };
    _ = request_message;

    const response_buffer = arena.alloc(u8, MAX_BODY_LEN) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    const response_bytes = if (counters) |value|
        runtime.answerWithMetrics(query, response_buffer, value) catch |err| return serveRuntimeError(writer, err)
    else
        runtime.answer(query, response_buffer) catch |err| return serveRuntimeError(writer, err);

    const response_message = dns_message.Message.parse(arena, response_bytes) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    try writeDnsResponse(writer, response_bytes, minTtl(&response_message), parsed.head.close);
    try writer.flush();
    return parsed.head.close;
}

fn serveRuntimeError(writer: *std.Io.Writer, err: anyerror) !bool {
    return switch (err) {
        error.BadQuery => {
            try writeError(writer, .bad_request);
            try writer.flush();
            return true;
        },
        else => {
            try writeError(writer, .internal_error);
            try writer.flush();
            return true;
        },
    };
}

pub fn serveDohStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    return serveDohStream(stream, io, runtime, null);
}

pub fn serveDohStreamOnceWithMetrics(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    counters: *metrics.Counters,
) !void {
    return serveDohStream(stream, io, runtime, counters);
}

fn serveDohStream(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, counters: ?*metrics.Counters) !void {
    tcp_deadline.setSocketTimeout(stream.socket.handle, DOH_IO_TIMEOUT);

    var read_buffer: [MAX_HEADER_BYTES]u8 = undefined;
    var write_buffer: [DOH_WRITE_BUFFER_SIZE]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var writer = stream.writer(io, &write_buffer);
    var exchanges: usize = 0;
    while (exchanges < MAX_EXCHANGES_PER_CONNECTION) : (exchanges += 1) {
        // Block-scoped so the arena frees at the end of each exchange, not
        // at connection close: memory stays bounded across keep-alive.
        const must_close = blk: {
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            break :blk serveDohExchange(&reader.interface, &writer.interface, arena.allocator(), runtime, counters) catch |err| {
                if (err == error.EndOfStream or err == error.ReadFailed) {
                    if (exchanges == 0) return error.EndOfStream;
                    return;
                }
                return err;
            };
        };
        if (must_close) return;
    }
}

fn streamPair() ![2]std.Io.net.Stream {
    var pair: [2]std.posix.fd_t = undefined;
    const result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    return .{
        .{ .socket = .{ .handle = pair[0], .address = address } },
        .{ .socket = .{ .handle = pair[1], .address = address } },
    };
}

test "DoH GET serves a base64url query with DNS media type" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "dns.home.arpa.", .A);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);

    var request_buffer: [2048]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{encoded_query});
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const status_line = try takeTestLine(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
    var content_type_ok = false;
    var content_length: usize = 0;
    while (true) {
        const trimmed = try takeTestLine(&client_reader.interface);
        if (trimmed.len == 0) break;
        if (std.ascii.eqlIgnoreCase(trimmed[0..12], "content-type")) content_type_ok = std.mem.indexOf(u8, trimmed, dns_message_media_type) != null;
        if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
            content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
        }
    }
    try std.testing.expect(content_type_ok);
    try std.testing.expect(content_length > 0);
    const body = try client_reader.interface.take(content_length);
    const response = try dns_message.Message.parse(arena.allocator(), body);
    try std.testing.expectEqual(@as(u16, 0xabcd), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "DoH POST serves an application/dns-message body" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xdcba, "dns.home.arpa.", .A);
    var request_buffer: [2048]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{query.len});
    try request_stream.writeAll(query);

    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request_stream.buffered());
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const status_line = try takeTestLine(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
    var content_length: usize = 0;
    while (true) {
        const trimmed = try takeTestLine(&client_reader.interface);
        if (trimmed.len == 0) break;
        if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
            content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
        }
    }
    const body = try client_reader.interface.take(content_length);
    const response = try dns_message.Message.parse(arena.allocator(), body);
    try std.testing.expectEqual(@as(u16, 0xdcba), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
}

test "DoH rejects wrong method, path, media type, and bad wire" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var get_head = ParsedRequest{ .method_is_get = true, .method_is_post = false, .target = @constCast("/nope?dns=AA"), .content_type = null, .content_length = null, .close = true };
    try std.testing.expectError(Error.BadTarget, dnsQueryFromRequest(arena.allocator(), get_head, &.{}));
    get_head.target = @constCast("/dns-query?dns=!!!not-base64!!!");
    try std.testing.expectError(Error.BadBase64, dnsQueryFromRequest(arena.allocator(), get_head, &.{}));
    get_head.target = @constCast("/dns-query?other=1");
    try std.testing.expectError(Error.BadDnsMessage, dnsQueryFromRequest(arena.allocator(), get_head, &.{}));
    get_head.target = @constCast("/dns-query?dns=AA&dns=BB");
    try std.testing.expectError(Error.BadDnsMessage, dnsQueryFromRequest(arena.allocator(), get_head, &.{}));
    var plain_body = [_]u8{ 'h', 'i' };
    const post_head = ParsedRequest{ .method_is_get = false, .method_is_post = true, .target = @constCast("/dns-query"), .content_type = @constCast("text/plain"), .content_length = 2, .close = true };
    try std.testing.expectError(Error.BadContentType, dnsQueryFromRequest(arena.allocator(), post_head, &plain_body));
    const no_type_head = ParsedRequest{ .method_is_get = false, .method_is_post = true, .target = @constCast("/dns-query"), .content_type = null, .content_length = 2, .close = true };
    try std.testing.expectError(Error.BadContentType, dnsQueryFromRequest(arena.allocator(), no_type_head, &plain_body));

    try std.testing.expectEqual(Status.method_not_allowed, statusForError(Error.UnsupportedMethod));
    try std.testing.expectEqual(Status.not_found, statusForError(Error.BadTarget));
    try std.testing.expectEqual(Status.unsupported_media_type, statusForError(Error.BadContentType));
    try std.testing.expectEqual(Status.payload_too_large, statusForError(Error.BodyTooLarge));
    try std.testing.expectEqual(Status.bad_request, statusForError(Error.BadDnsMessage));
}

test "DoH keep-alive serves pipelined exchanges with bounded per-exchange state" {
    try std.testing.expect(DOH_WRITE_BUFFER_SIZE < MAX_BODY_LEN);
    try std.testing.expectEqual(@as(u32, 5), DOH_IO_TIMEOUT.seconds);

    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [4096]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    for ([2]u16{ 0x1111, 0x2222 }) |id| {
        var query_buffer: [512]u8 = undefined;
        const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, id, "dns.home.arpa.", .A);
        var encoded: [1024]u8 = undefined;
        const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);
        try client_writer.interface.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    }
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    for ([2]u16{ 0x1111, 0x2222 }) |id| {
        const status_line = try takeTestLine(&client_reader.interface);
        try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
        var content_length: usize = 0;
        while (true) {
            const trimmed = try takeTestLine(&client_reader.interface);
            if (trimmed.len == 0) break;
            if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
                content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
            }
        }
        try std.testing.expect(content_length > 0);
        const body = try client_reader.interface.take(content_length);
        const response = try dns_message.Message.parse(arena.allocator(), body);
        try std.testing.expectEqual(id, response.header.id);
        try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    }
}

fn takeTestLine(reader: *std.Io.Reader) ![]u8 {
    const line = try reader.takeDelimiterExclusive('\n');
    const nl = try reader.takeByte();
    try std.testing.expectEqual(@as(u8, '\n'), nl);
    return trimCr(line);
}

test "DoH status reasons cover the served subset" {
    try std.testing.expectEqualStrings("OK", Status.ok.reason());
    try std.testing.expectEqualStrings("Bad Request", Status.bad_request.reason());
    try std.testing.expectEqualStrings("Not Found", Status.not_found.reason());
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;
