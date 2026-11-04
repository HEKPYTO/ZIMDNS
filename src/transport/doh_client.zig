/// Contract: Speaks DNS over HTTPS as a client (RFC 8484 §4.1 POST) for a
/// resolver that forwards instead of iterating. The TLS handshake comes from
/// the pinned inic/tls.zig dependency; this module owns the request head, the
/// `application/dns-message` media type on both directions (RFC 8484 §4.2),
/// the HTTP/1.1 response bound (status 200, content length or chunked
/// transfer), and the refusal of anything else.
/// RFC 8484 §5.2 makes HTTP/2 the minimum RECOMMENDED version; this client
/// speaks HTTP/1.1 with the `http/1.1` ALPN token, the same disclosed
/// deviation the server side carries.
/// Ownership: The trust bundle is loaded once and owned here; request and
/// response buffers are the caller's.
/// Errors: A refused handshake, a bad status or media type, and a malformed
/// or oversized body are typed as `Error`.
const std = @import("std");
const tls = @import("tls");
const http11_alpn = "http/1.1";
pub const media_type = "application/dns-message";
pub const default_path = "/dns-query";

pub const Error = error{
    HandshakeFailed,
    AlpnMismatch,
    TrustStoreEmpty,
    BadStatus,
    BadHeaders,
    BadContentType,
    BadContentLength,
    BadChunk,
    ResponseTooLarge,
    TruncatedBody,
};

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

/// The response head bound: a DoH answer's headers are small, and a peer
/// that sends more than this is refused instead of buffered forever.
pub const max_head_len: usize = 8192;

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    roots: std.crypto.Certificate.Bundle = .empty,
    roots_loaded: bool = false,

    pub fn init(self: *Client, allocator: std.mem.Allocator, io: std.Io) !void {
        self.* = .{ .allocator = allocator, .io = io };
        try self.loadRoots();
    }

    /// A client whose trust anchors are one certificate file, for a loopback
    /// server in the tests.
    pub fn initFromCertFile(self: *Client, allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
        self.* = .{ .allocator = allocator, .io = io };
        try self.roots.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), path);
        self.roots_loaded = self.roots.map.count() != 0;
    }

    /// A client whose trust anchors are one PEM bundle inside the caller
    /// supplied directory: RFC 9462 DDR trust stores resolve through the
    /// confined configuration directory, never through an absolute path.
    pub fn initFromCaFile(self: *Client, allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
        self.* = .{ .allocator = allocator, .io = io };
        try self.roots.addCertsFromFilePath(allocator, io, std.Io.Clock.real.now(io), dir, path);
        self.roots_loaded = self.roots.map.count() != 0;
    }

    pub fn deinit(self: *Client) void {
        self.roots.deinit(self.allocator);
        self.* = undefined;
    }

    fn loadRoots(self: *Client) !void {
        self.roots.rescan(self.allocator, self.io, std.Io.Clock.real.now(self.io)) catch return Error.TrustStoreEmpty;
        self.roots_loaded = self.roots.map.count() != 0;
        if (!self.roots_loaded) return Error.TrustStoreEmpty;
    }

    /// One POST exchange. The caller dials the stream; this function owns the
    /// handshake, the request head, the response head and the body framing.
    pub fn post(
        self: *Client,
        stream: std.Io.net.Stream,
        host: []const u8,
        path: []const u8,
        query: []const u8,
        response_buffer: []u8,
    ) ![]const u8 {
        return self.postWithVerification(stream, host, host, path, query, response_buffer);
    }

    /// One POST whose certificate verification host differs from the SNI
    /// on the wire. An empty `sni` sends no SNI: RFC 9462 section 6.3.
    pub fn postWithVerification(
        self: *Client,
        stream: std.Io.net.Stream,
        host: []const u8,
        sni: []const u8,
        path: []const u8,
        query: []const u8,
        response_buffer: []u8,
    ) ![]const u8 {
        if (!self.roots_loaded) return Error.TrustStoreEmpty;
        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var reader = stream.reader(self.io, &input_buffer);
        var writer = stream.writer(self.io, &output_buffer);
        const alpn = [_][]const u8{http11_alpn};
        var rng: std.Random.IoSource = .{ .io = self.io };
        var connection = tls.client(&reader.interface, &writer.interface, .{
            .rng = rng.interface(),
            .now = std.Io.Clock.real.now(self.io),
            .host = host,
            .sni = sni,
            .root_ca = self.roots,
            .alpn_protocols = &alpn,
        }) catch return Error.HandshakeFailed;
        defer connection.close() catch {};
        if (connection.alpn_protocol) |negotiated| {
            if (!std.mem.eql(u8, negotiated, http11_alpn)) return Error.AlpnMismatch;
        }

        var head_buffer: [512]u8 = undefined;
        // An IPv6 literal is bracketed in the Host authority; the
        // unbracketed text is only a certificate-verification name.
        var authority_buffer: [64]u8 = undefined;
        const authority = if (std.mem.indexOfScalar(u8, host, ':') != null and (host.len == 0 or host[0] != '['))
            std.fmt.bufPrint(&authority_buffer, "[{s}]", .{host}) catch host
        else
            host;
        const head = std.fmt.bufPrint(&head_buffer, "POST {s} HTTP/1.1\r\nHost: {s}\r\nContent-Type: {s}\r\nAccept: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
            path,
            authority,
            media_type,
            media_type,
            query.len,
        }) catch return Error.ResponseTooLarge;
        connection.writeAll(head) catch return Error.HandshakeFailed;
        connection.writeAll(query) catch return Error.HandshakeFailed;

        var received: [max_head_len + 4096]u8 = undefined;
        var filled: usize = 0;
        while (std.mem.indexOf(u8, received[0..filled], "\r\n\r\n") == null) {
            if (filled == received.len) return Error.BadHeaders;
            const n = connection.read(received[filled..]) catch return Error.TruncatedBody;
            if (n == 0) return Error.TruncatedBody;
            filled += n;
        }
        const split = std.mem.indexOf(u8, received[0..filled], "\r\n\r\n").? + 4;
        if (split > max_head_len) return Error.BadHeaders;
        const head_text = received[0..split];
        const status_ok = std.mem.startsWith(u8, head_text, "HTTP/1.1 200") or std.mem.startsWith(u8, head_text, "HTTP/1.0 200");
        if (!status_ok) return Error.BadStatus;

        var content_length: ?usize = null;
        var chunked = false;
        var content_type_ok = false;
        var lines = std.mem.splitSequence(u8, head_text, "\r\n");
        _ = lines.next();
        while (lines.next()) |line| {
            if (line.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.BadHeaders;
            const name = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "content-type")) {
                content_type_ok = containsIgnoreCase(value, media_type);
            } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                const length = std.fmt.parseInt(usize, value, 10) catch return Error.BadContentLength;
                if (content_length) |first| {
                    if (first != length) return Error.BadContentLength;
                }
                content_length = length;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                chunked = containsIgnoreCase(value, "chunked");
            }
        }
        if (!content_type_ok) return Error.BadContentType;

        var body_len: usize = 0;
        var available = filled - split;
        var cursor = split;
        if (chunked) {
            while (true) {
                while (std.mem.indexOf(u8, received[cursor..filled], "\r\n") == null) {
                    if (filled == received.len) return Error.ResponseTooLarge;
                    const n = connection.read(received[filled..]) catch return Error.TruncatedBody;
                    if (n == 0) return Error.TruncatedBody;
                    filled += n;
                }
                const line_end = std.mem.indexOf(u8, received[cursor..filled], "\r\n").?;
                const size_text = std.mem.trim(u8, received[cursor .. cursor + line_end], " \t");
                const semi = std.mem.indexOfScalar(u8, size_text, ';') orelse size_text.len;
                const size = std.fmt.parseInt(usize, size_text[0..semi], 16) catch return Error.BadChunk;
                cursor += line_end + 2;
                if (size == 0) break;
                if (body_len + size > response_buffer.len) return Error.ResponseTooLarge;
                while (filled - cursor < size + 2) {
                    if (filled == received.len) return Error.ResponseTooLarge;
                    const n = connection.read(received[filled..]) catch return Error.TruncatedBody;
                    if (n == 0) return Error.TruncatedBody;
                    filled += n;
                }
                @memcpy(response_buffer[body_len..][0..size], received[cursor..][0..size]);
                body_len += size;
                cursor += size + 2;
            }
            return response_buffer[0..body_len];
        }
        // Content length is the only other framing this client accepts; a
        // response with neither is not a DoH answer this build can read.
        const declared = content_length orelse return Error.BadContentLength;
        if (declared > response_buffer.len) return Error.ResponseTooLarge;
        if (available > declared) available = declared;
        @memcpy(response_buffer[0..available], received[cursor..][0..available]);
        body_len = available;
        cursor += available;
        while (body_len < declared) {
            const n = connection.read(response_buffer[body_len..declared]) catch return Error.TruncatedBody;
            if (n == 0) return Error.TruncatedBody;
            body_len += n;
            cursor += n;
        }
        return response_buffer[0..body_len];
    }
};

const tls_server = @import("tls_server.zig");
const dns_message = @import("../dns/message.zig");
const dns_name = @import("../dns/name.zig");
const dns_writer = @import("../dns/writer.zig");

const DoHArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    server: *tls_server.Server,
    /// true answers with a chunked body, false with a content-length body.
    chunked: bool = false,
    /// The status line the fake sends.
    status: []const u8 = "HTTP/1.1 200 OK",
    /// The media type the fake sends.
    content_type: []const u8 = media_type,
    answered: bool = false,
};

fn serveDohOne(args: *DoHArgs) void {
    const stream = args.listener.accept(args.io) catch return;
    defer stream.close(args.io);
    var input_buffer: [tls.input_buffer_len]u8 = undefined;
    var output_buffer: [tls.output_buffer_len]u8 = undefined;
    var reader = stream.reader(args.io, &input_buffer);
    var writer = stream.writer(args.io, &output_buffer);
    var connection = args.server.handshake(&reader.interface, &writer.interface) catch return;
    defer connection.close() catch {};
    var request: [8192]u8 = undefined;
    var filled: usize = 0;
    while (std.mem.indexOf(u8, request[0..filled], "\r\n\r\n") == null) {
        if (filled == request.len) return;
        const n = connection.read(request[filled..]) catch return;
        if (n == 0) return;
        filled += n;
    }
    const split = std.mem.indexOf(u8, request[0..filled], "\r\n\r\n").? + 4;
    // The head names the body length; the request may arrive in pieces, so
    // the body is read to that length before it is treated as the query.
    var body_len: usize = 0;
    var head_lines = std.mem.splitSequence(u8, request[0..split], "\r\n");
    _ = head_lines.next();
    while (head_lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;
        body_len = std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " \t"), 10) catch return;
    }
    if (body_len == 0 or split + body_len > request.len) return;
    while (filled < split + body_len) {
        const n = connection.read(request[filled..]) catch return;
        if (n == 0) return;
        filled += n;
    }
    // The POST body is the DNS query; the reply echoes it as the body with
    // the QR bit set, so the test can prove what reached the server.
    const query = request[split .. split + body_len];
    var response: [512]u8 = undefined;
    const body = if (query.len >= 12) blk: {
        @memcpy(response[0..query.len], query);
        response[2] |= 0x80;
        break :blk response[0..query.len];
    } else return;
    if (args.chunked) {
        var head_buffer: [512]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buffer, "{s}\r\ncontent-type: {s}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n", .{ args.status, args.content_type }) catch return;
        connection.writeAll(head) catch return;
        var chunk_header: [16]u8 = undefined;
        const chunk = std.fmt.bufPrint(&chunk_header, "{x}\r\n", .{body.len}) catch return;
        connection.writeAll(chunk) catch return;
        connection.writeAll(body) catch return;
        connection.writeAll("\r\n0\r\n\r\n") catch return;
    } else {
        var head_buffer: [512]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buffer, "{s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{ args.status, args.content_type, body.len }) catch return;
        connection.writeAll(head) catch return;
        connection.writeAll(body) catch return;
    }
    args.answered = true;
}

fn dohTestQuery(buffer: []u8, allocator: std.mem.Allocator) ![]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const built = dns_message.Message{
        .allocator = arena.allocator(),
        .header = .{ .id = 0x5151, .question_count = 1, .recursion_desired = true },
        .question = .{ .name = try dns_name.Name.fromText("example.com."), .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(arena.allocator(), 0),
    };
    var writer = dns_writer.Writer.init(buffer);
    try built.encode(&writer);
    return writer.written();
}

test "RFC 8484 section 4.1: a DoH POST carries application/dns-message and reads a content-length body" {
    try runDohInterop(false, 0x200);
}

test "RFC 8484 section 4.1: a chunked DoH body is decoded" {
    try runDohInterop(true, 0x201);
}

test "RFC 8484 section 4.2: a response with another media type is refused" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", http11_alpn);
    defer server.deinit();
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    var args = DoHArgs{ .io = io, .listener = &listener, .server = &server, .content_type = "text/plain" };
    const thread = try std.Thread.spawn(.{}, serveDohOne, .{&args});
    defer thread.join();

    var cert_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path_buffer);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, cert_path_buffer[0..cert_len]);
    defer client.deinit();
    var stream = try std.Io.net.IpAddress.connect(&listener.socket.address, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try dohTestQuery(&query_buffer, allocator);
    var response_buffer: [512]u8 = undefined;
    try std.testing.expectError(Error.BadContentType, client.post(stream, "localhost", default_path, query, &response_buffer));
}

fn runDohInterop(comptime chunked: bool, comptime offset: u16) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", http11_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    var args = DoHArgs{ .io = io, .listener = &listener, .server = &server, .chunked = chunked };
    const thread = try std.Thread.spawn(.{}, serveDohOne, .{&args});
    defer thread.join();

    var cert_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path_buffer);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, cert_path_buffer[0..cert_len]);
    defer client.deinit();

    var stream = try std.Io.net.IpAddress.connect(&listener.socket.address, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);
    var query_buffer: [512]u8 = undefined;
    const query = try dohTestQuery(&query_buffer, allocator);
    var response_buffer: [512]u8 = undefined;
    const body = try client.post(stream, "localhost", default_path, query, &response_buffer);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const response = try dns_message.Message.parse(arena.allocator(), body);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqualSlices(u8, query[12..], body[12..]);
    try std.testing.expect(args.answered);
    _ = offset;
}
