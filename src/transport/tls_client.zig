/// Contract: Speaks DNS over TLS as a client (RFC 7858) for a resolver that
/// forwards instead of iterating. The handshake, ALPN and certificate
/// verification come from the reviewed inic/tls.zig dependency pinned in
/// build.zig.zon; this module owns the `dot` ALPN requirement (RFC 8310
/// section 8.1 asks a client to offer the token), the framing (RFC 7858
/// section 3.3 reuses the RFC 1035 section 4.2.2 two-octet length prefix) and
/// the refusal of a server that does not present a valid certificate for the
/// name the operator configured.
/// Ownership: The trust bundle is loaded once and owned here; request and
/// response buffers are the caller's.
/// Errors: A refused handshake, a certificate that does not verify, a
/// mismatched ALPN, and a malformed frame are typed as `Error`.
const std = @import("std");
const tls = @import("tls");
const dns_message = @import("../dns/message.zig");
const dot_alpn = "dot";

pub const Error = error{
    HandshakeFailed,
    AlpnMismatch,
    FrameTooLarge,
    BadFrame,
    TrustStoreEmpty,
};

/// Largest DNS message a length-prefixed frame can carry (RFC 1035 section
/// 4.2.2: a two-octet length).
pub const max_frame_len: usize = std.math.maxInt(u16);

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// The roots the server certificate must chain to. Empty until loaded.
    roots: std.crypto.Certificate.Bundle = .empty,
    roots_loaded: bool = false,

    /// Loads the platform trust store once. RFC 7858 section 4.1 leaves the
    /// trust model to the operator's resolver; this build uses the system
    /// roots and refuses to forward when there are none, so a deployment
    /// cannot silently fall back to an unauthenticated channel.
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

    pub fn deinit(self: *Client) void {
        self.roots.deinit(self.allocator);
        self.* = undefined;
    }

    fn loadRoots(self: *Client) !void {
        self.roots.rescan(self.allocator, self.io, std.Io.Clock.real.now(self.io)) catch return Error.TrustStoreEmpty;
        self.roots_loaded = self.roots.map.count() != 0;
        if (!self.roots_loaded) return Error.TrustStoreEmpty;
    }

    /// One query/response exchange over a fresh TLS connection. The caller
    /// dials the stream (so its own source-port policy applies) and this
    /// function owns the handshake and the framing only.
    pub fn exchange(
        self: *Client,
        stream: std.Io.net.Stream,
        host: []const u8,
        request: []const u8,
        response_buffer: []u8,
    ) ![]const u8 {
        if (!self.roots_loaded) return Error.TrustStoreEmpty;
        if (request.len == 0 or request.len > max_frame_len) return Error.FrameTooLarge;

        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var reader = stream.reader(self.io, &input_buffer);
        var writer = stream.writer(self.io, &output_buffer);
        const alpn = [_][]const u8{dot_alpn};
        var rng: std.Random.IoSource = .{ .io = self.io };
        var connection = tls.client(&reader.interface, &writer.interface, .{
            .rng = rng.interface(),
            .now = std.Io.Clock.real.now(self.io),
            .host = host,
            .root_ca = self.roots,
            .alpn_protocols = &alpn,
        }) catch return Error.HandshakeFailed;
        defer connection.close() catch {};
        // RFC 8310 section 8.1 asks a client to offer the "dot" ALPN token,
        // and a server that ignores the extension (Cloudflare's 1.1.1.1:853
        // does) still speaks DoT on the port it was configured for. A server
        // that selects a different token is not that service.
        if (connection.alpn_protocol) |negotiated| {
            if (!std.mem.eql(u8, negotiated, dot_alpn)) return Error.AlpnMismatch;
        }

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, prefix[0..2], @intCast(request.len), .big);
        connection.writeAll(&prefix) catch return Error.HandshakeFailed;
        connection.writeAll(request) catch return Error.HandshakeFailed;

        _ = connection.readAll(prefix[0..2]) catch return Error.BadFrame;
        const response_len = std.mem.readInt(u16, prefix[0..2], .big);
        if (response_len == 0 or response_len > response_buffer.len) return Error.BadFrame;
        _ = connection.readAll(response_buffer[0..response_len]) catch return Error.BadFrame;
        return response_buffer[0..response_len];
    }
};

test "a frame longer than the two-octet length is refused" {
    var client: Client = .{ .allocator = std.testing.allocator, .io = std.Io.Threaded.global_single_threaded.io() };
    client.roots_loaded = true;
    const stream: std.Io.net.Stream = undefined;
    var request: [max_frame_len + 1]u8 = @splat(0);
    var response: [16]u8 = undefined;
    try std.testing.expectError(Error.FrameTooLarge, client.exchange(stream, "localhost", &request, &response));
}

test "a client without trust anchors refuses to exchange" {
    var client: Client = .{ .allocator = std.testing.allocator, .io = std.Io.Threaded.global_single_threaded.io() };
    const stream: std.Io.net.Stream = undefined;
    var request = [_]u8{ 1, 2 };
    var response: [16]u8 = undefined;
    try std.testing.expectError(Error.TrustStoreEmpty, client.exchange(stream, "localhost", &request, &response));
}

const tls_server = @import("tls_server.zig");
const dns_name = @import("../dns/name.zig");
const dns_writer = @import("../dns/writer.zig");

const ServeArgs = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    server: *tls_server.Server,
    answered: bool = false,
};

fn serveOne(args: *ServeArgs) void {
    const stream = args.listener.accept(args.io) catch return;
    defer stream.close(args.io);
    var input_buffer: [tls.input_buffer_len]u8 = undefined;
    var output_buffer: [tls.output_buffer_len]u8 = undefined;
    var reader = stream.reader(args.io, &input_buffer);
    var writer = stream.writer(args.io, &output_buffer);
    var connection = args.server.handshake(&reader.interface, &writer.interface) catch return;
    defer connection.close() catch {};
    var prefix: [2]u8 = undefined;
    _ = connection.readAll(prefix[0..2]) catch return;
    const request_len = std.mem.readInt(u16, prefix[0..2], .big);
    var request: [512]u8 = undefined;
    if (request_len > request.len) return;
    _ = connection.readAll(request[0..request_len]) catch return;
    // Reply with the same message marked as a response, so the test can
    // compare what it sent with what it got back.
    request[2] |= 0x80;
    std.mem.writeInt(u16, prefix[0..2], request_len, .big);
    connection.writeAll(&prefix) catch return;
    connection.writeAll(request[0..request_len]) catch return;
    args.answered = true;
}

test "RFC 7858 section 3.3: a DoT client frames a DNS message over the dot ALPN" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = tls_server.test_identity.cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = tls_server.test_identity.key_pem });
    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", dot_alpn);
    defer server.deinit();

    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try std.Io.net.IpAddress.listen(&listen_address, io, .{ .mode = .stream, .protocol = .tcp });
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var args = ServeArgs{ .io = io, .listener = &listener, .server = &server };
    const thread = try std.Thread.spawn(.{}, serveOne, .{&args});
    defer thread.join();

    var cert_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cert_len = try tmp.dir.realPathFile(io, "cert.pem", &cert_path_buffer);
    var client: Client = undefined;
    try Client.initFromCertFile(&client, allocator, io, cert_path_buffer[0..cert_len]);
    defer client.deinit();

    var stream = try std.Io.net.IpAddress.connect(&bound, io, .{ .mode = .stream, .protocol = .tcp, .timeout = .none });
    defer stream.close(io);

    var query: [512]u8 = undefined;
    var question_arena = std.heap.ArenaAllocator.init(allocator);
    defer question_arena.deinit();
    const built = dns_message.Message{
        .allocator = question_arena.allocator(),
        .header = .{ .id = 0x4242, .question_count = 1, .recursion_desired = true },
        .question = .{ .name = try dns_name.Name.fromText("example.com."), .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .authorities = try dns_message.RecordSection.init(question_arena.allocator(), 0),
        .additionals = try dns_message.RecordSection.init(question_arena.allocator(), 0),
    };
    var writer = dns_writer.Writer.init(&query);
    try built.encode(&writer);
    const query_bytes = writer.written();

    var response_buffer: [512]u8 = undefined;
    const response_bytes = try client.exchange(stream, "localhost", query_bytes, &response_buffer);
    const response = try dns_message.Message.parse(question_arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 0x4242), response.header.id);
    try std.testing.expect(response.header.qr);
    // Only the QR bit of the flags word differs: the same message comes back
    // as a response, and nothing else, rcode included, changed.
    try std.testing.expectEqual(query_bytes[2] & 0x7f, response_bytes[2] & 0x7f);
    try std.testing.expectEqual(query_bytes[3], response_bytes[3]);
    try std.testing.expectEqualSlices(u8, query_bytes[4..], response_bytes[4..]);
    try std.testing.expect(args.answered);
}
