/// Contract: Serves the RFC 9103 zone-transfer message sequence (AXFR and
/// RFC 1995 IXFR queries answered by the runtime, the encoder the cleartext
/// TCP path uses, so this channel serves the same incremental transfer;
/// ordinary queries share runtime.answer) over a TLS connection that
/// negotiated the "dot" ALPN token, which RFC 9103 section 7.1 requires for
/// the transfer channel. The listener binds the port, terminates the
/// handshake, and only then speaks DNS, so the port never answers a transfer
/// in cleartext. The two-octet length-prefixed framing is the RFC 7858
/// section 3.3 framing, the same one the Do53 TCP path uses. A transfer
/// connection lives no longer than the connection duration the operator
/// configured, and every frame runs under a deadline on the raw descriptor,
/// the same bounds the DoT port holds. A SIGHUP re-reads the zone file on
/// this path too, outside the signal handler, so the answer that follows a
/// TSIG-signed transfer is served signed, the way the cleartext path serves
/// it: the runtime encodes the chained sequence (RFC 8945 sections 5.3 and
/// 5.3.1), so this channel adds no signing logic of its own.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write failures propagate as
/// I/O errors.
const std = @import("std");
const ossl = @import("../transport/openssl_tls.zig");

/// Test-only insecure client: skips verification for loopback fixtures with
/// throwaway identities. MUST NOT be used in production paths.
fn insecureTestClient(
    fd: std.posix.fd_t,
    io: std.Io,
    alpn: []const u8,
    comptime test_only: bool,
) !ossl.Connection {
    comptime if (!test_only or !@import("builtin").is_test) @compileError("insecureTestClient is test-only: production must verify");
    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    // Loopback tests give the handshake and the exchange five seconds;
    // production paths pass their own absolute deadline instead.
    const deadline = tcp_deadline.deadline(io, .{ .seconds = 5 });
    const connection = try ossl.clientHandshake(ctx, fd, io, deadline, .{
        .verify = .insecure,
        .verify_host = "localhost",
        .sni = "localhost",
        .alpn = alpn,
    });
    return connection;
}

const Runtime = @import("../auth/runtime.zig").Runtime;
const keyring_mod = @import("../auth/keyring.zig");
const dns_message = @import("../dns/message.zig");
const dns_padding = @import("../dns/padding.zig");
const dns_tsig = @import("../dns/tsig.zig");
const metrics = @import("../metrics.zig");
const dns_writer = @import("../dns/writer.zig");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("../transport/tls.zig");
const tls_server = @import("../transport/tls_server.zig");
const channel_mod = @import("../transport/channel.zig");
const transfer_mod = @import("../zone/transfer.zig");

/// RFC 9103 section 7.1: the transfer channel selects the same "dot" token
/// the DoT port speaks.
pub const XFR_ALPN = tls_policy.dot_alpn;
pub const MAX_FRAMES_PER_CONNECTION = listener.TCP_MAX_FRAMES_PER_CONNECTION;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
/// The cleartext stream buffer. The frame buffers live in the framing.
const STREAM_BUFFER_SIZE: usize = 8192;

/// Serves one transfer connection: the TLS handshake with the "dot" ALPN
/// token, then the RFC 7858 framing over the encrypted channel.
pub fn serveXfrTlsStream(
    stream: std.Io.net.Stream,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    // RFC 9210 section 4.2: the operator may bound the lifetime of one
    // connection, and that deadline covers the whole connection.
    const connection_deadline = channel_mod.connectionDeadline(io);

    // The handshake is part of the connection, so it shares its deadline;
    // without an operator bound it still gets the module's own window, so a
    // peer that dribbles handshake bytes holds the worker no longer than one
    // frame timeout. It runs directly on the socket fd: the TLS layer polls
    // the fd and recomputes against this absolute deadline each iteration.
    const handshake_timeout = listener.frameTimeout(io, connection_deadline, listener.tcpIdleTimeout()) orelse return;
    const handshake_deadline = tcp_deadline.deadline(io, handshake_timeout);
    var connection = try server.handshake(stream.socket.handle, io, handshake_deadline);

    var read_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var write_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    defer {
        connection_writer.interface.flush() catch {};
        connection.close() catch {};
    }
    var channel = channel_mod.Channel{
        .io = io,
        .reader = &connection_reader.interface,
        .writer = &connection_writer.interface,
        .tls = &connection,
        .timeout = listener.tcpIdleTimeout(),
        .connection_deadline = connection_deadline,
    };
    try serveXfrFrames(&channel, stream.socket.address, runtime, counters);
}

/// The RFC 7858 section 3.3 framing over an already-terminated byte stream:
/// two-octet length-prefixed DNS messages with the same bounds as DNS over
/// TCP. A transfer query answers with the RFC 1995 sequence, one frame per
/// message; any other query answers the ordinary way.
fn serveXfrFrames(channel: *const channel_mod.Channel, client: std.Io.net.IpAddress, runtime: *Runtime, counters: ?*metrics.Counters) !void {
    var request_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var frame_count: usize = 0;
    while (frame_count < MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
        // A SIGHUP asks for the zone to be re-read. The reload happens here,
        // outside the signal handler. The first check answers a connection
        // that waited for the request, the second one answers a request that
        // arrived while the flag was set, so the answer that follows a
        // reload always comes from the new zone.
        _ = runtime.tryMaintenanceTick(channel.io);
        // One deadline for the whole frame: a peer that stalls in the middle
        // of a frame loses the frame, not the server.
        if (!channel.applyFrameDeadline()) return;
        const request = listener.readTcpFrame(channel.reader, &request_buffer) catch |err| {
            // A clean close at the frame boundary ends the connection.
            if (err == error.EndOfStream) {
                if (frame_count == 0) return error.EndOfStream;
                return;
            }
            return err;
        };
        var frame_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer frame_arena.deinit();
        _ = runtime.tryMaintenanceTick(channel.io);
        // The answer gets its own deadline: the read took time, and the
        // connection may be nearly over.
        if (!channel.applyFrameDeadline()) return;
        if (isTransferQuery(frame_arena.allocator(), request)) {
            if (!runtime.beginTransfer()) return error.TransferBusy;
            defer runtime.endTransfer();
            if (try transferAnswer(frame_arena.allocator(), request, &client, runtime)) |blob| {
                // The transfer answer is framed the way the cleartext TCP path
                // frames it, so the client reads the same sequence either way.
                try channel.writer.writeAll(blob);
                try channel.writer.flush();
                if (counters) |value| {
                    metrics.bump(&value.queries_total);
                    metrics.bump(&value.responses_total);
                    // A refusal carries no answer record and is not a transfer.
                    if (answerRecords(frame_arena.allocator(), blob) > 0) metrics.bump(&value.xfr_transfers_total);
                }
                continue;
            }
        }
        if (counters) |value| metrics.bump(&value.dot_queries_total);
        const response_bytes = if (counters) |value|
            try runtime.answerWithMetrics(request, &response_buffer, value)
        else
            try runtime.answer(request, &response_buffer);
        // RFC 7830 section 4: the responder pads the answer when the query
        // carried the Padding option, and section 6 keeps the option for
        // encrypted transports, which this channel is.
        const padded = if (dns_message.Message.parseQuery(frame_arena.allocator(), request)) |parsed|
            (try dns_padding.padResponse(frame_arena.allocator(), &parsed, response_bytes)) orelse response_bytes
        else |_|
            response_bytes;
        if (padded.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;
        try writeFrame(channel.writer, padded);
    }
}

/// The answer to a transfer query, framed the way the cleartext TCP path
/// frames it: one two-octet length prefix per message. Signed and unsigned
/// requests share the runtime's encode path, so a signed transfer is served
/// with the chained TSIG sequence the cleartext path serves (RFC 8945
/// sections 5.3 and 5.3.1) and an unsigned transfer stays byte-identical.
/// Null means the query is not a transfer query, so the ordinary
/// answer path runs.
fn transferAnswer(allocator: std.mem.Allocator, request: []const u8, client: *const std.Io.net.IpAddress, runtime: *const Runtime) !?[]u8 {
    if (!isTransferQuery(allocator, request)) return null;
    // The runtime answers the transfer and frames it, the way the cleartext
    // TCP path gets it, so the incremental RFC 1995 answer is served here too.
    return try runtime.encodeTransferFrames(allocator, request, client);
}

/// Whether the request is a transfer query. The strict query parser rejects
/// an RFC 1995 IXFR query, which carries the client's serial in an authority
/// record, so the transfer profile parses that shape; a signed request is
/// stripped first, so signed AXFR and IXFR are detected the same way.
fn isTransferQuery(allocator: std.mem.Allocator, request: []const u8) bool {
    const final = dns_tsig.parseFinalAdditional(request) catch null;
    var stripped: ?[]u8 = null;
    defer if (stripped) |bytes| allocator.free(bytes);
    const bytes = if (final) |tsig_final| blk: {
        stripped = transfer_mod.stripTsigRecord(allocator, request, tsig_final.record_start, tsig_final.record_end) catch return false;
        break :blk stripped.?;
    } else request;
    var message = dns_message.Message.parse(allocator, bytes) catch return false;
    defer message.deinit();
    return (transfer_mod.validateTransferRequest(&message) catch return false) != .none;
}

/// The number of answer records the framed transfer answer carries, so the
/// metrics count what the client received.
fn answerRecords(allocator: std.mem.Allocator, blob: []const u8) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (offset + 2 <= blob.len) {
        const frame_len = std.mem.readInt(u16, blob[offset..][0..2], .big);
        offset += 2;
        if (offset + frame_len > blob.len) break;
        var message = dns_message.Message.parse(allocator, blob[offset .. offset + frame_len]) catch break;
        count += message.header.answer_count;
        message.deinit();
        offset += frame_len;
    }
    return count;
}

/// Writes one length-prefixed frame and flushes it: the client waits for the
/// answer, and a TLS writer buffers until it is flushed.
fn writeFrame(writer: *std.Io.Writer, payload: []const u8) !void {
    if (payload.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(payload.len), .big);
    try writer.writeAll(&prefix);
    try writer.writeAll(payload);
    try writer.flush();
}

/// Binds the transfer port and serves transfer connections. Every accepted
/// connection gets a TLS handshake with the "dot" ALPN token before any DNS
/// byte is written, so the port never answers a transfer in cleartext. Each
/// connection is served on its own task, so a peer that stalls in the
/// handshake does not hold up the others.
pub fn serveXfrLoopOnAddress(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    server: *tls_server.Server,
    max_requests: ?usize,
) !void {
    var bind_address = address.*;
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    return serveXfrLoop(&listener_socket, io, runtime, server, max_requests);
}

/// Serves the transfer port on an already-bound listener.
pub fn serveXfrLoop(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    runtime: *Runtime,
    server: *tls_server.Server,
    max_requests: ?usize,
) !void {
    var group: std.Io.Group = .init;
    defer group.await(io) catch unreachable;

    var sources = listener.SourceCounter{};
    var accepted: usize = 0;
    while (max_requests == null or accepted < max_requests.?) {
        // A failing sibling ends this loop: the listener shutdown wakes
        // the blocked accept, and the flag ends it even when idle.
        try runtime.checkStop();
        const stream = try listener.acceptWithRetry(listener_socket, io);
        accepted += 1;
        // The encrypted listener holds the same bounds as the cleartext one: a
        // source address holds only so many connections at once (RFC 9210
        // section 4.2), and a connection with no worker slot is closed at once.
        if (!sources.admit(&stream.socket.address)) {
            stream.close(io);
            continue;
        }
        group.concurrent(io, serveXfrTlsWorker, .{ stream, io, server, runtime, &sources }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                sources.release(&stream.socket.address);
                stream.close(io);
            },
        };
    }
}

/// Serves one accepted transfer connection.
fn serveXfrTlsWorker(stream: std.Io.net.Stream, io: std.Io, server: *tls_server.Server, runtime: *Runtime, sources: *listener.SourceCounter) void {
    defer stream.close(io);
    defer sources.release(&stream.socket.address);
    serveXfrTlsStream(stream, io, server, runtime, null) catch {};
}

/// The identity the transfer tests load: a throwaway self-signed certificate
/// and its key, written to a temporary directory.
fn writeTestIdentity(dir: std.Io.Dir, io: std.Io) !void {
    try dir.writeFile(io, .{
        .sub_path = "cert.pem",
        .data = tls_server.test_identity.cert_pem,
        .flags = .{},
    });
    try dir.writeFile(io, .{
        .sub_path = "key.pem",
        .data = tls_server.test_identity.key_pem,
        .flags = .{},
    });
}

/// The server side of the transfer tests: one accepted connection, served.
fn serveOneConnection(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveXfrTlsStream(stream, io, server, runtime, null) catch {};
}

test "the transfer channel serves an AXFR sequence over a TLS 1.3 handshake with the dot token" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    // RFC 9103 section 7.1: the transfer channel speaks "dot".
    try std.testing.expectEqualStrings(XFR_ALPN, connection.alpnProtocol().?);
    // RFC 9103 section 7.2: only TLS 1.3 or later.
    try std.testing.expectEqual(@as(c_int, 0x0304), connection.version());

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(axfr_query.len), .big);
    try connection_writer.interface.writeAll(&prefix);
    try connection_writer.interface.writeAll(axfr_query);
    try connection_writer.interface.flush();

    // RFC 7858 section 3.3 framing: a two-octet length prefix per message.
    const len_bytes = try connection_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, len_bytes, .big);
    const response_bytes = try connection_reader.interface.take(response_len);
    const response = try @import("../dns/message.zig").Message.parse(allocator, response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x1234), response.header.id);
    // RFC 1995: the sequence starts with the apex SOA and ends with it.
    const answers = response.answers.slice();
    try std.testing.expectEqual(@as(usize, 4), answers.len);
    try std.testing.expect(answers[0].rrtype.eql(@import("../dns/types.zig").RecordType.SOA));
    try std.testing.expect(answers[answers.len - 1].rrtype.eql(@import("../dns/types.zig").RecordType.SOA));
    // The zone's own records travel with the sequence.
    var saw_ns = false;
    var saw_a = false;
    for (answers) |answer| {
        if (answer.rrtype.eql(@import("../dns/types.zig").RecordType.NS)) saw_ns = true;
        if (answer.rrtype.eql(@import("../dns/types.zig").RecordType.A)) saw_a = true;
    }
    try std.testing.expect(saw_ns and saw_a);

    connection.close() catch {};
    thread.join();
}

test "the transfer channel refuses a client that offers no dot token" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "http/1.1", true);
    defer connection.close() catch {};
    try std.testing.expect(connection.alpnProtocol() == null);
    // The server side refuses with AlpnMismatch; the refusal closes the
    // connection before any DNS byte is read.

    thread.join();
}

test "the transfer port answers no cleartext AXFR" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    // One connection is the whole quota, so the server stops on its own.
    const thread = try std.Thread.spawn(.{}, serveXfrLoop, .{ &listener_socket, io, &runtime, &server, @as(?usize, 1) });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    // A cleartext AXFR on the transfer port: the handshake comes first, so
    // the server never reads a DNS message in the clear.
    var client_write_buffer: [512]u8 = undefined;
    var client_writer = stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(axfr_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(axfr_query);
    try client_writer.interface.flush();
    // The client hangs up, so the server reads the cleartext bytes as a
    // truncated handshake and ends the connection.
    try stream.shutdown(io, .send);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = stream.reader(io, &client_read_buffer);
    const answer = client_reader.interface.take(1) catch |err| {
        // The connection ended without an answer.
        try std.testing.expect(err == error.EndOfStream or err == error.ConnectionResetByPeer);
        thread.join();
        return;
    };
    // The only thing the port can say to a cleartext peer is a TLS alert
    // (content type 0x15), never a DNS answer.
    try std.testing.expectEqual(@as(u8, 0x15), answer[0]);

    thread.join();
}

test "a transfer connection ends when the operator's connection duration is over" {
    const previous_limits = listener.tcpLimits();
    defer listener.setTcpLimits(previous_limits);
    // RFC 9210 section 4.2: one connection lives for a second.
    listener.setTcpLimits(.{ .max_connection_duration = 1 });

    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    // The peer completes the handshake and then says nothing.
    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    // The connection ends with the duration the operator configured, not with
    // the five-second frame deadline of the transport.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 3000));

    thread.join();
}

test "a transfer query answered after a SIGHUP comes from the reloaded zone" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);
    // The zone file the operator replaces, and the runtime that re-reads it.
    try tmp.dir.writeFile(io, .{ .sub_path = zone_file_name, .data = reload_zone_text });

    var runtime = try Runtime.fromZoneText(reload_zone_text);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));
    try runtime.setReloadSource(tmp.dir, zone_file_name, zone_origin);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    // The operator replaces the zone file and asks for the reload, exactly
    // as the SIGHUP handler does.
    try tmp.dir.writeFile(io, .{ .sub_path = zone_file_name, .data = reloaded_zone_text });
    runtime.requestZoneReload();

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x7a7a, .big);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try connection_writer.interface.writeAll(&prefix);
    try connection_writer.interface.writeAll(&query);
    try connection_writer.interface.flush();

    const len_bytes = try connection_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, len_bytes, .big);
    const response_bytes = try connection_reader.interface.take(response_len);
    const response = try @import("../dns/message.zig").Message.parse(allocator, response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x7a7a), response.header.id);
    // The answer comes from the reloaded zone, not from the zone the
    // connection started with.
    try std.testing.expectEqual(@as(usize, 1), response.answers.items.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 2 }, &response.answers.items[0].rdata.A);

    connection.close() catch {};
    thread.join();
}

test "the transfer channel refuses an out-of-zone AXFR" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    // A transfer for a zone this server does not serve is refused with one
    // REFUSED message.
    try writeTestFrame(&connection_writer.interface, out_of_zone_axfr_query);
    const refused = try readTestFrame(&connection_reader.interface);
    const refused_message = try @import("../dns/message.zig").Message.parse(allocator, refused);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.refused, refused_message.header.rcode);
    try std.testing.expectEqual(@as(usize, 0), refused_message.answers.len);

    connection.close() catch {};
    thread.join();
}

test "the transfer channel serves a signed AXFR as a chained TSIG sequence" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // More records than one frame carries, so the signed answer is a
    // sequence and the chain between its frames is exercised.
    var zone_text: std.ArrayList(u8) = .empty;
    defer zone_text.deinit(std.testing.allocator);
    try zone_text.appendSlice(std.testing.allocator,
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\
    );
    var index: usize = 0;
    while (index < 70) : (index += 1) {
        const line = try std.fmt.allocPrint(std.testing.allocator, "h{d} IN A 192.0.2.{d}\n", .{ index, index % 254 + 1 });
        defer std.testing.allocator.free(line);
        try zone_text.appendSlice(std.testing.allocator, line);
    }
    var keyring = try keyring_mod.Keyring.parse("key \"key.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };");
    var runtime = try Runtime.fromZoneTextWithKeyring(zone_text.items, &keyring);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));
    const now = 1_700_000_000;
    runtime.setTsigNow(now);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    // An unsigned transfer carries no TSIG record on any frame.
    try writeTestFrame(&connection_writer.interface, axfr_query);
    const unsigned_first = try readTestFrame(&connection_reader.interface);
    try std.testing.expect((try dns_tsig.parseFinalAdditional(unsigned_first)) == null);
    const unsigned_second = try readTestFrame(&connection_reader.interface);
    try std.testing.expect((try dns_tsig.parseFinalAdditional(unsigned_second)) == null);

    // RFC 8945 section 5.3.1: the first frame verifies with the request MAC
    // and the whole TSIG record; the second chains on the first frame's MAC.
    var query_buffer: [512]u8 = undefined;
    const signed_query = try signedTransferQuery(&query_buffer, 0x00fc, null, now);
    const request_final = (try dns_tsig.parseFinalAdditional(signed_query)) orelse return error.TestExpectedEqual;
    var request_mac: [32]u8 = undefined;
    @memcpy(&request_mac, request_final.tsig.macBytes()[0..32]);
    try writeTestFrame(&connection_writer.interface, signed_query);
    const first_frame = try readTestFrame(&connection_reader.interface);
    const first_final = (try dns_tsig.parseFinalAdditional(first_frame)) orelse return error.TestExpectedEqual;
    var first_frame_mac: [32]u8 = undefined;
    @memcpy(&first_frame_mac, first_final.tsig.macBytes()[0..32]);
    _ = try dns_tsig.verify(first_frame, tsig_secret, &request_mac);
    const second_frame = try readTestFrame(&connection_reader.interface);
    _ = try dns_tsig.verifyChained(&.{second_frame}, tsig_secret, &first_frame_mac);

    // A signed IXFR is served signed too: one frame verifying with the
    // request MAC.
    var ixfr_buffer: [512]u8 = undefined;
    const signed_ixfr = try signedTransferQuery(&ixfr_buffer, 0x00fb, 1, now);
    const ixfr_request_final = (try dns_tsig.parseFinalAdditional(signed_ixfr)) orelse return error.TestExpectedEqual;
    var ixfr_request_mac: [32]u8 = undefined;
    @memcpy(&ixfr_request_mac, ixfr_request_final.tsig.macBytes()[0..32]);
    try writeTestFrame(&connection_writer.interface, signed_ixfr);
    const ixfr_frame = try readTestFrame(&connection_reader.interface);
    _ = try dns_tsig.verify(ixfr_frame, tsig_secret, &ixfr_request_mac);

    connection.close() catch {};
    thread.join();
}
test "the transfer channel answers an ordinary query the ordinary way" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    // A query that is not a transfer is answered the ordinary way.
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x3c3c, .big);
    try writeTestFrame(&connection_writer.interface, &query);
    const response_bytes = try readTestFrame(&connection_reader.interface);
    const response = try @import("../dns/message.zig").Message.parse(allocator, response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x3c3c), response.header.id);
    try std.testing.expectEqual(@as(usize, 1), response.answers.items.len);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &response.answers.items[0].rdata.A);

    connection.close() catch {};
    thread.join();
}

test "the transfer channel serves the incremental transfer after a zone reload" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    try runtime.addTransferAllow("home.arpa.", try @import("../config/parser.zig").Cidr.parse("127.0.0.0/8"));
    // The zone is replaced under the runtime, so the delta log holds the
    // transition from the serial the client holds to the current one.
    try std.testing.expectEqual(@import("../auth/runtime.zig").ReloadOutcome.replaced, runtime.replaceZoneText(io, zone_origin, next_zone_text));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", XFR_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, XFR_ALPN, true);
    defer connection.close() catch {};

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    // The client holds the serial the zone had before the reload, so RFC
    // 1995 answers it with the difference instead of the whole zone.
    var query_buffer: [512]u8 = undefined;
    try writeTestFrame(&connection_writer.interface, try ixfrQuery(&query_buffer, 1));
    const response_bytes = try readTestFrame(&connection_reader.interface);
    const response = try @import("../dns/message.zig").Message.parse(allocator, response_bytes);
    try std.testing.expect(response.header.qr);
    try std.testing.expectEqual(@import("../dns/header.zig").Rcode.no_error, response.header.rcode);
    // The difference holds the record the old zone had and the one the new
    // zone holds; a full transfer would carry the new one alone.
    var saw_old_address = false;
    var saw_new_address = false;
    for (response.answers.items) |answer| {
        if (!answer.rrtype.eql(@import("../dns/types.zig").RecordType.A)) continue;
        if (std.mem.eql(u8, &answer.rdata.A, &.{ 192, 168, 1, 1 })) saw_old_address = true;
        if (std.mem.eql(u8, &answer.rdata.A, &.{ 192, 168, 1, 2 })) saw_new_address = true;
    }
    try std.testing.expect(saw_old_address and saw_new_address);

    connection.close() catch {};
    thread.join();
}

/// Writes one length-prefixed frame to the connection.
fn writeTestFrame(writer: *std.Io.Writer, payload: []const u8) !void {
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(payload.len), .big);
    try writer.writeAll(&prefix);
    try writer.writeAll(payload);
    try writer.flush();
}

/// Reads one length-prefixed frame from the connection.
fn readTestFrame(reader: *std.Io.Reader) ![]const u8 {
    const len_bytes = try reader.takeArray(2);
    const frame_len = std.mem.readInt(u16, len_bytes, .big);
    return reader.take(frame_len);
}

/// The HMAC-SHA256 secret the signed-transfer tests sign with, as base64 in
/// the keyring fixture above.
const tsig_secret = "01234567890123456789012345678901";

/// A TSIG-signed transfer query: the question plus a final TSIG record
/// carrying a real MAC, and (for IXFR) the client's serial in an authority
/// SOA.
fn signedTransferQuery(buffer: []u8, qtype: u16, client_serial: ?u32, time_signed: u64) ![]const u8 {
    const dns_name = @import("../dns/name.zig");
    const dns_rdata = @import("../dns/rdata.zig");
    const dns_record = @import("../dns/record.zig");
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeBytes(&.{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00 });
    try writer.writeU16(if (client_serial != null) 1 else 0);
    try writer.writeU16(1);
    try writer.writeBytes(&.{ 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(qtype);
    try writer.writeU16(1);
    if (client_serial) |serial| {
        const client_soa = dns_record.ResourceRecord{
            .owner = try dns_name.Name.fromText(zone_origin),
            .rrtype = .SOA,
            .class = .IN,
            .ttl = 3600,
            .rdata = .{ .SOA = .{
                .mname = try dns_name.Name.fromText("ns1.home.arpa."),
                .rname = try dns_name.Name.fromText("hostmaster.home.arpa."),
                .serial = serial,
                .refresh = 3600,
                .retry = 900,
                .expire = 1209600,
                .minimum = 3600,
            } },
        };
        try client_soa.encode(&writer);
    }
    const algorithm = try dns_name.Name.fromText("hmac-sha256.");
    const owner = try dns_name.Name.fromText("key.");
    var zeros: [32]u8 = @splat(0);
    try (dns_record.ResourceRecord{
        .owner = owner,
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = try dns_rdata.Tsig.init(algorithm, time_signed, 300, &zeros, 0x1234, 0, &.{}) },
    }).encode(&writer);
    const final = (try dns_tsig.parseFinalAdditional(writer.written())).?;
    const signed = try dns_tsig.sign(writer.written(), tsig_secret, final.owner, final.tsig, null);
    try dns_tsig.patchMac(buffer[0..writer.len()], final, signed.slice());
    return writer.written();
}

/// An RFC 1995 IXFR query: the question plus the client's serial in an
/// authority SOA owned by the question name.
fn ixfrQuery(buffer: []u8, client_serial: u32) ![]const u8 {
    const dns_name = @import("../dns/name.zig");
    const dns_record = @import("../dns/record.zig");
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    });
    try writer.writeBytes(&.{ 4, 'h', 'o', 'm', 'e', 4, 'a', 'r', 'p', 'a', 0 });
    try writer.writeU16(0x00fb);
    try writer.writeU16(1);
    const client_soa = dns_record.ResourceRecord{
        .owner = try dns_name.Name.fromText(zone_origin),
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns1.home.arpa."),
            .rname = try dns_name.Name.fromText("hostmaster.home.arpa."),
            .serial = client_serial,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 3600,
        } },
    };
    try client_soa.encode(&writer);
    return writer.written();
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

/// The zone the runtime serves after the reload: the same zone with a newer
/// serial and a changed address, so the delta log holds the difference an
/// incremental transfer answers.
const next_zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 2 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.2
    \\
;

/// The zone file the operator replaces, and the zone it holds before and
/// after the reload.
const zone_file_name = "zone.txt";
const zone_origin = "home.arpa.";

const reload_zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 10 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

const reloaded_zone_text =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 11 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.2
    \\
;

const simple_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
};

const axfr_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    4,    'h',  'o',  'm',  'e',  4,    'a',  'r',  'p',  'a',  0,    0x00,
    0xfc, 0x00, 0x01,
};

/// An AXFR for a zone this server does not serve.
const out_of_zone_axfr_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'n',  'e',  't',
    0,    0x00, 0xfc, 0x00, 0x01,
};
