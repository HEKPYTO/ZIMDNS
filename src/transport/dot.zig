/// Contract: Serves the RFC 7858 section 3.3 DNS-over-TLS wire framing on an
/// already-TLS-terminated byte channel. Two-octet length-prefixed stream
/// framing is the same as DNS over TCP, so frame bounds and FIFO order are
/// shared with the plaintext TCP listener. The framing runs over a
/// reader/writer pair, so the cleartext stream helper and the TLS connection
/// share one framing. The DoT port is served by the listener in this module:
/// it binds the port, terminates the handshake with the "dot" ALPN token, and
/// only then speaks DNS, so the port never answers in cleartext. The "dot"
/// token is the IANA ALPN protocol ID the registry lists for RFC 7858; the
/// strict-TLS zone-transfer channel of RFC 9103 has no listener here. The
/// channel under the TLS connection is the raw descriptor, read and written
/// under a poll deadline: a socket timeout would surface a timed-out read as
/// EAGAIN, which the threaded backend treats as a programmer bug and answers
/// with a panic, so a stalled peer would take the whole server down. A DoT
/// connection lives no longer than the connection duration the operator
/// configured, the same bound the cleartext TCP listener enforces, and its
/// handshake runs under one absolute deadline, so a peer that dribbles
/// handshake bytes holds a worker slot for that window and no longer. The
/// answer comes from the same entry point the cleartext TCP path uses, so the
/// peer address reaches the recursion policy, the local-zone table, and the
/// cookie validation. A SIGHUP
/// re-reads the zone file on this path too, outside the signal handler, so
/// the answer that follows a reload comes from the new zone.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write failures propagate as
/// I/O errors.
const std = @import("std");
const ossl = @import("openssl_tls.zig");

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
const dns_message = @import("../dns/message.zig");
const dns_padding = @import("../dns/padding.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_header = @import("../dns/header.zig");
const config_mod = @import("../config/parser.zig");
const resolver_mod = @import("../resolver.zig");
const metrics = @import("../metrics.zig");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("tls.zig");
const tls_server = @import("tls_server.zig");
const channel_mod = @import("channel.zig");

pub const DOT_ALPN = tls_policy.dot_alpn;
pub const DOT_PORT = tls_policy.dot_port;
pub const MAX_FRAMES_PER_CONNECTION = listener.TCP_MAX_FRAMES_PER_CONNECTION;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
/// The cleartext stream buffer. The frame buffers live in the framing.
const STREAM_BUFFER_SIZE: usize = 8192;

pub fn serveDotStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime) !void {
    return serveDotStream(stream, io, runtime, null);
}

pub fn serveDotStreamOnceWithMetrics(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *Runtime,
    counters: *metrics.Counters,
) !void {
    return serveDotStream(stream, io, runtime, counters);
}

/// Serves the cleartext stream: the framing over a socket, with no TLS. The
/// DoT port never uses this path; it exists for the framing tests.
fn serveDotStream(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, counters: ?*metrics.Counters) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    // One loop owns the maintenance tick across all loops sharing this
    // runtime; a DoT-only server still runs it here.
    _ = runtime.tryMaintenanceTick(io);

    var read_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var write_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var reader = tcp_deadline.DeadlineReader.init(stream.socket.handle, io, &read_buffer, listener.tcpIdleTimeout());
    var writer = tcp_deadline.DeadlineWriter.init(stream.socket.handle, io, &write_buffer, listener.tcpIdleTimeout());
    defer writer.interface.flush() catch {};
    var channel = channel_mod.Channel{
        .io = io,
        .reader = &reader.interface,
        .writer = &writer.interface,
        .deadlines = .{ .reader = &reader, .writer = &writer },
        .timeout = listener.tcpIdleTimeout(),
        .connection_deadline = channel_mod.connectionDeadline(io),
    };
    try serveDotFrames(&channel, runtime, counters, &stream.socket.address);
}

/// RFC 7858 section 3.3 framing loop: two-octet length-prefixed DNS messages
/// with the same bounds as DNS over TCP. Operates on an already-terminated
/// byte stream, so the cleartext helper and the TLS connection share it.
fn serveDotFrames(
    channel: *const channel_mod.Channel,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
    client: *const std.Io.net.IpAddress,
) !void {
    var request_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    // The request is parsed once per frame to see whether it asked for
    // padding, and the padded answer is allocated beside it.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var frame_count: usize = 0;
    while (frame_count < MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
        // The parsed query and the padded answer of the frame before are
        // gone: the arena is reset, so a connection that serves many frames
        // holds the memory of one frame and not of all of them.
        _ = arena.reset(.retain_capacity);
        // A SIGHUP asks for the zone to be re-read. The reload happens here,
        // outside the signal handler. The first check answers a connection
        // that waited for the request, the second one answers a request that
        // arrived while the flag was set, so the answer that follows a
        // reload always comes from the new zone.
        _ = runtime.tryMaintenanceTick(channel.io);
        // One deadline for the whole frame: a peer that stalls in the middle
        // of a frame loses the frame, not the server. The write of the answer
        // shares it, so one frame cannot take two windows.
        if (!channel.applyFrameDeadline()) return;
        const request = readFrame(channel.reader, &request_buffer) catch |err| {
            if (err == error.EndOfStream) {
                if (frame_count == 0) return error.EndOfStream;
                return;
            }
            if (err == error.Truncated) return listener.Error.BadTcpFrame;
            return err;
        };
        _ = runtime.tryMaintenanceTick(channel.io);
        // RFC 9210 section 3: the answer comes from the same entry point the
        // cleartext TCP path uses, so the peer address reaches the recursion
        // policy, the local-zone table, and the cookie validation.
        const response_bytes = try runtime.answerFromTcp(request, &response_buffer, client, counters);
        // The counter moves after the answer, so a refused or failed query
        // is not counted as served.
        if (counters) |value| metrics.bump(&value.dot_queries_total);
        // RFC 7830 section 4: the responder pads the answer when the query
        // carried the Padding option. RFC 7830 section 6 keeps the option for
        // encrypted transports, so this path and no other one calls it.
        const padded = if (dns_message.Message.parseQuery(arena.allocator(), request)) |parsed|
            (try dns_padding.padResponse(arena.allocator(), &parsed, response_bytes)) orelse response_bytes
        else |_|
            response_bytes;
        if (padded.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(padded.len), .big);
        try channel.writer.writeAll(&prefix);
        try channel.writer.writeAll(padded);
        // The answer leaves the connection now: a TLS writer buffers until
        // it is flushed, and the client waits for the answer.
        try channel.writer.flush();
    }
}

/// Reads one length-prefixed frame. A clean EOF at the frame boundary ends
/// the connection; a half-written length prefix and a truncated payload are
/// both a bad frame.
fn readFrame(reader: *std.Io.Reader, frame_buffer: []u8) ![]const u8 {
    // The two octets are read one at a time, so a prefix that stops after
    // the first octet is a bad frame and not a clean end of stream.
    const first = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => return err,
    };
    const second = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return error.Truncated,
        else => return err,
    };
    const request_len = std.mem.readInt(u16, &.{ first, second }, .big);
    try listener.validateTcpFrameLength(request_len);
    if (request_len > frame_buffer.len) return listener.Error.BadTcpFrame;
    reader.readSliceAll(frame_buffer[0..request_len]) catch |err| switch (err) {
        error.EndOfStream => return error.Truncated,
        else => return err,
    };
    return frame_buffer[0..request_len];
}

/// Serves one DoT connection: the TLS handshake with the "dot" ALPN token,
/// then the RFC 7858 framing over the encrypted channel.
pub fn serveDotTlsStream(
    stream: std.Io.net.Stream,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
) !void {
    return serveDotTlsStreamWithTimeout(stream, io, server, runtime, counters, listener.tcpIdleTimeout());
}

/// Serves one DoT connection with the frame timeout the caller asks for.
/// The handshake and every frame run on the raw descriptor under a poll
/// deadline, so a peer that stalls costs one connection and not the server.
fn serveDotTlsStreamWithTimeout(
    stream: std.Io.net.Stream,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
    timeout: tcp_deadline.Timeout,
) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    // A peer that stops reading must not block the worker in a write past
    // its frame deadline: the socket carries the same timeout the poll-based
    // deadline enforces.
    tcp_deadline.setSocketTimeout(stream.socket.handle, timeout);
    // RFC 9210 section 4.2: the operator may bound the lifetime of one
    // connection, and that deadline covers the whole connection.
    const connection_deadline = channel_mod.connectionDeadline(io);
    // The handshake runs under one absolute deadline: the connection's, when
    // the operator set one, and the module's own timeout otherwise. A peer
    // that dribbles handshake bytes holds a worker slot for that window and
    // no longer.
    const handshake_timeout = listener.frameTimeout(io, connection_deadline, timeout) orelse return;
    const handshake_deadline = tcp_deadline.deadline(io, handshake_timeout);

    // The handshake is part of the connection, so it shares its deadline.
    // It runs directly on the socket fd: the TLS layer polls the fd and
    // recomputes against this absolute deadline each iteration.
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
        .timeout = timeout,
        .connection_deadline = connection_deadline,
    };
    try serveDotFrames(&channel, runtime, counters, &stream.socket.address);
}

/// Binds the DoT port and serves DoT connections. Every accepted connection
/// gets a TLS handshake with the "dot" ALPN token before any DNS byte is
/// written, so the port never answers DNS in cleartext. Each connection is
/// served on its own task, so a peer that stalls in the handshake does not
/// hold up the others.
pub fn serveDotLoopOnAddress(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    server: *tls_server.Server,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
) !void {
    var bind_address = address.*;
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    return serveDotLoop(&listener_socket, io, runtime, server, max_requests, counters);
}

/// Serves the DoT port on an already-bound listener.
pub fn serveDotLoop(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    runtime: *Runtime,
    server: *tls_server.Server,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
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
        group.concurrent(io, serveDotTlsWorker, .{ stream, io, server, runtime, &sources, counters }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                sources.release(&stream.socket.address);
                stream.close(io);
            },
        };
    }
}

/// Serves one accepted DoT connection.
fn serveDotTlsWorker(
    stream: std.Io.net.Stream,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    sources: *listener.SourceCounter,
    counters: ?*metrics.Counters,
) void {
    defer stream.close(io);
    defer sources.release(&stream.socket.address);
    serveDotTlsStream(stream, io, server, runtime, counters) catch {};
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

test "DoT channel serves FIFO length-prefixed queries on one stream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    var server_stream = streams[1];
    var server_stream_closed = false;
    defer {
        if (!server_stream_closed) server_stream.close(io);
    }

    var first_query = simple_a_query.*;
    var second_query = simple_a_query.*;
    std.mem.writeInt(u16, first_query[0..2], 0x1234, .big);
    std.mem.writeInt(u16, second_query[0..2], 0x5678, .big);

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(first_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&first_query);
    std.mem.writeInt(u16, &prefix, @intCast(second_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&second_query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try serveDotStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [512]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const first_response_len_bytes = try client_reader.interface.takeArray(2);
    const first_response_len = std.mem.readInt(u16, first_response_len_bytes, .big);
    const first_response_bytes = try client_reader.interface.take(first_response_len);
    const first_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), first_response_bytes);
    try std.testing.expect(first_response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x1234), first_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), first_response.header.answer_count);

    const second_response_len_bytes = try client_reader.interface.takeArray(2);
    const second_response_len = std.mem.readInt(u16, second_response_len_bytes, .big);
    const second_response_bytes = try client_reader.interface.take(second_response_len);
    const second_response = try @import("../dns/message.zig").Message.parse(arena.allocator(), second_response_bytes);
    try std.testing.expect(second_response.header.qr);
    try std.testing.expectEqual(@as(u16, 0x5678), second_response.header.id);
    try std.testing.expectEqual(@as(u16, 1), second_response.header.answer_count);

    server_stream.close(io);
    server_stream_closed = true;
}

test "RFC 7830: the DoT answer is padded when the query asked for it" {
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

    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(padding_a_query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(padding_a_query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try serveDotStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const response_len_bytes = try client_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, response_len_bytes, .big);
    const response_bytes = try client_reader.interface.take(response_len);
    const response = try @import("../dns/message.zig").Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    // The answer carries the Padding option the query asked for, and the
    // padding rounds the message up to a multiple of the padding block.
    var options: ?[]const u8 = null;
    for (response.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        options = switch (record.rdata) {
            .OPT => |opt| opt.bytes(),
            else => unreachable,
        };
    }
    const padding = @import("../dns/rdata.zig").findOption(options.?, @import("../dns/rdata.zig").EDNS_PADDING_OPTION_CODE).?;
    try std.testing.expect(padding.len > 0);
    for (padding) |octet| try std.testing.expectEqual(@as(u8, 0), octet);
    // The answer carries the Padding option exactly once.
    try std.testing.expectEqual(@as(usize, 1), paddingOptionCount(options.?));
    try std.testing.expectEqual(@as(usize, 0), response_bytes.len % dns_padding.PADDING_BLOCK);
}

test "RFC 7830: the DoT answer carries no padding when the query did not ask for it" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const response_bytes = try dotStreamAnswer(arena.allocator(), io, &runtime, no_padding_a_query, null);
    const response = try dns_message.Message.parse(arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    // The query advertised EDNS(0), so the answer carries an OPT record, but
    // the query asked for no padding, so the option is absent.
    const options = messageOptions(&response).?;
    try std.testing.expectEqual(@as(usize, 0), options.len);
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);
}

test "DoT channel rejects a zero length prefix" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [8]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(&.{ 0, 0 });
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try std.testing.expectError(listener.Error.BadTcpFrame, serveDotStreamOnce(server_stream, io, &runtime));
}

test "DoT channel rejects a half-written length prefix" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [8]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    // One octet of the two-octet length prefix, and then the end of the
    // stream: a bad frame, not a clean close.
    try client_writer.interface.writeAll(&.{0x00});
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try std.testing.expectError(listener.Error.BadTcpFrame, serveDotStreamOnce(server_stream, io, &runtime));
}

/// Serves one query over a fresh stream and returns the answer the server
/// wrote, with the counters the caller asks for.
fn dotStreamAnswer(
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime: *Runtime,
    query: []const u8,
    counters: ?*metrics.Counters,
) ![]u8 {
    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [1024]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    if (counters) |value| {
        serveDotStreamOnceWithMetrics(server_stream, io, runtime, value) catch |err| switch (err) {
            error.EndOfStream => {},
            else => return err,
        };
    } else {
        serveDotStreamOnce(server_stream, io, runtime) catch |err| switch (err) {
            error.EndOfStream => {},
            else => return err,
        };
    }

    var client_read_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const length_bytes = try client_reader.interface.takeArray(2);
    const length = std.mem.readInt(u16, length_bytes, .big);
    const bytes = try allocator.alloc(u8, length);
    try client_reader.interface.readSliceAll(bytes);
    return bytes;
}

/// The option framing of a message's OPT record, or null when the message
/// carries no EDNS(0) at all.
fn messageOptions(message: *const dns_message.Message) ?[]const u8 {
    for (message.additionals.slice()) |record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return switch (record.rdata) {
            .OPT => |opt| opt.bytes(),
            else => unreachable,
        };
    }
    return null;
}

/// The number of times the option framing carries the RFC 7830 Padding
/// option.
fn paddingOptionCount(options: []const u8) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (offset + 4 <= options.len) {
        const code = std.mem.readInt(u16, options[offset..][0..2], .big);
        const length = std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        offset += 4;
        if (length > options.len - offset) break;
        if (code == dns_rdata.EDNS_PADDING_OPTION_CODE) count += 1;
        offset += length;
    }
    return count;
}

test "a DoT query for a locally served name answers the same way with and without the counters" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    // RFC 6761 section 6.3: a localhost name is answered from the local
    // table of RFC 6303, RFC 6761, RFC 7793, and RFC 8375.
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x1111, "localhost.", .A, false);

    var counters = metrics.Counters{};
    const with_counters = try dotStreamAnswer(arena.allocator(), io, &runtime, query, &counters);
    const without_counters = try dotStreamAnswer(arena.allocator(), io, &runtime, query, null);
    // The counters change how the query is counted, never what it is
    // answered.
    try std.testing.expectEqualSlices(u8, without_counters, with_counters);

    const answer = try dns_message.Message.parse(arena.allocator(), with_counters);
    try std.testing.expect(answer.header.qr);
    try std.testing.expectEqual(@as(usize, 1), answer.answers.items.len);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &answer.answers.items[0].rdata.A);
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.dot_queries_total.load(.monotonic));
}

test "DoT defaults name the RFC 7858 port and the IANA dot ALPN token" {
    try std.testing.expectEqual(@as(u16, 853), DOT_PORT);
    try std.testing.expectEqualStrings("dot", DOT_ALPN);
    try std.testing.expectEqual(listener.TCP_MAX_FRAMES_PER_CONNECTION, MAX_FRAMES_PER_CONNECTION);
}

/// The identity the DoT tests load: a throwaway self-signed certificate and
/// its key, written to a temporary directory.
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

/// The server side of the DoT tests: one accepted connection, served.
fn serveOneConnection(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveDotTlsStream(stream, io, server, runtime, null) catch {};
}

/// The server side of the stall test: two accepted connections, each served
/// with the frame timeout the test asks for.
fn serveTwoConnections(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    timeout: tcp_deadline.Timeout,
) void {
    for (0..2) |_| {
        const stream = listener_socket.accept(io) catch return;
        defer stream.close(io);
        serveDotTlsStreamWithTimeout(stream, io, server, runtime, null, timeout) catch {};
    }
}

/// The server side of the handshake-window test: one accepted connection,
/// served with the handshake window the test asks for.
fn serveOneConnectionWithTimeout(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    timeout: tcp_deadline.Timeout,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveDotTlsStreamWithTimeout(stream, io, server, runtime, null, timeout) catch {};
}

/// The server side of the metrics test: one accepted connection, served with
/// the counters the test watches.
fn serveOneConnectionWithMetrics(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    counters: *metrics.Counters,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveDotTlsStream(stream, io, server, runtime, counters) catch {};
}

/// A client connection that offers the "dot" token, the way a DoT client
/// does.
fn tlsClient(fd: std.posix.fd_t, io: std.Io) !ossl.Connection {
    return insecureTestClient(fd, io, DOT_ALPN, true);
}

/// Runs one DoT query over a real TLS handshake and returns the answer the
/// server wrote.
fn dotTlsAnswer(
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    query: []const u8,
) ![]u8 {
    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, server, runtime });
    defer thread.join();

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try tlsClient(stream.socket.handle, io);
    defer connection.close() catch {};

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try connection_writer.interface.writeAll(&prefix);
    try connection_writer.interface.writeAll(query);
    try connection_writer.interface.flush();

    const len_bytes = try connection_reader.interface.takeArray(2);
    const response_len = std.mem.readInt(u16, len_bytes, .big);
    const bytes = try allocator.alloc(u8, response_len);
    try connection_reader.interface.readSliceAll(bytes);
    return bytes;
}

test "a DoT query the recursion ACL refuses is refused over DoT too" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    // The recursion ACL allows one network only, and the peer is on the
    // loopback, so the ACL refuses it.
    var policy = resolver_mod.Policy{};
    policy.recursion_allow[0] = try config_mod.Cidr.parse("10.0.0.0/8");
    policy.recursion_allow_len = 1;
    runtime.resolver = try resolver_mod.Resolver.init(std.testing.allocator, io, policy);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var query_buffer: [512]u8 = undefined;
    // The query carries EDNS(0), so the refusal can carry the EDE option that
    // says why it was refused.
    const query = try @import("../cli/query.zig").buildQueryPacketWithEdns(&query_buffer, 0x2222, "example.com.", .A, .{ .dnssec_ok = true });
    const answer_bytes = try dotTlsAnswer(allocator, io, &server, &runtime, query);
    const answer = try dns_message.Message.parse(allocator, answer_bytes);

    // RFC 8914 section 4.21: the refusal carries the EDE code that says the
    // operator's recursion ACL refused the client. The cleartext TCP path
    // refuses the same peer the same way.
    try std.testing.expect(answer.header.qr);
    try std.testing.expectEqual(dns_header.Rcode.refused, answer.header.rcode);
    const options = messageOptions(&answer).?;
    const ede = dns_rdata.findOption(options, ede_option_code).?;
    try std.testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, ede[0..2], .big));
}

test "a DoT peer that dribbles handshake bytes is dropped inside the handshake window" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    // The handshake window is short, so the dribbling peer is dropped at
    // once instead of holding the connection for the production timeout.
    const handshake_window = tcp_deadline.Timeout{ .seconds = 1, .microseconds = 0 };
    const thread = try std.Thread.spawn(.{}, serveOneConnectionWithTimeout, .{ &listener_socket, io, &server, &runtime, handshake_window });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    // A valid record header, and then a body that never arrives whole: the
    // handshake never completes. Written directly on the fd: the peer is
    // deliberately not a TLS client.
    try tcp_deadline.writeExact(stalled.socket.handle, io, &.{ 0x16, 0x03, 0x03, 0x00, 0x64 }, tcp_deadline.deadline(io, handshake_window));

    var stop = std.atomic.Value(bool).init(false);
    var sent = std.atomic.Value(usize).init(0);
    const dribbler = try std.Thread.spawn(.{}, dribbleHandshake, .{ io, stalled.socket.handle, &stop, &sent });
    defer {
        stop.store(true, .release);
        dribbler.join();
    }

    // The handshake window is over, so the server drops the connection even
    // though the peer keeps sending handshake bytes.
    try std.testing.expect(readUntilEof(stalled.socket.handle, 3000));
    // The peer really dribbled: the server dropped the connection while the
    // bytes were still coming.
    try std.testing.expect(sent.load(.monotonic) > 4);

    thread.join();
}

/// The dribbling peer: one handshake byte every interval, so the peer never
/// lets the server wait long enough for a read to time out. The counter holds
/// the bytes the peer sent, so a test can tell a dribbling peer from a
/// silent one.
fn dribbleHandshake(io: std.Io, fd: std.posix.fd_t, stop: *std.atomic.Value(bool), sent: *std.atomic.Value(usize)) void {
    while (!stop.load(.acquire)) {
        const result = std.posix.system.write(fd, &.{0x00}, 1);
        if (std.posix.errno(result) != .SUCCESS) return;
        const count: usize = @intCast(result);
        if (count == 0) return;
        _ = sent.fetchAdd(1, .monotonic);
        std.Io.sleep(io, .fromMilliseconds(50), .awake) catch return;
    }
}

/// Reads what the peer still sends until the connection ends. False means the
/// connection was still open when the budget was over.
fn readUntilEof(fd: std.posix.fd_t, budget_ms: i32) bool {
    var buffer: [256]u8 = undefined;
    while (true) {
        var poll_fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const count = std.posix.poll(&poll_fds, budget_ms) catch return false;
        if (count == 0) return false;
        const read_count = std.posix.read(fd, &buffer) catch return true;
        if (read_count == 0) return true;
    }
}

test "DoT answers a query over a real TLS 1.3 handshake with the dot ALPN token" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, DOT_ALPN, true);
    // The server speaks "dot" and nothing else.
    try std.testing.expectEqualStrings(DOT_ALPN, connection.alpnProtocol().?);

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x4321, .big);
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
    try std.testing.expectEqual(@as(u16, 0x4321), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    // The DoT connection serves queries until the client goes away, so the
    // client closes its side and the server sees the end of the stream.
    connection.close() catch {};
    thread.join();
}

test "close against a silent peer waits for the deadline instead of spinning" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const Silent = struct {
        fn run(listener_ptr: *std.Io.net.Server, io_inner: std.Io, server_ptr: *tls_server.Server) void {
            const stream = listener_ptr.accept(io_inner) catch return;
            defer stream.close(io_inner);
            const hs_deadline = tcp_deadline.deadline(io_inner, .{ .seconds = 5 });
            var conn = server_ptr.handshake(stream.socket.handle, io_inner, hs_deadline) catch return;
            // Stay silent: never send close_notify, so the client's
            // `SSL_shutdown` keeps returning 0 until its deadline lapses.
            std.Io.sleep(io_inner, .fromMilliseconds(4000), .awake) catch {};
            conn.closeWithoutNotify();
        }
    };
    const thread = try std.Thread.spawn(.{}, Silent.run, .{ &listener_socket, io, &server });
    defer thread.join();

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    const ctx = try ossl.clientCtx(.insecure);
    defer ossl.freeClientCtx(ctx);
    const close_deadline = tcp_deadline.deadline(io, .{ .seconds = 2 });
    var connection = try ossl.clientHandshake(ctx, stream.socket.handle, io, close_deadline, .{
        .verify = .insecure,
        .verify_host = "localhost",
        .sni = "localhost",
        .alpn = DOT_ALPN,
    });

    const start_ns: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    connection.close() catch {};
    const end_ns: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    const elapsed_ns: i64 = end_ns - start_ns;
    // Bounded by the ~2s deadline plus a generous margin; the old tight
    // `continue` loop never returned here at all.
    try std.testing.expect(elapsed_ns < 10 * std.time.ns_per_s);
}

test "close against a peer that completes the shutdown returns promptly" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const Responder = struct {
        fn run(listener_ptr: *std.Io.net.Server, io_inner: std.Io, server_ptr: *tls_server.Server) void {
            const stream = listener_ptr.accept(io_inner) catch return;
            defer stream.close(io_inner);
            const hs_deadline = tcp_deadline.deadline(io_inner, .{ .seconds = 5 });
            var conn = server_ptr.handshake(stream.socket.handle, io_inner, hs_deadline) catch return;
            conn.close() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{ &listener_socket, io, &server });
    defer thread.join();

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try tlsClient(stream.socket.handle, io);

    const start_ns: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    try connection.close();
    const end_ns: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    const elapsed_ns: i64 = end_ns - start_ns;
    try std.testing.expect(elapsed_ns < 10 * std.time.ns_per_s);
}

test "a DoT peer that stalls past the deadline is dropped and the server keeps serving" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    // The frame deadline is short, so the stalled peer is dropped at once
    // instead of holding the connection for the production timeout.
    const frame_timeout = tcp_deadline.Timeout{ .seconds = 0, .microseconds = 200_000 };
    const thread = try std.Thread.spawn(.{}, serveTwoConnections, .{ &listener_socket, io, &server, &runtime, frame_timeout });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };

    // The first peer completes the handshake and then says nothing.
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    var stalled_connection = try tlsClient(stalled.socket.handle, io);
    defer stalled_connection.close() catch {};

    // The stalled peer is dropped: the connection ends instead of waiting
    // for a query that never comes.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = stalled.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 5000));

    // The server is still alive: it answers the peer that comes next.
    const answered = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer answered.close(io);
    var answered_connection = try tlsClient(answered.socket.handle, io);
    defer answered_connection.close() catch {};

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = answered_connection.reader(&read_buffer);
    var connection_writer = answered_connection.writer(&write_buffer);
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x5a5a, .big);
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
    try std.testing.expectEqual(@as(u16, 0x5a5a), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    thread.join();
}

test "a DoT connection ends when the configured connection duration is over" {
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

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };

    // The peer completes the handshake and then says nothing.
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    var stalled_connection = try tlsClient(stalled.socket.handle, io);
    defer stalled_connection.close() catch {};

    // The connection ends with the duration the operator configured, not with
    // the five-second frame deadline of the transport.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = stalled.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 3000));

    thread.join();
}

test "a DoT query answered after a SIGHUP comes from the reloaded zone" {
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
    try runtime.setReloadSource(tmp.dir, zone_file_name, zone_origin);

    var server: tls_server.Server = undefined;
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
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

    var connection = try tlsClient(stream.socket.handle, io);
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

test "a DoT query moves the counters the cleartext TCP path moves" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    var counters = metrics.Counters{};
    const thread = try std.Thread.spawn(.{}, serveOneConnectionWithMetrics, .{ &listener_socket, io, &server, &runtime, &counters });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try tlsClient(stream.socket.handle, io);
    defer connection.close() catch {};

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x6b6b, .big);
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
    try std.testing.expectEqual(@as(u16, 0x6b6b), response.header.id);

    thread.join();

    // The DoT path counts the query, the answer and the transport, the way
    // the cleartext TCP path counts them.
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.dot_queries_total.load(.monotonic));
}

test "the DoT listener answers a query over the bound port" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    // The listener serves one connection and then stops, so the test ends.
    const thread = try std.Thread.spawn(.{}, serveDotLoop, .{ &listener_socket, io, &runtime, &server, @as(?usize, 1), @as(?*metrics.Counters, null) });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, DOT_ALPN, true);
    try std.testing.expectEqualStrings(DOT_ALPN, connection.alpnProtocol().?);

    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x2468, .big);
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
    try std.testing.expectEqual(@as(u16, 0x2468), response.header.id);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);

    connection.close() catch {};
    thread.join();
}

test "DoT refuses a client that offers another ALPN token" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOT_ALPN);
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

test "DoT refuses to start without a loadable identity and binds no port" {
    var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestIdentity(tmp.dir, io);

    // The identity cannot be loaded, so the listener never starts.
    var server: tls_server.Server = undefined;
    if (server.init(allocator, io, tmp.dir, "missing-cert.pem", "key.pem", DOT_ALPN)) |_| {
        return error.ExpectedIdentityLoadFailure;
    } else |_| {}

    // Nothing is bound: the port refuses the connection instead of serving.
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(10531) };
    const served = std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp }) catch |err| switch (err) {
        error.ConnectionRefused => return,
        else => return err,
    };
    served.close(io);
    return error.EncryptedListenerServedAfterRefusal;
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
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

/// The same query with an OPT record that advertises EDNS(0) and carries the
/// RFC 7830 Padding option: the request that asks for a padded answer.
const padding_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x00,
};

/// The same query with an OPT record that advertises EDNS(0) and carries no
/// option at all: the request that asks for an unpadded answer.
const no_padding_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01, 0,    0x00, 0x29, 0x04, 0xd0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/// The RFC 8914 section 3 EDNS option code of the Extended DNS Error.
const ede_option_code: u16 = 15;
