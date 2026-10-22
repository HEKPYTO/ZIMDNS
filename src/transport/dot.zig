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
/// configured, the same bound the cleartext TCP listener enforces. A SIGHUP
/// re-reads the zone file on this path too, outside the signal handler, so
/// the answer that follows a reload comes from the new zone.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write failures propagate as
/// I/O errors.
const std = @import("std");
const tls = @import("tls");
const Runtime = @import("../auth/runtime.zig").Runtime;
const dns_message = @import("../dns/message.zig");
const dns_padding = @import("../dns/padding.zig");
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
const IO_TIMEOUT = listener.TCP_IO_TIMEOUT;
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

    var read_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var write_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var reader = tcp_deadline.DeadlineReader.init(stream.socket.handle, io, &read_buffer, IO_TIMEOUT);
    var writer = tcp_deadline.DeadlineWriter.init(stream.socket.handle, io, &write_buffer, IO_TIMEOUT);
    defer writer.interface.flush() catch {};
    var channel = channel_mod.Channel{
        .io = io,
        .reader = &reader.interface,
        .writer = &writer.interface,
        .deadlines = .{ .reader = &reader, .writer = &writer },
        .timeout = IO_TIMEOUT,
        .connection_deadline = channel_mod.connectionDeadline(io),
    };
    try serveDotFrames(&channel, runtime, counters);
}

/// RFC 7858 section 3.3 framing loop: two-octet length-prefixed DNS messages
/// with the same bounds as DNS over TCP. Operates on an already-terminated
/// byte stream, so the cleartext helper and the TLS connection share it.
fn serveDotFrames(channel: *const channel_mod.Channel, runtime: *Runtime, counters: ?*metrics.Counters) !void {
    var request_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    // The request is parsed once per frame to see whether it asked for
    // padding, and the padded answer is allocated beside it.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var frame_count: usize = 0;
    while (frame_count < MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
        // A SIGHUP asks for the zone to be re-read. The reload happens here,
        // outside the signal handler. The first check answers a connection
        // that waited for the request, the second one answers a request that
        // arrived while the flag was set, so the answer that follows a
        // reload always comes from the new zone.
        _ = runtime.reloadZoneIfRequested(channel.io);
        // One deadline for the whole frame: a peer that stalls in the middle
        // of a frame loses the frame, not the server.
        if (!channel.applyFrameDeadline()) return;
        const request = readFrame(channel.reader, &request_buffer) catch |err| {
            if (err == error.EndOfStream) {
                if (frame_count == 0) return error.EndOfStream;
                return;
            }
            if (err == error.Truncated) return listener.Error.BadTcpFrame;
            return err;
        };
        _ = runtime.reloadZoneIfRequested(channel.io);
        // The answer gets its own deadline: the reload took time, and the
        // cleartext path gives the write of a frame its own deadline too.
        if (!channel.applyFrameDeadline()) return;
        if (counters) |value| value.dot_queries_total += 1;
        const response_bytes = if (counters) |value|
            try runtime.answerWithMetrics(request, &response_buffer, value)
        else
            try runtime.answer(request, &response_buffer);
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
/// the connection; a truncated payload is a bad frame.
fn readFrame(reader: *std.Io.Reader, frame_buffer: []u8) ![]const u8 {
    const len_bytes = reader.takeArray(2) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => return err,
    };
    const request_len = std.mem.readInt(u16, len_bytes, .big);
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
    return serveDotTlsStreamWithTimeout(stream, io, server, runtime, counters, IO_TIMEOUT);
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
    // RFC 9210 section 4.2: the operator may bound the lifetime of one
    // connection, and that deadline covers the whole connection.
    const connection_deadline = channel_mod.connectionDeadline(io);

    var input_buffer: [tls_server.input_buffer_len]u8 = undefined;
    var output_buffer: [tls_server.output_buffer_len]u8 = undefined;
    var stream_reader = tcp_deadline.DeadlineReader.init(stream.socket.handle, io, &input_buffer, timeout);
    var stream_writer = tcp_deadline.DeadlineWriter.init(stream.socket.handle, io, &output_buffer, timeout);
    // The handshake is part of the connection, so it shares its deadline.
    if (connection_deadline) |value| {
        stream_reader.setFrameDeadline(value);
        stream_writer.setFrameDeadline(value);
    }
    var connection = try server.handshake(&stream_reader.interface, &stream_writer.interface);

    var read_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var write_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    defer {
        connection_writer.interface.flush() catch {};
        connection.close() catch {};
        stream_writer.interface.flush() catch {};
    }
    var channel = channel_mod.Channel{
        .io = io,
        .reader = &connection_reader.interface,
        .writer = &connection_writer.interface,
        .deadlines = .{ .reader = &stream_reader, .writer = &stream_writer },
        .timeout = timeout,
        .connection_deadline = connection_deadline,
    };
    try serveDotFrames(&channel, runtime, counters);
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
) !void {
    var bind_address = address.*;
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    return serveDotLoop(&listener_socket, io, runtime, server, max_requests);
}

/// Serves the DoT port on an already-bound listener.
pub fn serveDotLoop(
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
        const stream = try listener_socket.accept(io);
        accepted += 1;
        // The encrypted listener holds the same bounds as the cleartext one: a
        // source address holds only so many connections at once (RFC 9210
        // section 4.2), and a connection with no worker slot is closed at once.
        if (!sources.admit(&stream.socket.address)) {
            stream.close(io);
            continue;
        }
        group.concurrent(io, serveDotTlsWorker, .{ stream, io, server, runtime, &sources }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                sources.release(&stream.socket.address);
                stream.close(io);
            },
        };
    }
}

/// Serves one accepted DoT connection.
fn serveDotTlsWorker(stream: std.Io.net.Stream, io: std.Io, server: *tls_server.Server, runtime: *Runtime, sources: *listener.SourceCounter) void {
    defer stream.close(io);
    defer sources.release(&stream.socket.address);
    serveDotTlsStream(stream, io, server, runtime, null) catch {};
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
    try std.testing.expectEqual(@as(usize, 0), response_bytes.len % dns_padding.PADDING_BLOCK);
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

test "DoT channel records metrics for served queries" {
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

    var query = simple_a_query.*;
    std.mem.writeInt(u16, query[0..2], 0x9a9a, .big);
    var client_write_buffer: [512]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
    try client_writer.interface.writeAll(&prefix);
    try client_writer.interface.writeAll(&query);
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    var counters = metrics.Counters{};
    // One query then EOF ends the stream; EOF after a served frame is not an error.
    serveDotStreamOnceWithMetrics(server_stream, io, &runtime, &counters) catch |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    };
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 1), counters.dot_queries_total);
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
fn tlsClient(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    rng_source: *std.Random.IoSource,
    io: std.Io,
) !tls.Connection {
    return tls.client(reader, writer, .{
        .rng = rng_source.interface(),
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{DOT_ALPN},
    });
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

    var client_input: [tls_server.input_buffer_len]u8 = undefined;
    var client_output: [tls_server.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    var connection = try tls.client(&client_reader.interface, &client_writer.interface, .{
        .rng = rng_source.interface(),
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{DOT_ALPN},
    });
    // The server speaks "dot" and nothing else.
    try std.testing.expectEqualStrings(DOT_ALPN, connection.alpn_protocol.?);

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
    var rng_source: std.Random.IoSource = .{ .io = io };

    // The first peer completes the handshake and then says nothing.
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    var stalled_input: [tls_server.input_buffer_len]u8 = undefined;
    var stalled_output: [tls_server.output_buffer_len]u8 = undefined;
    var stalled_reader = stalled.reader(io, &stalled_input);
    var stalled_writer = stalled.writer(io, &stalled_output);
    var stalled_connection = try tlsClient(&stalled_reader.interface, &stalled_writer.interface, &rng_source, io);
    defer stalled_connection.close() catch {};

    // The stalled peer is dropped: the connection ends instead of waiting
    // for a query that never comes.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = stalled.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 5000));

    // The server is still alive: it answers the peer that comes next.
    const answered = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer answered.close(io);
    var answered_input: [tls_server.input_buffer_len]u8 = undefined;
    var answered_output: [tls_server.output_buffer_len]u8 = undefined;
    var answered_reader = answered.reader(io, &answered_input);
    var answered_writer = answered.writer(io, &answered_output);
    var answered_connection = try tlsClient(&answered_reader.interface, &answered_writer.interface, &rng_source, io);
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
    var rng_source: std.Random.IoSource = .{ .io = io };

    // The peer completes the handshake and then says nothing.
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    var stalled_input: [tls_server.input_buffer_len]u8 = undefined;
    var stalled_output: [tls_server.output_buffer_len]u8 = undefined;
    var stalled_reader = stalled.reader(io, &stalled_input);
    var stalled_writer = stalled.writer(io, &stalled_output);
    var stalled_connection = try tlsClient(&stalled_reader.interface, &stalled_writer.interface, &rng_source, io);
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

    var client_input: [tls_server.input_buffer_len]u8 = undefined;
    var client_output: [tls_server.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    var connection = try tlsClient(&client_reader.interface, &client_writer.interface, &rng_source, io);
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

    var client_input: [tls_server.input_buffer_len]u8 = undefined;
    var client_output: [tls_server.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    var connection = try tlsClient(&client_reader.interface, &client_writer.interface, &rng_source, io);
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
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total);
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total);
    try std.testing.expectEqual(@as(u64, 1), counters.dot_queries_total);
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
    const thread = try std.Thread.spawn(.{}, serveDotLoop, .{ &listener_socket, io, &runtime, &server, @as(?usize, 1) });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var client_input: [tls_server.input_buffer_len]u8 = undefined;
    var client_output: [tls_server.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    var connection = try tls.client(&client_reader.interface, &client_writer.interface, .{
        .rng = rng_source.interface(),
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{DOT_ALPN},
    });
    try std.testing.expectEqualStrings(DOT_ALPN, connection.alpn_protocol.?);

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

    var client_input: [tls_server.input_buffer_len]u8 = undefined;
    var client_output: [tls_server.output_buffer_len]u8 = undefined;
    var client_reader = stream.reader(io, &client_input);
    var client_writer = stream.writer(io, &client_output);
    var rng_source: std.Random.IoSource = .{ .io = io };
    // The client offers a protocol the DoT port does not speak.
    const handshake = tls.client(&client_reader.interface, &client_writer.interface, .{
        .rng = rng_source.interface(),
        .host = "localhost",
        .root_ca = .empty,
        .insecure_skip_verify = true,
        .now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{"http/1.1"},
    });
    // RFC 7301: the server answers a client that offers no ALPN token it
    // speaks with the no_application_protocol alert.
    try std.testing.expectError(error.TlsAlertNoApplicationProtocol, handshake);

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
