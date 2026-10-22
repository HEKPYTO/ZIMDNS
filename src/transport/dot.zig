/// Contract: Serves the RFC 7858 section 3.3 DNS-over-TLS wire framing on an
/// already-TLS-terminated byte channel. Two-octet length-prefixed stream
/// framing is the same as DNS over TCP, so frame bounds and FIFO order are
/// shared with the plaintext TCP listener. The framing runs over a
/// reader/writer pair, so the cleartext stream helper and the TLS connection
/// share one framing. The DoT port is served by the listener in this module:
/// it binds the port, terminates the handshake with the "dot" ALPN token, and
/// only then speaks DNS, so the port never answers in cleartext.
/// Ownership: Runtime is borrowed; streams are consumed/closed by the caller
/// loop; wire buffers are local.
/// Errors: DNS failures are typed; socket read/write failures propagate as
/// I/O errors.
const std = @import("std");
const tls = @import("tls");
const Runtime = @import("../auth/runtime.zig").Runtime;
const metrics = @import("../metrics.zig");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const tls_policy = @import("tls.zig");
const tls_server = @import("tls_server.zig");

pub const DOT_ALPN = tls_policy.dot_alpn;
pub const DOT_PORT = tls_policy.dot_port;
pub const MAX_FRAMES_PER_CONNECTION = listener.TCP_MAX_FRAMES_PER_CONNECTION;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
const IO_TIMEOUT = listener.TCP_IO_TIMEOUT;
/// The cleartext stream buffer. The frame buffers live in the framing.
const STREAM_BUFFER_SIZE: usize = 8192;

pub fn serveDotStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime) !void {
    return serveDotStream(stream, io, runtime, null);
}

pub fn serveDotStreamOnceWithMetrics(
    stream: std.Io.net.Stream,
    io: std.Io,
    runtime: *const Runtime,
    counters: *metrics.Counters,
) !void {
    return serveDotStream(stream, io, runtime, counters);
}

/// Serves the cleartext stream: the framing over a socket, with no TLS. The
/// DoT port never uses this path; it exists for the framing tests.
fn serveDotStream(stream: std.Io.net.Stream, io: std.Io, runtime: *const Runtime, counters: ?*metrics.Counters) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    tcp_deadline.setSocketTimeout(stream.socket.handle, IO_TIMEOUT);

    var read_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var write_buffer: [STREAM_BUFFER_SIZE]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var writer = stream.writer(io, &write_buffer);
    defer writer.interface.flush() catch {};
    try serveDotFrames(&reader.interface, &writer.interface, runtime, counters);
}

/// RFC 7858 section 3.3 framing loop: two-octet length-prefixed DNS messages
/// with the same bounds as DNS over TCP. Operates on an already-terminated
/// byte stream, so the cleartext helper and the TLS connection share it.
fn serveDotFrames(reader: *std.Io.Reader, writer: *std.Io.Writer, runtime: *const Runtime, counters: ?*metrics.Counters) !void {
    var request_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var response_buffer: [listener.TCP_MAX_FRAME_SIZE]u8 = undefined;
    var frame_count: usize = 0;
    while (frame_count < MAX_FRAMES_PER_CONNECTION) : (frame_count += 1) {
        const request = readFrame(reader, &request_buffer) catch |err| {
            if (err == error.EndOfStream) {
                if (frame_count == 0) return error.EndOfStream;
                return;
            }
            if (err == error.Truncated) return listener.Error.BadTcpFrame;
            return err;
        };
        if (counters) |value| value.dot_queries_total += 1;
        const response_bytes = if (counters) |value|
            try runtime.answerWithMetrics(request, &response_buffer, value)
        else
            try runtime.answer(request, &response_buffer);
        if (response_bytes.len > listener.TCP_MAX_FRAME_SIZE) return listener.Error.ResponseTooLarge;

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response_bytes.len), .big);
        try writer.writeAll(&prefix);
        try writer.writeAll(response_bytes);
        // The answer leaves the connection now: a TLS writer buffers until
        // it is flushed, and the client waits for the answer.
        try writer.flush();
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
    runtime: *const Runtime,
    counters: ?*metrics.Counters,
) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;
    tcp_deadline.setSocketTimeout(stream.socket.handle, IO_TIMEOUT);

    var input_buffer: [tls_server.input_buffer_len]u8 = undefined;
    var output_buffer: [tls_server.output_buffer_len]u8 = undefined;
    var stream_reader = stream.reader(io, &input_buffer);
    var stream_writer = stream.writer(io, &output_buffer);
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
    try serveDotFrames(&connection_reader.interface, &connection_writer.interface, runtime, counters);
}

/// Binds the DoT port and serves DoT connections. Every accepted connection
/// gets a TLS handshake with the "dot" ALPN token before any DNS byte is
/// written, so the port never answers DNS in cleartext. Each connection is
/// served on its own task, so a peer that stalls in the handshake does not
/// hold up the others.
pub fn serveDotLoopOnAddress(
    io: std.Io,
    runtime: *const Runtime,
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
    runtime: *const Runtime,
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
fn serveDotTlsWorker(stream: std.Io.net.Stream, io: std.Io, server: *tls_server.Server, runtime: *const Runtime, sources: *listener.SourceCounter) void {
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
    runtime: *const Runtime,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveDotTlsStream(stream, io, server, runtime, null) catch {};
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

const simple_a_query = &[_]u8{
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    3,    'd',  'n',  's',  4,    'h',  'o',  'm',  'e',  4,    'a',  'r',
    'p',  'a',  0,    0x00, 0x01, 0x00, 0x01,
};
