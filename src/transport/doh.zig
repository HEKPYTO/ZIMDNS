/// Contract: Serves the RFC 8484 DNS-over-HTTPS message mapping (GET
/// /dns-query?dns=<base64url> and POST /dns-query with application/dns-message
/// bodies) over a TLS 1.3 channel, sharing the runtime's TCP answer path with
/// the Do53/DoT paths: the peer address of the accepted connection reaches
/// the recursion policy, the cookie check, and the locally served zones, the
/// same way it does on the cleartext TCP port. The listener in this module
/// binds the port, terminates the handshake with the "http/1.1" ALPN token,
/// and only then speaks HTTP/1.1 exchanges, so the port never answers in
/// cleartext: a client that offers no common token is refused with the
/// RFC 7301 no_application_protocol alert.
/// The channel carries the same bounds the cleartext TCP listener carries: at
/// most MAX_EXCHANGES_PER_CONNECTION exchanges per connection, the operator's
/// per-source connection cap, a worker bound, a per-frame socket deadline, and
/// the operator's connection-duration limit. A DoH connection lives no longer
/// than the connection duration the operator configured, the same bound the
/// cleartext TCP listener enforces. HTTP/2 framing additionally needs the
/// reviewed HTTP/2 dependency, so this module is the HTTP/1.1 mapping subset,
/// not a full RFC 8484 transport claim.
/// Ownership: Request/response scratch lives in caller buffers or a
/// per-exchange arena; runtime zones stay borrowed.
/// Errors: HTTP mapping failures map to HTTP status codes and never reach
/// the resolver; socket failures propagate as I/O errors.
const std = @import("std");

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
const cli_query = @import("../cli/query.zig");
const config_parser = @import("../config/parser.zig");
const dns_header = @import("../dns/header.zig");
const metrics = @import("../metrics.zig");
const dns_message = @import("../dns/message.zig");
const dns_padding = @import("../dns/padding.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_types = @import("../dns/types.zig");
const dns_writer = @import("../dns/writer.zig");
const resolver_mod = @import("../resolver.zig");
const zone_index = @import("../zone/index.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");
const listener = @import("../platform/listener.zig");
const tls_policy = @import("tls.zig");
const tls_server = @import("tls_server.zig");
const ossl = @import("openssl_tls.zig");
const odoh = @import("../dns/odoh.zig");

pub const doh_path = "/dns-query";
pub const dns_message_media_type = "application/dns-message";
pub const odoh_media_type = "application/oblivious-dns-message";
/// The ALPN token the DoH port speaks. RFC 7301 section 6 registers
/// "http/1.1" as the HTTP/1.1 protocol ID; RFC 8484 section 5.2 makes
/// HTTP/2 the minimum RECOMMENDED version, which this build does not speak.
pub const DOH_ALPN = tls_policy.doh_alpn_http11;
pub const DOH_PORT = tls_policy.doh_port;
pub const MAX_CONNECTION_WORKERS = listener.TCP_MAX_CONNECTION_WORKERS;
pub const MAX_BODY_LEN: usize = 65535;
pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_EXCHANGES_PER_CONNECTION: usize = 16;
/// The octets a request line or a header line ends with: the CRLF the
/// reader strips before it hands the line over.
const line_terminator_len: usize = 2;
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
    /// The request head ends in the middle of a line.
    TruncatedRequest,
    /// The request carries a transfer coding. This channel decodes no
    /// chunked body, so such a request is refused.
    TransferEncodingUnsupported,
    /// The request carries two content lengths that differ, which makes
    /// the body length ambiguous.
    ConflictingContentLength,
    /// RFC 9112 section 3.2: an HTTP/1.1 request must carry a Host header.
    MissingHost,
    /// RFC 9110 section 10.1.1: a 100-continue expectation this channel does
    /// not honor is answered with a final status.
    ExpectationFailed,
};

pub const Status = enum(u16) {
    ok = 200,
    bad_request = 400,
    unauthorized = 401,
    not_found = 404,
    method_not_allowed = 405,
    expectation_failed = 417,
    unsupported_media_type = 415,
    request_header_fields_too_large = 431,
    payload_too_large = 413,
    internal_error = 500,

    fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .expectation_failed => "Expectation Failed",
            .unsupported_media_type => "Unsupported Media Type",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .payload_too_large => "Payload Too Large",
            .internal_error => "Internal Server Error",
        };
    }
};

pub fn statusForError(err: anyerror) Status {
    return switch (err) {
        Error.UnsupportedMethod => .method_not_allowed,
        Error.BadTarget => .not_found,
        Error.HeadersTooLarge => .request_header_fields_too_large,
        Error.BodyTooLarge => .payload_too_large,
        Error.BadContentType => .unsupported_media_type,
        Error.TruncatedRequest => .bad_request,
        Error.TransferEncodingUnsupported => .bad_request,
        Error.ConflictingContentLength => .bad_request,
        Error.MissingHost => .bad_request,
        Error.ExpectationFailed => .expectation_failed,
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
    host: bool = false,
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
        error.EndOfStream => return Error.TruncatedRequest,
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
    // The budget counts the octets the head really carries: every line
    // ends with the CRLF the reader strips before it hands the line over.
    var header_bytes: usize = request_line.len + line_terminator_len;
    while (true) {
        const line = try readLine(reader, arena);
        header_bytes += line.len + line_terminator_len;
        if (header_bytes > MAX_HEADER_BYTES) return Error.HeadersTooLarge;
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.BadRequestLine;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            head.content_type = arena.dupe(u8, value) catch return Error.BadRequestLine;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const length = std.fmt.parseInt(usize, value, 10) catch return Error.BadRequestLine;
            // RFC 9112 section 6.3: two content lengths that differ leave
            // the body length ambiguous, so the request is refused.
            if (head.content_length) |first| {
                if (first != length) return Error.ConflictingContentLength;
            } else {
                head.content_length = length;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            // RFC 9112 section 6.1: this channel decodes no chunked body,
            // and a message that carries a transfer coding is refused
            // rather than read as if it carried no body at all.
            return Error.TransferEncodingUnsupported;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.eqlIgnoreCase(value, "close")) head.close = true;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            head.host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            // RFC 9110 section 10.1.1: this channel never sends 100 Continue,
            // so the expectation is refused with a final status instead of
            // leaving the client waiting.
            return Error.ExpectationFailed;
        }
    }
    // RFC 9112 section 3.2: an HTTP/1.1 request without Host is malformed;
    // HTTP/1.0 does not require the header.
    if (!head.host and !std.mem.eql(u8, version, "HTTP/1.0")) return Error.MissingHost;

    var body: []u8 = &.{};
    const declared = head.content_length orelse 0;
    if (declared > MAX_BODY_LEN) return Error.BodyTooLarge;
    if (method_is_post) {
        // RFC 8484 section 4.2: the body of a POST carries the DNS message.
        if (head.content_length == null or declared == 0) return Error.BadRequestLine;
        body = arena.alloc(u8, declared) catch return Error.BadRequestLine;
        reader.readSliceAll(body) catch return Error.TruncatedBody;
    } else if (declared > 0) {
        // A body on a GET carries no query, but it has to leave the stream,
        // so the next request starts at a request line again.
        const discarded = arena.alloc(u8, declared) catch return Error.BadRequestLine;
        reader.readSliceAll(discarded) catch return Error.TruncatedBody;
    }
    return .{ .head = head, .body = body };
}

/// The path and the query of a request target. RFC 9112 section 3.2: the
/// target of a request is in origin-form, but a client may send the
/// absolute form, which carries the same path and query behind the
/// authority.
const Target = struct {
    path: []const u8,
    query: []const u8,
};

fn splitTarget(target: []const u8) Target {
    var rest = target;
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        rest = rest[scheme_end + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
            rest = rest[slash..];
        } else {
            return .{ .path = rest, .query = &.{} };
        }
    }
    const query_start = std.mem.indexOfScalar(u8, rest, '?') orelse return .{ .path = rest, .query = &.{} };
    return .{ .path = rest[0..query_start], .query = rest[query_start + 1 ..] };
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
    return dnsQueryFromParts(arena, head.method_is_get, head.method_is_post, head.target, head.content_type, body);
}

/// The shared RFC 8484 section 4.1/4.2 mapping both DoH channels use: the
/// path and query come from `target`, the media type and body from `body`.
/// The HTTP/1.1 channel in this module and the HTTP/3 channel in
/// `doh3.zig` both route through here, so the parsing rules cannot drift
/// apart. Only the DNS media type answers here; ODoH requests carry the
/// oblivious media type and route around this mapping in serveDohExchange.
pub fn dnsQueryFromParts(arena: std.mem.Allocator, method_is_get: bool, method_is_post: bool, target: []const u8, content_type: ?[]const u8, body: []u8) Error![]u8 {
    _ = method_is_post;
    const parsed = splitTarget(target);
    if (!std.mem.eql(u8, parsed.path, doh_path)) return Error.BadTarget;
    if (method_is_get) {
        if (target.len > MAX_HEADER_BYTES) return Error.BadDnsMessage;
        return decodeQueryParam(arena, try dnsParam(parsed.query));
    }
    const media_type = content_type orelse return Error.BadContentType;
    if (!std.mem.eql(u8, media_type, dns_message_media_type)) return Error.BadContentType;
    if (body.len == 0 or body.len > MAX_BODY_LEN) return Error.BadDnsMessage;
    return body;
}

/// The freshness lifetime the response carries. RFC 8484 section 5.1: it is
/// the smallest TTL in the answer section, and with no answer records it is
/// the SOA's MINIMUM field.
pub fn minTtl(message: *const dns_message.Message) u32 {
    var floor: ?u32 = null;
    for (message.answers.slice()) |record| {
        floor = if (floor) |current| @min(current, record.ttl) else record.ttl;
    }
    if (floor == null) {
        for (message.authorities.slice()) |record| {
            switch (record.rdata) {
                .SOA => |soa| floor = soa.minimum,
                else => {},
            }
        }
    }
    if (floor == null) {
        for (message.authorities.slice()) |record| {
            floor = if (floor) |current| @min(current, record.ttl) else record.ttl;
        }
    }
    return floor orelse 0;
}

fn writeError(writer: *std.Io.Writer, status: Status) !void {
    // RFC 9110 section 15.5.6: a 405 lists the methods the resource allows.
    if (status == .method_not_allowed) {
        try writer.print("HTTP/1.1 {d} {s}\r\nallow: GET, POST\r\ncontent-length: 0\r\nconnection: close\r\n\r\n", .{
            @backingInt(status),
            status.reason(),
        });
        return;
    }
    try writer.print("HTTP/1.1 {d} {s}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n", .{
        @backingInt(status),
        status.reason(),
    });
}

fn writeDnsResponse(writer: *std.Io.Writer, body: []const u8, max_age: u32, close: bool) !void {
    try writer.print("HTTP/1.1 200 OK\r\ncontent-type: {s}\r\ncontent-length: {d}\r\ncache-control: max-age={d}\r\nconnection: {s}\r\n\r\n", .{ dns_message_media_type, body.len, max_age, if (close) "close" else "keep-alive" });
    try writer.writeAll(body);
}

fn writeOdohResponse(writer: *std.Io.Writer, body: []const u8, close: bool) !void {
    // RFC 9230 section 4.1: an Oblivious DoH response carries no cacheable
    // plaintext, so it says no-store instead of the max-age plain DoH uses.
    try writer.print("HTTP/1.1 200 OK\r\ncontent-type: {s}\r\ncontent-length: {d}\r\ncache-control: no-store\r\nconnection: {s}\r\n\r\n", .{
        odoh_media_type,
        body.len,
        if (close) "close" else "keep-alive",
    });
    try writer.writeAll(body);
}

/// Serves one HTTP/1.1 exchange. Returns true when the connection must close.
pub fn serveDohExchange(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    arena: std.mem.Allocator,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
    client: *const std.Io.net.IpAddress,
    last_exchange: bool,
    odoh_target: ?*const odoh.Target,
) !bool {
    const parsed = readRequest(reader, arena) catch |err| {
        if (err == error.EndOfStream) return error.EndOfStream;
        try writeError(writer, statusForError(err));
        try writer.flush();
        return true;
    };
    if (parsed.head.method_is_post and parsed.head.content_type != null and std.mem.eql(u8, parsed.head.content_type.?, odoh_media_type)) {
        _ = odoh_target orelse {
            try writeError(writer, .not_found);
            try writer.flush();
            return true;
        };
        return serveOdohExchange(writer, arena, runtime, counters, client, parsed.head.close or last_exchange, parsed.body, odoh_target.?);
    }
    const query = dnsQueryFromRequest(arena, parsed.head, parsed.body) catch |err| {
        try writeError(writer, statusForError(err));
        try writer.flush();
        return true;
    };

    // Everything below lives in the per-exchange arena: one heap allocation
    // per exchange, freed together when the exchange ends. No 64KB stack
    // buffers and no page_allocator arenas escape this exchange.
    const request_message = dns_message.Message.parseQuery(arena, query) catch {
        try writeError(writer, .bad_request);
        try writer.flush();
        return true;
    };

    const response_buffer = arena.alloc(u8, MAX_BODY_LEN) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    const response_bytes = blk: {
        if (counters) |value| metrics.bump(&value.doh_queries_total);
        // One runtime entry point serves every DoH query, and it takes the
        // peer address: the recursion policy, the cookie check, and the
        // locally served zones apply as they do on the cleartext TCP port.
        break :blk runtime.answerFromTcp(query, response_buffer, client, counters) catch |err| return serveRuntimeError(writer, err);
    };

    // RFC 7830 section 4: the responder pads the answer when the query
    // carried the Padding option. RFC 7830 section 6 keeps the option for
    // encrypted transports, so this path and no other one calls the helper.
    const body = (dns_padding.padResponse(arena, &request_message, response_bytes) catch |err|
        return serveRuntimeError(writer, err)) orelse response_bytes;

    const response_message = dns_message.Message.parse(arena, body) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    // The last exchange of a connection says so, so the client does not
    // reuse a connection the server closes right after it.
    const close = parsed.head.close or last_exchange;
    try writeDnsResponse(writer, body, minTtl(&response_message), close);
    try writer.flush();
    return close;
}

fn serveOdohExchange(writer: *std.Io.Writer, arena: std.mem.Allocator, runtime: *Runtime, counters: ?*metrics.Counters, client: *const std.Io.net.IpAddress, close: bool, body: []u8, target: *const odoh.Target) !bool {
    const opened = odoh.openQuery(arena, target, body) catch |err| {
        try writeError(writer, if (err == error.UnknownKeyId) .unauthorized else .bad_request);
        try writer.flush();
        return true;
    };
    const request_message = dns_message.Message.parseQuery(arena, opened.dns_query) catch {
        try writeError(writer, .bad_request);
        try writer.flush();
        return true;
    };
    const response_buffer = arena.alloc(u8, MAX_BODY_LEN) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    if (counters) |value| metrics.bump(&value.doh_queries_total);
    const response_bytes = runtime.answerFromTcp(opened.dns_query, response_buffer, client, counters) catch |err| return serveRuntimeError(writer, err);
    const padded = (dns_padding.padResponse(arena, &request_message, response_bytes) catch |err| return serveRuntimeError(writer, err)) orelse response_bytes;
    const io = std.Io.Threaded.global_single_threaded.io();
    const sealed = odoh.sealResponse(arena, io, opened.exporter_secret, opened.q_plain, padded) catch {
        try writeError(writer, .internal_error);
        try writer.flush();
        return true;
    };
    try writeOdohResponse(writer, sealed, close);
    try writer.flush();
    return close;
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

pub fn serveDohStreamOnce(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime) !void {
    return serveDohStream(stream, io, runtime, null, null);
}

/// The end of one DoH connection: the operator may bound the lifetime of a
/// connection (RFC 9210 section 4.2), and that deadline covers the whole
/// connection. Null means the connection lives as long as the transport
/// allows.
fn connectionDeadline(io: std.Io) ?std.Io.Clock.Timestamp {
    const seconds = listener.tcpLimits().max_connection_duration orelse return null;
    return tcp_deadline.deadline(io, .{ .seconds = seconds });
}

/// One DoH connection: the channel the exchanges travel over and the
/// deadlines that bound them. On a TLS channel the TLS connection carries
/// the absolute deadline itself; otherwise the deadline goes to the raw
/// descriptor under the exchange.
const DohChannel = struct {
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    deadlines: ?tcp_deadline.FrameDeadlines = null,
    tls: ?*ossl.Connection = null,
    timeout: tcp_deadline.Timeout,
    connection_deadline: ?std.Io.Clock.Timestamp,
    /// The peer address of the accepted connection: the recursion policy and
    /// the cookie check need the client the query came from.
    client: *const std.Io.net.IpAddress,

    /// The deadline of the exchange that starts now: the per-exchange
    /// timeout, shortened to what is left of the connection's lifetime.
    /// Null means the connection is over.
    fn frameDeadline(self: *const DohChannel) ?std.Io.Clock.Timestamp {
        const frame_timeout = listener.frameTimeout(self.io, self.connection_deadline, self.timeout) orelse return null;
        return tcp_deadline.deadline(self.io, frame_timeout);
    }

    /// Bounds the exchange that starts now. On a TLS channel the TLS
    /// connection carries the absolute deadline itself. False means the
    /// connection has outlived its duration and ends here.
    fn applyFrameDeadline(self: *const DohChannel) bool {
        const frame_deadline = self.frameDeadline() orelse return false;
        if (self.tls) |conn| {
            conn.deadline = frame_deadline;
        } else if (self.deadlines) |deadlines| {
            deadlines.apply(frame_deadline);
        }
        return true;
    }
};

fn serveDohStream(stream: std.Io.net.Stream, io: std.Io, runtime: *Runtime, counters: ?*metrics.Counters, odoh_target: ?*const odoh.Target) !void {
    // Same tick as the plaintext and DoT paths: one loop owns it across
    // all loops sharing this runtime, and a DoH-only server runs it here.
    _ = runtime.tryMaintenanceTick(io);
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;

    var read_buffer: [MAX_HEADER_BYTES]u8 = undefined;
    var write_buffer: [DOH_WRITE_BUFFER_SIZE]u8 = undefined;
    var reader = tcp_deadline.DeadlineReader.init(stream.socket.handle, io, &read_buffer, DOH_IO_TIMEOUT);
    var writer = tcp_deadline.DeadlineWriter.init(stream.socket.handle, io, &write_buffer, DOH_IO_TIMEOUT);
    defer writer.interface.flush() catch {};
    var channel = DohChannel{
        .io = io,
        .reader = &reader.interface,
        .writer = &writer.interface,
        .deadlines = .{ .reader = &reader, .writer = &writer },
        .timeout = DOH_IO_TIMEOUT,
        .connection_deadline = connectionDeadline(io),
        .client = &stream.socket.address,
    };
    try serveDohExchanges(&channel, runtime, counters, odoh_target);
}

/// The exchange loop both channels share: HTTP/1.1 keep-alive over one
/// connection, bounded by MAX_EXCHANGES_PER_CONNECTION.
fn serveDohExchanges(channel: *const DohChannel, runtime: *Runtime, counters: ?*metrics.Counters, odoh_target: ?*const odoh.Target) !void {
    var exchanges: usize = 0;
    while (exchanges < MAX_EXCHANGES_PER_CONNECTION) : (exchanges += 1) {
        // One deadline for the whole exchange: a peer that stalls in the
        // middle of an exchange loses the exchange, not the server.
        if (!channel.applyFrameDeadline()) return;
        // Block-scoped so the arena frees at the end of each exchange, not
        // at connection close: memory stays bounded across keep-alive.
        const must_close = blk: {
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            break :blk serveDohExchange(
                channel.reader,
                channel.writer,
                arena.allocator(),
                runtime,
                counters,
                channel.client,
                exchanges + 1 == MAX_EXCHANGES_PER_CONNECTION,
                odoh_target,
            ) catch |err| {
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

/// Serves one DoH connection: the TLS handshake with the "http/1.1" ALPN
/// token, then HTTP/1.1 exchanges over the encrypted channel.
pub fn serveDohTlsStream(
    stream: std.Io.net.Stream,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    counters: ?*metrics.Counters,
    odoh_target: ?*const odoh.Target,
) !void {
    if (comptime !listener.TCP_DEADLINES_SUPPORTED) return listener.Error.UnsupportedPlatform;

    // RFC 9210 section 4.2: the operator may bound the lifetime of one
    // connection, and that deadline covers the whole connection.
    const connection_deadline = connectionDeadline(io);

    // The handshake is part of the connection, so it shares its deadline:
    // a peer that dribbles into the handshake cannot hold the worker. It
    // runs directly on the socket fd: the TLS layer polls the fd and
    // recomputes against this absolute deadline each iteration.
    const handshake_timeout = listener.frameTimeout(io, connection_deadline, DOH_IO_TIMEOUT) orelse return;
    const handshake_deadline = tcp_deadline.deadline(io, handshake_timeout);
    var connection = try server.handshake(stream.socket.handle, io, handshake_deadline);
    defer connection.close() catch {};

    var read_buffer: [MAX_HEADER_BYTES]u8 = undefined;
    var write_buffer: [DOH_WRITE_BUFFER_SIZE]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);
    defer connection_writer.interface.flush() catch {};
    var channel = DohChannel{
        .io = io,
        .reader = &connection_reader.interface,
        .writer = &connection_writer.interface,
        .tls = &connection,
        .timeout = DOH_IO_TIMEOUT,
        .connection_deadline = connection_deadline,
        .client = &stream.socket.address,
    };
    try serveDohExchanges(&channel, runtime, counters, odoh_target);
}

/// Binds the DoH port and serves DoH connections. Every accepted connection
/// gets a TLS handshake with the "http/1.1" ALPN token before any HTTP byte
/// is written, so the port never answers in cleartext. Each connection is
/// served on its own task, so a peer that stalls in the handshake does not
/// hold up the others.
pub fn serveDohLoopOnAddress(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    server: *tls_server.Server,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
    odoh_target: ?*const odoh.Target,
) !void {
    var bind_address = address.*;
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    return serveDohLoop(&listener_socket, io, runtime, server, max_requests, counters, odoh_target);
}

/// Serves the DoH port on an already-bound listener.
pub fn serveDohLoop(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    runtime: *Runtime,
    server: *tls_server.Server,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
    odoh_target: ?*const odoh.Target,
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
        group.concurrent(io, serveDohTlsWorker, .{ stream, io, server, runtime, &sources, counters, odoh_target }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                sources.release(&stream.socket.address);
                stream.close(io);
            },
        };
    }
}

/// Serves one accepted DoH connection.
fn serveDohTlsWorker(stream: std.Io.net.Stream, io: std.Io, server: *tls_server.Server, runtime: *Runtime, sources: *listener.SourceCounter, counters: ?*metrics.Counters, odoh_target: ?*const odoh.Target) void {
    defer stream.close(io);
    defer sources.release(&stream.socket.address);
    serveDohTlsStream(stream, io, server, runtime, counters, odoh_target) catch {};
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

/// Grows the send buffer of a socket. The buffer of a socket pair holds
/// less than an over-long head, so a test that writes one would block on a
/// peer that reads nothing.
fn growSendBuffer(fd: std.posix.fd_t, size: u32) !void {
    const value = size;
    const result = std.posix.system.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&value).ptr, @sizeOf(u32));
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "dns.home.arpa.", .A, false);
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

test "DoH freshness lifetime for a negative answer follows the SOA minimum" {
    // RFC 8484 section 5.1: with no answer records the freshness lifetime
    // must not be greater than the SOA's MINIMUM field, which here is 60 and
    // not the record TTL of 3600.
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(nodata_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "dns.home.arpa.", .TXT, false);
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
    var max_age: ?u32 = null;
    while (true) {
        const trimmed = try takeTestLine(&client_reader.interface);
        if (trimmed.len == 0) break;
        if (trimmed.len > 13 and std.ascii.eqlIgnoreCase(trimmed[0..13], "cache-control")) {
            const value = std.mem.trim(u8, trimmed[13..], " ");
            const after = std.mem.indexOf(u8, value, "max-age=") orelse continue;
            max_age = try std.fmt.parseInt(u32, value[after + 8 ..], 10);
        }
    }
    try std.testing.expectEqual(@as(?u32, 60), max_age);
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xdcba, "dns.home.arpa.", .A, false);
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

/// A query for the test zone whose OPT record advertises EDNS(0) and, when
/// `padding` is set, carries a Padding option: the RFC 7830 section 3
/// request that asks for a padded answer.
fn buildEdnsQuery(buffer: []u8, id: u16, padding: bool) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try writer.writeU16(id);
    try writer.writeU16(0x0100);
    try writer.writeU16(1);
    try writer.writeU16(0);
    try writer.writeU16(0);
    try writer.writeU16(1);
    try writer.writeBytes(&.{ 0x03, 'd', 'n', 's', 0x04, 'h', 'o', 'm', 'e', 0x04, 'a', 'r', 'p', 'a', 0x00 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    // The OPT pseudo-record: the root owner, the type, the requestor's
    // payload size, a zero TTL, and the option framing.
    try writer.writeU8(0);
    try writer.writeU16(dns_types.RecordType.OPT.code());
    try writer.writeU16(dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
    try writer.writeU32(0);
    if (!padding) {
        try writer.writeU16(0);
        return writer.written();
    }
    try writer.writeU16(8);
    try writer.writeU16(dns_rdata.EDNS_PADDING_OPTION_CODE);
    try writer.writeU16(4);
    try writer.writeBytes(&.{ 0, 0, 0, 0 });
    return writer.written();
}

/// Serves one DoH exchange with `query` and returns the DNS message the
/// server answered with. The counters are the ones the channel counts with,
/// or null for a channel that counts nothing.
fn dohAnswer(arena: std.mem.Allocator, runtime: *Runtime, query: []const u8, counters: ?*metrics.Counters) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var request_buffer: [2048]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{query.len});
    try request_stream.writeAll(query);

    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request_stream.buffered());
    try client_writer.interface.flush();

    try serveDohStream(server_stream, io, runtime, counters, null);

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
    const body = try arena.alloc(u8, content_length);
    try client_reader.interface.readSliceAll(body);
    return body;
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

test "RFC 7830: the DoH answer is padded when the query asked for it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [128]u8 = undefined;
    const query = try buildEdnsQuery(&query_buffer, 0xabcd, true);

    // The answer the server builds on its own, without the padding option.
    var answer_buffer: [4096]u8 = undefined;
    const answer = try runtime.answer(query, &answer_buffer);

    const body = try dohAnswer(arena.allocator(), &runtime, query, null);
    try std.testing.expect(body.len > answer.len);

    const parsed = try dns_message.Message.parse(arena.allocator(), body);
    try std.testing.expectEqual(@as(u16, 0xabcd), parsed.header.id);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    const options = messageOptions(&parsed).?;
    const padding = dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE);
    try std.testing.expect(padding != null);
    for (padding.?) |octet| try std.testing.expectEqual(@as(u8, 0), octet);
}

test "RFC 7830: the DoH answer carries no padding when the query did not ask for it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [128]u8 = undefined;
    const query = try buildEdnsQuery(&query_buffer, 0xdcba, false);

    const body = try dohAnswer(arena.allocator(), &runtime, query, null);
    const parsed = try dns_message.Message.parse(arena.allocator(), body);
    try std.testing.expectEqual(@as(u16, 0xdcba), parsed.header.id);
    // The query indicated EDNS(0) support, so the answer carries an OPT
    // record, but the query asked for no padding, so the option is absent.
    const options = messageOptions(&parsed).?;
    try std.testing.expectEqual(@as(usize, 0), options.len);
    try std.testing.expect(dns_rdata.findOption(options, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);
}

test "RFC 7830: the cleartext UDP and TCP paths never pad, even when the query asks for it" {
    // RFC 7830 section 6: an implementation MUST NOT use the option when
    // the DNS transport is not encrypted, so the cleartext paths keep
    // answering without it.
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [128]u8 = undefined;
    const query = try buildEdnsQuery(&query_buffer, 0xef01, true);

    // The cleartext UDP path.
    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server_socket = try std.Io.net.IpAddress.bind(&server_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var client_socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);

    try client_socket.send(io, &server_socket.address, query);
    try listener.serveUdpOnce(&server_socket, io, &runtime);

    var datagram_buffer: [4096]u8 = undefined;
    const datagram = try client_socket.receiveTimeout(io, &datagram_buffer, .{ .duration = .{
        .raw = .fromMilliseconds(500),
        .clock = .awake,
    } });
    const udp_answer = try dns_message.Message.parse(arena.allocator(), datagram.data);
    try std.testing.expectEqual(@as(u16, 0xef01), udp_answer.header.id);
    const udp_options = messageOptions(&udp_answer).?;
    try std.testing.expect(dns_rdata.findOption(udp_options, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);

    // The cleartext TCP path. It runs over a real socket pair of sockets,
    // the way the listener's own tests do, because the frame reader works on
    // the raw descriptor.
    var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);
    var client_stream = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    defer client_stream.close(io);
    const server_stream = try server.accept(io);
    defer server_stream.close(io);

    try cli_query.sendTcpQuery(client_stream, io, query);
    try client_stream.shutdown(io, .send);

    try listener.serveTcpStreamOnce(server_stream, io, &runtime);

    var client_read_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_read_buffer);
    const length_bytes = try client_reader.interface.takeArray(2);
    const tcp_answer_bytes = try client_reader.interface.take(std.mem.readInt(u16, length_bytes, .big));
    const tcp_answer = try dns_message.Message.parse(arena.allocator(), tcp_answer_bytes);
    try std.testing.expectEqual(@as(u16, 0xef01), tcp_answer.header.id);
    const tcp_options = messageOptions(&tcp_answer).?;
    try std.testing.expect(dns_rdata.findOption(tcp_options, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);
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
        const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, id, "dns.home.arpa.", .A, false);
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
        var keep_alive = false;
        while (true) {
            const trimmed = try takeTestLine(&client_reader.interface);
            if (trimmed.len == 0) break;
            if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
                content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
            }
            if (std.ascii.eqlIgnoreCase(trimmed, "connection: keep-alive")) keep_alive = true;
        }
        // The server holds the connection open for the next exchange: a
        // client that speaks TLS with the http/1.1 ALPN token gets
        // connection: keep-alive instead of a reset. Python http.client
        // sends no ALPN by default, so its handshake dies at the TLS
        // layer (no_application_protocol) before HTTP framing starts;
        // that is a client limitation the curl readiness probe avoids,
        // not a server framing bug.
        try std.testing.expect(keep_alive);
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
    try std.testing.expectEqualStrings("Method Not Allowed", Status.method_not_allowed.reason());
    try std.testing.expectEqualStrings("Unsupported Media Type", Status.unsupported_media_type.reason());
    try std.testing.expectEqualStrings("Request Header Fields Too Large", Status.request_header_fields_too_large.reason());
    try std.testing.expectEqualStrings("Payload Too Large", Status.payload_too_large.reason());
}

test "DoH refuses a request that carries a transfer coding and a content length" {
    // RFC 9112 section 6.1: a message with a transfer coding this channel
    // cannot decode is refused with 400, and the connection ends there, so
    // the chunked body is never read as the next request.
    const io = std.Io.Threaded.global_single_threaded.io();
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

    var request_buffer: [2048]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n", .{});
    try request_stream.writeAll("0\r\n\r\n");

    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request_stream.buffered());
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);
    server_stream.close(io);
    server_stream_closed = true;

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const status_line = try takeTestLine(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 400"));
    var closes = false;
    while (true) {
        const line = try takeTestLine(&client_reader.interface);
        if (line.len == 0) break;
        if (std.ascii.eqlIgnoreCase(line, "connection: close")) closes = true;
    }
    try std.testing.expect(closes);
    // The connection ends with the refusal: the chunked body that follows
    // is never answered as a request of its own.
    try std.testing.expectError(error.EndOfStream, takeTestLine(&client_reader.interface));
}

test "RFC 9112 3.2 and RFC 9110: no Host, a wrong method, and an Expect head are refused" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const cases = [_]struct { request: []const u8, status: []const u8, allow: bool }{
        // RFC 9112 section 3.2: HTTP/1.1 requires Host.
        .{ .request = "GET /dns-query?dns=AA HTTP/1.1\r\n\r\n", .status = "HTTP/1.1 400", .allow = false },
        // RFC 9110 section 15.5.6: a 405 lists the allowed methods.
        .{ .request = "PUT /dns-query HTTP/1.1\r\nHost: localhost\r\n\r\n", .status = "HTTP/1.1 405", .allow = true },
        // RFC 9110 section 10.1.1: the expectation gets a final status.
        .{ .request = "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n", .status = "HTTP/1.1 417", .allow = false },
    };
    for (cases) |case| {
        const streams = try streamPair();
        var client_stream = streams[0];
        defer client_stream.close(io);
        var server_stream = streams[1];
        var server_stream_closed = false;
        defer {
            if (!server_stream_closed) server_stream.close(io);
        }

        var client_write_buffer: [2048]u8 = undefined;
        var client_writer = client_stream.writer(io, &client_write_buffer);
        try client_writer.interface.writeAll(case.request);
        try client_writer.interface.flush();

        try serveDohStreamOnce(server_stream, io, &runtime);
        server_stream.close(io);
        server_stream_closed = true;

        var response_buffer: [4096]u8 = undefined;
        var client_reader = client_stream.reader(io, &response_buffer);
        const status_line = try takeTestLine(&client_reader.interface);
        try std.testing.expect(std.mem.startsWith(u8, status_line, case.status));
        var saw_allow = false;
        while (true) {
            const line = try takeTestLine(&client_reader.interface);
            if (line.len == 0) break;
            if (std.ascii.eqlIgnoreCase(line, "allow: GET, POST")) saw_allow = true;
        }
        try std.testing.expectEqual(case.allow, saw_allow);
    }
}

test "DoH refuses a request that declares two different content lengths" {
    // RFC 9112 section 6.3: two content lengths that differ leave the body
    // length ambiguous, so the request is refused.
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var request_buffer: [2048]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\n", .{});
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const status_line = try takeTestLine(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 400"));
}

test "DoH answers an over-long header block with 431" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    // A head that runs past the header budget of the channel. The server
    // stops reading it once the budget is over, so the send buffer grows
    // first: the write must not block on a peer that reads nothing.
    try growSendBuffer(client_stream.socket.handle, 64 * 1024);

    var request_buffer: [16384]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.writeAll("GET /dns-query HTTP/1.1\r\n");
    var filler: [100]u8 = @splat('a');
    for (0..80) |_| {
        try request_stream.writeAll("X-Fill: ");
        try request_stream.writeAll(&filler);
        try request_stream.writeAll("\r\n");
    }
    try request_stream.writeAll("\r\n");

    var client_write_buffer: [16384]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request_stream.buffered());
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const response = try readTestResponse(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, response.status, "HTTP/1.1 431"));
}

test "DoH answers a body above the body budget with 413" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var request_buffer: [2048]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {d}\r\n\r\n", .{MAX_BODY_LEN + 1});
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const response = try readTestResponse(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, response.status, "HTTP/1.1 413"));
}

test "DoH answers a POST with the wrong media type with 415" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    const request = "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\njunk";
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    const response = try readTestResponse(&client_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, response.status, "HTTP/1.1 415"));
}

test "DoH reads a body a GET declares, so the next request starts at a request line" {
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
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x9a9a, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);

    var request_buffer: [2048]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n", .{encoded_query});
    try request_stream.writeAll("junk");
    try request_stream.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{encoded_query});

    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request_stream.buffered());
    try client_writer.interface.flush();

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    // Both requests are answered: the body of the first one left the
    // stream, so the second one starts at a request line.
    for (0..2) |_| {
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
        try std.testing.expectEqual(@as(u16, 0x9a9a), response.header.id);
    }
}

test "the last exchange of a DoH connection says the connection closes" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var client_write_buffer: [4096]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    for (0..MAX_EXCHANGES_PER_CONNECTION) |_| {
        var query_buffer: [512]u8 = undefined;
        const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x1111, "dns.home.arpa.", .A, false);
        var encoded: [1024]u8 = undefined;
        const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);
        try client_writer.interface.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    }
    try client_writer.interface.flush();
    try client_stream.shutdown(io, .send);

    try serveDohStreamOnce(server_stream, io, &runtime);

    var response_buffer: [4096]u8 = undefined;
    var client_reader = client_stream.reader(io, &response_buffer);
    for (0..MAX_EXCHANGES_PER_CONNECTION) |index| {
        const status_line = try takeTestLine(&client_reader.interface);
        try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
        var connection_header: []const u8 = "";
        var content_length: usize = 0;
        while (true) {
            const trimmed = try takeTestLine(&client_reader.interface);
            if (trimmed.len == 0) break;
            if (trimmed.len > 10 and std.ascii.eqlIgnoreCase(trimmed[0..10], "connection")) {
                connection_header = trimmed;
            }
            if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
                content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
            }
        }
        try std.testing.expect(content_length > 0);
        _ = try client_reader.interface.take(content_length);
        // The last permitted exchange says the connection closes, so the
        // client does not reuse a connection the server closes right after.
        if (index + 1 == MAX_EXCHANGES_PER_CONNECTION) {
            try std.testing.expect(std.mem.indexOf(u8, connection_header, "close") != null);
        } else {
            try std.testing.expect(std.mem.indexOf(u8, connection_header, "keep-alive") != null);
        }
    }
}

test "a DoH query moves the counters the DoH path counts" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    const streams = try streamPair();
    var client_stream = streams[0];
    defer client_stream.close(io);
    const server_stream = streams[1];
    defer server_stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);

    var request_buffer: [2048]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{encoded_query});
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();

    var counters = metrics.Counters{};
    try serveDohStream(server_stream, io, &runtime, &counters, null);

    // The DoH path counts the query, the answer and the transport, the way
    // the cleartext TCP path counts them.
    try std.testing.expectEqual(@as(u64, 1), counters.queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.responses_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), counters.bad_queries_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), counters.doh_queries_total.load(.monotonic));
}

test "a DoH query for a locally served name is answered from the local zone table" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "localhost.", .A, false);

    // The counters are wired, the way the running server wires them.
    var counters = metrics.Counters{};
    const body = try dohAnswer(arena.allocator(), &runtime, query, &counters);
    const parsed = try dns_message.Message.parse(arena.allocator(), body);
    // RFC 6761 section 6.3: the localhost name resolves to the loopback
    // address, and the answer comes from the locally served zones, so the
    // DoH port serves it the way the cleartext TCP port does.
    try std.testing.expectEqual(@as(u16, 1), parsed.header.answer_count);
    try std.testing.expect(parsed.answers.items[0].rrtype.eql(.A));
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &parsed.answers.items[0].rdata.A);
}

test "a DoH query from a client the recursion ACL refuses is refused" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The operator's recursion ACL serves one network; the DoH client below
    // is outside it, so the refusal is the policy's and not the server's.
    var policy = resolver_mod.Policy{};
    policy.recursion_allow[0] = try config_parser.Cidr.parse("192.0.2.0/24");
    policy.recursion_allow_len = 1;
    var zones = std.ArrayList(zone_index.Zone).empty;
    var runtime = try Runtime.fromZonesWithPolicy(std.testing.allocator, &zones, .{}, io, policy);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    // The query carries an OPT pseudo-RR, so RFC 8914 section 2 allows the
    // EDE option in the answer.
    const query = try @import("../cli/query.zig").buildQueryPacketWithEdns(&query_buffer, 0xabcd, "outside.example.", .A, .{ .dnssec_ok = true });

    var counters = metrics.Counters{};
    const body = try dohAnswer(arena.allocator(), &runtime, query, &counters);
    const parsed = try dns_message.Message.parse(arena.allocator(), body);
    // The client address reaches the runtime, so the same source the policy
    // refuses over the cleartext TCP port is refused over DoH too. RFC 8914
    // section 4.19: INFO-CODE 18 is "Prohibited", and the EXTRA-TEXT says
    // the operator's recursion policy refused the client.
    try std.testing.expectEqual(dns_header.Rcode.refused, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
    const opt = parsed.additionals.items[0];
    try std.testing.expect(opt.rrtype.eql(.OPT));
    const ede = dns_rdata.findOption(opt.rdata.OPT.bytes(), 15);
    try std.testing.expect(ede != null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x12 }, ede.?[0..2]);
    try std.testing.expectEqualStrings("prohibited by policy", ede.?[2..]);
}

test "the DoH answer is the same with and without the counters wired" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "localhost.", .A, false);

    var counters = metrics.Counters{};
    const counted = try dohAnswer(arena.allocator(), &runtime, query, &counters);
    const uncounted = try dohAnswer(arena.allocator(), &runtime, query, null);
    // One answer path serves both: the counters change the count, not the
    // message the client receives.
    try std.testing.expectEqualSlices(u8, counted, uncounted);
    try std.testing.expectEqual(@as(u64, 1), counters.doh_queries_total.load(.monotonic));
}

/// The identity the DoH tests load: a throwaway self-signed certificate and
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

/// The server side of the DoH tests: one accepted connection, served.
fn serveOneConnection(
    listener_socket: *std.Io.net.Server,
    io: std.Io,
    server: *tls_server.Server,
    runtime: *Runtime,
    odoh_target: ?*const odoh.Target,
) void {
    const stream = listener_socket.accept(io) catch return;
    defer stream.close(io);
    serveDohTlsStream(stream, io, server, runtime, null, odoh_target) catch {};
}

/// Reads one HTTP/1.1 response head and body.
fn readTestResponse(reader: *std.Io.Reader) !struct { status: []u8, body: []u8 } {
    const status = try takeTestLine(reader);
    var content_length: usize = 0;
    while (true) {
        const line = try takeTestLine(reader);
        if (line.len == 0) break;
        if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
            content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, line[15..], " "), 10);
        }
    }
    return .{ .status = status, .body = try reader.take(content_length) };
}

test "DoH answers a GET and a POST over a real TLS 1.3 handshake with the http/1.1 ALPN token" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, DOH_ALPN, true);
    // The server speaks "http/1.1" and nothing else.
    try std.testing.expectEqualStrings(DOH_ALPN, connection.alpnProtocol().?);

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    // RFC 8484 section 4.1: the GET method carries the query in the "dns"
    // variable, encoded with base64url.
    var get_query_buffer: [512]u8 = undefined;
    const get_query = try @import("../cli/query.zig").buildQueryPacket(&get_query_buffer, 0x1111, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, get_query);
    try connection_writer.interface.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    try connection_writer.interface.flush();

    const get_response = try readTestResponse(&connection_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, get_response.status, "HTTP/1.1 200"));
    const get_message = try dns_message.Message.parse(allocator, get_response.body);
    try std.testing.expect(get_message.header.qr);
    try std.testing.expectEqual(@as(u16, 0x1111), get_message.header.id);
    try std.testing.expectEqual(@as(u16, 1), get_message.header.answer_count);

    // RFC 8484 section 4.1: the POST method carries the query in the body,
    // with the media type of section 6. One connection serves both.
    var post_query_buffer: [512]u8 = undefined;
    const post_query = try @import("../cli/query.zig").buildQueryPacket(&post_query_buffer, 0x2222, "dns.home.arpa.", .A, false);
    try connection_writer.interface.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {d}\r\n\r\n", .{post_query.len});
    try connection_writer.interface.writeAll(post_query);
    try connection_writer.interface.flush();

    const post_response = try readTestResponse(&connection_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, post_response.status, "HTTP/1.1 200"));
    const post_message = try dns_message.Message.parse(allocator, post_response.body);
    try std.testing.expect(post_message.header.qr);
    try std.testing.expectEqual(@as(u16, 0x2222), post_message.header.id);
    try std.testing.expectEqual(@as(u16, 1), post_message.header.answer_count);

    connection.close() catch {};
    thread.join();
}

test "the DoH listener answers a query over the bound port" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    // The listener serves one connection and then stops, so the test ends.
    const thread = try std.Thread.spawn(.{}, serveDohLoop, .{ &listener_socket, io, &runtime, &server, @as(?usize, 1), null, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, DOH_ALPN, true);
    try std.testing.expectEqualStrings(DOH_ALPN, connection.alpnProtocol().?);

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var connection_reader = connection.reader(&read_buffer);
    var connection_writer = connection.writer(&write_buffer);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x3333, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);
    try connection_writer.interface.print("GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    try connection_writer.interface.flush();

    const response = try readTestResponse(&connection_reader.interface);
    try std.testing.expect(std.mem.startsWith(u8, response.status, "HTTP/1.1 200"));
    const message = try dns_message.Message.parse(allocator, response.body);
    try std.testing.expectEqual(@as(u16, 0x3333), message.header.id);
    try std.testing.expectEqual(@as(u16, 1), message.header.answer_count);

    connection.close() catch {};
    thread.join();
}

test "a DoH connection ends when the configured connection duration is over" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };

    // The peer completes the handshake and then says nothing.
    const stalled = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stalled.close(io);
    var stalled_connection = try insecureTestClient(stalled.socket.handle, io, DOH_ALPN, true);
    defer stalled_connection.close() catch {};

    // The connection ends with the duration the operator configured, not
    // with the five-second deadline of the transport.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = stalled.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 3000));

    thread.join();
}

test "DoH refuses a client that offers another ALPN token" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "h2", true);
    defer connection.close() catch {};
    try std.testing.expect(connection.alpnProtocol() == null);
    // The server side refuses with AlpnMismatch; the refusal closes the
    // connection before any DNS byte is read.

    thread.join();
}

test "DoH refuses a client that offers no ALPN token" {
    // Python http.client sends no ALPN by default and curl sends
    // http/1.1, which is why the harness readiness probe uses curl:
    // the TLS handshake completes but negotiates no protocol, so the
    // server's AlpnMismatch refusal closes the connection before any
    // HTTP byte is read.
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var connection = try insecureTestClient(stream.socket.handle, io, "dot", true);
    defer connection.close() catch {};
    try std.testing.expect(connection.alpnProtocol() == null);

    thread.join();
}

test "the DoH port never answers a cleartext HTTP request" {
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
    try server.init(allocator, io, tmp.dir, "cert.pem", "key.pem", DOH_ALPN);
    defer server.deinit();

    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, io, .{ .reuse_address = true });
    defer listener_socket.deinit(io);
    const port = listener_socket.socket.address.getPort();

    const thread = try std.Thread.spawn(.{}, serveOneConnection, .{ &listener_socket, io, &server, &runtime, null });

    var address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var query_buffer: [512]u8 = undefined;
    const query = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x4444, "dns.home.arpa.", .A, false);
    var encoded: [1024]u8 = undefined;
    const encoded_query = std.base64.url_safe_no_pad.Encoder.encode(&encoded, query);
    var request_buffer: [2048]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "GET /dns-query?dns={s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{encoded_query});
    var client_write_buffer: [2048]u8 = undefined;
    var client_writer = stream.writer(io, &client_write_buffer);
    try client_writer.interface.writeAll(request);
    try client_writer.interface.flush();
    // No more request bytes are coming, so the server's handshake ends at once.
    try stream.shutdown(io, .send);

    // The server is doing a TLS handshake, so the cleartext request is never
    // answered: the connection ends, possibly with a TLS alert, but never
    // with an HTTP response or a DNS message.
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = stream.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&poll_fds, 500);
    var received: [512]u8 = undefined;
    const received_len: usize = if (ready == 0) 0 else std.posix.read(stream.socket.handle, &received) catch 0;
    try std.testing.expect(!std.mem.startsWith(u8, received[0..received_len], "HTTP/1.1"));
    if (received_len >= 12) {
        const message = dns_message.Message.parse(allocator, received[0..received_len]) catch {
            thread.join();
            return;
        };
        // A DNS answer for the cleartext query would carry its ID and the QR
        // bit; nothing else on this connection may look like one.
        try std.testing.expect(!(message.header.qr and message.header.id == 0x4444));
    }
    thread.join();
}

test "DoH defaults name the IANA http/1.1 ALPN token" {
    try std.testing.expectEqualStrings("http/1.1", DOH_ALPN);
    try std.testing.expectEqual(@as(u16, 443), DOH_PORT);
    try std.testing.expectEqual(listener.TCP_MAX_CONNECTION_WORKERS, MAX_CONNECTION_WORKERS);
}

const test_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

/// The same zone with an SOA MINIMUM below the record TTL, so the RFC 8484
/// section 5.1 rule for a response with no answer records is observable.
const nodata_zone =
    \\$ORIGIN home.arpa.
    \\$TTL 3600
    \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 60
    \\@ IN NS ns1.home.arpa.
    \\dns IN A 192.168.1.1
    \\
;

test "ODoH POST round trip through serveDohExchange" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8") catch unreachable;
    var target = odoh.makeTarget(priv);
    var query_buffer: [512]u8 = undefined;
    const inner = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0xabcd, "dns.home.arpa.", .A, false);
    const q_plain = try odoh.buildPlaintext(alloc, inner, &.{});
    const sealed_query = try odoh.sealQuery(alloc, io, target.public_key, &target.key_id, q_plain);
    var request_buffer: [65536]u8 = undefined;
    var request_stream = std.Io.Writer.fixed(&request_buffer);
    try request_stream.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{sealed_query.len});
    try request_stream.writeAll(sealed_query);
    var reader = std.Io.Reader.fixed(request_stream.buffered());
    var response_buffer: [65536]u8 = undefined;
    var writer = std.Io.Writer.fixed(&response_buffer);
    const client = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    _ = try serveDohExchange(&reader, &writer, alloc, &runtime, null, &client, true, &target);
    var response_reader = std.Io.Reader.fixed(writer.buffered());
    const status_line = try takeTestLine(&response_reader);
    try std.testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
    var content_type_ok = false;
    var cache_control_ok = false;
    var content_length: usize = 0;
    while (true) {
        const trimmed = try takeTestLine(&response_reader);
        if (trimmed.len == 0) break;
        if (trimmed.len > 12 and std.ascii.eqlIgnoreCase(trimmed[0..12], "content-type")) content_type_ok = std.mem.indexOf(u8, trimmed, odoh_media_type) != null;
        if (trimmed.len > 13 and std.ascii.eqlIgnoreCase(trimmed[0..13], "cache-control")) cache_control_ok = std.mem.indexOf(u8, trimmed, "no-store") != null;
        if (trimmed.len > 15 and std.ascii.eqlIgnoreCase(trimmed[0..14], "content-length")) {
            content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, trimmed[15..], " "), 10);
        }
    }
    try std.testing.expect(content_type_ok);
    try std.testing.expect(cache_control_ok);
    try std.testing.expect(content_length > 0);
    const sealed_response = try response_reader.take(content_length);
    const r_parsed = try odoh.parseMessage(sealed_response);
    try std.testing.expectEqual(odoh.response_message_type, r_parsed.message_type);
    // The channel must carry a sealed answer the client can open, not just
    // framed bytes: re-open the query to recover the sender exporter
    // secret and decrypt the DNS answer.
    const opened = try odoh.openQuery(alloc, &target, sealed_query);
    const answer_bytes = try odoh.openResponse(alloc, opened.exporter_secret, opened.q_plain, sealed_response);
    const answer = try dns_message.Message.parse(alloc, answer_bytes);
    try std.testing.expectEqual(@as(u16, 0xabcd), answer.header.id);
    try std.testing.expect(answer.header.answer_count > 0);
}

test "ODoH with no target is 404, wrong key is 401, corrupt body is 400" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var runtime = try Runtime.fromZoneText(test_zone);
    defer runtime.deinit();
    var priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8") catch unreachable;
    var target = odoh.makeTarget(priv);
    var query_buffer: [512]u8 = undefined;
    const inner = try @import("../cli/query.zig").buildQueryPacket(&query_buffer, 0x1234, "dns.home.arpa.", .A, false);
    const q_plain = try odoh.buildPlaintext(alloc, inner, &.{});
    const sealed_query = try odoh.sealQuery(alloc, io, target.public_key, &target.key_id, q_plain);
    const sendOdoh = struct {
        fn send(rt: *Runtime, body: []const u8, tgt: ?*const odoh.Target) ![]u8 {
            var req: [65536]u8 = undefined;
            var ws = std.Io.Writer.fixed(&req);
            try ws.print("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.len});
            try ws.writeAll(body);
            var reader = std.Io.Reader.fixed(ws.buffered());
            var resp: [65536]u8 = undefined;
            var writer = std.Io.Writer.fixed(&resp);
            const client = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
            var a2 = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer a2.deinit();
            _ = try serveDohExchange(&reader, &writer, a2.allocator(), rt, null, &client, true, tgt);
            var response_reader = std.Io.Reader.fixed(writer.buffered());
            const status = try takeTestLine(&response_reader);
            return try std.testing.allocator.dupe(u8, status);
        }
    }.send;
    const s404 = try sendOdoh(&runtime, sealed_query, null);
    defer std.testing.allocator.free(s404);
    try std.testing.expect(std.mem.startsWith(u8, s404, "HTTP/1.1 404"));
    var wrong_key = target.key_id;
    wrong_key[0] ^= 0xff;
    const wrong_msg = try odoh.buildMessage(alloc, odoh.query_message_type, &wrong_key, (try odoh.parseMessage(sealed_query)).encrypted);
    const s401 = try sendOdoh(&runtime, wrong_msg, &target);
    defer std.testing.allocator.free(s401);
    try std.testing.expect(std.mem.startsWith(u8, s401, "HTTP/1.1 401"));
    var corrupt = try alloc.dupe(u8, sealed_query);
    corrupt[corrupt.len - 1] ^= 0xff;
    const s400 = try sendOdoh(&runtime, corrupt, &target);
    defer std.testing.allocator.free(s400);
    try std.testing.expect(std.mem.startsWith(u8, s400, "HTTP/1.1 400"));
}
