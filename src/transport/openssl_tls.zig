/// Contract: The OpenSSL 3.x transport behind every encrypted listener and
/// every forwarding TLS client. One `SSL*` sits directly on the nonblocking
/// socket fd (`SSL_set_fd`); on `WANT_READ`/`WANT_WRITE` the wrapper polls
/// the fd and recomputes against one absolute deadline per iteration, so a
/// stalled peer fails typed instead of holding a worker. Fatal errors
/// close without sending close_notify.
/// Ownership: Each `Connection` owns one `SSL*` (freed by `SSL_free`);
/// each `Server`/client context owns one `SSL_CTX*` (freed by
/// `SSL_CTX_free`). Key material stays inside OpenSSL; nothing is copied
/// out or logged. The `SSL_CTX` is configured once and then shared
/// read-only across connections.
/// Errors: Handshake, verification, ALPN, deadline and framing failures are
/// typed; OpenSSL's error queue is drained and discarded, never propagated.
const std = @import("std");

const c = @import("openssl_abi.zig");

/// Largest single `SSL_read`/`SSL_write` chunk (<=16KB): short writes and
/// dribbled reads exercise the WANT_READ/WANT_WRITE paths instead of one
/// giant blocking call.
pub const chunk_len: usize = 16384;

/// TLS 1.3 on the wire (RFC 8446); the floor RFC 9103 section 7.2 sets for
/// the strict-TLS transfer channel and for every encrypted port here.
pub const tls13_version: c_long = 0x0304;

/// NUL-terminates a path for OpenSSL. The copy is freed by the caller.
fn dupeZ(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    const out = try allocator.allocSentinel(u8, text.len, 0);
    @memcpy(out[0..text.len], text);
    return out;
}

pub const Error = error{
    HandshakeFailed,
    VerifyFailed,
    AlpnMismatch,
    Closed,
    ReadFailed,
    WriteFailed,
    DeadlineExceeded,
};

/// The ALPN token the local side requires. The server selects exactly this
/// token or negotiates nothing (and then refuses); the client offers exactly
/// this token and tolerates a server that ignores the extension.
fn wireAlpn(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    const wire = try allocator.alloc(u8, token.len + 1);
    wire[0] = @intCast(token.len);
    @memcpy(wire[1..], token);
    return wire;
}

/// Server-side ALPN select callback: picks the configured token when the
/// client offered it, else negotiates nothing so `handshake` can refuse.
fn alpnSelect(
    ssl: ?*c.SSL,
    out: ?*anyopaque,
    outlen: ?*u8,
    in: ?*anyopaque,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    const token: []const u8 = if (arg) |p| std.mem.span(@as([*:0]const u8, @ptrCast(p))) else return c.SSL_TLSEXT_ERR_NOACK;
    const in_bytes: [*]const u8 = if (in) |p| @ptrCast(p) else return c.SSL_TLSEXT_ERR_NOACK;
    const offered = in_bytes[0..inlen];
    var i: usize = 0;
    while (i < offered.len) {
        const len: usize = offered[i];
        i += 1;
        if (i + len > offered.len) break;
        if (std.mem.eql(u8, offered[i..][0..len], token)) {
            const out_ptr: *?[*]const u8 = @ptrCast(@alignCast(out.?));
            out_ptr.* = offered[i..].ptr;
            outlen.?.* = @intCast(len);
            return c.SSL_TLSEXT_ERR_OK;
        }
        i += len;
    }
    return c.SSL_TLSEXT_ERR_NOACK;
}

/// Drains the pending check queue without surfacing it: callers get typed
/// errors, never OpenSSL internals.
fn drainErrors() void {
    while (c.ERR_get_error() != 0) {}
}

fn sslError(ssl: *c.SSL, ret: c_int) c_int {
    return c.SSL_get_error(ssl, ret);
}

pub const Server = struct {
    ctx: *c.SSL_CTX,
    /// Heap NUL-terminated ALPN token; the select callback reads it through
    /// arg. Heap because `init` returns by value: a pointer into `self`
    /// would dangle after the copy.
    alpn_z: [:0]u8,

    pub fn init(cert_path: []const u8, key_path: []const u8, alpn: []const u8) !Server {
        c.requireVersion();
        if (alpn.len == 0 or alpn.len > 63) return Error.HandshakeFailed;
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return Error.HandshakeFailed;
        errdefer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_MIN_PROTO_VERSION, tls13_version, null) != 1) {
            drainErrors();
            return Error.HandshakeFailed;
        }
        // Never ask for a client certificate: RFC 7858 section 3.1 keeps
        // the port for encrypted traffic only.
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        const cert_z = try dupeZ(std.heap.c_allocator, cert_path);
        defer std.heap.c_allocator.free(cert_z);
        const key_z = try dupeZ(std.heap.c_allocator, key_path);
        defer std.heap.c_allocator.free(key_z);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z) != 1) {
            drainErrors();
            return Error.HandshakeFailed;
        }
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z, c.SSL_FILETYPE_PEM) != 1) {
            drainErrors();
            return Error.HandshakeFailed;
        }
        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            drainErrors();
            return Error.HandshakeFailed;
        }
        const alpn_z = try dupeZ(std.heap.c_allocator, alpn);
        errdefer std.heap.c_allocator.free(alpn_z);
        const self = Server{ .ctx = ctx, .alpn_z = alpn_z };
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, self.alpn_z.ptr);
        return self;
    }

    pub fn deinit(self: *Server) void {
        c.SSL_CTX_free(self.ctx);
        std.heap.c_allocator.free(self.alpn_z);
        self.* = undefined;
    }
};

/// How a client authenticates the server. `insecure` is test-only: it
/// skips verification for loopback fixtures with throwaway identities and
/// MUST NOT be used in production paths.
pub const VerifyMode = union(enum) {
    system,
    ca_file: []const u8,
    insecure,
};

fn newClientCtx(mode: VerifyMode) !*c.SSL_CTX {
    c.requireVersion();
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return Error.HandshakeFailed;
    errdefer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_MIN_PROTO_VERSION, tls13_version, null) != 1) {
        drainErrors();
        return Error.HandshakeFailed;
    }
    switch (mode) {
        .insecure => c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null),
        .system => {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
            if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
                drainErrors();
                return Error.HandshakeFailed;
            }
        },
        .ca_file => |path| {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
            const path_z = try dupeZ(std.heap.c_allocator, path);
            defer std.heap.c_allocator.free(path_z);
            if (c.SSL_CTX_load_verify_locations(ctx, path_z, null) != 1) {
                drainErrors();
                return Error.HandshakeFailed;
            }
        },
    }
    return ctx;
}

fn isIpLiteral(host: []const u8) bool {
    if (host.len == 0) return false;
    // An IPv6 literal contains a colon; a dotted quad parses as IPv4.
    if (std.mem.indexOfScalar(u8, host, ':') != null) return true;
    var dots: usize = 0;
    for (host) |ch| {
        if (ch == '.') {
            dots += 1;
        } else if (ch < '0' or ch > '9') {
            return false;
        }
    }
    return dots == 3;
}

/// Puts `fd` nonblocking; the fd is consumed by the connection, so the
/// previous flags are not restored.
fn setNonblocking(fd: std.posix.fd_t) Error!void {
    const get = std.posix.system.fcntl(fd, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(get) != .SUCCESS) return Error.HandshakeFailed;
    const flags: std.posix.O = .{ .NONBLOCK = true };
    const want: usize = @intCast(@as(u32, @bitCast(get)) | @as(u32, @bitCast(flags)));
    const set = std.posix.system.fcntl(fd, std.posix.F.SETFL, want);
    if (std.posix.errno(set) != .SUCCESS) return Error.HandshakeFailed;
}

/// Polls `fd` for `events` until `deadline`. Recomputes the remaining time
/// each iteration; expiry is typed, never a hang.
fn pollUntil(io: std.Io, fd: std.posix.fd_t, events: i16, deadline: std.Io.Clock.Timestamp) Error!void {
    while (true) {
        const remaining = deadline.durationFromNow(io).raw.nanoseconds;
        if (remaining <= 0) return Error.DeadlineExceeded;
        const millis = @divTrunc(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms);
        const timeout: i32 = @intCast(@min(millis, std.math.maxInt(i32)));
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const count = std.posix.poll(&fds, timeout) catch return Error.ReadFailed;
        if (count == 0) return Error.DeadlineExceeded;
        const revents: i16 = fds[0].revents;
        if ((revents & std.posix.POLL.NVAL) != 0) return Error.ReadFailed;
        if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0 and (revents & events) == 0) {
            return Error.Closed;
        }
        if ((revents & events) != 0) return;
    }
}

pub const Connection = struct {
    ssl: ?*c.SSL,
    fd: std.posix.fd_t,
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    alpn_present: bool = false,
    alpn_storage: [64]u8 = undefined,
    alpn_len: usize = 0,

    /// The ALPN the peer selected, or null when it selected none. A
    /// function, not a stored slice: `Connection` crosses returns by
    /// value, and a slice stored at capture time would dangle at the
    /// caller's copy.
    pub fn alpnProtocol(self: *const Connection) ?[]const u8 {
        if (!self.alpn_present) return null;
        return self.alpn_storage[0..self.alpn_len];
    }

    /// One handshake step: runs `SSL_do_handshake`, polling the fd on
    /// WANT_READ/WANT_WRITE against the absolute deadline. Fatal errors
    /// close without sending close_notify.
    fn handshakeStep(self: *Connection) Error!bool {
        const ssl = self.ssl orelse return Error.Closed;
        const ret = c.SSL_do_handshake(ssl);
        if (ret == 1) return true;
        switch (sslError(ssl, ret)) {
            c.SSL_ERROR_WANT_READ => try pollUntil(self.io, self.fd, std.posix.POLL.IN, self.deadline),
            c.SSL_ERROR_WANT_WRITE => try pollUntil(self.io, self.fd, std.posix.POLL.OUT, self.deadline),
            c.SSL_ERROR_ZERO_RETURN => return Error.Closed,
            else => {
                drainErrors();
                return Error.HandshakeFailed;
            },
        }
        return false;
    }

    pub fn doHandshake(self: *Connection) Error!void {
        while (!try self.handshakeStep()) {}
    }

    /// Records the ALPN the peer selected; callers compare it with the
    /// transport's token.
    pub fn captureAlpn(self: *Connection) void {
        var out: [*c]const u8 = undefined;
        var outlen: c_uint = 0;
        if (self.ssl) |ssl| c.SSL_get0_alpn_selected(ssl, &out, &outlen);
        if (outlen == 0) {
            self.alpn_present = false;
            self.alpn_len = 0;
            return;
        }
        const len: usize = @min(@as(usize, @intCast(outlen)), self.alpn_storage.len);
        @memcpy(self.alpn_storage[0..len], out[0..len]);
        self.alpn_len = len;
        self.alpn_present = true;
    }

    /// The negotiated TLS version (e.g. 0x0304 for TLS 1.3).
    pub fn version(self: *Connection) c_int {
        return c.SSL_version(self.ssl orelse return 0);
    }

    /// Writes up to `chunk_len` bytes per `SSL_write` call so short writes
    /// exercise the WANT_WRITE path; polls against the absolute deadline.
    pub fn write(self: *Connection, bytes: []const u8) Error!usize {
        var off: usize = 0;
        while (off < bytes.len) {
            const ssl = self.ssl orelse return Error.Closed;
            const want = @min(bytes.len - off, chunk_len);
            const ret = c.SSL_write(ssl, bytes[off..].ptr, @intCast(want));
            if (ret > 0) {
                off += @intCast(ret);
                continue;
            }
            switch (sslError(ssl, ret)) {
                c.SSL_ERROR_WANT_READ => try pollUntil(self.io, self.fd, std.posix.POLL.IN, self.deadline),
                c.SSL_ERROR_WANT_WRITE => try pollUntil(self.io, self.fd, std.posix.POLL.OUT, self.deadline),
                c.SSL_ERROR_ZERO_RETURN => return Error.Closed,
                else => {
                    drainErrors();
                    return Error.WriteFailed;
                },
            }
        }
        return off;
    }

    pub fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        _ = try self.write(bytes);
    }

    /// Returns 0 on clean peer close only. WANT_READ/WANT_WRITE retries
    /// loop inside against the absolute deadline, so callers never see a
    /// short zero: a zero return is a clean close, never a retry. Reads in
    /// `chunk_len` pieces so a dribbling peer exercises the WANT_READ path.
    pub fn read(self: *Connection, buffer: []u8) Error!usize {
        if (buffer.len == 0) return 0;
        while (true) {
            const ssl = self.ssl orelse return Error.Closed;
            const want = @min(buffer.len, chunk_len);
            const ret = c.SSL_read(ssl, buffer.ptr, @intCast(want));
            if (ret > 0) {
                const n: usize = @intCast(ret);
                return n;
            }
            switch (sslError(ssl, ret)) {
                c.SSL_ERROR_WANT_READ => try pollUntil(self.io, self.fd, std.posix.POLL.IN, self.deadline),
                c.SSL_ERROR_WANT_WRITE => try pollUntil(self.io, self.fd, std.posix.POLL.OUT, self.deadline),
                c.SSL_ERROR_ZERO_RETURN => return 0,
                else => {
                    drainErrors();
                    return Error.ReadFailed;
                },
            }
        }
    }

    pub fn readAtLeast(self: *Connection, buffer: []u8, len: usize) Error!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try self.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub fn readAll(self: *Connection, buffer: []u8) Error!usize {
        return self.readAtLeast(buffer, buffer.len);
    }

    /// Idempotent: call sites pair an explicit `close() catch {}` with a
    /// deferred `close() catch {}`, so the second call is a no-op. A clean
    /// close sends close_notify; a fatal error path must use
    /// `closeWithoutNotify` instead.
    pub fn close(self: *Connection) Error!void {
        const ssl = self.ssl orelse return;
        self.ssl = null;
        defer c.SSL_free(ssl);
        // Deliver close_notify instead of only attempting it: retry the
        // WANTs against the absolute deadline, then drain whatever the
        // queue still holds so the next connection starts clean. A 0 return
        // means close_notify was sent but the peer's was not received: wait
        // once for readability against the absolute deadline, retry once,
        // then stop whether or not the peer answered. The flag keeps a peer
        // that stays readable without sending close_notify from spinning.
        var waited_zero = false;
        while (true) {
            const ret = c.SSL_shutdown(ssl);
            if (ret == 1) break;
            if (ret == 0) {
                if (waited_zero) break;
                waited_zero = true;
                pollUntil(self.io, self.fd, std.posix.POLL.IN, self.deadline) catch break;
                continue;
            }
            switch (sslError(ssl, ret)) {
                c.SSL_ERROR_WANT_READ => pollUntil(self.io, self.fd, std.posix.POLL.IN, self.deadline) catch break,
                c.SSL_ERROR_WANT_WRITE => pollUntil(self.io, self.fd, std.posix.POLL.OUT, self.deadline) catch break,
                else => break,
            }
        }
        drainErrors();
    }

    /// Frees the SSL without sending close_notify, for fatal error paths.
    pub fn closeWithoutNotify(self: *Connection) void {
        const ssl = self.ssl orelse return;
        self.ssl = null;
        c.SSL_free(ssl);
    }

    pub const Reader = struct {
        conn: *Connection,
        interface: std.Io.Reader,
        err: ?Error = null,

        pub fn init(conn: *Connection, buffer: []u8) Reader {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const buf = limit.slice(try w.writableSliceGreedy(1));
            const n = self.conn.read(buf) catch |err| {
                self.err = err;
                return error.ReadFailed;
            };
            // `read` retries WANTs internally; zero is a clean peer close.
            if (n == 0) return error.EndOfStream;
            w.advance(n);
            return n;
        }
    };

    pub fn reader(self: *Connection, buffer: []u8) Reader {
        return .init(self, buffer);
    }

    pub const Writer = struct {
        conn: *Connection,
        interface: std.Io.Writer,
        err: ?Error = null,

        pub fn init(conn: *Connection, buffer: []u8) Writer {
            return .{
                .conn = conn,
                .interface = .{
                    .vtable = &.{ .drain = drain },
                    .buffer = buffer,
                    .end = 0,
                },
            };
        }

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            self.writeAll(w.buffered()) catch return error.WriteFailed;
            w.end = 0;
            if (data.len == 0) return 0;
            var n: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                self.writeAll(bytes) catch return error.WriteFailed;
                n += bytes.len;
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 1) {
                var fill: [16384]u8 = undefined;
                @memset(&fill, pattern[0]);
                var remaining = splat;
                while (remaining > 0) {
                    const chunk = @min(remaining, fill.len);
                    self.writeAll(fill[0..chunk]) catch return error.WriteFailed;
                    remaining -= chunk;
                }
                n += splat;
            } else {
                for (0..splat) |_| {
                    self.writeAll(pattern) catch return error.WriteFailed;
                    n += pattern.len;
                }
            }
            return n;
        }

        fn writeAll(self: *Writer, bytes: []const u8) std.Io.Writer.Error!void {
            self.conn.writeAll(bytes) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
        }
    };

    pub fn writer(self: *Connection, buffer: []u8) Writer {
        return .init(self, buffer);
    }
};

fn newConnection(ctx: *c.SSL_CTX, fd: std.posix.fd_t, io: std.Io, deadline: std.Io.Clock.Timestamp, is_server: bool) Error!*c.SSL {
    try setNonblocking(fd);
    const ssl = c.SSL_new(ctx) orelse {
        drainErrors();
        return Error.HandshakeFailed;
    };
    errdefer c.SSL_free(ssl);
    if (c.SSL_set_fd(ssl, fd) != 1) {
        drainErrors();
        return Error.HandshakeFailed;
    }
    if (is_server) {
        c.SSL_set_accept_state(ssl);
    } else {
        c.SSL_set_connect_state(ssl);
    }
    _ = io;
    _ = deadline;
    return ssl;
}

/// Discards whatever the peer already sent without waiting for more, so
/// closing after a failed handshake sends FIN instead of RST. Capped and
/// wait-free: a dribbling peer cannot hold the worker here.
fn drainFailedHandshake(fd: std.posix.fd_t) void {
    var trash: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < 65536) {
        const n = std.posix.read(fd, &trash) catch return;
        if (n == 0) return;
        total += n;
    }
}

pub fn serverHandshake(server: *Server, fd: std.posix.fd_t, io: std.Io, deadline: std.Io.Clock.Timestamp) Error!Connection {
    // No errdefer: `closeWithoutNotify` frees the SSL on every failure
    // below, and success moves ownership to the returned Connection.
    const ssl = try newConnection(server.ctx, fd, io, deadline, true);
    var conn = Connection{ .ssl = ssl, .fd = fd, .io = io, .deadline = deadline };
    conn.doHandshake() catch |err| {
        conn.closeWithoutNotify();
        drainFailedHandshake(fd);
        return err;
    };
    conn.captureAlpn();
    // The caller frees with `close` (sending close_notify) or
    // `closeWithoutNotify` on fatal paths; cancel the errdefer.
    return conn;
}

pub const ClientOptions = struct {
    verify: VerifyMode,
    /// DNS name for verification, or an IP literal for IP verification
    /// (RFC 9462 section 6.3). `sni` below decides what goes on the wire.
    verify_host: []const u8,
    /// Sent as the SNI server_name; null falls back to `verify_host` (DNS
    /// names only, never IP literals); explicit empty sends nothing while
    /// verification still uses `verify_host`.
    sni: ?[]const u8,
    alpn: []const u8,
};

/// One client handshake directly on the socket fd. The caller owns `ctx`
/// (see `newClientCtx`, exposed for the forwarding clients that reuse one
/// context across exchanges).
pub fn clientHandshake(ctx: *c.SSL_CTX, fd: std.posix.fd_t, io: std.Io, deadline: std.Io.Clock.Timestamp, opt: ClientOptions) Error!Connection {
    const insecure = opt.verify == .insecure;
    // An empty name would sail through `SSL_set1_host("")` with no name
    // checks at all; refuse it before touching the socket.
    if (!insecure and opt.verify_host.len == 0) return Error.VerifyFailed;
    const ssl = try newConnection(ctx, fd, io, deadline, false);
    // Every failure path below frees the SSL exactly once; success clears
    // the flag and moves ownership to the Connection.
    var owned: ?*c.SSL = ssl;
    defer if (owned) |s| c.SSL_free(s);

    if (!insecure) {
        if (isIpLiteral(opt.verify_host)) {
            const param = c.SSL_get0_param(ssl) orelse return Error.HandshakeFailed;
            const ip_z = dupeZ(std.heap.c_allocator, opt.verify_host) catch return Error.HandshakeFailed;
            defer std.heap.c_allocator.free(ip_z);
            if (c.X509_VERIFY_PARAM_set1_ip_asc(param, ip_z) != 1) {
                drainErrors();
                return Error.HandshakeFailed;
            }
            // IP literals send no SNI at all.
        } else {
            const host_z = dupeZ(std.heap.c_allocator, opt.verify_host) catch return Error.HandshakeFailed;
            defer std.heap.c_allocator.free(host_z);
            if (c.SSL_set1_host(ssl, host_z) != 1) {
                drainErrors();
                return Error.HandshakeFailed;
            }
            // Null SNI falls back to the verification host; explicit empty
            // sends nothing while verification still uses the host.
            const sni_name = opt.sni orelse opt.verify_host;
            if (sni_name.len != 0 and !isIpLiteral(sni_name)) {
                const sni_z = dupeZ(std.heap.c_allocator, sni_name) catch return Error.HandshakeFailed;
                defer std.heap.c_allocator.free(sni_z);
                // A refused SNI fails the handshake: the name is required.
                if (c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(sni_z)) != 1) {
                    drainErrors();
                    return Error.HandshakeFailed;
                }
            }
        }
    }
    // Offer the transport's ALPN token; a server that ignores the extension
    // is tolerated by the caller, which checks `alpn_protocol` itself.
    const alpn_wire = wireAlpn(std.heap.c_allocator, opt.alpn) catch return Error.HandshakeFailed;
    defer std.heap.c_allocator.free(alpn_wire);
    if (c.SSL_set_alpn_protos(ssl, alpn_wire.ptr, @intCast(alpn_wire.len)) != 0) {
        drainErrors();
        return Error.HandshakeFailed;
    }
    owned = null;

    var conn = Connection{ .ssl = ssl, .fd = fd, .io = io, .deadline = deadline };
    conn.doHandshake() catch |err| {
        conn.closeWithoutNotify();
        drainFailedHandshake(fd);
        return err;
    };
    if (!insecure) {
        if (c.SSL_get_verify_result(ssl) != c.X509_V_OK) {
            conn.closeWithoutNotify();
            drainErrors();
            return Error.VerifyFailed;
        }
    }
    conn.captureAlpn();
    return conn;
}

/// Exposed so the forwarding clients can hold one context across exchanges.
pub const Ctx = c.SSL_CTX;
pub fn clientCtx(mode: VerifyMode) !*Ctx {
    return newClientCtx(mode);
}
pub fn freeClientCtx(ctx: *Ctx) void {
    c.SSL_CTX_free(ctx);
}
