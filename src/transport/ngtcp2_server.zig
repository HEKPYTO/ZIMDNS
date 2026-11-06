/// Contract: A single-threaded ngtcp2 QUIC server core for DNS-over-QUIC.
/// The loop owns one UDP socket, demultiplexes datagrams by destination
/// connection ID, and drives one ngtcp2 connection per client. Retry
/// tokens are HMAC-bound to the client address with a per-process secret
/// and verified with a 10s window; a tokenless Initial is answered with
/// a Retry, never a connection. Stream bytes are never answered from
/// inside an ngtcp2 callback: `recv_stream_data` copies the chunk into
/// the connection's scratch buffer and the read loop dispatches it after
/// `ngtcp2_conn_read_pkt` returns. Timers come from
/// `ngtcp2_conn_get_expiry2` via `poll`.
/// Ownership: the server owns every connection and its GnuTLS session;
/// `Handler.onStream` answers are borrowed until `flushConnection`
/// copies them into the response buffer.
const std = @import("std");
const abi = @import("ngtcp2_abi.zig");
const gnutls = @import("gnutls_server.zig");

const libc = struct {
    // Zig 0.17 dropped the high-level posix socket calls; the libc calls
    // below are the stable BSD surface (socket/bind/recvmsg/sendmsg/poll).
    extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
    extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;
    extern "c" fn bind(sockfd: c_int, address: ?*const std.posix.sockaddr, address_len: std.posix.socklen_t) c_int;
    extern "c" fn recvfrom(sockfd: c_int, buf: [*]u8, len: usize, flags: c_int, src_addr: ?*std.posix.sockaddr, addrlen: ?*std.posix.socklen_t) isize;
    extern "c" fn sendmsg(sockfd: c_int, msg: *const std.posix.msghdr_const, flags: c_int) isize;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn poll(fds: [*]std.posix.pollfd, nfds: std.posix.nfds_t, timeout: c_int) c_int;
    extern "c" fn sendto(sockfd: c_int, buf: [*]const u8, len: usize, flags: c_int, dest_addr: ?*const std.posix.sockaddr, addrlen: std.posix.socklen_t) isize;
};

var csprng_state: std.Random.DefaultCsprng = undefined;
var crypto_seeded: bool = false;

/// Process-wide CSPRNG for C callbacks (SCIDs, Retry SCIDs,
/// stateless-reset tokens). C callbacks cannot reach Zig state, so one
/// ChaCha instance is seeded once per process from OS entropy.
fn ensureCryptoSeed(io: std.Io) !void {
    if (crypto_seeded) return;
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    csprng_state = std.Random.DefaultCsprng.init(seed);
    csprng().bytes(&global_reset_secret);
    crypto_seeded = true;
}

fn csprng() std.Random {
    return csprng_state.random();
}

var global_reset_secret: [32]u8 = undefined;

pub const Error = error{
    BindFailed,
    SocketFailed,
    CredentialsFailed,
    ConnectionFailed,
    RetryFailed,
    EntropyUnavailable,
};

/// Per-listener Retry token secret, CSPRNG at startup.
pub const TokenSecret = struct {
    bytes: [32]u8,

    pub fn generate() TokenSecret {
        var secret: TokenSecret = undefined;
        csprng().bytes(&secret.bytes);
        return secret;
    }

    /// Builds the opaque token for `remote` + `odcid`, HMAC-bound so a
    /// token minted for one address never validates for another.
    pub fn mint(self: *const TokenSecret, out: []u8, version: u32, remote: *const std.posix.sockaddr.storage, remote_len: std.posix.socklen_t, retry_scid: *const abi.cid, odcid: *const abi.cid, now: abi.tstamp) []u8 {
        const rlen: usize = @intCast(remote_len);
        const need = 4 + 8 + 1 + odcid.datalen + 1 + retry_scid.datalen + rlen + 32;
        if (out.len < need or odcid.datalen > 20 or retry_scid.datalen > 20) return &.{};
        var pos: usize = 0;
        std.mem.writeInt(u32, out[pos..][0..4], version, .big);
        pos += 4;
        std.mem.writeInt(u64, out[pos..][0..8], now, .big);
        pos += 8;
        out[pos] = @intCast(odcid.datalen);
        pos += 1;
        @memcpy(out[pos..][0..odcid.datalen], odcid.data[0..odcid.datalen]);
        pos += odcid.datalen;
        out[pos] = @intCast(retry_scid.datalen);
        pos += 1;
        @memcpy(out[pos..][0..retry_scid.datalen], retry_scid.data[0..retry_scid.datalen]);
        pos += retry_scid.datalen;
        @memcpy(out[pos..][0..rlen], std.mem.asBytes(remote)[0..rlen]);
        pos += rlen;
        std.crypto.auth.hmac.sha2.HmacSha256.create(out[pos..][0..32], out[0..pos], &self.bytes);
        pos += 32;
        return out[0..pos];
    }

    /// Verifies a token and recovers the original DCID. Rejects tokens
    /// minted for another address or outside the window.
    const window: abi.duration = 10 * abi.SECONDS;
    pub fn check(self: *const TokenSecret, token: []const u8, version: u32, remote: *const std.posix.sockaddr.storage, remote_len: std.posix.socklen_t, dcid: *const abi.cid, now: abi.tstamp) ?abi.cid {
        const rlen: usize = @intCast(remote_len);
        if (token.len < 4 + 8 + 1 + 1 + rlen + 32) {
            return null;
        }
        var pos: usize = 0;
        if (std.mem.readInt(u32, token[pos..][0..4], .big) != version) {
            return null;
        }
        pos += 4;
        const minted = std.mem.readInt(u64, token[pos..][0..8], .big);
        pos += 8;
        if (now < minted or now - minted > window) {
            return null;
        }
        const odcid_len: usize = token[pos];
        pos += 1;
        if (odcid_len > 20 or token.len < pos + odcid_len + 1 + 32) {
            return null;
        }
        var recovered = std.mem.zeroes(abi.cid);
        recovered.datalen = odcid_len;
        @memcpy(recovered.data[0..odcid_len], token[pos..][0..odcid_len]);
        pos += odcid_len;
        const rscid_len: usize = token[pos];
        pos += 1;
        if (rscid_len > 20 or dcid.datalen != rscid_len) {
            return null;
        }
        if (token.len != pos + rscid_len + rlen + 32) {
            return null;
        }
        if (!std.mem.eql(u8, token[pos..][0..rscid_len], dcid.data[0..dcid.datalen])) {
            return null;
        }
        pos += rscid_len;
        if (!std.mem.eql(u8, token[pos..][0..rlen], std.mem.asBytes(remote)[0..rlen])) {
            return null;
        }
        pos += rlen;
        var expect: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&expect, token[0..pos], &self.bytes);
        var diff: u8 = 0;
        for (expect, token[pos..][0..32]) |a, b| diff |= a ^ b;
        if (diff != 0) {
            return null;
        }
        return recovered;
    }
};

/// What the DoQ layer does with one stream chunk. `data` is borrowed and
/// copied before `onStream` returns.
pub const StreamEvent = union(enum) {
    data: struct {
        stream_id: i64,
        bytes: []const u8,
        fin: bool,
        peer: std.Io.net.IpAddress,
        now: abi.tstamp,
    },
    reset: struct {
        stream_id: i64,
    },
};

pub const Handler = struct {
    ptr: *anyopaque,
    onStream: *const fn (*anyopaque, *Connection, StreamEvent) void,
    onHandshake: ?*const fn (*anyopaque, *Connection) void = null,
    onStreamOpen: ?*const fn (*anyopaque, *Connection, i64) void = null,
    onStreamClose: ?*const fn (*anyopaque, *Connection, i64) void = null,
    onStreamReset: ?*const fn (*anyopaque, *Connection, i64, u64) void = null,
    onAck: ?*const fn (*anyopaque, *Connection, i64, u64) void = null,
    onStopSending: ?*const fn (*anyopaque, *Connection, i64, u64) void = null,
    onClose: ?*const fn (*anyopaque, *Connection) void = null,
    flush: ?*const fn (*anyopaque, *Server, *Connection, abi.tstamp) void = null,
};

/// One ngtcp2 connection: the QUIC state, its TLS session, the conn_ref
/// the crypto backend uses to find it, queued answers, and the chunk
/// scratch the callbacks copy into.
const ChunkSlot = struct {
    stream: i64 = 0,
    start: usize = 0,
    len: usize = 0,
    fin: bool = false,
    used: bool = false,
};

/// One stream-lifecycle event stashed during read_pkt. A datagram can
/// close/reset several streams at once; a single slot would keep only
/// the last one and strand the handler entry for the others.
const CloseSlot = struct {
    stream: i64 = 0,
    used: bool = false,
};

const ResetSlot = struct {
    stream: i64 = 0,
    code: u64 = 0,
    used: bool = false,
};

pub const Connection = struct {
    conn: ?*abi.conn_t,
    session: gnutls.ServerSession,
    conn_ref: abi.crypto_conn_ref,
    handler: Handler,
    server_scid: abi.cid,
    peer_addr: std.posix.sockaddr.storage,
    peer_len: std.posix.socklen_t,
    local_addr: std.posix.sockaddr.storage,
    storage: abi.path_storage,
    pending: PendingQueue = .{},
    chunk: [65537]u8 = undefined,
    // One slot per stream frame stashed during read_pkt: a datagram can
    // carry frames for several streams (H3 control + QPACK + request),
    // and a single shared cursor would keep only the last one.
    chunks: [8]ChunkSlot = undefined,
    chunk_used: usize = 0,
    closes: [8]CloseSlot = undefined,
    resets: [8]ResetSlot = undefined,
    doomed: bool = false,
    acked_stream: i64 = 0,
    acked_len: u64 = 0,
    has_ack: bool = false,
    opened_stream: i64 = 0,
    has_open: bool = false,
    stop_stream: i64 = 0,
    stop_code: u64 = 0,
    has_stop: bool = false,
    handshook: bool = false,

    pub fn getConn(ref: ?*abi.crypto_conn_ref) callconv(.c) ?*abi.conn_t {
        const ud = ref.?.user_data orelse return null;
        const holder: *Connection = @ptrCast(@alignCast(ud));
        return holder.conn;
    }

    fn peerIp(self: *const Connection) ?std.Io.net.IpAddress {
        return ipAddressFromStorage(&self.peer_addr);
    }
};

/// Answers queued between dispatch (which must not write packets) and
/// the flush after `read_pkt`. Bounded: one stream carries one query.
const PendingQueue = struct {
    const Entry = struct {
        stream_id: i64,
        response: [65537]u8 = undefined,
        response_len: usize = 0,
        // Bytes already accepted by ngtcp2. A flush that cannot emit
        // stream bytes yet (handshake incomplete, amplification limit)
        // leaves the entry queued; the next flush resumes at `sent`.
        sent: usize = 0,
        reset: bool = false,
        error_code: u64 = 0,
    };
    entries: [8]Entry = undefined,
    count: usize = 0,

    fn pushAnswer(self: *PendingQueue, stream_id: i64, response: []const u8) bool {
        if (self.count >= self.entries.len) return false;
        const entry = &self.entries[self.count];
        if (response.len > entry.response.len) return false;
        @memcpy(entry.response[0..response.len], response);
        entry.stream_id = stream_id;
        entry.response_len = response.len;
        entry.sent = 0;
        entry.reset = false;
        self.count += 1;
        return true;
    }

    fn pushReset(self: *PendingQueue, stream_id: i64, error_code: u64) bool {
        if (self.count >= self.entries.len) return false;
        self.entries[self.count] = .{ .stream_id = stream_id, .reset = true, .error_code = error_code };
        self.count += 1;
        return true;
    }

    /// Queues an answer or, when full, a protocol-error reset instead.
    /// The queue can only fill under attack; resetting overflows keeps
    /// the server alive rather than dropping the connection.
    pub fn answer(self: *PendingQueue, stream_id: i64, response: []const u8, error_code: u64) void {
        if (!self.pushAnswer(stream_id, response)) _ = self.pushReset(stream_id, error_code);
    }

    pub fn resetStream(self: *PendingQueue, stream_id: i64, error_code: u64) void {
        _ = self.pushReset(stream_id, error_code);
    }

    // (clear removed: entries drain through flushConnection only.)
};

/// The UDP server loop. Binds `address`, loads `creds`, and serves until
/// `shouldStop` says enough (the DoQ layer stops after `max_requests`).
pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    creds: *const gnutls.ServerCredentials,
    handler: Handler,
    shouldStop: ?*const fn (*anyopaque) bool,
    stop_ctx: ?*anyopaque,
    idle_timeout_ns: u64,
    alpn: []const u8,
) Error!void {
    ensureCryptoSeed(io) catch return Error.EntropyUnavailable;
    var server = Server.init(allocator, io, address, creds, handler, idle_timeout_ns, alpn) catch return Error.SocketFailed;
    defer server.deinit();
    while (true) {
        if (shouldStop != null and shouldStop.?(stop_ctx.?)) return;
        server.step() catch return Error.SocketFailed;
    }
}

pub const Server = struct {
    /// Hard cap on live connections per listener. Enforced with a
    /// stateless close, never by dropping state.
    pub const MAX_CONNECTIONS: usize = 128;
    /// One client may open this many bidirectional streams per
    /// connection; matches the advertised transport parameters.
    pub const MAX_STREAMS_PER_CONN: usize = 100;
    allocator: std.mem.Allocator,
    io: std.Io,
    fd: std.posix.fd_t,
    bound: std.posix.sockaddr.storage,
    creds: *const gnutls.ServerCredentials,
    handler: Handler,
    alpn: []const u8,
    secret: TokenSecret,
    conns: std.AutoHashMapUnmanaged(CidKey, *Connection) = .empty,
    // The client's original DCID per live connection, so retransmitted
    // Initials (same DCID, before the client learns our SCID) route to
    // the existing holder instead of spawning a duplicate connection.
    client_dcids: std.AutoHashMapUnmanaged(CidKey, *Connection) = .empty,
    /// Live connection count. `conns` holds ~2-3 SCID aliases per
    /// connection, so the cap is enforced on this, not the map size.
    conn_count: usize = 0,
    idle_timeout: abi.duration,
    rx_buf: [65527]u8 = undefined,
    tx_buf: [65527]u8 = undefined,

    const CidKey = struct {
        len: usize,
        bytes: [abi.MAX_CIDLEN]u8,
    };

    fn init(allocator: std.mem.Allocator, io: std.Io, address: *const std.Io.net.IpAddress, creds: *const gnutls.ServerCredentials, handler: Handler, idle_timeout_ns: u64, alpn: []const u8) !Server {
        const domain: c_uint = switch (address.*) {
            .ip4 => std.posix.AF.INET,
            .ip6 => std.posix.AF.INET6,
        };
        // Darwin's socket(2) rejects the CLOEXEC/NONBLOCK type flags, so
        // create the socket plain and set both flags with fcntl instead.
        const fd = libc.socket(domain, @as(c_uint, 2), @as(c_uint, 17));
        if (fd < 0) return error.SocketFailed;
        errdefer _ = libc.close(fd);
        if (libc.fcntl(fd, std.posix.F.SETFD, @as(c_int, 1)) < 0) return error.SocketFailed;
        const flags = libc.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
        const nonblock: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
        if (flags < 0 or libc.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.SocketFailed;
        var bound = ipToStorage(address);
        const bind_len: std.posix.socklen_t = switch (address.*) {
            .ip4 => @sizeOf(std.posix.sockaddr.in),
            .ip6 => @sizeOf(std.posix.sockaddr.in6),
        };
        if (libc.bind(fd, @ptrCast(&bound), bind_len) < 0) return error.SocketFailed;
        return .{
            .allocator = allocator,
            .io = io,
            .fd = fd,
            .bound = bound,
            .creds = creds,
            .handler = handler,
            .alpn = alpn,
            .secret = TokenSecret.generate(),
            .idle_timeout = @max(idle_timeout_ns, 1 * abi.SECONDS),
        };
    }

    fn deinit(self: *Server) void {
        // Drain one holder at a time: each destroy unindexes its aliases,
        // so no snapshot can go stale and no cap can drop a holder.
        while (self.conns.count() > 0) {
            var kit = self.conns.iterator();
            const kv = kit.next() orelse break;
            const holder = kv.value_ptr.*;
            self.unindexConnection(holder);
            destroyConnection(self.allocator, holder);
            self.conn_count -= 1;
        }
        self.client_dcids.clearRetainingCapacity();
        self.conns.deinit(self.allocator);
        self.client_dcids.deinit(self.allocator);
        _ = libc.close(self.fd);
    }

    /// Registers every SCID the connection currently owns. Called after
    /// creation and after each flush (the handshake mints new CIDs), so
    /// later packets always demux to the live connection. Stale aliases
    /// are pruned first: without this, a reaped connection's CIDs would
    /// resurrect it in the map and its packets would feed a dead conn.
    fn reindex(self: *Server, holder: *Connection) void {
        self.unindexConnection(holder);
        self.indexConnection(holder);
    }

    /// One loop step: wait for a datagram or the next timer, then read
    /// everything pending, flush every connection, and reap the doomed.
    fn step(self: *Server) !void {
        const now = nowNs(self.io);
        var qfd = [1]std.posix.pollfd{.{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const pr = libc.poll(qfd[0..1], 1, @intCast(self.pollTimeoutMs()));
        if (pr < 0) {
            if (std.c._errno().* == 4) return; // EINTR: next step re-polls.
            return error.PollFailed;
        }
        if (pr == 0) {
            self.handleExpiries(now);
            var eit = self.conns.valueIterator();
            while (eit.next()) |holder| self.pumpConnection(holder.*, now);
            self.reindexAll();
            self.reapDoomed();
            return;
        }
        // Drain everything queued, pumping each connection's timer as
        // its packets arrive.
        while (self.readOne(now)) {}
        var pit = self.conns.valueIterator();
        while (pit.next()) |holder| self.pumpConnection(holder.*, now);
        // Reindex after the loop: indexing mints map puts that can grow
        // (rehash) the table, which invalidates the live iterator.
        self.reindexAll();
        self.reapDoomed();
    }

    /// Re-registers every live connection's SCIDs after a pump pass.
    /// Runs with no live iterator, so table growth is safe.
    fn reindexAll(self: *Server) void {
        // Snapshot first: reindex mutates the map being walked. No fixed
        // cap: allocate exactly the deduped holder count.
        const count = self.conns.count();
        if (count == 0) return;
        const snapshot = self.allocator.alloc(*Connection, count) catch return;
        defer self.allocator.free(snapshot);
        var n: usize = 0;
        var it = self.conns.valueIterator();
        while (it.next()) |holder| {
            var seen = false;
            for (snapshot[0..n]) |kept| if (kept == holder.*) {
                seen = true;
                break;
            };
            if (seen) continue;
            snapshot[n] = holder.*;
            n += 1;
        }
        for (snapshot[0..n]) |holder| self.reindex(holder);
    }

    /// Drives one connection's timer with a fresh timestamp and flushes
    /// any retransmit immediately, instead of waiting for the next loop
    /// tick. Called after every read and every expiry.
    fn pumpConnection(self: *Server, holder: *Connection, now: abi.tstamp) void {
        if (abi.conn_get_expiry(holder.conn) <= now) {
            if (abi.conn_handle_expiry(holder.conn, now) == 0) {
                self.flushConnection(holder, now);
            } else {
                holder.doomed = true;
            }
        } else {
            self.flushConnection(holder, now);
        }
    }

    fn readOne(self: *Server, now: abi.tstamp) bool {
        // Zero the storage: Darwin leaves sin_zero padding uninitialised,
        // and ngtcp2's token check memcmp's the full sockaddr — stale
        // padding would fail HMAC verification on the second Initial.
        var peer: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const n = libc.recvfrom(self.fd, self.rx_buf[0..].ptr, self.rx_buf.len, 0, @ptrCast(&peer), &peer_len);
        if (n < 0) {
            // Darwin reports EAGAIN as 35 and EINTR as 4; anything else
            // (e.g. ECONNREFUSED from a dead peer) drops the datagram.
            const err = std.c._errno().*;
            if (err == 4) return self.readOne(now);
            return false;
        }
        if (n < 21) return true; // Too short for QUIC; drop, keep draining.
        self.onDatagram(self.rx_buf[0..@intCast(n)], &peer, peer_len, now);
        return true;
    }

    fn pollTimeoutMs(self: *Server) u64 {
        var earliest: ?abi.tstamp = null;
        var it = self.conns.valueIterator();
        while (it.next()) |holder| {
            if (holder.*.conn == null) continue;
            const expiry = abi.conn_get_expiry(holder.*.conn);
            if (expiry == std.math.maxInt(u64)) continue;
            if (earliest == null or expiry < earliest.?) earliest = expiry;
        }
        const now = nowNs(self.io);
        if (earliest) |expiry| {
            if (expiry <= now) return 0;
            return @min((expiry - now) / 1_000_000, 100);
        }
        return 100;
    }

    fn onDatagram(self: *Server, data: []u8, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t, now: abi.tstamp) void {
        var vc: abi.version_cid = undefined;
        const vc_rc = abi.pkt_decode_version_cid(&vc, data.ptr, data.len, 0);
        if (vc_rc != 0 and vc_rc != abi.ERR_VERSION_NEGOTIATION) {
            // Unparseable as long header: may be 1-RTT on a live conn.
            if (self.findByPacket(data)) |holder| self.feed(holder, data, peer, peer_len, now);
            return;
        }
        if (vc_rc == abi.ERR_VERSION_NEGOTIATION or (vc.version != 0 and vc.version != abi.PROTO_VER_V1)) {
            self.sendVersionNegotiation(vc.scid, vc.scidlen, vc.dcid, vc.dcidlen, peer, peer_len);
            return;
        }
        if (vc.version == 0) {
            if (self.findByPacket(data)) |holder| self.feed(holder, data, peer, peer_len, now);
            return;
        }
        // Long header with our version: demux on DCID first.
        if (self.findByDcid(vc.dcid, vc.dcidlen)) |holder| {
            self.feed(holder, data, peer, peer_len, now);
            return;
        }
        // Retransmitted Initial: same client DCID as a live handshake.
        if (vc.dcidlen > 0 and vc.dcidlen <= abi.MAX_CIDLEN) {
            var ckey = CidKey{ .len = vc.dcidlen, .bytes = std.mem.zeroes([abi.MAX_CIDLEN]u8) };
            @memcpy(ckey.bytes[0..vc.dcidlen], vc.dcid[0..vc.dcidlen]);
            if (self.client_dcids.get(ckey)) |holder| {
                self.feed(holder, data, peer, peer_len, now);
                return;
            }
        }
        var hd: abi.pkt_hd = undefined;
        const arc = abi.accept(&hd, data.ptr, data.len);
        if (arc != 0) {
            return;
        }
        if (hd.type != abi.PKT_INITIAL) return; // No stateless reset; drop.
        if (hd.tokenlen > 0) {
            // Retry token path: verify HMAC/address/window, then create
            // the connection with the recovered original DCID.

            const token = hd.token[0..hd.tokenlen];
            if (self.secret.check(token, hd.version, peer, peer_len, &hd.dcid, now)) |odcid| {
                self.createConnection(&hd, odcid, peer, peer_len, data, now);
            } else {
                // Forged or stale token: stateless close, no state.
                self.sendClose(&hd, peer, peer_len, now);
            }
            return;
        }

        self.sendRetry(&hd, peer, peer_len, data.len, now);
    }

    fn createConnection(self: *Server, hd: *const abi.pkt_hd, odcid: abi.cid, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t, first_packet: []u8, now: abi.tstamp) void {
        if (self.conn_count >= MAX_CONNECTIONS) {
            self.sendClose(hd, peer, peer_len, now);
            return;
        }
        // Explicit cleanup: this function returns void, so errdefer
        // never fires here — each failure path frees what it owns.
        const holder = self.allocator.create(Connection) catch return;
        holder.* = .{
            .conn = null,
            .session = undefined,
            .conn_ref = undefined,
            .handler = self.handler,
            .server_scid = undefined,
            .peer_addr = peer.*,
            .peer_len = peer_len,
            .local_addr = self.bound,
            .storage = undefined,
        };
        for (&holder.chunks) |*slot| slot.* = .{};
        for (&holder.closes) |*slot| slot.* = .{};
        for (&holder.resets) |*slot| slot.* = .{};
        holder.conn_ref = .{ .get_conn = Connection.getConn, .user_data = holder };
        csprng().bytes(holder.server_scid.data[0..18]);
        holder.server_scid.datalen = 18;
        holder.session = gnutls.ServerSession.initWithAlpn(self.creds, &holder.conn_ref, self.alpn) catch {
            self.allocator.destroy(holder);
            return;
        };

        var cbs = std.mem.zeroes(abi.callbacks);
        cbs.recv_client_initial = abi.ngtcp2_crypto_recv_client_initial_cb;
        cbs.recv_crypto_data = abi.ngtcp2_crypto_recv_crypto_data_cb;
        cbs.encrypt = bridgeEncrypt;
        cbs.decrypt = bridgeDecrypt;
        cbs.hp_mask = bridgeHpMask;
        cbs.recv_stream_data = recvStreamData;
        cbs.acked_stream_data_offset = ackedStreamData;
        cbs.handshake_completed = handshakeCompleted;
        cbs.stream_open = streamOpen;
        cbs.stream_close2 = streamClose;
        cbs.stream_reset = streamReset;
        cbs.recv_stop_sending = recvStopSending;
        cbs.rand = randBytes;
        cbs.get_new_connection_id = getNewConnectionId;

        cbs.remove_connection_id = removeConnectionId;
        cbs.update_key = abi.ngtcp2_crypto_update_key_cb;
        cbs.delete_crypto_aead_ctx = abi.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cbs.delete_crypto_cipher_ctx = abi.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        cbs.get_path_challenge_data2 = abi.ngtcp2_crypto_get_path_challenge_data2_cb;
        cbs.version_negotiation = abi.ngtcp2_crypto_version_negotiation_cb;

        var s = std.mem.zeroes(abi.settings);
        abi.settings_default(abi.SETTINGS_VERSION, &s);
        s.initial_ts = now;

        var params = std.mem.zeroes(abi.transport_params);
        abi.transport_params_default(abi.TRANSPORT_PARAMS_VERSION, &params);
        params.initial_max_stream_data_bidi_local = 6 * 1024 * 1024;
        params.initial_max_stream_data_bidi_remote = 6 * 1024 * 1024;
        params.initial_max_stream_data_uni = 1024 * 1024;
        params.initial_max_data = 16 * 1024 * 1024;
        params.initial_max_streams_bidi = MAX_STREAMS_PER_CONN;
        params.initial_max_streams_uni = MAX_STREAMS_PER_CONN;
        params.max_idle_timeout = self.idle_timeout;
        params.max_udp_payload_size = 65527;
        params.original_dcid = odcid;
        params.original_dcid_present = 1;
        // Only a Retry-validated connection carries a Retry SCID: the
        // SCID of our Retry packet becomes the client's post-Retry DCID
        // and ngtcp2 checks the transport parameters against it. A
        // tokenless (NORETRY) Initial never saw a Retry, so asserting one
        // would fail TP validation.
        if (hd.tokenlen > 0) {
            params.retry_scid = hd.dcid;
            params.retry_scid_present = 1;
        }
        // Hand ngtcp2 the verified token bytes so the amplification
        // limit is lifted for this validated address.
        s.token = hd.token;
        s.tokenlen = hd.tokenlen;
        s.token_type = abi.TOKEN_TYPE_RETRY;

        // The connection is heap-stable, so the path can point at its
        // own address copies for the connection's whole life.
        holder.storage.local_addrbuf.sa = holder.local_addr;
        holder.storage.remote_addrbuf.sa = holder.peer_addr;

        holder.storage.path = .{
            .local = .{ .addr = @ptrCast(&holder.storage.local_addrbuf.sa), .addrlen = addrLen(&holder.local_addr) },
            .remote = .{ .addr = @ptrCast(&holder.storage.remote_addrbuf.sa), .addrlen = peer_len },
            .user_data = null,
        };

        var qconn: ?*abi.conn_t = null;
        // First arg is the client's source CID (hd.scid), validated
        // against the client's initial_scid transport parameter; the
        // second is our fresh server SCID. (Reference: server.cc
        // h->init(..., &hd.scid, &hd.dcid, pocid, ...).)
        const rc = abi.conn_server_new(
            &qconn,
            &hd.scid,
            &holder.server_scid,
            &holder.storage.path,
            hd.version,
            abi.CALLBACKS_VERSION,
            &cbs,
            abi.SETTINGS_VERSION,
            &s,
            abi.TRANSPORT_PARAMS_VERSION,
            &params,
            null,
            holder,
        );
        // Explicit failure path (void function: no errdefer fires).
        // conn_server_new allocated no ngtcp2 state on error and
        // nothing was indexed yet, so unwind session + holder only.
        if (rc != 0 or qconn == null) {
            holder.session.deinit();
            self.allocator.destroy(holder);
            return;
        }
        holder.conn = qconn;
        abi.conn_set_tls_native_handle(qconn, holder.session.session);
        self.conn_count += 1;
        self.indexConnection(holder);
        // Remember the client's DCID so its retransmitted Initials find
        // this holder while the handshake is still in flight.
        if (hd.dcid.datalen > 0 and hd.dcid.datalen <= abi.MAX_CIDLEN) {
            var ckey = CidKey{ .len = hd.dcid.datalen, .bytes = std.mem.zeroes([abi.MAX_CIDLEN]u8) };
            @memcpy(ckey.bytes[0..hd.dcid.datalen], hd.dcid.data[0..hd.dcid.datalen]);
            self.client_dcids.put(self.allocator, ckey, holder) catch {};
        }
        self.feed(holder, first_packet, peer, peer_len, now);
        self.flushConnection(holder, now);
    }

    fn indexConnection(self: *Server, holder: *Connection) void {
        var scids: [8]abi.cid = undefined;
        const n = abi.conn_get_scid(holder.conn, &scids);
        var i: usize = 0;
        while (i < n and i < scids.len) : (i += 1) {
            var key = CidKey{ .len = scids[i].datalen, .bytes = std.mem.zeroes([abi.MAX_CIDLEN]u8) };
            @memcpy(key.bytes[0..key.len], scids[i].data[0..key.len]);
            self.conns.put(self.allocator, key, holder) catch return;
        }
        // Long-header demux matches the client's destination CID, which
        // is our SCID: after retirement the current one is no longer
        // the handshake SCID, so index the live value every pump.
        if (abi.conn_get_dcid(holder.conn)) |dcid| self.indexCid(holder, dcid.*);
    }

    fn indexCid(self: *Server, holder: *Connection, c: abi.cid) void {
        if (c.datalen == 0 or c.datalen > abi.MAX_CIDLEN) return;
        var key = CidKey{ .len = c.datalen, .bytes = std.mem.zeroes([abi.MAX_CIDLEN]u8) };
        @memcpy(key.bytes[0..key.len], c.data[0..key.len]);
        self.conns.put(self.allocator, key, holder) catch return;
    }

    fn unindexConnection(self: *Server, holder: *Connection) void {
        // Remove-while-found: capture one key per pass so no iterator
        // outlives a mutation and no fixed cap can drop an alias.
        while (true) {
            var found: ?CidKey = null;
            var it = self.conns.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.* == holder) {
                    found = kv.key_ptr.*;
                    break;
                }
            }
            const key = found orelse break;
            _ = self.conns.remove(key);
        }
        while (true) {
            var found: ?CidKey = null;
            var cit = self.client_dcids.iterator();
            while (cit.next()) |kv| {
                if (kv.value_ptr.* == holder) {
                    found = kv.key_ptr.*;
                    break;
                }
            }
            const key = found orelse break;
            _ = self.client_dcids.remove(key);
        }
    }

    fn findByDcid(self: *Server, dcid: [*c]const u8, dcidlen: usize) ?*Connection {
        if (dcidlen == 0 or dcidlen > abi.MAX_CIDLEN) return null;
        var it = self.conns.iterator();
        while (it.next()) |kv| {
            if (kv.key_ptr.len == dcidlen and std.mem.eql(u8, kv.key_ptr.bytes[0..dcidlen], dcid[0..dcidlen])) {
                return kv.value_ptr.*;
            }
        }
        return null;
    }

    fn findByPacket(self: *Server, data: []u8) ?*Connection {
        // 1-RTT packets carry a short header with no DCID length; match
        // the bytes after the type octet against every known SCID.
        var it = self.conns.iterator();
        while (it.next()) |kv| {
            const key = kv.key_ptr;
            if (data.len >= 1 + key.len and std.mem.eql(u8, data[1..][0..key.len], key.bytes[0..key.len])) {
                return kv.value_ptr.*;
            }
        }
        return null;
    }

    fn feed(self: *Server, holder: *Connection, data: []u8, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t, now: abi.tstamp) void {
        holder.peer_addr = peer.*;
        holder.peer_len = peer_len;
        holder.storage.remote_addrbuf.sa = peer.*;
        holder.storage.path.remote.addr = @ptrCast(&holder.storage.remote_addrbuf.sa);
        holder.storage.path.remote.addrlen = peer_len;
        var pi = abi.pkt_info{ .ecn = 0 };
        const rc = abi.conn_read_pkt(holder.conn, &holder.storage.path, abi.PKT_INFO_VERSION, &pi, data.ptr, data.len, now);

        if (rc != 0) {
            if (rc == abi.ERR_DRAINING or rc == abi.ERR_CLOSING) return;
            if (rc == abi.ERR_IDLE_CLOSE or rc == abi.ERR_DROP_CONN) {
                holder.doomed = true;
                return;
            }
            self.writeClose(holder, @intCast(@abs(rc)), now);
            holder.doomed = true;
            return;
        }
        if (holder.handshook) {
            holder.handshook = false;
            // The negotiated ALPN is only known once the handshake
            // completes; refresh the mirror before the handler checks it.
            var selected: abi.gnutls_datum_t = .{ .data = null, .size = 0 };
            if (abi.alpn_get_selected_protocol(holder.session.session, &selected) == 0 and selected.size > 0 and selected.size <= holder.session.alpn.len) {
                @memcpy(holder.session.alpn[0..selected.size], selected.data[0..selected.size]);
                holder.session.alpn_len = selected.size;
            } else {
                holder.session.alpn_len = 0;
            }
            if (holder.handler.onHandshake) |f| f(holder.handler.ptr, holder);
        }
        if (holder.has_open) {
            holder.has_open = false;
            if (holder.handler.onStreamOpen) |f| f(holder.handler.ptr, holder, holder.opened_stream);
        }
        for (&holder.chunks) |*slot| {
            if (!slot.used) continue;
            slot.used = false;
            const from = holder.peerIp();
            if (from) |ip| {
                holder.handler.onStream(holder.handler.ptr, holder, .{ .data = .{
                    .stream_id = slot.stream,
                    .bytes = holder.chunk[slot.start..][0..slot.len],
                    .fin = slot.fin,
                    .peer = ip,
                    .now = now,
                } });
            }
        }
        holder.chunk_used = 0;
        if (holder.has_ack) {
            holder.has_ack = false;
            if (holder.handler.onAck) |f| f(holder.handler.ptr, holder, holder.acked_stream, holder.acked_len);
        }
        if (holder.has_stop) {
            holder.has_stop = false;
            if (holder.handler.onStopSending) |f| f(holder.handler.ptr, holder, holder.stop_stream, holder.stop_code);
        }
        for (&holder.resets) |*slot| {
            if (!slot.used) continue;
            slot.used = false;
            if (holder.handler.onStreamReset) |f| f(holder.handler.ptr, holder, slot.stream, slot.code);
        }
        for (&holder.closes) |*slot| {
            if (!slot.used) continue;
            slot.used = false;
            if (holder.handler.onStreamClose) |f| {
                f(holder.handler.ptr, holder, slot.stream);
            } else {
                holder.handler.onStream(holder.handler.ptr, holder, .{ .reset = .{ .stream_id = slot.stream } });
            }
        }
    }

    // (flushAll removed: step() pumps connections directly.)

    fn flushConnection(self: *Server, holder: *Connection, now: abi.tstamp) void {
        // Skip connections already in closing/draining: ngtcp2 forbids
        // further transmission for them, and anything emitted (e.g. a
        // close frame built from a half-dead state) decrypts as garbage.
        if (abi.conn_in_closing(holder.conn) != 0 or abi.conn_in_draining(holder.conn) != 0) {
            holder.doomed = true;
            return;
        }
        if (holder.handler.flush) |f| {
            f(holder.handler.ptr, self, holder, now);
            if (holder.pending.count == 0) {
                self.writeStream(holder, -1, &.{}, now);
            }
        }
        if (holder.pending.count == 0 and holder.handler.flush == null) {
            // No answers queued: still emit handshake/ACK-only packets.
            self.writeStream(holder, -1, &.{}, now);
            return;
        }
        // Write the head entry only; ngtcp2 accepts stream bytes only
        // once the handshake allows 1-RTT, so a short flush keeps the
        // entry queued and the next flush resumes where it stopped.
        while (holder.pending.count > 0) {
            const entry = &holder.pending.entries[0];
            if (entry.reset) {
                _ = abi.conn_shutdown_stream(holder.conn, 0, entry.stream_id, entry.error_code);
            } else {
                const before = entry.sent;
                self.writeStream(holder, entry.stream_id, entry.response[before..entry.response_len], now);
                if (entry.sent <= before) break;
            }
            if (entry.reset or entry.sent >= entry.response_len) {
                std.mem.copyForwards(PendingQueue.Entry, holder.pending.entries[0 .. holder.pending.count - 1], holder.pending.entries[1..holder.pending.count]);
                holder.pending.count -= 1;
            } else break;
        }
    }

    /// Emits one handshake/ACK datagram, or one answer chunk with FIN.
    /// Exactly one `conn_writev_stream` per call: bundling handshake and
    /// stream bytes across calls double-emits and corrupts the packet
    /// number space (the client's "incorrect reserved bits").
    fn writeStream(self: *Server, holder: *Connection, stream_id: i64, data: []const u8, now: abi.tstamp) void {
        const fresh = now;
        var pi = abi.pkt_info{ .ecn = 0 };
        var vecs: [1]abi.vec = undefined;
        var vcnt: usize = 0;
        if (data.len > 0) {
            vecs[0] = .{ .base = @constCast(data.ptr), .len = data.len };
            vcnt = 1;
        }
        // Crypto-only flushes carry no stream semantics; FIN there would
        // close stream -1. Answers are one-shot, so they take FIN.
        const flags: u32 = if (stream_id == -1) 0 else abi.WRITE_STREAM_FLAG_FIN;
        var ndatalen: abi.ssize = 0;
        const written = abi.conn_writev_stream(holder.conn, &holder.storage.path, abi.PKT_INFO_VERSION, &pi, &self.tx_buf, self.tx_buf.len, &ndatalen, flags, stream_id, if (vcnt > 0) &vecs else null, vcnt, fresh);
        if (written <= 0) {
            return;
        }
        if (ndatalen > 0) {
            // Find the head entry for this stream and advance it. The
            // flush writes entries in order, so the head is always the
            // stream just written.
            const entry = &holder.pending.entries[0];
            if (!entry.reset and entry.stream_id == stream_id) {
                entry.sent += @min(@as(usize, @intCast(ndatalen)), entry.response_len - entry.sent);
            }
        }
        self.sendTo(holder, self.tx_buf[0..@intCast(written)]);
    }

    // (writeH3Stream/nowTs removed: nghttp3 bytes go through sendDatagram;
    // timestamps come from step/readOne.)

    /// Sends a datagram produced outside `flushConnection` (nghttp3
    /// output). The caller owns flow-control accounting.
    pub fn sendDatagram(self: *Server, holder: *Connection, bytes: []const u8) void {
        self.sendRaw(bytes, &holder.peer_addr, holder.peer_len);
    }

    fn sendTo(self: *Server, holder: *Connection, bytes: []const u8) void {
        if (bytes.len == 0) return;
        self.sendRaw(bytes, &holder.peer_addr, holder.peer_len);
    }

    fn writeClose(self: *Server, holder: *Connection, code: u64, now: abi.tstamp) void {
        var pi = abi.pkt_info{ .ecn = 0 };
        const err = abi.ccerr{ .type = abi.CCERR_TYPE_TRANSPORT, .error_code = code, .frame_type = 0, .reason = null, .reasonlen = 0 };
        const written = abi.conn_write_connection_close(holder.conn, &holder.storage.path, abi.PKT_INFO_VERSION, &pi, &self.tx_buf, self.tx_buf.len, &err, now);
        if (written > 0) self.sendTo(holder, self.tx_buf[0..@intCast(written)]);
    }

    fn sendRetry(self: *Server, hd: *const abi.pkt_hd, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t, packet_len: usize, now: abi.tstamp) void {
        _ = packet_len;
        // Stateless Retry: fresh SCID per packet, fully stateless. A
        // retransmitted Initial gets a new Retry with a new token, and
        // the client's echo validates against whichever Retry it
        // answers — the token is HMAC-bound to the Retry SCID it was
        // minted with, so only the matching echo verifies. No map, no
        // eviction, no dedupe-key aliasing.
        var retry_scid = abi.cid{ .datalen = 18, .data = undefined };
        csprng().bytes(retry_scid.data[0..18]);
        var token_buf: [256]u8 = undefined;
        const token = self.secret.mint(&token_buf, hd.version, peer, peer_len, &retry_scid, &hd.dcid, now);
        if (token.len == 0) return;
        // A Retry must grow the client's Initial to 1200B; always emit a
        // full-size Retry so the follow-up Initial passes `ngtcp2_accept`.
        var buf: [1200]u8 = undefined;
        const written = abi.ngtcp2_crypto_write_retry(&buf, buf.len, hd.version, &hd.scid, &retry_scid, &hd.dcid, token.ptr, token.len);
        if (written <= 0) return;
        self.sendRaw(buf[0..@intCast(written)], peer, peer_len);
    }

    /// Stateless close for a bad token: CONNECTION_CLOSE with
    /// NO_ERROR costs no connection state (cf. server.cc stateless close).
    fn sendClose(self: *Server, hd: *const abi.pkt_hd, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t, now: abi.tstamp) void {
        _ = now;
        var scid: abi.cid = undefined;
        csprng().bytes(scid.data[0..8]);
        scid.datalen = 8;
        var buf: [256]u8 = undefined;
        const written = abi.ngtcp2_crypto_write_connection_close(&buf, buf.len, hd.version, &hd.scid, &scid, 0, null, 0);
        if (written <= 0) return;
        self.sendRaw(buf[0..@intCast(written)], peer, peer_len);
    }

    fn sendVersionNegotiation(self: *Server, dcid: [*c]const u8, dcidlen: usize, scid: [*c]const u8, scidlen: usize, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t) void {
        var rand_byte: [1]u8 = undefined;
        csprng().bytes(&rand_byte);
        const versions = [1]u32{abi.PROTO_VER_V1};
        const written = abi.pkt_write_version_negotiation(&self.tx_buf, self.tx_buf.len, rand_byte[0], dcid, dcidlen, scid, scidlen, &versions, versions.len);
        if (written <= 0) return;
        self.sendRaw(self.tx_buf[0..@intCast(written)], peer, peer_len);
    }

    fn sendRaw(self: *Server, bytes: []const u8, peer: *const std.posix.sockaddr.storage, peer_len: std.posix.socklen_t) void {
        _ = libc.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(peer), peer_len);
    }

    fn handleExpiries(self: *Server, now: abi.tstamp) void {
        // Snapshot first: the body reindexes/flushes, mutating the map.
        const count = self.conns.count();
        if (count == 0) return;
        const snapshot = self.allocator.alloc(*Connection, count) catch return;
        defer self.allocator.free(snapshot);
        var n: usize = 0;
        var it = self.conns.valueIterator();
        while (it.next()) |holder| {
            snapshot[n] = holder.*;
            n += 1;
        }
        for (snapshot[0..n]) |holder| {
            if (holder.conn == null) continue;
            if (abi.conn_get_expiry(holder.conn) <= now) {
                const rc = abi.conn_handle_expiry(holder.conn, now);
                if (rc == abi.ERR_IDLE_CLOSE) {
                    holder.doomed = true;
                } else if (rc != 0) {
                    self.writeClose(holder, @intCast(@abs(rc)), now);
                    holder.doomed = true;
                } else {
                    self.reindex(holder);
                    self.flushConnection(holder, now);
                }
            }
        }
    }

    /// Drops every doomed connection and all of its SCID aliases, so
    /// later packets create a fresh connection instead of feeding a
    /// half-closed one ngtcp2 would answer with undecryptable garbage.
    fn reapDoomed(self: *Server) void {
        // Destroy-during-iteration is unsafe, so find one doomed holder
        // per pass; O(n^2) worst case, fine for a reap path.
        while (true) {
            var found: ?*Connection = null;
            var it = self.conns.valueIterator();
            while (it.next()) |holder| {
                if (holder.*.doomed) {
                    found = holder.*;
                    break;
                }
            }
            const holder = found orelse break;
            self.unindexConnection(holder);
            destroyConnection(self.allocator, holder);
            self.conn_count -= 1;
        }
    }
};

fn destroyConnection(allocator: std.mem.Allocator, holder: *Connection) void {
    if (holder.handler.onClose) |f| f(holder.handler.ptr, holder);
    // Null first: GnuTLS alert/flush paths during conn_del re-enter
    // getConn through conn_ref, and must observe null, not a dying conn.
    const c = holder.conn;
    holder.conn = null;
    holder.conn_ref.user_data = null;
    if (c) |conn| abi.conn_del(conn);
    holder.session.deinit();
    allocator.destroy(holder);
}

fn nowNs(io: std.Io) abi.tstamp {
    // ngtcp2 wants a monotonic nanosecond base for token windows and
    // expiry arithmetic. `.awake` is CLOCK_UPTIME_RAW on Darwin (time
    // since boot, not epoch): the right monotonic base, and identical
    // at mint and verify within one process. `.real` (wall clock)
    // would also work but jumps with NTP.
    const ts = std.Io.Timestamp.now(io, .awake).nanoseconds;
    return @intCast(@max(ts, 0));
}

fn addrLen(storage: *const std.posix.sockaddr.storage) std.posix.socklen_t {
    return switch (storage.family) {
        std.posix.AF.INET => @sizeOf(std.posix.sockaddr.in),
        std.posix.AF.INET6 => @sizeOf(std.posix.sockaddr.in6),
        else => @sizeOf(std.posix.sockaddr.storage),
    };
}

fn ipToStorage(address: *const std.Io.net.IpAddress) std.posix.sockaddr.storage {
    var storage = std.mem.zeroes(std.posix.sockaddr.storage);
    switch (address.*) {
        .ip4 => |ip4| {
            const in: *std.posix.sockaddr.in = @ptrCast(@alignCast(&storage));
            if (@hasField(@TypeOf(in.*), "len")) in.len = @sizeOf(std.posix.sockaddr.in);
            in.family = std.posix.AF.INET;
            in.port = std.mem.nativeToBig(u16, address.getPort());
            in.addr = @bitCast(ip4.bytes);
        },
        .ip6 => |ip6| {
            const in6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
            if (@hasField(@TypeOf(in6.*), "len")) in6.len = @sizeOf(std.posix.sockaddr.in6);
            in6.family = std.posix.AF.INET6;
            in6.port = std.mem.nativeToBig(u16, address.getPort());
            @memcpy(@as(*[16]u8, @ptrCast(&in6.addr)), &ip6.bytes);
        },
    }
    return storage;
}

pub fn ipAddressFromStorage(storage: *const std.posix.sockaddr.storage) ?std.Io.net.IpAddress {
    if (storage.family == std.posix.AF.INET) {
        const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
        return .{ .ip4 = .{ .bytes = @bitCast(in.addr), .port = std.mem.bigToNative(u16, in.port) } };
    }
    if (storage.family == std.posix.AF.INET6) {
        const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
        const bytes: [16]u8 = @bitCast(in6.addr);
        const mapped_prefix: [12]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        if (std.mem.eql(u8, bytes[0..12], &mapped_prefix)) {
            var v4: [4]u8 = undefined;
            @memcpy(&v4, bytes[12..16]);
            return .{ .ip4 = .{ .bytes = v4, .port = std.mem.bigToNative(u16, in6.port) } };
        }
        return .{ .ip6 = .{ .bytes = bytes, .port = std.mem.bigToNative(u16, in6.port) } };
    }
    return null;
}

/// Copies stream bytes into the connection scratch; never writes. Any
/// chunk past the scratch cap (a datagram is at most 64k) dooms the
/// connection rather than corrupting a query.
fn recvStreamData(conn: ?*abi.conn_t, flags: u32, stream_id: i64, offset: u64, data: [*c]const u8, datalen: usize, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = stream_user_data;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    // DoQ queries arrive in one or two CRYPTO-sized chunks; accumulate at
    // the caller's offset instead of keeping only the last fragment.
    if (offset + datalen > holder.chunk.len) {
        holder.doomed = true;
        return 0;
    }
    // One slot per stream: find this stream's slot or take a free one,
    // appending contiguously (ngtcp2 delivers each stream in order).
    // Offsets only advance the tail; retransmitted overlap is dropped.
    var slot: ?*ChunkSlot = null;
    for (&holder.chunks) |*cand| {
        if (cand.used and cand.stream == stream_id) {
            slot = cand;
            break;
        }
    }
    if (slot == null) {
        for (&holder.chunks) |*cand| {
            if (!cand.used) {
                cand.* = .{ .stream = stream_id, .start = holder.chunk_used, .used = true };
                slot = cand;
                break;
            }
        }
    }
    const sl = slot orelse {
        holder.doomed = true;
        return 0;
    };
    const have: usize = sl.len;
    const off: usize = @intCast(offset);
    if (off > have) {
        // Gap (out-of-order): cannot place; doom rather than corrupt.
        holder.doomed = true;
        return 0;
    }
    const fresh: usize = if (off + datalen > have) off + datalen - have else 0;
    if (sl.start + sl.len + fresh > holder.chunk.len) {
        holder.doomed = true;
        return 0;
    }
    if (fresh > 0) {
        const tail_off = if (off < have) have - off else 0;
        @memcpy(holder.chunk[sl.start + sl.len ..][0..fresh], data[tail_off..][0..fresh]);
        sl.len += fresh;
        holder.chunk_used += fresh;
    }
    if (flags & abi.STREAM_DATA_FLAG_FIN != 0) sl.fin = true;
    return 0;
}

fn handshakeCompleted(conn: ?*abi.conn_t, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    holder.handshook = true;
    return 0;
}

fn ackedStreamData(conn: ?*abi.conn_t, stream_id: i64, offset: u64, datalen: u64, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = offset;
    _ = stream_user_data;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    holder.acked_stream = stream_id;
    holder.acked_len = datalen;
    holder.has_ack = true;
    return 0;
}

fn recvStopSending(conn: ?*abi.conn_t, stream_id: i64, app_error_code: u64, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = stream_user_data;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    holder.stop_stream = stream_id;
    holder.stop_code = app_error_code;
    holder.has_stop = true;
    return 0;
}

fn streamOpen(conn: ?*abi.conn_t, stream_id: i64, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    holder.opened_stream = stream_id;
    holder.has_open = true;
    return 0;
}

fn stashClose(holder: *Connection, stream_id: i64) void {
    // A stream that both resets and closes reports exactly once (reset
    // wins); dedupe repeat close frames for the same stream.
    for (&holder.resets) |*slot| {
        if (slot.used and slot.stream == stream_id) return;
    }
    for (&holder.closes) |*slot| {
        if (slot.used and slot.stream == stream_id) return;
    }
    for (&holder.closes) |*slot| {
        if (slot.used) continue;
        slot.* = .{ .stream = stream_id, .used = true };
        return;
    }
    holder.doomed = true;
}

fn stashReset(holder: *Connection, stream_id: i64, code: u64) void {
    // Reset wins over a queued close for the same stream: clear the
    // close so the handler sees one event, not two.
    for (&holder.closes) |*slot| {
        if (slot.used and slot.stream == stream_id) slot.used = false;
    }
    for (&holder.resets) |*slot| {
        if (slot.used and slot.stream == stream_id) {
            slot.code = code;
            return;
        }
    }
    for (&holder.resets) |*slot| {
        if (slot.used) continue;
        slot.* = .{ .stream = stream_id, .code = code, .used = true };
        return;
    }
    holder.doomed = true;
}

fn streamClose(conn: ?*abi.conn_t, flags: u32, stream_id: i64, rx: u64, tx: u64, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = flags;
    _ = rx;
    _ = tx;
    _ = stream_user_data;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    stashClose(holder, stream_id);
    return 0;
}

fn streamReset(conn: ?*abi.conn_t, stream_id: i64, final_size: u64, app_error_code: u64, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = final_size;
    _ = stream_user_data;
    const holder: *Connection = @ptrCast(@alignCast(user_data.?));
    stashReset(holder, stream_id, app_error_code);
    return 0;
}

/// The C-level crypto shims below only forward into the stateless
/// `ngtcp2_crypto_*` helpers: the packet bytes they protect never reach
/// this layer, so there is nothing to copy or retain.
fn bridgeEncrypt(dest: [*c]u8, aead: ?*const abi.crypto_aead, aead_ctx: ?*const abi.crypto_aead_ctx, plaintext: [*c]const u8, plaintextlen: usize, nonce: [*c]const u8, noncelen: usize, aad: [*c]const u8, aadlen: usize) callconv(.c) c_int {
    return abi.ngtcp2_crypto_encrypt_cb(dest, aead, aead_ctx, plaintext, plaintextlen, nonce, noncelen, aad, aadlen);
}

fn bridgeDecrypt(dest: [*c]u8, aead: ?*const abi.crypto_aead, aead_ctx: ?*const abi.crypto_aead_ctx, ciphertext: [*c]const u8, ciphertextlen: usize, nonce: [*c]const u8, noncelen: usize, aad: [*c]const u8, aadlen: usize) callconv(.c) c_int {
    return abi.ngtcp2_crypto_decrypt_cb(dest, aead, aead_ctx, ciphertext, ciphertextlen, nonce, noncelen, aad, aadlen);
}

fn bridgeHpMask(dest: [*c]u8, hp: ?*const abi.crypto_cipher, hp_ctx: ?*const abi.crypto_cipher_ctx, sample: [*c]const u8) callconv(.c) c_int {
    return abi.ngtcp2_crypto_hp_mask_cb(dest, hp, hp_ctx, sample);
}

fn randBytes(dest: [*c]u8, destlen: usize, ctx: ?*const abi.rand_ctx) callconv(.c) void {
    _ = ctx;
    if (destlen > 0) csprng().bytes(dest[0..destlen]);
}

fn getNewConnectionId(conn: ?*abi.conn_t, new_cid: ?*abi.cid, token: [*c]u8, cidlen: usize, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = user_data;
    const len = @min(cidlen, 18);
    csprng().bytes(new_cid.?.data[0..len]);
    new_cid.?.datalen = len;
    _ = abi.ngtcp2_crypto_generate_stateless_reset_token(token, &global_reset_secret, global_reset_secret.len, new_cid);
    return 0;
}

fn removeConnectionId(conn: ?*abi.conn_t, c: ?*const abi.cid, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = c;
    _ = user_data;
    return 0;
}

test "retry token verifies for the same address and fails for another" {
    var secret_bytes: [32]u8 = undefined;
    @memset(&secret_bytes, 7);
    const secret = TokenSecret{ .bytes = secret_bytes };
    var a = std.mem.zeroes(std.posix.sockaddr.storage);
    var b = std.mem.zeroes(std.posix.sockaddr.storage);
    a.family = std.posix.AF.INET;
    b.family = std.posix.AF.INET;
    const in_a: *std.posix.sockaddr.in = @ptrCast(@alignCast(&a));
    in_a.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
    const in_b: *std.posix.sockaddr.in = @ptrCast(@alignCast(&b));
    in_b.addr = @bitCast([4]u8{ 10, 0, 0, 1 });
    var scid = std.mem.zeroes(abi.cid);
    scid.datalen = 8;
    var odcid = std.mem.zeroes(abi.cid);
    odcid.datalen = 8;
    odcid.data[0] = 0x42;
    var buf: [256]u8 = undefined;
    const now: abi.tstamp = 999 * abi.SECONDS;
    const token = secret.mint(&buf, abi.PROTO_VER_V1, &a, @sizeOf(std.posix.sockaddr.in), &scid, &odcid, now);
    try std.testing.expect(token.len > 0);
    const recovered = secret.check(token, abi.PROTO_VER_V1, &a, @sizeOf(std.posix.sockaddr.in), &scid, now).?;
    try std.testing.expectEqualSlices(u8, odcid.data[0..odcid.datalen], recovered.data[0..recovered.datalen]);
    try std.testing.expect(secret.check(token, abi.PROTO_VER_V1, &b, @sizeOf(std.posix.sockaddr.in), &scid, now) == null);
    try std.testing.expect(secret.check(token, abi.PROTO_VER_V1, &a, @sizeOf(std.posix.sockaddr.in), &scid, now + 10 * abi.SECONDS) != null);
    try std.testing.expect(secret.check(token, abi.PROTO_VER_V1, &a, @sizeOf(std.posix.sockaddr.in), &scid, now + 11 * abi.SECONDS) == null);
    try std.testing.expectEqual(@as(u64, 1_000_000_000), abi.SECONDS);
    try std.testing.expectEqual(@as(u64, 1_000_000), abi.MILLISECONDS);
}

test "pending queue answers and resets without growing" {
    var queue = PendingQueue{};
    queue.answer(0, &.{ 0xde, 0xad }, 0x2);
    queue.resetStream(4, 0x2);
    try std.testing.expectEqual(@as(usize, 2), queue.count);
    try std.testing.expect(!queue.entries[0].reset);
    try std.testing.expectEqual(@as(usize, 2), queue.entries[0].response_len);
    try std.testing.expect(queue.entries[1].reset);
}
