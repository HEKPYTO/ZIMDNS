/// Contract: Serves the RFC 8484 DNS-over-HTTPS message mapping (GET
/// /dns-query?dns=<base64url> and POST /dns-query with application/dns-message
/// bodies) over HTTP/3 on nghttp3 over the ngtcp2 core in
/// `ngtcp2_server.zig`, reusing the RFC 8484 mapping in `doh.zig` so the
/// parsing rules cannot drift apart. The handshake selects the `h3` ALPN
/// token before any DNS byte is written, so the port never answers in
/// cleartext. One exchange per stream: a GET is answered at its headers,
/// a POST is answered when its body ends. Plain answers use content-type
/// application/dns-message and cache-control max-age=<TTL>, the freshness
/// lifetime the HTTP/1.1 channel computes; Oblivious DoH answers use the
/// oblivious media type with cache-control no-store. A missing :method or
/// :path, a wrong path, a wrong method, a wrong media type, or a malformed
/// base64url/DNS message is an HTTP status, never a resolver error.
/// Ownership: Runtime is borrowed; nghttp3 state lives per core
/// connection and is freed when the connection is destroyed; per-stream
/// state is freed when the stream ends; scratch lives in per-request
/// arenas.
/// Errors: HTTP mapping failures map to HTTP status codes and never reach
/// the resolver; malformed streams are reset where the handler cannot
/// answer them.
const std = @import("std");
const runtime_mod = @import("../auth/runtime.zig");
const Runtime = runtime_mod.Runtime;
const SharedStop = runtime_mod.SharedStop;
const cli_query = @import("../cli/query.zig");
const metrics = @import("../metrics.zig");
const dns_message = @import("../dns/message.zig");
const dns_padding = @import("../dns/padding.zig");
const listener = @import("../platform/listener.zig");
const tls_policy = @import("tls.zig");
const StreamRegistry = @import("stream_registry.zig");
const doh = @import("doh.zig");
const odoh = @import("../dns/odoh.zig");
const core = @import("ngtcp2_server.zig");
const gnutls = @import("gnutls_server.zig");
const abi = @import("ngtcp2_abi.zig");
const h3abi = @import("nghttp3_abi.zig");

/// The IANA ALPN protocol ID for HTTP/3. The handshake selects exactly
/// this token, so the port never serves another protocol and a client
/// that offers no common token is refused.
pub const DOH3_ALPN = "h3";
/// The HTTPS default port, the same default DoH binds.
pub const DOH3_PORT = tls_policy.doh_port;
pub const MAX_BODY_LEN: usize = doh.MAX_BODY_LEN;
pub const MAX_HEADER_BYTES: usize = doh.MAX_HEADER_BYTES;
/// Live streams one connection may hold; the registry enforces this cap per
/// connection id, so worst case per port is MAX_CONNECTIONS * MAX_STREAMS (512).
pub const MAX_STREAMS: usize = core.Server.MAX_STREAMS_PER_CONN;

/// One request stream's state. The header rcbufs nghttp3 hands to the
/// callbacks die when the callback returns, so everything the handler
/// needs past that point is copied here. `respond_now` stages the
/// answer decision: callbacks never submit responses or write packets,
/// the dispatch loop answers after nghttp3 returns.
const StreamState = struct {
    method: [8]u8 = undefined,
    method_len: usize = 0,
    target: [2048]u8 = undefined,
    target_len: usize = 0,
    content_type: [64]u8 = undefined,
    content_type_len: usize = 0,
    has_content_type: bool = false,
    head_bytes: usize = 0,
    head_too_large: bool = false,
    duplicate: bool = false,
    seen_method: bool = false,
    seen_path: bool = false,
    answered: bool = false,
    body: [MAX_BODY_LEN]u8 = undefined,
    body_len: usize = 0,
    respond_now: bool = false,
    post_end: bool = false,
    response: [MAX_BODY_LEN]u8 = undefined,
    response_len: usize = 0,
    response_sent: usize = 0,
    response_ready: bool = false,
    is_odoh: bool = false,
    max_age: u32 = 0,
};

/// The per-stream memory each DoH3 request stream can pin. The budget
/// test in this file sizes the QUIC worst case from this constant.
pub const STREAM_STATE_SIZE: usize = @sizeOf(StreamState);
/// Per-connection nghttp3 state. Created on handshake, destroyed with
/// the core connection.
const H3Conn = struct {
    h3: ?*h3abi.conn_t,
};

const Doh3Handler = struct {
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    io: std.Io,
    counters: ?*metrics.Counters,
    max_requests: ?usize,
    odoh_target: ?*const odoh.Target = null,
    completed: usize = 0,
    streams: StreamRegistry.Registry(StreamState) = .{ .max_entries = MAX_STREAMS },
    conns: std.AutoHashMapUnmanaged(u64, *H3Conn) = .empty,
    active: ?*core.Connection = null,

    fn destroyState(allocator: std.mem.Allocator, state: *StreamState) void {
        allocator.destroy(state);
    }

    fn keyFor(conn: *const core.Connection, stream_id: i64) StreamRegistry.Key {
        return .{ .connection = @intFromPtr(conn), .stream = @bitCast(stream_id) };
    }

    fn stateForId(self: *Doh3Handler, conn: *const core.Connection, stream_id: i64) ?*StreamState {
        return self.streams.get(keyFor(conn, stream_id));
    }

    fn ensureState(self: *Doh3Handler, conn: *const core.Connection, stream_id: i64) ?*StreamState {
        if (self.stateForId(conn, stream_id)) |s| return s;
        const owned = self.allocator.create(StreamState) catch return null;
        owned.* = .{};
        self.streams.insert(self.allocator, keyFor(conn, stream_id), owned) catch {
            self.allocator.destroy(owned);
            return null;
        };
        return owned;
    }

    fn dropState(self: *Doh3Handler, conn: *const core.Connection, stream_id: i64) void {
        const had = self.streams.get(keyFor(conn, stream_id)) != null;
        self.streams.removeOne(self.allocator, keyFor(conn, stream_id), destroyState);
        if (self.getH3(conn)) |h3conn| {
            _ = h3abi.nghttp3_conn_set_stream_user_data(h3conn.h3, stream_id, null);
            _ = h3abi.nghttp3_conn_close_stream2(h3conn.h3, 0, stream_id, 0, 0);
        }
        // One credit per actually-closed client bidi stream: uni streams
        // and missing entries grant nothing, and reset+close can no
        // longer double-grant since the second drop finds no entry.
        if (had and @as(u64, @bitCast(stream_id)) & 0x3 == 0) abi.conn_extend_max_streams_bidi(conn.conn, 1);
    }

    fn onClose(ctx: *anyopaque, conn: *core.Connection) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        const id: u64 = @intFromPtr(conn);
        self.streams.removeConnection(self.allocator, id, destroyState);
        if (self.conns.fetchRemove(id)) |kv| {
            if (kv.value.h3) |c| h3abi.nghttp3_conn_del(c);
            self.allocator.destroy(kv.value);
        }
    }

    fn getH3(self: *Doh3Handler, conn: *const core.Connection) ?*H3Conn {
        return self.conns.get(@intFromPtr(conn));
    }

    fn onHandshake(ctx: *anyopaque, conn: *core.Connection) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        // The ports serve exactly one ALPN each, configured on the
        // TLS session before the handshake runs; the core refreshes the
        // mirror once the handshake completes. A mismatch here means
        // the client offered no common token, so doom the connection.
        const got = conn.session.alpn[0..conn.session.alpn_len];
        if (!std.mem.eql(u8, got, DOH3_ALPN)) {
            conn.doomed = true;
            return;
        }
        const h3conn = self.allocator.create(H3Conn) catch {
            conn.doomed = true;
            return;
        };
        var settings = std.mem.zeroes(h3abi.settings);
        h3abi.settings_default(h3abi.SETTINGS_VERSION, &settings);
        settings.qpack_max_dtable_capacity = 4096;
        settings.qpack_blocked_streams = 100;
        settings.max_field_section_size = MAX_HEADER_BYTES;
        settings.qpack_encoder_max_dtable_capacity = 4096;
        var cbs = std.mem.zeroes(h3abi.callbacks);
        cbs.begin_headers = h3BeginHeaders;
        cbs.recv_header = h3RecvHeader;
        cbs.end_headers = h3EndHeaders;
        cbs.recv_data = h3RecvData;
        cbs.deferred_consume = h3DeferredConsume;
        cbs.end_stream = h3EndStream;
        cbs.acked_stream_data = h3AckedData;
        cbs.stop_sending = h3StopSending;
        cbs.reset_stream = h3ResetStream;
        cbs.stream_close2 = h3StreamClose;
        cbs.rand = h3Rand;
        var h3: ?*h3abi.conn_t = null;
        if (h3abi.conn_server_new(&h3, h3abi.CALLBACKS_VERSION, &cbs, h3abi.SETTINGS_VERSION, &settings, null, self) != 0 or h3 == null) {
            self.allocator.destroy(h3conn);
            conn.doomed = true;
            return;
        }
        h3conn.h3 = h3;
        h3abi.nghttp3_conn_set_max_client_streams_bidi(h3, MAX_STREAMS);
        h3abi.nghttp3_conn_set_max_concurrent_streams(h3, MAX_STREAMS + 8);
        self.conns.put(self.allocator, @intFromPtr(conn), h3conn) catch {
            h3abi.nghttp3_conn_del(h3);
            self.allocator.destroy(h3conn);
            conn.doomed = true;
            return;
        };
        var control: i64 = 0;
        if (abi.conn_open_uni_stream(conn.conn, &control, null) != 0) return;
        if (h3abi.nghttp3_conn_bind_control_stream(h3, control) != 0) return;
        var qenc: i64 = 0;
        var qdec: i64 = 0;
        if (abi.conn_open_uni_stream(conn.conn, &qenc, null) != 0) return;
        if (abi.conn_open_uni_stream(conn.conn, &qdec, null) != 0) return;
        if (h3abi.nghttp3_conn_bind_qpack_streams(h3, qenc, qdec) != 0) return;
    }

    fn onStreamClose(ctx: *anyopaque, conn: *core.Connection, stream_id: i64) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        if (self.getH3(conn)) |h3conn| {
            _ = h3abi.nghttp3_conn_close_stream2(h3conn.h3, 0, stream_id, 0, 0);
        }
        self.dropState(conn, stream_id);
    }

    fn onStreamReset(ctx: *anyopaque, conn: *core.Connection, stream_id: i64, code: u64) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        _ = code;
        if (self.getH3(conn)) |h3conn| {
            _ = h3abi.nghttp3_conn_close_stream2(h3conn.h3, 0, stream_id, 0, 0);
        }
        self.dropState(conn, stream_id);
    }

    fn onStopSending(ctx: *anyopaque, conn: *core.Connection, stream_id: i64, code: u64) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        _ = code;
        if (self.getH3(conn)) |h3conn| {
            _ = h3abi.nghttp3_conn_close_stream2(h3conn.h3, 0, stream_id, 0, 0);
        }
        self.dropState(conn, stream_id);
    }

    fn onAck(ctx: *anyopaque, conn: *core.Connection, stream_id: i64, datalen: u64) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        const h3conn = self.getH3(conn) orelse return;
        _ = h3abi.nghttp3_conn_add_ack_offset(h3conn.h3, stream_id, datalen);
        // Newly acked bytes reopen the flow-control window a blocked
        // stream was waiting on; resume it so nghttp3 re-offers the
        // bytes instead of stalling a small-window client.
        _ = h3abi.nghttp3_conn_resume_stream(h3conn.h3, stream_id);
    }

    fn onStream(ctx: *anyopaque, conn: *core.Connection, event: core.StreamEvent) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        switch (event) {
            .reset => |r| Doh3Handler.onStreamReset(ctx, conn, r.stream_id, 0),
            .data => |d| self.onStreamData(conn, d.stream_id, d.bytes, d.fin, d.now),
        }
    }

    fn withActive(self: *Doh3Handler, conn: *core.Connection, stream_id: i64, data: []const u8, fin: bool, now: h3abi.tstamp) isize {
        self.active = conn;
        defer self.active = null;

        var empty: u8 = 0;
        const ptr: [*c]const u8 = if (data.len > 0) data.ptr else @as([*c]const u8, @ptrCast(&empty));
        const h3conn = self.getH3(conn) orelse return -1;
        const n = h3abi.nghttp3_conn_read_stream2(h3conn.h3, stream_id, ptr, data.len, if (fin) @as(c_int, 1) else 0, now);

        return n;
    }

    fn onStreamData(self: *Doh3Handler, conn: *core.Connection, stream_id: i64, data: []const u8, fin: bool, now: abi.tstamp) void {
        const is_bidi = @as(u64, @bitCast(stream_id)) & 0x3 == 0;
        const n = self.withActive(conn, stream_id, data, fin, now);
        _ = abi.conn_extend_max_stream_offset(conn.conn, stream_id, data.len);
        abi.conn_extend_max_offset(conn.conn, data.len);
        if (!is_bidi) {
            // Control/QPACK decode failures are connection-fatal in
            // HTTP/3; doom rather than serve half-decoded requests.
            if (n < 0 and n != h3abi.ERR_WOULDBLOCK) conn.doomed = true;
            return;
        }
        if (n < 0) {
            conn.pending.resetStream(stream_id, 0x105);
            self.pumpAnswers(conn);
            return;
        }
        self.pumpAnswers(conn);
    }

    /// Runs every staged answer decision: submit the response, or reset
    /// the stream when the request is unanswerable.
    fn pumpAnswers(self: *Doh3Handler, conn: *core.Connection) void {
        var it = self.streams.map.iterator();
        while (it.next()) |kv| {
            if (kv.key_ptr.connection != @intFromPtr(conn)) continue;
            const state = kv.value_ptr.*;
            if (!state.respond_now or state.answered) continue;
            const stream_id: i64 = @bitCast(kv.key_ptr.stream);
            self.answer(conn, stream_id, state);
        }
    }

    fn flushConn(ctx: *anyopaque, server: *core.Server, conn: *core.Connection, now: abi.tstamp) void {
        const self: *Doh3Handler = @ptrCast(@alignCast(ctx));
        const h3conn = self.getH3(conn) orelse return;
        self.pumpAnswers(conn);
        var vecs: [16]h3abi.vec = undefined;
        var qvecs: [16]abi.vec = undefined;
        while (true) {
            var out_sid: i64 = -1;
            var out_fin: c_int = 0;
            const nvec = h3abi.nghttp3_conn_writev_stream(h3conn.h3, &out_sid, &out_fin, &vecs, vecs.len);
            if (nvec <= 0 or out_sid < 0) break;
            const count: usize = @intCast(nvec);
            for (vecs[0..count], 0..) |v, i| qvecs[i] = .{ .base = v.base, .len = v.len };
            var pi = abi.pkt_info{ .ecn = 0 };
            const flags: u32 = if (out_fin != 0) abi.WRITE_STREAM_FLAG_FIN else abi.WRITE_STREAM_FLAG_NONE;
            var ndatalen: abi.ssize = 0;
            var tx_buf: [65527]u8 = undefined;
            const written = abi.conn_writev_stream(conn.conn, &conn.storage.path, abi.PKT_INFO_VERSION, &pi, &tx_buf, tx_buf.len, &ndatalen, flags, out_sid, if (count > 0) &qvecs else null, count, now);
            if (written < 0) {
                // STREAM_DATA_BLOCKED (no flow-control window) and
                // WRITE_MORE (packet full, stream bytes pending): tell
                // nghttp3 the stream is blocked so it re-offers the
                // bytes on the next writev_stream pass.
                if (written == abi.ERR_STREAM_DATA_BLOCKED or written == abi.ERR_WRITE_MORE) h3abi.nghttp3_conn_block_stream(h3conn.h3, out_sid);
                // Transient errors: stop this pass, the next pump
                // resumes.
                break;
            }
            if (written == 0) break;
            if (ndatalen >= 0) _ = h3abi.nghttp3_conn_add_write_offset(h3conn.h3, out_sid, @intCast(@max(ndatalen, 0)));
            server.sendDatagram(conn, tx_buf[0..@intCast(written)]);
            if (ndatalen == 0 and out_fin == 0) break;
        }
    }

    fn answer(self: *Doh3Handler, conn: *core.Connection, stream_id: i64, state: *StreamState) void {
        state.answered = true;
        state.respond_now = false;
        const h3conn = self.getH3(conn) orelse return;
        // GET answers on end_headers (no body); POST answers on end_stream.
        const is_get = state.method_len == 3 and std.mem.eql(u8, state.method[0..3], "GET");
        const is_post = state.method_len == 4 and std.mem.eql(u8, state.method[0..4], "POST");
        const body = state.body[0..state.body_len];
        const target = state.target[0..state.target_len];
        const ct: ?[]const u8 = if (state.has_content_type) state.content_type[0..state.content_type_len] else null;
        if (state.head_too_large) return self.submitStatus(h3conn, conn, stream_id, state, .request_header_fields_too_large);
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        if (!state.seen_method or !state.seen_path or state.duplicate) {
            return self.submitStatus(h3conn, conn, stream_id, state, .bad_request);
        }
        if (!is_get and !is_post) {
            return self.submitStatus(h3conn, conn, stream_id, state, .method_not_allowed);
        }
        if (is_get) return self.answerQuery(h3conn, conn, stream_id, state, arena.allocator(), target, null, false);
        // POST body already bounded at recv_data time.
        if (ct != null and std.mem.eql(u8, ct.?, doh.odoh_media_type)) {
            return self.answerOdoh(h3conn, conn, stream_id, state, arena.allocator(), body);
        }
        return self.answerQuery(h3conn, conn, stream_id, state, arena.allocator(), target, ct, true);
    }

    fn answerQuery(self: *Doh3Handler, h3conn: *H3Conn, conn: *core.Connection, stream_id: i64, state: *StreamState, arena: std.mem.Allocator, target: []const u8, ct: ?[]const u8, is_post: bool) void {
        const qbody: []u8 = @constCast(state.body[0..state.body_len]);
        const query = doh.dnsQueryFromParts(arena, !is_post, is_post, target, ct, qbody) catch |err| {
            return self.submitStatus(h3conn, conn, stream_id, state, doh.statusForError(err));
        };
        const request_message = dns_message.Message.parseQuery(arena, query) catch {
            return self.submitStatus(h3conn, conn, stream_id, state, .bad_request);
        };
        const peer = core.ipAddressFromStorage(&conn.peer_addr) orelse {
            return self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
        };
        _ = self.runtime.tryMaintenanceTick(self.io);
        const response_buffer = arena.alloc(u8, MAX_BODY_LEN) catch {
            return self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
        };
        if (self.counters) |counters| metrics.bump(&counters.doh3_queries_total);
        const response_bytes = self.runtime.answerFromTcp(query, response_buffer, &peer, self.counters) catch |err| {
            return self.submitStatus(h3conn, conn, stream_id, state, if (err == error.BadQuery) .bad_request else .internal_error);
        };
        const answer_bytes = (dns_padding.padResponse(arena, &request_message, response_bytes) catch {
            return self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
        }) orelse response_bytes;
        const response_message = dns_message.Message.parse(arena, answer_bytes) catch {
            return self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
        };
        self.submitOk(h3conn, conn, stream_id, state, answer_bytes, doh.minTtl(&response_message), false);
        self.completed += 1;
    }

    fn answerOdoh(self: *Doh3Handler, h3conn: *H3Conn, conn: *core.Connection, stream_id: i64, state: *StreamState, arena: std.mem.Allocator, body: []const u8) void {
        const t = self.odoh_target orelse {
            self.submitStatus(h3conn, conn, stream_id, state, .not_found);
            self.completed += 1;
            return;
        };
        const opened = odoh.openQuery(arena, t, body) catch |err| {
            self.submitStatus(h3conn, conn, stream_id, state, if (err == error.UnknownKeyId) .unauthorized else .bad_request);
            self.completed += 1;
            return;
        };
        const request_message = dns_message.Message.parseQuery(arena, opened.dns_query) catch {
            self.submitStatus(h3conn, conn, stream_id, state, .bad_request);
            self.completed += 1;
            return;
        };
        const peer = core.ipAddressFromStorage(&conn.peer_addr) orelse {
            self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
            self.completed += 1;
            return;
        };
        _ = self.runtime.tryMaintenanceTick(self.io);
        const response_buffer = arena.alloc(u8, MAX_BODY_LEN) catch {
            self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
            self.completed += 1;
            return;
        };
        if (self.counters) |counters| metrics.bump(&counters.doh3_queries_total);
        const response_bytes = self.runtime.answerFromTcp(opened.dns_query, response_buffer, &peer, self.counters) catch |err| {
            self.submitStatus(h3conn, conn, stream_id, state, if (err == error.BadQuery) .bad_request else .internal_error);
            self.completed += 1;
            return;
        };
        const padded = (dns_padding.padResponse(arena, &request_message, response_bytes) catch {
            self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
            self.completed += 1;
            return;
        }) orelse response_bytes;
        const sealed = odoh.sealResponse(arena, self.io, opened.exporter_secret, opened.q_plain, padded) catch {
            self.submitStatus(h3conn, conn, stream_id, state, .internal_error);
            self.completed += 1;
            return;
        };
        self.submitOk(h3conn, conn, stream_id, state, sealed, 0, true);
        self.completed += 1;
    }

    fn submitStatus(self: *Doh3Handler, h3conn: *H3Conn, conn: *core.Connection, stream_id: i64, state: *StreamState, status: doh.Status) void {
        var text: [4]u8 = undefined;
        const value = std.fmt.bufPrint(&text, "{d}", .{@backingInt(status)}) catch unreachable;
        const nva = [_]h3abi.nv{
            .{ .name = ":status", .namelen = 7, .value = value.ptr, .valuelen = value.len, .flags = h3abi.NV_FLAG_NEVER_INDEX },
        };
        const allow: []const u8 = "GET, POST";
        var n: usize = 1;
        var nva_full: [2]h3abi.nv = undefined;
        nva_full[0] = nva[0];
        if (status == .method_not_allowed) {
            nva_full[1] = .{ .name = "allow", .namelen = 5, .value = allow.ptr, .valuelen = allow.len, .flags = h3abi.NV_FLAG_NEVER_INDEX };
            n = 2;
        }
        state.response_ready = false;
        state.answered = true;
        _ = h3abi.nghttp3_conn_submit_response(h3conn.h3, stream_id, &nva_full, n, null);
        _ = conn;

        self.completed += 1;
    }

    fn submitOk(self: *Doh3Handler, h3conn: *H3Conn, conn: *core.Connection, stream_id: i64, state: *StreamState, body: []const u8, max_age: u32, is_odoh: bool) void {
        const take = @min(body.len, state.response.len);
        @memcpy(state.response[0..take], body[0..take]);
        state.response_len = take;
        state.response_sent = 0;
        state.response_ready = true;
        state.is_odoh = is_odoh;
        state.max_age = max_age;
        const status_text: []const u8 = "200";
        var cc_buf: [32]u8 = undefined;
        const cc: []const u8 = if (is_odoh) "no-store" else std.fmt.bufPrint(&cc_buf, "max-age={d}", .{max_age}) catch "max-age=0";
        const ct: []const u8 = if (is_odoh) doh.odoh_media_type else doh.dns_message_media_type;
        const nva = [_]h3abi.nv{
            .{ .name = ":status", .namelen = 7, .value = status_text.ptr, .valuelen = status_text.len, .flags = h3abi.NV_FLAG_NEVER_INDEX },
            .{ .name = "content-type", .namelen = 12, .value = ct.ptr, .valuelen = ct.len, .flags = h3abi.NV_FLAG_NEVER_INDEX },
            .{ .name = "cache-control", .namelen = 13, .value = cc.ptr, .valuelen = cc.len, .flags = h3abi.NV_FLAG_NEVER_INDEX },
        };
        var reader = h3abi.data_reader{ .read_data = h3ReadData };
        _ = h3abi.nghttp3_conn_set_stream_user_data(h3conn.h3, stream_id, state);
        _ = h3abi.nghttp3_conn_submit_response(h3conn.h3, stream_id, &nva, nva.len, &reader);

        _ = self;
        _ = conn;
    }
};

/// The nghttp3 body reader: serves the response staged in StreamState.
/// Runs inside `writev_stream` during our own flush, never inside an
/// ngtcp2 callback.
fn h3ReadData(h3: ?*h3abi.conn_t, stream_id: i64, vec: [*c]h3abi.vec, veccnt: usize, pflags: [*c]u32, conn_user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) isize {
    _ = h3;
    _ = stream_id;
    _ = conn_user_data;
    if (veccnt == 0) return 0;
    const state: *StreamState = @ptrCast(@alignCast(stream_user_data orelse return h3abi.ERR_WOULDBLOCK));
    if (!state.response_ready) return h3abi.ERR_WOULDBLOCK;
    if (state.response_sent >= state.response_len) {
        pflags.* |= h3abi.DATA_FLAG_EOF;
        return 0;
    }
    vec[0].base = state.response[state.response_sent..].ptr;
    vec[0].len = state.response_len - state.response_sent;
    state.response_sent = state.response_len;
    pflags.* |= h3abi.DATA_FLAG_EOF;
    return 1;
}

fn rcbufBytes(rc: ?*h3abi.rcbuf_t) []const u8 {
    if (rc == null) return &.{};
    const v = h3abi.nghttp3_rcbuf_get_buf(rc);
    if (v.len == 0) return &.{};
    return v.base[0..v.len];
}

fn h3Lookup(handler: *Doh3Handler, stream_id: i64) ?*StreamState {
    const conn = handler.active orelse return null;
    return handler.ensureState(conn, stream_id);
}

fn h3BeginHeaders(_: ?*h3abi.conn_t, _: i64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3RecvHeader(_: ?*h3abi.conn_t, stream_id: i64, _: i32, name: ?*h3abi.rcbuf_t, value: ?*h3abi.rcbuf_t, _: u8, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    const handler: *Doh3Handler = @ptrCast(@alignCast(conn_user_data orelse return 0));
    const state = h3Lookup(handler, stream_id) orelse return 0;
    const n = rcbufBytes(name);
    const v = rcbufBytes(value);
    state.head_bytes += n.len + v.len + 2;
    if (state.head_bytes > MAX_HEADER_BYTES) {
        state.head_too_large = true;
        return 0;
    }
    if (std.mem.eql(u8, n, ":method")) {
        if (state.seen_method) state.duplicate = true;
        state.seen_method = true;
        const take = @min(v.len, state.method.len);
        @memcpy(state.method[0..take], v[0..take]);
        state.method_len = take;
    } else if (std.mem.eql(u8, n, ":path")) {
        if (state.seen_path) state.duplicate = true;
        state.seen_path = true;
        const take = @min(v.len, state.target.len);
        @memcpy(state.target[0..take], v[0..take]);
        state.target_len = take;
        if (take != v.len) state.head_too_large = true;
    } else if (n.len == 12 and std.ascii.eqlIgnoreCase(n, "content-type")) {
        if (state.has_content_type) state.duplicate = true;
        state.has_content_type = true;
        const take = @min(v.len, state.content_type.len);
        @memcpy(state.content_type[0..take], v[0..take]);
        state.content_type_len = take;
        if (take != v.len) state.head_too_large = true;
    }
    return 0;
}

fn h3EndHeaders(_: ?*h3abi.conn_t, stream_id: i64, fin: c_int, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    const handler: *Doh3Handler = @ptrCast(@alignCast(conn_user_data orelse return 0));
    const state = h3Lookup(handler, stream_id) orelse return 0;
    const is_get = state.method_len == 3 and std.mem.eql(u8, state.method[0..3], "GET");
    if (is_get or fin != 0) state.respond_now = true;
    return 0;
}

fn h3RecvData(_: ?*h3abi.conn_t, stream_id: i64, data: [*c]const u8, datalen: usize, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    const handler: *Doh3Handler = @ptrCast(@alignCast(conn_user_data orelse return 0));
    const state = h3Lookup(handler, stream_id) orelse return 0;
    if (state.answered) return 0;
    if (state.body_len + datalen > MAX_BODY_LEN) {
        state.head_too_large = true;
        state.respond_now = true;
        return 0;
    }
    if (datalen > 0) @memcpy(state.body[state.body_len..][0..datalen], data[0..datalen]);
    state.body_len += datalen;
    return 0;
}

fn h3DeferredConsume(_: ?*h3abi.conn_t, _: i64, _: usize, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3EndStream(_: ?*h3abi.conn_t, stream_id: i64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    const handler: *Doh3Handler = @ptrCast(@alignCast(conn_user_data orelse return 0));
    const state = h3Lookup(handler, stream_id) orelse return 0;
    state.post_end = true;
    state.respond_now = true;
    return 0;
}

fn h3AckedData(_: ?*h3abi.conn_t, _: i64, _: u64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3StopSending(_: ?*h3abi.conn_t, _: i64, _: u64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3ResetStream(_: ?*h3abi.conn_t, _: i64, _: u64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3StreamClose(_: ?*h3abi.conn_t, _: u32, _: i64, _: u64, _: u64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
    return 0;
}

fn h3Rand(dest: [*c]u8, destlen: usize) callconv(.c) void {
    // QPACK seed material; the Io CSPRNG never fails, fall back to
    // zeros only if the platform reports no entropy source.
    if (destlen == 0) return;
    std.Io.Threaded.global_single_threaded.io().random(dest[0..destlen]);
}

/// Binds the DoH/3 port and serves DNS-over-HTTPS over HTTP/3. The
/// handshake selects the `h3` ALPN token before any DNS byte is
/// written, so the port never answers cleartext DNS.
pub fn serveDoh3LoopOnAddress(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    cert_path: []const u8,
    key_path: []const u8,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
    odoh_target: ?*const odoh.Target,
) !void {
    return serveDoh3LoopOnAddressStop(io, runtime, address, cert_path, key_path, max_requests, counters, odoh_target, null);
}

/// Stop-aware DoH3 loop: `stop` ends the loop at the core's next boundary
/// even with no `max_requests`, so a failing sibling loop ends this one.
pub fn serveDoh3LoopOnAddressStop(
    io: std.Io,
    runtime: *Runtime,
    address: *const std.Io.net.IpAddress,
    cert_path: []const u8,
    key_path: []const u8,
    max_requests: ?usize,
    counters: ?*metrics.Counters,
    odoh_target: ?*const odoh.Target,
    shared_stop: ?*const SharedStop,
) !void {
    const allocator = std.heap.page_allocator;
    var creds = gnutls.ServerCredentials.load(cert_path, key_path) catch return error.TlsIdentityFailed;
    defer creds.deinit();
    var handler = Doh3Handler{
        .allocator = allocator,
        .runtime = runtime,
        .io = io,
        .counters = counters,
        .max_requests = max_requests,
        .odoh_target = odoh_target,
    };
    defer handler.streams.deinit(allocator, Doh3Handler.destroyState);
    defer {
        var it = handler.conns.valueIterator();
        while (it.next()) |h| {
            if (h.*.h3) |c| h3abi.nghttp3_conn_del(c);
            allocator.destroy(h.*);
        }
        handler.conns.deinit(allocator);
    }
    const core_handler = core.Handler{
        .ptr = &handler,
        .onStream = Doh3Handler.onStream,
        .onHandshake = Doh3Handler.onHandshake,
        .onStreamClose = Doh3Handler.onStreamClose,
        .onStreamReset = Doh3Handler.onStreamReset,
        .onAck = Doh3Handler.onAck,
        .onStopSending = Doh3Handler.onStopSending,
        .flush = Doh3Handler.flushConn,
    };
    const State = struct {
        handler: *Doh3Handler,
        shared: ?*const SharedStop,
        fn stop(ctx: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.shared) |shared| if (shared.shouldStop()) return true;
            if (self.handler.max_requests) |max| return self.handler.completed >= max;
            return false;
        }
    };
    var state = State{ .handler = &handler, .shared = shared_stop };
    try core.serve(allocator, io, address, &creds, core_handler, State.stop, &state, 30 * 1_000_000_000, DOH3_ALPN);
}

/// Handler-level mapping tests below drive `answer` through the same
/// `dnsQueryFromParts` + `statusForError` seam `answerQuery` uses, so the
/// status rules cannot drift from the HTTP/1.1 channel without a test
/// failing. Transport proof (a real H3 client speaking to this server)
/// lives in `test/interop/harness.py::check_doh3`, which exercises 200
/// GET/POST, 404/405/415/400, ODoH 200, and the cleartext no-answer rule.
const MapCase = struct {
    method_is_get: bool,
    method_is_post: bool,
    target: []const u8,
    content_type: ?[]const u8,
    body_len: usize,
};
fn mapStatus(case: MapCase, dns_ok: bool) doh.Status {
    var body_storage: [2]u8 = .{ 0, 0 };
    const body = body_storage[0..@min(case.body_len, body_storage.len)];
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const query = doh.dnsQueryFromParts(arena.allocator(), case.method_is_get, case.method_is_post, case.target, case.content_type, body) catch |err| {
        return doh.statusForError(err);
    };
    _ = query;
    if (!dns_ok) return .bad_request;
    return .ok;
}

test "DoH/3 mapping: GET answers, wrong path is 404, bad method/media is 415" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var qbuf: [512]u8 = undefined;
    const q = try cli_query.buildQueryPacket(&qbuf, 0xabcd, "dns.home.arpa.", .A, false);
    var enc: [1024]u8 = undefined;
    const enc_q = std.base64.url_safe_no_pad.Encoder.encode(&enc, q);
    const good_path = try std.fmt.allocPrint(alloc, "/dns-query?dns={s}", .{enc_q});
    const good = try doh.dnsQueryFromParts(alloc, true, false, good_path, null, qbuf[0..0]);
    try std.testing.expect(good.len > 0);
    // Wrong path never reaches the resolver; a method that is neither
    // GET nor POST without a content type fails the media check first.
    try std.testing.expectError(error.BadTarget, doh.dnsQueryFromParts(alloc, true, false, "/not-dns-query?dns=abcd", null, qbuf[0..0]));
    try std.testing.expectEqual(doh.Status.unsupported_media_type, mapStatus(.{ .method_is_get = false, .method_is_post = false, .target = "/dns-query", .content_type = null, .body_len = 0 }, true));
    try std.testing.expectEqual(doh.Status.not_found, doh.statusForError(error.BadTarget));
}

test "DoH/3 mapping: media types, malformed bodies, and header limits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var qbuf: [512]u8 = undefined;
    const q = try cli_query.buildQueryPacket(&qbuf, 0xdcba, "dns.home.arpa.", .A, false);
    // Wrong media type is 415; missing and empty bodies are 400.
    try std.testing.expectError(error.BadContentType, doh.dnsQueryFromParts(alloc, false, true, "/dns-query", "text/plain", qbuf[0..q.len]));
    try std.testing.expectError(error.BadContentType, doh.dnsQueryFromParts(alloc, false, true, "/dns-query", null, qbuf[0..q.len]));
    try std.testing.expectError(error.BadDnsMessage, doh.dnsQueryFromParts(alloc, false, true, "/dns-query", doh.dns_message_media_type, qbuf[0..0]));
    try std.testing.expectEqual(doh.Status.unsupported_media_type, doh.statusForError(error.BadContentType));
    try std.testing.expectEqual(doh.Status.bad_request, doh.statusForError(error.BadDnsMessage));
    // A bad base64url query is 400, and an empty query decodes to 400.
    try std.testing.expectError(error.BadBase64, doh.dnsQueryFromParts(alloc, true, false, "/dns-query?dns=!!!", null, qbuf[0..0]));
    try std.testing.expectEqual(doh.Status.bad_request, doh.statusForError(error.BadBase64));
    // Oversize bodies and targets exceed the mapping caps.
    var big: [MAX_BODY_LEN + 1]u8 = undefined;
    try std.testing.expectError(error.BadDnsMessage, doh.dnsQueryFromParts(alloc, false, true, "/dns-query", doh.dns_message_media_type, &big));
    try std.testing.expectEqual(doh.Status.bad_request, doh.statusForError(error.BadDnsMessage));
    var long_target = try alloc.alloc(u8, MAX_HEADER_BYTES + 16);
    @memset(long_target, 'a');
    @memcpy(long_target[0.."/dns-query?dns=".len], "/dns-query?dns=");
    try std.testing.expectError(error.BadDnsMessage, doh.dnsQueryFromParts(alloc, true, false, long_target, null, qbuf[0..0]));
}

test "QUIC worst case stays within the per-port budget" {
    const doq = @import("doq.zig");
    const per_stream = @max(@sizeOf(doq.StreamParser), STREAM_STATE_SIZE);
    const per_conn = @sizeOf(core.Connection) + core.Server.INITIAL_MAX_DATA + core.Server.MAX_STREAMS_PER_CONN * per_stream;
    const worst_case = core.Server.MAX_CONNECTIONS * per_conn;
    try std.testing.expectEqual(@as(usize, 32), core.Server.MAX_CONNECTIONS);
    try std.testing.expectEqual(@as(usize, 16), core.Server.MAX_STREAMS_PER_CONN);
    comptime {
        if (core.Server.MAX_CONNECTIONS * (@sizeOf(core.Connection) + core.Server.INITIAL_MAX_DATA + core.Server.MAX_STREAMS_PER_CONN * @max(@sizeOf(doq.StreamParser), STREAM_STATE_SIZE)) > core.Server.MAX_STATE_BYTES_PER_PORT) @compileError("QUIC worst case exceeds per-port budget");
    }
    try std.testing.expect(worst_case <= core.Server.MAX_STATE_BYTES_PER_PORT);
}
