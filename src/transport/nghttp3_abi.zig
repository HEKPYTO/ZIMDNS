/// Contract: Raw ABI surface for nghttp3 1.19.0 server use. Field order
/// in each struct matches the C header exactly; only the
/// `*_versioned` entry points are bound (short names are C macros).
/// Ownership: nghttp3 owns connection memory (`conn_del` frees it);
/// every header name/value handed to callbacks is an `rcbuf` the
/// callback must copy before returning.
const std = @import("std");

pub const conn_t = opaque {};
pub const rcbuf_t = opaque {};
pub const mem_t = opaque {};

pub const CALLBACKS_VERSION: c_int = 4;
pub const SETTINGS_VERSION: c_int = 4;

pub const NV_FLAG_NONE: u8 = 0x00;
pub const NV_FLAG_NEVER_INDEX: u8 = 0x01;

pub const DATA_FLAG_EOF: u32 = 0x01;
pub const DATA_FLAG_NO_END_STREAM: u32 = 0x02;

pub const ERR_WOULDBLOCK: c_int = -103;
pub const ERR_STREAM_NOT_FOUND: c_int = -110;
pub const ERR_CONN_CLOSING: c_int = -111;
pub const ERR_STREAM_DATA_BLOCKED: c_int = -209;
pub const ERR_H3_GENERAL_PROTOCOL_ERROR: c_int = -606;

pub const H3_NO_ERROR: u64 = 0x100;
pub const H3_REQUEST_REJECTED: u64 = 0x010b;
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;

pub const tstamp = u64;

pub const vec = extern struct {
    base: [*c]u8,
    len: usize,
};

pub const nv = extern struct {
    name: [*c]const u8,
    value: [*c]const u8,
    namelen: usize,
    valuelen: usize,
    flags: u8,
};

pub const settings = extern struct {
    max_field_section_size: u64,
    qpack_max_dtable_capacity: usize,
    qpack_encoder_max_dtable_capacity: usize,
    qpack_blocked_streams: usize,
    enable_connect_protocol: u8,
    h3_datagram: u8,
    origin_list: ?*const vec,
    glitch_ratelim_burst: u64,
    glitch_ratelim_rate: u64,
    qpack_indexing_strat: c_int,
};

pub const acked_stream_data_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const stream_close_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const recv_data_fn = *const fn (?*conn_t, i64, [*c]const u8, usize, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const deferred_consume_fn = *const fn (?*conn_t, i64, usize, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const begin_headers_fn = *const fn (?*conn_t, i64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const recv_header_fn = *const fn (?*conn_t, i64, i32, ?*rcbuf_t, ?*rcbuf_t, u8, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const end_headers_fn = *const fn (?*conn_t, i64, c_int, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const stop_sending_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const end_stream_fn = *const fn (?*conn_t, i64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const reset_stream_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const shutdown_fn = *const fn (?*conn_t, i64, ?*anyopaque) callconv(.c) c_int;
pub const stream_close2_fn = *const fn (?*conn_t, u32, i64, u64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const rand_fn = *const fn ([*c]u8, usize) callconv(.c) void;

pub const callbacks = extern struct {
    acked_stream_data: ?acked_stream_data_fn = null,
    stream_close: ?stream_close_fn = null,
    recv_data: ?recv_data_fn = null,
    deferred_consume: ?deferred_consume_fn = null,
    begin_headers: ?begin_headers_fn = null,
    recv_header: ?recv_header_fn = null,
    end_headers: ?end_headers_fn = null,
    begin_trailers: ?begin_headers_fn = null,
    recv_trailer: ?recv_header_fn = null,
    end_trailers: ?end_headers_fn = null,
    stop_sending: ?stop_sending_fn = null,
    end_stream: ?end_stream_fn = null,
    reset_stream: ?reset_stream_fn = null,
    shutdown: ?shutdown_fn = null,
    recv_settings: ?*anyopaque = null,
    recv_origin: ?*anyopaque = null,
    end_origin: ?*anyopaque = null,
    rand: ?rand_fn = null,
    recv_settings2: ?recv_settings2_fn = null,
    stream_close2: ?stream_close2_fn = null,
};

pub const recv_settings2_fn = *const fn (?*conn_t, ?*const settings, ?*anyopaque) callconv(.c) c_int;

pub const read_data_fn = *const fn (?*conn_t, i64, [*c]vec, usize, [*c]u32, ?*anyopaque, ?*anyopaque) callconv(.c) isize;
pub const data_reader = extern struct {
    read_data: ?read_data_fn,
};

pub extern "nghttp3" fn nghttp3_conn_server_new_versioned(pconn: ?*?*conn_t, callbacks_version: c_int, cb: ?*const callbacks, settings_version: c_int, s: ?*const settings, mem: ?*const mem_t, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_del(conn: ?*conn_t) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_conn_bind_control_stream(conn: ?*conn_t, stream_id: i64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_bind_qpack_streams(conn: ?*conn_t, qenc_stream_id: i64, qdec_stream_id: i64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_read_stream2(conn: ?*conn_t, stream_id: i64, src: [*c]const u8, srclen: usize, fin: c_int, ts: tstamp) callconv(.c) isize;
pub extern "nghttp3" fn nghttp3_conn_writev_stream(conn: ?*conn_t, pstream_id: ?*i64, pfin: ?*c_int, vec_out: [*c]vec, veccnt: usize) callconv(.c) isize;
pub extern "nghttp3" fn nghttp3_conn_add_write_offset(conn: ?*conn_t, stream_id: i64, n: usize) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_add_ack_offset(conn: ?*conn_t, stream_id: i64, n: u64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_block_stream(conn: ?*conn_t, stream_id: i64) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_conn_set_max_client_streams_bidi(conn: ?*conn_t, max_streams: u64) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_conn_set_max_concurrent_streams(conn: ?*conn_t, max: usize) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_conn_submit_response(conn: ?*conn_t, stream_id: i64, nva: [*c]const nv, nvlen: usize, dr: ?*const data_reader) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_shutdown_stream_read(conn: ?*conn_t, stream_id: i64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_resume_stream(conn: ?*conn_t, stream_id: i64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_close_stream(conn: ?*conn_t, stream_id: i64, app_error_code: u64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_close_stream2(conn: ?*conn_t, flags: u32, stream_id: i64, rx_app_error_code: u64, tx_app_error_code: u64) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_set_stream_user_data(conn: ?*conn_t, stream_id: i64, stream_user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "nghttp3" fn nghttp3_conn_get_stream_user_data(conn: ?*const conn_t, stream_id: i64) callconv(.c) ?*anyopaque;
pub extern "nghttp3" fn nghttp3_settings_default_versioned(version: c_int, settings: ?*settings) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_vec_get_buf(vec_in: [*c]const vec, out: [*c]u8) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_rcbuf_get_buf(rcbuf: ?*const rcbuf_t) callconv(.c) vec;
pub extern "nghttp3" fn nghttp3_rcbuf_decref(rcbuf: ?*rcbuf_t) callconv(.c) void;
pub extern "nghttp3" fn nghttp3_err_infer_quic_app_error_code(liberr: c_int) callconv(.c) u64;

pub const conn_server_new = nghttp3_conn_server_new_versioned;
pub const conn_del = nghttp3_conn_del;
pub const settings_default = nghttp3_settings_default_versioned;

test "nghttp3 settings version is the bound one" {
    try std.testing.expectEqual(@as(c_int, 4), SETTINGS_VERSION);
}
