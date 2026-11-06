/// Contract: Raw ABI surface for ngtcp2 1.26.0 + the GnuTLS crypto backend.
/// Zig 0.17 removed `@cImport`, so every type and symbol used here is
/// transcribed from `third_party/ngtcp2/lib/includes/ngtcp2/ngtcp2.h`,
/// `third_party/ngtcp2/crypto/includes/ngtcp2/ngtcp2_crypto.h`,
/// `ngtcp2_crypto_gnutls.h`, and the system `gnutls/gnutls.h`. Only the
/// server-side subset the DoQ loop needs is declared; field order in each
/// struct matches the C header exactly, because the layout is the ABI.
/// Only the `*_versioned` entry points are bound: the short names are C
/// macros the Zig compiler cannot see.
/// Ownership: ngtcp2 owns connection memory (`ngtcp2_conn_del` frees it);
/// GnuTLS credentials are owned by `gnutls_server.zig`.
const std = @import("std");

pub const conn_t = opaque {};
pub const gnutls_session_t = ?*opaque {};
pub const gnutls_cert_creds_t = ?*opaque {};
pub const gnutls_datum_t = extern struct {
    data: [*c]u8,
    size: c_uint,
};

pub const MAX_CIDLEN: usize = 20;
pub const STATELESS_RESET_TOKENLEN: usize = 16;
pub const PATH_CHALLENGE_DATALEN: usize = 8;

pub const NANOSECONDS: u64 = 1;
pub const MILLISECONDS: u64 = 1000 * 1000 * NANOSECONDS;
pub const SECONDS: u64 = 1000 * MILLISECONDS;

pub const PROTO_VER_V1: u32 = 0x00000001;

pub const PKT_INFO_V1: c_int = 1;
pub const PKT_INFO_VERSION: c_int = PKT_INFO_V1;
pub const SETTINGS_VERSION: c_int = 5;
pub const CALLBACKS_VERSION: c_int = 6;
pub const TRANSPORT_PARAMS_VERSION: c_int = 1;

pub const PKT_INITIAL: u8 = 0x10;

pub const NO_ERROR: u64 = 0x0;
pub const CCERR_TYPE_TRANSPORT: c_int = 0;
pub const CCERR_TYPE_APPLICATION: c_int = 1;

pub const ERR_NOBUF: c_int = -202;
pub const ERR_STREAM_DATA_BLOCKED: c_int = -208;
pub const ERR_STREAM_SHUT_WR: c_int = -219;
pub const ERR_STREAM_NOT_FOUND: c_int = -220;
pub const ERR_WRITE_MORE: c_int = -230;
pub const ERR_RETRY: c_int = -231;
pub const ERR_DROP_CONN: c_int = -232;
pub const ERR_DRAINING: c_int = -224;
pub const ERR_CLOSING: c_int = -223;
pub const ERR_IDLE_CLOSE: c_int = -238;
pub const ERR_VERSION_NEGOTIATION: c_int = -235;
pub const ERR_CRYPTO: c_int = -213;
pub const ERR_CALLBACK_FAILURE: c_int = -502;

pub const STREAM_DATA_FLAG_FIN: u32 = 0x01;

pub const WRITE_STREAM_FLAG_NONE: u32 = 0x00;
pub const WRITE_STREAM_FLAG_MORE: u32 = 0x01;
pub const WRITE_STREAM_FLAG_FIN: u32 = 0x02;

pub const TOKEN_TYPE_UNKNOWN: c_int = 0;
pub const TOKEN_TYPE_RETRY: c_int = 1;

pub const CC_ALGO_CUBIC: c_int = 0x01;
pub const DEFAULT_INITIAL_RTT: u64 = 333 * MILLISECONDS;

pub const GNUTLS_SERVER: c_uint = 1;
pub const GNUTLS_CRD_CERTIFICATE: c_int = 1;
pub const GNUTLS_X509_FMT_PEM: c_int = 1;
pub const GNUTLS_ALPN_MANDATORY: c_uint = 1;
pub const GNUTLS_ALPN_SERVER_PRECEDENCE: c_uint = 2;

pub const tstamp = u64;
pub const duration = u64;
pub const ssize = isize;

pub const cid = extern struct {
    datalen: usize,
    data: [MAX_CIDLEN]u8,
};

pub const vec = extern struct {
    base: [*c]u8,
    len: usize,
};

pub const pkt_info = extern struct {
    ecn: u8,
    _pad: [7]u8 = undefined,
};

pub const sockaddr_union = extern union {
    sa: std.posix.sockaddr.storage,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,
};

pub const addr = extern struct {
    addr: ?*std.posix.sockaddr.storage,
    addrlen: std.posix.socklen_t,
};

pub const path = extern struct {
    local: addr,
    remote: addr,
    user_data: ?*anyopaque,
};

pub const path_storage = extern struct {
    path: path,
    local_addrbuf: sockaddr_union,
    remote_addrbuf: sockaddr_union,
};

pub const pkt_hd = extern struct {
    dcid: cid,
    scid: cid,
    pkt_num: i64,
    token: [*c]const u8,
    tokenlen: usize,
    pkt_numlen: usize,
    len: usize,
    version: u32,
    type: u8,
    flags: u8,
};

pub const version_cid = extern struct {
    version: u32,
    dcid: [*c]const u8,
    dcidlen: usize,
    scid: [*c]const u8,
    scidlen: usize,
};

pub const ccerr = extern struct {
    type: c_int,
    error_code: u64,
    frame_type: u64,
    reason: [*c]const u8,
    reasonlen: usize,
};

pub const path_challenge_data = extern struct {
    data: [PATH_CHALLENGE_DATALEN]u8,
};

pub const rand_ctx = extern struct {
    native_handle: ?*anyopaque,
};

pub const crypto_aead = opaque {};
pub const crypto_aead_ctx = opaque {};
pub const crypto_cipher = opaque {};
pub const crypto_cipher_ctx = opaque {};

/// `ngtcp2_crypto_conn_ref`: the GnuTLS session points at one of these;
/// `get_conn` hands the crypto backend our connection back.
pub const crypto_get_conn_fn = *const fn (?*crypto_conn_ref) callconv(.c) ?*conn_t;
pub const crypto_conn_ref = extern struct {
    get_conn: ?crypto_get_conn_fn,
    user_data: ?*anyopaque,
};

pub const recv_client_initial_fn = *const fn (?*conn_t, ?*const cid, ?*anyopaque) callconv(.c) c_int;
pub const recv_crypto_data_fn = *const fn (?*conn_t, c_int, u64, [*c]const u8, usize, ?*anyopaque) callconv(.c) c_int;
pub const encrypt_fn = *const fn ([*c]u8, ?*const crypto_aead, ?*const crypto_aead_ctx, [*c]const u8, usize, [*c]const u8, usize, [*c]const u8, usize) callconv(.c) c_int;
pub const decrypt_fn = *const fn ([*c]u8, ?*const crypto_aead, ?*const crypto_aead_ctx, [*c]const u8, usize, [*c]const u8, usize, [*c]const u8, usize) callconv(.c) c_int;
pub const hp_mask_fn = *const fn ([*c]u8, ?*const crypto_cipher, ?*const crypto_cipher_ctx, [*c]const u8) callconv(.c) c_int;
pub const recv_stream_data_fn = *const fn (?*conn_t, u32, i64, u64, [*c]const u8, usize, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const stream_open_fn = *const fn (?*conn_t, i64, ?*anyopaque) callconv(.c) c_int;
pub const stream_close2_fn = *const fn (?*conn_t, u32, i64, u64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const rand_fn = *const fn ([*c]u8, usize, ?*const rand_ctx) callconv(.c) void;
pub const acked_stream_data_offset_fn = *const fn (?*conn_t, i64, u64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const recv_stop_sending_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const extend_max_data_fn = *const fn (?*conn_t, u64, ?*anyopaque) callconv(.c) c_int;
pub const get_new_connection_id_fn = *const fn (?*conn_t, ?*cid, [*c]u8, usize, ?*anyopaque) callconv(.c) c_int;
pub const remove_connection_id_fn = *const fn (?*conn_t, ?*const cid, ?*anyopaque) callconv(.c) c_int;
pub const update_key_fn = *const fn (?*conn_t, [*c]u8, [*c]u8, ?*crypto_aead_ctx, [*c]u8, ?*crypto_aead_ctx, [*c]u8, [*c]const u8, [*c]const u8, usize, ?*anyopaque) callconv(.c) c_int;
pub const stream_reset_fn = *const fn (?*conn_t, i64, u64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const extend_max_stream_data_fn = *const fn (?*conn_t, i64, u64, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;
pub const delete_crypto_aead_ctx_fn = *const fn (?*conn_t, ?*crypto_aead_ctx, ?*anyopaque) callconv(.c) void;
pub const delete_crypto_cipher_ctx_fn = *const fn (?*conn_t, ?*crypto_cipher_ctx, ?*anyopaque) callconv(.c) void;
pub const get_path_challenge_data2_fn = *const fn (?*conn_t, ?*path_challenge_data, ?*anyopaque) callconv(.c) c_int;
pub const version_negotiation_fn = *const fn (?*conn_t, u32, ?*const cid, ?*anyopaque) callconv(.c) c_int;
pub const handshake_completed_fn = *const fn (?*conn_t, ?*anyopaque) callconv(.c) c_int;

/// Field order is the C `ngtcp2_callbacks` layout verbatim (V1 through
/// V6); a reordered field would silently wire the wrong function.
pub const callbacks = extern struct {
    client_initial: ?*anyopaque = null,
    recv_client_initial: ?recv_client_initial_fn = null,
    recv_crypto_data: ?recv_crypto_data_fn = null,
    handshake_completed: ?handshake_completed_fn = null,
    recv_version_negotiation: ?*anyopaque = null,
    encrypt: ?encrypt_fn = null,
    decrypt: ?decrypt_fn = null,
    hp_mask: ?hp_mask_fn = null,
    recv_stream_data: ?recv_stream_data_fn = null,
    acked_stream_data_offset: ?acked_stream_data_offset_fn = null,
    stream_open: ?stream_open_fn = null,
    stream_close: ?*anyopaque = null,
    recv_stateless_reset: ?*anyopaque = null,
    recv_retry: ?*anyopaque = null,
    extend_max_local_streams_bidi: ?*anyopaque = null,
    extend_max_local_streams_uni: ?*anyopaque = null,
    rand: ?rand_fn = null,
    get_new_connection_id: ?get_new_connection_id_fn = null,
    remove_connection_id: ?remove_connection_id_fn = null,
    update_key: ?update_key_fn = null,
    path_validation: ?*anyopaque = null,
    select_preferred_addr: ?*anyopaque = null,
    stream_reset: ?stream_reset_fn = null,
    extend_max_remote_streams_bidi: ?*anyopaque = null,
    extend_max_remote_streams_uni: ?*anyopaque = null,
    extend_max_stream_data: ?extend_max_stream_data_fn = null,
    dcid_status: ?*anyopaque = null,
    handshake_confirmed: ?*anyopaque = null,
    recv_new_token: ?*anyopaque = null,
    delete_crypto_aead_ctx: ?delete_crypto_aead_ctx_fn = null,
    delete_crypto_cipher_ctx: ?delete_crypto_cipher_ctx_fn = null,
    recv_datagram: ?*anyopaque = null,
    ack_datagram: ?*anyopaque = null,
    lost_datagram: ?*anyopaque = null,
    get_path_challenge_data: ?*anyopaque = null,
    stream_stop_sending: ?*anyopaque = null,
    version_negotiation: ?version_negotiation_fn = null,
    recv_rx_key: ?*anyopaque = null,
    recv_tx_key: ?*anyopaque = null,
    tls_early_data_rejected: ?*anyopaque = null,
    begin_path_validation: ?*anyopaque = null,
    recv_stateless_reset2: ?*anyopaque = null,
    get_new_connection_id2: ?*anyopaque = null,
    dcid_status2: ?*anyopaque = null,
    get_path_challenge_data2: ?get_path_challenge_data2_fn = null,
    recv_stop_sending: ?recv_stop_sending_fn = null,
    stream_close2: ?stream_close2_fn = null,
    extend_max_data: ?extend_max_data_fn = null,
};

/// Field order is the C `ngtcp2_settings` layout verbatim (V1-V5).
pub const settings = extern struct {
    qlog_write: ?*anyopaque = null,
    cc_algo: c_int = CC_ALGO_CUBIC,
    initial_ts: tstamp = 0,
    initial_rtt: duration = DEFAULT_INITIAL_RTT,
    log_printf: ?*anyopaque = null,
    max_tx_udp_payload_size: usize = 0,
    token: [*c]const u8 = null,
    tokenlen: usize = 0,
    token_type: c_int = TOKEN_TYPE_UNKNOWN,
    rand_ctx: rand_ctx = .{ .native_handle = null },
    max_window: u64 = 0,
    max_stream_window: u64 = 0,
    ack_thresh: usize = 2,
    no_tx_udp_payload_size_shaping: u8 = 0,
    handshake_timeout: duration = std.math.maxInt(u64),
    preferred_versions: [*c]const u32 = null,
    preferred_versionslen: usize = 0,
    available_versions: [*c]const u32 = null,
    available_versionslen: usize = 0,
    original_version: u32 = 0,
    no_pmtud: u8 = 0,
    initial_pkt_num: u32 = 0,
    pmtud_probes: [*c]const u16 = null,
    pmtud_probeslen: usize = 0,
    glitch_ratelim_burst: u64 = 0,
    glitch_ratelim_rate: u64 = 0,
    log_write: ?*anyopaque = null,
    write_stream_data_thresh: usize = 0,
};

pub const preferred_addr = extern struct {
    cid: cid,
    ipv4: std.posix.sockaddr.in,
    ipv6: std.posix.sockaddr.in6,
    ipv4_present: u8,
    ipv6_present: u8,
    stateless_reset_token: [STATELESS_RESET_TOKENLEN]u8,
};

pub const version_info = extern struct {
    chosen_version: u32,
    available_versions: [*c]const u8,
    available_versionslen: usize,
};

/// Field order is the C `ngtcp2_transport_params` layout verbatim.
pub const transport_params = extern struct {
    preferred_addr: preferred_addr,
    original_dcid: cid,
    initial_scid: cid,
    retry_scid: cid,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_data: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    max_idle_timeout: duration,
    max_udp_payload_size: u64,
    active_connection_id_limit: u64,
    ack_delay_exponent: u64,
    max_ack_delay: duration,
    max_datagram_frame_size: u64,
    stateless_reset_token_present: u8,
    disable_active_migration: u8,
    original_dcid_present: u8,
    initial_scid_present: u8,
    retry_scid_present: u8,
    preferred_addr_present: u8,
    stateless_reset_token: [STATELESS_RESET_TOKENLEN]u8,
    grease_quic_bit: u8,
    version_info: version_info,
    version_info_present: u8,
};

pub extern "ngtcp2" fn ngtcp2_accept(dest: ?*pkt_hd, pkt: [*c]const u8, pktlen: usize) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_pkt_decode_version_cid(dest: ?*version_cid, data: [*c]const u8, datalen: usize, short_dcidlen: usize) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_pkt_write_version_negotiation(dest: [*c]u8, destlen: usize, unused_random: u8, dcid: [*c]const u8, dcidlen: usize, scid: [*c]const u8, scidlen: usize, sv: [*c]const u32, nsv: usize) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_conn_server_new_versioned(pconn: ?*?*conn_t, dcid: ?*const cid, scid: ?*const cid, p: ?*const path, client_chosen_version: u32, callbacks_version: c_int, cb: ?*const callbacks, settings_version: c_int, s: ?*const settings, transport_params_version: c_int, params: ?*const transport_params, mem: ?*const anyopaque, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_del(conn: ?*conn_t) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_conn_set_tls_native_handle(conn: ?*conn_t, tls_native_handle: ?*anyopaque) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_conn_read_pkt_versioned(conn: ?*conn_t, p: ?*const path, pkt_info_version: c_int, pi: ?*const pkt_info, pkt: [*c]const u8, pktlen: usize, ts: tstamp) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_writev_stream_versioned(conn: ?*conn_t, p: ?*path, pkt_info_version: c_int, pi: ?*pkt_info, dest: [*c]u8, destlen: usize, pdatalen: ?*ssize, flags: u32, stream_id: i64, datav: [*c]const vec, datavcnt: usize, ts: tstamp) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_conn_open_uni_stream(conn: ?*conn_t, pstream_id: ?*i64, stream_user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_write_connection_close_versioned(conn: ?*conn_t, p: ?*path, pkt_info_version: c_int, pi: ?*const pkt_info, dest: [*c]u8, destlen: usize, ccerr: ?*const ccerr, ts: tstamp) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_conn_open_bidi_stream(conn: ?*conn_t, pstream_id: ?*i64, stream_user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_shutdown_stream_read(conn: ?*conn_t, flags: u32, stream_id: i64, app_error_code: u64) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_extend_max_stream_offset(conn: ?*conn_t, stream_id: i64, datalen: u64) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_extend_max_offset(conn: ?*conn_t, datalen: u64) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_conn_extend_max_streams_bidi(conn: ?*conn_t, n: usize) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_conn_extend_max_streams_uni(conn: ?*conn_t, n: usize) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_conn_shutdown_stream(conn: ?*conn_t, flags: u32, stream_id: i64, app_error_code: u64) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_get_expiry2(conn: ?*conn_t) callconv(.c) tstamp;
pub extern "ngtcp2" fn ngtcp2_conn_handle_expiry(conn: ?*conn_t, ts: tstamp) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_get_scid2(conn: ?*conn_t, dest: [*c]cid) callconv(.c) usize;
pub extern "ngtcp2" fn ngtcp2_conn_get_dcid2(conn: ?*conn_t) callconv(.c) ?*const cid;
pub extern "ngtcp2" fn ngtcp2_conn_get_client_initial_dcid2(conn: ?*conn_t) callconv(.c) ?*const cid;
pub extern "ngtcp2" fn ngtcp2_conn_get_client_chosen_version2(conn: ?*conn_t) callconv(.c) u32;
pub extern "ngtcp2" fn ngtcp2_strerror(liberr: c_int) callconv(.c) [*:0]const u8;
pub extern "ngtcp2" fn ngtcp2_conn_in_closing_period2(conn: ?*conn_t) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_conn_in_draining_period2(conn: ?*conn_t) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_settings_default_versioned(version: c_int, s: ?*settings) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_transport_params_default_versioned(version: c_int, params: ?*transport_params) callconv(.c) void;

pub extern "ngtcp2" fn ngtcp2_crypto_recv_client_initial_cb(conn: ?*conn_t, dcid: ?*const cid, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_recv_crypto_data_cb(conn: ?*conn_t, encryption_level: c_int, offset: u64, data: [*c]const u8, datalen: usize, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_encrypt_cb(dest: [*c]u8, aead: ?*const crypto_aead, aead_ctx: ?*const crypto_aead_ctx, plaintext: [*c]const u8, plaintextlen: usize, nonce: [*c]const u8, noncelen: usize, aad: [*c]const u8, aadlen: usize) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_decrypt_cb(dest: [*c]u8, aead: ?*const crypto_aead, aead_ctx: ?*const crypto_aead_ctx, ciphertext: [*c]const u8, ciphertextlen: usize, nonce: [*c]const u8, noncelen: usize, aad: [*c]const u8, aadlen: usize) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_hp_mask_cb(dest: [*c]u8, hp: ?*const crypto_cipher, hp_ctx: ?*const crypto_cipher_ctx, sample: [*c]const u8) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_update_key_cb(conn: ?*conn_t, rx_secret: [*c]u8, tx_secret: [*c]u8, rx_aead_ctx: ?*crypto_aead_ctx, rx_iv: [*c]u8, tx_aead_ctx: ?*crypto_aead_ctx, tx_iv: [*c]u8, current_rx_secret: [*c]const u8, current_tx_secret: [*c]const u8, secretlen: usize, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_delete_crypto_aead_ctx_cb(conn: ?*conn_t, aead_ctx: ?*crypto_aead_ctx, user_data: ?*anyopaque) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_crypto_delete_crypto_cipher_ctx_cb(conn: ?*conn_t, cipher_ctx: ?*crypto_cipher_ctx, user_data: ?*anyopaque) callconv(.c) void;
pub extern "ngtcp2" fn ngtcp2_crypto_get_path_challenge_data2_cb(conn: ?*conn_t, data: ?*path_challenge_data, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_version_negotiation_cb(conn: ?*conn_t, version: u32, client_dcid: ?*const cid, user_data: ?*anyopaque) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_generate_stateless_reset_token(token: [*c]u8, secret: [*c]const u8, secretlen: usize, c: ?*const cid) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_generate_retry_token2(token: [*c]u8, secret: [*c]const u8, secretlen: usize, version: u32, remote_addr: ?*const anyopaque, remote_addrlen: std.posix.socklen_t, retry_scid: ?*const cid, odcid: ?*const cid, ts: tstamp) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_crypto_verify_retry_token2(odcid: ?*cid, token: [*c]const u8, tokenlen: usize, secret: [*c]const u8, secretlen: usize, version: u32, remote_addr: ?*const anyopaque, remote_addrlen: std.posix.socklen_t, dcid: ?*const cid, timeout: duration, ts: tstamp) callconv(.c) c_int;
pub extern "ngtcp2" fn ngtcp2_crypto_write_retry(dest: [*c]u8, destlen: usize, version: u32, dcid: ?*const cid, scid: ?*const cid, odcid: ?*const cid, token: [*c]const u8, tokenlen: usize) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_crypto_write_connection_close(dest: [*c]u8, destlen: usize, version: u32, dcid: ?*const cid, scid: ?*const cid, error_code: u64, reason: [*c]const u8, reasonlen: usize) callconv(.c) ssize;
pub extern "ngtcp2" fn ngtcp2_crypto_gnutls_configure_server_session(session: gnutls_session_t) callconv(.c) c_int;

pub extern "gnutls" fn gnutls_init(session: ?*gnutls_session_t, flags: c_uint) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_deinit(session: gnutls_session_t) callconv(.c) void;
pub extern "gnutls" fn gnutls_priority_set_direct(session: gnutls_session_t, priorities: [*:0]const u8, err_pos: ?*[*c]const u8) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_credentials_set(session: gnutls_session_t, cred_type: c_int, cred: ?*anyopaque) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_alpn_get_selected_protocol(session: gnutls_session_t, protocol: ?*gnutls_datum_t) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_alpn_set_protocols(session: gnutls_session_t, protocols: [*c]const gnutls_datum_t, protocols_size: c_uint, flags: c_uint) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_session_set_ptr(session: gnutls_session_t, ptr: ?*anyopaque) callconv(.c) void;
pub extern "gnutls" fn gnutls_certificate_allocate_credentials(res: ?*gnutls_cert_creds_t) callconv(.c) c_int;
pub extern "gnutls" fn gnutls_certificate_free_credentials(sc: gnutls_cert_creds_t) callconv(.c) void;
pub extern "gnutls" fn gnutls_certificate_set_x509_key_file(res: gnutls_cert_creds_t, certfile: [*:0]const u8, keyfile: [*:0]const u8, ftype: c_int) callconv(.c) c_int;

pub const accept = ngtcp2_accept;
pub const pkt_decode_version_cid = ngtcp2_pkt_decode_version_cid;
pub const pkt_write_version_negotiation = ngtcp2_pkt_write_version_negotiation;
pub const conn_server_new = ngtcp2_conn_server_new_versioned;
pub const conn_del = ngtcp2_conn_del;
pub const conn_set_tls_native_handle = ngtcp2_conn_set_tls_native_handle;
pub const conn_read_pkt = ngtcp2_conn_read_pkt_versioned;
pub const conn_writev_stream = ngtcp2_conn_writev_stream_versioned;
pub const conn_write_connection_close = ngtcp2_conn_write_connection_close_versioned;
pub const conn_shutdown_stream = ngtcp2_conn_shutdown_stream;
pub const conn_get_expiry = ngtcp2_conn_get_expiry2;
pub const conn_handle_expiry = ngtcp2_conn_handle_expiry;
pub const conn_get_scid = ngtcp2_conn_get_scid2;
pub const conn_get_dcid = ngtcp2_conn_get_dcid2;
pub const conn_open_uni_stream = ngtcp2_conn_open_uni_stream;
pub const conn_shutdown_stream_read = ngtcp2_conn_shutdown_stream_read;
pub const conn_extend_max_stream_offset = ngtcp2_conn_extend_max_stream_offset;
pub const conn_extend_max_offset = ngtcp2_conn_extend_max_offset;
pub const conn_extend_max_streams_bidi = ngtcp2_conn_extend_max_streams_bidi;
pub const conn_extend_max_streams_uni = ngtcp2_conn_extend_max_streams_uni;
pub const alpn_get_selected_protocol = gnutls_alpn_get_selected_protocol;
pub const conn_get_client_initial_dcid = ngtcp2_conn_get_client_initial_dcid2;
pub const conn_get_client_chosen_version = ngtcp2_conn_get_client_chosen_version2;
pub const strerror = ngtcp2_strerror;
pub const conn_in_closing = ngtcp2_conn_in_closing_period2;
pub const conn_in_draining = ngtcp2_conn_in_draining_period2;
pub const settings_default = ngtcp2_settings_default_versioned;
pub const transport_params_default = ngtcp2_transport_params_default_versioned;
pub const crypto_gnutls_configure_server_session = ngtcp2_crypto_gnutls_configure_server_session;

// Layout guards: these `extern struct` field orders mirror ngtcp2
// 1.26.0 exactly, because the layout IS the C ABI — a reordered field
// silently wires the wrong function or reads the wrong offset. A
// vendored header bump must re-verify and update these values.
comptime {
    if (@sizeOf(settings) != 216) @compileError("settings layout drifted");
    if (@sizeOf(transport_params) != 344) @compileError("transport_params layout drifted");
    if (@sizeOf(callbacks) != 384) @compileError("callbacks layout drifted");
    if (@sizeOf(path) != 40) @compileError("path layout drifted");
    if (@sizeOf(pkt_info) != 8) @compileError("pkt_info layout drifted");
    if (@sizeOf(vec) != 16) @compileError("vec layout drifted");
    if (@sizeOf(cid) != 32) @compileError("cid layout drifted");
    if (@offsetOf(settings, "token") != 48) @compileError("settings.token drifted");
    if (@offsetOf(settings, "tokenlen") != 56) @compileError("settings.tokenlen drifted");
    if (@offsetOf(settings, "token_type") != 64) @compileError("settings.token_type drifted");
    if (@offsetOf(settings, "initial_ts") != 16) @compileError("settings.initial_ts drifted");
    if (@offsetOf(transport_params, "original_dcid") != 96) @compileError("original_dcid drifted");
    if (@offsetOf(transport_params, "retry_scid") != 160) @compileError("retry_scid drifted");
    if (@offsetOf(transport_params, "original_dcid_present") != 290) @compileError("original_dcid_present drifted");
    if (@offsetOf(transport_params, "retry_scid_present") != 292) @compileError("retry_scid_present drifted");
    if (@offsetOf(callbacks, "recv_client_initial") != 8) @compileError("recv_client_initial drifted");
    if (@offsetOf(callbacks, "rand") != 128) @compileError("callbacks.rand drifted");
    if (@offsetOf(path, "local") != 0) @compileError("path.local drifted");
    if (@offsetOf(path, "remote") != 16) @compileError("path.remote drifted");
}
