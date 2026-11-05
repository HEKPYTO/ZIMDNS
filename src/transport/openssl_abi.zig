/// Contract: Manual OpenSSL 3.x ABI declarations. Zig 0.17 removed
/// `@cImport`, so the small slice of `openssl/ssl.h`, `openssl/bio.h`,
/// `openssl/err.h` and `openssl/x509_vfy.h` this transport uses is declared
/// here. Values were read off the OpenSSL 3.x headers; anything drifted
/// fails loudly at link time, not silently at runtime.
/// Ownership: Nothing is owned; every declaration is a foreign symbol.
pub const SSL = opaque {};
pub const SSL_CTX = opaque {};
pub const SSL_METHOD = opaque {};
pub const X509_VERIFY_PARAM = opaque {};

pub const SSL_VERIFY_NONE: c_int = 0x00;
pub const SSL_VERIFY_PEER: c_int = 0x01;
pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;
pub const X509_V_OK: c_long = 0;
pub const TLS1_3_VERSION: c_int = 0x0304;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const TLSEXT_NAMETYPE_host_name: c_long = 0;
pub const TLSEXT_NAMETYPE_no_extension: c_long = 65535;
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;

pub const AlpnSelectCb = *const fn (
    ssl: ?*SSL,
    out: ?*anyopaque,
    outlen: ?*u8,
    in: ?*anyopaque,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub extern "ssl" fn TLS_server_method() callconv(.c) ?*const SSL_METHOD;
pub extern "ssl" fn TLS_client_method() callconv(.c) ?*const SSL_METHOD;
pub extern "ssl" fn SSL_CTX_new(meth: ?*const SSL_METHOD) callconv(.c) ?*SSL_CTX;
pub extern "ssl" fn SSL_CTX_free(ctx: ?*SSL_CTX) callconv(.c) void;
pub extern "ssl" fn SSL_CTX_ctrl(ctx: ?*SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) callconv(.c) c_long;
pub extern "ssl" fn SSL_CTX_use_certificate_chain_file(ctx: ?*SSL_CTX, file: [*:0]const u8) callconv(.c) c_int;
pub extern "ssl" fn SSL_CTX_use_PrivateKey_file(ctx: ?*SSL_CTX, file: [*:0]const u8, type_: c_int) callconv(.c) c_int;
pub extern "ssl" fn SSL_CTX_check_private_key(ctx: ?*const SSL_CTX) callconv(.c) c_int;
pub extern "ssl" fn SSL_CTX_set_verify(ctx: ?*SSL_CTX, mode: c_int, callback: ?*const anyopaque) callconv(.c) void;
pub extern "ssl" fn SSL_CTX_set_alpn_select_cb(ctx: ?*SSL_CTX, cb: AlpnSelectCb, arg: ?*anyopaque) callconv(.c) void;
pub extern "ssl" fn SSL_CTX_set_default_verify_paths(ctx: ?*SSL_CTX) callconv(.c) c_int;
pub extern "ssl" fn SSL_CTX_load_verify_locations(ctx: ?*SSL_CTX, CAfile: [*:0]const u8, CApath: ?[*:0]const u8) callconv(.c) c_int;
pub extern "ssl" fn SSL_new(ctx: ?*SSL_CTX) callconv(.c) ?*SSL;
pub extern "ssl" fn SSL_free(ssl: ?*SSL) callconv(.c) void;
pub extern "ssl" fn SSL_set_fd(s: ?*SSL, fd: c_int) callconv(.c) c_int;
pub extern "ssl" fn SSL_get_fd(s: ?*const SSL) callconv(.c) c_int;
pub extern "ssl" fn SSL_set_accept_state(s: ?*SSL) callconv(.c) void;
pub extern "ssl" fn SSL_set_connect_state(s: ?*SSL) callconv(.c) void;
pub extern "ssl" fn SSL_do_handshake(s: ?*SSL) callconv(.c) c_int;
pub extern "ssl" fn SSL_get_error(s: ?*const SSL, ret_code: c_int) callconv(.c) c_int;
pub extern "ssl" fn SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: c_int) callconv(.c) c_int;
pub extern "ssl" fn SSL_write(ssl: ?*SSL, buf: ?*const anyopaque, num: c_int) callconv(.c) c_int;
pub extern "ssl" fn SSL_shutdown(s: ?*SSL) callconv(.c) c_int;
pub extern "ssl" fn SSL_ctrl(ssl: ?*SSL, cmd: c_int, larg: c_long, parg: ?*anyopaque) callconv(.c) c_long;
pub extern "ssl" fn SSL_version(ssl: ?*const SSL) callconv(.c) c_int;
pub extern "ssl" fn SSL_set_alpn_protos(ssl: ?*SSL, protos: [*c]const u8, protos_len: c_uint) callconv(.c) c_int;
pub extern "ssl" fn SSL_get0_alpn_selected(ssl: ?*const SSL, data: ?*[*c]const u8, len: ?*c_uint) callconv(.c) void;
pub extern "ssl" fn SSL_set1_host(s: ?*SSL, host: [*:0]const u8) callconv(.c) c_int;
pub extern "ssl" fn SSL_get_servername(s: ?*const SSL, type_: c_long) callconv(.c) ?[*:0]const u8;
pub extern "ssl" fn SSL_get0_param(ssl: ?*SSL) callconv(.c) ?*X509_VERIFY_PARAM;
pub extern "ssl" fn SSL_get_verify_result(ssl: ?*const SSL) callconv(.c) c_long;
pub extern "crypto" fn ERR_get_error() callconv(.c) c_ulong;
pub extern "crypto" fn X509_VERIFY_PARAM_set1_ip_asc(param: ?*X509_VERIFY_PARAM, ipasc: [*:0]const u8) callconv(.c) c_int;
pub extern "crypto" fn OpenSSL_version_num() callconv(.c) c_ulong;

/// Refuses OpenSSL < 3.0 at configure time. `OpenSSL_version_num` lays out
/// as `0xMNN00PP0L`, so the major nibble is bits 28-31.
/// Fails closed when the linked library predates 3.x. Callers run this
/// before the first handshake; the ABI below is 3.x-only.
pub fn requireVersion() void {
    if ((OpenSSL_version_num() >> 28) < 3) @panic("OpenSSL >= 3.0 is required");
}
