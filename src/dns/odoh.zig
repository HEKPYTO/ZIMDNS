/// Contract: Implements the RFC 9230 Oblivious DoH target crypto. HPKE base
/// mode (RFC 9180) with the RFC 9230 section 9 mandatory suite
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, plus the
/// ObliviousDoHConfigs / ObliviousDoHMessage / plaintext framing of
/// RFC 9230 sections 5 and 6. The module holds no HTTP state: the DoH
/// channels decode the request, call openQuery, answer the DNS message
/// through the runtime, and seal the answer with sealResponse.
/// Ownership: openQuery and sealResponse allocate with the caller's
/// allocator (a per-exchange arena in the channels); Target borrows
/// nothing. Error: UnknownKeyId maps to HTTP 401, BadMessage to 400.
const std = @import("std");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = std.crypto.dh.X25519;

pub const Error = error{
    UnknownKeyId,
    BadMessage,
    BadConfig,
    BadPrivateKey,
};

pub const kem_id: u16 = 0x0020;
pub const kdf_id: u16 = 0x0001;
pub const aead_id: u16 = 0x0001;
pub const config_version: u16 = 0x0001;
pub const query_message_type: u8 = 0x01;
pub const response_message_type: u8 = 0x02;
pub const query_info = "odoh query";
pub const response_export_context = "odoh response";
pub const key_id_label = "odoh key id";
pub const response_key_label = "odoh key";
pub const response_nonce_label = "odoh nonce";

pub const key_len: usize = 16;
pub const nonce_len: usize = 12;
pub const tag_len: usize = 16;
pub const enc_len: usize = 32;
pub const resp_nonce_len: usize = 16;

const kem_suite_id: [5]u8 = .{ 'K', 'E', 'M', 0x00, 0x20 };
const hpke_suite_id: [10]u8 = .{ 'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01 };

/// The operator's ODoH key: the private scalar from the key file and the
/// public key and key_id the client needs.
pub const Target = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    key_id: [32]u8,
};

pub const ParsedMessage = struct {
    message_type: u8,
    key_id: []const u8,
    encrypted: []const u8,
};

pub const OpenQueryResult = struct {
    /// The full decrypted plaintext; `dns_query` is a slice into it.
    q_plain: []u8,
    dns_query: []u8,
    exporter_secret: [32]u8,
};

fn labeledExtract(suite_id: []const u8, salt: []const u8, label: []const u8, ikm: []const u8) [32]u8 {
    var st = Hmac.init(salt);
    st.update("HPKE-v1");
    st.update(suite_id);
    st.update(label);
    st.update(ikm);
    var out: [32]u8 = undefined;
    st.final(&out);
    return out;
}

fn labeledExpand(prk: [32]u8, suite_id: []const u8, label: []const u8, info: []const u8, out: []u8) void {
    std.debug.assert(out.len <= 255 * 32);
    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, @intCast(out.len), .big);
    var prev_block: [32]u8 = undefined;
    var prev_len: usize = 0;
    var counter: u8 = 1;
    var offset: usize = 0;
    while (offset < out.len) : (offset += @min(32, out.len - offset)) {
        var st = Hmac.init(&prk);
        if (prev_len != 0) st.update(prev_block[0..prev_len]);
        st.update(&len_bytes);
        st.update("HPKE-v1");
        st.update(suite_id);
        st.update(label);
        st.update(info);
        st.update(&.{counter});
        var block: [32]u8 = undefined;
        st.final(&block);
        prev_block = block;
        prev_len = 32;
        const take = @min(32, out.len - offset);
        @memcpy(out[offset .. offset + take], block[0..take]);
        counter += 1;
    }
}

fn extractAndExpand(dh: [32]u8, kem_context: []const u8, out: *[32]u8) void {
    const eae_prk = labeledExtract(&kem_suite_id, "", "eae_prk", &dh);
    labeledExpand(eae_prk, &kem_suite_id, "shared_secret", kem_context, out);
}

/// RFC 9180 section 7.1.3 DeriveKeyPair for X25519: the secret is the
/// labeled expand; the public key is X25519 of the secret. The secret
/// bytes are stored unclamped; X25519 clamps when it is used.
pub fn deriveKeyPairSecret(ikm: []const u8) [32]u8 {
    const dkp_prk = labeledExtract(&kem_suite_id, "", "dkp_prk", ikm);
    var sk: [32]u8 = undefined;
    labeledExpand(dkp_prk, &kem_suite_id, "sk", "", &sk);
    return sk;
}

/// The HPKE base-mode context for one setup: AEAD key, nonce base, and
/// exporter secret, with the sequence number selecting the nonce.
pub const Context = struct {
    key: [key_len]u8,
    base_nonce: [nonce_len]u8,
    exporter_secret: [32]u8,
    seq: u32 = 0,

    fn nonceAtSeq(self: *const Context, seq: u32) [nonce_len]u8 {
        var nonce = self.base_nonce;
        var seq_bytes: [nonce_len]u8 = undefined;
        std.mem.writeInt(u96, &seq_bytes, seq, .big);
        for (&nonce, seq_bytes) |*b, s| b.* ^= s;
        return nonce;
    }

    /// ct_out is plaintext length plus the 16-byte tag (ciphertext || tag).
    pub fn seal(self: *Context, aad: []const u8, pt: []const u8, ct_out: []u8) void {
        std.debug.assert(ct_out.len == pt.len + tag_len);
        const nonce = self.nonceAtSeq(self.seq);
        var tag: [tag_len]u8 = undefined;
        Aes128Gcm.encrypt(ct_out[0..pt.len], &tag, pt, aad, nonce, self.key);
        @memcpy(ct_out[pt.len..], &tag);
        self.seq += 1;
    }

    pub fn open(self: *Context, aad: []const u8, ct: []const u8, pt_out: []u8) std.crypto.errors.AuthenticationError!void {
        std.debug.assert(ct.len == pt_out.len + tag_len);
        const nonce = self.nonceAtSeq(self.seq);
        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, ct[pt_out.len..]);
        try Aes128Gcm.decrypt(pt_out, ct[0..pt_out.len], tag, aad, nonce, self.key);
        self.seq += 1;
    }

    pub fn exportSecret(self: *const Context, exporter_context: []const u8, out: []u8) void {
        labeledExpand(self.exporter_secret, &hpke_suite_id, "sec", exporter_context, out);
    }
};

fn keySchedule(shared_secret: [32]u8, info: []const u8) Context {
    const psk_id_hash = labeledExtract(&hpke_suite_id, "", "psk_id_hash", "");
    const info_hash = labeledExtract(&hpke_suite_id, "", "info_hash", info);
    var ctx_buf: [65]u8 = undefined;
    ctx_buf[0] = 0x00;
    @memcpy(ctx_buf[1..33], &psk_id_hash);
    @memcpy(ctx_buf[33..65], &info_hash);
    const secret = labeledExtract(&hpke_suite_id, &shared_secret, "secret", "");
    var ctx = Context{ .key = undefined, .base_nonce = undefined, .exporter_secret = undefined };
    labeledExpand(secret, &hpke_suite_id, "key", &ctx_buf, &ctx.key);
    labeledExpand(secret, &hpke_suite_id, "base_nonce", &ctx_buf, &ctx.base_nonce);
    labeledExpand(secret, &hpke_suite_id, "exp", &ctx_buf, &ctx.exporter_secret);
    return ctx;
}

fn checkDh(dh: [32]u8) Error!void {
    var all_zero = true;
    for (dh) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return error.BadMessage;
}

/// RFC 9180 section 4.1 Encap for the base mode.
fn encap(io: std.Io, pk_r: [32]u8) !struct { enc: [32]u8, shared: [32]u8 } {
    const ephemeral = X25519.KeyPair.generate(io);
    const dh = X25519.scalarmult(ephemeral.secret_key, pk_r) catch return error.BadMessage;
    try checkDh(dh);
    var kem_context: [64]u8 = undefined;
    @memcpy(kem_context[0..32], &ephemeral.public_key);
    @memcpy(kem_context[32..64], &pk_r);
    var shared: [32]u8 = undefined;
    extractAndExpand(dh, &kem_context, &shared);
    return .{ .enc = ephemeral.public_key, .shared = shared };
}

/// RFC 9180 section 4.1 Decap.
fn decap(enc: [32]u8, sk_r: [32]u8) ![32]u8 {
    const dh = X25519.scalarmult(sk_r, enc) catch return error.BadMessage;
    try checkDh(dh);
    const pk_r = X25519.recoverPublicKey(sk_r);
    var kem_context: [64]u8 = undefined;
    @memcpy(kem_context[0..32], &enc);
    @memcpy(kem_context[32..64], &pk_r);
    var shared: [32]u8 = undefined;
    extractAndExpand(dh, &kem_context, &shared);
    return shared;
}

pub fn setupBaseS(io: std.Io, pk_r: [32]u8, info: []const u8) !struct { enc: [32]u8, context: Context } {
    const k = try encap(io, pk_r);
    return .{ .enc = k.enc, .context = keySchedule(k.shared, info) };
}

pub fn setupBaseR(enc: [32]u8, sk_r: [32]u8, info: []const u8) !Context {
    const shared = try decap(enc, sk_r);
    return keySchedule(shared, info);
}

/// The ObliviousDoHConfigContents encoding: kem_id, kdf_id, aead_id,
/// and the public key as an opaque vector with a two-octet length.
pub fn writeConfigContents(public_key: [32]u8, out: *[40]u8) void {
    std.mem.writeInt(u16, out[0..2], kem_id, .big);
    std.mem.writeInt(u16, out[2..4], kdf_id, .big);
    std.mem.writeInt(u16, out[4..6], aead_id, .big);
    std.mem.writeInt(u16, out[6..8], 32, .big);
    @memcpy(out[8..40], &public_key);
}

/// The ObliviousDoHConfigs bytes: a vector length, then one config whose
/// contents are the ObliviousDoHConfigContents.
pub fn buildConfigs(allocator: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    const out = try allocator.alloc(u8, 46);
    var contents: [40]u8 = undefined;
    writeConfigContents(public_key, &contents);
    std.mem.writeInt(u16, out[0..2], 44, .big);
    std.mem.writeInt(u16, out[2..4], config_version, .big);
    std.mem.writeInt(u16, out[4..6], 40, .big);
    @memcpy(out[6..46], &contents);
    return out;
}

/// RFC 9230 section 6: the key_id is the HKDF expand of the config
/// contents, with an empty extract salt and the "odoh key id" info.
pub fn computeKeyId(config_contents: []const u8) [32]u8 {
    const prk = Hkdf.extract("", config_contents);
    var key_id: [32]u8 = undefined;
    Hkdf.expand(&key_id, key_id_label, prk);
    return key_id;
}

pub fn makeTarget(private_key: [32]u8) Target {
    const public_key = X25519.recoverPublicKey(private_key);
    var contents: [40]u8 = undefined;
    writeConfigContents(public_key, &contents);
    return .{ .private_key = private_key, .public_key = public_key, .key_id = computeKeyId(&contents) };
}

/// The operator key file: exactly 64 hex characters for 32 bytes, with
/// surrounding whitespace allowed. The text is wiped by the caller.
pub fn parsePrivateKeyHex(text: []const u8) Error![32]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len != 64) return error.BadPrivateKey;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, trimmed) catch return error.BadPrivateKey;
    return out;
}

pub fn parseMessage(body: []const u8) Error!ParsedMessage {
    if (body.len < 1 + 2 + 2) return error.BadMessage;
    const message_type = body[0];
    const key_id_len = std.mem.readInt(u16, body[1..3], .big);
    const key_start: usize = 3;
    const key_end = key_start + key_id_len;
    if (key_end + 2 > body.len) return error.BadMessage;
    const enc_len_read = std.mem.readInt(u16, body[key_end..][0..2], .big);
    if (enc_len_read == 0) return error.BadMessage;
    const enc_start = key_end + 2;
    const enc_end = enc_start + enc_len_read;
    if (enc_end != body.len) return error.BadMessage;
    return .{
        .message_type = message_type,
        .key_id = body[key_start..key_end],
        .encrypted = body[enc_start..enc_end],
    };
}

pub fn buildMessage(allocator: std.mem.Allocator, message_type: u8, key_id: []const u8, encrypted: []const u8) ![]u8 {
    if (key_id.len > 65535 or encrypted.len == 0 or encrypted.len > 65535) return error.BadMessage;
    const out = try allocator.alloc(u8, 1 + 2 + key_id.len + 2 + encrypted.len);
    out[0] = message_type;
    std.mem.writeInt(u16, out[1..3], @intCast(key_id.len), .big);
    @memcpy(out[3 .. 3 + key_id.len], key_id);
    const len_off = 3 + key_id.len;
    std.mem.writeInt(u16, out[len_off..][0..2], @intCast(encrypted.len), .big);
    @memcpy(out[len_off + 2 ..], encrypted);
    return out;
}

pub fn parsePlaintext(pt: []const u8) Error!struct { dns: []const u8, padding: []const u8 } {
    if (pt.len < 2 + 2) return error.BadMessage;
    const dns_len = std.mem.readInt(u16, pt[0..2], .big);
    if (dns_len == 0) return error.BadMessage;
    if (2 + dns_len + 2 > pt.len) return error.BadMessage;
    const pad_len = std.mem.readInt(u16, pt[2 + dns_len ..][0..2], .big);
    if (2 + dns_len + 2 + pad_len != pt.len) return error.BadMessage;
    const dns = pt[2 .. 2 + dns_len];
    const padding = pt[2 + dns_len + 2 ..];
    for (padding) |b| {
        if (b != 0) return error.BadMessage;
    }
    return .{ .dns = dns, .padding = padding };
}

pub fn buildPlaintext(allocator: std.mem.Allocator, dns: []const u8, padding: []const u8) ![]u8 {
    if (dns.len == 0 or dns.len > 65535 or padding.len > 65535) return error.BadMessage;
    const out = try allocator.alloc(u8, 2 + dns.len + 2 + padding.len);
    std.mem.writeInt(u16, out[0..2], @intCast(dns.len), .big);
    @memcpy(out[2 .. 2 + dns.len], dns);
    const pad_off = 2 + dns.len;
    std.mem.writeInt(u16, out[pad_off..][0..2], @intCast(padding.len), .big);
    @memcpy(out[pad_off + 2 ..], padding);
    return out;
}

fn aadFor(message_type: u8, key_id: []const u8, out: []u8) void {
    out[0] = message_type;
    std.mem.writeInt(u16, out[1..3], @intCast(key_id.len), .big);
    @memcpy(out[3..], key_id);
}

/// Opens one ObliviousDoHMessage query to its DNS plaintext.
pub fn openQuery(allocator: std.mem.Allocator, target: *const Target, body: []const u8) !OpenQueryResult {
    const parsed = try parseMessage(body);
    if (parsed.message_type != query_message_type) return error.BadMessage;
    if (parsed.key_id.len != target.key_id.len or !std.crypto.timing_safe.eql([32]u8, parsed.key_id[0..32].*, target.key_id)) {
        return error.UnknownKeyId;
    }
    if (parsed.encrypted.len < enc_len + tag_len) return error.BadMessage;
    var enc: [32]u8 = undefined;
    @memcpy(&enc, parsed.encrypted[0..32]);
    var context = try setupBaseR(enc, target.private_key, query_info);
    var aad: [35]u8 = undefined;
    aadFor(query_message_type, parsed.key_id, &aad);
    const ct = parsed.encrypted[32..];
    const pt = try allocator.alloc(u8, ct.len - tag_len);
    errdefer allocator.free(pt);
    context.open(&aad, ct, pt) catch return error.BadMessage;
    const plain = try parsePlaintext(pt);
    return .{ .q_plain = pt, .dns_query = @constCast(plain.dns), .exporter_secret = context.exporter_secret };
}

/// Seals one DNS answer into an ObliviousDoHMessage response. The
/// response plaintext carries a zero-length padding.
pub fn sealResponse(allocator: std.mem.Allocator, io: std.Io, exporter_secret: [32]u8, q_plain: []const u8, dns_response: []const u8) ![]u8 {
    const exporter = Context{ .key = undefined, .base_nonce = undefined, .exporter_secret = exporter_secret };
    var secret: [key_len]u8 = undefined;
    exporter.exportSecret(response_export_context, &secret);
    var resp_nonce: [resp_nonce_len]u8 = undefined;
    io.random(&resp_nonce);
    const salt = try allocator.alloc(u8, q_plain.len + 2 + resp_nonce.len);
    defer allocator.free(salt);
    @memcpy(salt[0..q_plain.len], q_plain);
    std.mem.writeInt(u16, salt[q_plain.len..][0..2], @intCast(resp_nonce.len), .big);
    @memcpy(salt[q_plain.len + 2 ..], &resp_nonce);
    const prk = Hkdf.extract(salt, &secret);
    var key: [key_len]u8 = undefined;
    Hkdf.expand(&key, response_key_label, prk);
    var nonce: [nonce_len]u8 = undefined;
    Hkdf.expand(&nonce, response_nonce_label, prk);
    const r_plain = try buildPlaintext(allocator, dns_response, &.{});
    defer allocator.free(r_plain);
    var aad: [19]u8 = undefined;
    aadFor(response_message_type, &resp_nonce, &aad);
    var tag: [tag_len]u8 = undefined;
    const encrypted = try allocator.alloc(u8, r_plain.len + tag_len);
    defer allocator.free(encrypted);
    Aes128Gcm.encrypt(encrypted[0..r_plain.len], &tag, r_plain, &aad, nonce, key);
    @memcpy(encrypted[r_plain.len..], &tag);
    return buildMessage(allocator, response_message_type, &resp_nonce, encrypted);
}

/// Opens one sealed response as the client does, for tests: derives the
/// response keys from the sender exporter secret and the query plaintext
/// and decrypts the DNS answer.
pub fn openResponse(allocator: std.mem.Allocator, exporter_secret: [32]u8, q_plain: []const u8, sealed_response: []const u8) ![]u8 {
    const parsed = try parseMessage(sealed_response);
    if (parsed.message_type != response_message_type) return error.BadMessage;
    const exporter = Context{ .key = undefined, .base_nonce = undefined, .exporter_secret = exporter_secret };
    var secret: [key_len]u8 = undefined;
    exporter.exportSecret(response_export_context, &secret);
    const salt = try allocator.alloc(u8, q_plain.len + 2 + parsed.key_id.len);
    defer allocator.free(salt);
    @memcpy(salt[0..q_plain.len], q_plain);
    std.mem.writeInt(u16, salt[q_plain.len..][0..2], @intCast(parsed.key_id.len), .big);
    @memcpy(salt[q_plain.len + 2 ..], parsed.key_id);
    const prk = Hkdf.extract(salt, &secret);
    var key: [key_len]u8 = undefined;
    Hkdf.expand(&key, response_key_label, prk);
    var nonce: [nonce_len]u8 = undefined;
    Hkdf.expand(&nonce, response_nonce_label, prk);
    var aad: [19]u8 = undefined;
    aadFor(response_message_type, parsed.key_id, &aad);
    const r_plain = try allocator.alloc(u8, parsed.encrypted.len - tag_len);
    errdefer allocator.free(r_plain);
    Aes128Gcm.decrypt(r_plain, parsed.encrypted[0..r_plain.len], parsed.encrypted[r_plain.len..][0..tag_len].*, &aad, nonce, key) catch return error.BadMessage;
    const open = try parsePlaintext(r_plain);
    return @constCast(open.dns);
}

/// Seals one ObliviousDoHMessage query as the client does, for tests.
pub fn sealQuery(allocator: std.mem.Allocator, io: std.Io, public_key: [32]u8, key_id: []const u8, q_plain: []const u8) ![]u8 {
    var setup = try setupBaseS(io, public_key, query_info);
    var aad: [35]u8 = undefined;
    aadFor(query_message_type, key_id, aad[0 .. 1 + 2 + key_id.len]);
    const ct = try allocator.alloc(u8, q_plain.len + tag_len);
    defer allocator.free(ct);
    setup.context.seal(aad[0 .. 1 + 2 + key_id.len], q_plain, ct);
    const encrypted = try allocator.alloc(u8, enc_len + ct.len);
    defer allocator.free(encrypted);
    @memcpy(encrypted[0..32], &setup.enc);
    @memcpy(encrypted[32..], ct);
    return buildMessage(allocator, query_message_type, key_id, encrypted);
}

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "RFC 9180 A.1.1 base vector" {
    const ikm_e = hexBytes("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    const sk_e = hexBytes("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    const pk_e = hexBytes("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    const ikm_r = hexBytes("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    const sk_r = hexBytes("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    const pk_r = hexBytes("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    const shared = hexBytes("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    const key = hexBytes("4531685d41d65f03dc48f6b8302c05b0");
    const base_nonce = hexBytes("56d890e5accaaf011cff4b7d");
    const exporter_secret = hexBytes("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
    const info = hexBytes("4f6465206f6e2061204772656369616e2055726e");

    try std.testing.expectEqual(sk_e, deriveKeyPairSecret(&ikm_e));
    try std.testing.expectEqual(pk_e, X25519.recoverPublicKey(sk_e));
    try std.testing.expectEqual(sk_r, deriveKeyPairSecret(&ikm_r));
    try std.testing.expectEqual(pk_r, X25519.recoverPublicKey(sk_r));

    const dh = try X25519.scalarmult(sk_e, pk_r);
    var kem_context: [64]u8 = undefined;
    @memcpy(kem_context[0..32], &pk_e);
    @memcpy(kem_context[32..64], &pk_r);
    var got_shared: [32]u8 = undefined;
    extractAndExpand(dh, &kem_context, &got_shared);
    try std.testing.expectEqual(shared, got_shared);

    const ctx = keySchedule(shared, &info);
    try std.testing.expectEqual(key, ctx.key);
    try std.testing.expectEqual(base_nonce, ctx.base_nonce);
    try std.testing.expectEqual(exporter_secret, ctx.exporter_secret);

    const pt = hexBytes("4265617574792069732074727574682c20747275746820626561757479");
    const aad = hexBytes("436f756e742d30");
    const ct_expected = hexBytes("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
    var boxed = ctx;
    var ct: [ct_expected.len]u8 = undefined;
    boxed.seal(&aad, &pt, &ct);
    try std.testing.expectEqual(ct_expected, ct);

    var recv = ctx;
    var pt_out: [pt.len]u8 = undefined;
    try recv.open(&aad, &ct, &pt_out);
    try std.testing.expectEqual(pt, pt_out);

    var exported: [32]u8 = undefined;
    boxed.exportSecret("", &exported);
    try std.testing.expectEqual(hexBytes("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"), exported);
}

test "RFC 9180 A.1.1 sequence and export" {
    const shared = hexBytes("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    const info = hexBytes("4f6465206f6e2061204772656369616e2055726e");
    const pt = hexBytes("4265617574792069732074727574682c20747275746820626561757479");
    var ctx = keySchedule(shared, &info);
    ctx.seq = 1;
    try std.testing.expectEqual(hexBytes("56d890e5accaaf011cff4b7c"), ctx.nonceAtSeq(1));
    const aad = hexBytes("436f756e742d31");
    const ct_expected = hexBytes("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84");
    var ct: [ct_expected.len]u8 = undefined;
    ctx.seal(&aad, &pt, &ct);
    try std.testing.expectEqual(ct_expected, ct);
    var exported: [32]u8 = undefined;
    ctx.exportSecret(&.{0x00}, &exported);
    try std.testing.expectEqual(hexBytes("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"), exported);
}

test "ODoH query and response round trip" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8") catch unreachable;
    const target = makeTarget(priv);
    var contents: [40]u8 = undefined;
    writeConfigContents(target.public_key, &contents);
    try std.testing.expectEqual(target.key_id, computeKeyId(&contents));

    const dns_query = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x00, 0x00, 0x01, 0x00, 0x01 };
    const q_plain = try buildPlaintext(allocator, &dns_query, &[_]u8{ 0, 0, 0, 0 });
    const sealed_query = try sealQuery(allocator, io, target.public_key, &target.key_id, q_plain);
    const opened = try openQuery(allocator, &target, sealed_query);
    try std.testing.expectEqualSlices(u8, &dns_query, opened.dns_query);

    const dns_response = [_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const sealed_response = try sealResponse(allocator, io, opened.exporter_secret, opened.q_plain, &dns_response);
    const r_parsed = try parseMessage(sealed_response);
    try std.testing.expectEqual(response_message_type, r_parsed.message_type);
    try std.testing.expectEqual(@as(usize, resp_nonce_len), r_parsed.key_id.len);
    try std.testing.expectEqualSlices(u8, &dns_response, try openResponse(allocator, opened.exporter_secret, opened.q_plain, sealed_response));
}

test "ODoH rejects wrong key, corrupt ciphertext, and bad padding" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8") catch unreachable;
    const target = makeTarget(priv);
    const dns_query = [_]u8{ 0x11, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
    const q_plain = try buildPlaintext(allocator, &dns_query, &.{});
    const sealed = try sealQuery(allocator, io, target.public_key, &target.key_id, q_plain);
    var wrong_key = target.key_id;
    wrong_key[0] ^= 0xff;
    const wrong_key_msg = try buildMessage(allocator, query_message_type, &wrong_key, (try parseMessage(sealed)).encrypted);
    try std.testing.expectError(error.UnknownKeyId, openQuery(allocator, &target, wrong_key_msg));
    var corrupt = try allocator.dupe(u8, sealed);
    corrupt[corrupt.len - 1] ^= 0xff;
    try std.testing.expectError(error.BadMessage, openQuery(allocator, &target, corrupt));
    try std.testing.expectError(error.BadMessage, parsePlaintext(try buildPlaintext(allocator, &dns_query, &[_]u8{1})));
}
