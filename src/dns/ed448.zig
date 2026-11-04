const std = @import("std");

// SHAKE256 lives at std.crypto.hash.sha3.Shake256 in Zig 0.17;
// std.crypto.hash.shake.Shake256 names the same type in older docs.
const Shake256 = std.crypto.hash.sha3.Shake256;

pub const PublicKey = [57]u8;
pub const Signature = [114]u8;
pub const SecretKey = [57]u8;

const Field = [7]u64;
const Scalar = [8]u64;

const P: Field = .{
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xfffffffeffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
};

const P_MINUS_2: Field = .{
    0xfffffffffffffffd,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xfffffffeffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
};

// (p + 1) / 4, the square-root exponent for p = 3 (mod 4).
const SQRT_EXP: Field = .{
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0xffffffffc0000000,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x3fffffffffffffff,
};

// d = -39081 (mod p).
const D_FIELD: Field = .{
    0xffffffffffff6756,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xfffffffeffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
};

const BASE_X: Field = .{
    0x2626a82bc70cc05e,
    0x433b80e18b00938e,
    0x12ae1af72ab66511,
    0xea6de324a3d3a464,
    0x9e146570470f1767,
    0x221d15a622bf36da,
    0x4f1970c66bed0ded,
};

const BASE_Y: Field = .{
    0x9808795bf230fa14,
    0xfdbd132c4ed7c8ad,
    0x3ad3ff1ce67c39c4,
    0x87789c1e05a0c2d7,
    0x4bea73736ca39840,
    0x8876203756c9c762,
    0x693f46716eb6bc24,
};

// Group order of the base point.
const L: Scalar = .{
    0x2378c292ab5844f3,
    0x216cc2728dc58f55,
    0xc44edb49aed63690,
    0xffffffff7cca23e9,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x3fffffffffffffff,
    0x0000000000000000,
};

const dom4: [10]u8 = .{ 'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0, 0 };

const Point = struct {
    x: Field,
    y: Field,
    z: Field,
};

const ZERO: Field = .{ 0, 0, 0, 0, 0, 0, 0 };
const ONE: Field = .{ 1, 0, 0, 0, 0, 0, 0 };

const IDENTITY: Point = .{ .x = ZERO, .y = ONE, .z = ONE };
const BASE: Point = .{ .x = BASE_X, .y = BASE_Y, .z = ONE };

fn fieldIsZero(a: Field) bool {
    var v: u64 = 0;
    for (0..7) |i| v |= a[i];
    return v == 0;
}

fn fieldEqCt(a: Field, b: Field) bool {
    var diff: u64 = 0;
    for (0..7) |i| diff |= a[i] ^ b[i];
    return diff == 0;
}

// -1 if a < b, 0 if equal, 1 if a > b.
fn fieldCmp(a: Field, b: Field) i32 {
    var i: usize = 7;
    while (true) {
        i -= 1;
        if (a[i] != b[i]) return if (a[i] > b[i]) 1 else -1;
        if (i == 0) break;
    }
    return 0;
}

fn fieldGe(a: Field, b: Field) bool {
    return fieldCmp(a, b) >= 0;
}

fn sub8(a: [8]u64, b: Field) [8]u64 {
    var out: [8]u64 = undefined;
    var borrow: i128 = 0;
    for (0..7) |i| {
        const diff: i128 = @as(i128, a[i]) - @as(i128, b[i]) - borrow;
        if (diff < 0) {
            out[i] = @intCast(diff + (@as(i128, 1) << 64));
            borrow = 1;
        } else {
            out[i] = @intCast(diff);
            borrow = 0;
        }
    }
    const diff: i128 = @as(i128, a[7]) - borrow;
    if (diff < 0) {
        out[7] = @intCast(diff + (@as(i128, 1) << 64));
    } else {
        out[7] = @intCast(diff);
    }
    return out;
}

fn ge8(a: [8]u64, b: Field) bool {
    if (a[7] != 0) return true;
    var i: usize = 7;
    while (true) {
        i -= 1;
        if (a[i] != b[i]) return a[i] > b[i];
        if (i == 0) break;
    }
    return true;
}

fn fieldAdd(a: Field, b: Field) Field {
    var sum: [8]u64 = undefined;
    var carry: u128 = 0;
    for (0..7) |i| {
        const s: u128 = @as(u128, a[i]) + @as(u128, b[i]) + carry;
        sum[i] = @truncate(s);
        carry = s >> 64;
    }
    sum[7] = @intCast(carry);
    if (ge8(sum, P)) {
        const r = sub8(sum, P);
        var out: Field = undefined;
        for (0..7) |i| out[i] = r[i];
        return out;
    }
    var out: Field = undefined;
    for (0..7) |i| out[i] = sum[i];
    return out;
}

fn fieldSubInner(a: Field, b: Field, add_p: bool) Field {
    var aa: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    for (0..7) |i| aa[i] = a[i];
    if (add_p) {
        var carry: u128 = 0;
        for (0..7) |i| {
            const s: u128 = @as(u128, aa[i]) + @as(u128, P[i]) + carry;
            aa[i] = @truncate(s);
            carry = s >> 64;
        }
        const carry64: u64 = @intCast(carry);
        aa[7] = carry64 + aa[7];
    }
    const bb: [8]u64 = .{ b[0], b[1], b[2], b[3], b[4], b[5], b[6], 0 };
    const r = _sub8(bb, aa);
    var out: Field = undefined;
    for (0..7) |i| out[i] = r[i];
    return out;
}

fn _sub8(b: [8]u64, a: [8]u64) [8]u64 {
    // a - b assuming a >= b.
    var out: [8]u64 = undefined;
    var borrow: i128 = 0;
    for (0..8) |i| {
        const diff: i128 = @as(i128, a[i]) - @as(i128, b[i]) - borrow;
        if (diff < 0) {
            out[i] = @intCast(diff + (@as(i128, 1) << 64));
            borrow = 1;
        } else {
            out[i] = @intCast(diff);
            borrow = 0;
        }
    }
    return out;
}

fn fieldSub(a: Field, b: Field) Field {
    if (fieldGe(a, b)) return fieldSubInner(a, b, false);
    return fieldSubInner(a, b, true);
}

fn fieldNeg(a: Field) Field {
    if (fieldIsZero(a)) return ZERO;
    return fieldSub(P, a);
}

fn product14(a: Field, b: Field) [14]u64 {
    var out: [14]u64 = @as([14]u64, @splat(0));
    for (0..7) |i| {
        var carry: u128 = 0;
        for (0..7) |j| {
            const prod: u128 = @as(u128, a[i]) * @as(u128, b[j]) + @as(u128, out[i + j]) + carry;
            out[i + j] = @truncate(prod);
            carry = prod >> 64;
        }
        var k: usize = i + 7;
        while (carry != 0) {
            const s: u128 = @as(u128, out[k]) + carry;
            out[k] = @truncate(s);
            carry = s >> 64;
            k += 1;
        }
    }
    return out;
}

fn reduce14(v: [14]u64) Field {
    var s: [7]u64 = undefined;
    var carry: u128 = 0;
    for (0..7) |i| {
        const sum: u128 = @as(u128, v[i]) + @as(u128, v[i + 7]) + carry;
        s[i] = @truncate(sum);
        carry = sum >> 64;
    }
    const s_carry: u64 = @intCast(carry);
    var t: [11]u64 = @as([11]u64, @splat(0));
    t[3] = v[7] << 32;
    for (1..7) |i| {
        t[i + 3] = (v[7 + i] << 32) | (v[7 + i - 1] >> 32);
    }
    t[10] = v[13] >> 32;
    var w: [11]u64 = undefined;
    var c: u128 = 0;
    for (0..7) |i| {
        const sum: u128 = @as(u128, s[i]) + @as(u128, t[i]) + c;
        w[i] = @truncate(sum);
        c = sum >> 64;
    }
    {
        const sum: u128 = @as(u128, s_carry) + @as(u128, t[7]) + c;
        w[7] = @truncate(sum);
        c = sum >> 64;
    }
    for (8..11) |i| {
        const sum: u128 = @as(u128, t[i]) + c;
        w[i] = @truncate(sum);
        c = sum >> 64;
    }
    var u: [7]u64 = undefined;
    var cu: u128 = 0;
    for (0..7) |i| {
        const add: u64 = if (i < 4) w[7 + i] else 0;
        const sum: u128 = @as(u128, w[i]) + @as(u128, add) + cu;
        u[i] = @truncate(sum);
        cu = sum >> 64;
    }
    const u_carry: u64 = @intCast(cu);
    var vs: [8]u64 = @as([8]u64, @splat(0));
    vs[3] = w[7] << 32;
    for (1..4) |i| {
        vs[i + 3] = (w[7 + i] << 32) | (w[7 + i - 1] >> 32);
    }
    vs[7] = w[10] >> 32;
    var fin: [8]u64 = undefined;
    var cf: u128 = 0;
    for (0..7) |i| {
        const sum: u128 = @as(u128, u[i]) + @as(u128, vs[i]) + cf;
        fin[i] = @truncate(sum);
        cf = sum >> 64;
    }
    {
        const sum: u128 = @as(u128, u_carry) + @as(u128, vs[7]) + cf;
        fin[7] = @truncate(sum);
    }
    for (0..16) |_| {
        if (!ge8(fin, P)) break;
        fin = sub8(fin, P);
    }
    var out: Field = undefined;
    for (0..7) |i| out[i] = fin[i];
    return out;
}

fn fieldMul(a: Field, b: Field) Field {
    if (fieldIsZero(a) or fieldIsZero(b)) return ZERO;
    return reduce14(product14(a, b));
}

fn fieldPow(base: Field, exp: Field) Field {
    var result: Field = ONE;
    // MSB to LSB over 448 bits.
    var bit: i32 = 447;
    while (bit >= 0) : (bit -= 1) {
        result = fieldMul(result, result);
        const limb: usize = @intCast(@divFloor(bit, 64));
        const off: usize = @intCast(@mod(bit, 64));
        const shift: u6 = @intCast(off);
        if (((exp[limb] >> shift) & 1) == 1) {
            result = fieldMul(result, base);
        }
    }
    return result;
}

fn fieldInv(a: Field) Field {
    if (fieldIsZero(a)) return ZERO;
    return fieldPow(a, P_MINUS_2);
}

fn pointAdd(p: Point, q: Point) Point {
    const a = fieldMul(p.z, q.z);
    const b = fieldMul(a, a);
    const c = fieldMul(p.x, q.x);
    const d = fieldMul(p.y, q.y);
    const cd = fieldMul(c, d);
    const e = fieldMul(D_FIELD, cd);
    const f = fieldSub(b, e);
    const g = fieldAdd(b, e);
    const h = fieldMul(fieldAdd(p.x, p.y), fieldAdd(q.x, q.y));
    const hc = fieldSub(h, c);
    const hcd = fieldSub(hc, d);
    const dc = fieldSub(d, c);
    const x3 = fieldMul(a, fieldMul(f, hcd));
    const y3 = fieldMul(a, fieldMul(g, dc));
    const z3 = fieldMul(f, g);
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn pointDouble(p: Point) Point {
    const b = fieldMul(fieldAdd(p.x, p.y), fieldAdd(p.x, p.y));
    const c = fieldMul(p.x, p.x);
    const d = fieldMul(p.y, p.y);
    const e = fieldAdd(c, d);
    const h = fieldMul(p.z, p.z);
    const two_h = fieldAdd(h, h);
    const j = fieldSub(e, two_h);
    const be = fieldSub(b, e);
    const cd = fieldSub(c, d);
    const x3 = fieldMul(be, j);
    const y3 = fieldMul(e, cd);
    const z3 = fieldMul(e, j);
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn scalarBit(s: Scalar, bit: usize) bool {
    const limb: usize = bit / 64;
    const off: usize = bit % 64;
    const shift: u6 = @intCast(off);
    return ((s[limb] >> shift) & 1) == 1;
}

fn scalarMult(p: Point, s: Scalar) Point {
    var result: Point = IDENTITY;
    var addend: Point = p;
    for (0..512) |i| {
        if (scalarBit(s, i)) result = pointAdd(result, addend);
        addend = pointDouble(addend);
    }
    return result;
}

fn encodePoint(p: Point) [57]u8 {
    const iz = fieldInv(p.z);
    const x = fieldMul(p.x, iz);
    const y = fieldMul(p.y, iz);
    var out: [57]u8 = undefined;
    for (0..56) |i| {
        const limb: usize = i / 8;
        const off: usize = i % 8;
        const shift: u6 = @intCast(off * 8);
        out[i] = @intCast((y[limb] >> shift) & 0xff);
    }
    out[56] = 0;
    if ((x[0] & 1) == 1) out[56] |= 0x80;
    return out;
}

fn scalarCmp(a: Scalar, b: Scalar) i32 {
    var i: usize = 8;
    while (true) {
        i -= 1;
        if (a[i] != b[i]) return if (a[i] > b[i]) 1 else -1;
        if (i == 0) break;
    }
    return 0;
}

fn scalarSub(a: Scalar, b: Scalar) Scalar {
    var out: Scalar = undefined;
    var borrow: i128 = 0;
    for (0..8) |i| {
        const diff: i128 = @as(i128, a[i]) - @as(i128, b[i]) - borrow;
        if (diff < 0) {
            out[i] = @intCast(diff + (@as(i128, 1) << 64));
            borrow = 1;
        } else {
            out[i] = @intCast(diff);
            borrow = 0;
        }
    }
    return out;
}

fn scalarAddMod(a: Scalar, b: Scalar) Scalar {
    var sum: Scalar = undefined;
    var carry: u128 = 0;
    for (0..8) |i| {
        const s: u128 = @as(u128, a[i]) + @as(u128, b[i]) + carry;
        sum[i] = @truncate(s);
        carry = s >> 64;
    }
    if (scalarCmp(sum, L) >= 0) return scalarSub(sum, L);
    return sum;
}

fn scalarDoubleMod(a: Scalar) Scalar {
    return scalarAddMod(a, a);
}

fn scalarMulMod(k: Scalar, s: Scalar) Scalar {
    var result: Scalar = @as(Scalar, @splat(0));
    var cur: Scalar = k;
    for (0..512) |i| {
        if (scalarBit(s, i)) result = scalarAddMod(result, cur);
        cur = scalarDoubleMod(cur);
    }
    return result;
}

fn reduceShakeHash(bytes: [114]u8) Scalar {
    var rem: Scalar = @as(Scalar, @splat(0));
    var idx: usize = 0;
    while (idx < 912) : (idx += 1) {
        const bit: usize = 911 - idx;
        const byte_idx: usize = bit / 8;
        const off: usize = bit % 8;
        const shift: u3 = @intCast(off);
        const bit_val: u64 = @as(u64, (bytes[byte_idx] >> shift) & 1);
        var i: usize = 8;
        while (true) {
            i -= 1;
            if (i == 0) {
                rem[0] <<= 1;
                rem[0] |= bit_val;
            } else {
                const carry: u64 = rem[i - 1] >> 63;
                rem[i] = (rem[i] << 1) | carry;
            }
            if (i == 0) break;
        }
        if (scalarCmp(rem, L) >= 0) rem = scalarSub(rem, L);
    }
    return rem;
}

fn scalarFromLe(bytes: []const u8) Scalar {
    var out: Scalar = @as(Scalar, @splat(0));
    for (bytes, 0..) |b, i| {
        if (i >= 64) break;
        const limb: usize = i / 8;
        const off: usize = i % 8;
        const shift: u6 = @intCast(off * 8);
        out[limb] |= @as(u64, b) << shift;
    }
    return out;
}

fn scalarToLe(s: Scalar) [57]u8 {
    var out: [57]u8 = undefined;
    for (0..57) |i| {
        const limb: usize = i / 8;
        const off: usize = i % 8;
        const shift: u6 = @intCast(off * 8);
        out[i] = @intCast((s[limb] >> shift) & 0xff);
    }
    return out;
}

fn pointEqCt(a: Point, b: Point) bool {
    const x1z2 = fieldMul(a.x, b.z);
    const x2z1 = fieldMul(b.x, a.z);
    const y1z2 = fieldMul(a.y, b.z);
    const y2z1 = fieldMul(b.y, a.z);
    var diff: u64 = 0;
    for (0..7) |i| {
        diff |= x1z2[i] ^ x2z1[i];
        diff |= y1z2[i] ^ y2z1[i];
    }
    return diff == 0;
}

fn decodePoint(bytes: [57]u8) ?Point {
    const sign_bit: u64 = @as(u64, bytes[56] >> 7);
    var yb = bytes;
    yb[56] &= 0x7f;
    const y_scalar = scalarFromLe(&yb);
    const p_scalar: Scalar = .{
        P[0], P[1], P[2], P[3], P[4], P[5], P[6], 0,
    };
    if (scalarCmp(y_scalar, p_scalar) >= 0) return null;
    const y: Field = .{
        y_scalar[0], y_scalar[1], y_scalar[2], y_scalar[3],
        y_scalar[4], y_scalar[5], y_scalar[6],
    };
    const y2 = fieldMul(y, y);
    const one = ONE;
    const u = fieldSub(y2, one);
    const d_y2 = fieldMul(D_FIELD, y2);
    const v = fieldSub(d_y2, one);
    if (fieldIsZero(v)) return null;
    const xx = fieldMul(u, fieldInv(v));
    var x = fieldPow(xx, SQRT_EXP);
    if (!fieldEqCt(fieldMul(x, x), xx)) return null;
    if (fieldIsZero(x) and sign_bit == 1) return null;
    if ((x[0] & 1) != sign_bit) x = fieldNeg(x);
    return .{ .x = x, .y = y, .z = ONE };
}

fn shakeSecret(secret: SecretKey) [114]u8 {
    var out: [114]u8 = undefined;
    var h = Shake256.init(.{});
    h.update(&secret);
    h.final(&out);
    return out;
}

fn shakeR(prefix: [57]u8, message: []const u8) [114]u8 {
    var out: [114]u8 = undefined;
    var h = Shake256.init(.{});
    h.update(&dom4);
    h.update(&prefix);
    h.update(message);
    h.final(&out);
    return out;
}

fn shakeK(r_enc: [57]u8, public: PublicKey, message: []const u8) [114]u8 {
    var out: [114]u8 = undefined;
    var h = Shake256.init(.{});
    h.update(&dom4);
    h.update(&r_enc);
    h.update(&public);
    h.update(message);
    h.final(&out);
    return out;
}

fn secretScalar(khash: [114]u8) Scalar {
    var sb: [57]u8 = undefined;
    for (0..57) |i| sb[i] = khash[i];
    sb[0] &= 0xfc;
    sb[56] = 0;
    sb[55] |= 0x80;
    return scalarFromLe(&sb);
}

pub fn derivePublicKey(secret: SecretKey) PublicKey {
    const khash = shakeSecret(secret);
    const s = secretScalar(khash);
    return encodePoint(scalarMult(BASE, s));
}

pub fn sign(message: []const u8, secret: SecretKey, public: PublicKey, out: *Signature) void {
    const khash = shakeSecret(secret);
    const s = secretScalar(khash);
    var prefix: [57]u8 = undefined;
    for (0..57) |i| prefix[i] = khash[57 + i];
    const r_hash = shakeR(prefix, message);
    const r_mod = reduceShakeHash(r_hash);
    const r_enc = encodePoint(scalarMult(BASE, r_mod));
    const k_hash = shakeK(r_enc, public, message);
    const k_mod = reduceShakeHash(k_hash);
    const ks = scalarMulMod(k_mod, s);
    const s_val = scalarAddMod(r_mod, ks);
    const s_le = scalarToLe(s_val);
    for (0..57) |i| out.*[i] = r_enc[i];
    for (0..57) |i| out.*[57 + i] = s_le[i];
}

pub fn verify(message: []const u8, signature: Signature, public: PublicKey) bool {
    var r_enc: [57]u8 = undefined;
    var s_bytes: [57]u8 = undefined;
    for (0..57) |i| r_enc[i] = signature[i];
    for (0..57) |i| s_bytes[i] = signature[57 + i];
    const s_scalar = scalarFromLe(&s_bytes);
    if (scalarCmp(s_scalar, L) >= 0) return false;
    const r_point = decodePoint(r_enc) orelse return false;
    const a_point = decodePoint(public) orelse return false;
    const k_hash = shakeK(r_enc, public, message);
    const k_mod = reduceShakeHash(k_hash);
    var lhs = scalarMult(BASE, s_scalar);
    var rhs = pointAdd(r_point, scalarMult(a_point, k_mod));
    lhs = pointDouble(pointDouble(lhs));
    rhs = pointDouble(pointDouble(rhs));
    return pointEqCt(lhs, rhs);
}

// ---- Tests: RFC 8032 section 7.4 vectors ----

fn parseHex(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "ed448 rfc8032 blank vector" {
    const secret = parseHex(57, "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    const expected_public = parseHex(57, "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    const expected_sig = parseHex(114, "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
    const message: []const u8 = &.{};
    const public = derivePublicKey(secret);
    try std.testing.expectEqualSlices(u8, &expected_public, &public);
    var sig: Signature = undefined;
    sign(message, secret, public, &sig);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);
    try std.testing.expect(verify(message, sig, public));
    var bad = sig;
    bad[0] ^= 1;
    try std.testing.expect(!verify(message, bad, public));
}

test "ed448 rfc8032 one octet vector" {
    const secret = parseHex(57, "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
    const expected_public = parseHex(57, "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
    const expected_sig = parseHex(114, "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c0" ++ "3a00");
    const message: [1]u8 = .{0x03};
    const public = derivePublicKey(secret);
    try std.testing.expectEqualSlices(u8, &expected_public, &public);
    var sig: Signature = undefined;
    sign(&message, secret, public, &sig);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);
    try std.testing.expect(verify(&message, sig, public));
    var bad = sig;
    bad[10] ^= 1;
    try std.testing.expect(!verify(&message, bad, public));
}

test "ed448 rfc8032 eleven octet vector" {
    // RFC 8032 section 7.4 eleven-octet message is 0c3e544074ec63b0265e0c.
    const secret = parseHex(57, "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328");
    const expected_public = parseHex(57, "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400");
    const expected_sig = parseHex(114, "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00");
    const message = parseHex(11, "0c3e544074ec63b0265e0c");
    const public = derivePublicKey(secret);
    try std.testing.expectEqualSlices(u8, &expected_public, &public);
    var sig: Signature = undefined;
    sign(&message, secret, public, &sig);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);
    try std.testing.expect(verify(&message, sig, public));
    var bad = sig;
    bad[100] ^= 1;
    try std.testing.expect(!verify(&message, bad, public));
}

test "ed448 rejects non-canonical and out-of-range" {
    const secret = parseHex(57, "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    const message = parseHex(11, "0c3e544074ec63b0265e0c");
    const public = derivePublicKey(secret);
    var sig: Signature = undefined;
    sign(&message, secret, public, &sig);
    // S with high bits set is out of range.
    var bad_s = sig;
    bad_s[113] = 0xff;
    try std.testing.expect(!verify(&message, bad_s, public));
    // Top bits of y encoding set (non-canonical point encoding).
    var bad_pub = public;
    bad_pub[56] = 0x7f;
    try std.testing.expect(!verify(&message, sig, bad_pub));
}
