/// Contract: Parses a bounded BIND-compatible TSIG key file and owns secrets.
/// Ownership: Keyring stores copied names and secret bytes; deinit clears secrets.
/// The keyring also remembers the file it was parsed from, so a reload can
/// re-read it; the keyring itself never reads the file.
/// Errors: Malformed declarations and secret policy violations are typed; no I/O occurs.
/// One key name may carry several algorithms; the name with the algorithm is the key.
const std = @import("std");
const Name = @import("../dns/name.zig").Name;
const tsig = @import("../dns/tsig.zig");
const dns_record = @import("../dns/record.zig");
const dns_rdata = @import("../dns/rdata.zig");
const dns_writer = @import("../dns/writer.zig");

pub const max_keys = 16;
pub const max_secret_len = 64;
/// The longest key file path a keyring remembers. The configuration
/// directive that names the file bounds it the same way.
pub const max_path_len = 256;

pub const Error = error{
    BadSyntax,
    UnsupportedAlgorithm,
    BadSecret,
    SecretTooShort,
    SecretTooLong,
    DuplicateKey,
    TooManyKeys,
    PathTooLong,
};

/// The file a keyring was parsed from. The path is inline, so a keyring
/// carries the location wherever it is copied.
pub const Source = struct {
    dir: std.Io.Dir,
    bytes: [max_path_len]u8 = undefined,
    len: usize = 0,

    pub fn path(self: *const Source) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Key = struct {
    name: Name,
    algorithm: tsig.Algorithm,
    secret: [max_secret_len]u8 = undefined,
    secret_len: u8 = 0,

    pub fn secretBytes(self: *const Key) []const u8 {
        return self.secret[0..self.secret_len];
    }

    fn clear(self: *Key) void {
        std.crypto.secureZero(u8, &self.secret);
        self.secret_len = 0;
    }
};

pub const Keyring = struct {
    keys: [max_keys]Key = undefined,
    len: usize = 0,
    /// The file this keyring was parsed from. Null when the keyring was not
    /// read from a file.
    source: ?Source = null,

    pub fn parse(text: []const u8) Error!Keyring {
        var ring = Keyring{};
        errdefer ring.deinit();

        var scanner = Scanner{ .text = text };
        scanner.skipWhitespace();
        if (scanner.atEnd()) return Error.BadSyntax;

        while (!scanner.atEnd()) {
            if (ring.len == ring.keys.len) return Error.TooManyKeys;
            var key = try parseKey(&scanner);
            defer key.clear();
            for (ring.keys[0..ring.len]) |existing| {
                // RFC 8945 section 10 says there SHOULD only be one algorithm
                // associated with any given key name. This project departs
                // from that SHOULD on purpose: a name may carry several
                // algorithms, so a peer that rotates its algorithm stays
                // verifiable, and only the same name with the same algorithm
                // is the same key twice.
                if (existing.name.eql(&key.name) and existing.algorithm == key.algorithm) return Error.DuplicateKey;
            }
            ring.keys[ring.len] = key;
            ring.len += 1;
            scanner.skipWhitespace();
        }
        return ring;
    }

    /// The key that carries `name` with `algorithm`. Every key holding the
    /// name is checked, so a request that names an algorithm the first key
    /// of the name does not carry still finds its key.
    pub fn findAlgorithm(self: *const Keyring, name: Name, algorithm: tsig.Algorithm) ?*const Key {
        for (self.keys[0..self.len]) |*key| {
            if (key.name.eql(&name) and key.algorithm == algorithm) return key;
        }
        return null;
    }

    /// Records the file this keyring was parsed from, so a reload can
    /// re-read it.
    pub fn setSource(self: *Keyring, dir: std.Io.Dir, path: []const u8) Error!void {
        if (path.len > max_path_len) return Error.PathTooLong;
        var source = Source{ .dir = dir, .len = path.len };
        @memcpy(source.bytes[0..path.len], path);
        self.source = source;
    }

    /// Installs the keys of `other` and wipes the secrets this keyring
    /// held, so a replaced key leaves no secret behind in the freed slot.
    pub fn replace(self: *Keyring, other: *const Keyring) void {
        self.deinit();
        for (other.keys[0..other.len], 0..) |key, index| {
            self.keys[index] = key;
        }
        self.len = other.len;
    }

    pub fn deinit(self: *Keyring) void {
        for (self.keys[0..self.len]) |*key| {
            key.clear();
        }
        self.len = 0;
    }
};

const Scanner = struct {
    text: []const u8,
    index: usize = 0,

    fn atEnd(self: *const Scanner) bool {
        return self.index == self.text.len;
    }

    fn skipWhitespace(self: *Scanner) void {
        while (self.index < self.text.len and std.ascii.isWhitespace(self.text[self.index])) : (self.index += 1) {}
    }

    fn requireWhitespace(self: *Scanner) Error!void {
        if (self.index >= self.text.len or !std.ascii.isWhitespace(self.text[self.index])) return Error.BadSyntax;
        self.skipWhitespace();
    }

    fn expectWord(self: *Scanner, expected: []const u8) Error!void {
        const word = try self.readWord();
        if (!std.mem.eql(u8, word, expected)) return Error.BadSyntax;
    }

    fn readWord(self: *Scanner) Error![]const u8 {
        const start = self.index;
        while (self.index < self.text.len and !std.ascii.isWhitespace(self.text[self.index]) and
            self.text[self.index] != '{' and self.text[self.index] != '}' and self.text[self.index] != ';')
        {
            self.index += 1;
        }
        if (self.index == start) return Error.BadSyntax;
        return self.text[start..self.index];
    }

    fn readQuoted(self: *Scanner) Error![]const u8 {
        if (self.index >= self.text.len or self.text[self.index] != '"') return Error.BadSyntax;
        self.index += 1;
        const start = self.index;
        while (self.index < self.text.len and self.text[self.index] != '"') {
            if (self.text[self.index] == '\\' or self.text[self.index] < 0x20) return Error.BadSyntax;
            self.index += 1;
        }
        if (self.index >= self.text.len) return Error.BadSyntax;
        const result = self.text[start..self.index];
        self.index += 1;
        return result;
    }

    fn expect(self: *Scanner, byte: u8) Error!void {
        if (self.index >= self.text.len or self.text[self.index] != byte) return Error.BadSyntax;
        self.index += 1;
    }
};

fn parseKey(scanner: *Scanner) Error!Key {
    try scanner.expectWord("key");
    try scanner.requireWhitespace();
    const name_text = try scanner.readQuoted();
    if (!validNameText(name_text)) return Error.BadSyntax;
    const name = Name.fromText(name_text) catch return Error.BadSyntax;
    try scanner.requireWhitespace();
    try scanner.expect('{');
    try scanner.requireWhitespace();
    try scanner.expectWord("algorithm");
    try scanner.requireWhitespace();
    const algorithm_text = try scanner.readWord();
    const algorithm = parseAlgorithm(algorithm_text) catch return Error.UnsupportedAlgorithm;
    scanner.skipWhitespace();
    try scanner.expect(';');
    try scanner.requireWhitespace();
    try scanner.expectWord("secret");
    try scanner.requireWhitespace();
    const encoded_secret = try scanner.readQuoted();
    scanner.skipWhitespace();
    try scanner.expect(';');
    scanner.skipWhitespace();
    try scanner.expect('}');
    scanner.skipWhitespace();
    try scanner.expect(';');

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded_secret) catch return Error.BadSecret;
    // RFC 8945 section 8: the secret SHOULD be at least as long as the keyed
    // hash output, and the project holds that floor for every algorithm. A
    // truncated name truncates the MAC, not the key, so its floor is the
    // hash it truncates (RFC 4868 section 2.6).
    const minimum = tsig.hashLength(algorithm);
    if (decoded_len < minimum) return Error.SecretTooShort;
    if (decoded_len > max_secret_len) return Error.SecretTooLong;

    var key = Key{ .name = name, .algorithm = algorithm, .secret_len = @intCast(decoded_len) };
    errdefer key.clear();
    std.base64.standard.Decoder.decode(key.secret[0..decoded_len], encoded_secret) catch return Error.BadSecret;
    return key;
}

fn validNameText(text: []const u8) bool {
    for (text) |byte| {
        if (std.ascii.isWhitespace(byte) or byte == 0x7f) return false;
    }
    return true;
}

/// The RFC 8945 section 6 algorithm names this server implements, plus the
/// three truncated names of RFC 4868 section 2.6. Every other name is
/// refused: HMAC-MD5.SIG-ALG.REG.INT is a MUST NOT use there, and
/// gss-tsig delegates the cryptography to GSS, which is not implemented.
fn parseAlgorithm(text: []const u8) Error!tsig.Algorithm {
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha1")) return .hmac_sha1;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha224")) return .hmac_sha224;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha256")) return .hmac_sha256;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha384")) return .hmac_sha384;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha512")) return .hmac_sha512;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha256-128")) return .hmac_sha256_128;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha384-192")) return .hmac_sha384_192;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha512-256")) return .hmac_sha512_256;
    return Error.UnsupportedAlgorithm;
}

test "keyring parses and canonicalizes a SHA-256 key" {
    const text = "key \"Example.COM.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };";
    var ring = try Keyring.parse(text);
    defer ring.deinit();

    try std.testing.expectEqual(@as(usize, 1), ring.len);
    const key = ring.findAlgorithm(try Name.fromText("example.com."), .hmac_sha256).?;
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha256, key.algorithm);
    try std.testing.expectEqualSlices(u8, "01234567890123456789012345678901", key.secretBytes());
}

test "keyring supports SHA-1 rotation and case-insensitive lookup" {
    const text = "key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
        "key \"TWO.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };";
    var ring = try Keyring.parse(text);
    defer ring.deinit();

    try std.testing.expectEqual(@as(usize, 2), ring.len);
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha1, ring.findAlgorithm(try Name.fromText("two."), .hmac_sha1).?.algorithm);
}

test "keyring accepts one key name bundled with several algorithms" {
    const text = "key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
        "key \"one.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };";
    var ring = try Keyring.parse(text);
    defer ring.deinit();

    try std.testing.expectEqual(@as(usize, 2), ring.len);
    const name = try Name.fromText("one.");
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha256, ring.findAlgorithm(name, .hmac_sha256).?.algorithm);
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha1, ring.findAlgorithm(name, .hmac_sha1).?.algorithm);
    try std.testing.expect(ring.findAlgorithm(name, .hmac_sha512) == null);
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha256, ring.findAlgorithm(name, .hmac_sha256).?.algorithm);
}

test "keyring refuses the same key name with the same algorithm twice" {
    try std.testing.expectError(Error.DuplicateKey, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; }; key \"one.\" { algorithm hmac-sha256; secret \"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\"; };"));
}

test "keyring rejects duplicate names, unsupported algorithms, bad base64, and trailing syntax" {
    try std.testing.expectError(Error.DuplicateKey, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; }; key \"ONE.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
    try std.testing.expectError(Error.UnsupportedAlgorithm, Keyring.parse("key \"one.\" { algorithm hmac-md5; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
    try std.testing.expectError(Error.BadSecret, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"not-base64\"; };"));
    try std.testing.expectError(Error.BadSyntax, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; }; trailing"));
}

test "keyring rejects secrets shorter than the digest and malformed declarations" {
    try std.testing.expectError(Error.SecretTooShort, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ=\"; };"));
    try std.testing.expectError(Error.SecretTooLong, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\"; };"));
    try std.testing.expectError(Error.BadSyntax, Keyring.parse("key \"one.\" algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\";"));
    try std.testing.expectError(Error.BadSyntax, Keyring.parse("key \"bad name.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
}

test "keyring deinit clears owned secret bytes" {
    var ring = try Keyring.parse("key \"one.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };");
    ring.deinit();
    for (ring.keys[0].secret) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "keyring accepts every RFC 8945 section 6 HMAC-SHA algorithm" {
    const cases = [_]struct { name: []const u8, secret: []const u8, algorithm: tsig.Algorithm }{
        .{ .name = "hmac-sha1", .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODk=", .algorithm = .hmac_sha1 },
        .{ .name = "hmac-sha224", .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nw==", .algorithm = .hmac_sha224 },
        .{ .name = "hmac-sha256", .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=", .algorithm = .hmac_sha256 },
        .{ .name = "hmac-sha384", .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3", .algorithm = .hmac_sha384 },
        .{ .name = "hmac-sha512", .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==", .algorithm = .hmac_sha512 },
    };
    for (cases) |case| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "key \"one.\" {{ algorithm {s}; secret \"{s}\"; }};",
            .{ case.name, case.secret },
        );
        defer std.testing.allocator.free(text);
        var ring = try Keyring.parse(text);
        defer ring.deinit();

        const key = ring.findAlgorithm(try Name.fromText("one."), case.algorithm).?;
        try std.testing.expectEqual(case.algorithm, key.algorithm);
        try std.testing.expectEqual(tsig.digestLength(case.algorithm), key.secretBytes().len);
    }
}

test "keyring refuses a secret shorter than the algorithm's keyed hash output" {
    const cases = [_][]const u8{ "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512" };
    for (cases) |name| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "key \"one.\" {{ algorithm {s}; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3OA==\"; }};",
            .{name},
        );
        defer std.testing.allocator.free(text);
        try std.testing.expectError(Error.SecretTooShort, Keyring.parse(text));
    }
}

test "keyring refuses the algorithm names RFC 8945 section 6 does not allow" {
    // HMAC-MD5.SIG-ALG.REG.INT is a MUST NOT use, and gss-tsig delegates the
    // cryptography to GSS, which this server does not implement.
    try std.testing.expectError(Error.UnsupportedAlgorithm, Keyring.parse("key \"one.\" { algorithm HMAC-MD5.SIG-ALG.REG.INT; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
    try std.testing.expectError(Error.UnsupportedAlgorithm, Keyring.parse("key \"one.\" { algorithm gss-tsig; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
}

const truncated_algorithms = [_]struct {
    name: []const u8,
    wire: []const u8,
    secret: []const u8,
    algorithm: tsig.Algorithm,
}{
    .{
        .name = "hmac-sha256-128",
        .wire = "hmac-sha256-128.",
        .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        .algorithm = .hmac_sha256_128,
    },
    .{
        .name = "hmac-sha384-192",
        .wire = "hmac-sha384-192.",
        .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3",
        .algorithm = .hmac_sha384_192,
    },
    .{
        .name = "hmac-sha512-256",
        .wire = "hmac-sha512-256.",
        .secret = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==",
        .algorithm = .hmac_sha512_256,
    },
};

test "keyring accepts the truncated algorithm names with the hash-length secret" {
    for (truncated_algorithms) |case| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "key \"one.\" {{ algorithm {s}; secret \"{s}\"; }};",
            .{ case.name, case.secret },
        );
        defer std.testing.allocator.free(text);
        var ring = try Keyring.parse(text);
        defer ring.deinit();

        const name = try Name.fromText("one.");
        const key = ring.findAlgorithm(name, case.algorithm).?;
        try std.testing.expectEqual(case.algorithm, key.algorithm);
        // RFC 4868 section 2.6: the truncated name keeps the key length of
        // the hash it truncates, not the length of its MAC.
        try std.testing.expectEqual(tsig.hashLength(case.algorithm), key.secretBytes().len);
        // A key of the truncated name never answers for the full name.
        try std.testing.expect(ring.findAlgorithm(name, .hmac_sha256) == null);
    }
}

test "keyring refuses a secret shorter than the hash a truncated name truncates" {
    for (truncated_algorithms) |case| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "key \"one.\" {{ algorithm {s}; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3OA==\"; }};",
            .{case.name},
        );
        defer std.testing.allocator.free(text);
        try std.testing.expectError(Error.SecretTooShort, Keyring.parse(text));
    }
}

/// Writes a TSIG request for `algorithm` whose MAC field holds `mac_len`
/// zeroed octets. The digest never covers the MAC field, so the computed
/// MAC stays the same once it is patched in.
fn writeTsigRequest(writer: *dns_writer.Writer, algorithm: []const u8, mac_len: usize) !void {
    try writer.writeBytes(&.{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try writer.writeBytes(&.{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    try writer.writeU16(1);
    try writer.writeU16(1);
    var mac = @as([64]u8, @splat(@as(u8, 0)));
    const value = try dns_rdata.Tsig.init(try Name.fromText(algorithm), 1, 300, mac[0..mac_len], 0x1234, 0, &.{});
    try (dns_record.ResourceRecord{
        .owner = try Name.fromText("one."),
        .rrtype = .TSIG,
        .class = .ANY,
        .ttl = 0,
        .rdata = .{ .TSIG = value },
    }).encode(writer);
}

test "a request signed with a truncated algorithm name is verified with the keyring key" {
    for (truncated_algorithms) |case| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "key \"one.\" {{ algorithm {s}; secret \"{s}\"; }};",
            .{ case.name, case.secret },
        );
        defer std.testing.allocator.free(text);
        var ring = try Keyring.parse(text);
        defer ring.deinit();

        const key = ring.findAlgorithm(try Name.fromText("one."), case.algorithm).?;
        var packet: [512]u8 = undefined;
        var writer = dns_writer.Writer.init(&packet);
        try writeTsigRequest(&writer, case.wire, tsig.digestLength(case.algorithm));
        const final = (try tsig.parseFinalAdditional(writer.written())).?;
        const mac = try tsig.sign(writer.written(), key.secretBytes(), final.owner, final.tsig, null);
        try tsig.patchMac(packet[0..writer.len()], final, mac.slice());
        const verified = try tsig.verify(
            packet[0..writer.len()],
            key.secretBytes(),
            null,
            tsig.minimumMacLength(case.algorithm),
        );
        try std.testing.expectEqualSlices(u8, mac.slice(), verified.slice());
    }
}
