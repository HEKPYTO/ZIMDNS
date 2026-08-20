/// Contract: Parses a bounded BIND-compatible TSIG key file and owns secrets.
/// Ownership: Keyring stores copied names and secret bytes; deinit clears secrets.
/// Errors: Malformed declarations and secret policy violations are typed; no I/O occurs.
const std = @import("std");
const Name = @import("../dns/name.zig").Name;
const tsig = @import("../dns/tsig.zig");

pub const max_keys = 16;
pub const max_secret_len = 64;

pub const Error = error{
    BadSyntax,
    UnsupportedAlgorithm,
    BadSecret,
    SecretTooShort,
    SecretTooLong,
    DuplicateName,
    TooManyKeys,
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
                if (existing.name.eql(&key.name)) return Error.DuplicateName;
            }
            ring.keys[ring.len] = key;
            ring.len += 1;
            scanner.skipWhitespace();
        }
        return ring;
    }

    pub fn find(self: *const Keyring, name: Name) ?*const Key {
        for (self.keys[0..self.len]) |*key| {
            if (key.name.eql(&name)) return key;
        }
        return null;
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
    const minimum: usize = switch (algorithm) {
        .hmac_sha1 => 20,
        .hmac_sha256 => 32,
    };
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

fn parseAlgorithm(text: []const u8) Error!tsig.Algorithm {
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha1")) return .hmac_sha1;
    if (std.ascii.eqlIgnoreCase(text, "hmac-sha256")) return .hmac_sha256;
    return Error.UnsupportedAlgorithm;
}

test "keyring parses and canonicalizes a SHA-256 key" {
    const text = "key \"Example.COM.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };";
    var ring = try Keyring.parse(text);
    defer ring.deinit();

    try std.testing.expectEqual(@as(usize, 1), ring.len);
    const key = ring.find(try Name.fromText("example.com.")).?;
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha256, key.algorithm);
    try std.testing.expectEqualSlices(u8, "01234567890123456789012345678901", key.secretBytes());
}

test "keyring supports SHA-1 rotation and case-insensitive lookup" {
    const text = "key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };" ++
        "key \"TWO.\" { algorithm hmac-sha1; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODk=\"; };";
    var ring = try Keyring.parse(text);
    defer ring.deinit();

    try std.testing.expectEqual(@as(usize, 2), ring.len);
    try std.testing.expectEqual(tsig.Algorithm.hmac_sha1, ring.find(try Name.fromText("two.")).?.algorithm);
}

test "keyring rejects duplicate names, unsupported algorithms, bad base64, and trailing syntax" {
    try std.testing.expectError(Error.DuplicateName, Keyring.parse("key \"one.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; }; key \"ONE.\" { algorithm hmac-sha256; secret \"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=\"; };"));
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
