/// Contract: Parses the compact server configuration language into typed fixed-size values.
/// Ownership: Config owns inline directive storage; input text is borrowed and no deinit is required.
/// Errors: Directive and value failures are typed parser errors; config file I/O belongs to callers.
const std = @import("std");

const max_items = 32;
const max_text = 256;

pub const Error = error{
    UnknownDirective,
    BadDirective,
    BadPort,
    BadAddress,
    BadCidr,
    TextTooLong,
    TooManyItems,
};

pub const Transport = enum { udp, tcp, dot, doh };

const Text = struct {
    bytes: [max_text]u8 = undefined,
    len: usize = 0,

    fn set(self: *Text, value: []const u8) Error!void {
        if (value.len > self.bytes.len) return Error.TextTooLong;
        @memcpy(self.bytes[0..value.len], value);
        self.len = value.len;
    }

    pub fn text(self: *const Text) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Listener = struct {
    transport: Transport,
    address: Text = .{},
    port: u16,

    pub fn addressText(self: *const Listener) []const u8 {
        return self.address.text();
    }
};

pub const Cidr = struct {
    raw: Text = .{},
    bytes: [16]u8 = @splat(0),
    prefix: u8 = 0,
    v6: bool = false,

    pub fn parse(value: []const u8) Error!Cidr {
        const slash = std.mem.lastIndexOfScalar(u8, value, '/') orelse return Error.BadCidr;
        if (slash == 0 or slash + 1 >= value.len) return Error.BadCidr;
        const address_text = value[0..slash];
        const prefix = std.fmt.parseInt(u8, value[slash + 1 ..], 10) catch return Error.BadCidr;
        const address = std.Io.net.IpAddress.parse(address_text, 0) catch return Error.BadAddress;
        var cidr = Cidr{ .prefix = prefix };
        try cidr.raw.set(value);
        switch (address) {
            .ip4 => |ip4| {
                if (prefix > 32) return Error.BadCidr;
                cidr.bytes[0..4].* = ip4.bytes;
            },
            .ip6 => |ip6| {
                if (prefix > 128) return Error.BadCidr;
                cidr.v6 = true;
                cidr.bytes = ip6.bytes;
            },
        }
        return cidr;
    }

    pub fn text(self: *const Cidr) []const u8 {
        return self.raw.text();
    }

    pub fn contains(self: *const Cidr, address: *const std.Io.net.IpAddress) bool {
        return switch (address.*) {
            .ip4 => |ip4| if (self.v6) false else maskedEqual(self.bytes[0..4], &ip4.bytes, self.prefix),
            .ip6 => |ip6| if (!self.v6) false else maskedEqual(&self.bytes, &ip6.bytes, self.prefix),
        };
    }
};

fn maskedEqual(left: []const u8, right: []const u8, prefix: u8) bool {
    const whole = @as(usize, prefix) / 8;
    const remainder = prefix % 8;
    if (!std.mem.eql(u8, left[0..whole], right[0..whole])) return false;
    if (remainder == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - remainder);
    return (left[whole] & mask) == (right[whole] & mask);
}

pub const Forwarder = struct {
    address: Text = .{},
    port: u16,

    pub fn addressText(self: *const Forwarder) []const u8 {
        return self.address.text();
    }
};

pub const CookieConfig = struct {
    enabled: bool = false,
    current: Text = .{},
    previous: Text = .{},
    has_previous: bool = false,

    pub fn currentText(self: *const CookieConfig) []const u8 {
        return self.current.text();
    }

    pub fn previousText(self: *const CookieConfig) ?[]const u8 {
        if (!self.has_previous) return null;
        return self.previous.text();
    }
};

pub const Zone = struct {
    name: Text = .{},
    kind: Text = .{},
    file: Text = .{},

    pub fn nameText(self: *const Zone) []const u8 {
        return self.name.text();
    }

    pub fn fileText(self: *const Zone) []const u8 {
        return self.file.text();
    }
};

pub const BlocklistFile = struct {
    path: Text = .{},

    pub fn pathText(self: *const BlocklistFile) []const u8 {
        return self.path.text();
    }
};

fn List(comptime T: type) type {
    return struct {
        items: [max_items]T = undefined,
        len: usize = 0,

        fn append(self: *@This(), item: T) Error!void {
            if (self.len >= max_items) return Error.TooManyItems;
            self.items[self.len] = item;
            self.len += 1;
        }
    };
}

pub const Config = struct {
    listeners: List(Listener) = .{},
    recursion_allow: List(Cidr) = .{},
    forwarder: ?Forwarder = null,
    cookies: CookieConfig = .{},
    zones: List(Zone) = .{},
    blocklists: List(BlocklistFile) = .{},
    tsig_key_file: Text = .{},
    has_tsig_key_file: bool = false,
    /// Path to the DNSSEC signing key file. One key signs every configured
    /// zone at startup; see `dnssec-key-file` in the loader.
    dnssec_key_file: Text = .{},
    has_dnssec_key_file: bool = false,
    /// Path to the DNSSEC trust-anchor file the forwarding path validates
    /// against; see `trust-anchor-file` in the loader.
    trust_anchor_file: Text = .{},
    has_trust_anchor_file: bool = false,
    tls_cert_file: Text = .{},
    has_tls_cert_file: bool = false,
    tls_key_file: Text = .{},
    has_tls_key_file: bool = false,
    encrypted_dns: bool = false,
    has_encrypted_dns: bool = false,
    /// RFC 6303/6761/7793/8375 locally served zones. Default on; `off` is the
    /// RFC 6303 section 3 mechanism to disable them.
    local_zones: bool = true,
    has_local_zones: bool = false,
    /// RFC 5001 section 2.4 presentation format: the NSID payload is written
    /// as hexadecimal digits, two per octet. There is no default, so an
    /// unconfigured server answers no NSID at all.
    nsid: Text = .{},
    has_nsid: bool = false,
    /// RFC 9660 section 3.2 lets a server decline to answer ZONEVERSION.
    /// Default on: the value is the answer's own SOA serial.
    zoneversion: bool = true,
    has_zoneversion: bool = false,

    pub fn tlsCertFileText(self: *const Config) ?[]const u8 {
        if (!self.has_tls_cert_file) return null;
        return self.tls_cert_file.text();
    }

    pub fn tlsKeyFileText(self: *const Config) ?[]const u8 {
        if (!self.has_tls_key_file) return null;
        return self.tls_key_file.text();
    }

    pub fn tsigKeyFileText(self: *const Config) ?[]const u8 {
        if (!self.has_tsig_key_file) return null;
        return self.tsig_key_file.text();
    }

    pub fn dnssecKeyFileText(self: *const Config) ?[]const u8 {
        if (!self.has_dnssec_key_file) return null;
        return self.dnssec_key_file.text();
    }

    pub fn trustAnchorFileText(self: *const Config) ?[]const u8 {
        if (!self.has_trust_anchor_file) return null;
        return self.trust_anchor_file.text();
    }

    pub fn nsidText(self: *const Config) ?[]const u8 {
        if (!self.has_nsid) return null;
        return self.nsid.text();
    }

    pub fn parse(text: []const u8) !Config {
        var config = Config{};
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const stripped = stripComment(raw_line);
            const line = std.mem.trim(u8, stripped, " \t\r");
            if (line.len == 0) continue;
            try config.parseLine(line);
        }
        return config;
    }

    fn parseLine(self: *Config, line: []const u8) !void {
        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        const first = tokens.next() orelse return;
        if (std.mem.eql(u8, first, "listen")) return self.parseListen(&tokens);
        if (std.mem.eql(u8, first, "recursion")) return self.parseRecursion(&tokens);
        if (std.mem.eql(u8, first, "forwarder")) return self.parseForwarder(&tokens);
        if (std.mem.eql(u8, first, "cookies")) return self.parseCookies(&tokens);
        if (std.mem.eql(u8, first, "zone")) return self.parseZone(&tokens);
        if (std.mem.eql(u8, first, "blocklist")) return self.parseBlocklist(&tokens);
        if (std.mem.eql(u8, first, "tsig-key-file")) return self.parseTsigKeyFile(&tokens);
        if (std.mem.eql(u8, first, "dnssec-key-file")) return self.parseDnssecKeyFile(&tokens);
        if (std.mem.eql(u8, first, "trust-anchor-file")) return self.parseTrustAnchorFile(&tokens);
        if (std.mem.eql(u8, first, "tls-cert-file")) return self.parseTlsCertFile(&tokens);
        if (std.mem.eql(u8, first, "tls-key-file")) return self.parseTlsKeyFile(&tokens);
        if (std.mem.eql(u8, first, "encrypted-dns")) return self.parseEncryptedDns(&tokens);
        if (std.mem.eql(u8, first, "local-zones")) return self.parseLocalZones(&tokens);
        if (std.mem.eql(u8, first, "nsid")) return self.parseNsid(&tokens);
        if (std.mem.eql(u8, first, "zoneversion")) return self.parseZoneversion(&tokens);
        return Error.UnknownDirective;
    }

    fn parseListen(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "dns")) return Error.BadDirective;
        const transport = try parseTransport(tokens.next() orelse return Error.BadDirective);
        const endpoint = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        var listener = Listener{ .transport = transport, .port = undefined };
        const parsed = try parseEndpoint(endpoint);
        try listener.address.set(parsed.address);
        listener.port = parsed.port;
        try self.listeners.append(listener);
    }

    fn parseRecursion(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "allow")) return Error.BadDirective;
        const cidr = try Cidr.parse(tokens.next() orelse return Error.BadDirective);
        try requireNoTrailingTokens(tokens);
        try self.recursion_allow.append(cidr);
    }

    fn parseForwarder(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const endpoint = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = try parseEndpoint(endpoint);
        var forwarder = Forwarder{ .port = parsed.port };
        try forwarder.address.set(parsed.address);
        if (self.forwarder != null) return Error.BadDirective;
        self.forwarder = forwarder;
    }

    fn parseCookies(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.cookies.enabled) return Error.BadDirective;
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "validate")) return Error.BadDirective;
        const current = tokens.next() orelse return Error.BadDirective;
        var cookies = CookieConfig{ .enabled = true };
        if (current.len == 0) return Error.BadDirective;
        try cookies.current.set(current);
        if (tokens.next()) |previous| {
            if (previous.len == 0) return Error.BadDirective;
            try cookies.previous.set(previous);
            cookies.has_previous = true;
        }
        try requireNoTrailingTokens(tokens);
        self.cookies = cookies;
    }

    fn parseZone(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var zone = Zone{};
        try zone.name.set(tokens.next() orelse return Error.BadDirective);
        const kind = tokens.next() orelse return Error.BadDirective;
        if (!std.mem.eql(u8, kind, "primary")) return Error.BadDirective;
        try zone.kind.set(kind);
        try zone.file.set(tokens.next() orelse return Error.BadDirective);
        try requireNoTrailingTokens(tokens);
        try self.zones.append(zone);
    }

    fn parseBlocklist(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "file")) return Error.BadDirective;
        var file = BlocklistFile{};
        try file.path.set(tokens.next() orelse return Error.BadDirective);
        try requireNoTrailingTokens(tokens);
        try self.blocklists.append(file);
    }

    fn parseTsigKeyFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_tsig_key_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.tsig_key_file.set(path);
        self.has_tsig_key_file = true;
    }

    fn parseDnssecKeyFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_dnssec_key_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.dnssec_key_file.set(path);
        self.has_dnssec_key_file = true;
    }

    fn parseTrustAnchorFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_trust_anchor_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.trust_anchor_file.set(path);
        self.has_trust_anchor_file = true;
    }

    fn parseTlsCertFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_tls_cert_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.tls_cert_file.set(path);
        self.has_tls_cert_file = true;
    }

    fn parseTlsKeyFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_tls_key_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.tls_key_file.set(path);
        self.has_tls_key_file = true;
    }

    fn parseEncryptedDns(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_encrypted_dns) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (std.mem.eql(u8, value, "on")) {
            self.encrypted_dns = true;
        } else if (std.mem.eql(u8, value, "off")) {
            self.encrypted_dns = false;
        } else {
            return Error.BadDirective;
        }
        self.has_encrypted_dns = true;
    }

    fn parseLocalZones(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_local_zones) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (std.mem.eql(u8, value, "on")) {
            self.local_zones = true;
        } else if (std.mem.eql(u8, value, "off")) {
            self.local_zones = false;
        } else {
            return Error.BadDirective;
        }
        self.has_local_zones = true;
    }

    fn parseNsid(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_nsid) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        // RFC 5001 section 2.4: a user interface reads the payload as two
        // hexadecimal digits per octet, so an odd count or a non-hex character
        // is a malformed directive rather than an opaque blob.
        if (value.len == 0 or value.len % 2 != 0) return Error.BadDirective;
        for (value) |byte| {
            if (!std.ascii.isHex(byte)) return Error.BadDirective;
        }
        try self.nsid.set(value);
        self.has_nsid = true;
    }

    fn parseZoneversion(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_zoneversion) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (std.mem.eql(u8, value, "on")) {
            self.zoneversion = true;
        } else if (std.mem.eql(u8, value, "off")) {
            self.zoneversion = false;
        } else {
            return Error.BadDirective;
        }
        self.has_zoneversion = true;
    }
};

fn requireNoTrailingTokens(tokens: *std.mem.TokenIterator(u8, .any)) Error!void {
    if (tokens.next() != null) return Error.BadDirective;
}

fn parseTransport(text: []const u8) !Transport {
    if (std.mem.eql(u8, text, "udp")) return .udp;
    if (std.mem.eql(u8, text, "tcp")) return .tcp;
    if (std.mem.eql(u8, text, "dot")) return .dot;
    if (std.mem.eql(u8, text, "doh")) return .doh;
    return Error.BadDirective;
}

fn parseEndpoint(text: []const u8) !struct { address: []const u8, port: u16 } {
    const address: []const u8 = if (text.len > 0 and text[0] == '[') blk: {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return Error.BadAddress;
        if (close + 1 >= text.len or text[close + 1] != ':') return Error.BadAddress;
        break :blk text[1..close];
    } else blk: {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return Error.BadDirective;
        if (std.mem.indexOfScalarPos(u8, text, 0, ':') != colon) return Error.BadAddress;
        break :blk text[0..colon];
    };
    const port_start = if (text[0] == '[')
        (std.mem.indexOfScalar(u8, text, ']') orelse return Error.BadAddress) + 2
    else
        (std.mem.lastIndexOfScalar(u8, text, ':') orelse return Error.BadDirective) + 1;
    const port = std.fmt.parseInt(u16, text[port_start..], 10) catch return Error.BadPort;
    if (port == 0) return Error.BadPort;
    _ = std.Io.net.IpAddress.parse(address, port) catch return Error.BadAddress;
    return .{ .address = address, .port = port };
}

fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |byte, index| {
        if (byte == '#') return line[0..index];
    }
    return line;
}

test "config parser loads documented directives" {
    const text =
        \\listen dns udp 0.0.0.0:1053
        \\listen dns tcp 0.0.0.0:1053
        \\zone home.arpa primary /etc/zimdns/zones/home.arpa.zone
        \\blocklist file /etc/zimdns/blocklists/ads.txt
        \\
    ;

    const config = try Config.parse(text);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expectEqual(Transport.udp, config.listeners.items[0].transport);
    try std.testing.expectEqual(@as(u16, 1053), config.listeners.items[0].port);
    try std.testing.expectEqual(@as(usize, 1), config.zones.len);
    try std.testing.expectEqualStrings("home.arpa", config.zones.items[0].nameText());
    try std.testing.expectEqual(@as(usize, 1), config.blocklists.len);
    try std.testing.expectEqualStrings("/etc/zimdns/blocklists/ads.txt", config.blocklists.items[0].pathText());
}

test "config parser rejects unknown and malformed directives" {
    try std.testing.expectError(error.UnknownDirective, Config.parse("bogus thing\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("admin socket /run/zimdns/admin.sock\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("recursion deny 0.0.0.0/0\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("forwarder default udp 9.9.9.9\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("cookies validate\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("listen dns quic 0.0.0.0:1053\n"));
    try std.testing.expectError(error.BadPort, Config.parse("listen dns udp 0.0.0.0:notaport\n"));
}

test "config parser loads strict forwarding policy" {
    const config = try Config.parse(
        \\recursion allow 127.0.0.0/8
        \\recursion allow ::1/128
        \\forwarder 127.0.0.1:5353
        \\cookies validate current-secret previous-secret
        \\
    );
    try std.testing.expectEqual(@as(usize, 2), config.recursion_allow.len);
    try std.testing.expectEqualStrings("127.0.0.0/8", config.recursion_allow.items[0].text());
    try std.testing.expectEqualStrings("127.0.0.1", config.forwarder.?.addressText());
    try std.testing.expectEqual(@as(u16, 5353), config.forwarder.?.port);
    try std.testing.expect(config.cookies.enabled);
    try std.testing.expectEqualStrings("current-secret", config.cookies.currentText());
    try std.testing.expectEqualStrings("previous-secret", config.cookies.previousText().?);
}

test "config parser rejects unsupported zone kinds and trailing tokens" {
    try std.testing.expectError(error.BadDirective, Config.parse("zone home.arpa secondary /etc/zimdns/zones/home.arpa.zone\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("listen dns udp 127.0.0.1:1053 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone home.arpa primary /etc/zimdns/zones/home.arpa.zone extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("blocklist file /etc/zimdns/blocklists/ads.txt extra\n"));
}

test "config parser requires bracketed IPv6 endpoints and one cookie policy" {
    try std.testing.expectError(error.BadAddress, Config.parse("forwarder 2001:db8::53\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("cookies validate current previous\ncookies validate next\n"));
    const config = try Config.parse("forwarder [2001:db8::53]:53\n");
    try std.testing.expectEqualStrings("2001:db8::53", config.forwarder.?.addressText());
}

test "config parser accepts opt-in encrypted DNS listeners and TLS identity" {
    const config = try Config.parse(
        \\listen dns dot 127.0.0.1:853
        \\listen dns doh 127.0.0.1:8443
        \\tls-cert-file /etc/zimdns/tls/cert.pem
        \\tls-key-file /etc/zimdns/tls/key.pem
        \\encrypted-dns on
        \\
    );
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expectEqual(Transport.dot, config.listeners.items[0].transport);
    try std.testing.expectEqual(@as(u16, 853), config.listeners.items[0].port);
    try std.testing.expectEqual(Transport.doh, config.listeners.items[1].transport);
    try std.testing.expectEqualStrings("/etc/zimdns/tls/cert.pem", config.tlsCertFileText().?);
    try std.testing.expectEqualStrings("/etc/zimdns/tls/key.pem", config.tlsKeyFileText().?);
    try std.testing.expect(config.encrypted_dns);

    const off = try Config.parse("encrypted-dns off\n");
    try std.testing.expect(!off.encrypted_dns);
    const empty = try Config.parse("listen dns udp 127.0.0.1:1053\n");
    try std.testing.expect(!empty.encrypted_dns);
    try std.testing.expect(empty.tlsCertFileText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse("encrypted-dns yes\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("encrypted-dns on\nencrypted-dns off\n"));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tls-cert-file /a\ntls-cert-file /b\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tls-key-file /a\ntls-key-file /b\n",
    ));
}

test "config parser accepts one TSIG key-file path and no secret directive" {
    const config = try Config.parse("tsig-key-file /etc/zimdns/tsig.keys\n");
    try std.testing.expectEqualStrings("/etc/zimdns/tsig.keys", config.tsigKeyFileText().?);
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tsig-key-file /etc/zimdns/a\ntsig-key-file /etc/zimdns/b\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("tsig-key secret-value\n"));
}

test "config parser accepts one DNSSEC signing key-file path and no inline secret" {
    const config = try Config.parse("dnssec-key-file examples/dnssec/zsk.key\n");
    try std.testing.expectEqualStrings("examples/dnssec/zsk.key", config.dnssecKeyFileText().?);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).dnssecKeyFileText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse(
        "dnssec-key-file a.key\ndnssec-key-file b.key\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-key-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-key-file a.key b.key\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("dnssec-key ed25519-secret\n"));
}

test "config parser accepts one DNSSEC trust-anchor path and rejects every other shape" {
    const config = try Config.parse("trust-anchor-file examples/dnssec/root.anchor\n");
    try std.testing.expectEqualStrings("examples/dnssec/root.anchor", config.trustAnchorFileText().?);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).trustAnchorFileText() == null);
    // Same shape as `dnssec-key-file`: one directive, exactly one value, and
    // no inline key material.
    try std.testing.expectError(error.BadDirective, Config.parse(
        "trust-anchor-file a.anchor\ntrust-anchor-file b.anchor\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("trust-anchor-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("trust-anchor-file a.anchor b.anchor\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("trust-anchor ed25519-key\n"));
}

test "config parser keeps locally served zones on unless an operator turns them off" {
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.local_zones);
    try std.testing.expect(!implicit.has_local_zones);

    const on = try Config.parse("local-zones on\n");
    try std.testing.expect(on.local_zones);
    try std.testing.expect(on.has_local_zones);

    const off = try Config.parse("local-zones off\n");
    try std.testing.expect(!off.local_zones);
    try std.testing.expect(off.has_local_zones);

    try std.testing.expectError(error.BadDirective, Config.parse("local-zones maybe\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("local-zones\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("local-zones on extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "local-zones on\nlocal-zones off\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("local-zone on\n"));
}

test "config parser takes one RFC 5001 NSID as hex and rejects every other shape" {
    const config = try Config.parse("nsid 6e73312e6578616d706c652e\n");
    try std.testing.expectEqualStrings("6e73312e6578616d706c652e", config.nsidText().?);
    // No default identifier: RFC 5001 section 3.1 leaves the payload to the
    // operator, so an unconfigured server has nothing to answer with.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).nsidText() == null);

    // RFC 5001 section 2.4: two hexadecimal digits per payload octet, in either
    // case. The directive keeps the text as written and the loader decodes it.
    try std.testing.expectEqualStrings("00FF", (try Config.parse("nsid 00FF\n")).nsidText().?);
    for ([_][]const u8{
        "nsid\n",
        "nsid 6e73312e6578616d706c652e extra\n",
        "nsid abc\n",
        "nsid 6e73s1\n",
        "nsid ns1.example.\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "nsid 6e73\nnsid 6e74\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("nsid-hex 6e73\n"));
}

test "config parser keeps ZONEVERSION answers on unless an operator turns them off" {
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.zoneversion);
    try std.testing.expect(!implicit.has_zoneversion);

    const on = try Config.parse("zoneversion on\n");
    try std.testing.expect(on.zoneversion);
    try std.testing.expect(on.has_zoneversion);

    const off = try Config.parse("zoneversion off\n");
    try std.testing.expect(!off.zoneversion);
    try std.testing.expect(off.has_zoneversion);

    try std.testing.expectError(error.BadDirective, Config.parse("zoneversion maybe\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zoneversion\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zoneversion off extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "zoneversion on\nzoneversion off\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("zoneversions on\n"));
}
