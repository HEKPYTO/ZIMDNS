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
    BadNat64Prefix,
    BadExcludedRange,
    TextTooLong,
    TooManyItems,
};

pub const Transport = enum { udp, tcp, dot, doh };

/// The chain a signed zone publishes: the RFC 4034 NSEC chain or the
/// RFC 5155 NSEC3 chain.
pub const Chain = enum { nsec, nsec3 };

/// The chain an operator chose for the signed zones, with the parameters of
/// an NSEC3 chain (RFC 5155 section 4.1).
pub const ChainConfig = struct {
    chain: Chain,
    iterations: u16 = 0,
    salt: [255]u8 = undefined,
    salt_len: u8 = 0,

    pub fn saltBytes(self: *const ChainConfig) []const u8 {
        return self.salt[0..self.salt_len];
    }
};

/// RFC 9520 section 3.2: a resolution failure is cached for at least one
/// second and never longer than five minutes, so the operator's cache time
/// is a number of seconds inside those bounds.
pub const FAILURE_CACHE_MIN_SECONDS: u32 = 1;
pub const FAILURE_CACHE_MAX_SECONDS: u32 = 300;

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

    pub fn containsIpv4(self: *const Cidr, address: [4]u8) bool {
        if (self.v6) return false;
        return maskedEqual(self.bytes[0..4], &address, self.prefix);
    }

    pub fn containsIpv6(self: *const Cidr, address: [16]u8) bool {
        if (!self.v6) return false;
        return maskedEqual(&self.bytes, &address, self.prefix);
    }
};

/// RFC 6052 section 3.1: the IPv4 addresses the Well-Known Prefix must not
/// represent. The set is the blocks RFC 5735 section 3 lists, the private
/// ranges of RFC 1918 among them.
const non_global_ipv4 = [_]struct { bytes: [4]u8, prefix: u8 }{
    .{ .bytes = .{ 0, 0, 0, 0 }, .prefix = 8 },
    .{ .bytes = .{ 10, 0, 0, 0 }, .prefix = 8 },
    .{ .bytes = .{ 127, 0, 0, 0 }, .prefix = 8 },
    .{ .bytes = .{ 169, 254, 0, 0 }, .prefix = 16 },
    .{ .bytes = .{ 172, 16, 0, 0 }, .prefix = 12 },
    .{ .bytes = .{ 192, 0, 0, 0 }, .prefix = 24 },
    .{ .bytes = .{ 192, 0, 2, 0 }, .prefix = 24 },
    .{ .bytes = .{ 192, 88, 99, 0 }, .prefix = 24 },
    .{ .bytes = .{ 192, 168, 0, 0 }, .prefix = 16 },
    .{ .bytes = .{ 198, 18, 0, 0 }, .prefix = 15 },
    .{ .bytes = .{ 198, 51, 100, 0 }, .prefix = 24 },
    .{ .bytes = .{ 203, 0, 113, 0 }, .prefix = 24 },
    .{ .bytes = .{ 224, 0, 0, 0 }, .prefix = 4 },
    .{ .bytes = .{ 240, 0, 0, 0 }, .prefix = 4 },
};

/// RFC 6052 section 3.1: the address is one the Well-Known Prefix must not
/// represent.
fn nonGlobalIpv4(address: [4]u8) bool {
    for (non_global_ipv4) |range| {
        if (maskedEqual(&range.bytes, &address, range.prefix)) return true;
    }
    return false;
}

fn maskedEqual(left: []const u8, right: []const u8, prefix: u8) bool {
    const whole = @as(usize, prefix) / 8;
    const remainder = prefix % 8;
    if (!std.mem.eql(u8, left[0..whole], right[0..whole])) return false;
    if (remainder == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - remainder);
    return (left[whole] & mask) == (right[whole] & mask);
}

/// RFC 6052 section 2.2: an IPv4-embedded IPv6 address is a prefix, the
/// embedded IPv4 address, and a suffix. The prefix is one of the six
/// lengths the RFC allows, and the reserved u octet (bits 64 to 71) must
/// be zero.
pub const Nat64Prefix = struct {
    bytes: [16]u8 = @splat(0),
    length: u8 = 96,
    /// RFC 6147 section 5.1.7: the IPv4 address range the prefix serves. The
    /// default range 0.0.0.0/0 serves every IPv4 address.
    range: Cidr = .{},

    pub fn parse(value: []const u8) Error!Nat64Prefix {
        const slash = std.mem.lastIndexOfScalar(u8, value, '/') orelse return Error.BadNat64Prefix;
        if (slash == 0 or slash + 1 >= value.len) return Error.BadNat64Prefix;
        const length = std.fmt.parseInt(u8, value[slash + 1 ..], 10) catch return Error.BadNat64Prefix;
        const address = std.Io.net.IpAddress.parse(value[0..slash], 0) catch return Error.BadAddress;
        const ip6 = switch (address) {
            .ip6 => |ip6| ip6,
            .ip4 => return Error.BadAddress,
        };
        switch (length) {
            32, 40, 48, 56, 64, 96 => {},
            else => return Error.BadNat64Prefix,
        }
        // RFC 6052 section 2.2: bits 64 to 71 are the reserved u octet and
        // must be zero, which for a /96 prefix lies inside the prefix itself.
        if (ip6.bytes[8] != 0) return Error.BadNat64Prefix;
        return .{ .bytes = ip6.bytes, .length = length };
    }

    /// RFC 6052 section 2.1: the Well-Known Prefix, the prefix the RFC
    /// reserves for an algorithmic mapping.
    pub fn isWellKnown(self: *const Nat64Prefix) bool {
        return self.length == 96 and
            std.mem.eql(u8, self.bytes[0..12], &.{ 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 });
    }

    /// RFC 6052 section 3.1: the prefix may represent the address. The
    /// Well-Known Prefix must not represent a non-global IPv4 address.
    pub fn represents(self: *const Nat64Prefix, address: [4]u8) bool {
        if (self.isWellKnown() and nonGlobalIpv4(address)) return false;
        return true;
    }
};

pub const Forwarder = struct {
    address: Text = .{},
    port: u16,

    pub fn addressText(self: *const Forwarder) []const u8 {
        return self.address.text();
    }
};

/// RFC 5452 section 9.2: a source port the forwarder must not use. The
/// range covers one port when its ends are the same, and a value of
/// `first-last` covers every port between them.
pub const PortRange = struct {
    first: u16 = 0,
    last: u16 = 0,

    pub fn parse(value: []const u8) Error!PortRange {
        if (std.mem.indexOfScalar(u8, value, '-')) |split| {
            const first = std.fmt.parseInt(u16, value[0..split], 10) catch return Error.BadPort;
            const last = std.fmt.parseInt(u16, value[split + 1 ..], 10) catch return Error.BadPort;
            if (first == 0 or last == 0 or first > last) return Error.BadPort;
            return .{ .first = first, .last = last };
        }
        const port = std.fmt.parseInt(u16, value, 10) catch return Error.BadPort;
        if (port == 0) return Error.BadPort;
        return .{ .first = port, .last = port };
    }

    pub fn contains(self: PortRange, port: u16) bool {
        return port >= self.first and port <= self.last;
    }
};

/// RFC 9210 section 4.2: the connection limits an operator may set. A null
/// field is the project's own policy, which the operator did not change.
pub const TcpLimits = struct {
    /// The connections one source address may hold at once.
    max_connections_per_source: ?u32 = null,
    /// The total duration of one connection, in seconds.
    max_connection_duration: ?u32 = null,
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
    /// Path to the DNSSEC key-signing key file. RFC 6781 section 3.1: this
    /// key signs the DNSKEY RRset and the DS states it; see `dnssec-ksk-file`
    /// in the loader.
    dnssec_ksk_file: Text = .{},
    has_dnssec_ksk_file: bool = false,
    /// Path to the DNSSEC trust-anchor file the forwarding path validates
    /// against; see `trust-anchor-file` in the loader.
    trust_anchor_file: Text = .{},
    has_trust_anchor_file: bool = false,
    /// Path to the file that keeps the RFC 1995 IXFR delta log across a
    /// restart. Null when the operator did not ask for a durable log; see
    /// `ixfr-journal-file` in the loader.
    ixfr_journal_file: Text = .{},
    has_ixfr_journal_file: bool = false,
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
    /// Per-zone override: `local-zones except <apex>` excludes one locally
    /// served apex (repeatable, up to max_items). Matching is case-insensitive
    /// on the enclosing apex.
    local_zones_except: List(Text) = .{},
    /// RFC 5001 section 2.4 presentation format: the NSID payload is written
    /// as hexadecimal digits, two per octet. There is no default, so an
    /// unconfigured server answers no NSID at all.
    nsid: Text = .{},
    has_nsid: bool = false,
    /// RFC 9567 section 5: the agent domain the server advertises in the
    /// Report-Channel option. There is no default, so an unconfigured server
    /// advertises no agent at all.
    error_report_agent: Text = .{},
    has_error_report_agent: bool = false,
    /// RFC 9660 section 3.2 lets a server decline to answer ZONEVERSION.
    /// Default on: the value is the answer's own SOA serial.
    zoneversion: bool = true,
    has_zoneversion: bool = false,

    /// RFC 8482 section 4.2: the operator-chosen TTL of the synthesized HINFO
    /// in a minimal ANY answer. Null means "use the RFC's day-long default"
    /// (see AnswerPolicy.minimal_any_ttl); set via `minimal-any-ttl <seconds>`.
    minimal_any_ttl: ?u32 = null,

    /// RFC 8482 section 4.4: the TTL of the synthesized HINFO when the ANY
    /// query arrived over TCP. Null means the same TTL as over UDP; set via
    /// `minimal-any-ttl-tcp <seconds>`.
    minimal_any_ttl_tcp: ?u32 = null,

    /// RFC 6147 DNS64 synthesis prefixes, in the RFC 6052 section 2.2 format,
    /// each with the IPv4 address range it serves. No prefix means the
    /// forwarder never synthesizes an AAAA, which is the default; set via
    /// `nat64-prefix <prefix> [<ipv4-range>]`.
    nat64_prefixes: List(Nat64Prefix) = .{},

    /// RFC 6147 section 5.1.4: the IPv6 prefix ranges whose AAAA records are
    /// treated as an empty answer, on top of the default set. Repeatable via
    /// `dns64-exclude <ipv6-prefix>`.
    dns64_excluded: List(Cidr) = .{},

    /// RFC 9520 section 3.2: the time a resolution failure stays cached, in
    /// seconds. Null means the resolver's own default; set via
    /// `minimum-failure-cache-time <seconds>`.
    minimum_failure_cache_time: ?u32 = null,

    /// RFC 9210 section 4.2: the connection limits the operator set. The
    /// defaults are the project's own policy; see `tcp-max-connections-per-
    /// source` and `tcp-max-connection-duration` in the loader.
    tcp_limits: TcpLimits = .{},

    /// RFC 5452 section 9.2: the source ports the forwarder must not use.
    /// Empty means every ephemeral port is allowed, which is what the
    /// forwarder does without the directive; set via
    /// `forwarder-deny-port <port>`.
    deny_ports: List(PortRange) = .{},

    /// RFC 7871 section 7.1.1: the maximum cacheable prefix length of the
    /// client subnet option. Null means the client's own prefix length is
    /// forwarded unchanged; set via `client-subnet-max-prefix <length>`.
    max_cacheable_prefix: ?u8 = null,

    /// The chain the signed zones publish. Null means the zone's own apex
    /// NSEC3PARAM decides, as it always did; set via `dnssec-chain`.
    chain: ?ChainConfig = null,

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

    pub fn dnssecKskFileText(self: *const Config) ?[]const u8 {
        if (!self.has_dnssec_ksk_file) return null;
        return self.dnssec_ksk_file.text();
    }

    pub fn trustAnchorFileText(self: *const Config) ?[]const u8 {
        if (!self.has_trust_anchor_file) return null;
        return self.trust_anchor_file.text();
    }

    pub fn ixfrJournalFileText(self: *const Config) ?[]const u8 {
        if (!self.has_ixfr_journal_file) return null;
        return self.ixfr_journal_file.text();
    }

    pub fn nsidText(self: *const Config) ?[]const u8 {
        if (!self.has_nsid) return null;
        return self.nsid.text();
    }

    pub fn errorReportAgentText(self: *const Config) ?[]const u8 {
        if (!self.has_error_report_agent) return null;
        return self.error_report_agent.text();
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
        if (std.mem.eql(u8, first, "dnssec-ksk-file")) return self.parseDnssecKskFile(&tokens);
        if (std.mem.eql(u8, first, "trust-anchor-file")) return self.parseTrustAnchorFile(&tokens);
        if (std.mem.eql(u8, first, "ixfr-journal-file")) return self.parseIxfrJournalFile(&tokens);
        if (std.mem.eql(u8, first, "tls-cert-file")) return self.parseTlsCertFile(&tokens);
        if (std.mem.eql(u8, first, "tls-key-file")) return self.parseTlsKeyFile(&tokens);
        if (std.mem.eql(u8, first, "encrypted-dns")) return self.parseEncryptedDns(&tokens);
        if (std.mem.eql(u8, first, "local-zones")) return self.parseLocalZones(&tokens);
        if (std.mem.eql(u8, first, "nsid")) return self.parseNsid(&tokens);
        if (std.mem.eql(u8, first, "error-report-agent")) return self.parseErrorReportAgent(&tokens);
        if (std.mem.eql(u8, first, "zoneversion")) return self.parseZoneversion(&tokens);
        if (std.mem.eql(u8, first, "minimal-any-ttl")) return self.parseMinimalAnyTtl(&tokens);
        if (std.mem.eql(u8, first, "minimal-any-ttl-tcp")) return self.parseMinimalAnyTtlTcp(&tokens);
        if (std.mem.eql(u8, first, "nat64-prefix")) return self.parseNat64Prefix(&tokens);
        if (std.mem.eql(u8, first, "dns64-exclude")) return self.parseDns64Exclude(&tokens);
        if (std.mem.eql(u8, first, "minimum-failure-cache-time")) return self.parseMinimumFailureCacheTime(&tokens);
        if (std.mem.eql(u8, first, "forwarder-deny-port")) return self.parseForwarderDenyPort(&tokens);
        if (std.mem.eql(u8, first, "client-subnet-max-prefix")) return self.parseClientSubnetMaxPrefix(&tokens);
        if (std.mem.eql(u8, first, "dnssec-chain")) return self.parseChain(&tokens);
        if (std.mem.eql(u8, first, "tcp-max-connections-per-source")) return self.parseTcpMaxConnectionsPerSource(&tokens);
        if (std.mem.eql(u8, first, "tcp-max-connection-duration")) return self.parseTcpMaxConnectionDuration(&tokens);
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

    fn parseDnssecKskFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_dnssec_ksk_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.dnssec_ksk_file.set(path);
        self.has_dnssec_ksk_file = true;
    }

    fn parseTrustAnchorFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_trust_anchor_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.trust_anchor_file.set(path);
        self.has_trust_anchor_file = true;
    }

    fn parseIxfrJournalFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_ixfr_journal_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.ixfr_journal_file.set(path);
        self.has_ixfr_journal_file = true;
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
        const value = tokens.next() orelse return Error.BadDirective;
        if (std.mem.eql(u8, value, "except")) {
            const apex = tokens.next() orelse return Error.BadDirective;
            try requireNoTrailingTokens(tokens);
            var slot = Text{};
            try slot.set(apex);
            try self.local_zones_except.append(slot);
            return;
        }
        if (self.has_local_zones) return Error.BadDirective;
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

    fn parseErrorReportAgent(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_error_report_agent) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (value.len == 0) return Error.BadDirective;
        try self.error_report_agent.set(value);
        self.has_error_report_agent = true;
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

    fn parseMinimalAnyTtl(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.minimal_any_ttl != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        if (parsed > 0x7fffffff) return Error.BadDirective;
        self.minimal_any_ttl = parsed;
    }

    fn parseMinimalAnyTtlTcp(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.minimal_any_ttl_tcp != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        if (parsed > 0x7fffffff) return Error.BadDirective;
        self.minimal_any_ttl_tcp = parsed;
    }

    fn parseNat64Prefix(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const value = tokens.next() orelse return Error.BadDirective;
        var prefix = try Nat64Prefix.parse(value);
        // RFC 6147 section 5.1.7: the prefix may be bound to the IPv4 address
        // range it serves; without a range it serves every IPv4 address.
        if (tokens.next()) |range_text| {
            const range = try Cidr.parse(range_text);
            if (range.v6) return Error.BadCidr;
            prefix.range = range;
        }
        try requireNoTrailingTokens(tokens);
        try self.nat64_prefixes.append(prefix);
    }

    fn parseDns64Exclude(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const range = Cidr.parse(value) catch return Error.BadExcludedRange;
        if (!range.v6) return Error.BadExcludedRange;
        try self.dns64_excluded.append(range);
    }

    fn parseForwarderDenyPort(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        try self.deny_ports.append(try PortRange.parse(value));
    }

    fn parseClientSubnetMaxPrefix(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.max_cacheable_prefix != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u8, value, 10) catch return Error.BadDirective;
        // RFC 7871 section 7.1.1: a prefix length is a number of address
        // bits, and no address family has more than 128 of them.
        if (parsed > 128) return Error.BadDirective;
        self.max_cacheable_prefix = parsed;
    }

    fn parseChain(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.chain != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        if (std.mem.eql(u8, value, "nsec")) {
            try requireNoTrailingTokens(tokens);
            self.chain = .{ .chain = .nsec };
            return;
        }
        if (!std.mem.eql(u8, value, "nsec3")) return Error.BadDirective;
        const iterations = tokens.next() orelse return Error.BadDirective;
        const salt = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        var chain = ChainConfig{
            .chain = .nsec3,
            .iterations = std.fmt.parseInt(u16, iterations, 10) catch return Error.BadDirective,
        };
        chain.salt_len = try parseSalt(salt, &chain.salt);
        self.chain = chain;
    }

    fn parseMinimumFailureCacheTime(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.minimum_failure_cache_time != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        // RFC 9520 section 3.2: a failure is cached for at least one second
        // and never for longer than five minutes.
        if (parsed < FAILURE_CACHE_MIN_SECONDS or parsed > FAILURE_CACHE_MAX_SECONDS) return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        self.minimum_failure_cache_time = parsed;
    }

    fn parseTcpMaxConnectionsPerSource(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.tcp_limits.max_connections_per_source != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        // A limit below one connection would refuse every client.
        if (parsed == 0) return Error.BadDirective;
        self.tcp_limits.max_connections_per_source = parsed;
    }

    fn parseTcpMaxConnectionDuration(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.tcp_limits.max_connection_duration != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        // A connection that is over before it starts serves nothing.
        if (parsed == 0) return Error.BadDirective;
        self.tcp_limits.max_connection_duration = parsed;
    }
};

fn requireNoTrailingTokens(tokens: *std.mem.TokenIterator(u8, .any)) Error!void {
    if (tokens.next() != null) return Error.BadDirective;
}

/// RFC 5155 section 4.3: the salt is a sequence of hexadecimal digits, or
/// "-" when the chain has no salt. The salt length is one octet, so the salt
/// itself is at most 255 octets.
fn parseSalt(text: []const u8, out: *[255]u8) Error!u8 {
    if (std.mem.eql(u8, text, "-")) return 0;
    if (text.len == 0 or text.len % 2 != 0 or text.len > 510) return Error.BadDirective;
    var index: usize = 0;
    while (index < text.len) : (index += 2) {
        const high = std.fmt.charToDigit(text[index], 16) catch return Error.BadDirective;
        const low = std.fmt.charToDigit(text[index + 1], 16) catch return Error.BadDirective;
        out[index / 2] = (high << 4) | low;
    }
    return @intCast(text.len / 2);
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

test "config parser accepts one DNSSEC key-signing key-file path and no inline secret" {
    const config = try Config.parse("dnssec-ksk-file ksk.key\n");
    try std.testing.expectEqualStrings("ksk.key", config.dnssecKskFileText().?);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).dnssecKskFileText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse(
        "dnssec-ksk-file a.key\ndnssec-ksk-file b.key\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-ksk-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-ksk-file a.key b.key\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("dnssec-ksk ed25519-secret\n"));
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

test "config parser takes one IXFR journal path and rejects every other shape" {
    const config = try Config.parse("ixfr-journal-file ixfr.log\n");
    try std.testing.expectEqualStrings("ixfr.log", config.ixfrJournalFileText().?);
    // No journal file means the delta log lives in memory only.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).ixfrJournalFileText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse(
        "ixfr-journal-file a.log\nixfr-journal-file b.log\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("ixfr-journal-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("ixfr-journal-file a.log b.log\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("ixfr-journal ixfr.log\n"));
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
test "config parser collects local-zones except apexes" {
    const config = try Config.parse("local-zones except 10.in-addr.arpa.\nlocal-zones except EXAMPLE.\n");
    try std.testing.expect(config.local_zones);
    try std.testing.expectEqual(@as(usize, 2), config.local_zones_except.len);
    try std.testing.expectEqualStrings("10.in-addr.arpa.", config.local_zones_except.items[0].text());
    try std.testing.expectEqualStrings("EXAMPLE.", config.local_zones_except.items[1].text());

    try std.testing.expectError(error.BadDirective, Config.parse("local-zones except\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("local-zones except a. b.\n"));
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

test "config parser accepts minimal-any-ttl as a guarded unsigned TTL" {
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.minimal_any_ttl == null);

    const configured = try Config.parse("minimal-any-ttl 300\n");
    try std.testing.expectEqual(@as(u32, 300), configured.minimal_any_ttl.?);

    const zero = try Config.parse("minimal-any-ttl 0\n");
    try std.testing.expectEqual(@as(u32, 0), zero.minimal_any_ttl.?);

    for ([_][]const u8{
        "minimal-any-ttl\n",
        "minimal-any-ttl 300 extra\n",
        "minimal-any-ttl abc\n",
        "minimal-any-ttl -1\n",
        "minimal-any-ttl 2147483648\n",
        "minimal-any-ttl 4294967295\n",
        "minimal-any-ttl 0x12\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "minimal-any-ttl 300\nminimal-any-ttl 600\n",
    ));
    // Typical zone config plus the new directive survives parsing.
    const config = try Config.parse("zone one.example primary one.zone\nminimal-any-ttl 7200\n");
    try std.testing.expectEqual(@as(u32, 7200), config.minimal_any_ttl.?);
}

test "config parser accepts minimal-any-ttl-tcp as a guarded unsigned TTL" {
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.minimal_any_ttl_tcp == null);

    const configured = try Config.parse("minimal-any-ttl-tcp 3600\n");
    try std.testing.expectEqual(@as(u32, 3600), configured.minimal_any_ttl_tcp.?);

    const zero = try Config.parse("minimal-any-ttl-tcp 0\n");
    try std.testing.expectEqual(@as(u32, 0), zero.minimal_any_ttl_tcp.?);

    for ([_][]const u8{
        "minimal-any-ttl-tcp\n",
        "minimal-any-ttl-tcp 3600 extra\n",
        "minimal-any-ttl-tcp abc\n",
        "minimal-any-ttl-tcp -1\n",
        "minimal-any-ttl-tcp 2147483648\n",
        "minimal-any-ttl-tcp 0x12\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "minimal-any-ttl-tcp 3600\nminimal-any-ttl-tcp 7200\n",
    ));
    // The base TTL and the TCP TTL are two directives, not one.
    const config = try Config.parse("minimal-any-ttl 300\nminimal-any-ttl-tcp 3600\n");
    try std.testing.expectEqual(@as(u32, 300), config.minimal_any_ttl.?);
    try std.testing.expectEqual(@as(u32, 3600), config.minimal_any_ttl_tcp.?);
}

test "config parser takes one RFC 9520 failure cache time and rejects every other shape" {
    // No directive means the resolver's own default.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).minimum_failure_cache_time == null);

    const configured = try Config.parse("minimum-failure-cache-time 30\n");
    try std.testing.expectEqual(@as(u32, 30), configured.minimum_failure_cache_time.?);

    // RFC 9520 section 3.2: a failure is cached for at least one second and
    // never for longer than five minutes.
    try std.testing.expectEqual(@as(u32, 1), (try Config.parse("minimum-failure-cache-time 1\n")).minimum_failure_cache_time.?);
    try std.testing.expectEqual(@as(u32, 300), (try Config.parse("minimum-failure-cache-time 300\n")).minimum_failure_cache_time.?);

    for ([_][]const u8{
        "minimum-failure-cache-time\n",
        "minimum-failure-cache-time 30 extra\n",
        "minimum-failure-cache-time abc\n",
        "minimum-failure-cache-time -1\n",
        "minimum-failure-cache-time 0\n",
        "minimum-failure-cache-time 301\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "minimum-failure-cache-time 30\nminimum-failure-cache-time 60\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("failure-cache-time 30\n"));
}

test "config parser takes one TCP per-source limit and one connection duration" {
    // No directive means the project's own policy, which the operator did
    // not change.
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.tcp_limits.max_connections_per_source == null);
    try std.testing.expect(implicit.tcp_limits.max_connection_duration == null);

    const configured = try Config.parse("tcp-max-connections-per-source 25\ntcp-max-connection-duration 60\n");
    try std.testing.expectEqual(@as(u32, 25), configured.tcp_limits.max_connections_per_source.?);
    try std.testing.expectEqual(@as(u32, 60), configured.tcp_limits.max_connection_duration.?);

    for ([_][]const u8{
        "tcp-max-connections-per-source\n",
        "tcp-max-connections-per-source 25 extra\n",
        "tcp-max-connections-per-source abc\n",
        "tcp-max-connections-per-source -1\n",
        "tcp-max-connections-per-source 0\n",
        "tcp-max-connection-duration\n",
        "tcp-max-connection-duration 60 extra\n",
        "tcp-max-connection-duration abc\n",
        "tcp-max-connection-duration -1\n",
        "tcp-max-connection-duration 0\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tcp-max-connections-per-source 25\ntcp-max-connections-per-source 50\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tcp-max-connection-duration 60\ntcp-max-connection-duration 120\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("tcp-max-connection 60\n"));
}

test "config parser takes RFC 6052 NAT64 prefixes with their IPv4 ranges" {
    // No prefix means no synthesis, which is the default.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).nat64_prefixes.len == 0);

    // RFC 6052 section 2.2: the well-known prefix and a network-specific
    // prefix are both valid, and the reserved u octet is zero in each.
    const well_known = try Config.parse("nat64-prefix 64:ff9b::/96\n");
    try std.testing.expectEqual(@as(usize, 1), well_known.nat64_prefixes.len);
    try std.testing.expectEqual(@as(u8, 96), well_known.nat64_prefixes.items[0].length);
    try std.testing.expectEqual(@as(u8, 0), well_known.nat64_prefixes.items[0].bytes[8]);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x64, 0xff, 0x9b }, well_known.nat64_prefixes.items[0].bytes[0..4]);

    const specific = try Config.parse("nat64-prefix 2001:db8::/32\n");
    try std.testing.expectEqual(@as(u8, 32), specific.nat64_prefixes.items[0].length);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8 }, specific.nat64_prefixes.items[0].bytes[0..4]);

    // RFC 6147 section 5.1.7: a prefix may name the IPv4 range it serves.
    const bound = try Config.parse("nat64-prefix 2001:db8:100::/96 192.0.2.0/24\n");
    try std.testing.expectEqual(@as(u8, 24), bound.nat64_prefixes.items[0].range.prefix);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 0 }, bound.nat64_prefixes.items[0].range.bytes[0..4]);
    try std.testing.expect(!bound.nat64_prefixes.items[0].range.v6);
    // Without a range the prefix serves every IPv4 address.
    try std.testing.expectEqual(@as(u8, 0), well_known.nat64_prefixes.items[0].range.prefix);

    // RFC 6052 section 2.2 allows only these prefix lengths, and the u
    // octet (bits 64 to 71) must be zero.
    for ([_][]const u8{
        "nat64-prefix 2001:db8::/60\n",
        "nat64-prefix 2001:db8::/128\n",
        "nat64-prefix 2001:db8::/0\n",
        "nat64-prefix 2001:db8::\n",
        "nat64-prefix 2001:db8::/abc\n",
        "nat64-prefix 2001:db8:0:0:100::/96\n",
    }) |text| {
        try std.testing.expectError(error.BadNat64Prefix, Config.parse(text));
    }
    // The prefix is an IPv6 prefix, so an IPv4 address is not one.
    try std.testing.expectError(error.BadAddress, Config.parse("nat64-prefix 192.0.2.0/96\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("nat64-prefix not-an-address/96\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("nat64-prefix\n"));
    try std.testing.expectError(error.BadCidr, Config.parse("nat64-prefix 64:ff9b::/96 extra\n"));
    // The range holds IPv4 addresses, so an IPv6 range is refused.
    try std.testing.expectError(error.BadCidr, Config.parse("nat64-prefix 64:ff9b::/96 2001:db8::/32\n"));
    try std.testing.expectError(error.BadCidr, Config.parse("nat64-prefix 64:ff9b::/96 192.0.2.0\n"));
    try std.testing.expectError(error.BadCidr, Config.parse("nat64-prefix 64:ff9b::/96 192.0.2.0/33\n"));
}

test "RFC 6052 section 3.1: the well-known prefix does not represent a non-global address" {
    const well_known = try Nat64Prefix.parse("64:ff9b::/96");
    try std.testing.expect(well_known.isWellKnown());
    // The private ranges of RFC 1918 and the documentation ranges of RFC
    // 5735 section 3 are not represented.
    try std.testing.expect(!well_known.represents(.{ 10, 0, 0, 1 }));
    try std.testing.expect(!well_known.represents(.{ 172, 16, 0, 1 }));
    try std.testing.expect(!well_known.represents(.{ 192, 168, 0, 1 }));
    try std.testing.expect(!well_known.represents(.{ 192, 0, 2, 33 }));
    try std.testing.expect(!well_known.represents(.{ 198, 51, 100, 1 }));
    try std.testing.expect(!well_known.represents(.{ 203, 0, 113, 1 }));
    // A global address is represented.
    try std.testing.expect(well_known.represents(.{ 93, 184, 216, 34 }));
    // A network-specific prefix represents every address.
    const specific = try Nat64Prefix.parse("2001:db8:100::/96");
    try std.testing.expect(!specific.isWellKnown());
    try std.testing.expect(specific.represents(.{ 10, 0, 0, 1 }));
}

test "config parser takes the DNS64 excluded ranges and refuses malformed ones" {
    // RFC 6147 section 5.1.4: without a directive the default set applies.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).dns64_excluded.len == 0);

    const one = try Config.parse("dns64-exclude 2001:db8:1::/48\n");
    try std.testing.expectEqual(@as(usize, 1), one.dns64_excluded.len);
    try std.testing.expectEqual(@as(u8, 48), one.dns64_excluded.items[0].prefix);
    try std.testing.expect(one.dns64_excluded.items[0].v6);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8 }, one.dns64_excluded.items[0].bytes[0..4]);

    const two = try Config.parse("dns64-exclude 2001:db8:1::/48\ndns64-exclude 2001:db8:2::/48\n");
    try std.testing.expectEqual(@as(usize, 2), two.dns64_excluded.len);
    try std.testing.expectEqual(@as(u8, 48), two.dns64_excluded.items[1].prefix);

    for ([_][]const u8{
        "dns64-exclude 2001:db8:1::\n",
        "dns64-exclude 2001:db8:1::/48/48\n",
        "dns64-exclude 192.0.2.0/24\n",
        "dns64-exclude not-an-address/48\n",
        "dns64-exclude 2001:db8:1::/129\n",
    }) |text| {
        try std.testing.expectError(error.BadExcludedRange, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse("dns64-exclude\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("dns64-exclude 2001:db8:1::/48 extra\n"));
}

test "config parser takes the denied source ports and refuses malformed ones" {
    // RFC 5452 section 9.2: without a directive every source port is allowed.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).deny_ports.len == 0);

    const config = try Config.parse("forwarder-deny-port 53\nforwarder-deny-port 40000-40100\n");
    try std.testing.expectEqual(@as(usize, 2), config.deny_ports.len);
    try std.testing.expectEqual(@as(u16, 53), config.deny_ports.items[0].first);
    try std.testing.expectEqual(@as(u16, 53), config.deny_ports.items[0].last);
    try std.testing.expectEqual(@as(u16, 40000), config.deny_ports.items[1].first);
    try std.testing.expectEqual(@as(u16, 40100), config.deny_ports.items[1].last);

    try std.testing.expectError(error.BadDirective, Config.parse("forwarder-deny-port\n"));
    for ([_][]const u8{
        "forwarder-deny-port 0\n",
        "forwarder-deny-port not-a-port\n",
        "forwarder-deny-port 65536\n",
        "forwarder-deny-port 40100-40000\n",
        "forwarder-deny-port 53-\n",
        "forwarder-deny-port -53\n",
    }) |text| {
        try std.testing.expectError(error.BadPort, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse("forwarder-deny-port 53 extra\n"));
}

test "config parser takes one maximum cacheable prefix length and refuses malformed ones" {
    // RFC 7871 section 7.1.1: without a directive the client's own prefix
    // length is forwarded unchanged.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).max_cacheable_prefix == null);

    const config = try Config.parse("client-subnet-max-prefix 24\n");
    try std.testing.expectEqual(@as(u8, 24), config.max_cacheable_prefix.?);
    try std.testing.expectEqual(@as(u8, 0), (try Config.parse("client-subnet-max-prefix 0\n")).max_cacheable_prefix.?);
    try std.testing.expectEqual(@as(u8, 128), (try Config.parse("client-subnet-max-prefix 128\n")).max_cacheable_prefix.?);

    for ([_][]const u8{
        "client-subnet-max-prefix\n",
        "client-subnet-max-prefix 129\n",
        "client-subnet-max-prefix -1\n",
        "client-subnet-max-prefix 24.5\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse("client-subnet-max-prefix 24 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse(
        "client-subnet-max-prefix 24\nclient-subnet-max-prefix 16\n",
    ));
}

test "config parser takes one signed chain and refuses every other shape" {
    // Without the directive the zone's own apex NSEC3PARAM decides.
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).chain == null);

    const nsec = try Config.parse("dnssec-chain nsec\n");
    try std.testing.expectEqual(Chain.nsec, nsec.chain.?.chain);

    // RFC 5155 section 4.1: an NSEC3 chain names its iteration count and
    // its salt; the salt is hexadecimal digits, or "-" when it has none.
    const nsec3 = try Config.parse("dnssec-chain nsec3 2 73616c74\n");
    try std.testing.expectEqual(Chain.nsec3, nsec3.chain.?.chain);
    try std.testing.expectEqual(@as(u16, 2), nsec3.chain.?.iterations);
    try std.testing.expectEqualStrings("salt", nsec3.chain.?.saltBytes());

    const no_salt = try Config.parse("dnssec-chain nsec3 0 -\n");
    try std.testing.expectEqual(@as(usize, 0), no_salt.chain.?.saltBytes().len);

    for ([_][]const u8{
        "dnssec-chain\n",
        "dnssec-chain maybe\n",
        "dnssec-chain nsec 0 -\n",
        "dnssec-chain nsec3\n",
        "dnssec-chain nsec3 2\n",
        "dnssec-chain nsec3 2 73616c74 extra\n",
        "dnssec-chain nsec3 2 73616c7\n",
        "dnssec-chain nsec3 2 73616c7z\n",
        "dnssec-chain nsec3 -1 -\n",
        "dnssec-chain nsec3 65536 -\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "dnssec-chain nsec\ndnssec-chain nsec3 0 -\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("dnssec-chain-kind nsec\n"));
}
