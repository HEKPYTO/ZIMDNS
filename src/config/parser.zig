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

pub const Transport = enum { udp, tcp, dot, doh, doq };

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

/// RFC 8976 ZONEMD publishing the operator chose for signed zones.
pub const ZonemdMode = enum { off, sha384, sha512 };

/// RFC 9520 section 3.2: a resolution failure is cached for at least one
/// second and never longer than five minutes, so the operator's cache time
/// is a number of seconds inside those bounds.
pub const FAILURE_CACHE_MIN_SECONDS: u32 = 1;
pub const FAILURE_CACHE_MAX_SECONDS: u32 = 300;

/// RFC 9210 section 4.2: the idle timeout an operator may set, in seconds.
/// The upper bound keeps the value inside the RFC 7828 section 3.1 units of
/// the edns-tcp-keepalive option, which counts 100 milliseconds.
pub const IDLE_TIMEOUT_MIN_SECONDS: u32 = 1;
pub const IDLE_TIMEOUT_MAX_SECONDS: u32 = 3600;

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
    /// RFC 7858 section 3.1: the forwarder speaks DNS over TLS instead of
    /// plain UDP when the directive names a TLS server name.
    transport: ForwardTransport = .udp,
    /// The name the server certificate must match and the SNI value sent.
    tls_name: Text = .{},
    /// RFC 8484 section 4.1: the POST target of a DoH forwarder.
    doh_path: Text = .{},

    pub const ForwardTransport = enum { udp, tls, doh };

    pub fn addressText(self: *const Forwarder) []const u8 {
        return self.address.text();
    }

    pub fn tlsNameText(self: *const Forwarder) []const u8 {
        return self.tls_name.text();
    }

    pub fn dohPathText(self: *const Forwarder) []const u8 {
        return self.doh_path.text();
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
    /// RFC 9210 section 4.2: the time a connection that waits for a frame is
    /// held open, in seconds. The same deadline bounds a frame in flight.
    idle_timeout: ?u32 = null,
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
    address: Text = .{},
    port: u16 = 0,

    pub fn nameText(self: *const Zone) []const u8 {
        return self.name.text();
    }

    pub fn kindText(self: *const Zone) []const u8 {
        return self.kind.text();
    }

    pub fn fileText(self: *const Zone) []const u8 {
        return self.file.text();
    }

    pub fn addressText(self: *const Zone) []const u8 {
        return self.address.text();
    }
};

/// One `allow-update <apex> <key-name>` line: the zone an operator allowed
/// RFC 2136 updates for and the one TSIG key allowed to write it.
pub const AllowUpdate = struct {
    apex: Text = .{},
    key: Text = .{},

    pub fn apexText(self: *const AllowUpdate) []const u8 {
        return self.apex.text();
    }

    pub fn keyText(self: *const AllowUpdate) []const u8 {
        return self.key.text();
    }
};

/// One `notify <apex> <address:port>` line: RFC 1996 section 3.8 has the
/// master notify its secondaries when a zone changes. The address is the
/// operator's, not one derived from the NS RRset.
pub const NotifyTarget = struct {
    apex: Text = .{},
    address: Text = .{},
    port: u16 = 0,

    pub fn apexText(self: *const NotifyTarget) []const u8 {
        return self.apex.text();
    }

    pub fn addressText(self: *const NotifyTarget) []const u8 {
        return self.address.text();
    }
};

/// One `blacklist-zone <apex> <file>` line: the RFC 5782 zone the server
/// publishes from an entry list.
pub const BlacklistZone = struct {
    apex: Text = .{},
    file: Text = .{},

    pub fn apexText(self: *const BlacklistZone) []const u8 {
        return self.apex.text();
    }

    pub fn fileText(self: *const BlacklistZone) []const u8 {
        return self.file.text();
    }
};

/// One `ddr <target> <alpn> <port> [<dohpath>]` line: the RFC 9461 SVCB
/// record the resolver publishes at `_dns.resolver.arpa.` (RFC 9462).
pub const DdrRecord = struct {
    target: Text = .{},
    alpn: Text = .{},
    port: u16 = 0,
    dohpath: Text = .{},
    has_dohpath: bool = false,

    pub fn targetText(self: *const DdrRecord) []const u8 {
        return self.target.text();
    }

    pub fn alpnText(self: *const DdrRecord) []const u8 {
        return self.alpn.text();
    }

    pub fn dohpathText(self: *const DdrRecord) []const u8 {
        return self.dohpath.text();
    }
};

/// One `catalog-consumer <catalog-apex> <primary:address:port>` line: the
/// RFC 9432 catalog this server fetches at startup and provisions from.
pub const CatalogConsumer = struct {
    apex: Text = .{},
    address: Text = .{},
    port: u16 = 0,
    group: Text = .{},
    has_group: bool = false,

    pub fn apexText(self: *const CatalogConsumer) []const u8 {
        return self.apex.text();
    }

    pub fn addressText(self: *const CatalogConsumer) []const u8 {
        return self.address.text();
    }

    pub fn groupText(self: *const CatalogConsumer) ?[]const u8 {
        if (!self.has_group) return null;
        return self.group.text();
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

pub const RootHint = struct {
    /// Literal address text.
    address: Text = .{},
    port: u16 = 53,
};

pub const Config = struct {
    listeners: List(Listener) = .{},
    recursion_allow: List(Cidr) = .{},
    forwarder: ?Forwarder = null,
    cookies: CookieConfig = .{},
    zones: List(Zone) = .{},
    blocklists: List(BlocklistFile) = .{},
    allow_updates: List(AllowUpdate) = .{},
    notifies: List(NotifyTarget) = .{},
    blacklist_zones: List(BlacklistZone) = .{},
    ddr_records: List(DdrRecord) = .{},
    /// RFC 9461 section 4.2: operator-authorized ports beyond the two
    /// encrypted-DNS defaults the DDR client may reach.
    ddr_client_ports: List(u16) = .{},
    root_hints: List(RootHint) = .{},
    root_zone: Text = .{},
    has_root_zone: bool = false,
    catalog_consumer: ?CatalogConsumer = null,
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
    /// Path to the second DNSSEC key-signing key file. RFC 6781 section
    /// 4.1.2: the key is published at the apex and signs the DNSKEY RRset
    /// beside the key `dnssec-ksk-file` names, while the parent's DS still
    /// states that one; see `dnssec-new-ksk-file` in the loader.
    dnssec_new_ksk_file: Text = .{},
    has_dnssec_new_ksk_file: bool = false,
    /// RFC 6781 section 4.1.2.1: the second key-signing key is the one being
    /// removed, so it is published with the RFC 5011 section 3 REVOKE bit
    /// set. False when the key is not being revoked.
    dnssec_new_ksk_revoked: bool = false,
    /// Path to the DNSSEC trust-anchor file the forwarding path validates
    /// against; see `trust-anchor-file` in the loader.
    trust_anchor_file: Text = .{},
    has_trust_anchor_file: bool = false,
    /// Path to the RFC 5011 managed trust-anchor state. When set, the
    /// forwarding path maintains the DNSKEY anchors itself; see
    /// `managed-anchor-file` in the loader.
    managed_anchor_file: Text = .{},
    has_managed_anchor_file: bool = false,
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
    /// RFC 9462 section 4: DDR client discovery for the plaintext
    /// forwarder. Off unless `ddr-client on`.
    ddr_client: bool = false,
    has_ddr_client: bool = false,
    /// Path to the PEM trust-anchor file the forwarder's TLS/DDR
    /// certificate verifies against; see `forwarder-ca-file` in the loader.
    forwarder_ca_file: Text = .{},
    has_forwarder_ca_file: bool = false,
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
    /// RFC 9567 section 6.3: the agent domain this server monitors. There is
    /// no default, so an unconfigured server monitors no domain at all.
    error_report_monitor: Text = .{},
    has_error_report_monitor: bool = false,
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
    dns64: bool = false,

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
    /// RFC 8976 ZONEMD publishing for signed zones. Off means no record is
    /// added at startup; a zone that already carries an apex ZONEMD is still
    /// verified. Set via `zonemd publish [sha384|sha512]` or `zonemd off`.
    zonemd_mode: ZonemdMode = .off,
    has_zonemd: bool = false,

    /// RFC 9432 section 4: the apex of the catalog zone the server publishes
    /// for the zones it serves. Null means no catalog is served; set via
    /// `catalog-zone <apex>`.
    catalog_zone: Text = .{},
    has_catalog_zone: bool = false,
    catalog_zone_properties: Text = .{},
    has_catalog_zone_properties: bool = false,

    pub fn catalogZoneText(self: *const Config) ?[]const u8 {
        if (!self.has_catalog_zone) return null;
        return self.catalog_zone.text();
    }

    pub fn catalogZonePropertiesText(self: *const Config) ?[]const u8 {
        if (!self.has_catalog_zone_properties) return null;
        return self.catalog_zone_properties.text();
    }

    pub fn tlsCertFileText(self: *const Config) ?[]const u8 {
        if (!self.has_tls_cert_file) return null;
        return self.tls_cert_file.text();
    }

    pub fn tlsKeyFileText(self: *const Config) ?[]const u8 {
        if (!self.has_tls_key_file) return null;
        return self.tls_key_file.text();
    }

    pub fn forwarderCaFileText(self: *const Config) ?[]const u8 {
        if (!self.has_forwarder_ca_file) return null;
        return self.forwarder_ca_file.text();
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

    pub fn dnssecNewKskFileText(self: *const Config) ?[]const u8 {
        if (!self.has_dnssec_new_ksk_file) return null;
        return self.dnssec_new_ksk_file.text();
    }

    /// Whether the second key-signing key is the one being removed, which
    /// RFC 6781 section 4.1.2.1 publishes with the REVOKE bit set.
    pub fn dnssecNewKskRevoked(self: *const Config) bool {
        return self.dnssec_new_ksk_revoked;
    }

    pub fn trustAnchorFileText(self: *const Config) ?[]const u8 {
        if (!self.has_trust_anchor_file) return null;
        return self.trust_anchor_file.text();
    }

    pub fn managedAnchorFileText(self: *const Config) ?[]const u8 {
        if (!self.has_managed_anchor_file) return null;
        return self.managed_anchor_file.text();
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

    pub fn errorReportMonitorText(self: *const Config) ?[]const u8 {
        if (!self.has_error_report_monitor) return null;
        return self.error_report_monitor.text();
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
        if (std.mem.eql(u8, first, "allow-update")) return self.parseAllowUpdate(&tokens);
        if (std.mem.eql(u8, first, "notify")) return self.parseNotify(&tokens);
        if (std.mem.eql(u8, first, "blacklist-zone")) return self.parseBlacklistZone(&tokens);
        if (std.mem.eql(u8, first, "ddr")) return self.parseDdr(&tokens);
        if (std.mem.eql(u8, first, "catalog-consumer")) return self.parseCatalogConsumer(&tokens);
        if (std.mem.eql(u8, first, "tsig-key-file")) return self.parseTsigKeyFile(&tokens);
        if (std.mem.eql(u8, first, "dnssec-key-file")) return self.parseDnssecKeyFile(&tokens);
        if (std.mem.eql(u8, first, "dnssec-ksk-file")) return self.parseDnssecKskFile(&tokens);
        if (std.mem.eql(u8, first, "dnssec-new-ksk-file")) return self.parseDnssecNewKskFile(&tokens);
        if (std.mem.eql(u8, first, "trust-anchor-file")) return self.parseTrustAnchorFile(&tokens);
        if (std.mem.eql(u8, first, "managed-anchor-file")) return self.parseManagedAnchorFile(&tokens);
        if (std.mem.eql(u8, first, "ixfr-journal-file")) return self.parseIxfrJournalFile(&tokens);
        if (std.mem.eql(u8, first, "tls-cert-file")) return self.parseTlsCertFile(&tokens);
        if (std.mem.eql(u8, first, "tls-key-file")) return self.parseTlsKeyFile(&tokens);
        if (std.mem.eql(u8, first, "encrypted-dns")) return self.parseEncryptedDns(&tokens);
        if (std.mem.eql(u8, first, "ddr-client")) return self.parseDdrClient(&tokens);
        if (std.mem.eql(u8, first, "ddr-client-port")) return self.parseDdrClientPort(&tokens);
        if (std.mem.eql(u8, first, "forwarder-ca-file")) return self.parseForwarderCaFile(&tokens);
        if (std.mem.eql(u8, first, "local-zones")) return self.parseLocalZones(&tokens);
        if (std.mem.eql(u8, first, "nsid")) return self.parseNsid(&tokens);
        if (std.mem.eql(u8, first, "error-report-agent")) return self.parseErrorReportAgent(&tokens);
        if (std.mem.eql(u8, first, "error-report-monitor")) return self.parseErrorReportMonitor(&tokens);
        if (std.mem.eql(u8, first, "zoneversion")) return self.parseZoneversion(&tokens);
        if (std.mem.eql(u8, first, "minimal-any-ttl")) return self.parseMinimalAnyTtl(&tokens);
        if (std.mem.eql(u8, first, "minimal-any-ttl-tcp")) return self.parseMinimalAnyTtlTcp(&tokens);
        if (std.mem.eql(u8, first, "root-hint")) return self.parseRootHint(&tokens);
        if (std.mem.eql(u8, first, "root-zone")) return self.parseRootZone(&tokens);
        if (std.mem.eql(u8, first, "nat64-prefix")) return self.parseNat64Prefix(&tokens);
        if (std.mem.eql(u8, first, "dns64")) return self.parseDns64(&tokens);
        if (std.mem.eql(u8, first, "dns64-exclude")) return self.parseDns64Exclude(&tokens);
        if (std.mem.eql(u8, first, "minimum-failure-cache-time")) return self.parseMinimumFailureCacheTime(&tokens);
        if (std.mem.eql(u8, first, "forwarder-deny-port")) return self.parseForwarderDenyPort(&tokens);
        if (std.mem.eql(u8, first, "client-subnet-max-prefix")) return self.parseClientSubnetMaxPrefix(&tokens);
        if (std.mem.eql(u8, first, "dnssec-chain")) return self.parseChain(&tokens);
        if (std.mem.eql(u8, first, "catalog-zone")) return self.parseCatalogZone(&tokens);
        if (std.mem.eql(u8, first, "tcp-max-connections-per-source")) return self.parseTcpMaxConnectionsPerSource(&tokens);
        if (std.mem.eql(u8, first, "tcp-max-connection-duration")) return self.parseTcpMaxConnectionDuration(&tokens);
        if (std.mem.eql(u8, first, "tcp-idle-timeout")) return self.parseTcpIdleTimeout(&tokens);
        if (std.mem.eql(u8, first, "zonemd")) return self.parseZonemd(&tokens);
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
        const parsed = try parseEndpoint(endpoint);
        var forwarder = Forwarder{ .port = parsed.port };
        try forwarder.address.set(parsed.address);
        // RFC 7858 section 3.1: `forwarder <address>:<port> tls <name>` sends
        // the forwarder's queries over TLS, and the name is both the SNI and
        // the name the certificate must match.
        if (tokens.next()) |token| {
            // RFC 7858 section 3.1 for `tls`, RFC 8484 section 4.1 for `doh`:
            // both name the certificate and SNI value, and a DoH forwarder
            // may name its POST target.
            const transport: Forwarder.ForwardTransport = if (std.mem.eql(u8, token, "tls"))
                .tls
            else if (std.mem.eql(u8, token, "doh"))
                .doh
            else
                return Error.BadDirective;
            const name = tokens.next() orelse return Error.BadDirective;
            const is_literal = blk: {
                _ = std.Io.net.IpAddress.parse(name, 1) catch break :blk false;
                break :blk true;
            };
            if (is_literal) return Error.BadAddress;
            try validateHostName(name);
            try forwarder.tls_name.set(name);
            forwarder.transport = transport;
            if (transport == .doh) {
                const path = tokens.next() orelse return Error.BadDirective;
                if (path.len == 0 or path[0] != '/') return Error.BadDirective;
                try forwarder.doh_path.set(path);
            }
        }
        try requireNoTrailingTokens(tokens);
        if (self.forwarder != null) return Error.BadDirective;
        self.forwarder = forwarder;
    }

    /// RFC 7858 section 3.1 leaves the certificate name to the operator; the
    /// value must be a DNS name so it can serve as SNI and as the verified
    /// host, never an address literal (a certificate for an address is not
    /// what a DoT service presents).
    fn validateHostName(name: []const u8) !void {
        if (name.len == 0 or name.len > 253) return Error.BadAddress;
        var label_len: usize = 0;
        for (name) |byte| {
            if (byte == '.') {
                if (label_len == 0 or label_len > 63) return Error.BadAddress;
                label_len = 0;
                continue;
            }
            const allowed = (byte >= 'a' and byte <= 'z') or (byte >= 'A' and byte <= 'Z') or
                (byte >= '0' and byte <= '9') or byte == '-' or byte == '_';
            if (!allowed) return Error.BadAddress;
            label_len += 1;
        }
        if (label_len == 0 or label_len > 63) return Error.BadAddress;
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
        if (std.mem.eql(u8, kind, "primary")) {
            try zone.kind.set(kind);
            try zone.file.set(tokens.next() orelse return Error.BadDirective);
        } else if (std.mem.eql(u8, kind, "secondary")) {
            try zone.kind.set(kind);
            const endpoint = tokens.next() orelse return Error.BadDirective;
            const parsed = try parseEndpointOptional(endpoint);
            try zone.address.set(parsed.address);
            zone.port = parsed.port;
        } else {
            return Error.BadDirective;
        }
        try requireNoTrailingTokens(tokens);
        for (self.zones.items[0..self.zones.len]) |existing| {
            if (zoneNamesEqual(existing.nameText(), zone.nameText())) return Error.BadDirective;
        }
        try self.zones.append(zone);
    }

    fn parseCatalogConsumer(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.catalog_consumer != null) return Error.BadDirective;
        var consumer = CatalogConsumer{};
        try consumer.apex.set(tokens.next() orelse return Error.BadDirective);
        const parsed = try parseEndpoint(tokens.next() orelse return Error.BadDirective);
        try consumer.address.set(parsed.address);
        consumer.port = parsed.port;
        if (tokens.next()) |token| {
            if (!std.mem.eql(u8, token, "group")) return Error.BadDirective;
            try consumer.group.set(tokens.next() orelse return Error.BadDirective);
            consumer.has_group = true;
        }
        try requireNoTrailingTokens(tokens);
        self.catalog_consumer = consumer;
    }

    fn parseDdr(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var record = DdrRecord{};
        try record.target.set(tokens.next() orelse return Error.BadDirective);
        const alpn = tokens.next() orelse return Error.BadDirective;
        if (!(std.mem.eql(u8, alpn, "dot") or std.mem.eql(u8, alpn, "doq") or
            std.mem.eql(u8, alpn, "h2") or std.mem.eql(u8, alpn, "h3") or
            std.mem.eql(u8, alpn, "http/1.1")))
        {
            return Error.BadDirective;
        }
        try record.alpn.set(alpn);
        const port_text = tokens.next() orelse return Error.BadDirective;
        record.port = std.fmt.parseInt(u16, port_text, 10) catch return Error.BadPort;
        if (record.port == 0) return Error.BadPort;
        if (tokens.next()) |path| {
            // RFC 9461 section 5: the DoH path is required with an HTTP ALPN
            // and carries the {?dns} variable; a non-HTTP transport carries
            // none.
            if (!(std.mem.eql(u8, alpn, "h2") or std.mem.eql(u8, alpn, "h3") or std.mem.eql(u8, alpn, "http/1.1"))) return Error.BadDirective;
            if (std.mem.indexOf(u8, path, "{?dns}") == null) return Error.BadDirective;
            try record.dohpath.set(path);
            record.has_dohpath = true;
        } else if (std.mem.eql(u8, alpn, "h2") or std.mem.eql(u8, alpn, "h3") or std.mem.eql(u8, alpn, "http/1.1")) {
            return Error.BadDirective;
        }
        try requireNoTrailingTokens(tokens);
        try self.ddr_records.append(record);
    }

    fn parseBlacklistZone(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var entry = BlacklistZone{};
        try entry.apex.set(tokens.next() orelse return Error.BadDirective);
        try entry.file.set(tokens.next() orelse return Error.BadDirective);
        try requireNoTrailingTokens(tokens);
        for (self.blacklist_zones.items[0..self.blacklist_zones.len]) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.apexText(), entry.apexText())) return Error.BadDirective;
        }
        try self.blacklist_zones.append(entry);
    }

    fn parseNotify(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var target = NotifyTarget{};
        try target.apex.set(tokens.next() orelse return Error.BadDirective);
        const parsed = try parseEndpoint(tokens.next() orelse return Error.BadDirective);
        try target.address.set(parsed.address);
        target.port = parsed.port;
        try requireNoTrailingTokens(tokens);
        try self.notifies.append(target);
    }

    fn parseCatalogZone(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_catalog_zone) return Error.BadDirective;
        var apex = Text{};
        try apex.set(tokens.next() orelse return Error.BadDirective);
        var joined: [512]u8 = undefined;
        var joined_len: usize = 0;
        var has_properties = false;
        while (tokens.next()) |token| {
            if (has_properties) {
                joined[joined_len] = ' ';
                joined_len += 1;
            }
            if (joined_len + token.len > joined.len) return Error.TextTooLong;
            @memcpy(joined[joined_len .. joined_len + token.len], token);
            joined_len += token.len;
            has_properties = true;
        }
        var properties = Text{};
        if (has_properties) try properties.set(joined[0..joined_len]);
        self.catalog_zone = apex;
        self.has_catalog_zone = true;
        if (has_properties) {
            self.catalog_zone_properties = properties;
            self.has_catalog_zone_properties = true;
        }
    }

    fn parseAllowUpdate(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var entry = AllowUpdate{};
        try entry.apex.set(tokens.next() orelse return Error.BadDirective);
        try entry.key.set(tokens.next() orelse return Error.BadDirective);
        try requireNoTrailingTokens(tokens);
        for (self.allow_updates.items[0..self.allow_updates.len]) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.apexText(), entry.apexText())) return Error.BadDirective;
        }
        try self.allow_updates.append(entry);
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

    fn parseDnssecNewKskFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_dnssec_new_ksk_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        if (path.len == 0) return Error.BadDirective;
        // RFC 6781 section 4.1.2.1: the key to be removed is marked with the
        // word `revoked`, and with no other word.
        var revoked = false;
        if (tokens.next()) |word| {
            if (!std.mem.eql(u8, word, "revoked")) return Error.BadDirective;
            revoked = true;
            try requireNoTrailingTokens(tokens);
        }
        try self.dnssec_new_ksk_file.set(path);
        self.has_dnssec_new_ksk_file = true;
        self.dnssec_new_ksk_revoked = revoked;
    }

    fn parseTrustAnchorFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_trust_anchor_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.trust_anchor_file.set(path);
        self.has_trust_anchor_file = true;
    }

    fn parseManagedAnchorFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_managed_anchor_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.managed_anchor_file.set(path);
        self.has_managed_anchor_file = true;
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

    fn parseDdrClient(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_ddr_client) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (std.mem.eql(u8, value, "on")) {
            self.ddr_client = true;
        } else if (std.mem.eql(u8, value, "off")) {
            self.ddr_client = false;
        } else {
            return Error.BadDirective;
        }
        self.has_ddr_client = true;
    }

    fn parseDdrClientPort(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const text = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const port = std.fmt.parseInt(u16, text, 10) catch return Error.BadPort;
        if (port == 0) return Error.BadPort;
        for (self.ddr_client_ports.items[0..self.ddr_client_ports.len]) |seen| {
            if (seen == port) return Error.BadDirective;
        }
        try self.ddr_client_ports.append(port);
    }

    fn parseForwarderCaFile(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_forwarder_ca_file) return Error.BadDirective;
        const path = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (path.len == 0) return Error.BadDirective;
        try self.forwarder_ca_file.set(path);
        self.has_forwarder_ca_file = true;
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

    fn parseErrorReportMonitor(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_error_report_monitor) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        if (value.len == 0) return Error.BadDirective;
        try self.error_report_monitor.set(value);
        self.has_error_report_monitor = true;
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

    fn parseDns64(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const value = tokens.next() orelse return Error.BadDirective;
        if (std.mem.eql(u8, value, "on")) {
            self.dns64 = true;
        } else if (std.mem.eql(u8, value, "off")) {
            self.dns64 = false;
        } else {
            return Error.BadDirective;
        }
        if (tokens.next() != null) return Error.BadDirective;
    }

    fn parseRootHint(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const address_text = tokens.next() orelse return Error.BadDirective;
        var hint = RootHint{};
        hint.address.set(address_text) catch return Error.BadDirective;
        // validate address
        if (std.Io.net.IpAddress.parse(address_text, 53)) |_| {} else |_| return Error.BadAddress;
        if (tokens.next()) |port_text| {
            const port = std.fmt.parseInt(u16, port_text, 10) catch return Error.BadDirective;
            if (port == 0) return Error.BadDirective;
            hint.port = port;
            if (tokens.next() != null) return Error.BadDirective;
        }
        // duplicate check
        var i: usize = 0;
        while (i < self.root_hints.len) : (i += 1) {
            if (std.mem.eql(u8, self.root_hints.items[i].address.text(), hint.address.text()) and self.root_hints.items[i].port == hint.port) return Error.TooManyItems;
        }
        try self.root_hints.append(hint);
    }

    fn parseRootZone(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_root_zone) return Error.TooManyItems;
        const path = tokens.next() orelse return Error.BadDirective;
        if (tokens.next() != null) return Error.BadDirective;
        self.root_zone.set(path) catch return Error.BadDirective;
        self.has_root_zone = true;
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
        // RFC 9276 section 3.1: "Operators SHOULD NOT use a salt by indicating
        // a zero-length salt value instead", so the directive names the empty
        // salt only, written "-" in the presentation format of RFC 5155
        // section 4.3.
        if (!std.mem.eql(u8, salt, "-")) return Error.BadDirective;
        const chain = ChainConfig{
            .chain = .nsec3,
            .iterations = std.fmt.parseInt(u16, iterations, 10) catch return Error.BadDirective,
        };
        self.chain = chain;
    }

    fn parseZonemd(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.has_zonemd) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        if (std.mem.eql(u8, value, "off")) {
            try requireNoTrailingTokens(tokens);
            self.zonemd_mode = .off;
            self.has_zonemd = true;
            return;
        }
        if (!std.mem.eql(u8, value, "publish")) return Error.BadDirective;
        const hash = tokens.next();
        if (hash == null) {
            try requireNoTrailingTokens(tokens);
            self.zonemd_mode = .sha384;
            self.has_zonemd = true;
            return;
        }
        if (std.mem.eql(u8, hash.?, "sha384")) {
            try requireNoTrailingTokens(tokens);
            self.zonemd_mode = .sha384;
            self.has_zonemd = true;
            return;
        }
        if (std.mem.eql(u8, hash.?, "sha512")) {
            try requireNoTrailingTokens(tokens);
            self.zonemd_mode = .sha512;
            self.has_zonemd = true;
            return;
        }
        return Error.BadDirective;
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

    fn parseTcpIdleTimeout(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (self.tcp_limits.idle_timeout != null) return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        try requireNoTrailingTokens(tokens);
        const parsed = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        // RFC 9210 section 4.2: a connection closed at once is never usable,
        // and one held longer than an hour stops being an idle connection.
        if (parsed < IDLE_TIMEOUT_MIN_SECONDS or parsed > IDLE_TIMEOUT_MAX_SECONDS) return Error.BadDirective;
        self.tcp_limits.idle_timeout = parsed;
    }
};

test "allow-update names a zone and its key" {
    const config = try Config.parse(
        \\zone example.com. primary zones/example.zone
        \\allow-update example.com. update-key.
        \\
    );
    try std.testing.expectEqual(@as(usize, 1), config.allow_updates.len);
    try std.testing.expectEqualStrings("example.com.", config.allow_updates.items[0].apexText());
    try std.testing.expectEqualStrings("update-key.", config.allow_updates.items[0].keyText());
}

test "allow-update rejects a duplicate apex and a missing key" {
    try std.testing.expectError(Error.BadDirective, Config.parse(
        \\allow-update example.com. key.
        \\allow-update example.com. other.
        \\
    ));
    try std.testing.expectError(Error.BadDirective, Config.parse("allow-update example.com."));
    try std.testing.expectError(Error.BadDirective, Config.parse("allow-update example.com. key. extra"));
}

fn requireNoTrailingTokens(tokens: *std.mem.TokenIterator(u8, .any)) Error!void {
    if (tokens.next() != null) return Error.BadDirective;
}

fn parseTransport(text: []const u8) !Transport {
    if (std.mem.eql(u8, text, "udp")) return .udp;
    if (std.mem.eql(u8, text, "tcp")) return .tcp;
    if (std.mem.eql(u8, text, "dot")) return .dot;
    if (std.mem.eql(u8, text, "doh")) return .doh;
    if (std.mem.eql(u8, text, "doq")) return .doq;
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
fn parseEndpointOptional(text: []const u8) !struct { address: []const u8, port: u16 } {
    if (text.len > 0 and text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return Error.BadAddress;
        const address = text[1..close];
        if (close + 1 == text.len) {
            _ = std.Io.net.IpAddress.parse(address, 53) catch return Error.BadAddress;
            return .{ .address = address, .port = 53 };
        }
        if (text[close + 1] != ':') return Error.BadAddress;
        const port_text = text[close + 2 ..];
        const port = std.fmt.parseInt(u16, port_text, 10) catch return Error.BadPort;
        if (port == 0) return Error.BadPort;
        _ = std.Io.net.IpAddress.parse(address, port) catch return Error.BadAddress;
        return .{ .address = address, .port = port };
    }
    if (std.mem.indexOfScalar(u8, text, ':') == null) {
        _ = std.Io.net.IpAddress.parse(text, 53) catch return Error.BadAddress;
        return .{ .address = text, .port = 53 };
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return Error.BadDirective;
    if (std.mem.indexOfScalarPos(u8, text, 0, ':') != colon) return Error.BadAddress;
    const address = text[0..colon];
    const port_start = colon + 1;
    const port = std.fmt.parseInt(u16, text[port_start..], 10) catch return Error.BadPort;
    if (port == 0) return Error.BadPort;
    _ = std.Io.net.IpAddress.parse(address, port) catch return Error.BadAddress;
    return .{ .address = address, .port = port };
}

fn zoneNamesEqual(a: []const u8, b: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(a, b)) return true;
    const a_trim = if (std.mem.endsWith(u8, a, ".")) a[0 .. a.len - 1] else a;
    const b_trim = if (std.mem.endsWith(u8, b, ".")) b[0 .. b.len - 1] else b;
    return std.ascii.eqlIgnoreCase(a_trim, b_trim);
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

test "config parser accepts the doq listener transport" {
    const config = try Config.parse("listen dns doq 127.0.0.1:853\n");
    try std.testing.expectEqual(@as(usize, 1), config.listeners.len);
    try std.testing.expectEqual(Transport.doq, config.listeners.items[0].transport);
    try std.testing.expectEqual(@as(u16, 853), config.listeners.items[0].port);
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
    try std.testing.expectError(error.BadDirective, Config.parse("zone home.arpa tertiary /etc/zimdns/zones/home.arpa.zone\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("listen dns udp 127.0.0.1:1053 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone home.arpa primary /etc/zimdns/zones/home.arpa.zone extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("blocklist file /etc/zimdns/blocklists/ads.txt extra\n"));
}

test "config parser accepts secondary zones with an optional port" {
    const with_port = try Config.parse("zone one.example. secondary 192.0.2.1:5353\n");
    try std.testing.expectEqual(@as(usize, 1), with_port.zones.len);
    try std.testing.expectEqualStrings("one.example.", with_port.zones.items[0].nameText());
    try std.testing.expectEqualStrings("secondary", with_port.zones.items[0].kindText());
    try std.testing.expectEqualStrings("192.0.2.1", with_port.zones.items[0].addressText());
    try std.testing.expectEqual(@as(u16, 5353), with_port.zones.items[0].port);
    const default_v4 = try Config.parse("zone one.example secondary 192.0.2.1\n");
    try std.testing.expectEqual(@as(u16, 53), default_v4.zones.items[0].port);
    const default_v6 = try Config.parse("zone one.example. secondary [2001:db8::1]\n");
    try std.testing.expectEqualStrings("2001:db8::1", default_v6.zones.items[0].addressText());
    try std.testing.expectEqual(@as(u16, 53), default_v6.zones.items[0].port);
    const with_v6_port = try Config.parse("zone one.example. secondary [2001:db8::1]:5353\n");
    try std.testing.expectEqual(@as(u16, 5353), with_v6_port.zones.items[0].port);
    const primary = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expectEqualStrings("primary", primary.zones.items[0].kindText());
    try std.testing.expectEqualStrings("one.zone", primary.zones.items[0].fileText());
}

test "config parser rejects bad secondary zones" {
    try std.testing.expectError(error.BadDirective, Config.parse("zone one.example. secondary\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("zone one.example. secondary not-an-ip\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("zone one.example. secondary not-an-ip:5353\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("zone one.example. secondary 999.0.0.1:5353\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("zone one.example. secondary 2001:db8::1\n"));
    try std.testing.expectError(error.BadAddress, Config.parse("zone one.example. secondary /etc/zimdns/zones/one.zone\n"));
    try std.testing.expectError(error.BadPort, Config.parse("zone one.example. secondary 192.0.2.1:notaport\n"));
    try std.testing.expectError(error.BadPort, Config.parse("zone one.example. secondary 192.0.2.1:0\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone one.example. secondary 192.0.2.1:5353 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone one.example primary one.zone\nzone one.example primary other.zone\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone one.example primary one.zone\nzone ONE.example. secondary 192.0.2.1:5353\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("zone one.example. secondary 192.0.2.1\nzone one.example secondary 192.0.2.2\n"));
}

test "catalog-consumer names one catalog and its primary" {
    const config = try Config.parse("catalog-consumer catalog.example. 192.0.2.53:5353\n");
    try std.testing.expectEqualStrings("catalog.example.", config.catalog_consumer.?.apexText());
    try std.testing.expectEqualStrings("192.0.2.53", config.catalog_consumer.?.addressText());
    try std.testing.expectEqual(@as(u16, 5353), config.catalog_consumer.?.port);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).catalog_consumer == null);
    try std.testing.expectError(error.BadDirective, Config.parse("catalog-consumer catalog.example.\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("catalog-consumer catalog.example. 192.0.2.53:5353 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("catalog-consumer a.example. 192.0.2.53:5353\ncatalog-consumer b.example. 192.0.2.53:5353\n"));
}

test "ddr names the SVCB record for an encrypted endpoint" {
    const config = try Config.parse("ddr dns.example. dot 853\nddr dns.example. h2 443 /dns-query{?dns}\n");
    try std.testing.expectEqual(@as(usize, 2), config.ddr_records.len);
    try std.testing.expectEqualStrings("dns.example.", config.ddr_records.items[0].targetText());
    try std.testing.expectEqualStrings("dot", config.ddr_records.items[0].alpnText());
    try std.testing.expectEqual(@as(u16, 853), config.ddr_records.items[0].port);
    try std.testing.expect(config.ddr_records.items[1].has_dohpath);
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. h2 443\n"));
    const http = try Config.parse("ddr dns.example. http/1.1 443 /dns-query{?dns}\n");
    try std.testing.expectEqualStrings("http/1.1", http.ddr_records.items[0].alpnText());
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. http/1.1 443\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. dot 853 /dns-query{?dns}\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. h3 443 /plain\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. quic 853\n"));
    try std.testing.expectError(error.BadPort, Config.parse("ddr dns.example. dot 0\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("ddr dns.example. dot 853 extra\n"));
}

test "blacklist-zone names an apex and its entry list" {
    const config = try Config.parse("blacklist-zone bad.example. entries.txt\nblacklist-zone spam.example. other.txt\n");
    try std.testing.expectEqual(@as(usize, 2), config.blacklist_zones.len);
    try std.testing.expectEqualStrings("bad.example.", config.blacklist_zones.items[0].apexText());
    try std.testing.expectEqualStrings("entries.txt", config.blacklist_zones.items[0].fileText());
    try std.testing.expectError(error.BadDirective, Config.parse("blacklist-zone bad.example.\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("blacklist-zone bad.example. entries.txt extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("blacklist-zone bad.example. a.txt\nblacklist-zone BAD.example. b.txt\n"));
}

test "notify names a zone and the secondary address" {
    const config = try Config.parse("notify home.arpa. 192.0.2.10:5353\nnotify home.arpa. [2001:db8::10]:5353\n");
    try std.testing.expectEqual(@as(usize, 2), config.notifies.len);
    try std.testing.expectEqualStrings("home.arpa.", config.notifies.items[0].apexText());
    try std.testing.expectEqualStrings("192.0.2.10", config.notifies.items[0].addressText());
    try std.testing.expectEqual(@as(u16, 5353), config.notifies.items[0].port);
    try std.testing.expectEqualStrings("2001:db8::10", config.notifies.items[1].addressText());
    try std.testing.expectError(error.BadDirective, Config.parse("notify home.arpa.\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("notify home.arpa. 192.0.2.10:5353 extra\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("notify home.arpa. 192.0.2.10\n"));
}

test "catalog-zone names one catalog apex" {
    const config = try Config.parse("catalog-zone catalog.example.\n");
    try std.testing.expectEqualStrings("catalog.example.", config.catalogZoneText().?);
    const plain = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(plain.catalogZoneText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse("catalog-zone\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("catalog-zone a.example.\ncatalog-zone b.example.\n"));
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

test "config parser accepts one DNSSEC new key-signing key-file path and no other shape" {
    const config = try Config.parse("dnssec-new-ksk-file new-ksk.key\n");
    try std.testing.expectEqualStrings("new-ksk.key", config.dnssecNewKskFileText().?);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).dnssecNewKskFileText() == null);
    try std.testing.expect(!config.dnssecNewKskRevoked());
    // Same shape as `dnssec-ksk-file`: one directive, exactly one value, and
    // no inline key material.
    try std.testing.expectError(error.BadDirective, Config.parse(
        "dnssec-new-ksk-file a.key\ndnssec-new-ksk-file b.key\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-new-ksk-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-new-ksk-file a.key b.key\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("dnssec-new-ksk ed25519-secret\n"));
}

test "config parser marks the second key-signing key as revoked with one word" {
    // RFC 6781 section 4.1.2.1: the key to be removed is published with the
    // REVOKE bit set, and the word `revoked` says so.
    const config = try Config.parse("dnssec-new-ksk-file new-ksk.key revoked\n");
    try std.testing.expectEqualStrings("new-ksk.key", config.dnssecNewKskFileText().?);
    try std.testing.expect(config.dnssecNewKskRevoked());
    // A zone with no second key-signing key has no revoked key.
    try std.testing.expect(!(try Config.parse("zone one.example primary one.zone\n")).dnssecNewKskRevoked());
    // Any other word is refused, and so is a word after it.
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-new-ksk-file a.key bogus\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("dnssec-new-ksk-file a.key revoked extra\n"));
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

test "config parser takes one RFC 5011 state path and rejects every other shape" {
    const config = try Config.parse("managed-anchor-file managed.txt\n");
    try std.testing.expectEqualStrings("managed.txt", config.managedAnchorFileText().?);
    try std.testing.expect((try Config.parse("zone one.example primary one.zone\n")).managedAnchorFileText() == null);
    try std.testing.expectError(error.BadDirective, Config.parse(
        "managed-anchor-file a.txt\nmanaged-anchor-file b.txt\n",
    ));
    try std.testing.expectError(error.BadDirective, Config.parse("managed-anchor-file\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("managed-anchor-file a.txt b.txt\n"));
    try std.testing.expectError(error.UnknownDirective, Config.parse("managed-anchor managed.txt\n"));
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

test "config parser takes one TCP idle timeout" {
    // RFC 9210 section 4.2: without the directive the project's own timeout
    // applies, and the operator did not change it.
    const implicit = try Config.parse("zone one.example primary one.zone\n");
    try std.testing.expect(implicit.tcp_limits.idle_timeout == null);

    const configured = try Config.parse("tcp-idle-timeout 30\n");
    try std.testing.expectEqual(@as(u32, 30), configured.tcp_limits.idle_timeout.?);

    for ([_][]const u8{
        "tcp-idle-timeout\n",
        "tcp-idle-timeout 30 extra\n",
        "tcp-idle-timeout abc\n",
        "tcp-idle-timeout -1\n",
        "tcp-idle-timeout 0\n",
        "tcp-idle-timeout 3601\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse(
        "tcp-idle-timeout 30\ntcp-idle-timeout 60\n",
    ));
    try std.testing.expectError(error.UnknownDirective, Config.parse("tcp-idle 30\n"));
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
    // its salt. RFC 9276 section 3.1 says the operator SHOULD NOT use a
    // salt, so the only salt the directive may name is the empty one, "-".
    const nsec3 = try Config.parse("dnssec-chain nsec3 2 -\n");
    try std.testing.expectEqual(Chain.nsec3, nsec3.chain.?.chain);
    try std.testing.expectEqual(@as(u16, 2), nsec3.chain.?.iterations);
    try std.testing.expectEqual(@as(usize, 0), nsec3.chain.?.saltBytes().len);

    const no_salt = try Config.parse("dnssec-chain nsec3 0 -\n");
    try std.testing.expectEqual(@as(usize, 0), no_salt.chain.?.saltBytes().len);

    for ([_][]const u8{
        "dnssec-chain\n",
        "dnssec-chain maybe\n",
        "dnssec-chain nsec 0 -\n",
        "dnssec-chain nsec3\n",
        "dnssec-chain nsec3 2\n",
        "dnssec-chain nsec3 2 73616c74 extra\n",
        // RFC 9276 section 3.1: a salt is refused, however it is written.
        "dnssec-chain nsec3 0 salt\n",
        "dnssec-chain nsec3 0 73616c74\n",
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

test "config parser takes one zonemd publish and refuses every other shape" {
    try std.testing.expectEqual(ZonemdMode.off, (try Config.parse("zone one.example primary one.zone\n")).zonemd_mode);
    try std.testing.expectEqual(ZonemdMode.sha384, (try Config.parse("zonemd publish\n")).zonemd_mode);
    try std.testing.expectEqual(ZonemdMode.sha384, (try Config.parse("zonemd publish sha384\n")).zonemd_mode);
    try std.testing.expectEqual(ZonemdMode.sha512, (try Config.parse("zonemd publish sha512\n")).zonemd_mode);
    try std.testing.expectEqual(ZonemdMode.off, (try Config.parse("zonemd off\n")).zonemd_mode);
    for ([_][]const u8{
        "zonemd\n",
        "zonemd publish sha1\n",
        "zonemd publish sha384 extra\n",
        "zonemd off extra\n",
        "zonemd bogus\n",
    }) |text| {
        try std.testing.expectError(error.BadDirective, Config.parse(text));
    }
    try std.testing.expectError(error.BadDirective, Config.parse("zonemd off\nzonemd publish sha384\n"));
}

test "forwarder names a TLS server and its certificate name" {
    const config = try Config.parse(
        \\forwarder 1.1.1.1:853 tls cloudflare-dns.com
    );
    const forwarder = config.forwarder orelse return error.TestExpectedForwarder;
    try std.testing.expectEqual(Forwarder.ForwardTransport.tls, forwarder.transport);
    try std.testing.expectEqualStrings("cloudflare-dns.com", forwarder.tlsNameText());
    try std.testing.expectEqual(@as(u16, 853), forwarder.port);
}

test "a TLS forwarder without a certificate name is refused" {
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder 1.1.1.1:853 tls\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder 1.1.1.1:853 quic dns.example\n"));
    try std.testing.expectError(Error.BadAddress, Config.parse("forwarder 1.1.1.1:853 tls 1.1.1.1\n"));
}

test "forwarder names a DoH server, its certificate name, and its path" {
    const config = try Config.parse(
        \\forwarder 9.9.9.9:443 doh dns.quad9.net /dns-query
    );
    const forwarder = config.forwarder orelse return error.TestExpectedForwarder;
    try std.testing.expectEqual(Forwarder.ForwardTransport.doh, forwarder.transport);
    try std.testing.expectEqualStrings("dns.quad9.net", forwarder.tlsNameText());
    try std.testing.expectEqualStrings("/dns-query", forwarder.dohPathText());
}

test "a DoH forwarder needs a path that starts at the root" {
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder 9.9.9.9:443 doh dns.quad9.net\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder 9.9.9.9:443 doh dns.quad9.net dns-query\n"));
}

test "ddr-client takes on and off and nothing else, once" {
    const config = try Config.parse("ddr-client on\n");
    try std.testing.expect(config.ddr_client);
    const off = try Config.parse("ddr-client off\n");
    try std.testing.expect(!off.ddr_client);
    const plain = try Config.parse("forwarder 127.0.0.1:53\n");
    try std.testing.expect(!plain.ddr_client);
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client on\nddr-client off\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client yes\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client on extra\n"));
    try std.testing.expectError(Error.UnknownDirective, Config.parse("ddrclient on\n"));
}

test "ddr-client-port authorizes one port, once" {
    const config = try Config.parse("ddr-client-port 8443\nddr-client-port 1053\n");
    try std.testing.expectEqual(@as(usize, 2), config.ddr_client_ports.len);
    try std.testing.expectEqual(@as(u16, 8443), config.ddr_client_ports.items[0]);
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client-port 8443\nddr-client-port 8443\n"));
    try std.testing.expectError(Error.BadPort, Config.parse("ddr-client-port 0\n"));
    try std.testing.expectError(Error.BadPort, Config.parse("ddr-client-port 65536\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client-port\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("ddr-client-port 8443 extra\n"));
    try std.testing.expectError(Error.UnknownDirective, Config.parse("ddr-client-ports 8443\n"));
}

test "forwarder-ca-file takes one path and nothing else" {
    const config = try Config.parse("forwarder-ca-file ca.pem\n");
    try std.testing.expectEqualStrings("ca.pem", config.forwarderCaFileText().?);
    try std.testing.expect((try Config.parse("forwarder 127.0.0.1:53\n")).forwarderCaFileText() == null);
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder-ca-file a.pem\nforwarder-ca-file b.pem\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder-ca-file\n"));
    try std.testing.expectError(Error.BadDirective, Config.parse("forwarder-ca-file a.pem b.pem\n"));
    try std.testing.expectError(Error.UnknownDirective, Config.parse("forwarder-ca ca.pem\n"));
}
