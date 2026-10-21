/// Contract: Performs one bounded, UDP-first forwarding exchange and owns its
/// in-memory cache and cookie policy. No iterative recursion or upstream pool.
/// Locally generated EDE options carry an INFO-CODE plus purpose text; error
/// responses preserve the query CD/DO policy. Cookie replay tracking is opt-in
/// and ring-bounded. deinit zeroizes cookie secrets.
/// Ownership: Policy is copied into Resolver; cache responses are allocator-owned.
const std = @import("std");
const builtin = @import("builtin");
const config = @import("config/parser.zig");
const dns_header = @import("dns/header.zig");
const dns_message = @import("dns/message.zig");
const dns_name = @import("dns/name.zig");
const dns_record = @import("dns/record.zig");
const dns_rdata = @import("dns/rdata.zig");
const dns_types = @import("dns/types.zig");
const dns_writer = @import("dns/writer.zig");
const dnssec = @import("dns/dnssec.zig");
const validate = @import("dns/validate.zig");
const zone = @import("zone/index.zig");
const tcp_deadline = @import("platform/tcp_deadline.zig");

pub const MAX_CACHE_ENTRIES = 64;
/// RFC 9520 section 3.2: the resolution-failure cache is bounded too, so a
/// flood of failing names cannot grow it without limit.
pub const MAX_FAILURE_CACHE_ENTRIES = 64;
/// RFC 9520 section 3.2: a resolution failure is cached for at least one
/// second and never longer than five minutes. The operator sets the time
/// with `minimum-failure-cache-time`, inside those bounds.
pub const DEFAULT_FAILURE_CACHE_SECONDS: u32 = 5;
pub const STALE_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub const STALE_TTL: u32 = 30;
/// RFC 2308 section 5 and RFC 8198 section 5.4: the effective TTL of a
/// negative answer is capped at three hours.
pub const MAX_NEGATIVE_TTL: u32 = 3 * 60 * 60;
pub const UDP_ATTEMPTS = 2;
/// RFC 5452 section 9.2: a source port the operator denied is never used,
/// so the socket is bound again until an allowed port is found.
pub const SOURCE_PORT_ATTEMPTS = 8;
pub const UDP_TIMEOUT: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(1000),
    .clock = .awake,
} };
/// One-second upstream TCP connection and I/O budget.
pub const TCP_TIMEOUT: std.Io.Timeout = UDP_TIMEOUT;
pub const MAX_UPSTREAM_MESSAGE = std.math.maxInt(u16);
/// A DNS header is twelve octets; its ARCOUNT field is the last two.
const dns_header_len: usize = 12;
/// Root name, type, class, TTL, RDLENGTH: the wire length of an OPT record.
const opt_record_len: usize = 11;
pub const UPSTREAM_TCP_DEADLINES_SUPPORTED = switch (builtin.os.tag) {
    .linux, .macos => true,
    else => false,
};
pub const COOKIE_OPTION_CODE: u16 = 10;
pub const EDE_OPTION_CODE: u16 = 15;
pub const EDE_STALE_ANSWER: u16 = 3;
/// RFC 8914 section 4.20 assigns 19 to "Stale NXDOMAIN Answer". 22 is
/// "No Reachable Authority" (section 4.23), which is a different condition:
/// the upstream was unreachable, not the answer served from cache.
pub const EDE_STALE_NXDOMAIN: u16 = 19;
pub const EDE_NETWORK_ERROR: u16 = 23;
/// RFC 8914 DNSSEC-bogus INFO-CODEs (see dns/dnssec.zig for purpose text).
pub const EDE_DNSSEC_BOGUS: u16 = dnssec.EDE_DNSSEC_BOGUS;
pub const EDE_SIGNATURE_EXPIRED: u16 = dnssec.EDE_SIGNATURE_EXPIRED;
pub const EDE_SIGNATURE_NOT_YET_VALID: u16 = dnssec.EDE_SIGNATURE_NOT_YET_VALID;
pub const EDE_DNSKEY_MISSING: u16 = dnssec.EDE_DNSKEY_MISSING;
pub const EDE_RRSIGS_MISSING: u16 = dnssec.EDE_RRSIGS_MISSING;
/// Strict-mode cookie replay window. Fixed ring, no allocator, FIFO overwrite.
pub const MAX_COOKIE_REPLAY_ENTRIES = 32;

/// RFC 8914 EXTRA-TEXT purpose string for a locally generated EDE INFO-CODE.
pub fn edeText(code: u16) []const u8 {
    return switch (code) {
        EDE_STALE_ANSWER => "stale answer",
        EDE_STALE_NXDOMAIN => "stale nxdomain",
        EDE_NETWORK_ERROR => "network error",
        EDE_DNSSEC_BOGUS,
        EDE_SIGNATURE_EXPIRED,
        EDE_SIGNATURE_NOT_YET_VALID,
        EDE_DNSKEY_MISSING,
        EDE_RRSIGS_MISSING,
        => dnssec.edeText(code),
        else => "",
    };
}

pub const Error = error{
    NoForwarder,
    UpstreamFailure,
    BadUpstreamResponse,
    ResponseTooLarge,
    UnsupportedOpcode,
    /// The runtime maps this to a REFUSED response. The resolver forwards the
    /// client's client subnet option, so it produces no refusal today.
    EcsRefused,
    BadCookie,
};

pub const Endpoint = struct {
    address: std.Io.net.IpAddress,
};

/// The DNS64 prefixes and excluded ranges a policy holds: the fixed array
/// and the number of slots in use.
pub fn Dns64List(comptime T: type) type {
    return struct {
        items: [32]T = undefined,
        len: usize = 0,

        pub fn init(values: []const T) @This() {
            var list = @This(){ .len = values.len };
            @memcpy(list.items[0..values.len], values);
            return list;
        }
    };
}

pub const Policy = struct {
    recursion_allow: [32]config.Cidr = undefined,
    recursion_allow_len: usize = 0,
    forwarder: ?Endpoint = null,
    cookies: CookiePolicy = .{},
    /// RFC 6147 section 5.1.7: the NAT64 prefixes the synthesis may use, each
    /// with the IPv4 address range it serves. Empty means the forwarder never
    /// synthesizes an AAAA, which is what an operator gets without a
    /// `nat64-prefix` directive.
    nat64_prefixes: Dns64List(config.Nat64Prefix) = .{},

    /// RFC 6147 section 5.1.4: the IPv6 prefix ranges whose AAAA records are
    /// treated as an empty answer, on top of the default set.
    dns64_excluded: Dns64List(config.Cidr) = .{},

    /// RFC 9520 section 3.2: the time a resolution failure stays cached, in
    /// seconds. The operator sets it with `minimum-failure-cache-time`.
    failure_cache_seconds: u32 = DEFAULT_FAILURE_CACHE_SECONDS,

    /// RFC 5452 section 9.2: the source ports the forwarder must not use.
    /// Empty means every ephemeral port is allowed, which is what the
    /// forwarder does without a `forwarder-deny-port` directive.
    deny_ports: [32]config.PortRange = undefined,
    deny_ports_len: usize = 0,

    /// RFC 7871 section 7.1.1: the maximum cacheable prefix length of the
    /// client subnet option. Null means the client's own prefix length is
    /// forwarded unchanged.
    max_cacheable_prefix: ?u8 = null,

    /// RFC 4035 section 5.2 trust anchors. Empty unless `trust-anchor-file`
    /// named one, so a forwarder with no configured anchor validates nothing
    /// and never sets AD. Owned here because the Policy is copied into the
    /// Resolver that outlives the config load.
    anchors: validate.Anchors = .{},

    pub fn fromConfig(value: *const config.Config) !Policy {
        var policy = Policy{};
        if (value.recursion_allow.len > policy.recursion_allow.len) return error.TooManyItems;
        var index: usize = 0;
        while (index < value.recursion_allow.len) : (index += 1) {
            policy.recursion_allow[index] = value.recursion_allow.items[index];
        }
        policy.recursion_allow_len = value.recursion_allow.len;

        if (value.forwarder) |forwarder| {
            const address = std.Io.net.IpAddress.parse(forwarder.addressText(), forwarder.port) catch return error.BadAddress;
            policy.forwarder = .{ .address = address };
        }
        if (value.cookies.enabled) {
            policy.cookies = CookiePolicy.init(value.cookies.currentText(), value.cookies.previousText());
        }
        if (value.nat64_prefixes.len > policy.nat64_prefixes.items.len) return error.TooManyItems;
        index = 0;
        while (index < value.nat64_prefixes.len) : (index += 1) {
            policy.nat64_prefixes.items[index] = value.nat64_prefixes.items[index];
        }
        policy.nat64_prefixes.len = value.nat64_prefixes.len;
        if (value.dns64_excluded.len > policy.dns64_excluded.items.len) return error.TooManyItems;
        index = 0;
        while (index < value.dns64_excluded.len) : (index += 1) {
            policy.dns64_excluded.items[index] = value.dns64_excluded.items[index];
        }
        policy.dns64_excluded.len = value.dns64_excluded.len;
        if (value.minimum_failure_cache_time) |seconds| policy.failure_cache_seconds = seconds;
        if (value.deny_ports.len > policy.deny_ports.len) return error.TooManyItems;
        index = 0;
        while (index < value.deny_ports.len) : (index += 1) {
            policy.deny_ports[index] = value.deny_ports.items[index];
        }
        policy.deny_ports_len = value.deny_ports.len;
        if (value.max_cacheable_prefix) |prefix| policy.max_cacheable_prefix = prefix;
        return policy;
    }

    pub fn allows(self: *const Policy, client: *const std.Io.net.IpAddress) bool {
        var index: usize = 0;
        while (index < self.recursion_allow_len) : (index += 1) {
            if (self.recursion_allow[index].contains(client)) return true;
        }
        return false;
    }
};

pub const CookiePolicy = struct {
    current: [256]u8 = undefined,
    current_len: usize = 0,
    previous: [256]u8 = undefined,
    previous_len: usize = 0,
    /// Opt-in strict mode: reject a full cookie already seen from the same
    /// client within the bounded ring. Off by default so legitimate clients
    /// that reuse cookies keep working.
    replay_protection: bool = false,
    replay_db: CookieReplayDb = .{},

    pub fn init(current: []const u8, previous: ?[]const u8) CookiePolicy {
        var policy = CookiePolicy{};
        policy.current_len = @min(current.len, policy.current.len);
        @memcpy(policy.current[0..policy.current_len], current[0..policy.current_len]);
        if (previous) |secret| {
            policy.previous_len = @min(secret.len, policy.previous.len);
            @memcpy(policy.previous[0..policy.previous_len], secret[0..policy.previous_len]);
        }
        return policy;
    }

    pub fn deinit(self: *CookiePolicy) void {
        std.crypto.secureZero(u8, &self.current);
        std.crypto.secureZero(u8, &self.previous);
        self.current_len = 0;
        self.previous_len = 0;
        self.replay_protection = false;
        self.replay_db.deinit();
    }

    pub fn enabled(self: *const CookiePolicy) bool {
        return self.current_len != 0;
    }

    pub fn validLength(_: *const CookiePolicy, length: usize) bool {
        return length == 8 or (length >= 16 and length <= 40);
    }

    pub fn makeServerCookie(self: *const CookiePolicy, client: *const std.Io.net.IpAddress, client_cookie: []const u8, output: *[24]u8) void {
        @memcpy(output[0..8], client_cookie[0..8]);
        var mac_bytes: [32]u8 = undefined;
        self.mac(client, client_cookie[0..8], &mac_bytes, self.current[0..self.current_len]);
        @memcpy(output[8..], mac_bytes[0..16]);
    }

    pub fn validates(self: *const CookiePolicy, client: *const std.Io.net.IpAddress, cookie: []const u8) bool {
        if (!self.validLength(cookie.len)) return false;
        if (cookie.len == 8) return true;
        var expected: [32]u8 = undefined;
        if (self.current_len != 0) {
            self.mac(client, cookie[0..8], &expected, self.current[0..self.current_len]);
            if (std.crypto.timing_safe.compare(u8, cookie[8..], expected[0 .. cookie.len - 8], .big) == .eq) return true;
        }
        if (self.previous_len != 0) {
            self.mac(client, cookie[0..8], &expected, self.previous[0..self.previous_len]);
            if (std.crypto.timing_safe.compare(u8, cookie[8..], expected[0 .. cookie.len - 8], .big) == .eq) return true;
        }
        return false;
    }

    fn mac(_: *const CookiePolicy, client: *const std.Io.net.IpAddress, client_cookie: []const u8, output: *[32]u8, secret: []const u8) void {
        var input: [24]u8 = undefined;
        const address_len: usize = switch (client.*) {
            .ip4 => |ip4| blk: {
                @memcpy(input[0..4], &ip4.bytes);
                break :blk 4;
            },
            .ip6 => |ip6| blk: {
                @memcpy(input[0..16], &ip6.bytes);
                break :blk 16;
            },
        };
        @memcpy(input[address_len .. address_len + 8], client_cookie);
        std.crypto.auth.hmac.sha2.HmacSha256.create(output, input[0 .. address_len + 8], secret);
    }
};

/// Fixed-capacity ring of recently seen full cookies keyed by client address.
/// Never grows: once full, each track overwrites the oldest entry.
pub const CookieReplayDb = struct {
    const Entry = struct {
        ip_tag: u8 = 0,
        ip: [16]u8 = @as([16]u8, @as([16]u8, @splat(@as(u8, 0)))),
        cookie: [40]u8 = @as([40]u8, @as([40]u8, @splat(@as(u8, 0)))),
        cookie_len: u8 = 0,
    };

    entries: [MAX_COOKIE_REPLAY_ENTRIES]Entry = @splat(Entry{}),
    next: usize = 0,

    pub fn contains(self: *const CookieReplayDb, client: *const std.Io.net.IpAddress, cookie: []const u8) bool {
        const identity = clientIdentity(client);
        for (&self.entries) |*entry| {
            if (entry.ip_tag == 0) continue;
            if (entry.ip_tag != identity.tag or entry.cookie_len != cookie.len) continue;
            if (!std.mem.eql(u8, entry.ip[0..], identity.bytes[0..])) continue;
            if (std.mem.eql(u8, entry.cookie[0..entry.cookie_len], cookie)) return true;
        }
        return false;
    }

    pub fn track(self: *CookieReplayDb, client: *const std.Io.net.IpAddress, cookie: []const u8) void {
        if (cookie.len > self.entries[0].cookie.len) return;
        const identity = clientIdentity(client);
        const entry = &self.entries[self.next];
        self.next = (self.next + 1) % self.entries.len;
        entry.ip_tag = identity.tag;
        entry.ip = identity.bytes;
        @memcpy(entry.cookie[0..cookie.len], cookie);
        entry.cookie_len = @intCast(cookie.len);
    }

    pub fn deinit(self: *CookieReplayDb) void {
        std.crypto.secureZero(Entry, &self.entries);
        self.next = 0;
    }

    const ClientIdentity = struct { tag: u8, bytes: [16]u8 };

    fn clientIdentity(client: *const std.Io.net.IpAddress) ClientIdentity {
        return switch (client.*) {
            .ip4 => |ip4| blk: {
                var bytes = @as([16]u8, @splat(@as(u8, 0)));
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .tag = 4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .tag = 6, .bytes = ip6.bytes },
        };
    }
};

/// RFC 7871 section 6: the Client Subnet option as the network an answer was
/// fetched for. A family of 0 means the query carried no option at all.
const EcsScope = struct {
    family: u16 = 0,
    /// The SOURCE PREFIX-LENGTH the option carried.
    prefix: u8 = 0,
    /// The address bits of that prefix, zero padded to the last octet.
    address: [16]u8 = @splat(0),

    fn eql(self: EcsScope, other: EcsScope) bool {
        if (self.family != other.family or self.prefix != other.prefix) return false;
        const len = (@as(usize, self.prefix) + 7) / 8;
        return std.mem.eql(u8, self.address[0..len], other.address[0..len]);
    }
};

const CacheKey = struct {
    /// The question name in wire form: the RFC 8020 cut compares a name
    /// with its ancestors, and only the label structure says where one ends.
    name: [256]u8 = undefined,
    name_len: usize = 0,
    qtype: u16 = 0,
    qclass: u16 = 0,
    checking_disabled: bool = false,
    dnssec_ok: bool = false,
    /// RFC 7871 section 7.3.1: an answer is tied to the network it was
    /// fetched for, so the scope is part of the key.
    ecs: EcsScope = .{},

    fn fromQuestion(question: dns_message.Message) !CacheKey {
        const q = question.question orelse return error.BadQuery;
        var key = CacheKey{
            .qtype = q.qtype.code(),
            .qclass = q.qclass.code(),
            .checking_disabled = question.header.checking_disabled,
            .dnssec_ok = if (question.edns) |edns| edns.dnssec_ok else false,
        };
        if (ecsScope(question)) |scope| key.ecs = scope;
        @memcpy(key.name[0..q.name.wire_len], q.name.asWire());
        key.name_len = q.name.wire_len;
        return key;
    }

    fn eql(self: *const CacheKey, other: *const CacheKey) bool {
        return self.qtype == other.qtype and self.qclass == other.qclass and
            self.checking_disabled == other.checking_disabled and self.dnssec_ok == other.dnssec_ok and
            self.ecs.eql(other.ecs) and
            std.ascii.eqlIgnoreCase(self.name[0..self.name_len], other.name[0..other.name_len]);
    }

    /// True when two keys ask the same question. The CD and DO flags are
    /// left out: a resolution failure does not depend on them. The client
    /// subnet scope is not left out: a failure for one scope says nothing
    /// about another.
    fn sameQuestion(self: *const CacheKey, other: *const CacheKey) bool {
        return self.qtype == other.qtype and self.qclass == other.qclass and
            self.ecs.eql(other.ecs) and
            std.ascii.eqlIgnoreCase(self.name[0..self.name_len], other.name[0..other.name_len]);
    }
};

/// The Client Subnet option of a message, if it carries one. RFC 7871
/// section 6 gives the layout: FAMILY, SOURCE PREFIX-LENGTH, SCOPE
/// PREFIX-LENGTH, and the address truncated to the source prefix.
fn ecsScope(message: dns_message.Message) ?EcsScope {
    const payload = findOption(message, dns_rdata.EDNS_ECS_OPTION_CODE) orelse return null;
    if (payload.len < 4) return null;
    const family = std.mem.readInt(u16, payload[0..2], .big);
    const max_prefix: u8 = switch (family) {
        1 => 32,
        2 => 128,
        else => return null,
    };
    const prefix = payload[2];
    if (prefix > max_prefix) return null;
    const address_len = (@as(usize, prefix) + 7) / 8;
    if (payload.len != 4 + address_len) return null;
    var scope = EcsScope{ .family = family, .prefix = prefix };
    @memcpy(scope.address[0..address_len], payload[4..]);
    return scope;
}

/// The option payload of a scope. RFC 7871 section 6 gives the layout:
/// FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH, and the address
/// truncated to the source prefix. Section 7.1.1 keeps the scope of a query
/// at 0; an answer carries the scope the answer was fetched for.
fn ecsPayload(scope: EcsScope, scope_prefix: u8, buffer: *[4 + 16]u8) []const u8 {
    std.mem.writeInt(u16, buffer[0..2], scope.family, .big);
    buffer[2] = scope.prefix;
    buffer[3] = scope_prefix;
    const address_len = (@as(usize, scope.prefix) + 7) / 8;
    @memcpy(buffer[4..][0..address_len], scope.address[0..address_len]);
    return buffer[0 .. 4 + address_len];
}

/// RFC 7871 section 6: the SCOPE PREFIX-LENGTH of the Client Subnet option
/// of a message, the number of leading bits of the address the answer
/// covers. A message with no option, or with one that is not a usable
/// option, has the scope of 0.
fn ecsScopePrefix(message: dns_message.Message) u8 {
    const payload = findOption(message, dns_rdata.EDNS_ECS_OPTION_CODE) orelse return 0;
    if (ecsScope(message) == null) return 0;
    return payload[3];
}

/// RFC 7871 section 7.1.1: the outgoing SOURCE PREFIX-LENGTH is the
/// shorter of the client's and the server's maximum cacheable prefix
/// length, and the address is truncated to that many bits.
fn trimmedScope(scope: EcsScope, max_prefix: ?u8) EcsScope {
    const max = max_prefix orelse return scope;
    if (scope.prefix <= max) return scope;
    var trimmed = scope;
    trimmed.prefix = max;
    const whole = @as(usize, max) / 8;
    const remainder = max % 8;
    if (remainder == 0) {
        @memset(trimmed.address[whole..], 0);
    } else {
        trimmed.address[whole] &= @as(u8, 0xff) << @intCast(8 - remainder);
        @memset(trimmed.address[whole + 1 ..], 0);
    }
    return trimmed;
}

/// RFC 7871 section 6 and 7.3: the scope of an upstream answer is the scope
/// the upstream reported, and an answer with no Client Subnet option has
/// the scope of 0. A scope the resolver cannot use, one wider than the
/// prefix the query asked for, is reported as 0: a client is never told the
/// answer covers a scope the resolver did not learn from the upstream.
fn upstreamEcsScope(response: dns_message.Message, scope: EcsScope) u8 {
    const reported = ecsScopePrefix(response);
    if (reported == 0) return 0;
    if (scope.family == 0) return 0;
    if (reported > scope.prefix) return 0;
    return reported;
}

/// RFC 7871 section 7.2.2: a client that sent the option gets one in the
/// answer and a client that sent none never sees one. The scope reported is
/// the scope the upstream answered with, and the address is the one the
/// resolver sent upstream, so no address bit the client did not send is
/// disclosed.
fn appendEcsScope(message: *dns_message.Message, scope: EcsScope, scope_prefix: u8) !void {
    if (message.edns == null) return;
    if (scope.family == 0) return;
    var buffer: [4 + 16]u8 = undefined;
    try appendOption(message, dns_rdata.EDNS_ECS_OPTION_CODE, ecsPayload(scope, scope_prefix, &buffer));
}

const CacheEntry = struct {
    response: ?[]u8 = null,
    key: CacheKey = .{},
    stored_at: i64 = 0,
    ttl: u32 = 0,
    negative: bool = false,
    nxdomain: bool = false,
    /// RFC 7871 section 6: the scope the upstream answered with, which the
    /// cached copy reports to the clients it serves.
    ecs_scope: u8 = 0,
};

/// RFC 9520 section 3.2: a resolution failure, kept so the next client for
/// the same question is answered without a new upstream query. The RCODE is
/// the one the client would have seen; the EDE is the local one the fresh
/// failure carried, if any.
const Failure = struct {
    rcode: dns_header.Rcode = .servfail,
    ede: ?u16 = null,
};

const FailureEntry = struct {
    key: CacheKey = .{},
    expires_at: i64 = 0,
    failure: Failure = .{},
    /// RFC 9520 section 3.2: the consecutive failures of this question. The
    /// count drives the backoff and is forgotten when the question resolves.
    streak: u32 = 0,
};

/// RFC 9520 section 3.2: the cache of resolution failures. It is a table of
/// its own, so a failure never evicts a good answer and the answer cache
/// keeps its own bounds. Every entry expires on its own.
const FailureCache = struct {
    entries: [MAX_FAILURE_CACHE_ENTRIES]FailureEntry = @splat(FailureEntry{}),
    len: usize = 0,
    replacement: usize = 0,
    /// The operator's minimum cache time, in seconds.
    minimum_ttl: u32 = DEFAULT_FAILURE_CACHE_SECONDS,

    fn init(minimum_ttl: u32) FailureCache {
        // RFC 9520 section 3.2: a failure is cached for at least one second
        // and never for longer than five minutes.
        return .{ .minimum_ttl = @min(@max(minimum_ttl, config.FAILURE_CACHE_MIN_SECONDS), config.FAILURE_CACHE_MAX_SECONDS) };
    }

    /// RFC 9520 section 3.2: a failure that keeps repeating is held longer.
    /// The time doubles with every consecutive failure of the question and
    /// never passes the RFC's five-minute ceiling.
    fn ttlFor(self: *const FailureCache, streak: u32) u32 {
        var seconds = self.minimum_ttl;
        var step: u32 = 1;
        while (step < streak) : (step += 1) {
            if (seconds >= config.FAILURE_CACHE_MAX_SECONDS) return config.FAILURE_CACHE_MAX_SECONDS;
            seconds = @min(seconds * 2, config.FAILURE_CACHE_MAX_SECONDS);
        }
        return seconds;
    }

    /// Records the failure of one question. A failure for the same question
    /// is replaced and its count grows, and a full table recycles its oldest
    /// slot.
    fn put(self: *FailureCache, key: CacheKey, failure: Failure, now: i64) void {
        var slot: usize = 0;
        var streak: u32 = 1;
        var index: usize = 0;
        var empty: ?usize = null;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].key.name_len == 0) {
                if (empty == null) empty = index;
                continue;
            }
            if (self.entries[index].key.sameQuestion(&key)) {
                slot = index;
                streak = self.entries[index].streak +| 1;
                break;
            }
        } else {
            if (empty) |free| {
                slot = free;
            } else if (self.len < MAX_FAILURE_CACHE_ENTRIES) {
                slot = self.len;
                self.len += 1;
            } else {
                slot = self.replacement;
                self.replacement = (self.replacement + 1) % MAX_FAILURE_CACHE_ENTRIES;
            }
        }
        self.entries[slot] = .{
            .key = key,
            .expires_at = now + @as(i64, self.ttlFor(streak)),
            .failure = failure,
            .streak = streak,
        };
    }

    /// The failure of this question, or null when it has no live failure.
    /// An expired entry is not served, but its count is kept until the
    /// question resolves, so a failure that keeps repeating is held longer.
    fn lookup(self: *FailureCache, key: *const CacheKey, now: i64) ?Failure {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            const entry = &self.entries[index];
            if (entry.key.name_len == 0) continue;
            if (!entry.key.sameQuestion(key)) continue;
            if (now >= entry.expires_at) return null;
            return entry.failure;
        }
        return null;
    }

    /// RFC 9520 section 3.2: a question that resolves again forgets its
    /// failure count, so the next failure is held for the minimum again.
    fn forget(self: *FailureCache, key: *const CacheKey) void {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].key.name_len == 0) continue;
            if (!self.entries[index].key.sameQuestion(key)) continue;
            self.entries[index] = .{};
            return;
        }
    }
};

const Cache = struct {
    allocator: std.mem.Allocator,
    entries: [MAX_CACHE_ENTRIES]CacheEntry = @splat(CacheEntry{}),
    len: usize = 0,
    replacement: usize = 0,
    /// RFC 9520 section 3.2: the resolution failures this resolver holds.
    failures: FailureCache = .{},

    fn init(allocator: std.mem.Allocator, failure_ttl: u32) Cache {
        return .{ .allocator = allocator, .failures = FailureCache.init(failure_ttl) };
    }

    fn deinit(self: *Cache) void {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].response) |bytes| self.allocator.free(bytes);
            self.entries[index].response = null;
        }
        self.len = 0;
    }

    /// The scope is the one the upstream answered with (RFC 7871 section 6),
    /// which the cached copy reports to every client it serves.
    fn put(self: *Cache, key: CacheKey, message: *dns_message.Message, now: i64, ecs_scope: u8) !void {
        if (message.header.truncated or (message.header.rcode != .no_error and message.header.rcode != .nxdomain)) return;
        const ttl_info = cacheTtl(message) orelse return;
        if (ttl_info.ttl == 0) return;
        try self.store(key, message, now, ttl_info, ecs_scope);
    }

    /// Stores a denial this server synthesized (RFC 8198). Its TTL is the
    /// negative TTL of RFC 2308 section 5, which the SOA the denial carries
    /// already states.
    fn putDenial(self: *Cache, key: CacheKey, message: *dns_message.Message, ttl: u32, now: i64) !void {
        if (ttl == 0) return;
        try self.store(key, message, now, .{
            .ttl = ttl,
            .negative = true,
            .nxdomain = message.header.rcode == .nxdomain,
        }, 0);
    }

    fn store(self: *Cache, key: CacheKey, message: *dns_message.Message, now: i64, ttl_info: TtlInfo, ecs_scope: u8) !void {
        var raw: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        stripOptions(message);
        var writer = dns_writer.Writer.init(&raw);
        message.encode(&writer) catch return Error.ResponseTooLarge;

        var slot: usize = 0;
        var index: usize = 0;
        var empty: ?usize = null;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].response == null) {
                if (empty == null) empty = index;
                continue;
            }
            if (self.entries[index].key.eql(&key)) {
                slot = index;
                break;
            }
        } else {
            if (empty) |free| {
                slot = free;
            } else if (self.len < MAX_CACHE_ENTRIES) {
                slot = self.len;
                self.len += 1;
            } else {
                slot = self.replacement;
                self.replacement = (self.replacement + 1) % MAX_CACHE_ENTRIES;
            }
        }

        if (self.entries[slot].response) |bytes| self.allocator.free(bytes);
        const stored = try self.allocator.dupe(u8, writer.written());
        self.entries[slot] = .{
            .response = stored,
            .key = key,
            .stored_at = now,
            .ttl = ttl_info.ttl,
            .negative = ttl_info.negative,
            .nxdomain = ttl_info.nxdomain,
            .ecs_scope = ecs_scope,
        };
    }

    fn lookup(self: *Cache, key: *const CacheKey, query: dns_message.Message, now: i64, output: []u8, allow_stale: bool) !?LookupResult {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            const entry = &self.entries[index];
            if (entry.response == null) continue;
            if (!entry.key.eql(key)) continue;
            const elapsed = @max(@as(i64, 0), now - entry.stored_at);
            const fresh = elapsed < @as(i64, entry.ttl);
            const stale = !fresh and elapsed <= @as(i64, entry.ttl) + STALE_WINDOW_SECONDS;
            if (!fresh and (!allow_stale or !stale)) {
                self.allocator.free(entry.response.?);
                entry.* = .{};
                break;
            }

            var message = dns_message.Message.parse(arena.allocator(), entry.response.?) catch return null;
            ageMessage(&message, @intCast(elapsed), if (fresh) null else STALE_TTL);
            if (fresh and entry.negative) applyNegativeTtl(&message, remainingTtl(entry, elapsed));
            message.header.id = query.header.id;
            message.header.recursion_desired = query.header.recursion_desired;
            message.header.recursion_available = true;
            message.header.checking_disabled = query.header.checking_disabled;
            message.question = query.question;
            stripProofsForClient(&message, query);
            if (query.edns != null) try appendOpt(&message, query.edns.?);
            try appendEcsScope(&message, key.ecs, entry.ecs_scope);
            if (!fresh) try appendEde(&message, if (entry.nxdomain) EDE_STALE_NXDOMAIN else EDE_STALE_ANSWER);
            var writer = dns_writer.Writer.init(output);
            message.encode(&writer) catch return Error.ResponseTooLarge;
            return .{ .stale = !fresh, .bytes = writer.written() };
        }
        return self.cutLookup(key, query, now, output, arena.allocator());
    }

    /// RFC 8020 section 2: a cached NXDOMAIN makes every name at or below it
    /// unreachable, so a later query for a descendant is answered from the
    /// cache with that denial instead of going upstream. RFC 8020 section 3.2
    /// revises RFC 2308 section 5 the same way: the descendant of the
    /// original QNAME with the same class is answered from the cache. The
    /// scan walks the same table, so the cache keeps its entry limit.
    fn cutLookup(self: *Cache, key: *const CacheKey, query: dns_message.Message, now: i64, output: []u8, allocator: std.mem.Allocator) !?LookupResult {
        var cut: ?*CacheEntry = null;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            const entry = &self.entries[index];
            if (entry.response == null) continue;
            if (!entry.nxdomain) continue;
            if (entry.key.qclass != key.qclass) continue;
            if (entry.key.checking_disabled != key.checking_disabled) continue;
            if (entry.key.dnssec_ok != key.dnssec_ok) continue;
            // RFC 7871 section 7.3.1: a denial is tied to the network it was
            // fetched for, so a cut never crosses into another scope.
            if (!entry.key.ecs.eql(key.ecs)) continue;
            const elapsed = @max(@as(i64, 0), now - entry.stored_at);
            if (elapsed >= @as(i64, entry.ttl)) continue;
            if (!isDescendant(key.name[0..key.name_len], entry.key.name[0..entry.key.name_len])) continue;
            // The closest enclosing denial is the one that names the answer.
            if (cut == null or entry.key.name_len > cut.?.key.name_len) cut = entry;
        }
        const entry = cut orelse return null;
        const elapsed = @max(@as(i64, 0), now - entry.stored_at);
        var message = try dns_message.Message.parse(allocator, entry.response.?);
        // The cached answer belongs to the name above, so its records do not
        // answer this one; the denial and its SOA do.
        message.answers.len = 0;
        message.header.answer_count = 0;
        message.header.id = query.header.id;
        message.header.recursion_desired = query.header.recursion_desired;
        message.header.recursion_available = true;
        message.header.checking_disabled = query.header.checking_disabled;
        message.question = query.question;
        ageMessage(&message, elapsed, null);
        applyNegativeTtl(&message, remainingTtl(entry, elapsed));
        stripProofsForClient(&message, query);
        if (query.edns != null) try appendOpt(&message, query.edns.?);
        try appendEcsScope(&message, key.ecs, entry.ecs_scope);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return .{ .stale = false, .bytes = writer.written() };
    }
};

/// The TTL a negative answer still has left, which is the negative TTL of
/// the entry (RFC 2308 section 5) less the time it has been cached.
fn remainingTtl(entry: *const CacheEntry, elapsed: i64) u32 {
    return entry.ttl -| @as(u32, @intCast(elapsed));
}

/// RFC 2308 section 6: the cached SOA record joins the answer with the TTL
/// it has left, so the client sees when the denial expires.
fn applyNegativeTtl(message: *dns_message.Message, ttl: u32) void {
    for (message.authorities.items[0..message.authorities.len]) |*record| {
        if (record.rrtype.eql(.SOA)) record.ttl = ttl;
    }
}

/// True when `name` sits strictly below `ancestor` in the DNS tree. Both
/// are wire names, so the label structure decides where the ancestor starts.
/// The suffix is compared without regard to case: all comparisons between
/// character strings are case-insensitive (RFC 1035 section 2.3.3).
fn isDescendant(name: []const u8, ancestor: []const u8) bool {
    if (ancestor.len >= name.len) return false;
    if (!endsWithIgnoreCase(name, ancestor)) return false;
    // The root sits above every other name.
    if (ancestor.len == 1 and ancestor[0] == 0) return true;
    const offset = name.len - ancestor.len;
    var index: usize = 0;
    while (index < name.len) {
        const len = name[index];
        if (len == 0) break;
        if (index == offset) return true;
        index += 1 + len;
    }
    return false;
}

/// RFC 5452 section 6: only data in the domain of the query may be
/// accepted. A name is in the domain of the query when it is the query name
/// itself or one of its ancestors or descendants. The comparison ignores
/// case: all comparisons between character strings are case-insensitive
/// (RFC 1035 section 2.3.3).
fn inDomainOf(name: []const u8, query_name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, query_name)) return true;
    return isDescendant(name, query_name) or isDescendant(query_name, name);
}

/// RFC 5452 section 6: the authority section of an upstream answer may hold
/// only data in the domain of the query, so a record for any other name is
/// dropped before the answer is cached and relayed. The records the answer
/// cannot be used without survive: the SOA of a negative answer (RFC 2308
/// section 5), the NS records of a referral (RFC 1034 section 4.3.2), and
/// the DNSSEC denial proofs that ride with them.
fn dropOutOfDomainAuthorities(message: *dns_message.Message, query_name: []const u8) void {
    const referral = isReferral(message);
    const denial = hasSoa(message);
    var write_index: usize = 0;
    var read_index: usize = 0;
    while (read_index < message.authorities.len) : (read_index += 1) {
        const record = message.authorities.items[read_index];
        if (!inDomainOf(record.owner.asWire(), query_name) and
            !isOwnAuthorityData(record, referral, denial)) continue;
        message.authorities.items[write_index] = record;
        write_index += 1;
    }
    message.authorities.len = write_index;
    message.header.authority_count = @intCast(write_index);
}

/// True when the record is the answer's own authority data, which no client
/// can use the answer without: the SOA of a negative answer (RFC 2308
/// section 5), the NS records of a referral (RFC 1034 section 4.3.2), and
/// the DNSSEC denial proofs that ride with them (RFC 2308 section 5 for the
/// NXT record, RFC 4034 section 4 and RFC 5155 section 7.2 for NSEC and
/// NSEC3, whose covering RRSIG the validator needs).
fn isOwnAuthorityData(record: dns_record.ResourceRecord, referral: bool, denial: bool) bool {
    if (record.rrtype.eql(dns_types.RecordType.SOA)) return true;
    if (referral and record.rrtype.eql(dns_types.RecordType.NS)) return true;
    if (!referral and !denial) return false;
    return record.rrtype.eql(dns_types.RecordType.RRSIG) or
        record.rrtype.eql(dns_types.RecordType.NSEC) or
        record.rrtype.eql(dns_types.RecordType.NSEC3) or
        record.rrtype.eql(dns_types.RecordType.NSEC3PARAM);
}

/// True when the authority section carries the SOA of a negative answer
/// (RFC 2308 sections 2.1 and 2.2).
fn hasSoa(message: *const dns_message.Message) bool {
    for (message.authorities.slice()) |record| {
        if (record.rrtype.eql(dns_types.RecordType.SOA)) return true;
    }
    return false;
}

/// RFC 5452 section 6: the additional section of an upstream answer may hold
/// only data in the domain of the query, so a record for any other name is
/// dropped before the answer is cached and relayed.
fn dropOutOfDomainAdditionals(message: *dns_message.Message, query_name: []const u8) void {
    var write_index: usize = 0;
    var read_index: usize = 0;
    while (read_index < message.additionals.len) : (read_index += 1) {
        if (!inDomainOf(message.additionals.items[read_index].owner.asWire(), query_name)) continue;
        message.additionals.items[write_index] = message.additionals.items[read_index];
        write_index += 1;
    }
    message.additionals.len = write_index;
    message.header.additional_count = @intCast(write_index);
}

/// RFC 5452 section 6: a referral's additional section is filtered too. The
/// records a client needs from a referral are the glue of the delegation's
/// own name servers (RFC 9471 section 3.1), so a record survives only when
/// the delegation the query is about names it as a target and that target
/// sits inside the zone the delegation names. Every other record the
/// upstream put there is dropped.
fn filterReferralAdditionals(message: *dns_message.Message, query_name: []const u8) void {
    var write_index: usize = 0;
    var read_index: usize = 0;
    while (read_index < message.additionals.len) : (read_index += 1) {
        const record = message.additionals.items[read_index];
        if (!isDelegationGlue(message, record, query_name)) continue;
        message.additionals.items[write_index] = record;
        write_index += 1;
    }
    message.additionals.len = write_index;
    message.header.additional_count = @intCast(write_index);
}

/// True when the record is the address of a name server the delegation the
/// query is about names: its owner is the target of an NS record of the
/// authority section, that NS record is in the domain of the query, and
/// that target is inside the zone the delegation names.
fn isDelegationGlue(message: *const dns_message.Message, record: dns_record.ResourceRecord, query_name: []const u8) bool {
    for (message.authorities.slice()) |authority| {
        if (!authority.rrtype.eql(dns_types.RecordType.NS)) continue;
        // RFC 5452 section 6: only data in the domain of the query may be
        // accepted, so a delegation the query is not about relays no glue.
        if (!inDomainOf(authority.owner.asWire(), query_name)) continue;
        const target = authority.rdata.NS;
        if (!target.eql(&record.owner)) continue;
        if (!nameInZone(target, authority.owner)) continue;
        return true;
    }
    return false;
}

/// True when the message is a referral: an empty answer section with NS
/// records in the authority section (RFC 1035 section 4.1.1). A referral is
/// not an answer, and its additional section holds the glue of the delegated
/// name servers, which the client needs to follow the delegation.
fn isReferral(message: *const dns_message.Message) bool {
    if (message.answers.len != 0) return false;
    for (message.authorities.slice()) |record| {
        if (record.rrtype.eql(dns_types.RecordType.NS)) return true;
    }
    return false;
}

const LookupResult = struct {
    stale: bool,
    bytes: []const u8,
};

/// True when `name` ends with `suffix`, comparing ASCII case-insensitively.
fn endsWithIgnoreCase(name: []const u8, suffix: []const u8) bool {
    if (suffix.len > name.len) return false;
    return std.ascii.eqlIgnoreCase(name[name.len - suffix.len ..], suffix);
}

const TtlInfo = struct { ttl: u32, negative: bool, nxdomain: bool };

/// RFC 2308 section 5: a negative answer is carried by the SOA record in
/// the authority section, and its TTL is the smaller of that record's TTL
/// and the SOA MINIMUM field. RFC 9520 section 2 keeps NXDOMAIN and NODATA
/// out of the resolution-failure cache, so they follow this rule.
fn cacheTtl(message: *const dns_message.Message) ?TtlInfo {
    if (message.header.rcode == .nxdomain) {
        var ttl: ?u32 = null;
        for (message.authorities.slice()) |record| {
            if (record.rrtype.eql(.SOA)) ttl = @min(ttl orelse record.ttl, @min(record.ttl, record.rdata.SOA.minimum));
        }
        return if (ttl) |value| .{ .ttl = value, .negative = true, .nxdomain = true } else null;
    }
    if (message.header.answer_count == 0) {
        for (message.authorities.slice()) |record| {
            if (record.rrtype.eql(.SOA)) return .{ .ttl = @min(record.ttl, record.rdata.SOA.minimum), .negative = true, .nxdomain = false };
        }
        return null;
    }
    var ttl: ?u32 = null;
    for (message.answers.slice()) |record| ttl = @min(ttl orelse record.ttl, record.ttl);
    return if (ttl) |value| .{ .ttl = value, .negative = false, .nxdomain = false } else null;
}

fn ageMessage(message: *dns_message.Message, elapsed: i64, stale_ttl: ?u32) void {
    ageSection(&message.answers, elapsed, stale_ttl);
    ageSection(&message.authorities, elapsed, stale_ttl);
    ageSection(&message.additionals, elapsed, stale_ttl);
}

fn ageSection(section: *dns_message.RecordSection, elapsed: i64, stale_ttl: ?u32) void {
    for (section.items[0..section.len]) |*record| {
        if (record.rrtype.eql(.OPT)) continue;
        record.ttl = if (stale_ttl) |value| value else if (@as(i64, record.ttl) > elapsed) @intCast(@as(i64, record.ttl) - elapsed) else 0;
    }
}

fn stripOptions(message: *dns_message.Message) void {
    var write_index: usize = 0;
    var read_index: usize = 0;
    while (read_index < message.additionals.len) : (read_index += 1) {
        if (message.additionals.items[read_index].rrtype.eql(.OPT)) continue;
        message.additionals.items[write_index] = message.additionals.items[read_index];
        write_index += 1;
    }
    message.additionals.len = write_index;
    message.header.additional_count = @intCast(write_index);
    message.edns = null;
}

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    policy: Policy,
    upstream: ?std.Io.net.IpAddress,
    cache: Cache,
    /// RFC 8198 aggressive-NSEC cache. Fed from upstream NSEC proofs on the
    /// forward path and consulted before forwarding when the client set DO
    /// without CD. No cryptographic validation is claimed for its denials:
    /// they restate proofs a signed zone already published.
    dnssec_aggressive: dnssec.AggressiveCache = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, policy: Policy) !Resolver {
        return .{
            .allocator = allocator,
            .io = io,
            .policy = policy,
            .upstream = if (policy.forwarder) |forwarder| forwarder.address else null,
            .cache = Cache.init(allocator, policy.failure_cache_seconds),
        };
    }

    pub fn deinit(self: *Resolver) void {
        self.cache.deinit();
        self.policy.cookies.deinit();
        self.policy.anchors.deinit(self.allocator);
    }

    pub fn validateCookie(self: *Resolver, query: dns_message.Message, client: *const std.Io.net.IpAddress) Error!?[24]u8 {
        return switch (self.clientCookie(query, client)) {
            .disabled, .absent => null,
            .invalid => Error.BadCookie,
            .valid => |cookie| cookie,
        };
    }

    pub fn badCookieResponse(self: *const Resolver, query: dns_message.Message, client: *const std.Io.net.IpAddress) !dns_message.Message {
        var message = try errorResponse(query, .badcookie, null);
        errdefer message.deinit();
        if (findOption(query, COOKIE_OPTION_CODE)) |option| if (option.len >= 8) {
            var cookie: [24]u8 = undefined;
            self.policy.cookies.makeServerCookie(client, option[0..8], &cookie);
            try appendCookie(&message, cookie);
        };
        return message;
    }

    pub fn answer(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, client: *const std.Io.net.IpAddress, output: []u8) ![]const u8 {
        if (query.header.opcode != .query) return Error.UnsupportedOpcode;
        const cookie = self.clientCookie(query, client);
        if (cookie == .invalid) return self.cookieFailure(query, client, output);
        var key = try CacheKey.fromQuestion(query);
        // RFC 7871 section 7.1.1: the query goes upstream with the shorter
        // of the client's prefix length and the server's maximum cacheable
        // prefix length, and the key follows the scope the query was sent
        // with, so an answer fetched for one scope is never served to a
        // client that asked for another.
        const scope = self.upstreamScope(query);
        if (scope) |value| key.ecs = value;
        const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s));
        if (try self.cache.lookup(&key, query, now, output, false)) |hit| {
            if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
            return hit.bytes;
        }

        if (self.upstream == null) return Error.NoForwarder;
        // RFC 8198 section 3: a cached NSEC proof answers denial queries
        // without an upstream round trip. Only when the client asked for
        // DNSSEC proofs (DO) and did not disable checking (CD).
        if (wantsDnssecProofs(query)) {
            if (query.question) |question| {
                const denial = self.dnssec_aggressive.deny(question.name, question.qtype, now) catch {
                    // Fail closed: an exact-owner NSEC proof is cached but its
                    // bitmap is malformed, so no denial can be synthesized.
                    // Answer SERVFAIL with a DNSSEC-bogus EDE (RFC 8914)
                    // instead of forwarding as if the cache were clean.
                    var bogus = try Resolver.buildDnssecBogusResponse(query, EDE_DNSSEC_BOGUS);
                    defer bogus.deinit();
                    var writer = dns_writer.Writer.init(output);
                    bogus.encode(&writer) catch return Error.ResponseTooLarge;
                    const bytes = writer.written();
                    if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                    return bytes;
                };
                if (denial) |d| {
                    const bytes = try self.aggressiveAnswer(query, d, key, now, output);
                    if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                    return bytes;
                }
            }
        }
        // RFC 9520 section 3.2: a cached resolution failure answers the next
        // client for the same question, and no outgoing query is sent for it.
        if (self.cache.failures.lookup(&key, now)) |failure| {
            // A stale answer is still better than a failure, and it needs no
            // outgoing query either.
            if (try self.cache.lookup(&key, query, now, output, true)) |stale| {
                if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                return stale.bytes;
            }
            const bytes = try self.failureResponse(query, failure, output);
            if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
            return bytes;
        }
        const exchange = self.queryUpstream(query_bytes, query, scope) catch |err| switch (err) {
            Error.UpstreamFailure,
            Error.BadUpstreamResponse,
            => {
                // RFC 9520 section 3.2: an upstream that sends no usable
                // answer is a resolution failure, and the next client for the
                // same question is answered from the cache.
                self.cache.failures.put(key, .{ .rcode = .servfail, .ede = EDE_NETWORK_ERROR }, now);
                if (try self.cache.lookup(&key, query, now, output, true)) |stale| {
                    if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                    return stale.bytes;
                }
                return err;
            },
            else => return err,
        };
        var response = exchange.response;
        defer response.deinit();

        // RFC 4035 section 3.2.3: the name server side of a validating
        // forwarder sets AD only when the resolver side vouched for every
        // RRset. That verdict is computed below, so the upstream's own bit is
        // cleared first: a forwarder that does not validate must never relay
        // another server's claim of authenticity.
        response.header.authenticated_data = false;
        response.header.id = query.header.id;
        response.header.recursion_desired = query.header.recursion_desired;
        response.header.recursion_available = true;
        response.header.checking_disabled = query.header.checking_disabled;
        response.question = query.question;
        // RFC 7871 section 6: the scope of the answer is the scope the
        // upstream reported, so it is read before the options are stripped.
        // The scope of the query that fetched it bounds it, so an answer
        // fetched without an ADDRESS never reports a scope of its own.
        var upstream_scope = upstreamEcsScope(response, exchange.scope orelse EcsScope{});
        stripOptions(&response);
        // RFC 5452 section 6: only data in the domain of the query may be
        // accepted, so the authority and the additional section keep the
        // records whose owner name is the query name or one of its ancestors
        // or descendants. The answer section is not touched. A referral is not
        // an answer: its additional section holds the glue of the delegated
        // name servers, which the client needs to follow the delegation, so
        // it keeps the glue of the delegation the authority section names and
        // loses everything else.
        if (query.question) |question| {
            dropOutOfDomainAuthorities(&response, question.name.asWire());
            if (isReferral(&response)) {
                filterReferralAdditionals(&response, question.name.asWire());
            } else {
                dropOutOfDomainAdditionals(&response, question.name.asWire());
            }
        }
        // Validation runs before the cache so a bogus answer is never stored
        // (RFC 4035 section 4.7) and so the AD bit a client sees is the one
        // this server computed rather than one re-derived on a cache hit.
        const validated = self.validating(query);
        if (validated) {
            const result = try self.checkDnssec(query, response, @intCast(@max(now, 0)));
            switch (result.status) {
                .secure => {
                    // RFC 6147 section 5.5 item 1: with CD clear and DO
                    // clear the vDNS64 must not set the AD bit, so only a
                    // client that asked for the proofs is told the answer
                    // is authentic.
                    if (wantsDnssecProofs(query)) response.header.authenticated_data = true;
                },
                // RFC 4035 section 5.5: a response that fails validation MUST
                // not be returned, and the client gets SERVFAIL carrying the
                // RFC 8914 INFO-CODE that says why. `wantsDnssecProofs` is
                // false when CD is set, and that is exactly the case section
                // 5.5 says must be returned in full instead.
                // RFC 9520 section 3.4: the validation failure is cached, so
                // the next client for the same question is answered with the
                // same SERVFAIL and the same code and no new upstream query.
                .bogus => {
                    self.cache.failures.put(key, .{ .rcode = .servfail, .ede = result.ede }, now);
                    return self.relayBogus(query, cookie, result.ede, output);
                },
                .insecure => {},
            }
        }
        // RFC 9520 sections 2.1, 2.2, 2.7 and 3.2: an upstream SERVFAIL,
        // REFUSED, or FORMERR says nothing about the name, so it is a
        // resolution failure. The next client for the same question is
        // answered from the failure cache instead of a new upstream query. A
        // DNSSEC validation failure never reaches this point: it returned
        // above with its own RFC 8914 code, and RFC 9520 section 3.4 put it
        // in the failure cache there.
        //
        // RFC 6147 section 5.1.2 runs before this: an error RCODE other than
        // NXDOMAIN is treated as an empty answer, so a synthesis that
        // answers the client with a record is not a resolution failure.
        switch (try synthesizeDns64Answer(self, query, &response, exchange.scope, now)) {
            .none => {},
            .synthesized => |answer_scope| upstream_scope = answer_scope,
            .bogus => |ede| {
                // RFC 9520 section 3.4: the validation failure is cached, so
                // the next client for the same question is answered with the
                // same SERVFAIL and the same code.
                self.cache.failures.put(key, .{ .rcode = .servfail, .ede = ede }, now);
                return self.relayBogus(query, cookie, ede, output);
            },
        }
        switch (response.header.rcode) {
            .servfail => self.cache.failures.put(key, .{ .rcode = .servfail }, now),
            .refused => self.cache.failures.put(key, .{ .rcode = .refused }, now),
            .formerr => self.cache.failures.put(key, .{ .rcode = .formerr }, now),
            // RFC 9520 section 3.2: the question resolved, so its failure
            // count is forgotten and the next failure for it is held for the
            // operator's minimum again.
            .no_error, .nxdomain => self.cache.failures.forget(&key),
            else => {},
        }
        // RFC 8198 sections 5 and 9: only a proof that DNSSEC validation
        // has made trustworthy may be used aggressively. AD is set above
        // only on a validated-secure answer, so it is the verdict here.
        // The harvest runs before the client copy is stripped, so it
        // still sees the full proofs.
        if (response.header.authenticated_data) self.harvestNsecProofs(response, now);
        // RFC 7871 section 7.3.1: the answer is cached under the network it
        // was fetched for, which is the /0 of the retry that carried no
        // ADDRESS, so it is served to the /0 queries only.
        var answer_key = key;
        answer_key.ecs = exchange.scope orelse EcsScope{};
        self.cache.put(answer_key, &response, now, upstream_scope) catch {};
        // RFC 3225 section 3: a query with the DO bit clear must not be answered
        // with DNSSEC security RRs. The cached copy keeps them, so the removal
        // happens on the way out only.
        stripProofsForClient(&response, query);
        if (query.edns) |edns| try appendOpt(&response, edns);
        try appendEcsScope(&response, key.ecs, upstream_scope);
        // DNSSEC presence signals (RFC 8914 6-10) ride along as informational
        // EDE on a relayed response this server did NOT validate. Once the
        // validator has spoken above, its verdict is the answer: emitting a
        // presence-based DNSSEC-bogus code alongside a secure or insecure
        // verdict would contradict it.
        if (!validated and wantsDnssecProofs(query)) {
            if (dnssecPresenceEde(response, @intCast(@max(now, 0)))) |code| {
                appendEde(&response, code) catch {};
            }
        }
        if (cookie == .valid) try appendCookie(&response, cookie.valid);
        var writer = dns_writer.Writer.init(output);
        response.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
    }

    /// RFC 7871 section 7.1.1: the scope the query is sent upstream with,
    /// the client's scope trimmed to the server's maximum cacheable prefix
    /// length. Null when the client sent no option.
    fn upstreamScope(self: *const Resolver, query: dns_message.Message) ?EcsScope {
        const scope = ecsScope(query) orelse return null;
        return trimmedScope(scope, self.policy.max_cacheable_prefix);
    }

    /// True when this response is one this server validates itself: a
    /// configured trust anchor and no CD. The DO bit does not gate
    /// validation: the upstream request always carries DO=1 (RFC 3225
    /// section 3), so the answer holds the records to check whatever the
    /// client asked for. RFC 6147 section 5.5 wants the validation done
    /// with or without DO, because skipping it would let an attacker use
    /// DNS64 to circumvent DNSSEC.
    fn validating(self: *const Resolver, query: dns_message.Message) bool {
        return self.policy.anchors.len != 0 and !query.header.checking_disabled;
    }

    fn checkDnssec(self: *Resolver, query: dns_message.Message, response: dns_message.Message, now: u32) validate.Error!validate.Result {
        // `extra` is empty: the forward path answers from the response alone,
        // so a DS-only anchor has no child DNSKEY RRset to match and the
        // answer is honestly insecure rather than secure.
        return validate.validate(self.allocator, &self.policy.anchors, query, response, &.{}, now);
    }

    /// SERVFAIL plus the RFC 8914 DNSSEC-bogus INFO-CODE the validator
    /// produced, with the cookie the same answer path would have carried.
    /// RFC 9520 section 3.4: the failure is in the failure cache, so the next
    /// client for the same question is answered with the same RCODE and code.
    fn relayBogus(self: *Resolver, query: dns_message.Message, cookie: CookieDecision, ede_code: u16, output: []u8) ![]const u8 {
        _ = self;
        var message = try Resolver.buildDnssecBogusResponse(query, ede_code);
        defer message.deinit();
        if (cookie == .valid) try appendCookie(&message, cookie.valid);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
    }

    /// RFC 9520 section 3.2: the cached failure is answered with the RCODE
    /// the client would have seen, so a cached SERVFAIL stays a SERVFAIL and
    /// is never an NXDOMAIN, a NODATA, or an authenticated answer.
    fn failureResponse(self: *Resolver, query: dns_message.Message, failure: Failure, output: []u8) ![]const u8 {
        _ = self;
        var message = try errorResponse(query, failure.rcode, failure.ede);
        defer message.deinit();
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
    }

    /// SERVFAIL answer carrying a DNSSEC-bogus EDE code for callers that DID
    /// cryptographically validate (or applied policy) and found the data
    /// bogus. The forwarder never calls this on its own presence signals.
    pub fn buildDnssecBogusResponse(query: dns_message.Message, ede_code: u16) !dns_message.Message {
        return errorResponse(query, .servfail, ede_code);
    }

    // RFC 8198 sections 5 and 9: only a proof that DNSSEC validation has
    // made trustworthy may be used aggressively. The call site sets AD only
    // on a validated-secure answer; the gate lives here too so no future
    // caller can bypass it.
    fn harvestNsecProofs(self: *Resolver, response: dns_message.Message, now: i64) void {
        if (!response.header.authenticated_data) return;
        harvestSectionNsec(&self.dnssec_aggressive, response.answers.slice(), now);
        harvestSectionNsec(&self.dnssec_aggressive, response.authorities.slice(), now);
    }

    /// RFC 8198 section 5: the denial this server synthesizes from a cached
    /// NSEC proof. It is kept in the negative cache, so the next client for
    /// a name the denial covers is answered without an upstream query.
    fn aggressiveAnswer(self: *Resolver, query: dns_message.Message, proof: dnssec.ProvenDenial, key: CacheKey, now: i64, output: []u8) ![]const u8 {
        const q = query.question orelse return Error.BadUpstreamResponse;
        var message = dns_message.Message{
            .allocator = query.allocator,
            .header = .{
                .id = query.header.id,
                .qr = true,
                .recursion_desired = query.header.recursion_desired,
                .recursion_available = true,
                .rcode = switch (proof.denial) {
                    .nxdomain => .nxdomain,
                    .nodata => .no_error,
                },
                .question_count = 1,
            },
            .question = q,
            .answers = try dns_message.RecordSection.init(query.allocator, 0),
            .authorities = try dns_message.RecordSection.init(query.allocator, 0),
            .additionals = try dns_message.RecordSection.init(query.allocator, 0),
            .edns = if (query.edns) |edns| .{
                .udp_payload_size = @max(dns_message.CLASSIC_UDP_PAYLOAD_SIZE, @min(edns.udp_payload_size, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE)),
                .extended_rcode = 0,
                .version = dns_message.EDNS_VERSION,
                .dnssec_ok = edns.dnssec_ok,
            } else null,
        };
        errdefer message.deinit();
        // RFC 2308 section 3: a negative answer carries the zone SOA, so the
        // client can cache the denial itself. A denial with no SOA stays
        // uncached (RFC 2308 section 5), and its TTL stays zero: there is no
        // way to stop such a denial from looping between two servers.
        var ttl: u32 = 0;
        if (proof.soa) |soa| {
            ttl = self.denialTtl(now, soa);
            var soa_record = soa;
            soa_record.ttl = ttl;
            try message.authorities.append(soa_record);
            message.header.authority_count = 1;
        }
        // RFC 8020 section 2: the cut answer carries the proof that
        // justifies it. The proof rides only for a client that asked for
        // it (RFC 3225 section 3), and the denial without a proof is served
        // all the same.
        if (proof.proof) |records| {
            if (wantsDnssecProofs(query)) {
                for (records.records[0..records.len]) |record| {
                    const parsed = dns_record.ResourceRecord.parse(record.bytes(), 0) catch continue;
                    try message.authorities.append(parsed.record);
                    message.header.authority_count += 1;
                }
            }
        }
        if (query.edns) |edns| try appendOpt(&message, edns);
        try appendEcsScope(&message, key.ecs, 0);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        // The denial and its proof are kept for the clients that asked for
        // the proofs and for the clients that did not, so the next client in
        // the scope is answered from the cache either way.
        if (ttl != 0) {
            self.cache.putDenial(key, &message, ttl, now) catch {};
            var plain_key = key;
            plain_key.dnssec_ok = false;
            self.cache.putDenial(plain_key, &message, ttl, now) catch {};
        }
        return writer.written();
    }

    /// RFC 8198 section 4: a denial lives no longer than the proof it rests
    /// on, so the shortest live proof bounds it. RFC 8198 section 5.4 caps
    /// the effective TTL of a negative answer at the three hours RFC 2308
    /// section 5 sets, and RFC 2308 section 5 takes the smaller of the SOA's
    /// TTL and its MINIMUM field.
    fn denialTtl(self: *const Resolver, now: i64, soa: dns_record.ResourceRecord) u32 {
        var ttl: u32 = MAX_NEGATIVE_TTL;
        for (self.dnssec_aggressive.entries) |entry| {
            if (!entry.valid) continue;
            const remaining = entry.expires_at - now;
            if (remaining <= 0) continue;
            ttl = @min(ttl, @as(u32, @intCast(remaining)));
        }
        const minimum = switch (soa.rdata) {
            .SOA => |soa_rdata| soa_rdata.minimum,
            else => 0,
        };
        return @min(ttl, @min(soa.ttl, minimum));
    }

    const CookieDecision = union(enum) { disabled, absent, valid: [24]u8, invalid };

    fn clientCookie(self: *Resolver, query: dns_message.Message, client: *const std.Io.net.IpAddress) CookieDecision {
        if (!self.policy.cookies.enabled()) return .disabled;
        const option = findOption(query, COOKIE_OPTION_CODE) orelse return .absent;
        if (!self.policy.cookies.validLength(option.len)) return .invalid;
        if (!self.policy.cookies.validates(client, option)) return .invalid;
        // Challenges carry no server cookie and clients legitimately retry
        // them, so only full cookies enter the bounded replay window.
        if (option.len != 8 and self.policy.cookies.replay_protection) {
            if (self.policy.cookies.replay_db.contains(client, option)) return .invalid;
            self.policy.cookies.replay_db.track(client, option);
        }
        var server_cookie: [24]u8 = undefined;
        self.policy.cookies.makeServerCookie(client, option[0..8], &server_cookie);
        return .{ .valid = server_cookie };
    }

    fn cookieFailure(self: *const Resolver, query: dns_message.Message, client: *const std.Io.net.IpAddress, output: []u8) ![]const u8 {
        var message = try self.badCookieResponse(query, client);
        defer message.deinit();
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
    }

    fn addCachedCookie(self: *const Resolver, output: []u8, query: dns_message.Message, cookie: [24]u8) ![]const u8 {
        _ = self;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        var message = dns_message.Message.parse(arena.allocator(), output) catch return Error.BadUpstreamResponse;
        try appendCookie(&message, cookie);
        var writer = dns_writer.Writer.init(output);
        message.header.id = query.header.id;
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
    }

    /// The answer the upstream gave, and the scope of the query that fetched
    /// it. RFC 7871 section 7.3.1 ties an answer to the network it was
    /// fetched for, and the retry of section 7.1.3 fetches it for /0.
    const UpstreamAnswer = struct {
        response: dns_message.Message,
        scope: ?EcsScope,
    };

    /// RFC 7871 section 7.1.3: an upstream that refuses a query that carried
    /// a non-zero ADDRESS is asked once more with the same query and no
    /// ADDRESS, so it can answer the question without the scope. The retry is
    /// bounded: it happens once, and a second REFUSED ends the exchange the
    /// way it ends without a client subnet.
    fn queryUpstream(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, scope: ?EcsScope) !UpstreamAnswer {
        var response = try self.queryUdp(query_bytes, query, scope);
        const sent = scope orelse return .{ .response = response, .scope = scope };
        if (sent.prefix == 0 or response.header.rcode != .refused) return .{ .response = response, .scope = scope };
        // RFC 7871 section 6: an option whose SOURCE PREFIX-LENGTH is 0
        // carries no ADDRESS, which is the query the retry is.
        var without_address = sent;
        without_address.prefix = 0;
        response.deinit();
        return .{ .response = try self.queryUdp(query_bytes, query, without_address), .scope = without_address };
    }

    fn queryUdp(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, scope: ?EcsScope) !dns_message.Message {
        const upstream = self.upstream orelse return Error.NoForwarder;
        var query_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        if (query_bytes.len < 2 or query_bytes.len > query_buffer.len) return Error.UpstreamFailure;
        // RFC 5452 §9.2: each attempt binds its own socket so the
        // OS-assigned ephemeral source port differs per attempt, widening the
        // Q-ID space with the per-attempt randomized ID below.
        var response_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        var attempt: usize = 0;
        while (attempt < UDP_ATTEMPTS) : (attempt += 1) {
            var socket = try self.bindSourceSocket(upstream);
            defer socket.close(self.io);
            var randomized_id: [2]u8 = undefined;
            self.io.randomSecure(&randomized_id) catch return Error.UpstreamFailure;
            const upstream_query = try buildUpstreamQuery(query_bytes, query, &query_buffer, &self.policy.anchors, scope);
            @memcpy(query_buffer[0..2], &randomized_id);
            const expected_id = std.mem.readInt(u16, &randomized_id, .big);

            socket.send(self.io, &upstream, query_buffer[0..upstream_query.len]) catch continue;
            while (true) {
                const incoming = socket.receiveTimeout(self.io, &response_buffer, UDP_TIMEOUT) catch break;
                if (!incoming.from.eql(&upstream)) continue;
                switch (classifyUpstreamPacket(self.allocator, query, expected_id, incoming.data, scope)) {
                    .ignore => continue,
                    .truncated => return self.queryTcpAfterTruncation(query_buffer[0..upstream_query.len], query, expected_id, UPSTREAM_TCP_DEADLINES_SUPPORTED, scope),
                    .ready => |message| return message,
                }
            }
        }
        return Error.UpstreamFailure;
    }

    /// RFC 5452 section 9.2: the source port of an outgoing query is an
    /// unpredictable ephemeral port, and a port the operator denied is
    /// never used: the socket is closed and another one is bound until a
    /// port outside the denylist is found, and the query fails when there
    /// is none.
    fn bindSourceSocket(self: *Resolver, upstream: std.Io.net.IpAddress) !std.Io.net.Socket {
        var attempt: usize = 0;
        while (attempt < SOURCE_PORT_ATTEMPTS) : (attempt += 1) {
            var local = switch (upstream) {
                .ip4 => std.Io.net.IpAddress{ .ip4 = .unspecified(0) },
                .ip6 => std.Io.net.IpAddress{ .ip6 = .unspecified(0) },
            };
            const socket = std.Io.net.IpAddress.bind(&local, self.io, .{ .mode = .dgram, .protocol = .udp }) catch return Error.UpstreamFailure;
            if (!portDenied(self.policy.deny_ports[0..self.policy.deny_ports_len], localPort(socket))) return socket;
            socket.close(self.io);
        }
        return Error.UpstreamFailure;
    }
    fn queryTcpAfterTruncation(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, expected_id: u16, comptime deadline_support: bool, scope: ?EcsScope) !dns_message.Message {
        if (comptime !deadline_support) return Error.UpstreamFailure;
        return self.queryTcp(query_bytes, query, expected_id, scope);
    }

    fn queryTcp(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, expected_id: u16, scope: ?EcsScope) !dns_message.Message {
        const upstream = self.upstream orelse return Error.NoForwarder;
        var stream = if (comptime UPSTREAM_TCP_DEADLINES_SUPPORTED)
            connectTcpWithTimeoutAvoiding(self.io, &upstream, .{
                .mode = .stream,
                .protocol = .tcp,
                .timeout = TCP_TIMEOUT,
            }, self.policy.deny_ports[0..self.policy.deny_ports_len]) catch return Error.UpstreamFailure
        else
            std.Io.net.IpAddress.connect(&upstream, self.io, .{
                .mode = .stream,
                .protocol = .tcp,
                .timeout = TCP_TIMEOUT,
            }) catch return Error.UpstreamFailure;
        defer stream.close(self.io);
        if (comptime !UPSTREAM_TCP_DEADLINES_SUPPORTED) {
            // The plain connector binds its own source port, so a denied
            // port is refused here instead of carrying a query.
            if (portDenied(self.policy.deny_ports[0..self.policy.deny_ports_len], localPort(stream.socket))) return Error.UpstreamFailure;
        }
        const frame_deadline = tcp_deadline.deadlineFromTimeout(self.io, TCP_TIMEOUT) orelse return Error.UpstreamFailure;
        setTcpIoTimeout(stream);

        var prefix: [2]u8 = undefined;
        if (query_bytes.len == 0 or query_bytes.len > MAX_UPSTREAM_MESSAGE) return Error.UpstreamFailure;
        std.mem.writeInt(u16, &prefix, @intCast(query_bytes.len), .big);
        tcp_deadline.writeExact(stream.socket.handle, self.io, &prefix, frame_deadline) catch return Error.UpstreamFailure;
        tcp_deadline.writeExact(stream.socket.handle, self.io, query_bytes, frame_deadline) catch return Error.UpstreamFailure;

        var response_len_bytes: [2]u8 = undefined;
        tcp_deadline.readExact(stream.socket.handle, self.io, &response_len_bytes, frame_deadline) catch return Error.UpstreamFailure;
        const response_len = std.mem.readInt(u16, &response_len_bytes, .big);
        if (response_len == 0) return Error.BadUpstreamResponse;
        var response_bytes: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        tcp_deadline.readExact(stream.socket.handle, self.io, response_bytes[0..response_len], frame_deadline) catch return Error.UpstreamFailure;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const response = dns_message.Message.parse(arena.allocator(), response_bytes[0..response_len]) catch return Error.BadUpstreamResponse;
        if (!validUpstreamResponse(response, query, expected_id, scope)) return Error.BadUpstreamResponse;
        return cloneMessage(self.allocator, response);
    }
};

/// What the DNS64 synthesis did with the answer: nothing was synthesized, a
/// synthesized AAAA took the answer's place, or the answer the synthesis
/// rests on did not validate and the client must see that failure instead.
const Dns64Outcome = union(enum) {
    none,
    /// The scope the A answer covered: the scope the synthesis rests on.
    synthesized: u8,
    /// RFC 8914 INFO-CODE of the validation failure.
    bogus: u16,
};

/// RFC 6147 sections 5.1.1, 5.1.2, 5.1.4, 5.1.5 and 5.1.6: a DNS64 answers an
/// IN AAAA query whose answer came back empty with an AAAA synthesized from
/// the A records of the same name. An answer that holds a CNAME or DNAME
/// chain is followed to the owner that holds the A records, and the A
/// records come from one more upstream query. An RCODE other than 0 counts as
/// an empty answer, so the query for the A records runs for an error answer
/// too. The scope is the one the AAAA answer was fetched for, so the A query
/// is fetched for that same scope (RFC 7871 section 7.3.1). Returns `.none`
/// when nothing is synthesized, which leaves the answer as the upstream sent
/// it.
fn synthesizeDns64Answer(self: *Resolver, query: dns_message.Message, response: *dns_message.Message, scope: ?EcsScope, now: i64) !Dns64Outcome {
    if (self.policy.nat64_prefixes.len == 0) return .none;
    if (!dns64Applies(query, response.*)) return .none;
    // RFC 6147 section 5.1.4: an AAAA record inside the excluded ranges is
    // not real AAAA data. The offending records are dropped, and an answer
    // that held only such records is then empty, so the synthesis proceeds.
    dropExcludedAaaa(response, &self.policy);
    // RFC 6147 section 5.1.1: a name with a real AAAA is never synthesized
    // over. Section 5.1.2: any other RCODE "is treated as though the RCODE
    // were 0 and the answer section were empty".
    if (response.header.rcode == .no_error and !synthesisTrigger(response.*)) return .none;
    const question = query.question.?;
    // RFC 6147 section 5.1.5: the chain the answer carries is followed to the
    // owner that holds the A records. The chase stays inside the zone the
    // answer came from when the answer names that zone in its SOA; an answer
    // with no SOA is chased under the hop limit and the repeat check alone.
    var chain = AliasChain{};
    const zone_name = answerZone(response.*);
    var target = followAliasChain(response.*, question.name, zone_name, &chain) orelse return .none;
    // RFC 6147 section 5.5: the negative AAAA answer was validated by the
    // caller before this point, and the A answer must validate as well
    // whenever this server validates at all.
    const validating = self.validating(query);
    var hops: usize = 0;
    while (true) {
        var a_query = try buildAQuery(self, query, target, scope);
        defer a_query.deinit();
        var a_query_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        var a_writer = dns_writer.Writer.init(&a_query_buffer);
        a_query.encode(&a_writer) catch return .none;
        var a_response = self.queryUdp(a_writer.written(), a_query, scope) catch return .none;
        defer a_response.deinit();
        if (validating) {
            // RFC 6147 section 5.5: "If the data does not validate, the
            // vDNS64 MUST respond with RCODE=2 (Server failure)".
            const result = try self.checkDnssec(a_query, a_response, @intCast(@max(now, 0)));
            if (result.status == .bogus) return .{ .bogus = result.ede };
        }
        // The A answer may carry a further chain, which is followed too.
        const owner = followAliasChain(a_response, target, zone_name, &chain) orelse return .none;
        if (try synthesizeDns64(&self.policy, owner, response, a_response, &chain)) {
            // RFC 7871 section 7.3.1: the records the client gets come from
            // the A answer, so the answer reports the scope of that answer.
            return .{ .synthesized = upstreamEcsScope(a_response, scope orelse EcsScope{}) };
        }
        // No A records at the owner: the chain goes on, if it goes on at all.
        if (owner.eql(&target) or hops >= zone.MaxAliasHops) return .none;
        target = owner;
        hops += 1;
    }
}

/// RFC 6147 sections 5.1.1, 5.1.5 and 5.1.6: the answer decides whether the
/// synthesis may run. A real AAAA is the answer and is never synthesized
/// over, an empty answer is the trigger, and an answer that holds a CNAME or
/// DNAME chain is the trigger of section 5.1.5.
fn synthesisTrigger(response: dns_message.Message) bool {
    var alias = false;
    for (response.answers.slice()) |record| {
        if (record.rrtype.eql(.AAAA)) return false;
        if (record.rrtype.eql(.CNAME) or record.rrtype.eql(.DNAME)) alias = true;
    }
    return alias or response.answers.len == 0;
}

/// The zone the answer came from: the SOA in the authority section names it.
fn answerZone(response: dns_message.Message) ?dns_name.Name {
    for (response.authorities.slice()) |record| {
        if (record.rrtype.eql(.SOA)) return record.owner;
    }
    return null;
}

/// RFC 6147 section 5.1.5: the CNAME and DNAME records the chase followed.
/// The records stay in the answer section next to the synthesized AAAA.
const AliasChain = struct {
    records: [zone.MaxAliasHops]dns_record.ResourceRecord = undefined,
    len: usize = 0,

    fn append(self: *AliasChain, record: dns_record.ResourceRecord) void {
        if (self.len == self.records.len) return;
        self.records[self.len] = record;
        self.len += 1;
    }
};

/// RFC 6147 section 5.1.5: "the CNAME or DNAME chain is followed until the
/// first terminating A or AAAA record is reached". The chase is bounded the
/// way the authoritative path bounds it: a name that repeats ends it, a
/// chain longer than the hop limit ends it, and so does a chain that leaves
/// the zone the answer came from. Returns the owner the chain ends at.
fn followAliasChain(message: dns_message.Message, start: dns_name.Name, zone_name: ?dns_name.Name, chain: *AliasChain) ?dns_name.Name {
    for (message.answers.slice()) |record| {
        if (record.rrtype.eql(.CNAME) or record.rrtype.eql(.DNAME)) chain.append(record);
    }
    var current = start;
    var visited: [zone.MaxAliasHops]dns_name.Name = undefined;
    var hops: usize = 0;
    while (true) {
        var next: ?dns_name.Name = null;
        for (message.answers.slice()) |record| {
            if (record.rrtype.eql(.CNAME) and record.owner.eql(&current)) {
                next = record.rdata.CNAME;
                break;
            }
        }
        if (next == null) {
            // RFC 6672 section 2.2: a DNAME at an ancestor redirects every
            // name below it, and the closest one wins.
            var closest_len: usize = 0;
            for (message.answers.slice()) |record| {
                if (!record.rrtype.eql(.DNAME)) continue;
                if (next != null and record.owner.asWire().len <= closest_len) continue;
                const substituted = dnameSubstitution(current, record.owner, record.rdata.DNAME) orelse continue;
                next = substituted;
                closest_len = record.owner.asWire().len;
            }
        }
        const target = next orelse return current;
        for (visited[0..hops]) |seen| {
            if (seen.eql(&target)) return null;
        }
        if (hops >= zone.MaxAliasHops) return null;
        if (zone_name) |enclosing| {
            if (!nameInZone(target, enclosing)) return null;
        }
        visited[hops] = target;
        hops += 1;
        current = target;
    }
}

/// RFC 6672 section 2.2: the substitution replaces the suffix labels of the
/// name with the labels in the DNAME's RDATA. Only whole labels are
/// replaced.
fn dnameSubstitution(current: dns_name.Name, owner: dns_name.Name, target: dns_name.Name) ?dns_name.Name {
    const current_wire = current.asWire();
    const owner_wire = owner.asWire();
    if (current_wire.len <= owner_wire.len) return null;
    if (!std.ascii.eqlIgnoreCase(current_wire[current_wire.len - owner_wire.len ..], owner_wire)) return null;
    if (!labelBoundary(current_wire, current_wire.len - owner_wire.len)) return null;
    const prefix = current_wire[0 .. current_wire.len - owner_wire.len];
    const target_wire = target.asWire();
    var buffer: [512]u8 = undefined;
    if (prefix.len + target_wire.len > buffer.len) return null;
    @memcpy(buffer[0..prefix.len], prefix);
    @memcpy(buffer[prefix.len..][0..target_wire.len], target_wire);
    const parsed = dns_name.Name.parse(&buffer, 0) catch return null;
    return parsed.name;
}

/// True when the name is the zone or sits below it. The chase never leaves
/// the zone the answer came from.
fn nameInZone(name: dns_name.Name, zone_name: dns_name.Name) bool {
    const name_wire = name.asWire();
    const zone_wire = zone_name.asWire();
    if (name_wire.len < zone_wire.len) return false;
    if (!std.ascii.eqlIgnoreCase(name_wire[name_wire.len - zone_wire.len ..], zone_wire)) return false;
    return labelBoundary(name_wire, name_wire.len - zone_wire.len);
}

/// True when the offset is where a label starts in the wire name. A suffix
/// that starts inside a label is not a name.
fn labelBoundary(wire: []const u8, offset: usize) bool {
    if (offset == 0) return true;
    var index: usize = 0;
    while (index < wire.len) {
        const len = wire[index];
        if (len == 0) return false;
        index += 1 + len;
        if (index == offset) return true;
    }
    return false;
}

/// RFC 6147 section 5.1.2: the query and the response decide whether this
/// server acts as a DNS64 for them. A client that set CD does the validation
/// and the synthesis itself (RFC 6147 section 5.5), and NXDOMAIN is the one
/// RCODE that is handled as the error it is.
fn dns64Applies(query: dns_message.Message, response: dns_message.Message) bool {
    if (query.header.checking_disabled) return false;
    const question = query.question orelse return false;
    if (!question.qtype.eql(.AAAA) or !question.qclass.eql(.IN)) return false;
    // RFC 6147 section 5.1.2: "A result with RCODE=3 (Name Error) is
    // handled according to normal DNS operation", so the name error is
    // relayed and nothing is synthesized from it.
    if (response.header.rcode == .nxdomain) return false;
    return true;
}

/// RFC 6147 section 5.1.4: the special exclusion set for AAAA records. An
/// AAAA record with an address inside one of these ranges is not real AAAA
/// data: the RFC says an answer that holds only such records "MUST be
/// treated as though it were an empty answer", and the offending records
/// "MUST NOT" be returned to the client.
const dns64_excluded_ranges = [_]struct { bytes: [16]u8, octets: usize }{
    // The IPv4-mapped network ::ffff:0:0/96, the range the RFC says to
    // include by default.
    .{ .bytes = .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    }, .octets = 12 },
    // The Well-Known Prefix 64:ff9b::/96 of RFC 6052 section 2.1.
    .{ .bytes = .{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }, .octets = 12 },
};

/// RFC 6147 section 5.1.4: the address is inside the exclusion set, so the
/// AAAA record that holds it is not real AAAA data. The set is the default
/// ranges, the site's own prefixes, and the ranges the operator named.
fn dns64Excluded(address: [16]u8, policy: *const Policy) bool {
    for (dns64_excluded_ranges) |range| {
        if (addressInRange(address, range.bytes, range.octets)) return true;
    }
    // The site's own Pref64::/n, the prefixes this server synthesizes into.
    for (policy.nat64_prefixes.items[0..policy.nat64_prefixes.len]) |prefix| {
        if (addressInRange(address, prefix.bytes, @as(usize, prefix.length) / 8)) return true;
    }
    for (policy.dns64_excluded.items[0..policy.dns64_excluded.len]) |range| {
        if (range.containsIpv6(address)) return true;
    }
    return false;
}

/// The leading octets of the address are the ones the range covers. Every
/// length in play is a whole number of octets: RFC 6052 section 2.2's six
/// prefix lengths and the two ranges above.
fn addressInRange(address: [16]u8, network: [16]u8, octets: usize) bool {
    return std.mem.eql(u8, address[0..octets], network[0..octets]);
}

/// RFC 6147 section 5.1.4: the offending AAAA records "MUST NOT" be returned
/// as part of a response, so they are taken out of the answer section.
fn dropExcludedAaaa(response: *dns_message.Message, policy: *const Policy) void {
    var kept: usize = 0;
    for (response.answers.slice()) |record| {
        if (record.rdata == .AAAA and dns64Excluded(record.rdata.AAAA, policy)) continue;
        response.answers.items[kept] = record;
        kept += 1;
    }
    if (kept == response.answers.len) return;
    response.answers.len = kept;
    response.header.answer_count = @intCast(kept);
}

/// RFC 6147 section 5.1.7: "The DNS64 MUST check each A RR against
/// configured IPv4 address ranges and select the corresponding IPv6 prefix to
/// use in synthesizing the AAAA RR". The most specific range wins, and a
/// prefix configured without a range serves every IPv4 address.
fn selectPrefix(policy: *const Policy, address: [4]u8) ?config.Nat64Prefix {
    var chosen: ?config.Nat64Prefix = null;
    var chosen_len: u8 = 0;
    for (policy.nat64_prefixes.items[0..policy.nat64_prefixes.len]) |candidate| {
        if (!candidate.range.containsIpv4(address)) continue;
        // RFC 6052 section 3.1: the Well-Known Prefix must not represent a
        // non-global IPv4 address, so it never serves one.
        if (!candidate.represents(address)) continue;
        if (chosen == null or candidate.range.prefix > chosen_len) {
            chosen = candidate;
            chosen_len = candidate.range.prefix;
        }
    }
    return chosen;
}

/// RFC 6147 section 5.1.7: the prefix that builds the synthetic AAAA of an A
/// record, or null when no configured prefix serves the address.
fn prefixForRecord(policy: *const Policy, record: dns_record.ResourceRecord) ?config.Nat64Prefix {
    return selectPrefix(policy, record.rdata.A);
}

/// RFC 6147 section 5.1.6: the A query for the owner that holds the A
/// records. It carries the question the client asked apart from the type,
/// and the client's AD claim does not travel upstream (RFC 4035 section 4.6).
/// RFC 7871 section 7.1.1: it carries the scope the AAAA query carried, so
/// both answers are fetched for one scope.
fn buildAQuery(self: *Resolver, query: dns_message.Message, name: dns_name.Name, scope: ?EcsScope) !dns_message.Message {
    const question = query.question orelse return Error.BadUpstreamResponse;
    var a_query = dns_message.Message{
        .allocator = self.allocator,
        .header = query.header,
        .question = question,
        .answers = try dns_message.RecordSection.init(self.allocator, 0),
        .authorities = try dns_message.RecordSection.init(self.allocator, 0),
        .additionals = try dns_message.RecordSection.init(self.allocator, 0),
    };
    errdefer a_query.deinit();
    a_query.question.?.name = name;
    a_query.question.?.qtype = .A;
    a_query.header.authenticated_data = false;
    // The query carries no OPT record of its own, so the upstream request is
    // composed the way a client query without EDNS is.
    a_query.header.additional_count = 0;
    a_query.edns = null;
    if (scope != null) {
        // The client subnet option rides in an OPT record, so the query
        // needs one of its own for the option to travel upstream.
        a_query.edns = query.edns;
    }
    return a_query;
}

/// RFC 6147 sections 5.1.5, 5.1.6, 5.1.7 and 5.4: the answer section holds
/// the chain the synthesis followed and one synthesized AAAA per A record of
/// the owner that chain ended at, and the authority section keeps the zone's
/// SOA with the TTL RFC 2308 section 5 gives a negative answer, so the client
/// can cache the missing AAAA. The answer claims neither authority nor
/// DNSSEC security: the record comes from no zone.
fn synthesizeDns64(policy: *const Policy, owner: dns_name.Name, response: *dns_message.Message, a_response: dns_message.Message, chain: *const AliasChain) !bool {
    var soa: ?dns_record.ResourceRecord = null;
    for (response.authorities.slice()) |record| {
        if (record.rrtype.eql(.SOA)) {
            soa = record;
            break;
        }
    }
    var usable: usize = 0;
    for (a_response.answers.slice()) |record| {
        if (!record.rrtype.eql(.A) or !record.owner.eql(&owner)) continue;
        if (prefixForRecord(policy, record) == null) continue;
        usable += 1;
    }
    if (usable == 0) return false;

    // RFC 6147 section 5.1.7: the TTL is the smaller of the A record's TTL
    // and the SOA's, or the smaller of the A record's TTL and 600 seconds
    // when the negative answer carried no SOA.
    const soa_limit: u32 = if (soa) |record| record.ttl else 600;
    response.answers.len = 0;
    // RFC 6147 section 5.1.5: the chain stays in the answer section, next to
    // the synthesized AAAA.
    for (chain.records[0..chain.len]) |record| {
        try response.answers.append(record);
    }
    for (a_response.answers.slice()) |record| {
        if (!record.rrtype.eql(.A) or !record.owner.eql(&owner)) continue;
        const prefix = prefixForRecord(policy, record) orelse continue;
        try response.answers.append(.{
            .owner = record.owner,
            .rrtype = .AAAA,
            // RFC 6147 section 5.1.7: the class is the A record's class.
            .class = record.class,
            .ttl = @min(record.ttl, soa_limit),
            .rdata = .{ .AAAA = embedIpv4(prefix, record.rdata.A) },
        });
    }
    response.header.answer_count = @intCast(response.answers.len);

    // The authority section keeps the zone's SOA alone.
    response.authorities.len = 0;
    if (soa) |record| {
        var soa_record = record;
        soa_record.ttl = @min(record.ttl, record.rdata.SOA.minimum);
        try response.authorities.append(soa_record);
    }
    response.header.authority_count = @intCast(response.authorities.len);
    response.header.authoritative = false;
    response.header.authenticated_data = false;
    // RFC 6147 section 5.4: the header of a synthesized answer is set by the
    // usual rules, so the answer the client gets carries no error.
    response.header.rcode = .no_error;
    return true;
}

/// RFC 6052 section 2.2: the IPv4 address inside the prefix. The reserved u
/// octet at bits 64 to 71 and the suffix stay zero.
fn embedIpv4(prefix: config.Nat64Prefix, v4: [4]u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    if (prefix.length == 96) {
        @memcpy(out[0..12], prefix.bytes[0..12]);
        @memcpy(out[12..16], &v4);
        return out;
    }
    const prefix_len: usize = @as(usize, prefix.length) / 8;
    // The bits of the IPv4 address that fit before the u octet.
    const head: usize = (64 - @as(usize, prefix.length)) / 8;
    @memcpy(out[0..prefix_len], prefix.bytes[0..prefix_len]);
    @memcpy(out[prefix_len..][0..head], v4[0..head]);
    @memcpy(out[9..][0 .. 4 - head], v4[head..4]);
    return out;
}

const UpstreamPacket = union(enum) {
    ignore,
    truncated,
    ready: dns_message.Message,
};

/// Parses and validates one UDP datagram with a scratch arena owned by this
/// call, so the receive loop holds no deferred cleanups across iterations.
fn classifyUpstreamPacket(allocator: std.mem.Allocator, query: dns_message.Message, expected_id: u16, data: []const u8, scope: ?EcsScope) UpstreamPacket {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const response = dns_message.Message.parse(arena.allocator(), data) catch return .ignore;
    if (!validUpstreamResponse(response, query, expected_id, scope)) return .ignore;
    if (response.header.truncated) return .truncated;
    return .{ .ready = cloneMessage(allocator, response) catch return .ignore };
}

/// One EDNS(0) OPT record for an upstream request: root owner, type 41, the
/// classic 512-octet payload, the DO bit set, and no option data. RFC 3225
/// section 3 wants the DO bit on every recursive request, so a client query
/// that carried no OPT still gets one upstream.
fn writeDoOptRecord(buffer: []u8) void {
    buffer[0] = 0;
    std.mem.writeInt(u16, buffer[1..3], 41, .big);
    std.mem.writeInt(u16, buffer[3..5], dns_message.CLASSIC_UDP_PAYLOAD_SIZE, .big);
    std.mem.writeInt(u32, buffer[5..9], 0x00008000, .big);
    std.mem.writeInt(u16, buffer[9..11], 0, .big);
}

fn buildUpstreamQuery(
    original: []const u8,
    query: dns_message.Message,
    output: []u8,
    anchors: *const validate.Anchors,
    scope: ?EcsScope,
) ![]const u8 {
    if (query.edns == null) {
        // RFC 3225 section 3: a recursive DNSSEC-aware server MUST set the DO
        // bit on its recursive requests whatever the client asked for, so the
        // upstream answer carries the records this server validates and feeds
        // (RFC 8198) proofs from. A client that sent no OPT gets one OPT
        // record with DO=1 appended to the forwarded bytes, so the question
        // keeps the client's own octets and its QNAME case survives the hop.
        if (original.len < dns_header_len or original.len + opt_record_len > output.len) return Error.UpstreamFailure;
        @memcpy(output[0..original.len], original);
        // RFC 4035 section 4.6: a security-aware resolver MUST clear the AD
        // bit when composing a query message, so a client's claim that an
        // answer was authenticated never reaches the upstream. RFC 1035
        // section 4.1.1 reserves the Z bit, which must be zero in every
        // query. Both bits sit in the header flags word, whose low octet is
        // octet 3.
        output[3] &= ~@as(u8, 0x60);
        const additional_count = std.mem.readInt(u16, output[10..12], .big);
        if (additional_count == std.math.maxInt(u16)) return Error.UpstreamFailure;
        std.mem.writeInt(u16, output[10..12], additional_count + 1, .big);
        writeDoOptRecord(output[original.len..][0..opt_record_len]);
        return output[0 .. original.len + opt_record_len];
    }

    var sanitized = dns_message.Message{
        .allocator = query.allocator,
        .header = query.header,
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    defer sanitized.deinit();
    // RFC 4035 section 4.6: as in the verbatim path above, the client's AD
    // claim does not travel with the composed upstream query.
    sanitized.header.authenticated_data = false;
    // RFC 3225 section 3: a DNSSEC-aware server sets the DO bit on its
    // recursive requests regardless of the query's own DO bit, so the
    // response carries the records this server validates and feeds (RFC 8198)
    // proofs from. A client that did not ask for them gets them stripped on
    // the way out instead.
    var upstream_edns = query.edns.?;
    upstream_edns.dnssec_ok = true;
    try appendOpt(&sanitized, upstream_edns);
    // RFC 7871 section 7.1.1: the SOURCE PREFIX-LENGTH of the client's own
    // option caps what this server may ask upstream, and the server's
    // maximum cacheable prefix length caps it further, so the option
    // travels with the prefix the query was sent with and a scope of 0.
    if (scope) |value| {
        var ecs_buffer: [4 + 16]u8 = undefined;
        try appendOption(&sanitized, dns_rdata.EDNS_ECS_OPTION_CODE, ecsPayload(value, 0, &ecs_buffer));
    }
    appendKeyTags(&sanitized, query, anchors);
    var writer = dns_writer.Writer.init(output);
    sanitized.encode(&writer) catch return Error.UpstreamFailure;
    return writer.written();
}

/// RFC 8145 section 4.2.2.1: a validating resolver signals the Key Tags it
/// will use on a DNSKEY query for a zone a configured anchor speaks for.
/// Section 4.2 forbids the option on any other query, and section 4.3 forbids
/// putting it in a response, so this appears on the way out only. A querier
/// that sent no OPT gets its bytes forwarded untouched, option and all.
fn appendKeyTags(message: *dns_message.Message, query: dns_message.Message, anchors: *const validate.Anchors) void {
    const question = query.question orelse return;
    if (!question.qtype.eql(.DNSKEY)) return;
    var tags: [2 * validate.max_anchors]u8 = undefined;
    const count = anchors.keyTags(question.name, &tags);
    if (count == 0) return;
    appendOption(message, dns_rdata.EDNS_KEY_TAG_OPTION_CODE, tags[0 .. count * 2]) catch {};
}

/// `std.Io.Threaded` currently rejects a non-none connect timeout on POSIX.
/// Keep the same `ConnectOptions.timeout` contract while enforcing it with a
/// nonblocking connect and poll before handing the socket back to `std.Io`.
pub fn connectTcpWithTimeout(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    options: std.Io.net.IpAddress.ConnectOptions,
) std.Io.net.IpAddress.ConnectError!std.Io.net.Stream {
    return connectTcpWithTimeoutAvoiding(io, address, options, &.{});
}

/// RFC 5452 section 9.2: the source port of the TCP retry is an
/// ephemeral port too, and a port the operator denied is never used: the
/// socket is closed and another one is bound until a port outside the
/// denylist is found.
fn connectTcpWithTimeoutAvoiding(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    options: std.Io.net.IpAddress.ConnectOptions,
    deny_ports: []const config.PortRange,
) std.Io.net.IpAddress.ConnectError!std.Io.net.Stream {
    var attempt: usize = 0;
    while (attempt < SOURCE_PORT_ATTEMPTS) : (attempt += 1) {
        const stream = try connectTcpOnce(io, address, options);
        if (!portDenied(deny_ports, localPort(stream.socket))) return stream;
        stream.close(io);
    }
    return error.Unexpected;
}

fn connectTcpOnce(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    options: std.Io.net.IpAddress.ConnectOptions,
) std.Io.net.IpAddress.ConnectError!std.Io.net.Stream {
    if (comptime !UPSTREAM_TCP_DEADLINES_SUPPORTED) return error.OptionUnsupported;

    const timeout = options.timeout.toDurationFromNow(io) orelse return error.OptionUnsupported;
    const timeout_ms = timeout.raw.toMilliseconds();
    if (timeout_ms <= 0) return error.Timeout;
    const poll_timeout: i32 = @intCast(@min(timeout_ms, std.math.maxInt(i32)));

    var local = switch (address.*) {
        .ip4 => std.Io.net.IpAddress{ .ip4 = .unspecified(0) },
        .ip6 => std.Io.net.IpAddress{ .ip6 = .unspecified(0) },
    };
    var socket = std.Io.net.IpAddress.bind(&local, io, .{
        .mode = options.mode,
        .protocol = options.protocol,
    }) catch return error.Unexpected;
    errdefer socket.close(io);

    const flags = fdFlags(socket.handle) catch return error.Unexpected;
    setFdFlags(socket.handle, flags | nonBlockingFlag()) catch return error.Unexpected;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const address_len = std.Io.Threaded.addressToPosix(address, &storage);
    const connect_result = std.posix.system.connect(socket.handle, &storage.any, address_len);
    switch (std.posix.errno(connect_result)) {
        .SUCCESS => {},
        .INPROGRESS, .AGAIN => {
            var poll_fds = [_]std.posix.pollfd{.{
                .fd = socket.handle,
                .events = std.posix.POLL.OUT,
                .revents = 0,
            }};
            const ready = std.posix.poll(&poll_fds, poll_timeout) catch return error.Unexpected;
            if (ready == 0) return error.Timeout;
            const events = std.posix.POLL.OUT | std.posix.POLL.ERR | std.posix.POLL.HUP;
            if ((poll_fds[0].revents & events) == 0) return error.Timeout;

            var socket_error: i32 = 0;
            var option_length: std.posix.socklen_t = @sizeOf(@TypeOf(socket_error));
            const option_result = std.posix.system.getsockopt(
                socket.handle,
                std.posix.SOL.SOCKET,
                std.posix.SO.ERROR,
                @ptrCast(&socket_error),
                &option_length,
            );
            if (std.posix.errno(option_result) != .SUCCESS or socket_error != 0) return error.ConnectionRefused;
        },
        else => return error.Unexpected,
    }
    setFdFlags(socket.handle, flags) catch return error.Unexpected;
    return .{ .socket = socket };
}

/// RFC 5452 section 9.2: a source port the operator denied is never used.
fn portDenied(ports: []const config.PortRange, port: u16) bool {
    for (ports) |range| {
        if (range.contains(port)) return true;
    }
    return false;
}

/// The port a bound socket sends from, which is the source port of the
/// query it carries.
fn localPort(socket: std.Io.net.Socket) u16 {
    return switch (socket.address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
}

fn fdFlags(fd: std.posix.fd_t) !usize {
    const result = std.posix.system.fcntl(fd, std.posix.F.GETFL, @as(usize, 0));
    if (std.posix.errno(result) != .SUCCESS) return error.Unexpected;
    return @intCast(result);
}

fn setFdFlags(fd: std.posix.fd_t, flags: usize) !void {
    const result = std.posix.system.fcntl(fd, std.posix.F.SETFL, flags);
    if (std.posix.errno(result) != .SUCCESS) return error.Unexpected;
}

fn nonBlockingFlag() usize {
    const flags: std.posix.O = .{ .NONBLOCK = true };
    return @intCast(@as(u32, @bitCast(flags)));
}

fn setTcpIoTimeout(stream: std.Io.net.Stream) void {
    if (comptime UPSTREAM_TCP_DEADLINES_SUPPORTED) {
        tcp_deadline.setSocketTimeout(stream.socket.handle, .{ .seconds = 1 });
    }
}

fn cloneMessage(allocator: std.mem.Allocator, source: dns_message.Message) !dns_message.Message {
    var writer_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var writer = dns_writer.Writer.init(&writer_buffer);
    source.encode(&writer) catch return Error.BadUpstreamResponse;
    return dns_message.Message.parse(allocator, writer.written());
}

fn validUpstreamResponse(response: dns_message.Message, query: dns_message.Message, expected_id: u16, scope: ?EcsScope) bool {
    if (!response.header.qr or response.header.id != expected_id or response.header.opcode != query.header.opcode or response.header.question_count != 1) return false;
    const expected = query.question orelse return false;
    const actual = response.question orelse return false;
    if (!actual.name.eql(&expected.name) or !actual.qtype.eql(expected.qtype) or !actual.qclass.eql(expected.qclass)) return false;
    return validEcsResponse(response, scope);
}

/// RFC 7871 section 7.3: an answer that carries a Client Subnet option must
/// match the family, the prefix, and the address bits the query asked for,
/// and an answer that carries one for a query that asked for none is
/// unsolicited and is dropped.
fn validEcsResponse(response: dns_message.Message, scope: ?EcsScope) bool {
    if (findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE) == null) return true;
    const asked = scope orelse return false;
    const answered = ecsScope(response) orelse return false;
    if (answered.family != asked.family) return false;
    // A query that named no address leaves the address to the responder.
    if (asked.prefix == 0) return true;
    if (answered.prefix != asked.prefix) return false;
    const len = (@as(usize, asked.prefix) + 7) / 8;
    return std.mem.eql(u8, asked.address[0..len], answered.address[0..len]);
}

test "upstream TCP connect timeout is explicit and bounded" {
    switch (TCP_TIMEOUT) {
        .duration => |duration| try std.testing.expectEqual(@as(i64, 1000), duration.raw.toMilliseconds()),
        else => return error.TestUnexpectedResult,
    }
}

test "upstream TCP connector rejects an unbounded timeout" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 9);
    try std.testing.expectError(error.OptionUnsupported, connectTcpWithTimeout(io, &address, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = .none,
    }));
}

/// RFC 3225 section 3: a query with the DO bit clear must not be answered
/// with DNSSEC security RRs. The cached copy keeps them, so the removal
/// happens on the way out only.
fn stripProofsForClient(message: *dns_message.Message, query: dns_message.Message) void {
    const dnssec_ok = if (query.edns) |edns| edns.dnssec_ok else false;
    if (dnssec_ok) return;
    const q = query.question orelse return;
    dnssec.stripProofRecords(message, q.qtype);
}
fn wantsDnssecProofs(query: dns_message.Message) bool {
    if (query.header.checking_disabled) return false;
    const edns = query.edns orelse return false;
    return edns.dnssec_ok;
}

fn harvestSectionNsec(cache: *dnssec.AggressiveCache, records: []const dns_record.ResourceRecord, now: i64) void {
    // RFC 2308 section 3: the SOA of the zone rides with the proof that
    // arrived with it, so a denial the proof gives can carry it.
    const soa = sectionSoa(records);
    for (records) |*record| {
        if (!record.rrtype.eql(.NSEC)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const next = dns_name.Name.parse(raw, 0) catch continue;
        cache.insertNsec(record.owner, next.name, raw[next.next_offset..], now, record.ttl, soa, .{
            .nsec = record.*,
            .rrsig = coveringRrsig(records, record.owner),
        });
    }
}

/// The RRSIG that covers the NSEC at `owner` in the same section. RFC 4035
/// section 3.1.3 wants the proof returned with the signature that covers
/// it, and RFC 8020 section 2 returns that signature with a cut answer.
fn coveringRrsig(records: []const dns_record.ResourceRecord, owner: dns_name.Name) ?dns_record.ResourceRecord {
    for (records) |*record| {
        if (!record.rrtype.eql(.RRSIG)) continue;
        if (!record.owner.eql(&owner)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const covered = dnssec.rrsigCovers(raw) catch continue;
        if (covered != dns_types.RecordType.NSEC.code()) continue;
        return record.*;
    }
    return null;
}

/// The zone SOA of a section, which a negative answer carries (RFC 2308
/// section 3).
fn sectionSoa(records: []const dns_record.ResourceRecord) ?dns_record.ResourceRecord {
    for (records) |record| {
        if (record.rrtype.eql(.SOA)) return record;
    }
    return null;
}

/// Presence-only DNSSEC classifier over a response already received. Reports
/// freshness failures (EDE 7/8) and missing-signature cases (EDE 10) from
/// opaque RRSIG/NSEC bytes. Unsigned data yields null (insecure, not bogus).
/// This is NOT cryptographic validation: a null result must never set AD.
fn dnssecPresenceEde(message: dns_message.Message, now: u32) ?u16 {
    var saw_rrsig = false;
    var saw_signed_signal = false;
    const sections = [_][]const dns_record.ResourceRecord{
        message.answers.slice(),
        message.authorities.slice(),
    };
    for (sections) |records| {
        for (records) |*record| {
            if (record.rrtype.eql(.RRSIG)) {
                const raw = switch (record.rdata) {
                    .Unknown => |*unknown| unknown.bytes(),
                    else => continue,
                };
                saw_rrsig = true;
                const status = dnssec.rrsigTimeStatus(raw, now) catch continue;
                if (dnssec.rrsigTimeEde(status)) |code| return code;
            } else if (record.rrtype.eql(.DNSKEY) or record.rrtype.eql(.NSEC) or record.rrtype.eql(.NSEC3)) {
                saw_signed_signal = true;
            }
        }
    }
    if (!saw_rrsig and saw_signed_signal) return EDE_RRSIGS_MISSING;
    return null;
}

fn findOption(message: dns_message.Message, code: u16) ?[]const u8 {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        return switch (record.rdata) {
            .OPT => |*opt| dns_rdata.findOption(opt.bytes(), code),
            else => unreachable,
        };
    }
    return null;
}

fn appendOpt(message: *dns_message.Message, edns: dns_message.EdnsState) !void {
    message.edns = .{
        .udp_payload_size = @max(dns_message.CLASSIC_UDP_PAYLOAD_SIZE, @min(edns.udp_payload_size, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE)),
        .extended_rcode = 0,
        .version = dns_message.EDNS_VERSION,
        .dnssec_ok = edns.dnssec_ok,
    };
    try message.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(message.edns.?.udp_payload_size),
        .ttl = if (edns.dnssec_ok) 0x8000 else 0,
        .rdata = .{ .OPT = .{} },
    });
    message.header.additional_count = @intCast(message.additionals.len);
}

fn errorResponse(request: dns_message.Message, rcode: dns_header.Rcode, ede_code: ?u16) !dns_message.Message {
    const q = request.question orelse return Error.BadUpstreamResponse;
    // RFC 7873 BADCOOKIE is extended RCODE 23: header low bits 7 plus an
    // OPT record with extended-rcode 1 carrying the fresh server cookie. A
    // bare header 7 with no OPT is YXRRSET, so BADCOOKIE responses always
    // synthesize EDNS even when the offending query carried none.
    const with_opt = request.edns != null or rcode == .badcookie;
    const fallback_edns = dns_message.EdnsState{
        .udp_payload_size = dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE,
        .extended_rcode = 0,
        .version = dns_message.EDNS_VERSION,
        .dnssec_ok = false,
    };
    const edns = request.edns orelse fallback_edns;
    var message = dns_message.Message{
        .allocator = request.allocator,
        .header = .{
            .id = request.header.id,
            .qr = true,
            .recursion_desired = request.header.recursion_desired,
            .recursion_available = true,
            .checking_disabled = request.header.checking_disabled,
            .rcode = rcode,
            .question_count = 1,
        },
        .question = q,
        .answers = try dns_message.RecordSection.init(request.allocator, 0),
        .authorities = try dns_message.RecordSection.init(request.allocator, 0),
        .additionals = try dns_message.RecordSection.init(request.allocator, 0),
        .edns = if (with_opt) .{
            .udp_payload_size = @max(dns_message.CLASSIC_UDP_PAYLOAD_SIZE, @min(edns.udp_payload_size, dns_message.DEFAULT_EDNS_UDP_PAYLOAD_SIZE)),
            .extended_rcode = if (rcode == .badcookie) 1 else 0,
            .version = dns_message.EDNS_VERSION,
            .dnssec_ok = edns.dnssec_ok,
        } else null,
    };
    errdefer message.deinit();
    if (with_opt) {
        try appendOpt(&message, edns);
        try appendEcsScope(&message, ecsScope(request) orelse .{}, 0);
        if (rcode == .badcookie) {
            message.edns.?.extended_rcode = 1;
            message.additionals.items[message.additionals.len - 1].ttl |= @as(u32, 1) << 24;
        }
        if (ede_code) |code| try appendEde(&message, code);
    }
    return message;
}

pub fn buildNetworkErrorResponse(request: dns_message.Message) !dns_message.Message {
    return errorResponse(request, .servfail, EDE_NETWORK_ERROR);
}

fn appendEde(message: *dns_message.Message, code: u16) !void {
    if (message.edns == null) return;
    // RFC 8914 OPTION-DATA: two-octet INFO-CODE followed by EXTRA-TEXT.
    // Sized for the longest emitted purpose text ("signature not yet valid").
    const text = edeText(code);
    var ede: [2 + 32]u8 = undefined;
    std.debug.assert(text.len <= 32);
    ede[0] = @intCast(code >> 8);
    ede[1] = @intCast(code & 0xff);
    @memcpy(ede[2..][0..text.len], text);
    try appendOption(message, EDE_OPTION_CODE, ede[0 .. 2 + text.len]);
}

pub fn appendCookie(message: *dns_message.Message, cookie: [24]u8) !void {
    if (message.edns == null) return;
    try appendOption(message, COOKIE_OPTION_CODE, &cookie);
}

fn appendOption(message: *dns_message.Message, code: u16, data: []const u8) !void {
    for (message.additionals.items[0..message.additionals.len]) |*record| {
        if (!record.rrtype.eql(.OPT)) continue;
        if (!record.rdata.OPT.appendOption(code, data)) return Error.ResponseTooLarge;
        return;
    }
    return Error.BadUpstreamResponse;
}

test "resolver ACL and cookie contracts" {
    const cidr = try config.Cidr.parse("127.0.0.0/8");
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 12345);
    try std.testing.expect(cidr.contains(&client));
    const cookie = CookiePolicy.init("current-secret", "previous-secret");
    try std.testing.expect(cookie.validLength(8));
    try std.testing.expect(cookie.validLength(16));
    try std.testing.expect(cookie.validLength(24));
    try std.testing.expect(cookie.validLength(40));
    try std.testing.expect(!cookie.validLength(9));
    try std.testing.expect(!cookie.validLength(15));
    try std.testing.expect(!cookie.validLength(41));

    const client_cookie = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var current_server_cookie: [24]u8 = undefined;
    cookie.makeServerCookie(&client, &client_cookie, &current_server_cookie);
    try std.testing.expect(cookie.validates(&client, &current_server_cookie));

    const previous_only = CookiePolicy.init("previous-secret", null);
    var previous_server_cookie: [24]u8 = undefined;
    previous_only.makeServerCookie(&client, &client_cookie, &previous_server_cookie);
    try std.testing.expect(cookie.validates(&client, &previous_server_cookie));
    try std.testing.expect(!CookiePolicy.init("current-secret", null).validates(&client, &previous_server_cookie));
    previous_server_cookie[23] ^= 1;
    try std.testing.expect(!cookie.validates(&client, &previous_server_cookie));
}

test "cache ages positive and negative responses and emits stale EDE" {
    try std.testing.expectEqual(@as(usize, 64), MAX_CACHE_ENTRIES);
    try std.testing.expectEqual(@as(i64, 86400), STALE_WINDOW_SECONDS);
    try std.testing.expectEqual(@as(u32, 30), STALE_TTL);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2200, "example.com.", true);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();

    var positive = try makePositiveResponse(arena.allocator(), 60);
    defer positive.deinit();
    try cache.put(key, &positive, 1000, 0);
    var output: [2048]u8 = undefined;
    const fresh = (try cache.lookup(&key, query, 1030, &output, false)).?;
    const fresh_message = try dns_message.Message.parse(arena.allocator(), fresh.bytes);
    try std.testing.expect(!fresh.stale);
    try std.testing.expectEqual(@as(u32, 30), fresh_message.answers.items[0].ttl);
    try std.testing.expectEqual(@as(?[]const u8, null), findOption(fresh_message, EDE_OPTION_CODE));

    const stale = (try cache.lookup(&key, query, 1100, &output, true)).?;
    const stale_message = try dns_message.Message.parse(arena.allocator(), stale.bytes);
    try std.testing.expect(stale.stale);
    try std.testing.expectEqual(@as(u32, STALE_TTL), stale_message.answers.items[0].ttl);
    try expectEde(stale_message, EDE_STALE_ANSWER, "stale answer");
    try std.testing.expect((try cache.lookup(&key, query, 1000 + 60 + STALE_WINDOW_SECONDS + 1, &output, true)) == null);

    var negative = try makeNegativeResponse(arena.allocator(), 60, 30);
    defer negative.deinit();
    const negative_key = try CacheKey.fromQuestion(negative);
    try cache.put(negative_key, &negative, 2000, 0);
    var negative_query = try makeTestQuery(arena.allocator(), 0x2201, "missing.example.", true);
    defer negative_query.deinit();
    const negative_stale = (try cache.lookup(&negative_key, negative_query, 2100, &output, true)).?;
    const negative_message = try dns_message.Message.parse(arena.allocator(), negative_stale.bytes);
    try std.testing.expect(negative_stale.stale);
    try std.testing.expectEqual(@as(u32, STALE_TTL), negative_message.authorities.items[0].ttl);
    try expectEde(negative_message, EDE_STALE_NXDOMAIN, "stale nxdomain");

    var nodata = try makeNegativeResponse(arena.allocator(), 60, 30);
    defer nodata.deinit();
    nodata.header.rcode = .no_error;
    try cache.put(negative_key, &nodata, 3000, 0);
    const nodata_stale = (try cache.lookup(&negative_key, negative_query, 3100, &output, true)).?;
    const nodata_message = try dns_message.Message.parse(arena.allocator(), nodata_stale.bytes);
    try expectEde(nodata_message, EDE_STALE_ANSWER, "stale answer");
}

test "the answer cache excludes failures truncation and upstream option data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2300, "example.com.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var failure = try makePositiveResponse(arena.allocator(), 60);
    defer failure.deinit();
    failure.header.rcode = .servfail;
    try cache.put(key, &failure, 1000, 0);
    try std.testing.expect((try cache.lookup(&key, query, 1001, &output, true)) == null);

    var truncated = try makePositiveResponse(arena.allocator(), 60);
    defer truncated.deinit();
    truncated.header.truncated = true;
    try cache.put(key, &truncated, 1000, 0);
    try std.testing.expect((try cache.lookup(&key, query, 1001, &output, true)) == null);

    var with_opt = try makePositiveResponse(arena.allocator(), 60);
    defer with_opt.deinit();
    with_opt.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
    try with_opt.additionals.append(.{
        .owner = dns_name.Name.root(),
        .rrtype = .OPT,
        .class = dns_types.Class.fromCode(1232),
        .ttl = 0,
        .rdata = .{ .OPT = .{} },
    });
    with_opt.header.additional_count = 1;
    try cache.put(key, &with_opt, 1000, 0);
    const hit = (try cache.lookup(&key, query, 1001, &output, false)).?;
    const hit_message = try dns_message.Message.parse(arena.allocator(), hit.bytes);
    try std.testing.expect(hit_message.edns == null);
    try std.testing.expectEqual(@as(usize, 0), hit_message.additionals.len);
}

test "cache reuses an expired slot instead of evicting a live entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var queries: [MAX_CACHE_ENTRIES]dns_message.Message = undefined;
    var responses: [MAX_CACHE_ENTRIES]dns_message.Message = undefined;
    defer {
        for (&queries) |*message| message.deinit();
        for (&responses) |*message| message.deinit();
    }
    var keys: [MAX_CACHE_ENTRIES]CacheKey = undefined;

    var name_buffer: [32]u8 = undefined;
    var index: usize = 0;
    while (index < MAX_CACHE_ENTRIES) : (index += 1) {
        const name_text = try std.fmt.bufPrint(&name_buffer, "host{d}.example.", .{index});
        const name = try dns_name.Name.fromText(name_text);
        queries[index] = try makeTestQuery(arena.allocator(), @intCast(0x3000 + index), name_text, false);
        responses[index] = try makeTestQuery(arena.allocator(), @intCast(0x3000 + index), name_text, false);
        responses[index].header.qr = true;
        responses[index].header.recursion_available = true;
        try responses[index].answers.append(.{
            .owner = name,
            .rrtype = .A,
            .class = .IN,
            .ttl = if (index == 5) 60 else 3600,
            .rdata = .{ .A = .{ 192, 0, 2, 1 } },
        });
        responses[index].header.answer_count = 1;
        keys[index] = try CacheKey.fromQuestion(queries[index]);
        try cache.put(keys[index], &responses[index], 1000, 0);
    }
    try std.testing.expectEqual(MAX_CACHE_ENTRIES, cache.len);

    // Expire the short-lived entry; its slot must be recycled by the next put.
    try std.testing.expect((try cache.lookup(&keys[5], queries[5], 1061, &output, false)) == null);

    var newcomer = try makeTestQuery(arena.allocator(), 0x3fff, "new.example.", false);
    defer newcomer.deinit();
    var newcomer_response = try makeTestQuery(arena.allocator(), 0x3fff, "new.example.", false);
    defer newcomer_response.deinit();
    newcomer_response.header.qr = true;
    newcomer_response.header.recursion_available = true;
    try newcomer_response.answers.append(.{
        .owner = try dns_name.Name.fromText("new.example."),
        .rrtype = .A,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .A = .{ 192, 0, 2, 2 } },
    });
    newcomer_response.header.answer_count = 1;
    const newcomer_key = try CacheKey.fromQuestion(newcomer);
    try cache.put(newcomer_key, &newcomer_response, 1061, 0);
    try std.testing.expectEqual(MAX_CACHE_ENTRIES, cache.len);

    const survivor = (try cache.lookup(&keys[0], queries[0], 1062, &output, false)).?;
    try std.testing.expect(!survivor.stale);
    const fresh = (try cache.lookup(&newcomer_key, newcomer, 1062, &output, false)).?;
    try std.testing.expect(!fresh.stale);
}

test "RFC 8020 section 2: a cached NXDOMAIN cuts the names below it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var denied = try makeTestQuery(arena.allocator(), 0x2800, "a.example.", false);
    defer denied.deinit();
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try cache.put(denied_key, &denial, 1000, 0);

    // A direct child of the denied name is cut.
    var child = try makeTestQuery(arena.allocator(), 0x2801, "b.a.example.", false);
    defer child.deinit();
    const child_key = try CacheKey.fromQuestion(child);
    const child_hit = (try cache.lookup(&child_key, child, 1000, &output, false)).?;
    try std.testing.expect(!child_hit.stale);
    const child_message = try dns_message.Message.parse(arena.allocator(), child_hit.bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, child_message.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), child_message.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), child_message.header.authority_count);
    try std.testing.expect(child_message.authorities.items[0].rrtype.eql(.SOA));
    var question_buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("b.a.example.", try child_message.question.?.name.toText(&question_buffer));

    // A deeper descendant is cut as well.
    var deep = try makeTestQuery(arena.allocator(), 0x2802, "c.d.a.example.", false);
    defer deep.deinit();
    const deep_key = try CacheKey.fromQuestion(deep);
    const deep_hit = (try cache.lookup(&deep_key, deep, 1000, &output, false)).?;
    const deep_message = try dns_message.Message.parse(arena.allocator(), deep_hit.bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, deep_message.header.rcode);

    // A sibling of the denied name and the name above it are not cut.
    var sibling = try makeTestQuery(arena.allocator(), 0x2803, "x.example.", false);
    defer sibling.deinit();
    const sibling_key = try CacheKey.fromQuestion(sibling);
    try std.testing.expect((try cache.lookup(&sibling_key, sibling, 1000, &output, false)) == null);

    var ancestor = try makeTestQuery(arena.allocator(), 0x2804, "example.", false);
    defer ancestor.deinit();
    const ancestor_key = try CacheKey.fromQuestion(ancestor);
    try std.testing.expect((try cache.lookup(&ancestor_key, ancestor, 1000, &output, false)) == null);
}

test "RFC 8020 section 2: a cached answer below a cut name still wins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var denied = try makeTestQuery(arena.allocator(), 0x2810, "a.example.", false);
    defer denied.deinit();
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try cache.put(denied_key, &denial, 1000, 0);

    var positive_query = try makeTestQuery(arena.allocator(), 0x2811, "b.a.example.", false);
    defer positive_query.deinit();
    var positive = try makePositiveResponseFor(arena.allocator(), "b.a.example.", 120);
    defer positive.deinit();
    const positive_key = try CacheKey.fromQuestion(positive_query);
    try cache.put(positive_key, &positive, 1000, 0);

    const hit = (try cache.lookup(&positive_key, positive_query, 1000, &output, false)).?;
    const message = try dns_message.Message.parse(arena.allocator(), hit.bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, message.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), message.header.answer_count);
    try std.testing.expect(message.answers.items[0].rrtype.eql(.A));
}

test "RFC 8020 section 2: the cut expires with the cached entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var denied = try makeTestQuery(arena.allocator(), 0x2820, "a.example.", false);
    defer denied.deinit();
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try cache.put(denied_key, &denial, 1000, 0);

    var child = try makeTestQuery(arena.allocator(), 0x2821, "b.a.example.", false);
    defer child.deinit();
    const child_key = try CacheKey.fromQuestion(child);
    // The negative TTL is 30 seconds, so the cut lives exactly that long.
    const hit = (try cache.lookup(&child_key, child, 1029, &output, false)).?;
    try std.testing.expect(!hit.stale);
    try std.testing.expect((try cache.lookup(&child_key, child, 1030, &output, false)) == null);
}

test "RFC 2308 section 5: the negative TTL is the smaller of the SOA TTL and the SOA MINIMUM" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var denied = try makeTestQuery(arena.allocator(), 0x2830, "a.example.", false);
    defer denied.deinit();
    // SOA TTL 60 with MINIMUM 30: the denial lives 30 seconds.
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try cache.put(denied_key, &denial, 1000, 0);

    const exact = (try cache.lookup(&denied_key, denied, 1000, &output, false)).?;
    const exact_message = try dns_message.Message.parse(arena.allocator(), exact.bytes);
    try std.testing.expectEqual(@as(u32, 30), exact_message.authorities.items[0].ttl);
    const later = (try cache.lookup(&denied_key, denied, 1001, &output, false)).?;
    const later_message = try dns_message.Message.parse(arena.allocator(), later.bytes);
    try std.testing.expectEqual(@as(u32, 29), later_message.authorities.items[0].ttl);

    var child = try makeTestQuery(arena.allocator(), 0x2831, "b.a.example.", false);
    defer child.deinit();
    const child_key = try CacheKey.fromQuestion(child);
    const cut = (try cache.lookup(&child_key, child, 1000, &output, false)).?;
    const cut_message = try dns_message.Message.parse(arena.allocator(), cut.bytes);
    try std.testing.expectEqual(@as(u32, 30), cut_message.authorities.items[0].ttl);

    // SOA TTL 20 with MINIMUM 300: the denial lives 20 seconds.
    var short = try makeTestQuery(arena.allocator(), 0x2832, "c.example.", false);
    defer short.deinit();
    var short_denial = try makeNxdomainResponse(arena.allocator(), "c.example.", 20, 300);
    defer short_denial.deinit();
    const short_key = try CacheKey.fromQuestion(short);
    try cache.put(short_key, &short_denial, 1000, 0);
    const short_hit = (try cache.lookup(&short_key, short, 1000, &output, false)).?;
    const short_message = try dns_message.Message.parse(arena.allocator(), short_hit.bytes);
    try std.testing.expectEqual(@as(u32, 20), short_message.authorities.items[0].ttl);
}

test "RFC 8020 section 2: a descendant of a cached NXDOMAIN is answered without an upstream query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));

    var denied = try makeTestQuery(arena.allocator(), 0x2840, "a.example.", false);
    defer denied.deinit();
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try resolver.cache.put(denied_key, &denial, now, 0);

    var query = try makeTestQuery(arena.allocator(), 0x2841, "b.a.example.", false);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42610);
    // The forwarder points at a closed port, so an upstream attempt would
    // fail instead of answering.
    const bytes = try resolver.answer(encoded, query, &client, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, parsed.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.authority_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.header.answer_count);
}

test "resolver treats missing cookie normally and rejects an invalid cookie" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 12346);
    const policy = Policy{ .cookies = CookiePolicy.init("current-secret", "previous-secret") };
    var resolver = try Resolver.init(std.testing.allocator, io, policy);
    defer resolver.deinit();

    var query = try makeTestQuery(std.testing.allocator, 0x2400, "example.com.", true);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const missing_cookie = try encodeTestMessage(query, &query_bytes);
    try std.testing.expectError(Error.NoForwarder, resolver.answer(missing_cookie, query, &client, &query_bytes));

    const client_cookie = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try setCookieOption(&query, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    const invalid_cookie = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const response_bytes = try resolver.answer(invalid_cookie, query, &client, &output);
    var response_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer response_arena.deinit();
    const response = try dns_message.Message.parse(response_arena.allocator(), response_bytes);
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .badcookie), response.header.rcode);
    try std.testing.expect(response.edns != null);
    try std.testing.expectEqual(@as(u8, 1), response.edns.?.extended_rcode);
    // RFC 7873 section 8: the OPT extended-rcode of 1 is what makes the low
    // bits 7 the extended code 23 rather than YXRRSET.
    try std.testing.expectEqual(@as(u16, dns_header.Rcode.BADCOOKIE_EXTENDED_CODE), response.effectiveRcode());
    try std.testing.expect(response.isBadCookie());
    const server_cookie = findOption(response, COOKIE_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 24), server_cookie.len);
    try std.testing.expectEqualSlices(u8, &client_cookie, server_cookie[0..8]);
}

test "BADCOOKIE answers carry OPT extended 23 even without request EDNS" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2401, "example.com.", false);
    defer query.deinit();

    var message = try errorResponse(query, .badcookie, null);
    defer message.deinit();
    try std.testing.expect(message.edns != null);
    try std.testing.expectEqual(@as(u8, 1), message.edns.?.extended_rcode);
    try std.testing.expect(message.isBadCookie());
    try std.testing.expectEqual(@as(u16, dns_header.Rcode.BADCOOKIE_EXTENDED_CODE), message.effectiveRcode());

    var servfail = try errorResponse(query, .servfail, null);
    defer servfail.deinit();
    try std.testing.expect(servfail.edns == null);
    try std.testing.expectEqual(@as(u16, 2), servfail.effectiveRcode());
}

test "network failures add EDE only when the query has EDNS" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var edns_query = try makeTestQuery(arena.allocator(), 0x2500, "example.com.", true);
    defer edns_query.deinit();
    var response = try buildNetworkErrorResponse(edns_query);
    defer response.deinit();
    try std.testing.expectEqual(@as(@TypeOf(response.header.rcode), .servfail), response.header.rcode);
    try expectEde(response, EDE_NETWORK_ERROR, "network error");

    var classic_query = try makeTestQuery(arena.allocator(), 0x2501, "example.com.", false);
    defer classic_query.deinit();
    var classic_response = try buildNetworkErrorResponse(classic_query);
    defer classic_response.deinit();
    try std.testing.expect(findOption(classic_response, EDE_OPTION_CODE) == null);
}

test "TC fallback is fail closed without deadline support" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{});
    defer resolver.deinit();
    var query = try makeTestQuery(std.testing.allocator, 0x2580, "example.com.", false);
    defer query.deinit();
    try std.testing.expectError(Error.UpstreamFailure, resolver.queryTcpAfterTruncation(&.{}, query, 0, false, null));
}

test "resolver rejects non-query opcodes before cache or upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var query = try makeTestQuery(std.testing.allocator, 0x2600, "example.com.", false);
    defer query.deinit();
    query.header.opcode = .status;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42600);
    try std.testing.expectError(Error.UnsupportedOpcode, resolver.answer(encoded, query, &client, &output));
}

test "resolver forwards the client subnet option upstream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2601, "example.com.", true);
    defer query.deinit();
    const ecs = [_]u8{ 0, 1, 24, 0, 192, 0, 2 };
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &ecs);

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, query, &output, &.{}, ecsScope(query));

    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    const option = findOption(upstream, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 7), option.len);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, option[0..2], .big));
    try std.testing.expectEqual(@as(u8, 24), option[2]);
    // RFC 7871 section 6: the scope of a query is 0.
    try std.testing.expectEqual(@as(u8, 0), option[3]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2 }, option[4..]);

    // RFC 7871 section 7.3: an answer that echoes the option is taken, and
    // one that names another network is dropped.
    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    response.header.id = query.header.id;
    response.question = query.question;
    try appendOpt(&response, query.edns.?);
    try appendOption(&response, dns_rdata.EDNS_ECS_OPTION_CODE, &ecs);
    try std.testing.expect(validUpstreamResponse(response, query, query.header.id, ecsScope(query)));

    var other = try makePositiveResponse(arena.allocator(), 60);
    defer other.deinit();
    other.header.id = query.header.id;
    other.question = query.question;
    try appendOpt(&other, query.edns.?);
    try appendOption(&other, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 198, 51, 100 });
    try std.testing.expect(!validUpstreamResponse(other, query, query.header.id, ecsScope(query)));
}

/// The fake upstream the client subnet tests forward to. It records the
/// client subnet option of the query it received and answers the question.
const EcsUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    /// The number of queries the fake answers before it stops.
    max_requests: usize = 1,
    /// The client subnet option the upstream saw, if any.
    seen: [4 + 16]u8 = @splat(0),
    seen_len: usize = 0,
    requests: usize = 0,
    /// The scope the upstream answers with, or null when its answer carries
    /// no client subnet option.
    answer_scope: ?u8 = null,
};

fn serveEcsUpstream(args: *EcsUpstream) void {
    const timeout: std.Io.Timeout = .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } };
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    while (args.requests < args.max_requests) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, timeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |option| {
            args.seen_len = @min(option.len, args.seen.len);
            @memcpy(args.seen[0..args.seen_len], option[0..args.seen_len]);
        }
        const question = query.question orelse return;
        var answer_slot: [1]dns_record.ResourceRecord = undefined;
        answer_slot[0] = .{
            .owner = question.name,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 1 } },
        };
        var response_buffer: [2048]u8 = undefined;
        // RFC 7871 section 6: an answer that carries the option states the
        // scope it covers in its SCOPE PREFIX-LENGTH.
        var echoed: [4 + 16]u8 = @splat(0);
        var ecs: ?[]const u8 = null;
        if (args.answer_scope) |scope| {
            if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |option| {
                const len = @min(option.len, echoed.len);
                @memcpy(echoed[0..len], option[0..len]);
                echoed[3] = scope;
                ecs = echoed[0..len];
            }
        }
        const bytes = buildDns64UpstreamAnswer(&response_buffer, query, &answer_slot, &.{}, .no_error, ecs) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

test "RFC 7871 section 7.2.2: the answer reports the scope the upstream answered with" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket, .answer_scope = 20 };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2607, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42630);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    // RFC 7871 section 7.2.2: the client that sent the option gets one back.
    const ecs = findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 7), ecs.len);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, ecs[0..2], .big));
    // The source prefix mirrors the query and the scope is the one the
    // upstream answered with, so the client learns the scope of the answer.
    try std.testing.expectEqual(@as(u8, 24), ecs[2]);
    try std.testing.expectEqual(@as(u8, 20), ecs[3]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2 }, ecs[4..]);
    // The upstream saw the scope the answer reports.
    try std.testing.expectEqual(@as(usize, 7), upstream.seen_len);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, upstream.seen[0..2], .big));
    try std.testing.expectEqual(@as(u8, 24), upstream.seen[2]);
    try std.testing.expectEqual(@as(u8, 0), upstream.seen[3]);
}

test "RFC 7871 section 7.3: an upstream answer with no client subnet option has the scope of 0" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x260d, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42632);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    const ecs = findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 7), ecs.len);
    // RFC 7871 section 7.3: an answer with no client subnet option has the
    // scope of 0, so the client is never told the answer covers the prefix
    // it asked for.
    try std.testing.expectEqual(@as(u8, 24), ecs[2]);
    try std.testing.expectEqual(@as(u8, 0), ecs[3]);
}

test "RFC 7871 section 7.2.2: a client that sent no client subnet option gets none in the answer" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket, .max_requests = 2 };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42631);
    var output: [2048]u8 = undefined;

    // A query with EDNS but no client subnet option is answered with the
    // OPT record of the query and with no option in it.
    var edns_query = try makeTestQuery(arena.allocator(), 0x2608, "example.com.", true);
    defer edns_query.deinit();
    var edns_bytes: [1024]u8 = undefined;
    const encoded_edns = try encodeTestMessage(edns_query, &edns_bytes);
    const edns_answer = try resolver.answer(encoded_edns, edns_query, &client, &output);
    const edns_response = try dns_message.Message.parse(arena.allocator(), edns_answer);
    try std.testing.expect(edns_response.edns != null);
    try std.testing.expect(findOption(edns_response, dns_rdata.EDNS_ECS_OPTION_CODE) == null);
    try std.testing.expectEqual(@as(usize, 0), upstream.seen_len);

    // A query without EDNS is answered without an OPT record, so it cannot
    // carry the option either.
    var plain_query = try makeTestQuery(arena.allocator(), 0x2609, "other.example.", false);
    defer plain_query.deinit();
    var plain_bytes: [1024]u8 = undefined;
    const encoded_plain = try encodeTestMessage(plain_query, &plain_bytes);
    const plain_answer = try resolver.answer(encoded_plain, plain_query, &client, &output);
    thread.join();
    const plain_response = try dns_message.Message.parse(arena.allocator(), plain_answer);
    try std.testing.expect(plain_response.edns == null);
    try std.testing.expect(findOption(plain_response, dns_rdata.EDNS_ECS_OPTION_CODE) == null);
}

test "a cached answer reports the scope the upstream answered with" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var scoped = try makeTestQuery(arena.allocator(), 0x260a, "example.com.", true);
    defer scoped.deinit();
    try appendOption(&scoped, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });

    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    try cache.put(try CacheKey.fromQuestion(scoped), &response, 4000, 20);

    var output: [2048]u8 = undefined;
    const key = try CacheKey.fromQuestion(scoped);
    const hit = (try cache.lookup(&key, scoped, 4001, &output, false)).?;
    const answer = try dns_message.Message.parse(arena.allocator(), hit.bytes);
    // RFC 7871 section 7.2.2: the cached answer reports the scope the
    // upstream answered with, so the client learns the scope of the answer it
    // got.
    const ecs = findOption(answer, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 7), ecs.len);
    try std.testing.expectEqual(@as(u8, 24), ecs[2]);
    try std.testing.expectEqual(@as(u8, 20), ecs[3]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2 }, ecs[4..]);
}

test "the answer cache keeps the client subnet scopes apart" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var scoped = try makeTestQuery(arena.allocator(), 0x2604, "example.com.", true);
    defer scoped.deinit();
    try appendOption(&scoped, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var other = try makeTestQuery(arena.allocator(), 0x2604, "example.com.", true);
    defer other.deinit();
    try appendOption(&other, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 16, 0, 192, 0 });
    var plain = try makeTestQuery(arena.allocator(), 0x2604, "example.com.", true);
    defer plain.deinit();

    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    try cache.put(try CacheKey.fromQuestion(scoped), &response, 4000, 0);

    var output: [2048]u8 = undefined;
    const scoped_key = try CacheKey.fromQuestion(scoped);
    try std.testing.expect((try cache.lookup(&scoped_key, scoped, 4001, &output, false)) != null);
    // Another scope and a client that sent no option at all are answered by
    // the upstream, never by the answer fetched for this scope.
    const other_key = try CacheKey.fromQuestion(other);
    try std.testing.expect((try cache.lookup(&other_key, other, 4001, &output, false)) == null);
    const plain_key = try CacheKey.fromQuestion(plain);
    try std.testing.expect((try cache.lookup(&plain_key, plain, 4001, &output, false)) == null);
}

test "a client without the client subnet option keeps today's behavior" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var plain = try makeTestQuery(arena.allocator(), 0x2605, "example.com.", true);
    defer plain.deinit();

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, plain, &output, &.{}, null);
    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    try std.testing.expect(findOption(upstream, dns_rdata.EDNS_ECS_OPTION_CODE) == null);

    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    try cache.put(try CacheKey.fromQuestion(plain), &response, 4000, 0);

    var cache_output: [2048]u8 = undefined;
    const plain_key = try CacheKey.fromQuestion(plain);
    try std.testing.expect((try cache.lookup(&plain_key, plain, 4001, &cache_output, false)) != null);
}

test "a malformed client subnet is refused before the resolver sees it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2606, "example.com.", true);
    defer query.deinit();
    // RFC 7871 section 6: the address is truncated to the source prefix, so
    // a /24 needs three octets and this option carries two.
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0 });

    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    try std.testing.expectError(
        dns_message.Error.MalformedEcsOption,
        dns_message.Message.parse(arena.allocator(), encoded),
    );
}

test "resolver rejects ECS-bearing upstream responses before cache" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2602, "example.com.", true);
    defer query.deinit();
    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    response.header.id = query.header.id;
    response.question = query.question;
    try appendOpt(&response, query.edns.?);
    const ecs = [_]u8{ 0, 1, 24, 0, 192, 0, 2 };
    try appendOption(&response, dns_rdata.EDNS_ECS_OPTION_CODE, &ecs);
    try std.testing.expect(!validUpstreamResponse(response, query, query.header.id, null));
}

test "buildUpstreamQuery strips the other client EDNS options but preserves payload size and DO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query = try makeTestQuery(arena.allocator(), 0x2603, "example.com.", true);
    defer query.deinit();
    query.edns.?.udp_payload_size = 1200;
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].class = dns_types.Class.fromCode(1200);
    query.additionals.items[0].ttl = 0x8000;

    try appendOption(&query, dns_rdata.EDNS_PADDING_OPTION_CODE, &.{ 0xaa, 0xbb });
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 0, 0 });
    try appendOption(&query, COOKIE_OPTION_CODE, &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try appendOption(&query, 65000, &.{ 9, 8, 7 });
    // RFC 7314 section 3.3: the forwarder is not authoritative for the zone,
    // so it neither forwards nor answers with the EXPIRE option.
    try appendOption(&query, dns_rdata.EDNS_EXPIRE_OPTION_CODE, &.{});

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, query, &output, &.{}, ecsScope(query));

    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    try std.testing.expectEqual(@as(u16, 1200), upstream.edns.?.udp_payload_size);
    try std.testing.expect(upstream.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(usize, 8), upstream.additionals.items[0].rdata.OPT.bytes().len);
    try std.testing.expect(findOption(upstream, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);
    // The client subnet option is the one option that travels upstream.
    const ecs = findOption(upstream, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, ecs[0..2], .big));
    try std.testing.expectEqual(@as(u8, 0), ecs[2]);
    try std.testing.expectEqual(@as(u8, 0), ecs[3]);
    try std.testing.expect(findOption(upstream, COOKIE_OPTION_CODE) == null);
    try std.testing.expect(findOption(upstream, 65000) == null);
    try std.testing.expect(findOption(upstream, dns_rdata.EDNS_EXPIRE_OPTION_CODE) == null);
}

test "RFC 3225: buildUpstreamQuery sets DO=1 when the client cleared DO" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query = try makeTestQuery(arena.allocator(), 0x2710, "example.com.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = false;
    query.edns.?.udp_payload_size = 1200;
    query.additionals.items[0].class = dns_types.Class.fromCode(1200);
    query.additionals.items[0].ttl = 0;

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, query, &output, &.{}, null);

    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    try std.testing.expect(upstream.edns.?.dnssec_ok);
}

test "RFC 4343 4.1: the upstream query keeps the case the client sent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query = try makeTestQuery(arena.allocator(), 0x2715, "example.com.", true);
    defer query.deinit();
    query.question.?.name = (try dns_name.Name.parsePreservingCase(
        &.{ 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0 },
        0,
    )).name;

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, query, &output, &.{}, null);

    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Example.COM.", try upstream.question.?.name.toText(&text));
}

test "RFC 4035 section 4.6: buildUpstreamQuery clears the client's AD bit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var plain = try makeTestQuery(arena.allocator(), 0x2714, "example.com.", false);
    defer plain.deinit();
    plain.header.authenticated_data = true;

    var original_bytes: [512]u8 = undefined;
    const original = try encodeTestMessage(plain, &original_bytes);

    var output: [512]u8 = undefined;
    const composed = try buildUpstreamQuery(original, plain, &output, &.{}, null);

    // The client's own octets head the upstream query with the AD bit
    // cleared, and one OPT record with DO=1 follows them (RFC 3225 section 3):
    // the query goes upstream with the DO bit set even though the client sent
    // no OPT. Only ARCOUNT grows, to carry that record.
    var expected = try std.testing.allocator.dupe(u8, original);
    defer std.testing.allocator.free(expected);
    expected[3] &= ~@as(u8, 0x20);
    try std.testing.expectEqualSlices(u8, expected[0..10], composed[0..10]);
    try std.testing.expectEqualSlices(u8, expected[12..], composed[12..original.len]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, composed[10..12], .big));
    try std.testing.expectEqual(@as(usize, original.len + opt_record_len), composed.len);
    try std.testing.expectEqual(@as(u8, 0), composed[original.len]);
    try std.testing.expectEqual(@as(u16, 41), std.mem.readInt(u16, composed[original.len + 1 ..][0..2], .big));
    try std.testing.expectEqual(@as(u32, 0x8000), std.mem.readInt(u32, composed[original.len + 5 ..][0..4], .big));

    // The EDNS-aware path re-encodes the message; the AD claim must not
    // travel there either, and the upstream query semantics stay intact.
    var dnssec_query = try makeTestQuery(arena.allocator(), 0x2715, "example.com.", true);
    defer dnssec_query.deinit();
    dnssec_query.header.authenticated_data = true;
    dnssec_query.edns.?.dnssec_ok = true;
    dnssec_query.edns.?.udp_payload_size = 1200;
    dnssec_query.additionals.items[0].class = dns_types.Class.fromCode(1200);
    dnssec_query.additionals.items[0].ttl = 0x8000;

    var edns_output: [512]u8 = undefined;
    const composed_edns = try buildUpstreamQuery(&.{ 0xde, 0xad }, dnssec_query, &edns_output, &.{}, null);
    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), composed_edns);
    try std.testing.expect(!upstream.header.authenticated_data);
    try std.testing.expect(upstream.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(u16, 1200), upstream.edns.?.udp_payload_size);
}

test "RFC 3225 section 3: a client query without EDNS still asks the upstream with DO=1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var plain = try makeTestQuery(arena.allocator(), 0x2716, "example.com.", false);
    defer plain.deinit();

    var original_bytes: [512]u8 = undefined;
    const original = try encodeTestMessage(plain, &original_bytes);

    var output: [512]u8 = undefined;
    const composed = try buildUpstreamQuery(original, plain, &output, &.{}, null);

    // The question the client sent is the question that goes upstream: only
    // the header's ARCOUNT grows, to carry the record appended to it.
    try std.testing.expectEqualSlices(u8, original[0..10], composed[0..10]);
    try std.testing.expectEqualSlices(u8, original[12..], composed[12..original.len]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, composed[10..12], .big));
    const opt = composed[original.len..];
    try std.testing.expectEqual(@as(usize, opt_record_len), opt.len);
    try std.testing.expectEqual(@as(u8, 0), opt[0]);
    try std.testing.expectEqual(@as(u16, 41), std.mem.readInt(u16, opt[1..3], .big));
    try std.testing.expectEqual(@as(u16, dns_message.CLASSIC_UDP_PAYLOAD_SIZE), std.mem.readInt(u16, opt[3..5], .big));
    try std.testing.expectEqual(@as(u32, 0x8000), std.mem.readInt(u32, opt[5..9], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, opt[9..11], .big));
}

test "RFC 3225: stripProofsForClient drops RRSIG unless the query named it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var message = try makeTestQuery(arena.allocator(), 0x2711, "example.com.", true);
    defer message.deinit();
    message.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .A,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 0, 2, 7 } },
    }) catch unreachable;
    var rrsig_rdata = dns_rdata.Unknown{};
    rrsig_rdata.len = 1;
    rrsig_rdata.data[0] = 0;
    message.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .{ .value = 46 },
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .Unknown = rrsig_rdata },
    }) catch unreachable;
    message.header.answer_count = @intCast(message.answers.len);

    var query = try makeTestQuery(arena.allocator(), 0x2712, "example.com.", false);
    defer query.deinit();
    stripProofsForClient(&message, query);
    try std.testing.expectEqual(@as(u16, 1), message.header.answer_count);

    // Explicit RRSIG query keeps the proof record.
    var rrsig_query = try makeTestQuery(arena.allocator(), 0x2713, "example.com.", false);
    defer rrsig_query.deinit();
    rrsig_query.question.?.qtype.value = 46;
    var message2 = try makeTestQuery(arena.allocator(), 0x2714, "example.com.", true);
    defer message2.deinit();
    message2.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .{ .value = 46 },
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .Unknown = rrsig_rdata },
    }) catch unreachable;
    message2.header.answer_count = @intCast(message2.answers.len);
    stripProofsForClient(&message2, rrsig_query);
    try std.testing.expectEqual(@as(u16, 1), message2.header.answer_count);
}

test "RFC 8145: an upstream DNSKEY query carries the anchors' key tags and nothing else does" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var anchors = try validate.Anchors.parse(arena.allocator(),
        \\example.com. DNSKEY 257 3 8 QUJDRA==
        \\other.test. DS 60485 8 2 aabbccdd
        \\
    );
    defer anchors.deinit(arena.allocator());

    var output: [512]u8 = undefined;
    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();

    var dnskey_query = try makeTestQuery(arena.allocator(), 0x2605, "example.com.", true);
    defer dnskey_query.deinit();
    dnskey_query.question.?.qtype = .DNSKEY;
    const dnskey_upstream = try dns_message.Message.parse(
        parsed_arena.allocator(),
        try buildUpstreamQuery(&.{ 0xde, 0xad }, dnskey_query, &output, &anchors, null),
    );
    // 34959 is the RFC 4034 Appendix B checksum of the DNSKEY RDATA
    // 01 01 03 08 41 42 43 44 that `257 3 8 QUJDRA==` encodes.
    const tags = findOption(dnskey_upstream, dns_rdata.EDNS_KEY_TAG_OPTION_CODE).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x8f }, tags);

    // A DS anchor speaks for its own zone only, and the tag is the Key Tag
    // field its RDATA already carries (RFC 4034 section 5.1.4).
    var ds_query = try makeTestQuery(arena.allocator(), 0x2606, "other.test.", true);
    defer ds_query.deinit();
    ds_query.question.?.qtype = .DNSKEY;
    const ds_upstream = try dns_message.Message.parse(
        parsed_arena.allocator(),
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, ds_query, &output, &anchors, null),
    );
    try std.testing.expectEqualSlices(u8, &.{ 0xec, 0x45 }, findOption(ds_upstream, dns_rdata.EDNS_KEY_TAG_OPTION_CODE).?);

    // Section 4.2: the option is for DNSKEY queries only, so an ordinary query
    // for an anchored name carries nothing extra.
    var a_query = try makeTestQuery(arena.allocator(), 0x2607, "example.com.", true);
    defer a_query.deinit();
    const a_upstream = try dns_message.Message.parse(
        parsed_arena.allocator(),
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, a_query, &output, &anchors, null),
    );
    try std.testing.expect(findOption(a_upstream, dns_rdata.EDNS_KEY_TAG_OPTION_CODE) == null);
    try std.testing.expectEqual(@as(usize, 0), a_upstream.additionals.items[0].rdata.OPT.bytes().len);

    // A forwarder with no trust anchor is not a validating resolver and has
    // no key tags to signal.
    var unanchored = try makeTestQuery(arena.allocator(), 0x2608, "example.com.", true);
    defer unanchored.deinit();
    unanchored.question.?.qtype = .DNSKEY;
    const plain_upstream = try dns_message.Message.parse(
        parsed_arena.allocator(),
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, unanchored, &output, &.{}, null),
    );
    try std.testing.expect(findOption(plain_upstream, dns_rdata.EDNS_KEY_TAG_OPTION_CODE) == null);
}

test "cache separates CD and EDNS DO variants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var base = try makeTestQuery(arena.allocator(), 0x2700, "example.com.", true);
    defer base.deinit();
    var cd = try makeTestQuery(arena.allocator(), 0x2701, "example.com.", true);
    defer cd.deinit();
    cd.header.checking_disabled = true;
    var dnssec_query = try makeTestQuery(arena.allocator(), 0x2702, "example.com.", true);
    defer dnssec_query.deinit();
    dnssec_query.edns.?.dnssec_ok = true;
    dnssec_query.additionals.items[0].ttl |= 0x8000;

    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    try cache.put(try CacheKey.fromQuestion(base), &response, 4000, 0);

    var output: [2048]u8 = undefined;
    const cd_key = try CacheKey.fromQuestion(cd);
    try std.testing.expect((try cache.lookup(&cd_key, cd, 4001, &output, false)) == null);
    const dnssec_key = try CacheKey.fromQuestion(dnssec_query);
    try std.testing.expect((try cache.lookup(&dnssec_key, dnssec_query, 4001, &output, false)) == null);
}

fn expectEde(message: dns_message.Message, code: u16, text: []const u8) !void {
    const option = findOption(message, EDE_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 2 + text.len), option.len);
    try std.testing.expectEqual(code, std.mem.readInt(u16, option[0..2], .big));
    try std.testing.expectEqualSlices(u8, text, option[2..]);
}

test "stale nxdomain ede wire code is 19 not 22" {
    try std.testing.expectEqual(@as(u16, 19), EDE_STALE_NXDOMAIN);
}

test "ede purpose text covers emitted codes" {
    try std.testing.expectEqualStrings("stale answer", edeText(EDE_STALE_ANSWER));
    try std.testing.expectEqualStrings("stale nxdomain", edeText(EDE_STALE_NXDOMAIN));
    try std.testing.expectEqualStrings("network error", edeText(EDE_NETWORK_ERROR));
    try std.testing.expectEqualStrings("dnssec bogus", edeText(EDE_DNSSEC_BOGUS));
    try std.testing.expectEqualStrings("signature expired", edeText(EDE_SIGNATURE_EXPIRED));
    try std.testing.expectEqualStrings("signature not yet valid", edeText(EDE_SIGNATURE_NOT_YET_VALID));
    try std.testing.expectEqualStrings("dnskey missing", edeText(EDE_DNSKEY_MISSING));
    try std.testing.expectEqualStrings("rrsigs missing", edeText(EDE_RRSIGS_MISSING));
    try std.testing.expectEqualStrings("", edeText(0));
}

fn makeTestRrsig(now_expired: bool) dns_rdata.Unknown {
    // Covers A(1), alg 8; expiration/inception chosen relative to now=1_500_000_000.
    const expiration: u32 = if (now_expired) 1_400_000_000 else 2_000_000_000;
    var raw = dns_rdata.Unknown{};
    raw.data[0] = 0x00;
    raw.data[1] = 0x01;
    raw.data[2] = 0x08;
    raw.data[3] = 0x03;
    std.mem.writeInt(u32, raw.data[4..8], 3600, .big);
    std.mem.writeInt(u32, raw.data[8..12], expiration, .big);
    std.mem.writeInt(u32, raw.data[12..16], 1_000_000_000, .big);
    std.mem.writeInt(u16, raw.data[16..18], 1234, .big);
    @memcpy(raw.data[18..27], &[_]u8{ 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00 });
    raw.data[27] = 0xAB;
    raw.len = 28;
    return raw;
}

fn makeTestNsec() dns_rdata.Unknown {
    // next = zzz.example., window-0 bitmap with A only.
    var raw = dns_rdata.Unknown{};
    const next = [_]u8{ 0x03, 'z', 'z', 'z', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00 };
    @memcpy(raw.data[0..next.len], &next);
    raw.data[next.len] = 0x00;
    raw.data[next.len + 1] = 0x01;
    raw.data[next.len + 2] = 0x40;
    raw.len = @intCast(next.len + 3);
    return raw;
}

test "dnssec presence classifier reports freshness and missing signatures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fresh = try makePositiveResponse(arena.allocator(), 60);
    defer fresh.deinit();
    try fresh.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .Unknown = makeTestRrsig(false) },
    });
    try std.testing.expect(dnssecPresenceEde(fresh, 1_500_000_000) == null);
    try std.testing.expectEqual(@as(?u16, EDE_SIGNATURE_EXPIRED), dnssecPresenceEde(fresh, 2_000_000_001));

    var premature = try makePositiveResponse(arena.allocator(), 60);
    defer premature.deinit();
    try premature.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .Unknown = makeTestRrsig(false) },
    });
    try std.testing.expectEqual(@as(?u16, EDE_SIGNATURE_NOT_YET_VALID), dnssecPresenceEde(premature, 999_999_999));

    var unsigned = try makePositiveResponse(arena.allocator(), 60);
    defer unsigned.deinit();
    try std.testing.expect(dnssecPresenceEde(unsigned, 1_500_000_000) == null);

    var no_sigs = try makePositiveResponse(arena.allocator(), 60);
    defer no_sigs.deinit();
    try no_sigs.authorities.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .NSEC,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .Unknown = makeTestNsec() },
    });
    try std.testing.expectEqual(@as(?u16, EDE_RRSIGS_MISSING), dnssecPresenceEde(no_sigs, 1_500_000_000));
}

test "dnssec bogus responses carry SERVFAIL with the EDE code and text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2703, "example.com.", true);
    defer query.deinit();

    var bogus = try Resolver.buildDnssecBogusResponse(query, EDE_DNSSEC_BOGUS);
    defer bogus.deinit();
    try std.testing.expectEqual(dns_header.Rcode.servfail, bogus.header.rcode);
    try expectEde(bogus, EDE_DNSSEC_BOGUS, "dnssec bogus");

    var expired = try Resolver.buildDnssecBogusResponse(query, EDE_SIGNATURE_EXPIRED);
    defer expired.deinit();
    try expectEde(expired, EDE_SIGNATURE_EXPIRED, "signature expired");
}

test "aggressive NSEC answers denials without upstream and honors CD" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Seed closest-encloser plus wildcard-cover proofs as harvestSectionNsec
    // would from NSEC RRs (RFC 8198 section 5). Window 0 bitmap carries
    // A(1) and NSEC(47); byte 5 covers 47 % 8.
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );

    var query = try makeTestQuery(arena.allocator(), 0x2704, "nx.example.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    try std.testing.expect(wantsDnssecProofs(query));

    var output: [2048]u8 = undefined;
    const denial = try resolver.dnssec_aggressive.deny(
        (query.question orelse return error.TestUnexpectedResult).name,
        (query.question orelse return error.TestUnexpectedResult).qtype,
        now,
    );
    try std.testing.expectEqual(dnssec.Denial.nxdomain, denial.?.denial);
    const bytes = try resolver.aggressiveAnswer(query, denial.?, try CacheKey.fromQuestion(query), now, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, parsed.header.rcode);
    try std.testing.expect(parsed.edns.?.dnssec_ok);

    var cd_query = try makeTestQuery(arena.allocator(), 0x2705, "nx.example.", true);
    defer cd_query.deinit();
    cd_query.header.checking_disabled = true;
    cd_query.edns.?.dnssec_ok = true;
    try std.testing.expect(!wantsDnssecProofs(cd_query));
}

test "RFC 8198 section 4: a synthesized denial is reused from the negative cache" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Closest-encloser and wildcard-cover proofs, as harvestSectionNsec
    // would take them from an upstream answer (RFC 8198 section 5).
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42620);
    var output: [2048]u8 = undefined;

    // The first client asks for the proofs: the denial is synthesized from
    // the cached NSEC proofs, with no upstream query.
    var first = try makeTestQuery(arena.allocator(), 0x2860, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    const denial_bytes = try resolver.answer(encoded_first, first, &client, &output);
    const denial = try dns_message.Message.parse(arena.allocator(), denial_bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, denial.header.rcode);

    // The second client asks for a name below the same cut: the denial comes
    // from the negative cache. The forwarder points at a closed port, so an
    // upstream attempt would fail instead of answering.
    var second = try makeTestQuery(arena.allocator(), 0x2861, "deep.nx.example.", false);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const cut_bytes = try resolver.answer(encoded_second, second, &client, &output);
    const cut = try dns_message.Message.parse(arena.allocator(), cut_bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, cut.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), cut.header.answer_count);
    var question_buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("deep.nx.example.", try cut.question.?.name.toText(&question_buffer));

    // A name outside the cut is not answered from that entry: the upstream
    // is asked for it.
    var outside = try makeTestQuery(arena.allocator(), 0x2862, "other.example.", false);
    defer outside.deinit();
    var outside_bytes: [1024]u8 = undefined;
    const encoded_outside = try encodeTestMessage(outside, &outside_bytes);
    try std.testing.expectError(Error.UpstreamFailure, resolver.answer(encoded_outside, outside, &client, &output));
}

/// The NSEC record an upstream answer carries: the next owner name and the
/// type bitmap in the RDATA (RFC 4034 section 4.1.2).
fn makeTestNsecRecord(owner_text: []const u8, next_text: []const u8, bitmap: []const u8, ttl: u32) !dns_record.ResourceRecord {
    var rdata = dns_rdata.Unknown{};
    const wire = (try dns_name.Name.fromText(next_text)).asWire();
    @memcpy(rdata.data[0..wire.len], wire);
    @memcpy(rdata.data[wire.len..][0..bitmap.len], bitmap);
    rdata.len = @intCast(wire.len + bitmap.len);
    return .{
        .owner = try dns_name.Name.fromText(owner_text),
        .rrtype = .NSEC,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .Unknown = rdata },
    };
}

/// The RRSIG that covers an NSEC RRset (RFC 4034 section 3.2): the
/// 18-octet header, the signer's name, and the signature.
fn makeTestRrsigRecord(owner_text: []const u8, signer_text: []const u8, ttl: u32) !dns_record.ResourceRecord {
    var rdata = dns_rdata.Unknown{};
    const wire = (try dns_name.Name.fromText(signer_text)).asWire();
    std.mem.writeInt(u16, rdata.data[0..2], dns_types.RecordType.NSEC.code(), .big);
    rdata.data[2] = 8; // algorithm
    rdata.data[3] = 2; // labels
    std.mem.writeInt(u32, rdata.data[4..8], ttl, .big);
    std.mem.writeInt(u32, rdata.data[8..12], 0xffff_ffff, .big); // expiration
    std.mem.writeInt(u32, rdata.data[12..16], 0, .big); // inception
    std.mem.writeInt(u16, rdata.data[16..18], 1234, .big); // key tag
    @memcpy(rdata.data[18..][0..wire.len], wire);
    @memset(rdata.data[18 + wire.len ..][0..8], 0x5a); // the signature
    rdata.len = @intCast(18 + wire.len + 8);
    return .{
        .owner = try dns_name.Name.fromText(owner_text),
        .rrtype = .RRSIG,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .Unknown = rdata },
    };
}

/// The proofs an upstream answer carried for the closest encloser
/// "example." and the name below it, with the RRSIG that covers each one
/// when the answer carried it.
fn harvestTestProofs(cache: *dnssec.AggressiveCache, now: i64, with_rrsig: bool) !void {
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const records = [_]dns_record.ResourceRecord{
        try makeTestSoa(3600, 3600),
        try makeTestNsecRecord("example.", "mail.example.", &bitmap, 3600),
        try makeTestNsecRecord("mail.example.", "www.example.", &bitmap, 3600),
        try makeTestRrsigRecord("example.", "example.", 3600),
        try makeTestRrsigRecord("mail.example.", "example.", 3600),
    };
    harvestSectionNsec(cache, if (with_rrsig) &records else records[0..3], now);
}

test "RFC 8020 section 2: a cut answer carries the NSEC proof and its RRSIG" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    try harvestTestProofs(&resolver.dnssec_aggressive, now, true);

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42630);
    var output: [4096]u8 = undefined;
    var query = try makeTestQuery(arena.allocator(), 0x2900, "nx.example.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    const answer = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, answer.header.rcode);
    // The proof rides in the authority section: the SOA, the two NSEC
    // records the denial rests on, and the RRSIG that covers each.
    var soa_count: usize = 0;
    var nsec_count: usize = 0;
    var rrsig_count: usize = 0;
    for (answer.authorities.slice()) |record| {
        if (record.rrtype.eql(.SOA)) soa_count += 1;
        if (record.rrtype.eql(.NSEC)) nsec_count += 1;
        if (record.rrtype.eql(.RRSIG)) rrsig_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), soa_count);
    try std.testing.expectEqual(@as(usize, 2), nsec_count);
    try std.testing.expectEqual(@as(usize, 2), rrsig_count);
}

test "RFC 8020 section 2: a cut answer for a client without DO carries no proof" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    try harvestTestProofs(&resolver.dnssec_aggressive, now, true);

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42631);
    var output: [4096]u8 = undefined;
    // The first client asked for the proofs, so the denial is cached with
    // them.
    var first = try makeTestQuery(arena.allocator(), 0x2901, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    _ = try resolver.answer(encoded_first, first, &client, &output);

    // The second client did not ask for the proofs: the cached denial is
    // answered with the SOA and without the proof records.
    var second = try makeTestQuery(arena.allocator(), 0x2902, "nx.example.", true);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const bytes = try resolver.answer(encoded_second, second, &client, &output);
    const answer = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, answer.header.rcode);
    var soa_count: usize = 0;
    for (answer.authorities.slice()) |record| {
        try std.testing.expect(!record.rrtype.eql(.NSEC));
        try std.testing.expect(!record.rrtype.eql(.RRSIG));
        if (record.rrtype.eql(.SOA)) soa_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), soa_count);
}

test "RFC 8020 section 2: the cut answer for a name below the denial carries the cached proof" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    try harvestTestProofs(&resolver.dnssec_aggressive, now, true);

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42632);
    var output: [4096]u8 = undefined;
    var first = try makeTestQuery(arena.allocator(), 0x2903, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    _ = try resolver.answer(encoded_first, first, &client, &output);

    // The second client asks for a name below the denial: the answer comes
    // from the cache with the proof, and the forwarder points at a closed
    // port, so an upstream attempt would fail instead of answering.
    var second = try makeTestQuery(arena.allocator(), 0x2904, "deep.nx.example.", true);
    defer second.deinit();
    second.edns.?.dnssec_ok = true;
    second.additionals.items[0].ttl |= 0x8000;
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const bytes = try resolver.answer(encoded_second, second, &client, &output);
    const answer = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, answer.header.rcode);
    var nsec_count: usize = 0;
    var rrsig_count: usize = 0;
    for (answer.authorities.slice()) |record| {
        if (record.rrtype.eql(.NSEC)) nsec_count += 1;
        if (record.rrtype.eql(.RRSIG)) rrsig_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), nsec_count);
    try std.testing.expectEqual(@as(usize, 2), rrsig_count);
}

test "RFC 8020 section 2: a cut answer with no proof is served all the same" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    // The upstream answer carried the NSEC without the RRSIG that covers
    // it, so there is no proof to return.
    try harvestTestProofs(&resolver.dnssec_aggressive, now, false);

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42633);
    var output: [4096]u8 = undefined;
    var query = try makeTestQuery(arena.allocator(), 0x2905, "nx.example.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    const answer = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, answer.header.rcode);
    var soa_count: usize = 0;
    for (answer.authorities.slice()) |record| {
        try std.testing.expect(!record.rrtype.eql(.NSEC));
        try std.testing.expect(!record.rrtype.eql(.RRSIG));
        if (record.rrtype.eql(.SOA)) soa_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), soa_count);
}

test "RFC 8198 section 5.4: a synthesized denial lives as long as its proof" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };

    // The TTL of the denial is the TTL of the proof it rests on.
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );
    var query = try makeTestQuery(arena.allocator(), 0x2864, "nx.example.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42621);
    _ = try resolver.answer(encoded, query, &client, &output);
    try std.testing.expectEqual(@as(u32, 3600), resolver.cache.entries[0].ttl);

    // RFC 8198 section 5.4 caps the effective TTL of a negative answer at
    // the three hours RFC 2308 section 5 sets.
    var capped = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer capped.deinit();
    capped.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        200000,
        try makeTestSoa(200000, 200000),
        .{},
    );
    capped.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        200000,
        try makeTestSoa(200000, 200000),
        .{},
    );
    var capped_query = try makeTestQuery(arena.allocator(), 0x2865, "nx.example.", true);
    defer capped_query.deinit();
    capped_query.edns.?.dnssec_ok = true;
    capped_query.additionals.items[0].ttl |= 0x8000;
    var capped_bytes: [1024]u8 = undefined;
    const encoded_capped = try encodeTestMessage(capped_query, &capped_bytes);
    _ = try capped.answer(encoded_capped, capped_query, &client, &output);
    try std.testing.expectEqual(MAX_NEGATIVE_TTL, capped.cache.entries[0].ttl);
}

test "RFC 2308 section 5: a synthesized NODATA covers its own name only" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Exact-owner proof whose bitmap lists NSEC (47) and no A: the denial is
    // a NODATA for that name.
    const bitmap = [_]u8{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("www.example."),
        try dns_name.Name.fromText("zzz.example."),
        &bitmap,
        now,
        3600,
        try makeTestSoa(3600, 3600),
        .{},
    );

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42622);
    var output: [2048]u8 = undefined;

    var first = try makeTestQuery(arena.allocator(), 0x2866, "www.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    const denial_bytes = try resolver.answer(encoded_first, first, &client, &output);
    const denial = try dns_message.Message.parse(arena.allocator(), denial_bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, denial.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), denial.header.answer_count);

    // The same name is answered from the cache.
    var second = try makeTestQuery(arena.allocator(), 0x2867, "www.example.", false);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const cached_bytes = try resolver.answer(encoded_second, second, &client, &output);
    const cached = try dns_message.Message.parse(arena.allocator(), cached_bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, cached.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), cached.header.answer_count);

    // A name below it is not covered by a NODATA (RFC 2308 section 5), so
    // the upstream is asked for it.
    var below = try makeTestQuery(arena.allocator(), 0x2868, "sub.www.example.", false);
    defer below.deinit();
    var below_bytes: [1024]u8 = undefined;
    const encoded_below = try encodeTestMessage(below, &below_bytes);
    try std.testing.expectError(Error.UpstreamFailure, resolver.answer(encoded_below, below, &client, &output));
}

test "RFC 2308 section 6: a cached denial carries the zone SOA" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Closest-encloser and wildcard-cover proofs, as harvestSectionNsec
    // would take them from an upstream answer (RFC 8198 section 5), with the
    // SOA that answer carried.
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const soa = try makeTestSoa(3600, 3600);
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        soa,
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        soa,
        .{},
    );

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42623);
    var output: [2048]u8 = undefined;

    // The first client gets the synthesized denial with the zone SOA in the
    // authority section, so the client can cache the denial itself.
    var first = try makeTestQuery(arena.allocator(), 0x2870, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    const denial_bytes = try resolver.answer(encoded_first, first, &client, &output);
    const denial = try dns_message.Message.parse(arena.allocator(), denial_bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, denial.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), denial.header.authority_count);
    try std.testing.expect(denial.authorities.items[0].rrtype.eql(.SOA));
    var owner_buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("example.", try denial.authorities.items[0].owner.toText(&owner_buffer));

    // The second client is answered from the cache, and the answer carries
    // the SOA too. The forwarder points at a closed port, so an upstream
    // attempt would fail instead of answering.
    var second = try makeTestQuery(arena.allocator(), 0x2871, "deep.nx.example.", false);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const cut_bytes = try resolver.answer(encoded_second, second, &client, &output);
    const cut = try dns_message.Message.parse(arena.allocator(), cut_bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, cut.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), cut.header.authority_count);
    try std.testing.expect(cut.authorities.items[0].rrtype.eql(.SOA));
    // RFC 2308 section 6: the SOA rides with the TTL it has left.
    try std.testing.expect(cut.authorities.items[0].ttl > 0);
    try std.testing.expect(cut.authorities.items[0].ttl <= 3600);
}

test "RFC 2308 section 5: the negative TTL of a synthesized denial is the SOA's" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // The proof lives an hour, but the SOA's MINIMUM is a minute, so the
    // negative TTL is the minute (RFC 2308 section 5).
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const soa = try makeTestSoa(3600, 60);
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        soa,
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        soa,
        .{},
    );

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42624);
    var output: [2048]u8 = undefined;

    var first = try makeTestQuery(arena.allocator(), 0x2872, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    _ = try resolver.answer(encoded_first, first, &client, &output);

    // The cached entry lives the negative TTL, not the TTL of the proof.
    try std.testing.expectEqual(@as(u32, 60), resolver.cache.entries[0].ttl);

    // The SOA the client is served carries that TTL.
    var second = try makeTestQuery(arena.allocator(), 0x2873, "deep.nx.example.", false);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    const cut_bytes = try resolver.answer(encoded_second, second, &client, &output);
    const cut = try dns_message.Message.parse(arena.allocator(), cut_bytes);
    try std.testing.expect(cut.authorities.items[0].ttl > 0);
    try std.testing.expect(cut.authorities.items[0].ttl <= 60);
}

test "RFC 2308 section 5: a denial without an SOA is not cached" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // The same proofs without the SOA of the zone they came from.
    const bitmap = [_]u8{ 0x00, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("example."),
        try dns_name.Name.fromText("mail.example."),
        &bitmap,
        now,
        3600,
        null,
        .{},
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
        null,
        .{},
    );

    var client = try std.Io.net.IpAddress.parse("127.0.0.1", 42625);
    var output: [2048]u8 = undefined;

    // The first client is still answered with the denial.
    var first = try makeTestQuery(arena.allocator(), 0x2874, "nx.example.", true);
    defer first.deinit();
    first.edns.?.dnssec_ok = true;
    first.additionals.items[0].ttl |= 0x8000;
    var first_bytes: [1024]u8 = undefined;
    const encoded_first = try encodeTestMessage(first, &first_bytes);
    const denial_bytes = try resolver.answer(encoded_first, first, &client, &output);
    const denial = try dns_message.Message.parse(arena.allocator(), denial_bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, denial.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), denial.header.authority_count);

    // The denial is not cached: without an SOA there is no way to stop it
    // from looping between two servers (RFC 2308 section 5).
    try std.testing.expectEqual(@as(usize, 0), resolver.cache.len);

    // The second client for the same name is not answered from the cache:
    // the upstream is asked, and the forwarder points at a closed port.
    var second = try makeTestQuery(arena.allocator(), 0x2875, "nx.example.", false);
    defer second.deinit();
    var second_bytes: [1024]u8 = undefined;
    const encoded_second = try encodeTestMessage(second, &second_bytes);
    try std.testing.expectError(Error.UpstreamFailure, resolver.answer(encoded_second, second, &client, &output));
}

test "aggressive NSEC answers SERVFAIL with bogus EDE on malformed bitmap" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = try std.Io.net.IpAddress.parse("127.0.0.1", 9) },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // Exact-owner proof whose bitmap lacks the NSEC bit: deny errors instead
    // of synthesizing a false NODATA.
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("www.example."),
        try dns_name.Name.fromText("zzz.example."),
        &[_]u8{ 0x00, 0x01, 0x40 },
        now,
        3600,
        null,
        .{},
    );
    try std.testing.expectError(
        dnssec.Error.MalformedNsec,
        resolver.dnssec_aggressive.deny(try dns_name.Name.fromText("www.example."), .A, now),
    );

    // The forward path maps that failure to SERVFAIL with a DNSSEC-bogus
    // EDE (RFC 8914) before any upstream round trip.
    var query = try makeTestQuery(arena.allocator(), 0x2706, "www.example.", true);
    defer query.deinit();
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42602);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.servfail, parsed.header.rcode);
    try expectEde(parsed, EDE_DNSSEC_BOGUS, "dnssec bogus");
}

test "error responses preserve query CD and DO policy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2502, "example.com.", true);
    defer query.deinit();
    query.header.checking_disabled = true;
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;

    var response = try buildNetworkErrorResponse(query);
    defer response.deinit();
    try std.testing.expect(response.header.checking_disabled);
    try std.testing.expect(response.edns.?.dnssec_ok);
    try expectEde(response, EDE_NETWORK_ERROR, "network error");

    var classic = try makeTestQuery(arena.allocator(), 0x2503, "example.com.", true);
    defer classic.deinit();
    var classic_response = try buildNetworkErrorResponse(classic);
    defer classic_response.deinit();
    try std.testing.expect(!classic_response.header.checking_disabled);
    try std.testing.expect(!classic_response.edns.?.dnssec_ok);
}

test "cookie secrets are zeroized on deinit" {
    var policy = CookiePolicy.init("current-secret", "previous-secret");
    try std.testing.expect(policy.current_len != 0);
    try std.testing.expect(policy.previous_len != 0);
    policy.deinit();
    try std.testing.expectEqual(@as(usize, 0), policy.current_len);
    try std.testing.expectEqual(@as(usize, 0), policy.previous_len);
    for (policy.current) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (policy.previous) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{ .cookies = CookiePolicy.init("current-secret", null) });
    resolver.deinit();
    try std.testing.expectEqual(@as(usize, 0), resolver.policy.cookies.current_len);
    for (resolver.policy.cookies.current) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "cookie replay window is bounded" {
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 5353);
    const other = try std.Io.net.IpAddress.parse("127.0.0.2", 5353);
    var db = CookieReplayDb{};
    var cookie: [24]u8 = undefined;
    @memset(&cookie, 0xab);
    try std.testing.expect(!db.contains(&client, &cookie));
    db.track(&client, &cookie);
    try std.testing.expect(db.contains(&client, &cookie));
    try std.testing.expect(!db.contains(&other, &cookie));

    var distinct: [MAX_COOKIE_REPLAY_ENTRIES + 1][24]u8 = undefined;
    var index: usize = 0;
    while (index < distinct.len) : (index += 1) {
        @memset(&distinct[index], 0);
        distinct[index][23] = @intCast(index);
        db.track(&client, &distinct[index]);
    }
    try std.testing.expect(!db.contains(&client, &distinct[0]));
    index = 1;
    while (index < distinct.len) : (index += 1) {
        try std.testing.expect(db.contains(&client, &distinct[index]));
    }
    db.deinit();
    try std.testing.expect(!db.contains(&client, &distinct[1]));
    try std.testing.expectEqual(@as(usize, 0), db.next);
}

test "cookie replay enforcement rejects a reused full cookie when enabled" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 5354);
    const other = try std.Io.net.IpAddress.parse("127.0.0.2", 5354);
    const client_cookie = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };

    var cookie_policy = CookiePolicy.init("current-secret", null);
    var server_cookie: [24]u8 = undefined;
    cookie_policy.makeServerCookie(&client, &client_cookie, &server_cookie);
    cookie_policy.replay_protection = true;

    var resolver = try Resolver.init(std.testing.allocator, io, .{ .cookies = cookie_policy });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2604, "example.com.", true);
    defer query.deinit();
    try setCookieOption(&query, &server_cookie);

    _ = try resolver.validateCookie(query, &client);
    try std.testing.expectError(Error.BadCookie, resolver.validateCookie(query, &client));
    // Cookies are bound to the client address, so another address fails
    // validation without touching the replay window.
    try std.testing.expectError(Error.BadCookie, resolver.validateCookie(query, &other));
    try setCookieOption(&query, &client_cookie);
    _ = try resolver.validateCookie(query, &client);
    _ = try resolver.validateCookie(query, &client);
}

test "upstream packet classification isolates validation and truncation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2606, "example.com.", false);
    defer query.deinit();

    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, 0x2606, &.{ 1, 2, 3 }, null) == .ignore);

    var truncated = try makePositiveResponse(arena.allocator(), 60);
    defer truncated.deinit();
    truncated.header.id = query.header.id;
    truncated.header.truncated = true;
    var wire: [2048]u8 = undefined;
    const truncated_bytes = try encodeTestMessage(truncated, &wire);
    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, 0x9999, truncated_bytes, null) == .ignore);
    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, query.header.id, truncated_bytes, null) == .truncated);

    var good = try makePositiveResponse(arena.allocator(), 60);
    defer good.deinit();
    good.header.id = query.header.id;
    const good_bytes = try encodeTestMessage(good, &wire);
    var ready = classifyUpstreamPacket(std.testing.allocator, query, query.header.id, good_bytes, null);
    switch (ready) {
        .ready => |*message| {
            defer message.deinit();
            try std.testing.expectEqual(query.header.id, message.header.id);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "cookie reuse stays accepted when replay protection is off" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 5355);
    const client_cookie = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };

    var cookie_policy = CookiePolicy.init("current-secret", null);
    try std.testing.expect(!cookie_policy.replay_protection);
    var server_cookie: [24]u8 = undefined;
    cookie_policy.makeServerCookie(&client, &client_cookie, &server_cookie);

    var resolver = try Resolver.init(std.testing.allocator, io, .{ .cookies = cookie_policy });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2605, "example.com.", true);
    defer query.deinit();
    try setCookieOption(&query, &server_cookie);

    _ = try resolver.validateCookie(query, &client);
    _ = try resolver.validateCookie(query, &client);
}

test "RFC 6052 section 2.2: the IPv4 address sits in the prefix as the RFC's table shows" {
    // RFC 6052 section 2.4 Table 1: the IPv4 address 192.0.2.33 in every
    // prefix form the RFC allows, byte for byte. Table 2 holds the
    // well-known prefix.
    const cases = [_]struct { prefix: []const u8, expected: [16]u8 }{
        .{ .prefix = "2001:db8::/32", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x00, 0x02, 0x21,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        } },
        .{ .prefix = "2001:db8:100::/40", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0x01, 0xc0, 0x00, 0x02,
            0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        } },
        .{ .prefix = "2001:db8:122::/48", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0x01, 0x22, 0xc0, 0x00,
            0x00, 0x02, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
        } },
        .{ .prefix = "2001:db8:122:300::/56", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0x01, 0x22, 0x03, 0xc0,
            0x00, 0x00, 0x02, 0x21, 0x00, 0x00, 0x00, 0x00,
        } },
        .{ .prefix = "2001:db8:122:344::/64", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0x01, 0x22, 0x03, 0x44,
            0x00, 0xc0, 0x00, 0x02, 0x21, 0x00, 0x00, 0x00,
        } },
        .{ .prefix = "2001:db8:122:344::/96", .expected = .{
            0x20, 0x01, 0x0d, 0xb8, 0x01, 0x22, 0x03, 0x44,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x21,
        } },
        .{ .prefix = "64:ff9b::/96", .expected = .{
            0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x21,
        } },
    };
    for (cases) |case| {
        const prefix = try config.Nat64Prefix.parse(case.prefix);
        try std.testing.expectEqualSlices(u8, &case.expected, &embedIpv4(prefix, .{ 192, 0, 2, 33 }));
    }
}

test "RFC 6147: an empty AAAA answer is answered with an AAAA synthesized from the A record" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2900, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42700);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    // RFC 6052 section 2.2: the IPv4 address sits in the last four octets of
    // the /96 prefix.
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
    // RFC 6147 section 5.1.7: the TTL is the A record's TTL.
    try std.testing.expectEqual(@as(u32, 300), response.answers.items[0].ttl);
    // The zone's SOA rides in the authority section, with the TTL RFC 2308
    // section 5 gives a negative answer.
    try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);
    try std.testing.expect(response.authorities.items[0].rrtype.eql(.SOA));
    try std.testing.expectEqual(@as(u32, 600), response.authorities.items[0].ttl);
    // The synthesized record comes from no zone: it is neither authoritative
    // nor DNSSEC-secure.
    try std.testing.expect(!response.header.authoritative);
    try std.testing.expect(!response.header.authenticated_data);
    // The upstream saw the AAAA query and the A query that followed it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6052 section 3.1: the well-known prefix does not represent a non-global address" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // The A record holds an address of the RFC 1918 private range, which the
    // Well-Known Prefix must not represent.
    const a_records = [_]dns_record.ResourceRecord{dns64TestPrivateARecord("private.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x290f, "private.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42730);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The client gets the empty answer the upstream sent: no address is
    // built in the Well-Known Prefix for a non-global IPv4 address.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    // The upstream saw the AAAA query and the A query that followed it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 7871 section 7.1.1: the DNS64 A query is fetched for the scope the AAAA query carried" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .max_cacheable_prefix = 16,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2920, "v4only.example.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42740);
    _ = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The AAAA query and the A query that followed it were fetched for one
    // scope: the client's prefix trimmed to the maximum cacheable prefix
    // length.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
    try std.testing.expectEqual(@as(usize, 6), upstream.seen_len[0]);
    try std.testing.expectEqual(@as(u8, 16), upstream.seen[0][2]);
    try std.testing.expectEqual(@as(usize, 6), upstream.seen_len[1]);
    try std.testing.expectEqual(@as(u8, 16), upstream.seen[1][2]);
    try std.testing.expectEqualSlices(u8, upstream.seen[0][0..6], upstream.seen[1][0..6]);
}

test "RFC 7871 section 7.1.1: the DNS64 A query of a client without a client subnet carries no option" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2921, "v4only.example.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42741);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // Neither query carried a scope, so neither asked for one.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
    try std.testing.expectEqual(@as(usize, 0), upstream.seen_len[0]);
    try std.testing.expectEqual(@as(usize, 0), upstream.seen_len[1]);
    // RFC 7871 section 7.2.2: a client that sent no option gets none.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expect(findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE) == null);
}

test "RFC 7871 section 7.3.1: the DNS64 answer reports the scope the synthesis rests on" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    // The upstream answers the AAAA query for the whole /24 the client asked
    // for and the A query for the /16 the address was fetched for.
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
        .aaaa_scope = 24,
        .a_scope = 16,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2922, "v4only.example.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42742);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The answer holds the address the A answer was fetched for, so it
    // reports the scope of that answer and not the one of the AAAA answer.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    const ecs = findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 7), ecs.len);
    try std.testing.expectEqual(@as(u8, 24), ecs[2]);
    try std.testing.expectEqual(@as(u8, 16), ecs[3]);
}

test "RFC 6147 section 5.1.5: an answer without an SOA is chased under the hop limit" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    // The AAAA answer carries no SOA, so the zone the chase would stay in
    // is not known: the chain is still followed, bounded by the hop limit
    // and the repeat check alone.
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x290e, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42720);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    // The A record of the queried name is synthesized into an AAAA, because
    // an answer that names no zone does not stop the chase.
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(dns_types.RecordType.AAAA.eql(response.answers.items[0].rrtype));
    // The upstream saw the AAAA query and the A query that followed it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.1: a name with a real AAAA is never synthesized over" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const aaaa_records = [_]dns_record.ResourceRecord{dns64TestAaaaRecord("dual.example.", .{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
    })};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("dual.example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2901, "dual.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42701);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    // The real AAAA is the answer, not one this server made.
    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
    }, &response.answers.items[0].rdata.AAAA);
    // No A query followed, so nothing was synthesized.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.1.4: an AAAA in an excluded range is not a real AAAA and the synthesis answers the client" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // The IPv4-mapped network ::ffff:0:0/96, the range the RFC says to
    // include in the exclusion set by default.
    const aaaa_records = [_]dns_record.ResourceRecord{dns64TestAaaaRecord("mapped.example.", .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x21,
    })};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("mapped.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2905, "mapped.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42705);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // RFC 6147 section 5.1.4: an answer that holds only an excluded AAAA
    // counts as an empty answer, so the synthesis answers the client.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    // The address the client gets is the synthesized one, not the excluded
    // AAAA the upstream sent.
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
    // The upstream saw the AAAA query and the A query that followed it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.4: the site's own prefix and the well-known prefix are excluded too" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const aaaa_records = [_]dns_record.ResourceRecord{
        // The site's own Pref64::/n, the prefix this server synthesizes into.
        dns64TestAaaaRecord("site.example.", .{
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x21,
        }),
        // The Well-Known Prefix 64:ff9b::/96 of RFC 6052 section 2.1.
        dns64TestAaaaRecord("site.example.", .{
            0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x21,
        }),
    };
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("site.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("2001:db8:64::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2906, "site.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42706);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // Both excluded AAAA records are gone and the synthesis answers the
    // client with the address in the site's own prefix.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x64, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.4: a real AAAA beside an excluded one is the answer and the excluded one is dropped" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const aaaa_records = [_]dns_record.ResourceRecord{
        dns64TestAaaaRecord("mixed.example.", .{
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
        }),
        dns64TestAaaaRecord("mixed.example.", .{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x21,
        }),
    };
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("mixed.example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2907, "mixed.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42707);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The real AAAA is the answer and the excluded one is not returned.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
    }, &response.answers.items[0].rdata.AAAA);
    // A real AAAA means no synthesis, so no A query followed.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "a forwarder without a NAT64 prefix never synthesizes and asks the upstream once" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2902, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42702);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    // The empty answer the upstream sent is the answer, unchanged.
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);
    try std.testing.expect(response.authorities.items[0].rrtype.eql(.SOA));
    // No prefix means no A query: the upstream saw the AAAA query only.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.1.4: an AAAA in a range the operator excluded is not a real AAAA" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // The range the operator excluded, 2001:db8:1::/48.
    const aaaa_records = [_]dns_record.ResourceRecord{dns64TestAaaaRecord("excluded.example.", .{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    })};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("excluded.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .dns64_excluded = .init(&.{try config.Cidr.parse("2001:db8:1::/48")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2909, "excluded.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42709);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // RFC 6147 section 5.1.4: an answer that holds only an excluded AAAA
    // counts as an empty answer, so the synthesis answers the client.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.4: an AAAA outside every excluded range is still a real AAAA" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const aaaa_records = [_]dns_record.ResourceRecord{dns64TestAaaaRecord("real.example.", .{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
    })};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("real.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .aaaa = &aaaa_records,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .dns64_excluded = .init(&.{try config.Cidr.parse("2001:db8:1::/48")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x290a, "real.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42710);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The real AAAA is the answer, and no A query followed it.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
    }, &response.answers.items[0].rdata.AAAA);
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.1.7: the prefix that serves the IPv4 address builds the AAAA" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    // The well-known prefix serves every IPv4 address, the other prefix
    // serves the range 93.184.216.0/24, which holds the A record's address.
    var bound = try config.Nat64Prefix.parse("2001:db8:100::/96");
    bound.range = try config.Cidr.parse("93.184.216.0/24");
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{ try config.Nat64Prefix.parse("64:ff9b::/96"), bound }),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x290b, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42711);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The more specific range wins, so the address carries 2001:db8:100::.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
}

test "RFC 6147 section 5.1.2: an error RCODE counts as an empty answer and the synthesis answers the client" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
        .rcode = .servfail,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2903, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42703);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // RFC 6147 section 5.1.2: the error RCODE is treated as though the
    // answer were empty, so the A query followed and the client gets the
    // synthesized answer, not the error.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[0].rdata.AAAA);
    // The upstream saw the AAAA query and the A query that followed it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.2: an NXDOMAIN is relayed as the error it is" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .rcode = .nxdomain,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2904, "v4only.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42704);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The name error is the answer the client gets, and no A query follows.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.1.5: the synthesis follows a CNAME to the owner that holds the A records" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const cname_records = [_]dns_record.ResourceRecord{dns64TestCnameRecord("alias.example.", "target.example.")};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("target.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    const entries = [_]Dns64AliasEntry{
        .{ .name = "alias.example.", .qtype = .AAAA, .answers = &cname_records },
        .{ .name = "target.example.", .qtype = .A, .answers = &a_records },
    };
    var upstream = Dns64AliasUpstream{
        .io = io,
        .udp = &upstream_socket,
        .entries = &entries,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64AliasUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2908, "alias.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42708);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    // RFC 6147 section 5.1.5: the chain stays in the answer section, next to
    // the synthesized AAAA.
    try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.CNAME));
    try std.testing.expect(response.answers.items[1].rrtype.eql(.AAAA));
    // RFC 6147 section 5.1.7: the synthetic record carries the A record's
    // owner name, so the answer names the host the alias points at.
    var text_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings("target.example.", try response.answers.items[1].owner.toText(&text_buffer));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[1].rdata.AAAA);
    // The upstream saw the AAAA query and the A query for the final owner.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.5: the synthesis follows a DNAME to the substituted owner" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // RFC 6672 section 3.1: the answer holds the DNAME and the CNAME the
    // substitution adds.
    const dname_records = [_]dns_record.ResourceRecord{
        dns64TestDnameRecord("old.example.", "new.example."),
        dns64TestCnameRecord("www.old.example.", "www.new.example."),
    };
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("www.new.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    const entries = [_]Dns64AliasEntry{
        .{ .name = "www.old.example.", .qtype = .AAAA, .answers = &dname_records },
        .{ .name = "www.new.example.", .qtype = .A, .answers = &a_records },
    };
    var upstream = Dns64AliasUpstream{
        .io = io,
        .udp = &upstream_socket,
        .entries = &entries,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64AliasUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2909, "www.old.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42709);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 3), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.DNAME));
    try std.testing.expect(response.answers.items[1].rrtype.eql(.CNAME));
    try std.testing.expect(response.answers.items[2].rrtype.eql(.AAAA));
    // The synthetic record carries the A record's owner name, which is the
    // name the DNAME substituted.
    var text_buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.new.example.", try response.answers.items[2].owner.toText(&text_buffer));
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
    }, &response.answers.items[2].rdata.AAAA);
    // The upstream saw the AAAA query and the A query for the substituted
    // owner.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.1.5: a CNAME loop stops the synthesis and asks the upstream once" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const cname_records = [_]dns_record.ResourceRecord{
        dns64TestCnameRecord("loop.example.", "other.example."),
        dns64TestCnameRecord("other.example.", "loop.example."),
    };
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    const entries = [_]Dns64AliasEntry{
        .{ .name = "loop.example.", .qtype = .AAAA, .answers = &cname_records },
    };
    var upstream = Dns64AliasUpstream{
        .io = io,
        .udp = &upstream_socket,
        .entries = &entries,
        .soa = &soa_records,
        .max_requests = 1,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64AliasUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x290a, "loop.example.", false);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42710);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The chain loops, so the synthesis stops and the answer is the
    // upstream's own: no A record was fetched and no AAAA was made.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(@as(u16, 2), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.CNAME));
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.5: a bogus A answer is never synthesized from" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // The A answer is for a name the trust anchor covers, and it carries no
    // signature: inside the trust domain that is a validation failure.
    const cname_records = [_]dns_record.ResourceRecord{dns64TestCnameRecord("alias.other.test.", "target.example.")};
    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("target.example.")};
    const entries = [_]Dns64AliasEntry{
        .{ .name = "alias.other.test.", .qtype = .AAAA, .answers = &cname_records },
        .{ .name = "target.example.", .qtype = .A, .answers = &a_records },
    };
    var upstream = Dns64AliasUpstream{
        .io = io,
        .udp = &upstream_socket,
        .entries = &entries,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64AliasUpstream, .{&upstream});

    const anchors = try validate.Anchors.parse(std.testing.allocator,
        \\target.example. DS 60485 8 2 aabbccdd
        \\
    );
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .anchors = anchors,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2940, "alias.other.test.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    // The client asks for the proofs, so this server validates the answers.
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42740);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    // RFC 6147 section 5.5: the data does not validate, so the client gets
    // SERVFAIL and no synthesized record.
    try std.testing.expectEqual(dns_header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try expectEde(response, EDE_RRSIGS_MISSING, "rrsigs missing");
    // The upstream saw the AAAA query and the A query behind it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.5: a validating resolver synthesizes from an answer that validates" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    // The anchor speaks for another zone, so the answer is outside the trust
    // domain: the validator accepts it and the synthesis goes on.
    const anchors = try validate.Anchors.parse(std.testing.allocator,
        \\other.test. DS 60485 8 2 aabbccdd
        \\
    );
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .anchors = anchors,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2941, "v4only.example.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42741);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    // The synthesized record comes from no zone: it is neither authoritative
    // nor DNSSEC-secure, and it carries no signature.
    try std.testing.expect(!response.header.authoritative);
    try std.testing.expect(!response.header.authenticated_data);
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.5: a resolver with no trust anchor synthesizes without validating" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    // No trust anchor: this server validates nothing, so the synthesis runs
    // on the answer the upstream sent.
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2942, "v4only.example.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42742);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expect(response.answers.items[0].rrtype.eql(.AAAA));
    try std.testing.expect(!response.header.authenticated_data);
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

test "RFC 6147 section 5.5: a bogus negative AAAA answer is not synthesized over" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.com.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.com.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    const anchors = try validate.Anchors.parse(std.testing.allocator,
        \\example.com. DS 60485 8 2 aabbccdd
        \\
    );
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .anchors = anchors,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2943, "v4only.example.com.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    query.edns.?.dnssec_ok = true;
    query.additionals.items[0].ttl |= 0x8000;
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42743);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    // The negative AAAA answer is validated before the A query follows it,
    // and a negative answer that does not validate ends the answer there.
    try std.testing.expectEqual(dns_header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try expectEde(response, EDE_RRSIGS_MISSING, "rrsigs missing");
    // The upstream saw the AAAA query and no A query behind it.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 6147 section 5.5: the negative answer is validated without the client's DO bit" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    const a_records = [_]dns_record.ResourceRecord{dns64TestARecord("v4only.example.com.")};
    const soa_records = [_]dns_record.ResourceRecord{dns64TestSoaRecord("example.com.")};
    var upstream = Dns64Upstream{
        .io = io,
        .udp = &upstream_socket,
        .a = &a_records,
        .soa = &soa_records,
    };
    const thread = try std.Thread.spawn(.{}, serveDns64Upstream, .{&upstream});

    const anchors = try validate.Anchors.parse(std.testing.allocator,
        \\example.com. DS 60485 8 2 aabbccdd
        \\
    );
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .nat64_prefixes = .init(&.{try config.Nat64Prefix.parse("64:ff9b::/96")}),
        .anchors = anchors,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2944, "v4only.example.com.", true);
    defer query.deinit();
    query.question.?.qtype = .AAAA;
    // The client did not ask for the proofs. The DO bit decides what the
    // client gets back, not whether the answer is validated.
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42744);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    // RFC 6147 section 5.5: the negative AAAA answer does not validate, so
    // the client gets SERVFAIL and no synthesized record.
    try std.testing.expectEqual(dns_header.Rcode.servfail, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), response.header.answer_count);
    try expectEde(response, EDE_RRSIGS_MISSING, "rrsigs missing");
    // The upstream saw the AAAA query and no A query behind it.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

/// The fake upstream a DNS64 test forwards to. It answers the AAAA query and
/// the A query that may follow it.
const Dns64Upstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    /// The answer to the AAAA query.
    aaaa: []const dns_record.ResourceRecord = &.{},
    /// The answer to the A query.
    a: []const dns_record.ResourceRecord = &.{},
    /// The SOA the AAAA answer carries in its authority section.
    soa: []const dns_record.ResourceRecord = &.{},
    /// The RCODE the AAAA answer carries (RFC 6147 section 5.1.2).
    rcode: dns_header.Rcode = .no_error,
    requests: usize = 0,
    /// The client subnet option each query carried, so a test can tell which
    /// scope every query was fetched for.
    seen: [2][4 + 16]u8 = .{ @splat(0), @splat(0) },
    seen_len: [2]usize = .{ 0, 0 },
    /// The scope the upstream answers the AAAA query with, and the scope it
    /// answers the A query with. Null means the answer carries no option.
    aaaa_scope: ?u8 = null,
    a_scope: ?u8 = null,
};

const Dns64Timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromSeconds(2),
    .clock = .awake,
} };

fn serveDns64Upstream(args: *Dns64Upstream) void {
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, Dns64Timeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        const question = query.question orelse return;
        if (index < args.seen.len) {
            if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |option| {
                const len = @min(option.len, args.seen[index].len);
                @memcpy(args.seen[index][0..len], option[0..len]);
                args.seen_len[index] = len;
            }
        }
        const answers = if (question.qtype.eql(.AAAA)) args.aaaa else args.a;
        var soa_slot: [1]dns_record.ResourceRecord = undefined;
        var authority: []const dns_record.ResourceRecord = &.{};
        if (question.qtype.eql(.AAAA) and args.soa.len != 0) {
            soa_slot[0] = args.soa[0];
            authority = soa_slot[0..1];
        }
        const rcode = if (question.qtype.eql(.AAAA)) args.rcode else .no_error;
        // RFC 7871 section 6: an answer that carries the client subnet
        // option states the scope it covers in its SCOPE PREFIX-LENGTH.
        var echoed: [4 + 16]u8 = @splat(0);
        var ecs: ?[]const u8 = null;
        const scope = if (question.qtype.eql(.AAAA)) args.aaaa_scope else args.a_scope;
        if (scope) |value| {
            if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |option| {
                const len = @min(option.len, echoed.len);
                @memcpy(echoed[0..len], option[0..len]);
                echoed[3] = value;
                ecs = echoed[0..len];
            }
        }
        var response_buffer: [2048]u8 = undefined;
        const bytes = buildDns64UpstreamAnswer(&response_buffer, query, answers, authority, rcode, ecs) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

/// A response that answers the question the upstream was asked.
fn buildDns64UpstreamAnswer(
    buffer: []u8,
    query: dns_message.Message,
    answers: []const dns_record.ResourceRecord,
    authority: []const dns_record.ResourceRecord,
    rcode: dns_header.Rcode,
    ecs: ?[]const u8,
) ![]const u8 {
    var message = dns_message.Message{
        .allocator = query.allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .recursion_desired = query.header.recursion_desired,
            .recursion_available = true,
            .rcode = rcode,
            .question_count = 1,
        },
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    defer message.deinit();
    for (answers) |record| try message.answers.append(record);
    for (authority) |record| try message.authorities.append(record);
    message.header.answer_count = @intCast(message.answers.len);
    message.header.authority_count = @intCast(message.authorities.len);
    if (ecs) |option| {
        try appendOpt(&message, query.edns.?);
        try appendOption(&message, dns_rdata.EDNS_ECS_OPTION_CODE, option);
    }
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

/// The fake upstream a DNS64 alias test forwards to. It answers each
/// question with the records the test set for that name and type.
const Dns64AliasUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    /// The answers, one per question the test asks.
    entries: []const Dns64AliasEntry,
    /// The SOA the AAAA answer carries in its authority section.
    soa: []const dns_record.ResourceRecord = &.{},
    /// The number of queries the fake answers before it stops.
    max_requests: usize = 2,
    requests: usize = 0,
};

const Dns64AliasEntry = struct {
    name: []const u8,
    qtype: dns_types.RecordType,
    answers: []const dns_record.ResourceRecord,
};

fn serveDns64AliasUpstream(args: *Dns64AliasUpstream) void {
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var index: usize = 0;
    while (index < args.max_requests) : (index += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, Dns64Timeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        const question = query.question orelse return;
        var name_buffer: [256]u8 = undefined;
        const name_text = question.name.toText(&name_buffer) catch return;
        var answers: []const dns_record.ResourceRecord = &.{};
        for (args.entries) |entry| {
            if (!entry.qtype.eql(question.qtype)) continue;
            if (!std.ascii.eqlIgnoreCase(entry.name, name_text)) continue;
            answers = entry.answers;
            break;
        }
        var soa_slot: [1]dns_record.ResourceRecord = undefined;
        var authority: []const dns_record.ResourceRecord = &.{};
        if (question.qtype.eql(.AAAA) and args.soa.len != 0) {
            soa_slot[0] = args.soa[0];
            authority = soa_slot[0..1];
        }
        var response_buffer: [2048]u8 = undefined;
        const bytes = buildDns64UpstreamAnswer(&response_buffer, query, answers, authority, .no_error, null) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

fn dns64TestARecord(name_text: []const u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(name_text) catch unreachable,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        // The address is a global one: RFC 6052 section 3.1 keeps the
        // non-global ranges out of the Well-Known Prefix.
        .rdata = .{ .A = .{ 93, 184, 216, 34 } },
    };
}

/// An A record of an address of the RFC 1918 private range, which the
/// Well-Known Prefix must not represent.
fn dns64TestPrivateARecord(name_text: []const u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(name_text) catch unreachable,
        .rrtype = .A,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .A = .{ 10, 0, 0, 1 } },
    };
}

fn dns64TestAaaaRecord(name_text: []const u8, address: [16]u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(name_text) catch unreachable,
        .rrtype = .AAAA,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .AAAA = address },
    };
}

fn dns64TestCnameRecord(owner_text: []const u8, target_text: []const u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(owner_text) catch unreachable,
        .rrtype = .CNAME,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .CNAME = dns_name.Name.fromText(target_text) catch unreachable },
    };
}

fn dns64TestDnameRecord(owner_text: []const u8, target_text: []const u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(owner_text) catch unreachable,
        .rrtype = .DNAME,
        .class = .IN,
        .ttl = 300,
        .rdata = .{ .DNAME = dns_name.Name.fromText(target_text) catch unreachable },
    };
}

fn dns64TestSoaRecord(name_text: []const u8) dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromText(name_text) catch unreachable,
        .rrtype = .SOA,
        .class = .IN,
        .ttl = 3600,
        .rdata = .{ .SOA = .{
            .mname = dns_name.Name.fromText("ns.example.") catch unreachable,
            .rname = dns_name.Name.fromText("hostmaster.example.") catch unreachable,
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = 600,
        } },
    };
}

/// The fake upstream a failure-cache test forwards to. It answers every
/// query with the same failure and counts the queries it received.
const FailingUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    rcode: dns_header.Rcode,
    requests: usize = 0,
};

/// Long enough for a second upstream query to arrive, short enough that the
/// test does not wait for one when the cache answers instead.
const FailingUpstreamTimeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(500),
    .clock = .awake,
} };

fn serveFailingUpstream(args: *FailingUpstream) void {
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, FailingUpstreamTimeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        var response_buffer: [512]u8 = undefined;
        const bytes = buildFailingUpstreamAnswer(&response_buffer, query, args.rcode) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

/// The fake upstream a validation-failure test forwards to. It answers every
/// query with an unsigned A record, which inside the trust domain is a
/// validation failure (RFC 4035 section 5.5), and counts the queries it
/// received.
const UnsignedUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    requests: usize = 0,
};

fn serveUnsignedUpstream(args: *UnsignedUpstream) void {
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, FailingUpstreamTimeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        var response_buffer: [512]u8 = undefined;
        const bytes = buildUnsignedUpstreamAnswer(&response_buffer, query) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

/// The answer the upstream sends: the A record the client asked for, with no
/// signature over it.
fn buildUnsignedUpstreamAnswer(buffer: []u8, query: dns_message.Message) ![]const u8 {
    const question = query.question orelse return Error.BadUpstreamResponse;
    var message = dns_message.Message{
        .allocator = query.allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .recursion_desired = true,
            .recursion_available = true,
            .question_count = 1,
        },
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    defer message.deinit();
    try message.answers.append(.{
        .owner = question.name,
        .rrtype = .A,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    });
    message.header.answer_count = 1;
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

/// A response that fails the question the upstream was asked.
fn buildFailingUpstreamAnswer(buffer: []u8, query: dns_message.Message, rcode: dns_header.Rcode) ![]const u8 {
    var message = dns_message.Message{
        .allocator = query.allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .recursion_desired = true,
            .recursion_available = true,
            .rcode = rcode,
            .question_count = 1,
        },
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    defer message.deinit();
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

test "RFC 9520 section 3.2: a SERVFAIL is answered from the cache without a second upstream query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = FailingUpstream{ .io = io, .udp = &upstream_socket, .rcode = .servfail };
    const thread = try std.Thread.spawn(.{}, serveFailingUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2910, "fail.example.", true);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42710);

    const first = try resolver.answer(encoded, query, &client, &output);
    const first_message = try dns_message.Message.parse(arena.allocator(), first);
    try std.testing.expectEqual(dns_header.Rcode.servfail, first_message.header.rcode);

    // The same question again: the failure is in the cache, so no second
    // query goes upstream.
    const second = try resolver.answer(encoded, query, &client, &output);
    const second_message = try dns_message.Message.parse(arena.allocator(), second);
    try std.testing.expectEqual(dns_header.Rcode.servfail, second_message.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), second_message.header.answer_count);
    try std.testing.expect(!second_message.header.authenticated_data);

    thread.join();
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
}

test "RFC 9520 section 3.2: a cached failure is answered as the failure it is" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{});
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2911, "fail.example.", true);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    // Every failure keeps its own RCODE: a failure is a failure, never an
    // NXDOMAIN, never a NODATA, and never an authenticated answer.
    for ([_]dns_header.Rcode{ .servfail, .refused, .formerr }) |rcode| {
        cache.failures.put(key, .{ .rcode = rcode, .ede = EDE_NETWORK_ERROR }, 1000);
        const failure = cache.failures.lookup(&key, 1001).?;
        const bytes = try resolver.failureResponse(query, failure, &output);
        const message = try dns_message.Message.parse(arena.allocator(), bytes);
        try std.testing.expectEqual(rcode, message.header.rcode);
        try std.testing.expectEqual(@as(u16, 0), message.header.answer_count);
        try std.testing.expectEqual(@as(u16, 0), message.header.authority_count);
        try std.testing.expect(!message.header.authenticated_data);
        // The RFC 8914 code the fresh failure carried rides along as well.
        try expectEde(message, EDE_NETWORK_ERROR, "network error");
    }
}

test "RFC 9520 section 3.2: a cached failure expires at the maximum cache time" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2912, "fail.example.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, config.FAILURE_CACHE_MAX_SECONDS);
    defer cache.deinit();
    cache.failures.put(key, .{ .rcode = .servfail }, 1000);

    // The failure lives exactly as long as the RFC's five minutes allow.
    try std.testing.expect(cache.failures.lookup(&key, 1000 + config.FAILURE_CACHE_MAX_SECONDS - 1) != null);
    try std.testing.expect(cache.failures.lookup(&key, 1000 + config.FAILURE_CACHE_MAX_SECONDS) == null);
}

test "RFC 9520 section 3.2: a failure that keeps repeating is held longer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2914, "fail.example.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();

    // The first failure of the question is held for the operator's minimum.
    cache.failures.put(key, .{ .rcode = .servfail }, 1000);
    try std.testing.expect(cache.failures.lookup(&key, 1000 + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS) - 1) != null);
    try std.testing.expect(cache.failures.lookup(&key, 1000 + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS)) == null);

    // The second failure of the same question is held twice as long.
    cache.failures.put(key, .{ .rcode = .servfail }, 2000);
    try std.testing.expect(cache.failures.lookup(&key, 2000 + 2 * @as(i64, DEFAULT_FAILURE_CACHE_SECONDS) - 1) != null);
    try std.testing.expect(cache.failures.lookup(&key, 2000 + 2 * @as(i64, DEFAULT_FAILURE_CACHE_SECONDS)) == null);
}

test "RFC 9520 section 3.2: the backoff never holds a failure past the five-minute ceiling" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2915, "fail.example.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    const ceiling: i64 = config.FAILURE_CACHE_MAX_SECONDS;

    var now: i64 = 1000;
    var index: usize = 0;
    while (index < 10) : (index += 1) {
        cache.failures.put(key, .{ .rcode = .servfail }, now);
        // No failure is ever held past the RFC's five-minute ceiling.
        try std.testing.expect(cache.failures.lookup(&key, now + ceiling) == null);
        now += ceiling;
    }
    // The ceiling is reached: the last failure is held for all of it.
    try std.testing.expect(cache.failures.lookup(&key, now - 1) != null);
}

test "RFC 9520 section 3.2: a question that resolves again forgets its failure count" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = UnsignedUpstream{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveUnsignedUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2916, "fail.example.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42714);

    // A failure of the question that has already expired.
    resolver.cache.failures.put(key, .{ .rcode = .servfail }, -100);

    // The exchange succeeds now, so the failure count is forgotten.
    const answer = try resolver.answer(encoded, query, &client, &output);
    const message = try dns_message.Message.parse(arena.allocator(), answer);
    try std.testing.expectEqual(dns_header.Rcode.no_error, message.header.rcode);

    // The next failure of the question is held for the operator's minimum
    // again, not for the longer time a repeated failure is held.
    const now: i64 = @intCast(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    resolver.cache.failures.put(key, .{ .rcode = .servfail }, now);
    try std.testing.expect(resolver.cache.failures.lookup(&key, now + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS) - 1) != null);
    try std.testing.expect(resolver.cache.failures.lookup(&key, now + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS)) == null);

    thread.join();
}

test "RFC 9520 section 3.2: the failure cache keeps the answer cache's own bounds" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var query = try makeTestQuery(arena.allocator(), 0x2913, "answer.example.", false);
    defer query.deinit();
    var response = try makePositiveResponse(arena.allocator(), 60);
    defer response.deinit();
    const key = try CacheKey.fromQuestion(query);
    try cache.put(key, &response, 1000, 0);

    // A full table of failures leaves the answer cache alone.
    var name_buffer: [32]u8 = undefined;
    var index: usize = 0;
    while (index < MAX_FAILURE_CACHE_ENTRIES) : (index += 1) {
        const name_text = try std.fmt.bufPrint(&name_buffer, "fail{d}.example.", .{index});
        var failure_query = try makeTestQuery(arena.allocator(), @intCast(0x2920 + index), name_text, false);
        defer failure_query.deinit();
        const failure_key = try CacheKey.fromQuestion(failure_query);
        cache.failures.put(failure_key, .{ .rcode = .servfail }, 1000);
    }
    try std.testing.expectEqual(MAX_FAILURE_CACHE_ENTRIES, cache.failures.len);
    try std.testing.expectEqual(@as(usize, 1), cache.len);
    const hit = (try cache.lookup(&key, query, 1001, &output, false)).?;
    try std.testing.expect(!hit.stale);
}

/// A validating resolver in front of a fake upstream that answers with an
/// unsigned record, which inside the trust domain is a validation failure.
const ValidationFixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    upstream_socket: std.Io.net.Socket,
    upstream: UnsignedUpstream,
    thread: std.Thread,
    resolver: Resolver,
    arena: std.heap.ArenaAllocator,
    query: dns_message.Message,
    query_bytes: [1024]u8 = undefined,
    encoded: []const u8 = &.{},

    fn create(io: std.Io) !*ValidationFixture {
        const allocator = std.testing.allocator;
        const self = try allocator.create(ValidationFixture);
        errdefer allocator.destroy(self);
        var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.* = .{
            .allocator = allocator,
            .io = io,
            .upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp }),
            .upstream = .{ .io = io, .udp = undefined },
            .thread = undefined,
            .resolver = undefined,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .query = undefined,
        };
        errdefer self.upstream_socket.close(io);
        errdefer self.arena.deinit();
        self.upstream.udp = &self.upstream_socket;
        self.thread = try std.Thread.spawn(.{}, serveUnsignedUpstream, .{&self.upstream});
        errdefer self.thread.join();

        // A DS anchor for the zone the question is in: an unsigned answer
        // there is a validation failure, not an insecure answer.
        var anchors = try validate.Anchors.parse(allocator,
            \\example.com. DS 60485 8 2 aabbccdd
            \\
        );
        var anchors_owned = false;
        errdefer if (!anchors_owned) anchors.deinit(allocator);
        self.resolver = try Resolver.init(allocator, io, .{
            .forwarder = .{ .address = self.upstream_socket.address },
            .anchors = anchors,
        });
        // The resolver owns the anchors now.
        anchors_owned = true;
        errdefer self.resolver.deinit();

        self.query = try makeTestQuery(self.arena.allocator(), 0x2930, "example.com.", true);
        errdefer self.query.deinit();
        // The client asks for the proofs, so this server validates the answer.
        self.query.edns.?.dnssec_ok = true;
        self.encoded = try encodeTestMessage(self.query, &self.query_bytes);
        return self;
    }

    fn destroy(self: *ValidationFixture) void {
        self.thread.join();
        self.upstream_socket.close(self.io);
        self.resolver.deinit();
        self.query.deinit();
        self.arena.deinit();
        self.allocator.destroy(self);
    }

    /// The unix second the clock reads now.
    fn now(self: *const ValidationFixture) i64 {
        return @intCast(@divTrunc(std.Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s));
    }
};

test "RFC 9520 section 3.4: a validation failure is cached and answered without a second upstream query" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try ValidationFixture.create(io);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42711);

    const first = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const first_message = try dns_message.Message.parse(fixture.arena.allocator(), first);
    try std.testing.expectEqual(dns_header.Rcode.servfail, first_message.header.rcode);
    // The RFC 8914 code the validator produced rides along with it.
    try expectEde(first_message, EDE_RRSIGS_MISSING, "rrsigs missing");

    // The same question again: the validation failure is in the cache, so no
    // second query goes upstream and the client sees the same failure.
    const second = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const second_message = try dns_message.Message.parse(fixture.arena.allocator(), second);
    try std.testing.expectEqual(dns_header.Rcode.servfail, second_message.header.rcode);
    try expectEde(second_message, EDE_RRSIGS_MISSING, "rrsigs missing");

    try std.testing.expectEqual(@as(usize, 1), fixture.upstream.requests);
}

test "RFC 9520 section 3.4: a cached validation failure is answered as the failure it is" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try ValidationFixture.create(io);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42712);

    _ = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const cached = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), cached);

    // A cached validation failure is a failure: never an NXDOMAIN, never a
    // NODATA, and never an authenticated answer.
    try std.testing.expectEqual(dns_header.Rcode.servfail, message.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), message.header.answer_count);
    try std.testing.expectEqual(@as(u16, 0), message.header.authority_count);
    try std.testing.expect(!message.header.authenticated_data);

    // The failure is in the failure cache, and it never enters the answer
    // cache.
    const key = try CacheKey.fromQuestion(fixture.query);
    try std.testing.expect(fixture.resolver.cache.failures.lookup(&key, fixture.now()) != null);
    try std.testing.expect((try fixture.resolver.cache.lookup(&key, fixture.query, fixture.now(), &output, false)) == null);
}

test "RFC 9520 section 3.4: a cached validation failure expires like every other failure" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try ValidationFixture.create(io);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42713);

    const before = fixture.now();
    _ = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const after = fixture.now();
    const key = try CacheKey.fromQuestion(fixture.query);

    // The failure lives exactly as long as any other cached failure: the
    // operator's `minimum-failure-cache-time` seconds.
    try std.testing.expect(fixture.resolver.cache.failures.lookup(&key, before + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS) - 1) != null);
    try std.testing.expect(fixture.resolver.cache.failures.lookup(&key, after + @as(i64, DEFAULT_FAILURE_CACHE_SECONDS)) == null);
}

test "RFC 1035 section 4.1.1: the upstream query never carries the reserved Z bit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query = try makeTestQuery(arena.allocator(), 0x2718, "example.com.", false);
    defer query.deinit();

    var original_bytes: [512]u8 = undefined;
    const original = try encodeTestMessage(query, &original_bytes);
    // A client that sets the reserved Z bit in its own header.
    var raw: [512]u8 = undefined;
    @memcpy(raw[0..original.len], original);
    raw[3] |= 0x40;
    try std.testing.expectEqual(@as(u8, 0x40), raw[3] & 0x40);

    var output: [512]u8 = undefined;
    const composed = try buildUpstreamQuery(raw[0..original.len], query, &output, &.{}, null);
    // RFC 1035 section 4.1.1: the Z bit must be zero in all queries.
    try std.testing.expectEqual(@as(u8, 0), composed[3] & 0x40);
}

test "RFC 1035 section 2.3.3: the NXDOMAIN cut ignores the case of the ancestor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator, DEFAULT_FAILURE_CACHE_SECONDS);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var denied = try makeTestQuery(arena.allocator(), 0x2850, "a.example.", false);
    defer denied.deinit();
    var denial = try makeNxdomainResponse(arena.allocator(), "a.example.", 60, 30);
    defer denial.deinit();
    const denied_key = try CacheKey.fromQuestion(denied);
    try cache.put(denied_key, &denial, 1000, 0);

    // The descendant spells the ancestor in another case, which names the
    // same node: the cut applies.
    var child = try makeTestQuery(arena.allocator(), 0x2851, "b.a.example.", false);
    defer child.deinit();
    child.question.?.name = (try dns_name.Name.parsePreservingCase(
        &.{ 1, 'b', 1, 'A', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 },
        0,
    )).name;
    const child_key = try CacheKey.fromQuestion(child);
    const cut = (try cache.lookup(&child_key, child, 1000, &output, false)).?;
    const cut_message = try dns_message.Message.parse(arena.allocator(), cut.bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, cut_message.header.rcode);
    try std.testing.expectEqual(@as(u16, 0), cut_message.header.answer_count);
}

/// The shape the fake upstream answers with.
const UpstreamShape = enum {
    /// An answer whose additional section holds records inside and outside
    /// the domain of the query.
    answer,
    /// An answer whose authority section holds a record inside and outside
    /// the domain of the query.
    answer_with_authority,
    /// A negative answer whose authority section holds the zone SOA beside a
    /// record for an unrelated name.
    negative_answer,
    /// A referral whose glue names a name server inside the zone the
    /// delegation names.
    referral,
    /// A referral whose glue names a name server outside that zone.
    referral_out_of_zone,
    /// A referral for a zone the query is not about.
    referral_out_of_domain,
};

/// The fake upstream the in-domain tests forward to. Its answer carries an
/// additional section with a record for a name that has nothing to do with
/// the query beside records for names in the domain of the query. A referral
/// answers with the NS record of the delegated zone in the authority section
/// and the glue of its name server in the additional section, beside records
/// that are not the glue of that delegation.
const AdditionalUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    requests: usize = 0,
    shape: UpstreamShape = .answer,
};

fn serveAdditionalUpstream(args: *AdditionalUpstream) void {
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, FailingUpstreamTimeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        var response_buffer: [512]u8 = undefined;
        const bytes = buildAdditionalUpstreamAnswer(&response_buffer, query, args.shape) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

/// The answer the upstream sends: the A record the client asked for, and an
/// additional section that holds a record for an unrelated name beside
/// records for the query name and for a name below it. The shape with an
/// authority section adds to it a record for the query name and one for an
/// unrelated name. A negative answer instead carries the zone SOA in the
/// authority section beside a record for an unrelated name. A referral
/// carries the NS record of the delegated zone in the authority section and
/// the glue of its name server in the additional section, beside a record for
/// the query name and one for an unrelated name.
fn buildAdditionalUpstreamAnswer(buffer: []u8, query: dns_message.Message, shape: UpstreamShape) ![]const u8 {
    const question = query.question orelse return Error.BadUpstreamResponse;
    var message = dns_message.Message{
        .allocator = query.allocator,
        .header = .{
            .id = query.header.id,
            .qr = true,
            .recursion_desired = true,
            .recursion_available = true,
            .question_count = 1,
        },
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    defer message.deinit();
    const referral_shape = switch (shape) {
        .referral, .referral_out_of_zone, .referral_out_of_domain => true,
        else => false,
    };
    if (referral_shape) {
        // The delegation the query is about names the zone the query sits
        // in; the out-of-domain shape delegates a zone of its own.
        const zone_text = switch (shape) {
            .referral_out_of_domain => "elsewhere.example.",
            else => "example.com.",
        };
        const server_text = switch (shape) {
            .referral => "ns.example.com.",
            .referral_out_of_zone => "ns.other.example.",
            .referral_out_of_domain => "ns.elsewhere.example.",
            else => unreachable,
        };
        const server = try dns_name.Name.fromText(server_text);
        try message.authorities.append(.{
            .owner = try dns_name.Name.fromText(zone_text),
            .rrtype = .NS,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .NS = server },
        });
        message.header.authority_count = 1;
        try message.additionals.append(.{
            .owner = server,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 2 } },
        });
        // Neither the query name nor an unrelated name is the glue of the
        // delegation, so neither may be relayed with it.
        for ([_]dns_name.Name{ question.name, try dns_name.Name.fromText("mail.elsewhere.example.") }) |owner| {
            try message.additionals.append(.{
                .owner = owner,
                .rrtype = .A,
                .class = .IN,
                .ttl = 60,
                .rdata = .{ .A = .{ 192, 0, 2, 3 } },
            });
        }
        message.header.additional_count = 3;
        var writer = dns_writer.Writer.init(buffer);
        try message.encode(&writer);
        return writer.written();
    }
    if (shape == .negative_answer) {
        // A negative answer carries the zone SOA in the authority section
        // (RFC 2308 section 5). The SOA sits in a zone of its own, so it
        // survives only because it is the SOA of the negative answer, and the
        // record beside it has nothing to do with the query.
        message.header.rcode = .nxdomain;
        try message.authorities.append(.{
            .owner = try dns_name.Name.fromText("elsewhere.example."),
            .rrtype = .SOA,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .SOA = .{
                .mname = try dns_name.Name.fromText("ns.elsewhere.example."),
                .rname = try dns_name.Name.fromText("hostmaster.elsewhere.example."),
                .serial = 1,
                .refresh = 3600,
                .retry = 900,
                .expire = 1209600,
                .minimum = 60,
            } },
        });
        try message.authorities.append(.{
            .owner = try dns_name.Name.fromText("mail.elsewhere.example."),
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 4 } },
        });
        message.header.authority_count = 2;
        var writer = dns_writer.Writer.init(buffer);
        try message.encode(&writer);
        return writer.written();
    }
    try message.answers.append(.{
        .owner = question.name,
        .rrtype = .A,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    });
    message.header.answer_count = 1;
    if (shape == .answer_with_authority) {
        // The authority section holds a record for the query name, which is
        // in the domain of the query, and one for an unrelated name, which is
        // not.
        try message.authorities.append(.{
            .owner = question.name,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 4 } },
        });
        try message.authorities.append(.{
            .owner = try dns_name.Name.fromText("mail.elsewhere.example."),
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 5 } },
        });
        message.header.authority_count = 2;
    }
    for ([_][]const u8{ "mail.elsewhere.example.", "www.example.com.", "mail.www.example.com." }) |owner| {
        try message.additionals.append(.{
            .owner = try dns_name.Name.fromText(owner),
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 2 } },
        });
    }
    message.header.additional_count = 3;
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

/// A resolver in front of the fake upstream whose answer carries an
/// additional section with records inside and outside the domain of the
/// query.
const AdditionalFixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    upstream_socket: std.Io.net.Socket,
    upstream: AdditionalUpstream,
    thread: std.Thread,
    joined: bool = false,
    resolver: Resolver,
    arena: std.heap.ArenaAllocator,
    query: dns_message.Message,
    query_bytes: [1024]u8 = undefined,
    encoded: []const u8 = &.{},

    fn create(io: std.Io, shape: UpstreamShape) !*AdditionalFixture {
        const allocator = std.testing.allocator;
        const self = try allocator.create(AdditionalFixture);
        errdefer allocator.destroy(self);
        var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.* = .{
            .allocator = allocator,
            .io = io,
            .upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp }),
            .upstream = .{ .io = io, .udp = undefined, .shape = shape },
            .thread = undefined,
            .resolver = undefined,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .query = undefined,
        };
        errdefer self.upstream_socket.close(io);
        errdefer self.arena.deinit();
        self.upstream.udp = &self.upstream_socket;
        self.thread = try std.Thread.spawn(.{}, serveAdditionalUpstream, .{&self.upstream});
        errdefer self.join();
        self.resolver = try Resolver.init(allocator, io, .{
            .forwarder = .{ .address = self.upstream_socket.address },
        });
        errdefer self.resolver.deinit();
        self.query = try makeTestQuery(self.arena.allocator(), 0x2940, "www.example.com.", false);
        errdefer self.query.deinit();
        self.encoded = try encodeTestMessage(self.query, &self.query_bytes);
        return self;
    }

    /// Waits for the fake upstream to stop, so a later answer can only come
    /// from the cache.
    fn join(self: *AdditionalFixture) void {
        if (self.joined) return;
        self.thread.join();
        self.joined = true;
    }

    fn destroy(self: *AdditionalFixture) void {
        self.join();
        self.upstream_socket.close(self.io);
        self.resolver.deinit();
        self.query.deinit();
        self.arena.deinit();
        self.allocator.destroy(self);
    }
};

test "RFC 5452 section 6: an additional record outside the domain of the query is not relayed" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .answer);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42714);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // The answer section is relayed as the upstream sent it.
    try std.testing.expectEqual(@as(u16, 1), message.header.answer_count);
    // The additional section keeps the two records whose owner name is in the
    // domain of the query and drops the one that is not.
    try std.testing.expectEqual(@as(u16, 2), message.header.additional_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try message.additionals.items[0].owner.toText(&text));
    try std.testing.expectEqualStrings("mail.www.example.com.", try message.additionals.items[1].owner.toText(&text));
}

test "RFC 5452 section 6: the cached answer holds the filtered additional section" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .answer);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42715);

    _ = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    // The upstream is done, so the next client can only be answered from the
    // cache.
    fixture.join();
    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, message.header.rcode);
    try std.testing.expectEqual(@as(u16, 2), message.header.additional_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try message.additionals.items[0].owner.toText(&text));
    try std.testing.expectEqualStrings("mail.www.example.com.", try message.additionals.items[1].owner.toText(&text));
    try std.testing.expectEqual(@as(usize, 1), fixture.upstream.requests);
}

test "RFC 5452 section 6: a referral keeps only the glue of the delegation it names" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .referral);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42716);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // A referral is not an answer, but its additional section is filtered
    // too: the glue of the delegated name server is what the client follows
    // the delegation with, and the records beside it are not the glue of
    // that delegation, so they are dropped.
    try std.testing.expectEqual(@as(u16, 0), message.header.answer_count);
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    try std.testing.expectEqual(@as(u16, 1), message.header.additional_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("ns.example.com.", try message.additionals.items[0].owner.toText(&text));
}

test "RFC 5452 section 6: a referral whose glue is out of the zone keeps none of it" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .referral_out_of_zone);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42717);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // The delegation names a name server outside the zone it delegates, so
    // its glue is not the delegation's own data and none of it is relayed.
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    try std.testing.expectEqual(@as(u16, 0), message.header.additional_count);
}

test "RFC 5452 section 6: a referral for another domain keeps none of its glue" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .referral_out_of_domain);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42718);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // The delegation the authority section names is not in the domain of
    // the query, so its glue is not the query's data and none of it is
    // relayed.
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    try std.testing.expectEqual(@as(u16, 0), message.header.additional_count);
}

test "RFC 5452 section 6: an authority record outside the domain of the query is not relayed" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .answer_with_authority);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42719);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // The answer section is relayed as the upstream sent it.
    try std.testing.expectEqual(@as(u16, 1), message.header.answer_count);
    // The authority section keeps the record whose owner name is in the
    // domain of the query and drops the one that is not.
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try message.authorities.items[0].owner.toText(&text));
}

test "RFC 5452 section 6: a negative answer keeps its SOA" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .negative_answer);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42720);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // A negative answer is carried by the zone SOA (RFC 2308 section 5), so
    // the SOA survives even though its owner name is not in the domain of the
    // query, and the record beside it is dropped.
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, message.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    try std.testing.expect(dns_types.RecordType.SOA.eql(message.authorities.items[0].rrtype));
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("elsewhere.example.", try message.authorities.items[0].owner.toText(&text));
}

test "RFC 5452 section 6: the cached answer holds the filtered authority section" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .answer_with_authority);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42721);

    _ = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    // The upstream is done, so the next client can only be answered from the
    // cache.
    fixture.join();
    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, message.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try message.authorities.items[0].owner.toText(&text));
    try std.testing.expectEqual(@as(usize, 1), fixture.upstream.requests);
}

test "RFC 5452 section 6: a referral keeps the NS records of its delegation" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const fixture = try AdditionalFixture.create(io, .referral_out_of_domain);
    defer fixture.destroy();
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42722);

    const bytes = try fixture.resolver.answer(fixture.encoded, fixture.query, &client, &output);
    const message = try dns_message.Message.parse(fixture.arena.allocator(), bytes);

    // The delegation is not in the domain of the query, but the client
    // follows the delegation with the NS records the referral carries
    // (RFC 1034 section 4.3.2), so they survive, and the glue rule is
    // unchanged: a delegation the query is not about keeps none of it.
    try std.testing.expectEqual(@as(u16, 1), message.header.authority_count);
    try std.testing.expect(dns_types.RecordType.NS.eql(message.authorities.items[0].rrtype));
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("elsewhere.example.", try message.authorities.items[0].owner.toText(&text));
    try std.testing.expectEqual(@as(u16, 0), message.header.additional_count);
}

test "RFC 5452 section 6: a name in the domain of the query is the query name, an ancestor, or a descendant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response = try makeTestQuery(arena.allocator(), 0x1102, "www.example.com.", false);
    defer response.deinit();
    response.header.qr = true;

    // The additional section holds a record for the query name, one for a
    // name below it, one for a name above it, and one for a name that has
    // nothing to do with the query.
    for ([_][]const u8{ "www.example.com.", "mail.www.example.com.", "example.com.", "mail.elsewhere.example." }) |owner| {
        try response.additionals.append(.{
            .owner = try dns_name.Name.fromText(owner),
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 2 } },
        });
    }
    response.header.additional_count = 4;
    // The answer and the authority section keep the names they hold, whether
    // they are in the domain of the query or not.
    try response.answers.append(.{
        .owner = try dns_name.Name.fromText("mail.elsewhere.example."),
        .rrtype = .A,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .A = .{ 192, 0, 2, 3 } },
    });
    response.header.answer_count = 1;
    try response.authorities.append(.{
        .owner = try dns_name.Name.fromText("elsewhere.example."),
        .rrtype = .NS,
        .class = .IN,
        .ttl = 60,
        .rdata = .{ .NS = try dns_name.Name.fromText("ns.elsewhere.example.") },
    });
    response.header.authority_count = 1;

    // The query name keeps the case the client sent, and the comparison
    // ignores it (RFC 1035 section 2.3.3).
    const query_name = (try dns_name.Name.parsePreservingCase(
        &.{ 3, 'W', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 },
        0,
    )).name;
    dropOutOfDomainAdditionals(&response, query_name.asWire());

    try std.testing.expectEqual(@as(usize, 3), response.additionals.len);
    try std.testing.expectEqual(@as(u16, 3), response.header.additional_count);
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try response.additionals.items[0].owner.toText(&text));
    try std.testing.expectEqualStrings("mail.www.example.com.", try response.additionals.items[1].owner.toText(&text));
    try std.testing.expectEqualStrings("example.com.", try response.additionals.items[2].owner.toText(&text));
    try std.testing.expectEqual(@as(usize, 1), response.answers.len);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    try std.testing.expectEqual(@as(usize, 1), response.authorities.len);
    try std.testing.expectEqual(@as(u16, 1), response.header.authority_count);
}

fn makeTestQuery(allocator: std.mem.Allocator, id: u16, name_text: []const u8, with_edns: bool) !dns_message.Message {
    const name = try dns_name.Name.fromText(name_text);
    var message = dns_message.Message{
        .allocator = allocator,
        .header = .{ .id = id, .recursion_desired = true, .question_count = 1 },
        .question = .{ .name = name, .qtype = .A, .qclass = .IN },
        .answers = try dns_message.RecordSection.init(allocator, 0),
        .authorities = try dns_message.RecordSection.init(allocator, 0),
        .additionals = try dns_message.RecordSection.init(allocator, 0),
    };
    errdefer message.deinit();
    if (with_edns) {
        message.edns = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = false };
        try message.additionals.append(.{
            .owner = dns_name.Name.root(),
            .rrtype = .OPT,
            .class = dns_types.Class.fromCode(1232),
            .ttl = 0,
            .rdata = .{ .OPT = .{} },
        });
        message.header.additional_count = 1;
    }
    return message;
}

fn setCookieOption(message: *dns_message.Message, cookie: []const u8) !void {
    const option = &message.additionals.items[0].rdata.OPT;
    option.len = 0;
    try appendOption(message, COOKIE_OPTION_CODE, cookie);
}

fn encodeTestMessage(message: dns_message.Message, buffer: []u8) ![]const u8 {
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

fn makePositiveResponse(allocator: std.mem.Allocator, ttl: u32) !dns_message.Message {
    return makePositiveResponseFor(allocator, "example.com.", ttl);
}

fn makePositiveResponseFor(allocator: std.mem.Allocator, name_text: []const u8, ttl: u32) !dns_message.Message {
    var message = try makeTestQuery(allocator, 0x1100, name_text, false);
    message.header.qr = true;
    message.header.recursion_available = true;
    errdefer message.deinit();
    try message.answers.append(.{
        .owner = try dns_name.Name.fromText(name_text),
        .rrtype = .A,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    });
    message.header.answer_count = 1;
    return message;
}

fn makeNegativeResponse(allocator: std.mem.Allocator, ttl: u32, minimum: u32) !dns_message.Message {
    return makeNxdomainResponse(allocator, "missing.example.", ttl, minimum);
}

/// An NXDOMAIN answer for `name_text` whose authority section carries the
/// SOA of the zone, with the record TTL and the MINIMUM field given apart
/// so the negative TTL rule can be exercised.
fn makeNxdomainResponse(allocator: std.mem.Allocator, name_text: []const u8, ttl: u32, minimum: u32) !dns_message.Message {
    var message = try makeTestQuery(allocator, 0x1101, name_text, false);
    message.header.qr = true;
    message.header.rcode = .nxdomain;
    errdefer message.deinit();
    try message.authorities.append(.{
        .owner = try dns_name.Name.fromText("example."),
        .rrtype = .SOA,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns.example."),
            .rname = try dns_name.Name.fromText("hostmaster.example."),
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = minimum,
        } },
    });
    message.header.authority_count = 1;
    return message;
}

/// The zone SOA a negative answer carries (RFC 2308 section 3), with the
/// record TTL and the MINIMUM field given apart so the negative TTL rule
/// can be exercised.
fn makeTestSoa(ttl: u32, minimum: u32) !dns_record.ResourceRecord {
    return .{
        .owner = try dns_name.Name.fromText("example."),
        .rrtype = .SOA,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .SOA = .{
            .mname = try dns_name.Name.fromText("ns.example."),
            .rname = try dns_name.Name.fromText("hostmaster.example."),
            .serial = 1,
            .refresh = 3600,
            .retry = 900,
            .expire = 1209600,
            .minimum = minimum,
        } },
    };
}

test "RFC 5452 section 9.2: the upstream socket never binds a denied source port" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    // Every port the operating system can assign is denied, so the forwarder
    // has no source port left and sends nothing at all.
    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});
    var policy = Policy{ .forwarder = .{ .address = upstream_socket.address } };
    policy.deny_ports[0] = .{ .first = 1024, .last = 65535 };
    policy.deny_ports_len = 1;
    var resolver = try Resolver.init(std.testing.allocator, io, policy);
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2611, "example.com.", true);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42640);
    try std.testing.expectError(Error.UpstreamFailure, resolver.answer(encoded, query, &client, &output));
    thread.join();
    try std.testing.expectEqual(@as(usize, 0), upstream.requests);
}

test "RFC 5452 section 9.2: a denied port the forwarder would not use anyway changes nothing" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});
    var policy = Policy{ .forwarder = .{ .address = upstream_socket.address } };
    // Port 53 is the resolver port, not a source port of a forwarder that
    // is not the local resolver, so denying it leaves the query untouched.
    policy.deny_ports[0] = .{ .first = 53, .last = 53 };
    policy.deny_ports_len = 1;
    var resolver = try Resolver.init(std.testing.allocator, io, policy);
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2612, "example.com.", true);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42641);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
}

test "RFC 7871 section 7.1.1: the client subnet prefix is trimmed to the maximum cacheable prefix length" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket, .max_requests = 2, .answer_scope = 16 };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .max_cacheable_prefix = 16,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2613, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42642);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The upstream saw the trimmed prefix and the trimmed address.
    try std.testing.expectEqual(@as(usize, 6), upstream.seen_len);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, upstream.seen[0..2], .big));
    try std.testing.expectEqual(@as(u8, 16), upstream.seen[2]);
    try std.testing.expectEqual(@as(u8, 0), upstream.seen[3]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0 }, upstream.seen[4..6]);

    // The client learns the scope the query was actually sent with.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    const ecs = findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(usize, 6), ecs.len);
    try std.testing.expectEqual(@as(u8, 16), ecs[2]);
    try std.testing.expectEqual(@as(u8, 16), ecs[3]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0 }, ecs[4..]);
}

test "RFC 7871 section 7.3.1: a trimmed scope keys the cache, so another scope is not served from it" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = EcsUpstream{ .io = io, .udp = &upstream_socket, .max_requests = 2, .answer_scope = 16 };
    const thread = try std.Thread.spawn(.{}, serveEcsUpstream, .{&upstream});
    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
        .max_cacheable_prefix = 16,
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2614, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42643);
    _ = try resolver.answer(encoded, query, &client, &output);

    // A client in another network asks for a prefix of its own; the answer
    // cached for the first scope does not answer it.
    var other = try makeTestQuery(arena.allocator(), 0x2615, "example.com.", true);
    defer other.deinit();
    try appendOption(&other, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 198, 51, 100 });
    var other_bytes: [1024]u8 = undefined;
    const other_encoded = try encodeTestMessage(other, &other_bytes);
    _ = try resolver.answer(other_encoded, other, &client, &output);
    thread.join();
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
}

/// The fake upstream the client subnet retry tests forward to. It refuses a
/// query that carries an ADDRESS, the way a resolver with a policy against
/// forwarding it does, and it records the option of every query it saw.
const RefusingUpstream = struct {
    io: std.Io,
    udp: *const std.Io.net.Socket,
    /// The number of queries the fake answers before it stops.
    max_requests: usize = 2,
    /// The SOURCE PREFIX-LENGTH of the client subnet option of each query.
    seen_prefix: [4]u8 = @splat(0),
    /// The length of the client subnet option of each query.
    seen_len: [4]usize = @splat(0),
    requests: usize = 0,
    /// The upstream refuses the query even when it carries no ADDRESS.
    refuse_all: bool = false,
};

fn serveRefusingUpstream(args: *RefusingUpstream) void {
    const timeout: std.Io.Timeout = .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } };
    var request_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
    while (args.requests < args.max_requests) {
        const incoming = args.udp.receiveTimeout(args.io, &request_buffer, timeout) catch return;
        args.requests += 1;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const query = dns_message.Message.parseQuery(arena.allocator(), incoming.data) catch return;
        var prefix: u8 = 0;
        var option_len: usize = 0;
        if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |option| {
            option_len = option.len;
            if (option.len >= 4) prefix = option[2];
        }
        const index = args.requests - 1;
        if (index < args.seen_prefix.len) {
            args.seen_prefix[index] = prefix;
            args.seen_len[index] = option_len;
        }
        const question = query.question orelse return;
        var answer_slot: [1]dns_record.ResourceRecord = undefined;
        answer_slot[0] = .{
            .owner = question.name,
            .rrtype = .A,
            .class = .IN,
            .ttl = 60,
            .rdata = .{ .A = .{ 192, 0, 2, 1 } },
        };
        var answers: []const dns_record.ResourceRecord = &.{};
        var rcode: dns_header.Rcode = .no_error;
        if (args.refuse_all or prefix > 0) {
            rcode = .refused;
        } else {
            answers = answer_slot[0..1];
        }
        var response_buffer: [2048]u8 = undefined;
        const bytes = buildDns64UpstreamAnswer(&response_buffer, query, answers, &.{}, rcode, null) catch return;
        args.udp.send(args.io, &incoming.from, bytes) catch return;
    }
}

test "RFC 7871 section 7.1.3: a refused query with a client subnet is asked again without the address" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = RefusingUpstream{ .io = io, .udp = &upstream_socket };
    const thread = try std.Thread.spawn(.{}, serveRefusingUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2616, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42650);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The upstream was asked twice: the first query carried the address, the
    // retry carried the option with no address in it.
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
    try std.testing.expectEqual(@as(u8, 24), upstream.seen_prefix[0]);
    try std.testing.expectEqual(@as(usize, 7), upstream.seen_len[0]);
    try std.testing.expectEqual(@as(u8, 0), upstream.seen_prefix[1]);
    try std.testing.expectEqual(@as(usize, 4), upstream.seen_len[1]);

    // The client gets the answer of the retry.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.no_error, response.header.rcode);
    try std.testing.expectEqual(@as(u16, 1), response.header.answer_count);
    // RFC 7871 section 6: the answer reports the scope the upstream answered
    // with, and an answer fetched without an address covers every network.
    const ecs = findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE).?;
    try std.testing.expectEqual(@as(u8, 24), ecs[2]);
    try std.testing.expectEqual(@as(u8, 0), ecs[3]);
}

test "RFC 7871 section 7.1.3: a second refusal ends the exchange" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = RefusingUpstream{ .io = io, .udp = &upstream_socket, .refuse_all = true };
    const thread = try std.Thread.spawn(.{}, serveRefusingUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2617, "example.com.", true);
    defer query.deinit();
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &.{ 0, 1, 24, 0, 192, 0, 2 });
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42651);
    const bytes = try resolver.answer(encoded, query, &client, &output);

    // The retry is bounded: the upstream was asked twice and no more.
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.refused, response.header.rcode);

    // RFC 9520 section 3.2: the refusal is a failure, so the next client
    // for the same question is answered with it and no query goes upstream.
    const again = try resolver.answer(encoded, query, &client, &output);
    thread.join();
    try std.testing.expectEqual(@as(usize, 2), upstream.requests);
    const refusal = try dns_message.Message.parse(arena.allocator(), again);
    try std.testing.expectEqual(dns_header.Rcode.refused, refusal.header.rcode);
}

test "RFC 7871 section 7.1.3: a query without a client subnet is not retried" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var upstream_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var upstream_socket = try std.Io.net.IpAddress.bind(&upstream_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer upstream_socket.close(io);

    var upstream = RefusingUpstream{ .io = io, .udp = &upstream_socket, .refuse_all = true };
    const thread = try std.Thread.spawn(.{}, serveRefusingUpstream, .{&upstream});

    var resolver = try Resolver.init(std.testing.allocator, io, .{
        .forwarder = .{ .address = upstream_socket.address },
    });
    defer resolver.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2618, "example.com.", true);
    defer query.deinit();
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42652);
    const bytes = try resolver.answer(encoded, query, &client, &output);
    thread.join();

    // The query carried no address, so there was nothing to retry without.
    try std.testing.expectEqual(@as(usize, 1), upstream.requests);
    try std.testing.expectEqual(@as(usize, 0), upstream.seen_len[0]);
    const response = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.refused, response.header.rcode);
    try std.testing.expect(findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE) == null);
}
