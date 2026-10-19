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
const tcp_deadline = @import("platform/tcp_deadline.zig");

pub const MAX_CACHE_ENTRIES = 64;
pub const STALE_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub const STALE_TTL: u32 = 30;
pub const UDP_ATTEMPTS = 2;
pub const UDP_TIMEOUT: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(1000),
    .clock = .awake,
} };
/// One-second upstream TCP connection and I/O budget.
pub const TCP_TIMEOUT: std.Io.Timeout = UDP_TIMEOUT;
pub const MAX_UPSTREAM_MESSAGE = std.math.maxInt(u16);
pub const UPSTREAM_TCP_DEADLINES_SUPPORTED = switch (builtin.os.tag) {
    .linux, .macos => true,
    else => false,
};
pub const COOKIE_OPTION_CODE: u16 = 10;
pub const EDE_OPTION_CODE: u16 = 15;
pub const EDE_STALE_ANSWER: u16 = 3;
pub const EDE_STALE_NXDOMAIN: u16 = 22;
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
    EcsRefused,
    BadCookie,
};

pub const Endpoint = struct {
    address: std.Io.net.IpAddress,
};

pub const Policy = struct {
    recursion_allow: [32]config.Cidr = undefined,
    recursion_allow_len: usize = 0,
    forwarder: ?Endpoint = null,
    cookies: CookiePolicy = .{},

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

const CacheKey = struct {
    name: [256]u8 = undefined,
    name_len: usize = 0,
    qtype: u16 = 0,
    qclass: u16 = 0,
    checking_disabled: bool = false,
    dnssec_ok: bool = false,

    fn fromQuestion(question: dns_message.Message) !CacheKey {
        const q = question.question orelse return error.BadQuery;
        var key = CacheKey{
            .qtype = q.qtype.code(),
            .qclass = q.qclass.code(),
            .checking_disabled = question.header.checking_disabled,
            .dnssec_ok = if (question.edns) |edns| edns.dnssec_ok else false,
        };
        const name = q.name.toText(&key.name) catch return error.BadQuery;
        key.name_len = name.len;
        return key;
    }

    fn eql(self: *const CacheKey, other: *const CacheKey) bool {
        return self.qtype == other.qtype and self.qclass == other.qclass and
            self.checking_disabled == other.checking_disabled and self.dnssec_ok == other.dnssec_ok and
            std.ascii.eqlIgnoreCase(self.name[0..self.name_len], other.name[0..other.name_len]);
    }
};

const CacheEntry = struct {
    response: ?[]u8 = null,
    key: CacheKey = .{},
    stored_at: i64 = 0,
    ttl: u32 = 0,
    nxdomain: bool = false,
};

const Cache = struct {
    allocator: std.mem.Allocator,
    entries: [MAX_CACHE_ENTRIES]CacheEntry = @splat(CacheEntry{}),
    len: usize = 0,
    replacement: usize = 0,

    fn init(allocator: std.mem.Allocator) Cache {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *Cache) void {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].response) |bytes| self.allocator.free(bytes);
            self.entries[index].response = null;
        }
        self.len = 0;
    }

    fn put(self: *Cache, key: CacheKey, message: *dns_message.Message, now: i64) !void {
        if (message.header.truncated or (message.header.rcode != .no_error and message.header.rcode != .nxdomain)) return;
        const ttl_info = cacheTtl(message) orelse return;
        if (ttl_info.ttl == 0) return;
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
            .nxdomain = ttl_info.nxdomain,
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
                return null;
            }

            var message = dns_message.Message.parse(arena.allocator(), entry.response.?) catch return null;
            ageMessage(&message, @intCast(elapsed), if (fresh) null else STALE_TTL);
            message.header.id = query.header.id;
            message.header.recursion_desired = query.header.recursion_desired;
            message.header.recursion_available = true;
            message.header.checking_disabled = query.header.checking_disabled;
            message.question = query.question;
            if (query.edns != null) try appendOpt(&message, query.edns.?);
            if (!fresh) try appendEde(&message, if (entry.nxdomain) EDE_STALE_NXDOMAIN else EDE_STALE_ANSWER);
            var writer = dns_writer.Writer.init(output);
            message.encode(&writer) catch return Error.ResponseTooLarge;
            return .{ .stale = !fresh, .bytes = writer.written() };
        }
        return null;
    }
};

const LookupResult = struct {
    stale: bool,
    bytes: []const u8,
};

const TtlInfo = struct { ttl: u32, nxdomain: bool };

fn cacheTtl(message: *const dns_message.Message) ?TtlInfo {
    if (message.header.rcode == .nxdomain) {
        var ttl: ?u32 = null;
        for (message.authorities.slice()) |record| {
            if (record.rrtype.eql(.SOA)) ttl = @min(ttl orelse record.ttl, @min(record.ttl, record.rdata.SOA.minimum));
        }
        return if (ttl) |value| .{ .ttl = value, .nxdomain = true } else null;
    }
    if (message.header.answer_count == 0) {
        for (message.authorities.slice()) |record| {
            if (record.rrtype.eql(.SOA)) return .{ .ttl = @min(record.ttl, record.rdata.SOA.minimum), .nxdomain = false };
        }
        return null;
    }
    var ttl: ?u32 = null;
    for (message.answers.slice()) |record| ttl = @min(ttl orelse record.ttl, record.ttl);
    return if (ttl) |value| .{ .ttl = value, .nxdomain = false } else null;
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
            .cache = Cache.init(allocator),
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
        if (findOption(query, dns_rdata.EDNS_ECS_OPTION_CODE)) |ecs| {
            if (ecs.len >= 4 and ecs[2] != 0) return Error.EcsRefused;
        }
        const cookie = self.clientCookie(query, client);
        if (cookie == .invalid) return self.cookieFailure(query, client, output);
        const key = try CacheKey.fromQuestion(query);
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
                    const bytes = try self.aggressiveAnswer(query, d, output);
                    if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                    return bytes;
                }
            }
        }
        var response = self.queryUdp(query_bytes, query) catch |err| switch (err) {
            Error.UpstreamFailure,
            Error.BadUpstreamResponse,
            => {
                if (try self.cache.lookup(&key, query, now, output, true)) |stale| {
                    if (cookie == .valid) return self.addCachedCookie(output, query, cookie.valid);
                    return stale.bytes;
                }
                return err;
            },
            else => return err,
        };
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
        stripOptions(&response);
        // Validation runs before the cache so a bogus answer is never stored
        // (RFC 4035 section 4.7) and so the AD bit a client sees is the one
        // this server computed rather than one re-derived on a cache hit.
        const validated = self.validating(query);
        if (validated) {
            const result = try self.checkDnssec(query, response, @intCast(@max(now, 0)));
            switch (result.status) {
                .secure => response.header.authenticated_data = true,
                // RFC 4035 section 5.5: a response that fails validation MUST
                // not be returned, and the client gets SERVFAIL carrying the
                // RFC 8914 INFO-CODE that says why. `wantsDnssecProofs` is
                // false when CD is set, and that is exactly the case section
                // 5.5 says must be returned in full instead.
                .bogus => return self.relayBogus(query, cookie, result.ede, output),
                .insecure => {},
            }
        }
        self.cache.put(key, &response, now) catch {};
        self.harvestNsecProofs(response, now);
        if (query.edns) |edns| try appendOpt(&response, edns);
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

    /// True when this response is one this server validates itself: a
    /// configured trust anchor, a client that asked for the proofs (DO=1), and
    /// no CD. DO gates validation because the forwarder relays the client's
    /// DO bit upstream unchanged, so a query without DO never carries RRSIGs
    /// back and there would be nothing to check. Failing closed there is what
    /// keeps a plain query from being answered SERVFAIL: AD is simply not set.
    fn validating(self: *const Resolver, query: dns_message.Message) bool {
        return self.policy.anchors.len != 0 and wantsDnssecProofs(query);
    }

    fn checkDnssec(self: *Resolver, query: dns_message.Message, response: dns_message.Message, now: u32) validate.Error!validate.Result {
        // `extra` is empty: the forward path answers from the response alone,
        // so a DS-only anchor has no child DNSKEY RRset to match and the
        // answer is honestly insecure rather than secure.
        return validate.validate(self.allocator, &self.policy.anchors, query, response, &.{}, now);
    }

    /// SERVFAIL plus the RFC 8914 DNSSEC-bogus INFO-CODE the validator
    /// produced, with the cookie the same answer path would have carried.
    fn relayBogus(self: *Resolver, query: dns_message.Message, cookie: CookieDecision, ede_code: u16, output: []u8) ![]const u8 {
        _ = self;
        var message = try Resolver.buildDnssecBogusResponse(query, ede_code);
        defer message.deinit();
        if (cookie == .valid) try appendCookie(&message, cookie.valid);
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

    fn harvestNsecProofs(self: *Resolver, response: dns_message.Message, now: i64) void {
        harvestSectionNsec(&self.dnssec_aggressive, response.answers.slice(), now);
        harvestSectionNsec(&self.dnssec_aggressive, response.authorities.slice(), now);
    }

    fn aggressiveAnswer(self: *const Resolver, query: dns_message.Message, denial: dnssec.Denial, output: []u8) ![]const u8 {
        _ = self;
        const q = query.question orelse return Error.BadUpstreamResponse;
        var message = dns_message.Message{
            .allocator = query.allocator,
            .header = .{
                .id = query.header.id,
                .qr = true,
                .recursion_desired = query.header.recursion_desired,
                .recursion_available = true,
                .rcode = switch (denial) {
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
        if (query.edns) |edns| try appendOpt(&message, edns);
        var writer = dns_writer.Writer.init(output);
        message.encode(&writer) catch return Error.ResponseTooLarge;
        return writer.written();
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

    fn queryUdp(self: *Resolver, query_bytes: []const u8, query: dns_message.Message) !dns_message.Message {
        const upstream = self.upstream orelse return Error.NoForwarder;
        var query_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        if (query_bytes.len < 2 or query_bytes.len > query_buffer.len) return Error.UpstreamFailure;
        // RFC 5452 §9.2: each attempt binds its own socket so the
        // OS-assigned ephemeral source port differs per attempt, widening the
        // Q-ID space with the per-attempt randomized ID below.
        var response_buffer: [MAX_UPSTREAM_MESSAGE]u8 = undefined;
        var attempt: usize = 0;
        while (attempt < UDP_ATTEMPTS) : (attempt += 1) {
            var local = switch (upstream) {
                .ip4 => std.Io.net.IpAddress{ .ip4 = .unspecified(0) },
                .ip6 => std.Io.net.IpAddress{ .ip6 = .unspecified(0) },
            };
            var socket = std.Io.net.IpAddress.bind(&local, self.io, .{ .mode = .dgram, .protocol = .udp }) catch return Error.UpstreamFailure;
            defer socket.close(self.io);
            var randomized_id: [2]u8 = undefined;
            self.io.randomSecure(&randomized_id) catch return Error.UpstreamFailure;
            const upstream_query = try buildUpstreamQuery(query_bytes, query, &query_buffer, &self.policy.anchors);
            @memcpy(query_buffer[0..2], &randomized_id);
            const expected_id = std.mem.readInt(u16, &randomized_id, .big);

            socket.send(self.io, &upstream, query_buffer[0..upstream_query.len]) catch continue;
            while (true) {
                const incoming = socket.receiveTimeout(self.io, &response_buffer, UDP_TIMEOUT) catch break;
                if (!incoming.from.eql(&upstream)) continue;
                switch (classifyUpstreamPacket(self.allocator, query, expected_id, incoming.data)) {
                    .ignore => continue,
                    .truncated => return self.queryTcpAfterTruncation(query_buffer[0..upstream_query.len], query, expected_id, UPSTREAM_TCP_DEADLINES_SUPPORTED),
                    .ready => |message| return message,
                }
            }
        }
        return Error.UpstreamFailure;
    }

    fn queryTcpAfterTruncation(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, expected_id: u16, comptime deadline_support: bool) !dns_message.Message {
        if (comptime !deadline_support) return Error.UpstreamFailure;
        return self.queryTcp(query_bytes, query, expected_id);
    }

    fn queryTcp(self: *Resolver, query_bytes: []const u8, query: dns_message.Message, expected_id: u16) !dns_message.Message {
        const upstream = self.upstream orelse return Error.NoForwarder;
        var stream = if (comptime UPSTREAM_TCP_DEADLINES_SUPPORTED)
            connectTcpWithTimeout(self.io, &upstream, .{
                .mode = .stream,
                .protocol = .tcp,
                .timeout = TCP_TIMEOUT,
            }) catch return Error.UpstreamFailure
        else
            std.Io.net.IpAddress.connect(&upstream, self.io, .{
                .mode = .stream,
                .protocol = .tcp,
                .timeout = TCP_TIMEOUT,
            }) catch return Error.UpstreamFailure;
        defer stream.close(self.io);
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
        if (!validUpstreamResponse(response, query, expected_id)) return Error.BadUpstreamResponse;
        return cloneMessage(self.allocator, response);
    }
};

const UpstreamPacket = union(enum) {
    ignore,
    truncated,
    ready: dns_message.Message,
};

/// Parses and validates one UDP datagram with a scratch arena owned by this
/// call, so the receive loop holds no deferred cleanups across iterations.
fn classifyUpstreamPacket(allocator: std.mem.Allocator, query: dns_message.Message, expected_id: u16, data: []const u8) UpstreamPacket {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const response = dns_message.Message.parse(arena.allocator(), data) catch return .ignore;
    if (!validUpstreamResponse(response, query, expected_id)) return .ignore;
    if (response.header.truncated) return .truncated;
    return .{ .ready = cloneMessage(allocator, response) catch return .ignore };
}

fn buildUpstreamQuery(
    original: []const u8,
    query: dns_message.Message,
    output: []u8,
    anchors: *const validate.Anchors,
) ![]const u8 {
    if (query.edns == null) {
        if (original.len > output.len) return Error.UpstreamFailure;
        @memcpy(output[0..original.len], original);
        return output[0..original.len];
    }

    var sanitized = dns_message.Message{
        .allocator = query.allocator,
        .header = query.header,
        .question = query.question,
        .answers = try dns_message.RecordSection.init(query.allocator, 0),
        .authorities = try dns_message.RecordSection.init(query.allocator, 0),
        .additionals = try dns_message.RecordSection.init(query.allocator, 0),
    };
    errdefer sanitized.deinit();
    try appendOpt(&sanitized, query.edns.?);
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

fn validUpstreamResponse(response: dns_message.Message, query: dns_message.Message, expected_id: u16) bool {
    if (!response.header.qr or response.header.id != expected_id or response.header.opcode != query.header.opcode or response.header.question_count != 1) return false;
    if (findOption(response, dns_rdata.EDNS_ECS_OPTION_CODE) != null) return false;
    const expected = query.question orelse return false;
    const actual = response.question orelse return false;
    return actual.name.eql(&expected.name) and actual.qtype.eql(expected.qtype) and actual.qclass.eql(expected.qclass);
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

fn wantsDnssecProofs(query: dns_message.Message) bool {
    if (query.header.checking_disabled) return false;
    const edns = query.edns orelse return false;
    return edns.dnssec_ok;
}

fn harvestSectionNsec(cache: *dnssec.AggressiveCache, records: []const dns_record.ResourceRecord, now: i64) void {
    for (records) |*record| {
        if (!record.rrtype.eql(.NSEC)) continue;
        const raw = switch (record.rdata) {
            .Unknown => |*unknown| unknown.bytes(),
            else => continue,
        };
        const next = dns_name.Name.parse(raw, 0) catch continue;
        cache.insertNsec(record.owner, next.name, raw[next.next_offset..], now, record.ttl);
    }
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
    // bare header 7 with no OPT is reserved, so BADCOOKIE responses always
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
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();

    var positive = try makePositiveResponse(arena.allocator(), 60);
    defer positive.deinit();
    try cache.put(key, &positive, 1000);
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
    try cache.put(negative_key, &negative, 2000);
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
    try cache.put(negative_key, &nodata, 3000);
    const nodata_stale = (try cache.lookup(&negative_key, negative_query, 3100, &output, true)).?;
    const nodata_message = try dns_message.Message.parse(arena.allocator(), nodata_stale.bytes);
    try expectEde(nodata_message, EDE_STALE_ANSWER, "stale answer");
}

test "cache excludes failures truncation and upstream option data" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var query = try makeTestQuery(arena.allocator(), 0x2300, "example.com.", false);
    defer query.deinit();
    const key = try CacheKey.fromQuestion(query);
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();
    var output: [2048]u8 = undefined;

    var failure = try makePositiveResponse(arena.allocator(), 60);
    defer failure.deinit();
    failure.header.rcode = .servfail;
    try cache.put(key, &failure, 1000);
    try std.testing.expect((try cache.lookup(&key, query, 1001, &output, true)) == null);

    var truncated = try makePositiveResponse(arena.allocator(), 60);
    defer truncated.deinit();
    truncated.header.truncated = true;
    try cache.put(key, &truncated, 1000);
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
    try cache.put(key, &with_opt, 1000);
    const hit = (try cache.lookup(&key, query, 1001, &output, false)).?;
    const hit_message = try dns_message.Message.parse(arena.allocator(), hit.bytes);
    try std.testing.expect(hit_message.edns == null);
    try std.testing.expectEqual(@as(usize, 0), hit_message.additionals.len);
}

test "cache reuses an expired slot instead of evicting a live entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cache = Cache.init(std.testing.allocator);
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
        try cache.put(keys[index], &responses[index], 1000);
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
    try cache.put(newcomer_key, &newcomer_response, 1061);
    try std.testing.expectEqual(MAX_CACHE_ENTRIES, cache.len);

    const survivor = (try cache.lookup(&keys[0], queries[0], 1062, &output, false)).?;
    try std.testing.expect(!survivor.stale);
    const fresh = (try cache.lookup(&newcomer_key, newcomer, 1062, &output, false)).?;
    try std.testing.expect(!fresh.stale);
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
    try std.testing.expectError(Error.UpstreamFailure, resolver.queryTcpAfterTruncation(&.{}, query, 0, false));
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

test "resolver refuses nonzero ECS before cache or upstream" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var resolver = try Resolver.init(std.testing.allocator, io, .{});
    defer resolver.deinit();

    var query = try makeTestQuery(std.testing.allocator, 0x2601, "example.com.", true);
    defer query.deinit();
    const ecs = [_]u8{ 0, 1, 24, 0, 192, 0, 2 };
    try appendOption(&query, dns_rdata.EDNS_ECS_OPTION_CODE, &ecs);
    var query_bytes: [1024]u8 = undefined;
    const encoded = try encodeTestMessage(query, &query_bytes);
    var output: [2048]u8 = undefined;
    const client = try std.Io.net.IpAddress.parse("127.0.0.1", 42601);
    try std.testing.expectError(Error.EcsRefused, resolver.answer(encoded, query, &client, &output));
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
    try std.testing.expect(!validUpstreamResponse(response, query, query.header.id));
}

test "buildUpstreamQuery strips client EDNS options but preserves payload size and DO" {
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

    var output: [512]u8 = undefined;
    const encoded = try buildUpstreamQuery(&.{ 0xde, 0xad }, query, &output, &.{});

    var parsed_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer parsed_arena.deinit();
    const upstream = try dns_message.Message.parse(parsed_arena.allocator(), encoded);
    try std.testing.expectEqual(@as(u16, 1200), upstream.edns.?.udp_payload_size);
    try std.testing.expect(upstream.edns.?.dnssec_ok);
    try std.testing.expectEqual(@as(usize, 0), upstream.additionals.items[0].rdata.OPT.bytes().len);
    try std.testing.expect(findOption(upstream, dns_rdata.EDNS_PADDING_OPTION_CODE) == null);
    try std.testing.expect(findOption(upstream, dns_rdata.EDNS_ECS_OPTION_CODE) == null);
    try std.testing.expect(findOption(upstream, COOKIE_OPTION_CODE) == null);
    try std.testing.expect(findOption(upstream, 65000) == null);
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
        try buildUpstreamQuery(&.{ 0xde, 0xad }, dnskey_query, &output, &anchors),
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
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, ds_query, &output, &anchors),
    );
    try std.testing.expectEqualSlices(u8, &.{ 0xec, 0x45 }, findOption(ds_upstream, dns_rdata.EDNS_KEY_TAG_OPTION_CODE).?);

    // Section 4.2: the option is for DNSKEY queries only, so an ordinary query
    // for an anchored name carries nothing extra.
    var a_query = try makeTestQuery(arena.allocator(), 0x2607, "example.com.", true);
    defer a_query.deinit();
    const a_upstream = try dns_message.Message.parse(
        parsed_arena.allocator(),
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, a_query, &output, &anchors),
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
        try buildUpstreamQuery(&.{ 0xbe, 0xef }, unanchored, &output, &.{}),
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
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();
    try cache.put(try CacheKey.fromQuestion(base), &response, 4000);

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
    );
    resolver.dnssec_aggressive.insertNsec(
        try dns_name.Name.fromText("mail.example."),
        try dns_name.Name.fromText("www.example."),
        &bitmap,
        now,
        3600,
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
    try std.testing.expectEqual(dnssec.Denial.nxdomain, denial.?);
    const bytes = try resolver.aggressiveAnswer(query, denial.?, &output);
    const parsed = try dns_message.Message.parse(arena.allocator(), bytes);
    try std.testing.expectEqual(dns_header.Rcode.nxdomain, parsed.header.rcode);
    try std.testing.expect(parsed.edns.?.dnssec_ok);

    var cd_query = try makeTestQuery(arena.allocator(), 0x2705, "nx.example.", true);
    defer cd_query.deinit();
    cd_query.header.checking_disabled = true;
    cd_query.edns.?.dnssec_ok = true;
    try std.testing.expect(!wantsDnssecProofs(cd_query));
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

    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, 0x2606, &.{ 1, 2, 3 }) == .ignore);

    var truncated = try makePositiveResponse(arena.allocator(), 60);
    defer truncated.deinit();
    truncated.header.id = query.header.id;
    truncated.header.truncated = true;
    var wire: [2048]u8 = undefined;
    const truncated_bytes = try encodeTestMessage(truncated, &wire);
    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, 0x9999, truncated_bytes) == .ignore);
    try std.testing.expect(classifyUpstreamPacket(arena.allocator(), query, query.header.id, truncated_bytes) == .truncated);

    var good = try makePositiveResponse(arena.allocator(), 60);
    defer good.deinit();
    good.header.id = query.header.id;
    const good_bytes = try encodeTestMessage(good, &wire);
    var ready = classifyUpstreamPacket(std.testing.allocator, query, query.header.id, good_bytes);
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
    var message = try makeTestQuery(allocator, 0x1100, "example.com.", false);
    message.header.qr = true;
    message.header.recursion_available = true;
    errdefer message.deinit();
    try message.answers.append(.{
        .owner = try dns_name.Name.fromText("example.com."),
        .rrtype = .A,
        .class = .IN,
        .ttl = ttl,
        .rdata = .{ .A = .{ 192, 0, 2, 1 } },
    });
    message.header.answer_count = 1;
    return message;
}

fn makeNegativeResponse(allocator: std.mem.Allocator, ttl: u32, minimum: u32) !dns_message.Message {
    var message = try makeTestQuery(allocator, 0x1101, "missing.example.", false);
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
