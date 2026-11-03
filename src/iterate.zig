/// Contract: Resolves one question iteratively from the root hints by
/// following referrals and alias chains. The transport is an injected
/// `Sender`, so the state machine is testable without sockets.
/// Ownership: the returned `Message` is owned by the caller's allocator; every
/// interim message is deinitialized here.
/// Errors: protocol failure is `MalformedResponse`; a resolution that cannot
/// reach an authoritative answer is `NoReachableServer` or `TooManyHops`.
const std = @import("std");
const dns_message = @import("dns/message.zig");
const dns_name = @import("dns/name.zig");
const dns_question = @import("dns/question.zig");
const dns_writer = @import("dns/writer.zig");
const types = @import("dns/types.zig");
const Name = dns_name.Name;
const RecordType = types.RecordType;

/// RFC 1034 section 4.3.2: a referral moves one zone closer to the answer.
/// The bound keeps a hostile or broken delegation chain from running away.
pub const MAX_REFERRALS: usize = 32;
/// RFC 1034 section 4.3.2: an alias chain restarts the resolution at the
/// alias target. RFC 8767 section 4.1 and operational practice cap it at
/// eight links.
pub const MAX_ALIAS_HOPS: usize = 8;
/// One delegation names at most a handful of servers this module keeps; a
/// longer NS set is served by its first entries.
pub const MAX_SERVERS: usize = 16;

pub const Error = error{
    MalformedResponse,
    NoReachableServer,
    TooManyHops,
};

/// The transport seam. `send` must send `query` to `server`, check the
/// response against the question it asked, and return the parsed message
/// owned by `allocator`; it must not return a truncated answer.
pub const Sender = struct {
    context: *anyopaque,
    send: *const fn (context: *anyopaque, allocator: std.mem.Allocator, server: std.Io.net.IpAddress, query: []const u8, dnssec_ok: bool) anyerror!dns_message.Message,
};

/// The root name servers as published by InterNIC in `named.root`
/// (last update 2026-10-28). IPv4 only: an address family the host lacks
/// never answers, and the transport tries the next server.
pub const root_hint_text = [13][]const u8{
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
};

/// The root hints as socket addresses. The literals are constant and valid.
pub fn rootHints(buffer: *[root_hint_text.len]std.Io.net.IpAddress) []const std.Io.net.IpAddress {
    for (root_hint_text, 0..) |text, index| {
        buffer[index] = std.Io.net.IpAddress.parseIp4(text, 53) catch unreachable;
    }
    return buffer[0..];
}

/// RFC 1034 section 4.3.2: a delegation is reused for later names inside the
/// same zone until its NS TTL runs out.
pub const MAX_DELEGATIONS: usize = 32;
/// A delegation this module keeps keeps its first few servers; the rest of a
/// long NS set is reachable through the same zone.
pub const MAX_DELEGATION_SERVERS: usize = 8;
/// The delegation TTL is capped so a hostile parent cannot pin an address
/// for longer than a day.
pub const MAX_DELEGATION_TTL: u32 = 24 * 60 * 60;

pub const Delegation = struct {
    zone: Name,
    servers: [MAX_DELEGATION_SERVERS]std.Io.net.IpAddress,
    server_count: usize,
    /// The NS TTL the referral gave; carried into `expires` on commit.
    ttl: u32 = 0,
    expires: i64,
};

/// The bounded delegation cache. Every method runs under the resolver's own
/// lock, so the table needs no lock of its own.
pub const DelegationCache = struct {
    entries: [MAX_DELEGATIONS]Delegation = undefined,
    len: usize = 0,

    /// The longest unexpired delegation whose zone holds `name`, which is
    /// the closest place to start the resolution.
    pub fn lookup(self: *const DelegationCache, name: Name, now: i64) ?*const Delegation {
        var best: ?*const Delegation = null;
        for (self.entries[0..self.len]) |*entry| {
            if (entry.expires <= now) continue;
            if (!isAncestorOrEqual(&entry.zone, &name)) continue;
            if (best) |current| {
                if (entry.zone.asWire().len <= current.zone.asWire().len) continue;
            }
            best = entry;
        }
        return best;
    }

    pub fn put(self: *DelegationCache, zone: Name, servers: []const std.Io.net.IpAddress, ttl: u32, now: i64) void {
        if (servers.len == 0 or zone.asWire().len == 0) return;
        const count = @min(servers.len, MAX_DELEGATION_SERVERS);
        const expires = now + @as(i64, @min(ttl, MAX_DELEGATION_TTL));
        for (self.entries[0..self.len]) |*entry| {
            if (!entry.zone.eql(&zone)) continue;
            entry.* = .{ .zone = zone, .servers = undefined, .server_count = count, .expires = expires };
            @memcpy(entry.servers[0..count], servers[0..count]);
            return;
        }
        if (self.len < self.entries.len) {
            self.entries[self.len] = .{ .zone = zone, .servers = undefined, .server_count = count, .expires = expires };
            @memcpy(self.entries[self.len].servers[0..count], servers[0..count]);
            self.len += 1;
            return;
        }
        // Replace the entry that expires first.
        var victim: usize = 0;
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (entry.expires < self.entries[victim].expires) victim = index;
        }
        self.entries[victim] = .{ .zone = zone, .servers = undefined, .server_count = count, .expires = expires };
        @memcpy(self.entries[victim].servers[0..count], servers[0..count]);
    }

    pub fn clear(self: *DelegationCache) void {
        self.len = 0;
    }
};

pub const Options = struct {
    /// The delegation cache the resolution reads and fills; null leaves the
    /// walk stateless.
    cache: ?*DelegationCache = null,
    /// Wall-clock seconds, the same clock the answer cache uses.
    now: i64 = 0,
    /// RFC 3225 section 3: a validating resolver asks its own hops for the
    /// DNSSEC records, so every query carries the DO bit. Without it a signed
    /// zone's answer arrives unsigned and cannot be chained.
    dnssec_ok: bool = false,
    /// Filled with the zone that answered, which is the closest enclosing
    /// zone of the question and the zone whose DS the parent publishes. A
    /// validating caller needs it to decide whether an unsigned answer came
    /// from an insecure delegation.
    zone_out: ?*Name = null,
};

/// Resolves `question` from `hints`: the root hint addresses for an ordinary
/// resolution. A warm cache starts the walk at the closest known delegation
/// and falls back to `hints` when that delegation does not answer.
pub fn resolve(
    allocator: std.mem.Allocator,
    sender: Sender,
    hints: []const std.Io.net.IpAddress,
    question: dns_question.Question,
    options: Options,
) anyerror!dns_message.Message {
    return resolveAt(allocator, sender, hints, question, options, 0);
}

fn resolveAt(
    allocator: std.mem.Allocator,
    sender: Sender,
    hints: []const std.Io.net.IpAddress,
    question: dns_question.Question,
    options: Options,
    depth: usize,
) anyerror!dns_message.Message {
    if (depth > MAX_ALIAS_HOPS) return Error.TooManyHops;
    if (hints.len == 0) return Error.NoReachableServer;
    if (options.cache) |cache| {
        if (cache.lookup(question.name, options.now)) |cached| {
            return resolveFrom(allocator, sender, cached.servers[0..cached.server_count], cached.zone, question, options, depth) catch |err| switch (err) {
                Error.NoReachableServer, Error.TooManyHops => resolveFrom(allocator, sender, hints, Name.root(), question, options, depth),
                else => return err,
            };
        }
    }
    return resolveFrom(allocator, sender, hints, Name.root(), question, options, depth);
}

fn resolveFrom(
    allocator: std.mem.Allocator,
    sender: Sender,
    hints: []const std.Io.net.IpAddress,
    start_zone: Name,
    question: dns_question.Question,
    options: Options,
    depth: usize,
) anyerror!dns_message.Message {
    var servers: [MAX_SERVERS]std.Io.net.IpAddress = undefined;
    var server_count: usize = @min(hints.len, servers.len);
    @memcpy(servers[0..server_count], hints[0..server_count]);
    var targets: [MAX_SERVERS]Name = undefined;
    var glue: [MAX_SERVERS]std.Io.net.IpAddress = undefined;
    var zone = start_zone;
    var query_buffer: [512]u8 = undefined;
    // A delegation is cached only after one of its own servers answered:
    // a parent that hands out a lame delegation must not steer later names.
    var pending: ?Delegation = null;

    var hops: usize = 0;
    while (hops < MAX_REFERRALS) : (hops += 1) {
        var advanced = false;
        var index: usize = 0;
        while (index < server_count) : (index += 1) {
            const query = encodeQuery(question, &query_buffer) catch return Error.MalformedResponse;
            var response = sender.send(sender.context, allocator, servers[index], query, options.dnssec_ok) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => continue,
            };

            const rcode = response.header.rcode;
            if (rcode != .no_error and rcode != .nxdomain) {
                // A server that fails for this question is tried no further;
                // another address in the delegation may still answer it.
                response.deinit();
                continue;
            }
            // The delegation the previous referral named is usable: one of
            // its servers answered with a usable response, not an error.
            if (pending) |entry| {
                if (options.cache) |cache| cache.put(entry.zone, entry.servers[0..entry.server_count], entry.ttl, options.now);
                pending = null;
            }
            // RFC 1034 section 4.3.2 step 3: the answer section ends the
            // resolution. NXDOMAIN ends it too, and an empty answer with an
            // SOA in the authority section is the NODATA denial.
            if (rcode == .nxdomain or answered(&response, question) or hasSoa(&response)) {
                if (options.zone_out) |out| out.* = zone;
                return response;
            }
            if (aliasTarget(&response, question.name)) |target| {
                var final = try resolveAt(allocator, sender, hints, .{
                    .name = target,
                    .qtype = question.qtype,
                    .qclass = question.qclass,
                }, options, depth + 1);
                const merged = mergeAlias(allocator, &response, &final, question) catch |err| {
                    final.deinit();
                    response.deinit();
                    return err;
                };
                final.deinit();
                response.deinit();
                return merged;
            }

            // RFC 1034 section 4.3.2 step 2: a referral names a child zone
            // and, when in the parent's bailiwick, its glue.
            if (referral(&response, zone, &targets, &glue)) |next| {
                if (next.glue_count != 0) {
                    @memcpy(servers[0..next.glue_count], glue[0..next.glue_count]);
                    server_count = next.glue_count;
                } else {
                    var resolved: [MAX_SERVERS]std.Io.net.IpAddress = undefined;
                    const count = try resolveServerAddresses(allocator, sender, hints, targets[0..next.target_count], &resolved, options, depth + 1);
                    // A delegation whose name servers cannot be reached is
                    // not a new place to look; the next server of the
                    // current delegation may still answer.
                    if (count == 0) {
                        response.deinit();
                        continue;
                    }
                    @memcpy(servers[0..count], resolved[0..count]);
                    server_count = count;
                }
                pending = .{
                    .zone = next.child,
                    .servers = undefined,
                    .server_count = @min(server_count, MAX_DELEGATION_SERVERS),
                    .expires = 0,
                    .ttl = next.ttl,
                };
                @memcpy(pending.?.servers[0..pending.?.server_count], servers[0..pending.?.server_count]);
                zone = next.child;
                response.deinit();
                advanced = true;
                break;
            }
            response.deinit();
        }
        if (!advanced) return Error.NoReachableServer;
    }
    return Error.TooManyHops;
}

/// Copies the addresses the additional section gives for the delegation's
/// name servers. With `bailiwick` set, only records inside that zone are
/// accepted; with null, any record naming an NS target is a next-hop hint.
fn collectGlue(
    message: *const dns_message.Message,
    bailiwick: ?*const Name,
    targets: []const Name,
    glue: *[MAX_SERVERS]std.Io.net.IpAddress,
) usize {
    var glue_count: usize = 0;
    for (message.additionals.slice()) |record| {
        if (glue_count == glue.len) break;
        if (bailiwick) |zone| if (!isDescendant(&record.owner, zone)) continue;
        for (targets) |*target| {
            if (!record.owner.eql(target)) continue;
            const octets = switch (record.rdata) {
                .A => |value| value,
                else => break,
            };
            glue[glue_count] = .{ .ip4 = .{ .bytes = octets, .port = 53 } };
            glue_count += 1;
            break;
        }
    }
    return glue_count;
}

const Referral = struct {
    child: Name,
    target_count: usize,
    glue_count: usize,
    /// The smallest TTL of the child's NS records: how long the delegation
    /// may be reused.
    ttl: u32,
};

/// The deepest NS owner in the authority section that is a strict descendant
/// of `zone`. Nothing else can legitimately move the resolution. The NS
/// targets and the in-bailiwick A/AAAA glue are copied into the caller's
/// arrays.
fn referral(
    message: *const dns_message.Message,
    zone: Name,
    targets: *[MAX_SERVERS]Name,
    glue: *[MAX_SERVERS]std.Io.net.IpAddress,
) ?Referral {
    var child: ?Name = null;
    for (message.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NS)) continue;
        if (!isDescendant(&record.owner, &zone)) continue;
        if (child) |current| {
            if (record.owner.asWire().len <= current.asWire().len) continue;
        }
        child = record.owner;
    }
    const found = child orelse return null;

    var target_count: usize = 0;
    var ttl: u32 = std.math.maxInt(u32);
    for (message.authorities.slice()) |record| {
        if (!record.rrtype.eql(.NS)) continue;
        if (!record.owner.eql(&found)) continue;
        const target: Name = switch (record.rdata) {
            .NS => |name| name,
            else => continue,
        };
        if (target_count < targets.len) {
            targets[target_count] = target;
            target_count += 1;
        }
        ttl = @min(ttl, record.ttl);
    }
    if (target_count == 0) return null;

    // RFC 1034 section 4.3.2: the additional section carries the address of
    // a name server the delegation named. In-bailiwick addresses are used
    // first. A name server outside the child's bailiwick (the root's `com.`
    // delegation names `.gtld-servers.net`) still gets its address from the
    // parent; the address is only a place to send the next query, and the
    // answer there must match the question, so it is a hint and not proof
    // (RFC 5452 section 6 forbids taking it as data).
    var glue_count = collectGlue(message, &found, targets[0..target_count], glue);
    if (glue_count == 0) glue_count = collectGlue(message, null, targets[0..target_count], glue);
    return .{ .child = found, .target_count = target_count, .glue_count = glue_count, .ttl = ttl };
}

/// Resolves each NS target's address when the referral carried no glue, in
/// the order the authority section listed the targets. The first target that
/// resolves to at least one address ends the search.
fn resolveServerAddresses(
    allocator: std.mem.Allocator,
    sender: Sender,
    hints: []const std.Io.net.IpAddress,
    targets: []const Name,
    servers: []std.Io.net.IpAddress,
    options: Options,
    depth: usize,
) anyerror!usize {
    for (targets) |target| {
        var answer = resolveAt(allocator, sender, hints, .{ .name = target, .qtype = .A, .qclass = .IN }, options, depth) catch continue;
        defer answer.deinit();
        var count: usize = 0;
        for (answer.answers.slice()) |record| {
            if (count == servers.len) break;
            if (!record.owner.eql(&target)) continue;
            const octets = switch (record.rdata) {
                .A => |value| value,
                else => continue,
            };
            const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = octets, .port = 53 } };
            servers[count] = address;
            count += 1;
        }
        if (count != 0) return count;
    }
    return 0;
}

fn answered(message: *const dns_message.Message, question: dns_question.Question) bool {
    if (question.qtype.eql(.ANY)) return message.answers.len != 0;
    for (message.answers.slice()) |record| {
        if (!record.rrtype.eql(question.qtype)) continue;
        return true;
    }
    return false;
}

fn aliasTarget(message: *const dns_message.Message, qname: Name) ?Name {
    for (message.answers.slice()) |record| {
        if (!record.owner.eql(&qname)) continue;
        if (!record.rrtype.eql(.CNAME)) continue;
        return switch (record.rdata) {
            .CNAME => |name| name,
            else => null,
        };
    }
    return null;
}

fn encodeQuery(question: dns_question.Question, buffer: []u8) ![]const u8 {
    var message = dns_message.Message{
        .header = .{ .id = 0, .question_count = 1 },
        .question = question,
    };
    defer message.deinit();
    var writer = dns_writer.Writer.init(buffer);
    try message.encode(&writer);
    return writer.written();
}

fn mergeAlias(
    allocator: std.mem.Allocator,
    alias: *const dns_message.Message,
    final: *const dns_message.Message,
    question: dns_question.Question,
) !dns_message.Message {
    var merged = dns_message.Message{
        .header = final.header,
        .question = question,
        .answers = try dns_message.RecordSection.init(allocator, alias.answers.len + final.answers.len),
        .authorities = try dns_message.RecordSection.init(allocator, final.authorities.len),
        .additionals = try dns_message.RecordSection.init(allocator, final.additionals.len),
    };
    errdefer merged.deinit();
    for (alias.answers.slice()) |record| try merged.answers.append(record);
    for (final.answers.slice()) |record| try merged.answers.append(record);
    for (final.authorities.slice()) |record| try merged.authorities.append(record);
    for (final.additionals.slice()) |record| try merged.additionals.append(record);
    // The header counts follow the merged sections, not the target answer's
    // own counts: the wire writer copies the header verbatim.
    merged.header.question_count = 1;
    merged.header.answer_count = @intCast(merged.answers.len);
    merged.header.authority_count = @intCast(merged.authorities.len);
    merged.header.additional_count = @intCast(merged.additionals.len);
    return merged;
}

fn hasSoa(message: *const dns_message.Message) bool {
    for (message.authorities.slice()) |record| if (record.rrtype.eql(.SOA)) return true;
    return false;
}

fn isAncestorOrEqual(ancestor: *const Name, name: *const Name) bool {
    const parent = ancestor.asWire();
    const child = name.asWire();
    if (parent.len > child.len) return false;
    return std.mem.eql(u8, child[child.len - parent.len ..], parent);
}

fn isDescendant(name: *const Name, ancestor: *const Name) bool {
    const child = name.asWire();
    const parent = ancestor.asWire();
    if (parent.len >= child.len) return false;
    return std.mem.eql(u8, child[child.len - parent.len ..], parent);
}

const TestScript = struct {
    server: [4]u8,
    qname: []const u8,
    qtype: RecordType,
    kind: Kind,

    const Kind = union(enum) {
        referral: struct { child: []const u8, ns: []const u8, glue: ?[4]u8 },
        address: [4]u8,
        cname: []const u8,
        nxdomain,
        servfail,
    };
};

const FakeSender = struct {
    scripts: []const TestScript,
    used: []bool,

    fn send(context: *anyopaque, allocator: std.mem.Allocator, server: std.Io.net.IpAddress, query_bytes: []const u8, dnssec_ok: bool) anyerror!dns_message.Message {
        _ = dnssec_ok;
        const self: *FakeSender = @ptrCast(@alignCast(context));
        var query = try dns_message.Message.parse(allocator, query_bytes);
        defer query.deinit();
        const question = query.question orelse return Error.MalformedResponse;
        const server_bytes = switch (server) {
            .ip4 => |address| address.bytes,
            else => return Error.NoReachableServer,
        };
        for (self.scripts, 0..) |script, index| {
            if (self.used[index]) continue;
            if (!std.mem.eql(u8, &script.server, &server_bytes)) continue;
            if (!question.name.eql(&(dns_name.Name.fromText(script.qname) catch unreachable))) continue;
            if (!question.qtype.eql(script.qtype)) continue;
            self.used[index] = true;
            return buildResponse(allocator, script, question);
        }
        return Error.NoReachableServer;
    }

    fn buildResponse(allocator: std.mem.Allocator, script: TestScript, question: dns_question.Question) !dns_message.Message {
        var message = dns_message.Message{
            .header = .{ .id = 0, .qr = true, .question_count = 1 },
            .question = question,
            .answers = try dns_message.RecordSection.init(allocator, 1),
            .authorities = try dns_message.RecordSection.init(allocator, 1),
            .additionals = try dns_message.RecordSection.init(allocator, 1),
        };
        errdefer message.deinit();
        switch (script.kind) {
            .referral => |next| {
                const child = try Name.fromText(next.child);
                const ns = try Name.fromText(next.ns);
                try message.authorities.append(.{ .owner = child, .rrtype = .NS, .class = .IN, .ttl = 3600, .rdata = .{ .NS = ns } });
                message.header.authority_count = 1;
                if (next.glue) |octets| {
                    try message.additionals.append(.{ .owner = ns, .rrtype = .A, .class = .IN, .ttl = 3600, .rdata = .{ .A = octets } });
                    message.header.additional_count = 1;
                }
            },
            .address => |octets| {
                try message.answers.append(.{ .owner = question.name, .rrtype = .A, .class = .IN, .ttl = 300, .rdata = .{ .A = octets } });
                message.header.answer_count = 1;
                message.header.authoritative = true;
            },
            .cname => |target| {
                try message.answers.append(.{ .owner = question.name, .rrtype = .CNAME, .class = .IN, .ttl = 300, .rdata = .{ .CNAME = try Name.fromText(target) } });
                message.header.answer_count = 1;
                message.header.authoritative = true;
            },
            .nxdomain => message.header.rcode = .nxdomain,
            .servfail => message.header.rcode = .servfail,
        }
        return message;
    }
};

fn hint(octets: [4]u8) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = octets, .port = 53 } };
}

test "RFC 1034 section 4.3.2: a referral with glue is followed to the answer" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    var answer = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{});
    defer answer.deinit();

    try std.testing.expectEqual(@as(usize, 1), answer.answers.len);
    const rdata = answer.answers.slice()[0].rdata;
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 7 }, rdata.A);
    try std.testing.expect(used[0] and used[1]);
}

test "RFC 1034 section 4.3.2: an out-of-bailiwick name server address is resolved from the root" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.net.", .glue = null } } },
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "ns.example.net.", .qtype = .A, .kind = .{ .referral = .{ .child = "net.", .ns = "ns.net.", .glue = .{ 203, 0, 113, 9 } } } },
        .{ .server = .{ 203, 0, 113, 9 }, .qname = "ns.example.net.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.net.", .ns = "ns.example.net.", .glue = .{ 203, 0, 113, 10 } } } },
        .{ .server = .{ 203, 0, 113, 10 }, .qname = "ns.example.net.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 9 } } },
        .{ .server = .{ 192, 0, 2, 9 }, .qname = "www.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    var answer = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{});
    defer answer.deinit();

    try std.testing.expectEqual(@as(usize, 1), answer.answers.len);
    const rdata = answer.answers.slice()[0].rdata;
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 7 }, rdata.A);
    for (used) |entry| try std.testing.expect(entry);
}

test "RFC 1034 section 4.3.2: an alias chain is followed and merged into the answer" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .{ .cname = "target.example." } },
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "target.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "target.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 8 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    var answer = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{});
    defer answer.deinit();

    try std.testing.expectEqual(@as(usize, 2), answer.answers.len);
    try std.testing.expectEqual(@as(u16, 2), answer.header.answer_count);
    try std.testing.expect(answer.answers.slice()[0].rrtype.eql(.CNAME));
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 8 }, answer.answers.slice()[1].rdata.A);
}

test "RFC 1034 section 4.3.2: a delegation whose servers all fail is unreachable" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .servfail },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    try std.testing.expectError(Error.NoReachableServer, resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{}));
}

test "RFC 1034 section 4.3.2: an NXDOMAIN ends the resolution" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "nx.", .qtype = .A, .kind = .nxdomain },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    var answer = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("nx."),
        .qtype = .A,
        .qclass = .IN,
    }, .{});
    defer answer.deinit();

    try std.testing.expect(answer.header.rcode == .nxdomain);
}

test "RFC 1034 section 4.3.2: an out-of-bailiwick glue address is the next server" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The root's `com.` delegation names name servers under `.net.`, so the
    // address arrives in the additional section outside the child's
    // bailiwick. It is still where the next query goes.
    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.com.", .qtype = .A, .kind = .{ .referral = .{ .child = "com.", .ns = "a.gtld-servers.net.", .glue = .{ 203, 0, 113, 7 } } } },
        .{ .server = .{ 203, 0, 113, 7 }, .qname = "www.example.com.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};

    var answer = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example.com."),
        .qtype = .A,
        .qclass = .IN,
    }, .{});
    defer answer.deinit();

    try std.testing.expectEqual(@as(usize, 1), answer.answers.len);
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 7 }, answer.answers.slice()[0].rdata.A);
    try std.testing.expect(used[0] and used[1]);
}

test "RFC 1034 section 4.3.2: a warm delegation answers the next name without the root" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The only hint is the root. The first resolution learns `example.` with
    // a 300-second NS TTL; the second resolution carries no root script at
    // all, so it can only succeed from the cached delegation.
    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "mail.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 8 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};
    var cache = DelegationCache{};

    var first = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1000 });
    first.deinit();
    try std.testing.expectEqual(@as(usize, 1), cache.len);

    var second = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("mail.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1001 });
    defer second.deinit();
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 8 }, second.answers.slice()[0].rdata.A);
    // The warm walk did not add a second entry for the same zone.
    try std.testing.expectEqual(@as(usize, 1), cache.len);
    for (used) |entry| try std.testing.expect(entry);
}

test "RFC 1034 section 4.3.2: an expired delegation is not used" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "mail.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "mail.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 8 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};
    var cache = DelegationCache{};

    var first = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1000 });
    first.deinit();

    // The fixture's NS TTL is 3600 seconds: at 5000 the delegation is stale,
    // so the root is asked again.
    var second = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("mail.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 5000 });
    defer second.deinit();
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 8 }, second.answers.slice()[0].rdata.A);
    try std.testing.expect(used[2] and used[3]);
}

test "RFC 1034 section 4.3.2: an unreachable cached delegation falls back to the root" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 7 } } },
        // No script for the cached 203.0.113.5 at mail.example., so it fails.
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "mail.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 6 } } } },
        .{ .server = .{ 203, 0, 113, 6 }, .qname = "mail.example.", .qtype = .A, .kind = .{ .address = .{ 192, 0, 2, 8 } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};
    var cache = DelegationCache{};

    var first = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1000 });
    first.deinit();

    var second = try resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("mail.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1001 });
    defer second.deinit();
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 8 }, second.answers.slice()[0].rdata.A);
}

test "RFC 1034 section 4.3.2: a delegation whose server never answers is not cached" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The root refers to `example.` with one glue address, and nothing
    // answers there. The referral must not be remembered, so a later name
    // starts at the root instead of a dead delegation.
    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};
    var cache = DelegationCache{};

    try std.testing.expectError(Error.NoReachableServer, resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1000 }));
    try std.testing.expectEqual(@as(usize, 0), cache.len);
}

test "RFC 1034 section 4.3.2: a delegation whose server answers SERVFAIL is not cached" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The server is reachable but refuses to serve the zone, which is the
    // lame-delegation case: a SERVFAIL must not validate the delegation.
    const scripts = [_]TestScript{
        .{ .server = .{ 198, 41, 0, 4 }, .qname = "www.example.", .qtype = .A, .kind = .{ .referral = .{ .child = "example.", .ns = "ns.example.", .glue = .{ 203, 0, 113, 5 } } } },
        .{ .server = .{ 203, 0, 113, 5 }, .qname = "www.example.", .qtype = .A, .kind = .servfail },
    };
    var used = std.mem.zeroes([scripts.len]bool);
    var fake = FakeSender{ .scripts = &scripts, .used = &used };
    const hints = [_]std.Io.net.IpAddress{hint(.{ 198, 41, 0, 4 })};
    var cache = DelegationCache{};

    try std.testing.expectError(Error.NoReachableServer, resolve(allocator, .{ .context = &fake, .send = FakeSender.send }, &hints, .{
        .name = try Name.fromText("www.example."),
        .qtype = .A,
        .qclass = .IN,
    }, .{ .cache = &cache, .now = 1000 }));
    try std.testing.expectEqual(@as(usize, 0), cache.len);
}
