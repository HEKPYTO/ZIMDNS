/// Contract: RFC 9156 QNAME minimization policy as pure label math plus a
/// bounded fallback tracker. No I/O, no allocation, no iterative resolution.
/// Ownership: All functions copy small Name values; the caller owns inputs.
/// Errors: Name construction cannot fail on valid wire suffixes; truncation
/// and fallback state are explicit, never silent.
///
/// Scope notes (P1-1 minimal):
/// - Per-delegation minimization: `minimize` maps (full QNAME, known zone
///   cut, mode) to the next query name. Strict sends one label below the cut;
///   relaxed sends two (extra label absorbs empty non-terminals).
/// - Exceptions: NS qtype (delegation NS sets need the full QNAME) and the
///   root name (nothing to minimize) are never minimized.
/// - Fallback: `FallbackTracker` records per-zone minimization failures; at
///   `FALLBACK_THRESHOLD` the zone falls back to full QNAME until a success
///   clears it. Bounded at `MAX_FALLBACK_ZONES` with round-robin eviction.
/// - Cache isolation: responses cached under a minimized name serve only that
///   exact name (`cacheHitIsolated`). A referral for `example.com.` must never
///   answer a query for `www.example.com.`.
/// - Forwarder rule: minimization is an iterative-query policy. A forwarder
///   talking to a recursive upstream always sends the full QNAME; see
///   `forwarderQueryName`. No auth, DNSSEC, or DNS64 behavior lives here.
const std = @import("std");
const dns_name = @import("dns/name.zig");
const dns_types = @import("dns/types.zig");

pub const Mode = enum { disabled, relaxed, strict };

/// Consecutive minimization failures before a zone falls back to full QNAME.
pub const FALLBACK_THRESHOLD: u8 = 3;
/// Upper bound on tracked fallback zones; oldest slot is evicted past this.
pub const MAX_FALLBACK_ZONES: usize = 16;

/// Number of labels in a name, excluding the root terminator.
pub fn labelCount(name: *const dns_name.Name) usize {
    const wire = name.asWire();
    var count: usize = 0;
    var index: usize = 0;
    while (index < wire.len) {
        const len = wire[index];
        if (len == 0) break;
        count += 1;
        index += 1 + @as(usize, len);
    }
    return count;
}

/// The ancestor of `full` keeping the rightmost `keep` labels plus root.
/// Keeping at least the full label count returns the name unchanged.
pub fn ancestor(full: *const dns_name.Name, keep: usize) dns_name.Name {
    const wire = full.asWire();
    if (keep >= labelCount(full)) return full.*;
    var drop = labelCount(full) - keep;
    var index: usize = 0;
    while (drop > 0) : (drop -= 1) {
        index += 1 + @as(usize, wire[index]);
    }
    // A suffix cut at a label boundary of a valid name is itself valid wire.
    var buffer: [256]u8 = undefined;
    const rest = wire[index..];
    @memcpy(buffer[0..rest.len], rest);
    const parsed = dns_name.Name.parse(buffer[0..rest.len], 0) catch unreachable;
    return parsed.name;
}

/// The QNAME to send to the next delegation below a known zone cut with
/// `zone_labels` labels. Strict keeps one label below the cut, relaxed keeps
/// two; the result never exceeds the full QNAME.
pub fn minimize(full: *const dns_name.Name, zone_labels: usize, mode: Mode) dns_name.Name {
    return switch (mode) {
        .disabled => full.*,
        .strict => ancestor(full, zone_labels + 1),
        .relaxed => ancestor(full, zone_labels + 2),
    };
}

/// RFC 9156 minimization exceptions: NS queries carry the full QNAME so the
/// delegation NS set can be learned, and the root name has nothing to hide.
pub fn isException(qtype: dns_types.RecordType, name: *const dns_name.Name) bool {
    if (qtype.eql(dns_types.RecordType.NS)) return true;
    if (labelCount(name) == 0) return true;
    return false;
}

/// True when a minimized query is worth sending: enabled, not an exception,
/// and strictly shorter than the full QNAME.
pub fn shouldMinimize(
    qtype: dns_types.RecordType,
    full: *const dns_name.Name,
    zone: *const dns_name.Name,
    mode: Mode,
) bool {
    if (mode == .disabled) return false;
    if (isException(qtype, full)) return false;
    const minimized = minimize(full, labelCount(zone), mode);
    if (minimized.eql(full)) return false;
    return true;
}

/// A response cached under `stored` may serve a query for `queried` only on
/// exact-name match, so minimized referrals stay isolated from full queries.
pub fn cacheHitIsolated(stored: *const dns_name.Name, queried: *const dns_name.Name) bool {
    return stored.eql(queried);
}

/// Forwarder rule: a forwarder asking a recursive upstream always sends the
/// full QNAME regardless of mode. Resolver calls this hook so the policy
/// decision stays explicit for the future iterative path.
pub fn forwarderQueryName(full: *const dns_name.Name, mode: Mode) dns_name.Name {
    _ = mode;
    return full.*;
}

/// Bounded per-zone minimization-failure memory. After FALLBACK_THRESHOLD
/// consecutive failures a zone falls back to full QNAME; one success clears
/// the zone. Fixed capacity, no allocation.
pub const FallbackTracker = struct {
    zones: [MAX_FALLBACK_ZONES]dns_name.Name = undefined,
    counts: [MAX_FALLBACK_ZONES]u8 = [_]u8{0} ** MAX_FALLBACK_ZONES,
    len: usize = 0,
    next_evict: usize = 0,

    pub fn noteFailure(self: *FallbackTracker, zone: *const dns_name.Name) void {
        if (self.find(zone)) |index| {
            self.counts[index] = std.math.add(u8, self.counts[index], 1) catch std.math.maxInt(u8);
            return;
        }
        if (self.len < MAX_FALLBACK_ZONES) {
            self.zones[self.len] = zone.*;
            self.counts[self.len] = 1;
            self.len += 1;
            return;
        }
        self.zones[self.next_evict] = zone.*;
        self.counts[self.next_evict] = 1;
        self.next_evict = (self.next_evict + 1) % MAX_FALLBACK_ZONES;
    }

    pub fn noteSuccess(self: *FallbackTracker, zone: *const dns_name.Name) void {
        const index = self.find(zone) orelse return;
        self.len -= 1;
        self.zones[index] = self.zones[self.len];
        self.counts[index] = self.counts[self.len];
        self.counts[self.len] = 0;
    }

    pub fn fallbackActive(self: *const FallbackTracker, zone: *const dns_name.Name) bool {
        const index = self.find(zone) orelse return false;
        return self.counts[index] >= FALLBACK_THRESHOLD;
    }

    /// Full per-query decision: policy plus fallback state.
    pub fn shouldQueryMinimized(
        self: *const FallbackTracker,
        qtype: dns_types.RecordType,
        full: *const dns_name.Name,
        zone: *const dns_name.Name,
        mode: Mode,
    ) bool {
        if (!shouldMinimize(qtype, full, zone, mode)) return false;
        if (self.fallbackActive(zone)) return false;
        return true;
    }

    fn find(self: *const FallbackTracker, zone: *const dns_name.Name) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.zones[index].eql(zone)) return index;
        }
        return null;
    }
};

fn nameToText(name: *const dns_name.Name, buffer: []u8) []const u8 {
    return name.toText(buffer) catch unreachable;
}

test "strict walk minimizes one label below each delegation" {
    const full = try dns_name.Name.fromText("www.example.com.");
    const root = dns_name.Name.root();
    const com = try dns_name.Name.fromText("com.");
    const example = try dns_name.Name.fromText("example.com.");

    var text: [64]u8 = undefined;
    var minimized = minimize(&full, labelCount(&root), .strict);
    try std.testing.expectEqualStrings("com.", nameToText(&minimized, &text));
    minimized = minimize(&full, labelCount(&com), .strict);
    try std.testing.expectEqualStrings("example.com.", nameToText(&minimized, &text));
    minimized = minimize(&full, labelCount(&example), .strict);
    try std.testing.expectEqualStrings("www.example.com.", nameToText(&minimized, &text));
}

test "relaxed walk sends one extra label below each delegation" {
    const full = try dns_name.Name.fromText("www.example.com.");
    const root = dns_name.Name.root();
    const com = try dns_name.Name.fromText("com.");

    var text: [64]u8 = undefined;
    var minimized = minimize(&full, labelCount(&root), .relaxed);
    try std.testing.expectEqualStrings("example.com.", nameToText(&minimized, &text));
    minimized = minimize(&full, labelCount(&com), .relaxed);
    try std.testing.expectEqualStrings("www.example.com.", nameToText(&minimized, &text));
}

test "minimization never exceeds the full name" {
    const root = dns_name.Name.root();
    var text: [64]u8 = undefined;

    const minimized_root = minimize(&root, 0, .strict);
    try std.testing.expectEqualStrings(".", nameToText(&minimized_root, &text));

    const com = try dns_name.Name.fromText("com.");
    const minimized_com = minimize(&com, 0, .strict);
    try std.testing.expectEqualStrings("com.", nameToText(&minimized_com, &text));

    const full = try dns_name.Name.fromText("a.b.example.com.");
    const deep = try dns_name.Name.fromText("example.com.");
    const minimized_deep = minimize(&full, labelCount(&deep), .relaxed);
    try std.testing.expect(minimized_deep.eql(&full));

    const disabled = minimize(&full, 0, .disabled);
    try std.testing.expect(disabled.eql(&full));
}

test "NS qtype and root qname are minimization exceptions" {
    const full = try dns_name.Name.fromText("www.example.com.");
    const root = dns_name.Name.root();
    try std.testing.expect(isException(dns_types.RecordType.NS, &full));
    try std.testing.expect(isException(dns_types.RecordType.A, &root));
    try std.testing.expect(!isException(dns_types.RecordType.A, &full));
    try std.testing.expect(!isException(dns_types.RecordType.AAAA, &full));

    try std.testing.expect(!shouldMinimize(dns_types.RecordType.NS, &full, &root, .relaxed));
    try std.testing.expect(!shouldMinimize(dns_types.RecordType.A, &full, &root, .disabled));
    try std.testing.expect(shouldMinimize(dns_types.RecordType.A, &full, &root, .relaxed));
    try std.testing.expect(shouldMinimize(dns_types.RecordType.A, &full, &root, .strict));

    const example = try dns_name.Name.fromText("example.com.");
    try std.testing.expect(!shouldMinimize(dns_types.RecordType.A, &full, &example, .strict));
}

test "fallback tracker bounds minimization after repeated failures" {
    // Strict below the com. cut shortens www.example.com. to example.com.,
    // so the fallback transitions are observable (at the example.com. cut
    // strict already equals the full QNAME and never minimizes).
    const zone = try dns_name.Name.fromText("com.");
    const full = try dns_name.Name.fromText("www.example.com.");
    var tracker = FallbackTracker{};

    try std.testing.expect(tracker.shouldQueryMinimized(dns_types.RecordType.A, &full, &zone, .strict));
    tracker.noteFailure(&zone);
    tracker.noteFailure(&zone);
    try std.testing.expect(!tracker.fallbackActive(&zone));
    try std.testing.expect(tracker.shouldQueryMinimized(dns_types.RecordType.A, &full, &zone, .strict));
    tracker.noteFailure(&zone);
    try std.testing.expect(tracker.fallbackActive(&zone));
    try std.testing.expect(!tracker.shouldQueryMinimized(dns_types.RecordType.A, &full, &zone, .strict));
    tracker.noteSuccess(&zone);
    try std.testing.expect(!tracker.fallbackActive(&zone));
    try std.testing.expect(tracker.shouldQueryMinimized(dns_types.RecordType.A, &full, &zone, .strict));
    tracker.noteSuccess(&zone);
}

test "fallback tracker saturates counts and evicts oldest slot when full" {
    var tracker = FallbackTracker{};
    var first = try dns_name.Name.fromText("zone0.example.");
    tracker.noteFailure(&first);
    tracker.noteFailure(&first);
    tracker.noteFailure(&first);
    try std.testing.expect(tracker.fallbackActive(&first));

    var index: usize = 1;
    while (index < MAX_FALLBACK_ZONES) : (index += 1) {
        var text: [32]u8 = undefined;
        const zone_text = try std.fmt.bufPrint(&text, "zone{d}.example.", .{index});
        var zone = try dns_name.Name.fromText(zone_text);
        tracker.noteFailure(&zone);
    }
    try std.testing.expectEqual(MAX_FALLBACK_ZONES, tracker.len);

    var overflow = try dns_name.Name.fromText("overflow.example.");
    tracker.noteFailure(&overflow);
    try std.testing.expectEqual(MAX_FALLBACK_ZONES, tracker.len);
    try std.testing.expect(!tracker.fallbackActive(&first));
    // One failure is below FALLBACK_THRESHOLD, so the freshly admitted
    // overflow zone is tracked but not yet in fallback.
    try std.testing.expect(!tracker.fallbackActive(&overflow));

    var saturated = try dns_name.Name.fromText("saturated.example.");
    var count: usize = 0;
    while (count < 300) : (count += 1) tracker.noteFailure(&saturated);
    try std.testing.expect(tracker.fallbackActive(&saturated));
}

test "cache isolates minimized referrals from full queries" {
    const full = try dns_name.Name.fromText("www.example.com.");
    const root = dns_name.Name.root();
    var minimized = minimize(&full, labelCount(&root), .strict);

    try std.testing.expect(!cacheHitIsolated(&minimized, &full));
    try std.testing.expect(cacheHitIsolated(&minimized, &minimized));
    try std.testing.expect(cacheHitIsolated(&full, &full));

    const com = try dns_name.Name.fromText("com.");
    try std.testing.expect(minimized.eql(&com));
    var text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("com.", nameToText(&minimized, &text));
}

test "forwarder always sends the full QNAME in every mode" {
    const full = try dns_name.Name.fromText("www.example.com.");
    for ([_]Mode{ .disabled, .relaxed, .strict }) |mode| {
        const upstream = forwarderQueryName(&full, mode);
        try std.testing.expect(upstream.eql(&full));
    }
    const root = dns_name.Name.root();
    const upstream_root = forwarderQueryName(&root, .strict);
    try std.testing.expect(upstream_root.eql(&root));
}
