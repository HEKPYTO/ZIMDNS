//! RFC 5011 automated updates of DNSSEC trust anchors.
//!
//! The resolver keeps one trust point per configured DNSKEY anchor. A key is
//! trusted only after the add hold-down, a revocation takes effect the moment
//! a validated RRset proves it, and state survives a restart in a text file
//! the operator can inspect. This module is the state machine and its
//! serialization; the resolver does the network I/O and the file writes.

const std = @import("std");
const dns_name = @import("name.zig");
const dns_types = @import("types.zig");
const dnssec = @import("dnssec.zig");
const validate = @import("validate.zig");

/// RFC 5011 section 2.4.1: the add hold-down is 30 days or the original TTL
/// of the first DNSKEY RRset that carried the key, whichever is greater.
pub const add_hold_down_seconds: u64 = 30 * 24 * 60 * 60;
/// RFC 5011 section 2.4.2: the remove hold-down is 30 days.
pub const remove_hold_down_seconds: u64 = 30 * 24 * 60 * 60;
/// RFC 5011 section 2.3: no more often than once per hour.
pub const min_refresh_seconds: u64 = 60 * 60;
/// RFC 5011 section 2.3: no less often than 15 days.
pub const max_refresh_seconds: u64 = 15 * 24 * 60 * 60;
/// RFC 5011 section 2.3: a failed query is retried no less often than a day.
pub const max_retry_seconds: u64 = 24 * 60 * 60;
/// RFC 5011 section 2.4.3: a resolver manages at least five SEP keys per
/// trust point. The bound also keeps the state file and the scan finite.
pub const max_keys_per_point: usize = 8;
/// The trust points one process tracks. The configured DNSKEY anchors are
/// the usual set; eight covers a root plus every operator-run zone.
pub const max_points: usize = 8;
/// The state file is read in one piece and is never written past this size.
pub const max_state_bytes: usize = 1024 * 1024;

const revoke_flag: u16 = 0x0080;
const sep_flag: u16 = 0x0001;
const zone_key_flag: u16 = 0x0100;

pub const State = enum {
    /// RFC 5011 section 4.2: seen in a validated RRset, not yet a trust
    /// anchor. `timer` is the earliest acceptance time.
    add_pending,
    /// A trust anchor.
    valid,
    /// RFC 5011 section 4.2: a valid anchor that was absent from the last
    /// validated RRset. It stays a valid anchor.
    missing,
    /// RFC 5011 section 3: permanently invalid except to validate the
    /// revocation itself. Kept as a tombstone so a static anchor file that
    /// still names the key cannot resurrect it.
    revoked,

    fn text(self: State) []const u8 {
        return switch (self) {
            .add_pending => "addpend",
            .valid => "valid",
            .missing => "missing",
            .revoked => "revoked",
        };
    }

    fn parse(token: []const u8) ?State {
        if (std.mem.eql(u8, token, "addpend")) return .add_pending;
        if (std.mem.eql(u8, token, "valid")) return .valid;
        if (std.mem.eql(u8, token, "missing")) return .missing;
        if (std.mem.eql(u8, token, "revoked")) return .revoked;
        return null;
    }
};

pub const Error = error{
    BadState,
    TooManyPoints,
    TooManyKeys,
    OutOfMemory,
};

/// One key the resolver tracks for a trust point.
pub const ManagedKey = struct {
    /// DNSKEY RDATA in the form the zone published it, REVOKE bit clear.
    rdata: []u8,
    state: State,
    /// add_pending: earliest acceptance time. missing: when it went missing.
    /// revoked: zero, because a revocation is immediate.
    timer: u64 = 0,
    /// RFC 5011 section 2.2: the key tags that validated the RRset the key
    /// was first seen in. The acceptance is reset when all of them are
    /// revoked.
    validated_by: [max_keys_per_point]u16 = @splat(0),
    validated_by_len: u8 = 0,

    pub fn keyTag(self: *const ManagedKey) u16 {
        return dnssec.keyTag(self.rdata);
    }
};

pub const Point = struct {
    owner: dns_name.Name,
    keys: std.ArrayList(ManagedKey) = .empty,
    /// RFC 5011 section 2.3: the next time this trust point is queried.
    next_refresh: u64 = 0,
    /// The original TTL of the last validated DNSKEY RRset.
    ttl: u32 = 3600,
    /// The expiration of the last validated RRSIG over that RRset.
    expiration: u32 = 0,
};

/// The outcome of applying one DNSKEY RRset to a trust point.
pub const ObserveResult = enum {
    /// No signature verified with a current trust anchor; nothing changed.
    untrusted,
    /// Trusted, and the state did not move.
    unchanged,
    /// Trusted, and the persisted state moved.
    changed,
};

pub const ManagedAnchors = struct {
    allocator: std.mem.Allocator,
    points: std.ArrayList(Point) = .empty,
    /// The operator's anchors. When `owns_static` is set the store frees
    /// them; the live anchor set is a view over these slices, which outlive
    /// every rebuild.
    static: validate.Anchors = .{},
    owns_static: bool = false,

    /// A fresh store with no points. `bootstrap` then seeds it.
    pub fn init(allocator: std.mem.Allocator, static_anchors: validate.Anchors) ManagedAnchors {
        return .{ .allocator = allocator, .static = static_anchors };
    }

    pub fn deinit(self: *ManagedAnchors) void {
        for (self.points.items) |*point| {
            for (point.keys.items) |key| self.allocator.free(key.rdata);
            point.keys.deinit(self.allocator);
        }
        self.points.deinit(self.allocator);
        self.points = .empty;
        if (self.owns_static) {
            self.static.deinit(self.allocator);
            self.static = .{};
            self.owns_static = false;
        }
    }

    pub fn pointIndex(self: *const ManagedAnchors, owner: dns_name.Name) ?usize {
        for (self.points.items, 0..) |point, index| {
            if (point.owner.eql(&owner)) return index;
        }
        return null;
    }

    fn pointFor(self: *ManagedAnchors, owner: dns_name.Name) Error!*Point {
        if (self.pointIndex(owner)) |index| return &self.points.items[index];
        if (self.points.items.len >= max_points) return Error.TooManyPoints;
        try self.points.append(self.allocator, .{ .owner = owner });
        return &self.points.items[self.points.items.len - 1];
    }

    /// Seeds a trust point from every configured DNSKEY anchor. A key that a
    /// state file already revoked is not resurrected.
    /// Drops every trust point whose owner no configured DNSKEY anchor still
    /// names. Removing an anchor from `trust-anchor-file` is the operator's
    /// retraction; a state file written under the old configuration must not
    /// keep validating that owner.
    pub fn retainConfiguredOwners(self: *ManagedAnchors) void {
        var index: usize = 0;
        while (index < self.points.items.len) {
            const point = &self.points.items[index];
            if (self.configuredOwner(point.owner)) {
                index += 1;
                continue;
            }
            for (point.keys.items) |key| self.allocator.free(key.rdata);
            point.keys.deinit(self.allocator);
            _ = self.points.orderedRemove(index);
        }
    }

    fn configuredOwner(self: *const ManagedAnchors, owner: dns_name.Name) bool {
        for (self.static.items[0..self.static.len]) |anchor| {
            if (anchor.rrtype.eql(.DNSKEY) and anchor.owner.eql(&owner)) return true;
        }
        return false;
    }

    pub fn bootstrap(self: *ManagedAnchors) !void {
        for (self.static.items[0..self.static.len]) |anchor| {
            if (!anchor.rrtype.eql(.DNSKEY)) continue;
            const point = try self.pointFor(anchor.owner);
            if (self.findKey(point, anchor.rdata) != null) continue;
            if (point.keys.items.len >= max_keys_per_point) return Error.TooManyKeys;
            try point.keys.append(self.allocator, .{
                .rdata = try self.allocator.dupe(u8, anchor.rdata),
                .state = .valid,
            });
        }
    }

    /// True when a managed revocation names the key a static anchor holds.
    fn staticRevoked(self: *const ManagedAnchors, owner: dns_name.Name, rdata: []const u8) bool {
        const index = self.pointIndex(owner) orelse return false;
        for (self.points.items[index].keys.items) |key| {
            if (key.state == .revoked and sameKey(key.rdata, rdata)) return true;
        }
        return false;
    }

    /// The live anchor set: the static anchors a revocation did not invalidate
    /// plus every managed key that is valid or missing. RFC 5011 section 4.2:
    /// a missing key stays a valid trust-point key.
    pub fn liveAnchors(self: *const ManagedAnchors, out: *validate.Anchors) void {
        out.len = 0;
        for (self.static.items[0..self.static.len]) |anchor| {
            if (anchor.rrtype.eql(.DNSKEY) and self.staticRevoked(anchor.owner, anchor.rdata)) continue;
            self.pushAnchor(out, anchor);
        }
        for (self.points.items) |point| {
            if (!self.configuredOwner(point.owner)) continue;
            for (point.keys.items) |key| {
                if (key.state != .valid and key.state != .missing) continue;
                self.pushAnchor(out, .{ .owner = point.owner, .rrtype = .DNSKEY, .rdata = key.rdata });
            }
        }
    }

    fn pushAnchor(self: *const ManagedAnchors, out: *validate.Anchors, anchor: validate.Anchor) void {
        _ = self;
        if (out.len >= validate.max_anchors) return;
        for (out.items[0..out.len]) |existing| {
            if (!existing.owner.eql(&anchor.owner)) continue;
            if (!existing.rrtype.eql(anchor.rrtype)) continue;
            if (std.mem.eql(u8, existing.rdata, anchor.rdata)) return;
        }
        out.items[out.len] = anchor;
        out.len += 1;
    }

    /// The index of the trust point whose RFC 5011 refresh is due, or null.
    pub fn refreshDue(self: *const ManagedAnchors, now: u64) ?usize {
        for (self.points.items, 0..) |point, index| {
            if (point.next_refresh <= now) return index;
        }
        return null;
    }

    /// Records a successful validated fetch: RFC 5011 section 2.3's query
    /// interval, `MAX(1 hr, MIN(15 days, 1/2 TTL, 1/2 expireInterval))`.
    pub fn noteSuccess(self: *ManagedAnchors, index: usize, ttl: u32, expiration: u32, now: u64) void {
        const point = &self.points.items[index];
        point.ttl = ttl;
        point.expiration = expiration;
        var interval: u64 = max_refresh_seconds;
        interval = @min(interval, @as(u64, ttl) / 2);
        if (expiration > now) {
            interval = @min(interval, (expiration - now) / 2);
        } else {
            interval = 0;
        }
        interval = @max(min_refresh_seconds, interval);
        point.next_refresh = now + interval;
    }

    /// RFC 5011 section 2.3: a failed fetch retries at
    /// `MAX(1 hr, MIN(1 day, .1 TTL, .1 expireInterval))`.
    pub fn noteFailure(self: *ManagedAnchors, index: usize, now: u64) void {
        const point = &self.points.items[index];
        const ttl: u64 = if (point.ttl == 0) 86_400 else point.ttl;
        var interval: u64 = max_retry_seconds;
        interval = @min(interval, ttl / 10);
        if (point.expiration > now) {
            interval = @min(interval, (point.expiration - now) / 10);
        } else {
            interval = 0;
        }
        interval = @max(min_refresh_seconds, interval);
        point.next_refresh = now + interval;
    }

    /// Applies one DNSKEY RRset to the trust point at `index`. The caller has
    /// already established that at least one RRSIG over the RRset verifies
    /// with a currently trusted key; the verified tags name those signatures.
    ///
    /// Returns true when the persisted state changed.
    pub fn observe(
        self: *ManagedAnchors,
        index: usize,
        dnskey_rdatas: []const []const u8,
        verifier_tags: []const validate.DnskeySignature,
        ttl: u32,
        now: u64,
    ) !ObserveResult {
        const point = &self.points.items[index];
        var changed = false;

        // RFC 5011 section 2: only an RRset an existing trust anchor
        // authenticated may add, revoke, or remove a key.
        var trusted = false;
        for (verifier_tags) |signature| {
            if (self.keyTrusted(point, signature)) trusted = true;
        }
        // A key that revokes itself signs the revoked form, whose tag differs
        // from the anchor's. RFC 5011 section 2.1 lets that signature stand
        // for the revocation and nothing else, so it authenticates this RRset
        // only when the revoked key was a valid anchor.
        if (!trusted) {
            for (dnskey_rdatas) |rdata| {
                if (!hasRevokeBit(rdata) or rdata.len < 4) continue;
                if (!verifiedSignature(verifier_tags, rdata)) continue;
                if (self.findKey(point, rdata)) |key| {
                    if (key.state == .valid or key.state == .missing) trusted = true;
                }
            }
        }
        if (!trusted) return .untrusted;

        // RFC 5011 sections 2.1 and 3: a key with the REVOKE bit that signed
        // the DNSKEY RRset is revoked immediately. The bit without the
        // signature proves nothing.
        for (dnskey_rdatas) |rdata| {
            if (!hasRevokeBit(rdata)) continue;
            if (!verifiedSignature(verifier_tags, rdata)) continue;
            if (self.findKey(point, rdata)) |existing| {
                if (existing.state != .revoked) {
                    existing.state = .revoked;
                    existing.timer = now;
                    changed = true;
                }
            } else {
                if (point.keys.items.len >= max_keys_per_point) return Error.TooManyKeys;
                try point.keys.append(self.allocator, .{
                    .rdata = try self.allocator.dupe(u8, rdata),
                    .state = .revoked,
                    .timer = now,
                });
                changed = true;
            }
        }

        // The state table of RFC 5011 section 4.
        var cursor: usize = 0;
        while (cursor < point.keys.items.len) {
            const key = &point.keys.items[cursor];
            const present = dnskeyPresent(dnskey_rdatas, key.rdata);
            var remove = false;
            switch (key.state) {
                .add_pending => {
                    if (present) {
                        // RFC 5011 section 2.2: acceptance needs a validated
                        // RRset seen after the hold-down, which this is.
                        if (now >= key.timer) {
                            key.state = .valid;
                            changed = true;
                        }
                    } else {
                        remove = true;
                        changed = true;
                    }
                },
                .valid => if (!present) {
                    key.state = .missing;
                    key.timer = now;
                    changed = true;
                },
                .missing => if (present) {
                    key.state = .valid;
                    key.timer = 0;
                    changed = true;
                },
                .revoked => {
                    // RFC 5011 section 5: after the removal hold-down the
                    // key is gone from the trust point. A static anchor that
                    // still names it keeps its tombstone, or the static file
                    // would resurrect it on the next bootstrap.
                    if (!self.staticNames(point.owner, key.rdata) and key.timer != 0 and
                        now >= key.timer + remove_hold_down_seconds)
                    {
                        remove = true;
                        changed = true;
                    }
                },
            }
            if (remove) {
                self.allocator.free(key.rdata);
                _ = point.keys.orderedRemove(cursor);
                continue;
            }
            cursor += 1;
        }

        // RFC 5011 section 4.1, NewKey: a validated RRset with a SEP key the
        // resolver does not track starts the hold-down.
        for (dnskey_rdatas) |rdata| {
            // A key the state file cannot name back is not a key to track:
            // protocol 3 and a non-empty public key match what parseState and
            // the verifier accept.
            if (rdata.len <= 4 or rdata[2] != 3) continue;
            const flags = std.mem.readInt(u16, rdata[0..2], .big);
            if (flags & sep_flag == 0 or flags & zone_key_flag == 0) continue;
            if (flags & revoke_flag != 0) continue;
            if (self.findKey(point, rdata) != null or revokedTombstone(point, rdata)) continue;
            if (point.keys.items.len >= max_keys_per_point) return Error.TooManyKeys;
            var key = ManagedKey{
                .rdata = try self.allocator.dupe(u8, rdata),
                .state = .add_pending,
                .timer = now + @max(add_hold_down_seconds, ttl),
            };
            for (verifier_tags) |signature| {
                if (!self.keyTrusted(point, signature)) continue;
                if (key.validated_by_len == key.validated_by.len) break;
                key.validated_by[key.validated_by_len] = signature.key_tag;
                key.validated_by_len += 1;
            }
            try point.keys.append(self.allocator, key);
            changed = true;
        }

        // RFC 5011 section 2.2: when every key that validated a pending key
        // is revoked, the pending key is dropped.
        cursor = 0;
        while (cursor < point.keys.items.len) {
            const key = &point.keys.items[cursor];
            if (key.state != .add_pending or key.validated_by_len == 0) {
                cursor += 1;
                continue;
            }
            var all_revoked = true;
            for (key.validated_by[0..key.validated_by_len]) |tag| {
                if (!tagRevoked(point, tag)) {
                    all_revoked = false;
                    break;
                }
            }
            if (!all_revoked) {
                cursor += 1;
                continue;
            }
            self.allocator.free(key.rdata);
            _ = point.keys.orderedRemove(cursor);
            changed = true;
        }

        return if (changed) .changed else .unchanged;
    }

    fn findKey(self: *const ManagedAnchors, point: *const Point, rdata: []const u8) ?*ManagedKey {
        _ = self;
        for (point.keys.items) |*key| {
            if (sameKey(key.rdata, rdata)) return key;
        }
        return null;
    }

    /// True when the signature name a key that may trust a DNSKEY RRset:
    /// a managed key that is valid or missing, or a configured DNSKEY the
    /// managed state has not revoked. The tag identifies the published
    /// DNSKEY RDATA, so the algorithm is matched with it.
    fn keyTrusted(self: *const ManagedAnchors, point: *const Point, signature: validate.DnskeySignature) bool {
        for (point.keys.items) |key| {
            if (key.state != .valid and key.state != .missing) continue;
            if (key.rdata.len < 4) continue;
            if (key.rdata[3] != signature.algorithm) continue;
            if (key.keyTag() != signature.key_tag) continue;
            if (digestEqual(key.rdata, signature.key_digest)) return true;
        }
        for (self.static.items[0..self.static.len]) |anchor| {
            if (!anchor.rrtype.eql(.DNSKEY)) continue;
            if (!anchor.owner.eql(&point.owner)) continue;
            if (anchor.rdata.len < 4 or anchor.rdata[3] != signature.algorithm) continue;
            if (self.staticRevoked(anchor.owner, anchor.rdata)) continue;
            if (dnssec.keyTag(anchor.rdata) != signature.key_tag) continue;
            if (digestEqual(anchor.rdata, signature.key_digest)) return true;
        }
        return false;
    }

    fn staticNames(self: *const ManagedAnchors, owner: dns_name.Name, rdata: []const u8) bool {
        for (self.static.items[0..self.static.len]) |anchor| {
            if (!anchor.rrtype.eql(.DNSKEY) or !anchor.owner.eql(&owner)) continue;
            if (sameKey(anchor.rdata, rdata)) return true;
        }
        return false;
    }

    fn tagRevoked(point: *const Point, tag: u16) bool {
        for (point.keys.items) |key| {
            if (key.state != .revoked) continue;
            if (key.keyTag() == tag) return true;
        }
        return false;
    }

    /// A revoked key whose published form differs only in the REVOKE bit is
    /// the same key; RFC 5011 section 2.1 warns the fingerprints differ.
    fn revokedTombstone(point: *const Point, rdata: []const u8) bool {
        for (point.keys.items) |key| {
            if (key.state == .revoked and sameKey(key.rdata, rdata)) return true;
        }
        return false;
    }

    /// Serializes the state to the text the loader reads back.
    pub fn serialize(self: *const ManagedAnchors, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "# zimdns managed trust anchors (RFC 5011); generated, do not edit by hand\n");
        for (self.points.items) |point| {
            var owner_buffer: [256]u8 = undefined;
            const owner_text = point.owner.toText(&owner_buffer) catch return Error.BadState;
            for (point.keys.items) |key| {
                const encoded = try encodeBase64(allocator, key.rdata[4..]);
                defer allocator.free(encoded);
                var tags_buffer: [max_keys_per_point * 6]u8 = undefined;
                var tags_len: usize = 0;
                for (key.validated_by[0..key.validated_by_len], 0..) |tag, tag_index| {
                    if (tag_index != 0) {
                        tags_buffer[tags_len] = ',';
                        tags_len += 1;
                    }
                    const written = std.fmt.bufPrint(tags_buffer[tags_len..], "{d}", .{tag}) catch return Error.BadState;
                    tags_len += written.len;
                }
                const tags = if (tags_len == 0) "-" else tags_buffer[0..tags_len];
                const flags = std.mem.readInt(u16, key.rdata[0..2], .big);
                const line = try std.fmt.allocPrint(allocator, "{s} {d} {d} {d} {s} {s} {d} {s}\n", .{
                    owner_text, flags, key.rdata[2], key.rdata[3], encoded, key.state.text(), key.timer, tags,
                });
                defer allocator.free(line);
                try out.appendSlice(allocator, line);
            }
        }
        return out.toOwnedSlice(allocator);
    }

    /// Reads the state `serialize` wrote. A malformed line refuses the file:
    /// a trust-anchor store that half-parsed would silently change the trust
    /// domain.
    pub fn parseState(self: *ManagedAnchors, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const hash = std.mem.indexOfScalar(u8, raw_line, '#') orelse raw_line.len;
            const line = std.mem.trim(u8, raw_line[0..hash], " \t\r");
            if (line.len == 0) continue;
            var tokens = std.mem.tokenizeAny(u8, line, " \t");
            const owner = dns_name.Name.fromText(tokens.next() orelse return Error.BadState) catch return Error.BadState;
            const flags = std.fmt.parseInt(u16, tokens.next() orelse return Error.BadState, 10) catch return Error.BadState;
            const protocol = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadState, 10) catch return Error.BadState;
            if (protocol != 3) return Error.BadState;
            const algorithm = std.fmt.parseInt(u8, tokens.next() orelse return Error.BadState, 10) catch return Error.BadState;
            const key_text = tokens.next() orelse return Error.BadState;
            const state = State.parse(tokens.next() orelse return Error.BadState) orelse return Error.BadState;
            const timer = std.fmt.parseInt(u64, tokens.next() orelse return Error.BadState, 10) catch return Error.BadState;
            const tags_text = tokens.next() orelse return Error.BadState;
            if (tokens.next() != null) return Error.BadState;

            const key_len = std.base64.standard.Decoder.calcSizeForSlice(key_text) catch return Error.BadState;
            if (key_len == 0 or key_len > validate_max_rdata - 4) return Error.BadState;
            const rdata = try self.allocator.alloc(u8, 4 + key_len);
            errdefer self.allocator.free(rdata);
            std.mem.writeInt(u16, rdata[0..2], flags, .big);
            rdata[2] = protocol;
            rdata[3] = algorithm;
            std.base64.standard.Decoder.decode(rdata[4..], key_text) catch return Error.BadState;

            const point = try self.pointFor(owner);
            if (point.keys.items.len >= max_keys_per_point) return Error.TooManyKeys;
            var key = ManagedKey{ .rdata = rdata, .state = state, .timer = timer };
            if (!std.mem.eql(u8, tags_text, "-")) {
                var tags = std.mem.splitScalar(u8, tags_text, ',');
                while (tags.next()) |tag_text| {
                    if (key.validated_by_len == key.validated_by.len) return Error.BadState;
                    key.validated_by[key.validated_by_len] = std.fmt.parseInt(u16, tag_text, 10) catch return Error.BadState;
                    key.validated_by_len += 1;
                }
            }
            try point.keys.append(self.allocator, key);
        }
    }

    pub fn revokedCount(self: *const ManagedAnchors) usize {
        var count: usize = 0;
        for (self.points.items) |point| {
            for (point.keys.items) |key| {
                if (key.state == .revoked) count += 1;
            }
        }
        return count;
    }
};

/// Writes the state through a temporary file beside it and renames it, so a
/// crash leaves the old store or the new one.
pub fn writeFile(io: std.Io, dir: std.Io.Dir, allocator: std.mem.Allocator, path: []const u8, text: []const u8) !void {
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(temp_path);
    const file = try dir.createFile(io, temp_path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, text);
    try file.sync(io);
    try dir.rename(temp_path, dir, path, io);
}

/// The largest RDATA this store accepts, matching the opaque RDATA ceiling
/// the wire parser uses.
const validate_max_rdata: usize = 2048;

fn encodeBase64(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const length = std.base64.standard.Encoder.calcSize(bytes.len);
    const out = try allocator.alloc(u8, length);
    _ = std.base64.standard.Encoder.encode(out, bytes);
    return out;
}

fn hasRevokeBit(rdata: []const u8) bool {
    return rdata.len >= 2 and (std.mem.readInt(u16, rdata[0..2], .big) & revoke_flag) != 0;
}

fn verifiedSignature(tags: []const validate.DnskeySignature, rdata: []const u8) bool {
    if (rdata.len < 4) return false;
    const key_tag = dnssec.keyTag(rdata);
    for (tags) |signature| {
        if (signature.key_tag != key_tag or signature.algorithm != rdata[3]) continue;
        if (digestEqual(rdata, signature.key_digest)) return true;
    }
    return false;
}

fn digestEqual(rdata: []const u8, digest: [32]u8) bool {
    const actual = validate.dnskeyDigest(rdata);
    return std.mem.eql(u8, &actual, &digest);
}

fn dnskeyPresent(rdatas: []const []const u8, rdata: []const u8) bool {
    for (rdatas) |candidate| {
        if (sameKey(candidate, rdata)) return true;
    }
    return false;
}

/// Two DNSKEY RDATA name the same key when they differ at most in the
/// REVOKE bit of RFC 5011 section 3.
fn sameKey(left: []const u8, right: []const u8) bool {
    if (left.len != right.len or left.len < 4) return false;
    if (left[2] != right[2] or left[3] != right[3]) return false;
    const left_flags = std.mem.readInt(u16, left[0..2], .big) & ~revoke_flag;
    const right_flags = std.mem.readInt(u16, right[0..2], .big) & ~revoke_flag;
    if (left_flags != right_flags) return false;
    return std.mem.eql(u8, left[4..], right[4..]);
}

// ------------------------------------------------------------------ tests

const fixture_key_tag: u16 = 35217;

fn testAnchors(allocator: std.mem.Allocator) !validate.Anchors {
    var anchors = validate.Anchors{};
    const parsed = try validate.Anchors.parse(allocator, ". DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=\n");
    anchors.items[0] = parsed.items[0];
    anchors.len = 1;
    return anchors;
}

fn testKey(allocator: std.mem.Allocator, flags: u16) ![]u8 {
    const public = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";
    const key_len = try std.base64.standard.Decoder.calcSizeForSlice(public);
    const rdata = try allocator.alloc(u8, 4 + key_len);
    std.mem.writeInt(u16, rdata[0..2], flags, .big);
    rdata[2] = 3;
    rdata[3] = 15;
    try std.base64.standard.Decoder.decode(rdata[4..], public);
    return rdata;
}

fn verifier(allocator: std.mem.Allocator, rdata: []const u8) ![]validate.DnskeySignature {
    const tags = try allocator.alloc(validate.DnskeySignature, 1);
    tags[0] = .{ .key_tag = fixture_key_tag, .algorithm = 15, .key_digest = validate.dnskeyDigest(rdata) };
    return tags;
}

test "RFC 5011 section 2.2: a new SEP key waits out the add hold-down" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();
    try std.testing.expectEqual(@as(usize, 1), managed.points.items.len);

    const existing = try testKey(allocator, 257);
    const fresh = try testKey(allocator, 257);
    fresh[4] ^= 0x01; // a different key body
    const keys = [_][]const u8{ existing, fresh };
    const tags = try verifier(allocator, existing);

    // The first validated RRset that carries the new key starts the timer.
    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &keys, tags, 3600, 1_000));
    try std.testing.expectEqual(State.add_pending, managed.points.items[0].keys.items[1].state);

    // A validated RRset after the hold-down accepts it.
    const later = 1_000 + add_hold_down_seconds;
    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &keys, tags, 3600, later));
    try std.testing.expectEqual(State.valid, managed.points.items[0].keys.items[1].state);

    // A validated RRset without it marks the live key missing but still
    // trusted (RFC 5011 section 4.2).
    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &.{fresh}, tags, 3600, later + 1));
    try std.testing.expectEqual(State.missing, managed.points.items[0].keys.items[0].state);
    try std.testing.expectEqual(State.valid, managed.points.items[0].keys.items[1].state);
}

test "RFC 5011 section 2.2: a pending key is dropped when it leaves the RRset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    const existing = try testKey(allocator, 257);
    const fresh = try testKey(allocator, 257);
    fresh[4] ^= 0x01;
    const tags = try verifier(allocator, existing);

    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &.{ existing, fresh }, tags, 3600, 1_000));
    try std.testing.expectEqual(@as(usize, 2), managed.points.items[0].keys.items.len);
    _ = try managed.observe(0, &.{existing}, tags, 3600, 2_000);
    try std.testing.expectEqual(@as(usize, 1), managed.points.items[0].keys.items.len);
}

test "RFC 5011 section 3: the REVOKE bit with its own signature revokes the key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    const revoked = try testKey(allocator, 257 | revoke_flag);
    var tags_buf: [1]validate.DnskeySignature = undefined;
    tags_buf[0] = .{ .key_tag = dnssec.keyTag(revoked), .algorithm = 15, .key_digest = validate.dnskeyDigest(revoked) };

    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &.{revoked}, &tags_buf, 3600, 5_000));
    try std.testing.expectEqual(State.revoked, managed.points.items[0].keys.items[0].state);

    // The revoked key is not a live anchor, and the static file that still
    // names it cannot bring it back.
    var live = validate.Anchors{};
    managed.liveAnchors(&live);
    try std.testing.expectEqual(@as(usize, 0), live.len);

    // The bit alone, with no signature by that key, proves nothing.
    var other = ManagedAnchors.init(allocator, static);
    defer other.deinit();
    try other.bootstrap();
    var wrong: [1]validate.DnskeySignature = undefined;
    wrong[0] = .{ .key_tag = fixture_key_tag, .algorithm = 15, .key_digest = validate.dnskeyDigest(revoked) };
    _ = try other.observe(0, &.{revoked}, &wrong, 3600, 5_000);
    try std.testing.expectEqual(State.valid, other.points.items[0].keys.items[0].state);
}

test "RFC 5011 section 2: a 16-bit tag collision alone does not authenticate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    const existing = try testKey(allocator, 257);
    const impostor = try testKey(allocator, 257);
    impostor[4] ^= 0x01;
    // The tag names the anchor, but the digest belongs to another key: the
    // signature did not verify with the trust anchor.
    var forged: [1]validate.DnskeySignature = undefined;
    forged[0] = .{ .key_tag = fixture_key_tag, .algorithm = 15, .key_digest = validate.dnskeyDigest(impostor) };
    _ = try managed.observe(0, &.{existing}, &forged, 3600, 1_000);
    try std.testing.expectEqual(@as(usize, 1), managed.points.items[0].keys.items.len);
    try std.testing.expectEqual(State.valid, managed.points.items[0].keys.items[0].state);
}

test "RFC 5011 section 5: a managed-only revoked key leaves the state after the hold-down" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    const existing = try testKey(allocator, 257);
    const revoked = try testKey(allocator, 257 | revoke_flag);
    revoked[4] ^= 0x01;
    var tags: [2]validate.DnskeySignature = undefined;
    tags[0] = .{ .key_tag = fixture_key_tag, .algorithm = 15, .key_digest = validate.dnskeyDigest(existing) };
    tags[1] = .{ .key_tag = dnssec.keyTag(revoked), .algorithm = 15, .key_digest = validate.dnskeyDigest(revoked) };

    try std.testing.expectEqual(ObserveResult.changed, try managed.observe(0, &.{ existing, revoked }, &tags, 3600, 1_000));
    try std.testing.expectEqual(@as(usize, 2), managed.points.items[0].keys.items.len);
    // Still inside the removal hold-down: the tombstone stays.
    _ = try managed.observe(0, &.{existing}, &tags, 3600, 1_000 + remove_hold_down_seconds - 1);
    try std.testing.expectEqual(@as(usize, 2), managed.points.items[0].keys.items.len);
    _ = try managed.observe(0, &.{existing}, &tags, 3600, 1_000 + remove_hold_down_seconds);
    try std.testing.expectEqual(@as(usize, 1), managed.points.items[0].keys.items.len);
    try std.testing.expectEqual(State.valid, managed.points.items[0].keys.items[0].state);
}

test "RFC 5011 section 2.2: a protocol-2 or empty DNSKEY is not tracked" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    const existing = try testKey(allocator, 257);
    const bad_protocol = try testKey(allocator, 257);
    bad_protocol[2] = 2;
    const empty = try allocator.dupe(u8, &[_]u8{ 1, 1, 3, 15 });
    const tags = try verifier(allocator, existing);
    _ = try managed.observe(0, &.{ existing, bad_protocol, empty }, tags, 3600, 1_000);
    try std.testing.expectEqual(@as(usize, 1), managed.points.items[0].keys.items.len);
}

test "an owner whose static anchor was removed does not outlive the configuration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    var encoded_buffer: [64]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encoded_buffer, static.items[0].rdata[4..]);
    const state = try std.fmt.allocPrint(allocator, "other.example. 257 3 15 {s} valid 0 -\n", .{encoded});
    try managed.parseState(state);
    try std.testing.expectEqual(@as(usize, 1), managed.points.items.len);
    managed.retainConfiguredOwners();
    try std.testing.expectEqual(@as(usize, 0), managed.points.items.len);
}

test "RFC 5011 section 2.3: the refresh interval and its retry bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();

    managed.noteSuccess(0, 3600, 120_000, 60_000);
    // Half the TTL is 30 minutes, below the section 2.3 hour floor.
    try std.testing.expectEqual(@as(u64, 60_000 + 3600), managed.points.items[0].next_refresh);
    // A failed fetch waits at least the section 2.3 hour, even though ten
    // percent of this TTL is six minutes.
    managed.noteFailure(0, 60_000);
    try std.testing.expectEqual(@as(u64, 60_000 + 3600), managed.points.items[0].next_refresh);
    try std.testing.expect(managed.refreshDue(63_599) == null);
}

test "the state file round-trips and refuses a malformed line" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try testAnchors(allocator);
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();
    const text = try managed.serialize(allocator);

    var restored = ManagedAnchors.init(allocator, static);
    defer restored.deinit();
    try restored.parseState(text);
    try std.testing.expectEqual(@as(usize, 1), restored.points.items.len);
    var live = validate.Anchors{};
    restored.liveAnchors(&live);
    try std.testing.expectEqual(@as(usize, 1), live.len);
    try std.testing.expectEqual(fixture_key_tag, dnssec.keyTag(live.items[0].rdata));

    try std.testing.expectError(Error.BadState, restored.parseState("example. 257 3 15 not-base64 valid 0 -\n"));
}

test "a static DS anchor stays live and is never managed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const static = try validate.Anchors.parse(allocator, "example. DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=\nexample. DS 35217 15 2 0000000000000000000000000000000000000000000000000000000000000000\n");
    var managed = ManagedAnchors.init(allocator, static);
    defer managed.deinit();
    try managed.bootstrap();
    try std.testing.expectEqual(@as(usize, 1), managed.points.items.len);
    var live = validate.Anchors{};
    managed.liveAnchors(&live);
    try std.testing.expectEqual(@as(usize, 2), live.len);
}
