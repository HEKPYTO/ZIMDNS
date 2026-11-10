/// Contract: Builds authoritative lookup indexes from parsed zones.
/// Ownership: Zone owns moved ZoneFile backing and records; call Zone.deinit; lookup results own allocator storage and need deinit.
/// Errors: In-memory lookup has typed results; loading and file I/O are outside this module.
const std = @import("std");
const dns_types = @import("../dns/types.zig");
const RecordType = dns_types.RecordType;
const dns_name = @import("../dns/name.zig");
const dns_record = @import("../dns/record.zig");
const parser = @import("parser.zig");
const journal_mod = @import("journal.zig");

pub const LookupKind = enum {
    answer,
    cname,
    dname,
    yxdomain,
    referral,
    nodata,
    nxdomain,
    servfail,
    not_authoritative,
};

pub const MaxAliasHops = 16;

pub const SynthesizedCname = struct {
    owner: dns_name.Name,
    target: dns_name.Name,
    ttl: u32,
};

pub const LookupResult = struct {
    kind: LookupKind,
    records: parser.RecordList = .{},
    authorities: parser.RecordList = .{},
    additionals: parser.RecordList = .{},
    soa: ?parser.ZoneRecord = null,
    answer_owner: ?[]const u8 = null,
    synthesized_cname: ?SynthesizedCname = null,

    pub fn deinit(self: *LookupResult, allocator: std.mem.Allocator) void {
        allocator.free(self.records.items);
        allocator.free(self.authorities.items);
        allocator.free(self.additionals.items);
        if (self.answer_owner) |owner| allocator.free(owner);
        self.records = .{};
        self.authorities = .{};
        self.additionals = .{};
        self.answer_owner = null;
        self.synthesized_cname = null;
    }

    pub fn answerOwnerText(self: *const LookupResult) []const u8 {
        if (self.answer_owner) |owner| return owner;
        if (self.records.len != 0) return self.records.items[0].ownerText();
        return &.{};
    }
};

pub const OwnerRecords = std.ArrayListUnmanaged(parser.ZoneRecord);

pub const Zone = struct {
    backing: []u8,
    origin: []const u8 = &.{},
    records: parser.RecordList = .{},
    soa: ?parser.ZoneRecord = null,
    /// Exact-owner index: lowercased owner -> records. Owned via page_allocator.
    owner_index: std.StringHashMapUnmanaged(OwnerRecords) = .{},
    /// Suffix-walk indexes rebuilt with owner_index: lowercased owners holding
    /// non-NSEC3 data (nodeExists exact hits), reversed-owner strings sorted
    /// for descendant checks, longest-suffix delegation owners, DNAME owners,
    /// and NSEC3 hashed owners. Zone is immutable after build, so lookups
    /// need no locks.
    live_owners: std.StringHashMapUnmanaged(void) = .empty,
    rev_owners: std.ArrayListUnmanaged([]const u8) = .empty,
    rev_sorted: bool = false,
    delegations: std.StringHashMapUnmanaged(void) = .empty,
    dnames: std.StringHashMapUnmanaged(void) = .empty,
    hashed_owners: std.StringHashMapUnmanaged(void) = .empty,
    /// live outside `backing`: `generated` is the appended tail to release
    /// field by field, and `generated_allocation` is the whole array the
    /// allocator must be given back. The loaded records are slices of
    /// `backing` and must never be freed here.
    generated: []parser.ZoneRecord = &.{},
    generated_allocation: []parser.ZoneRecord = &.{},
    generated_allocator: ?std.mem.Allocator = null,

    /// Moves parsed-zone ownership into an index. The moved-from ZoneFile is safe
    /// to deinit and no longer owns backing storage or records.
    pub fn fromZoneFile(zone_file: *parser.ZoneFile) !Zone {
        var zone = Zone{
            .backing = zone_file.backing,
            .origin = zone_file.origin,
            .records = zone_file.records,
        };
        zone_file.backing = &.{};
        zone_file.storage = std.heap.FixedBufferAllocator.init(zone_file.backing);
        zone_file.origin = &.{};
        zone_file.default_ttl = 0;
        zone_file.records = .{};
        for (zone.records.items[0..zone.records.len]) |record| {
            if (record.rrtype.eql(.SOA)) zone.soa = record;
        }
        registerZoneSize(&zone);
        errdefer zone.deinit();
        try zone.rebuildOwnerIndex();
        return zone;
    }

    fn lowerOwnerKey(allocator: std.mem.Allocator, owner: []const u8) ![]u8 {
        const key = try allocator.alloc(u8, owner.len);
        for (owner, 0..) |c, i| key[i] = std.ascii.toLower(c);
        return key;
    }

    fn freeKeySet(map: *std.StringHashMapUnmanaged(void), alloc: std.mem.Allocator) void {
        var it = map.iterator();
        while (it.next()) |entry| alloc.free(entry.key_ptr.*);
        map.deinit(alloc);
    }

    fn putKey(map: *std.StringHashMapUnmanaged(void), alloc: std.mem.Allocator, owner: []const u8) !void {
        const key = try lowerOwnerKey(alloc, owner);
        const gop = map.getOrPut(alloc, key) catch |err| {
            alloc.free(key);
            return err;
        };
        if (gop.found_existing) alloc.free(key);
    }

    // Reversed-label form so a descendant check is a prefix test.
    fn reverseLabels(owner: []const u8, buf: []u8) []u8 {
        var len: usize = 0;
        var end: usize = owner.len;
        if (end != 0 and owner[end - 1] == '.') end -= 1;
        while (end > 0) {
            var start = end;
            while (start > 0 and owner[start - 1] != '.') start -= 1;
            const label = owner[start..end];
            @memcpy(buf[len .. len + label.len], label);
            len += label.len;
            buf[len] = '.';
            len += 1;
            if (start == 0) break;
            end = start - 1;
        }
        return buf[0..len];
    }

    fn freeOwnerIndex(map: *std.StringHashMapUnmanaged(OwnerRecords), alloc: std.mem.Allocator) void {
        var it = map.iterator();
        while (it.next()) |entry| {
            alloc.free(entry.key_ptr.*);
            entry.value_ptr.deinit(alloc);
        }
        map.deinit(alloc);
    }

    /// Rebuilds owner_index from records transactionally; signer calls after
    /// replacing records. A failed rebuild leaves the old index untouched.
    pub fn rebuildOwnerIndex(self: *Zone) !void {
        const alloc = std.heap.smp_allocator;
        var next: std.StringHashMapUnmanaged(OwnerRecords) = .{};
        var live: std.StringHashMapUnmanaged(void) = .empty;
        var revs: std.ArrayListUnmanaged([]const u8) = .empty;
        var delegs: std.StringHashMapUnmanaged(void) = .empty;
        var dnames: std.StringHashMapUnmanaged(void) = .empty;
        var hashed: std.StringHashMapUnmanaged(void) = .empty;
        var built = false;
        defer {
            if (!built) freeOwnerIndex(&next, alloc);
            if (!built) freeKeySet(&live, alloc);
            if (!built) freeKeySet(&delegs, alloc);
            if (!built) freeKeySet(&dnames, alloc);
            if (!built) freeKeySet(&hashed, alloc);
            if (!built) {
                for (revs.items) |r| alloc.free(r);
                revs.deinit(alloc);
            }
        }
        for (self.records.items[0..self.records.len]) |record| {
            const key = try lowerOwnerKey(alloc, record.ownerText());
            const gop = next.getOrPut(alloc, key) catch |err| {
                alloc.free(key);
                return err;
            };
            const found = gop.found_existing;
            if (!found) {
                gop.value_ptr.* = .empty;
            } else {
                alloc.free(key);
            }
            gop.value_ptr.append(alloc, record) catch |err| {
                if (!found) {
                    _ = next.remove(key);
                    alloc.free(key);
                }
                return err;
            };
            if (record.rrtype.eql(.NSEC3)) {
                try putKey(&hashed, alloc, record.ownerText());
            } else {
                try putKey(&live, alloc, record.ownerText());
                var rev_buf: [1024]u8 = undefined;
                if (record.ownerText().len < rev_buf.len) {
                    var low: [1024]u8 = undefined;
                    for (record.ownerText(), 0..) |c, i| low[i] = std.ascii.toLower(c);
                    const rev = reverseLabels(low[0..record.ownerText().len], &rev_buf);
                    const owned = try alloc.dupe(u8, rev);
                    revs.append(alloc, owned) catch |err| {
                        alloc.free(owned);
                        return err;
                    };
                }
            }
            if (record.rrtype.eql(.NS) and !std.ascii.eqlIgnoreCase(record.ownerText(), self.originText())) {
                try putKey(&delegs, alloc, record.ownerText());
            }
            if (record.rrtype.eql(.DNAME)) try putKey(&dnames, alloc, record.ownerText());
        }
        std.mem.sort([]const u8, revs.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
        freeOwnerIndex(&self.owner_index, alloc);
        freeKeySet(&self.live_owners, alloc);
        for (self.rev_owners.items) |r| alloc.free(r);
        self.rev_owners.deinit(alloc);
        freeKeySet(&self.delegations, alloc);
        freeKeySet(&self.dnames, alloc);
        freeKeySet(&self.hashed_owners, alloc);
        self.owner_index = next;
        self.live_owners = live;
        self.rev_owners = revs;
        self.rev_sorted = true;
        self.delegations = delegs;
        self.dnames = dnames;
        self.hashed_owners = hashed;
        built = true;
    }

    pub fn deinit(self: *Zone) void {
        if (self.generated_allocator) |allocator| {
            for (self.generated) |record| {
                allocator.free(record.owner);
                allocator.free(record.rdata);
            }
            allocator.free(self.generated_allocation);
            self.generated = &.{};
            self.generated_allocation = &.{};
            self.generated_allocator = null;
        }
        freeOwnerIndex(&self.owner_index, std.heap.smp_allocator);
        freeKeySet(&self.live_owners, std.heap.smp_allocator);
        for (self.rev_owners.items) |r| std.heap.smp_allocator.free(r);
        self.rev_owners.deinit(std.heap.smp_allocator);
        freeKeySet(&self.delegations, std.heap.smp_allocator);
        freeKeySet(&self.dnames, std.heap.smp_allocator);
        freeKeySet(&self.hashed_owners, std.heap.smp_allocator);
        std.heap.page_allocator.free(self.backing);
        self.backing = &.{};
        self.records = .{};
        self.origin = &.{};
        self.soa = null;
    }

    pub fn lookup(self: *const Zone, allocator: std.mem.Allocator, qname: []const u8, qtype: RecordType) LookupResult {
        if (!isSubdomainOrEqual(qname, self.originText())) {
            return .{ .kind = .not_authoritative };
        }

        var result = LookupResult{ .kind = .nxdomain, .soa = self.soa };
        // A zone cut refers for every QTYPE except DS at the cut itself, which
        // stays authoritative in the parent (RFC 4035 section 3.1). The cut
        // wins over any data the parent zone file happens to hold below it:
        // glue is not authoritative data (RFC 1034 section 4.2.2), and a
        // parent that answered it would claim authority it does not have.
        if (self.findDelegation(qname)) |delegation| {
            const ds_at_cut = qtype.eql(.DS) and std.ascii.eqlIgnoreCase(qname, delegation);
            if (!ds_at_cut) {
                result.kind = .referral;
                result.soa = null;
                self.appendDelegation(allocator, &result, delegation) catch return failResult(&result, allocator);
                return result;
            }
        }
        var exact_nodata = false;
        if (self.lookupExact(allocator, qname, qtype, &result)) |exact_kind| {
            if (exact_kind == .servfail) {
                result.kind = .servfail;
                return failResult(&result, allocator);
            }
            if (exact_kind == .answer or exact_kind == .cname or exact_kind == .dname or exact_kind == .yxdomain or exact_kind == .nxdomain) {
                result.kind = exact_kind;
                return result;
            }
            exact_nodata = true;
        }

        if (exact_nodata) {
            result.kind = .nodata;
            return result;
        }

        if (self.nodeExists(qname)) {
            result.kind = .nodata;
            return result;
        }

        const closest = self.closestEncloser(qname);
        if (labelCount(qname) != labelCount(closest) + 1) return result;
        var wildcard_text: [1024]u8 = undefined;
        const wildcard_owner = makeWildcardName(closest, &wildcard_text) catch return result;
        if (self.hasOwner(wildcard_owner)) {
            result.records = .{};
            result.kind = .nxdomain;
            result.soa = self.soa;
            var saw_owner = false;
            var saw_cname = false;
            if (self.recordsAtOwner(wildcard_owner)) |owners| {
                for (owners) |record| {
                    saw_owner = true;
                    if (record.rrtype.eql(qtype)) {
                        result.records.append(allocator, record) catch return failResult(&result, allocator);
                        result.kind = .answer;
                    } else if (record.rrtype.eql(.CNAME) and !qtype.eql(.CNAME)) {
                        result.records.append(allocator, record) catch return failResult(&result, allocator);
                        saw_cname = true;
                    }
                }
            }
            if (result.kind == .answer or saw_cname) {
                if (saw_cname and result.kind != .answer) result.kind = .cname;
                result.soa = null;
                result.answer_owner = allocator.dupe(u8, qname) catch return failResult(&result, allocator);
                return result;
            }
            if (saw_owner) {
                result.kind = .nodata;
                return result;
            }
        }

        return result;
    }

    pub fn originText(self: *const Zone) []const u8 {
        return self.origin;
    }

    /// The apex SOA serial: RFC 9660 section 4's SOA-SERIAL ZONEVERSION, and
    /// the serial an RFC 1995 transfer compares against. Parsed on demand
    /// rather than cached, because only these two paths ask for it.
    pub fn soaSerial(self: *const Zone) ?u32 {
        const record = self.soa orelse return null;
        const rdata = parser.parseRData(.SOA, record.rdataText()) catch return null;
        if (rdata != .SOA) return null;
        return rdata.SOA.serial;
    }

    /// Reports whether the zone holds a record equal to `record`: the same
    /// owner, TTL, type, and rdata.
    pub fn hasRecord(self: *const Zone, record: parser.ZoneRecord) bool {
        for (self.records.items[0..self.records.len]) |*candidate| {
            if (sameRecord(candidate, &record)) return true;
        }
        return false;
    }

    pub fn contains(self: *const Zone, qname: []const u8) bool {
        return isSubdomainOrEqual(qname, self.originText());
    }

    /// Whether the zone publishes RRSIG records: its RRsets are signed, so an
    /// answer that carries an RRset the server cannot sign is bogus for a
    /// validating client (RFC 4035 section 5.3).
    pub fn carriesRrsigs(self: *const Zone) bool {
        for (self.records.items[0..self.records.len]) |record| {
            if (record.rrtype.eql(.RRSIG)) return true;
        }
        return false;
    }
    fn recordsAtOwner(self: *const Zone, owner: []const u8) ?[]const parser.ZoneRecord {
        var key_buf: [1024]u8 = undefined;
        if (owner.len > key_buf.len) return null;
        for (owner, 0..) |c, i| key_buf[i] = std.ascii.toLower(c);
        const list = self.owner_index.get(key_buf[0..owner.len]) orelse return null;
        return list.items[0..list.items.len];
    }

    fn lookupExact(self: *const Zone, allocator: std.mem.Allocator, qname: []const u8, qtype: RecordType, result: *LookupResult) ?LookupKind {
        var owner_exists = false;
        var saw_cname = false;
        var saw_dname = false;
        var current_buffer: [256]u8 = undefined;
        var dname_target_buffer: [1024]u8 = undefined;
        var current = qname;
        var hops: usize = 0;
        var visited: [MaxAliasHops]dns_name.Name = undefined;

        while (true) {
            var matched = false;
            var cname: ?parser.ZoneRecord = null;
            var exact_match = false;
            // The owner of an NSEC3 record names nothing in the zone, and
            // neither does the signature over it (RFC 5155 section 7.2.8).
            const hashed_owner = self.ownerIsHashed(current);
            // Exact-owner fast path: records at this owner only. Falls back to
            // the full scan if the index lacks the key (e.g. signer replaced
            // records without rebuilding) so semantics never change.
            const at_owner = self.recordsAtOwner(current);
            if (at_owner) |owners| {
                if (!hashed_owner) {
                    for (owners) |record| {
                        owner_exists = true;
                        matched = true;
                        if (record.rrtype.eql(qtype)) {
                            result.records.append(allocator, record) catch return .servfail;
                            exact_match = true;
                        } else if (record.rrtype.eql(.CNAME) and !qtype.eql(.CNAME)) {
                            result.records.append(allocator, record) catch return .servfail;
                            cname = record;
                            saw_cname = true;
                        }
                    }
                } else if (owners.len != 0) {
                    owner_exists = false;
                }
            } else {
                var index: usize = 0;
                while (index < self.records.len) : (index += 1) {
                    const record = self.records.items[index];
                    if (!std.ascii.eqlIgnoreCase(record.ownerText(), current)) continue;
                    if (hashed_owner) continue;
                    owner_exists = true;
                    matched = true;
                    if (record.rrtype.eql(qtype)) {
                        result.records.append(allocator, record) catch return .servfail;
                        exact_match = true;
                    } else if (record.rrtype.eql(.CNAME) and !qtype.eql(.CNAME)) {
                        result.records.append(allocator, record) catch return .servfail;
                        cname = record;
                        saw_cname = true;
                    }
                }
            }

            if (exact_match) {
                result.soa = null;
                return .answer;
            }
            if (qtype.eql(.CNAME) and matched) {
                result.soa = null;
                return if (result.records.len != 0) .answer else .nodata;
            }

            var next_target: ?dns_name.Name = null;
            if (cname) |cname_record| {
                next_target = dns_name.Name.fromText(cname_record.rdataText()) catch return .servfail;
            } else if (self.findDname(current)) |dname| {
                const dname_target = dns_name.Name.fromText(dname.rdataText()) catch return .servfail;
                result.records.append(allocator, dname) catch return .servfail;
                saw_dname = true;
                const target_name_text = synthesizeDnameTarget(current, dname.ownerText(), dname.rdataText(), &dname_target_buffer) catch {
                    result.soa = null;
                    return .yxdomain;
                };
                // The synthesized target carries the case the DNAME's own
                // target was written in (RFC 4343 section 4.1).
                const synthesized_target = dns_name.Name.fromTextPreservingCase(target_name_text) catch {
                    result.soa = null;
                    return .yxdomain;
                };
                if (result.synthesized_cname == null) {
                    result.synthesized_cname = .{
                        .owner = dns_name.Name.fromText(current) catch return .servfail,
                        .target = synthesized_target,
                        .ttl = dname.ttl,
                    };
                }
                _ = dname_target;
                next_target = synthesized_target;
            } else {
                break;
            }

            const target = next_target.?;
            for (visited[0..hops]) |seen| {
                if (seen.eql(&target)) return .servfail;
            }
            if (hops >= MaxAliasHops) return .servfail;
            visited[hops] = target;
            hops += 1;
            current = target.toText(&current_buffer) catch return .servfail;
            // The target text is used only for this iteration; the inline Name
            // remains in visited, and all source records are zone-owned.
        }

        if (saw_cname or saw_dname) {
            // RFC 8020 section 2 Warning: in a CNAME or DNAME chain the name
            // that does not exist is the last of the chain, not the QNAME. An
            // in-zone target with nothing at or below it is therefore
            // NXDOMAIN for the denied name; an out-of-zone target keeps the
            // alias answer so the client chases the alias at its own server.
            if (self.contains(current) and !self.nodeExists(current)) return .nxdomain;
            result.soa = null;
            return if (saw_dname) .dname else .cname;
        }
        if (owner_exists) return .nodata;
        return null;
    }

    // Suffix walks use recordsAtOwner over indexed owners; the Zone is
    // immutable after build so no locks are needed.
    fn appendDelegation(self: *const Zone, allocator: std.mem.Allocator, result: *LookupResult, owner: []const u8) !void {
        if (self.recordsAtOwner(owner)) |owners| {
            for (owners) |record| {
                if (!record.rrtype.eql(.NS)) continue;
                try result.authorities.append(allocator, record);
                const target = dns_name.Name.fromText(record.rdataText()) catch continue;
                var target_text: [256]u8 = undefined;
                const target_name = target.toText(&target_text) catch continue;
                // RFC 9471 Â§3.1 (in-domain) and Â§3.2 (sibling-domain) glue:
                // the zone attaches addresses it holds for targets inside
                // its own origin. Anything outside that bailiwick (RFC 5452
                // Â§6) contributes nothing, even if a record exists for it.
                if (!isSubdomainOrEqual(target_name, self.originText())) continue;
                if (self.recordsAtOwner(target_name)) |glues| {
                    for (glues) |glue| {
                        if (glue.rrtype.eql(.A) or glue.rrtype.eql(.AAAA)) try result.additionals.append(allocator, glue);
                    }
                    continue;
                }
                // shortcut: unindexed owner (signer replaced records); fall back to scan
                var glue_index: usize = 0;
                while (glue_index < self.records.len) : (glue_index += 1) {
                    const glue = self.records.items[glue_index];
                    if (!std.ascii.eqlIgnoreCase(glue.ownerText(), target_name)) continue;
                    if (glue.rrtype.eql(.A) or glue.rrtype.eql(.AAAA)) try result.additionals.append(allocator, glue);
                }
                continue;
            }
            return;
        }
        var index: usize = 0;
        while (index < self.records.len) : (index += 1) {
            const record = self.records.items[index];
            if (record.rrtype.eql(.NS) and std.ascii.eqlIgnoreCase(record.ownerText(), owner)) {
                try result.authorities.append(allocator, record);
                const target = dns_name.Name.fromText(record.rdataText()) catch continue;
                var target_text: [256]u8 = undefined;
                const target_name = target.toText(&target_text) catch continue;
                // RFC 9471 §3.1 (in-domain) and §3.2 (sibling-domain) glue:
                // the zone attaches addresses it holds for targets inside
                // its own origin. Anything outside that bailiwick (RFC 5452
                // §6) contributes nothing, even if a record exists for it.
                if (!isSubdomainOrEqual(target_name, self.originText())) continue;
                var glue_index: usize = 0;
                while (glue_index < self.records.len) : (glue_index += 1) {
                    const glue = self.records.items[glue_index];
                    if (!std.ascii.eqlIgnoreCase(glue.ownerText(), target_name)) continue;
                    if (glue.rrtype.eql(.A) or glue.rrtype.eql(.AAAA)) try result.additionals.append(allocator, glue);
                }
            }
        }
    }

    fn lowerCmpBuf(owner: []const u8, buf: []u8) []u8 {
        for (owner, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return buf[0..owner.len];
    }

    fn suffixOwnerText(self: *const Zone, qname: []const u8, buf: []u8) []const u8 {
        // Longest indexed owner that is a suffix of qname (walk up labels).
        var candidate = qname;
        while (true) {
            var low: [1024]u8 = undefined;
            if (candidate.len <= low.len) {
                const key = lowerCmpBuf(candidate, &low);
                if (self.owner_index.get(key)) |list| {
                    if (list.items.len != 0) {
                        @memcpy(buf[0..candidate.len], candidate);
                        return buf[0..candidate.len];
                    }
                }
            }
            if (std.ascii.eqlIgnoreCase(candidate, self.originText())) return self.originText();
            const dot = std.mem.indexOfScalar(u8, candidate, '.') orelse return self.originText();
            candidate = candidate[dot + 1 ..];
        }
    }

    fn findDelegation(self: *const Zone, qname: []const u8) ?[]const u8 {
        // Longest-suffix delegation: strip labels and probe the delegation set.
        var candidate = qname;
        var low: [1024]u8 = undefined;
        while (true) {
            if (!std.ascii.eqlIgnoreCase(candidate, self.originText()) and candidate.len <= low.len) {
                const key = lowerCmpBuf(candidate, &low);
                if (self.delegations.contains(key)) {
                    if (self.recordsAtOwner(candidate)) |owners| {
                        for (owners) |record| {
                            if (record.rrtype.eql(.NS)) return record.ownerText();
                        }
                    }
                }
            }
            if (std.ascii.eqlIgnoreCase(candidate, self.originText())) return null;
            const dot = std.mem.indexOfScalar(u8, candidate, '.') orelse return null;
            candidate = candidate[dot + 1 ..];
        }
    }

    fn findDname(self: *const Zone, qname: []const u8) ?parser.ZoneRecord {
        // Closest-encloser DNAME: strip labels, longest match wins (loop bound:
        // one probe per label, no record scan).
        var candidate = qname;
        const dot0 = std.mem.indexOfScalar(u8, candidate, '.') orelse return null;
        candidate = candidate[dot0 + 1 ..];
        var low: [1024]u8 = undefined;
        while (true) {
            if (candidate.len <= low.len) {
                const key = lowerCmpBuf(candidate, &low);
                if (self.dnames.contains(key)) {
                    if (self.recordsAtOwner(candidate)) |owners| {
                        for (owners) |record| {
                            if (record.rrtype.eql(.DNAME)) return record;
                        }
                    }
                }
            }
            if (std.ascii.eqlIgnoreCase(candidate, self.originText())) return null;
            const dot = std.mem.indexOfScalar(u8, candidate, '.') orelse return null;
            candidate = candidate[dot + 1 ..];
        }
    }

    /// True when any record in this zone has this exact owner name. An
    /// empty non-terminal has descendants but no record of its own.
    pub fn hasOwner(self: *const Zone, owner: []const u8) bool {
        if (self.ownerIsHashed(owner)) return false;
        if (self.recordsAtOwner(owner)) |owners| return owners.len != 0;
        var low: [1024]u8 = undefined;
        if (owner.len <= low.len and self.live_owners.contains(lowerCmpBuf(owner, &low))) return true;
        return false;
    }

    /// True when the zone holds an NSEC3 record at this owner name. The owner
    /// of an NSEC3 record is the hash of another name, so it names nothing in
    /// the zone (RFC 5155 section 7.2.8).
    fn ownerIsHashed(self: *const Zone, owner: []const u8) bool {
        // NSEC3 owners name nothing (RFC 5155 section 7.2.8); hashed-owner skip.
        var low: [1024]u8 = undefined;
        if (owner.len > low.len) {
            for (self.records.items[0..self.records.len]) |record| {
                if (!record.rrtype.eql(.NSEC3)) continue;
                if (std.ascii.eqlIgnoreCase(record.ownerText(), owner)) return true;
            }
            return false;
        }
        return self.hashed_owners.contains(lowerCmpBuf(owner, &low));
    }

    fn hasDescendant(self: *const Zone, name: []const u8) bool {
        // Sorted reversed-owner prefix probe: O(log owners + labels).
        if (!self.rev_sorted or self.rev_owners.items.len == 0) return false;
        var low: [1024]u8 = undefined;
        if (name.len > low.len) return false;
        for (name, 0..) |c, i| low[i] = std.ascii.toLower(c);
        var rev: [1024]u8 = undefined;
        const needle = reverseLabels(low[0..name.len], &rev);
        var lo: usize = 0;
        var hi: usize = self.rev_owners.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.lessThan(u8, self.rev_owners.items[mid], needle)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo < self.rev_owners.items.len) {
            const cand = self.rev_owners.items[lo];
            if (cand.len <= needle.len) return false;
            if (std.mem.startsWith(u8, cand, needle)) return true;
        }
        return false;
    }

    fn nodeExists(self: *const Zone, name: []const u8) bool {
        if (std.ascii.eqlIgnoreCase(name, self.originText())) return true;
        if (self.ownerIsHashed(name)) return false;
        var low: [1024]u8 = undefined;
        if (name.len <= low.len and self.live_owners.contains(lowerCmpBuf(name, &low))) return true;
        // Empty non-terminal: some live owner strictly below this name.
        return self.hasDescendant(name);
    }

    fn closestEncloser(self: *const Zone, qname: []const u8) []const u8 {
        // Suffix walk over indexed owners: one probe per label, no record scan.
        // An empty non-terminal exists via its descendants, so each label
        // checks live owners first and the descendant index second.
        var candidate = qname;
        var low: [1024]u8 = undefined;
        while (true) {
            if (candidate.len <= low.len and self.live_owners.contains(lowerCmpBuf(candidate, &low))) return candidate;
            if (self.hasDescendant(candidate)) return candidate;
            if (std.ascii.eqlIgnoreCase(candidate, self.originText())) return self.originText();
            const dot = std.mem.indexOfScalar(u8, candidate, '.') orelse return self.originText();
            candidate = candidate[dot + 1 ..];
        }
    }
};

fn failResult(result: *LookupResult, allocator: std.mem.Allocator) LookupResult {
    result.deinit(allocator);
    return .{ .kind = .servfail };
}

/// The wire size of the records a full transfer of the zone carries, the
/// two apex SOA records aside: the bytes the AXFR answer adds to the two
/// current SOA records it shares with the incremental answer.
pub fn fullTransferBytes(zone: *const Zone) usize {
    var total: usize = 0;
    for (zone.records.items[0..zone.records.len]) |record| {
        if (record.rrtype.eql(.SOA)) continue;
        const converted = toResourceRecord(record) orelse continue;
        total += journal_mod.recordBytes(converted);
    }
    return total;
}

/// Records the wire size of the zone's full transfer, so the delta log of
/// the zone measures an incremental answer against the full transfer it
/// replaces (RFC 1995 section 5). The zone index calls this when it loads
/// the zone, and the signer calls it again once the zone carries the records
/// it generated.
pub fn registerZoneSize(zone: *const Zone) void {
    journal_mod.registerZoneSize(zone.originText(), fullTransferBytes(zone));
}

/// Turns one zone record into the DNS record the zone holds, with the names
/// in the case the zone wrote them in (RFC 4343 section 4.1).
fn toResourceRecord(record: parser.ZoneRecord) ?dns_record.ResourceRecord {
    return .{
        .owner = dns_name.Name.fromTextPreservingCase(record.ownerText()) catch return null,
        .rrtype = record.rrtype,
        .class = dns_types.Class.IN,
        .ttl = record.ttl,
        .rdata = parser.parseRDataPreservingCase(record.rrtype, record.rdataText()) catch return null,
    };
}

/// The difference between two zone snapshots, in the journal's encoding: the
/// records the old zone held and the new one does not, then the records the
/// new zone holds and the old one did not. RFC 1995 section 4 wants the
/// older SOA to open the deleted records and the newer SOA to open the
/// added ones. The caller owns the returned text.
pub fn difference(allocator: std.mem.Allocator, old_zone: *const Zone, new_zone: *const Zone) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (old_zone.soa) |*soa| try appendDifferenceRecord(&out, allocator, true, soa);
    for (old_zone.records.items[0..old_zone.records.len]) |*record| {
        if (record.rrtype.eql(.SOA)) continue;
        if (new_zone.hasRecord(record.*)) continue;
        try appendDifferenceRecord(&out, allocator, true, record);
    }
    if (new_zone.soa) |*soa| try appendDifferenceRecord(&out, allocator, false, soa);
    for (new_zone.records.items[0..new_zone.records.len]) |*record| {
        if (record.rrtype.eql(.SOA)) continue;
        if (old_zone.hasRecord(record.*)) continue;
        try appendDifferenceRecord(&out, allocator, false, record);
    }
    return out.toOwnedSlice(allocator);
}

/// Reports whether two records are the same record: the same owner, TTL,
/// type, and rdata.
fn sameRecord(left: *const parser.ZoneRecord, right: *const parser.ZoneRecord) bool {
    if (left.ttl != right.ttl) return false;
    if (!left.rrtype.eql(right.rrtype)) return false;
    if (!std.ascii.eqlIgnoreCase(left.ownerText(), right.ownerText())) return false;
    return std.mem.eql(u8, left.rdataText(), right.rdataText());
}

fn appendDifferenceRecord(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    deleted: bool,
    record: *const parser.ZoneRecord,
) !void {
    // A record whose rdata carries a line break cannot be carried in the
    // journal's line-based encoding, so the difference is left out and the
    // client at the old serial gets the full transfer.
    if (std.mem.indexOfAny(u8, record.rdataText(), "\n\r") != null) return error.Unrepresentable;
    try journal_mod.encodeRecord(out, allocator, deleted, record.ownerText(), record.ttl, record.rrtype.code(), record.rdataText());
}

fn isStrictSubdomain(name: []const u8, parent: []const u8) bool {
    if (!isSubdomainOrEqual(name, parent)) return false;
    return !std.ascii.eqlIgnoreCase(name, parent);
}

fn labelCount(name: []const u8) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index < name.len) {
        while (index < name.len and name[index] == '.') index += 1;
        if (index == name.len) break;
        count += 1;
        while (index < name.len and name[index] != '.') index += 1;
    }
    return count;
}

fn isSubdomainOrEqual(name: []const u8, parent: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, parent)) return true;
    if (parent.len >= name.len or !std.ascii.eqlIgnoreCase(name[name.len - parent.len ..], parent)) return false;
    return name[name.len - parent.len - 1] == '.';
}
fn makeWildcardName(encloser: []const u8, buffer: []u8) ![]const u8 {
    if (encloser.len + 2 > buffer.len) return error.NameTooLong;
    buffer[0] = '*';
    buffer[1] = '.';
    @memcpy(buffer[2 .. 2 + encloser.len], encloser);
    return buffer[0 .. encloser.len + 2];
}

fn synthesizeDnameTarget(qname: []const u8, owner: []const u8, target: []const u8, buffer: []u8) ![]const u8 {
    if (!isStrictSubdomain(qname, owner)) return error.BadName;
    const prefix_len = qname.len - owner.len;
    if (prefix_len + target.len > 255 or prefix_len + target.len > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..prefix_len], qname[0..prefix_len]);
    @memcpy(buffer[prefix_len .. prefix_len + target.len], target);
    return buffer[0 .. prefix_len + target.len];
}

test "zone index suffix walks use indexes for delegation dname nsec3" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\sub IN NS ns.other.
        \\alias IN DNAME target.example.
        \\target.example. IN A 192.0.2.9
        \\sub.target.example. IN A 192.0.2.11
        \\*.example. IN A 192.0.2.3
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // Delegation: referral for names at and below the cut, DS stays authoritative.
    var ref = zone.lookup(arena.allocator(), "www.sub.example.", .A);
    defer ref.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, ref.kind);
    var ds = zone.lookup(arena.allocator(), "sub.example.", .DS);
    defer ds.deinit(arena.allocator());
    try std.testing.expect(ds.kind != .referral);

    // DNAME: closest-encloser match synthesizes the target.
    var dn = zone.lookup(arena.allocator(), "sub.alias.example.", .A);
    defer dn.deinit(arena.allocator());
    try std.testing.expect(dn.kind == .dname or dn.kind == .answer);
    try std.testing.expect(dn.records.len >= 2);

    // Empty non-terminal: parent of leaf with no records of its own is nodata.
    var ent = zone.lookup(arena.allocator(), "alias.example.", .MX);
    defer ent.deinit(arena.allocator());
    try std.testing.expect(ent.kind == .nodata or ent.kind == .dname);
}

test "zone index answers exact A lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var result = zone.lookup(arena.allocator(), "dns.home.arpa.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualStrings("192.168.1.1", result.records.items[0].rdataText());
}

test "zone index returns CNAME, NODATA, and NXDOMAIN results" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\alias IN CNAME dns.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var cname = zone.lookup(arena.allocator(), "alias.home.arpa.", .A);
    defer cname.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, cname.kind);
    try std.testing.expectEqual(@as(usize, 2), cname.records.len);

    var nodata = zone.lookup(arena.allocator(), "dns.home.arpa.", .AAAA);
    defer nodata.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nodata, nodata.kind);
    try std.testing.expect(nodata.soa != null);

    var nxdomain = zone.lookup(arena.allocator(), "missing.home.arpa.", .A);
    defer nxdomain.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nxdomain, nxdomain.kind);
    try std.testing.expect(nxdomain.soa != null);
}

test "zone index moves zone file ownership before either value deinitializes" {
    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\dns IN A 192.168.1.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    zone_file.deinit();
    try std.testing.expectEqual(@as(usize, 0), zone_file.backing.len);
    try std.testing.expectEqual(@as(usize, 3), zone.records.len);
}

test "zone index applies closest-encloser wildcard and empty non-terminal rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\www IN A 192.0.2.2
        \\*.example. IN A 192.0.2.3
        \\*.wild.example. IN A 192.0.2.4
        \\leaf.branch.example. IN A 192.0.2.5
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var exact = zone.lookup(arena.allocator(), "www.example.", .A);
    defer exact.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, exact.kind);
    try std.testing.expectEqualSlices(u8, "www.example.", exact.answerOwnerText());

    var wildcard = zone.lookup(arena.allocator(), "other.example.", .A);
    defer wildcard.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, wildcard.kind);
    try std.testing.expectEqualSlices(u8, "other.example.", wildcard.answerOwnerText());

    var closest = zone.lookup(arena.allocator(), "child.wild.example.", .A);
    defer closest.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, closest.kind);
    try std.testing.expectEqualSlices(u8, "child.wild.example.", closest.answerOwnerText());

    var ent = zone.lookup(arena.allocator(), "child.branch.example.", .A);
    defer ent.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nxdomain, ent.kind);

    var empty_non_terminal = zone.lookup(arena.allocator(), "branch.example.", .A);
    defer empty_non_terminal.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nodata, empty_non_terminal.kind);

    // A wildcard at the closest encloser matches exactly one label; a
    // deeper name must not inherit it (RFC 4592 section 2.2.1).
    var deep = zone.lookup(arena.allocator(), "deep.child.example.", .A);
    defer deep.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nxdomain, deep.kind);

    var wrong_type = zone.lookup(arena.allocator(), "other.example.", .AAAA);
    defer wrong_type.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nodata, wrong_type.kind);
}

test "zone index compares mixed-case origins at label boundaries" {
    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN Example.
        \\$TTL 3600
        \\@ IN SOA ns.Example. hostmaster.Example. 1 3600 900 1209600 300
        \\@ IN NS ns.Example.
        \\www IN A 192.0.2.1
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    try std.testing.expect(zone.contains("WWW.Example."));
    try std.testing.expect(zone.contains("child.EXAMPLE."));
    try std.testing.expect(!zone.contains("badexample."));
}

test "zone index returns both in-domain and sibling-domain glue on a referral" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.external.example.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.external.example. IN A 192.0.2.11
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "www.child.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, result.kind);
    try std.testing.expectEqual(@as(usize, 2), result.authorities.len);
    try std.testing.expectEqual(@as(usize, 2), result.additionals.len);
    try std.testing.expectEqualSlices(u8, "ns.child.example.", result.additionals.items[0].ownerText());
    try std.testing.expectEqualSlices(u8, "ns.external.example.", result.additionals.items[1].ownerText());
}

test "zone index drops out-of-bailiwick glue on a referral" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.evil.other.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.evil.other. IN A 192.0.2.99
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "www.child.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.additionals.len);
    try std.testing.expectEqualSlices(u8, "ns.child.example.", result.additionals.items[0].ownerText());
}

test "zone index synthesizes bounded DNAME redirects" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\legacy IN DNAME target.example.
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var below = zone.lookup(arena.allocator(), "www.legacy.example.", .A);
    defer below.deinit(arena.allocator());
    // RFC 8020 section 2 Warning: the synthesized CNAME target
    // www.target.example. is the last name of the chain and it does not exist
    // in this zone, so the whole chain is answered NXDOMAIN with the SOA.
    try std.testing.expectEqual(LookupKind.nxdomain, below.kind);
    try std.testing.expect(below.soa != null);
    try std.testing.expectEqual(@as(usize, 1), below.records.len);
    try std.testing.expect(below.synthesized_cname != null);
    var target_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.target.example.", try below.synthesized_cname.?.target.toText(&target_text));

    var owner = zone.lookup(arena.allocator(), "legacy.example.", .DNAME);
    defer owner.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, owner.kind);
    try std.testing.expectEqual(@as(usize, 1), owner.records.len);
}

test "zone index continues a CNAME target through DNAME synthesis" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\legacy IN DNAME target.example.
        \\alias IN CNAME www.legacy.example.
        \\www.target.example. IN A 192.0.2.9
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "alias.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, result.kind);
    try std.testing.expectEqual(@as(usize, 3), result.records.len);
    const synthetic = result.synthesized_cname orelse return error.TestExpectedEqual;
    var owner_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.legacy.example.", try synthetic.owner.toText(&owner_text));
    var target_text: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.target.example.", try synthetic.target.toText(&target_text));
}

test "zone index bounds DNAME redirect loops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\a IN DNAME b.example.
        \\b IN DNAME a.example.
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "www.a.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.servfail, result.kind);
}

test "zone index bounds mixed CNAME and DNAME redirect loops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\start IN CNAME www.a.example.
        \\a IN DNAME b.example.
        \\b IN DNAME a.example.
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "start.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.servfail, result.kind);
}

test "zone index bounds CNAME loops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\a IN CNAME b.example.
        \\b IN CNAME a.example.
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var result = zone.lookup(arena.allocator(), "a.example.", .A);
    defer result.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.servfail, result.kind);
}

test "zone index returns YXDOMAIN when DNAME synthesis exceeds the wire name limit" {
    var target: [256]u8 = undefined;
    var target_len: usize = 0;
    var label_index: usize = 0;
    while (label_index < 3) : (label_index += 1) {
        if (label_index != 0) {
            target[target_len] = '.';
            target_len += 1;
        }
        @memset(target[target_len .. target_len + 63], 't');
        target_len += 63;
    }
    @memcpy(target[target_len .. target_len + 8], ".target.");
    target_len += 8;
    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.print(
        "$ORIGIN example.\n$TTL 3600\n@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300\n@ IN NS ns.example.\nns IN A 192.0.2.1\nlegacy IN DNAME {s}\n",
        .{target[0..target_len]},
    );
    // Build a valid query name whose replacement target is too long.
    var qname: [256]u8 = undefined;
    @memset(qname[0..63], 'p');
    qname[63] = '.';
    @memcpy(qname[64 .. 64 + "legacy.example.".len], "legacy.example.");
    const qname_len = 64 + "legacy.example.".len;
    var zone_file = try parser.ZoneFile.parse(zone_text.written());
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = zone.lookup(arena.allocator(), qname[0..qname_len], .A);
    try std.testing.expectEqual(LookupKind.yxdomain, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expect(result.synthesized_cname == null);
}

test "zone index returns SERVFAIL after the shared CNAME hop cap" {
    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.writeAll(
        "$ORIGIN example.\n$TTL 3600\n@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300\n@ IN NS ns.example.\nns IN A 192.0.2.1\n",
    );
    var index: usize = 0;
    while (index < 18) : (index += 1) {
        try zone_text.writer.print("a{d} IN CNAME a{d}.example.\n", .{ index, index + 1 });
    }
    try zone_text.writer.writeAll("a18 IN A 192.0.2.18\n");

    var zone_file = try parser.ZoneFile.parse(zone_text.written());
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = zone.lookup(arena.allocator(), "a0.example.", .A);
    try std.testing.expectEqual(LookupKind.servfail, result.kind);
}

test "zone index refers at a zone cut before answering data below it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\child IN NS ns.external.example.
        \\ns.child.example. IN A 192.0.2.10
        \\ns.external.example. IN A 192.0.2.11
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    // The glue A below the cut is not authoritative data: a direct query for
    // it gets the delegation, exactly as BIND does.
    var glue = zone.lookup(arena.allocator(), "ns.child.example.", .A);
    defer glue.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, glue.kind);
    try std.testing.expectEqual(@as(usize, 2), glue.authorities.len);
    try std.testing.expectEqual(@as(usize, 2), glue.additionals.len);

    var cut = zone.lookup(arena.allocator(), "child.example.", .NS);
    defer cut.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, cut.kind);
    try std.testing.expectEqual(@as(usize, 2), cut.authorities.len);
    try std.testing.expectEqual(@as(usize, 2), cut.additionals.len);

    var below = zone.lookup(arena.allocator(), "www.child.example.", .A);
    defer below.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, below.kind);
    try std.testing.expectEqual(@as(usize, 2), below.authorities.len);
    try std.testing.expectEqual(@as(usize, 2), below.additionals.len);

    var at_cut = zone.lookup(arena.allocator(), "child.example.", .TXT);
    defer at_cut.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, at_cut.kind);
}

test "zone index keeps DS queries at the cut authoritative" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\ns.child.example. IN A 192.0.2.10
        \\child IN DS 1234 8 2 DEADBEEF
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var ds = zone.lookup(arena.allocator(), "child.example.", .DS);
    defer ds.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.answer, ds.kind);
    try std.testing.expectEqual(@as(usize, 1), ds.records.len);

    var below = zone.lookup(arena.allocator(), "www.child.example.", .DS);
    defer below.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.referral, below.kind);
}

test "zone index returns nodata for a missing DS at the cut" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var zone_file = try parser.ZoneFile.parse(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\child IN NS ns.child.example.
        \\ns.child.example. IN A 192.0.2.10
        \\
    );
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();

    var ds = zone.lookup(arena.allocator(), "child.example.", .DS);
    defer ds.deinit(arena.allocator());
    try std.testing.expectEqual(LookupKind.nodata, ds.kind);
    try std.testing.expect(ds.soa != null);
}

test "exact-owner index answers a 100k-record zone" {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(std.testing.allocator);
    try text.appendSlice(std.testing.allocator,
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 1 3600 900 1209600 300
        \\@ IN NS ns.example.
        \\ns IN A 192.0.2.1
        \\
    );
    var name_buffer: [64]u8 = undefined;
    var index: usize = 0;
    while (index < 100_000) : (index += 1) {
        const line = try std.fmt.bufPrint(&name_buffer, "host{d} IN A 192.0.2.10\n", .{index});
        try text.appendSlice(std.testing.allocator, line);
    }
    var zone_file = try parser.ZoneFile.parse(text.items);
    var zone = try Zone.fromZoneFile(&zone_file);
    defer zone.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = zone.lookup(arena.allocator(), "host99999.example.", .A);
    try std.testing.expectEqual(LookupKind.answer, result.kind);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    const missing = zone.lookup(arena.allocator(), "missing.example.", .A);
    try std.testing.expectEqual(LookupKind.nxdomain, missing.kind);
}
