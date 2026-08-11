/// Contract: Stores bounded DNS responses with TTL and stale-serving lookup semantics.
/// Ownership: Store owns all fixed-size entry bytes; Lookup borrows response bytes from Store.
/// Errors: Capacity and size violations are typed; persistence or I/O is not handled here.
const std = @import("std");

const max_name = 255;
const max_response = 512;

pub const Error = error{
    NameTooLong,
    ResponseTooLarge,
};

pub const Lookup = struct {
    bytes: []const u8,
    stale: bool,
};

const Entry = struct {
    occupied: bool = false,
    name: [max_name]u8 = undefined,
    name_len: usize = 0,
    qtype: u16 = 0,
    qclass: u16 = 0,
    response: [max_response]u8 = undefined,
    response_len: usize = 0,
    inserted_at: u64 = 0,
    expires_at: u64 = 0,

    fn nameText(self: *const Entry) []const u8 {
        return self.name[0..self.name_len];
    }

    fn responseBytes(self: *const Entry) []const u8 {
        return self.response[0..self.response_len];
    }
};

pub fn Store(comptime capacity: usize) type {
    return struct {
        entries: [capacity]Entry = [_]Entry{.{}} ** capacity,

        pub fn put(self: *@This(), name: []const u8, qtype: u16, qclass: u16, response: []const u8, ttl: u32, now: u64) Error!void {
            if (name.len > max_name) return Error.NameTooLong;
            if (response.len > max_response) return Error.ResponseTooLarge;

            const index = self.findWritableSlot(name, qtype, qclass);
            var entry = &self.entries[index];
            entry.occupied = true;
            @memcpy(entry.name[0..name.len], name);
            entry.name_len = name.len;
            entry.qtype = qtype;
            entry.qclass = qclass;
            @memcpy(entry.response[0..response.len], response);
            entry.response_len = response.len;
            entry.inserted_at = now;
            entry.expires_at = now + ttl;
        }

        pub fn get(self: *const @This(), name: []const u8, qtype: u16, qclass: u16, now: u64, serve_stale: bool, stale_ttl: u32) ?Lookup {
            var index: usize = 0;
            while (index < self.entries.len) : (index += 1) {
                const entry = &self.entries[index];
                if (!entry.occupied) continue;
                if (entry.qtype != qtype or entry.qclass != qclass) continue;
                if (!std.mem.eql(u8, entry.nameText(), name)) continue;

                if (now <= entry.expires_at) {
                    return .{ .bytes = entry.responseBytes(), .stale = false };
                }
                if (serve_stale and now <= entry.expires_at + stale_ttl) {
                    return .{ .bytes = entry.responseBytes(), .stale = true };
                }
                return null;
            }
            return null;
        }

        fn findWritableSlot(self: *const @This(), name: []const u8, qtype: u16, qclass: u16) usize {
            var oldest_index: usize = 0;
            var oldest_time: u64 = std.math.maxInt(u64);

            var index: usize = 0;
            while (index < self.entries.len) : (index += 1) {
                const entry = &self.entries[index];
                if (!entry.occupied) return index;
                if (entry.qtype == qtype and entry.qclass == qclass and std.mem.eql(u8, entry.nameText(), name)) return index;
                if (entry.inserted_at < oldest_time) {
                    oldest_time = entry.inserted_at;
                    oldest_index = index;
                }
            }
            return oldest_index;
        }
    };
}

test "cache returns fresh entries until ttl expires" {
    var cache = Store(2){};
    try cache.put("dns.home.arpa.", 1, 1, "answer", 10, 100);

    const fresh = cache.get("dns.home.arpa.", 1, 1, 105, false, 0) orelse return error.MissingFreshEntry;
    try std.testing.expectEqualStrings("answer", fresh.bytes);
    try std.testing.expect(!fresh.stale);

    try std.testing.expect(cache.get("dns.home.arpa.", 1, 1, 111, false, 0) == null);
}

test "cache can serve expired entries inside stale window" {
    var cache = Store(2){};
    try cache.put("dns.home.arpa.", 1, 1, "answer", 10, 100);

    const stale = cache.get("dns.home.arpa.", 1, 1, 115, true, 30) orelse return error.MissingStaleEntry;
    try std.testing.expectEqualStrings("answer", stale.bytes);
    try std.testing.expect(stale.stale);

    try std.testing.expect(cache.get("dns.home.arpa.", 1, 1, 141, true, 30) == null);
}

test "cache evicts oldest entry when capacity is full" {
    var cache = Store(2){};
    try cache.put("one.home.arpa.", 1, 1, "one", 30, 100);
    try cache.put("two.home.arpa.", 1, 1, "two", 30, 101);
    try cache.put("three.home.arpa.", 1, 1, "three", 30, 102);

    try std.testing.expect(cache.get("one.home.arpa.", 1, 1, 103, false, 0) == null);
    try std.testing.expect(cache.get("two.home.arpa.", 1, 1, 103, false, 0) != null);
    try std.testing.expect(cache.get("three.home.arpa.", 1, 1, 103, false, 0) != null);
}
