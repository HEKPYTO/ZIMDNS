/// One shared seam for connection-scoped QUIC stream state. Both the DoQ
/// and DoH/3 handlers key per-stream state by `{ connection, stream }` so
/// two connections reusing the same stream id never share an entry, and
/// `removeConnection` reclaims every entry when a connection closes.
const std = @import("std");

pub const Key = struct {
    connection: u64,
    stream: u64,
};

/// A bounded map from composite stream key to an owned `*T` value. Insert
/// errors on a duplicate key without touching either value; removal
/// destroys the owned value through `destroy`, which the caller supplies
/// so nested allocations (DoH/3 header copies) free correctly. Ownership:
/// a failed `insert` never takes the value, so the caller keeps (and must
/// free) it; a successful `insert` transfers it to the registry.
pub fn Registry(comptime T: type) type {
    return struct {
        const Self = @This();
        map: std.AutoHashMapUnmanaged(Key, *T) = .empty,
        max_entries: usize,

        pub fn init(max_entries: usize) Self {
            return .{ .max_entries = max_entries };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator, destroy: *const fn (std.mem.Allocator, *T) void) void {
            var it = self.map.iterator();
            while (it.next()) |kv| destroy(allocator, kv.value_ptr.*);
            self.map.deinit(allocator);
        }

        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        pub fn insert(self: *Self, allocator: std.mem.Allocator, key: Key, value: *T) !void {
            if (self.map.contains(key)) return error.DuplicateStream;
            // Per-connection cap: one client holding the advertised
            // limit must not starve every other connection sharing
            // this registry.
            var held: usize = 0;
            var it = self.map.iterator();
            while (it.next()) |kv| if (kv.key_ptr.connection == key.connection) {
                held += 1;
            };
            if (held >= self.max_entries) return error.TooManyStreams;
            try self.map.put(allocator, key, value);
        }

        pub fn get(self: *const Self, key: Key) ?*T {
            return self.map.get(key);
        }

        pub fn removeOne(self: *Self, allocator: std.mem.Allocator, key: Key, destroy: *const fn (std.mem.Allocator, *T) void) void {
            if (self.map.fetchRemove(key)) |kv| destroy(allocator, kv.value);
        }

        /// Removes and destroys every entry for one connection; unknown
        /// connection ids are a no-op. Repeatedly removes one match until
        /// none remain, so no entry is dropped no matter how large
        /// `max_entries` is. O(n^2) worst case; fine while the bound is
        /// tiny (`max_entries` in each handler).
        pub fn removeConnection(self: *Self, allocator: std.mem.Allocator, connection: u64, destroy: *const fn (std.mem.Allocator, *T) void) void {
            while (self.findConnectionEntry(connection)) |key| self.removeOne(allocator, key, destroy);
        }

        fn findConnectionEntry(self: *const Self, connection: u64) ?Key {
            var it = self.map.iterator();
            while (it.next()) |kv| {
                if (kv.key_ptr.connection == connection) return kv.key_ptr.*;
            }
            return null;
        }
    };
}

fn destroyU64(allocator: std.mem.Allocator, value: *u64) void {
    allocator.destroy(value);
}

fn putEntry(registry: *Registry(u64), allocator: std.mem.Allocator, connection: u64, stream: u64, n: u64) !void {
    const owned = try allocator.create(u64);
    errdefer allocator.destroy(owned);
    owned.* = n;
    try registry.insert(allocator, .{ .connection = connection, .stream = stream }, owned);
}

test "same stream id on two connections yields two independent entries" {
    var registry = Registry(u64).init(64);
    defer registry.deinit(std.testing.allocator, destroyU64);
    try putEntry(&registry, std.testing.allocator, 1, 0, 11);
    try putEntry(&registry, std.testing.allocator, 2, 0, 22);
    try std.testing.expectEqual(@as(u64, 11), registry.get(.{ .connection = 1, .stream = 0 }).?.*);
    try std.testing.expectEqual(@as(u64, 22), registry.get(.{ .connection = 2, .stream = 0 }).?.*);
}

test "removeConnection drops only that connection's entries" {
    var registry = Registry(u64).init(64);
    defer registry.deinit(std.testing.allocator, destroyU64);
    try putEntry(&registry, std.testing.allocator, 1, 0, 11);
    try putEntry(&registry, std.testing.allocator, 2, 0, 22);
    registry.removeConnection(std.testing.allocator, 1, destroyU64);
    try std.testing.expect(registry.get(.{ .connection = 1, .stream = 0 }) == null);
    try std.testing.expectEqual(@as(u64, 22), registry.get(.{ .connection = 2, .stream = 0 }).?.*);
}

test "duplicate insert errors and leaves the map unchanged" {
    var registry = Registry(u64).init(64);
    defer registry.deinit(std.testing.allocator, destroyU64);
    try putEntry(&registry, std.testing.allocator, 1, 0, 11);
    const owned = try std.testing.allocator.create(u64);
    owned.* = 99;
    const result = registry.insert(std.testing.allocator, .{ .connection = 1, .stream = 0 }, owned);
    try std.testing.expectError(error.DuplicateStream, result);
    std.testing.allocator.destroy(owned);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(u64, 11), registry.get(.{ .connection = 1, .stream = 0 }).?.*);
}

test "the bound rejects the 65th live entry and accepts again after removal" {
    var registry = Registry(u64).init(64);
    defer registry.deinit(std.testing.allocator, destroyU64);
    var i: u64 = 0;
    while (i < 64) : (i += 1) try putEntry(&registry, std.testing.allocator, 1, i, i);
    const owned = try std.testing.allocator.create(u64);
    owned.* = 64;
    defer if (registry.get(.{ .connection = 1, .stream = 64 }) == null) std.testing.allocator.destroy(owned);
    try std.testing.expectError(error.TooManyStreams, registry.insert(std.testing.allocator, .{ .connection = 1, .stream = 64 }, owned));
    registry.removeOne(std.testing.allocator, .{ .connection = 1, .stream = 0 }, destroyU64);
    try registry.insert(std.testing.allocator, .{ .connection = 1, .stream = 64 }, owned);
    try std.testing.expectEqual(@as(usize, 64), registry.count());
}
test "the bound is per connection: a full client does not starve others" {
    var registry = Registry(u64).init(2);
    defer registry.deinit(std.testing.allocator, destroyU64);
    try putEntry(&registry, std.testing.allocator, 1, 0, 11);
    try putEntry(&registry, std.testing.allocator, 1, 1, 12);
    // Client 1 is at its cap; client 2 still inserts fine.
    try putEntry(&registry, std.testing.allocator, 2, 0, 22);
    const owned = try std.testing.allocator.create(u64);
    owned.* = 13;
    defer std.testing.allocator.destroy(owned);
    try std.testing.expectError(error.TooManyStreams, registry.insert(std.testing.allocator, .{ .connection = 1, .stream = 2 }, owned));
    try std.testing.expectEqual(@as(usize, 3), registry.count());
}

test "a full 16-stream QUIC connection does not starve the next connection" {
    // Mirrors core.Server.MAX_STREAMS_PER_CONN (the per-connection cap the
    // DoQ/DoH3 handlers pass as max_entries).
    const per_conn: u64 = 16;
    var registry = Registry(u64).init(per_conn);
    defer registry.deinit(std.testing.allocator, destroyU64);
    var i: u64 = 0;
    while (i < per_conn) : (i += 1) try putEntry(&registry, std.testing.allocator, 1, i, i);
    // Second connection registers despite the first sitting at its cap.
    try putEntry(&registry, std.testing.allocator, 2, 0, 999);
    try std.testing.expectEqual(@as(u64, 999), registry.get(.{ .connection = 2, .stream = 0 }).?.*);
    const owned = try std.testing.allocator.create(u64);
    owned.* = 1000;
    defer std.testing.allocator.destroy(owned);
    try std.testing.expectError(error.TooManyStreams, registry.insert(std.testing.allocator, .{ .connection = 1, .stream = 99 }, owned));
}

test "removeConnection on an unknown id is a no-op" {
    var registry = Registry(u64).init(64);
    defer registry.deinit(std.testing.allocator, destroyU64);
    try putEntry(&registry, std.testing.allocator, 1, 0, 11);
    registry.removeConnection(std.testing.allocator, 7, destroyU64);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(u64, 11), registry.get(.{ .connection = 1, .stream = 0 }).?.*);
}

test "removeConnection clears entries past the old 64-slot scan cap" {
    var registry = Registry(u64).init(80);
    defer registry.deinit(std.testing.allocator, destroyU64);
    var i: u64 = 0;
    while (i < 70) : (i += 1) try putEntry(&registry, std.testing.allocator, 1, i, i);
    try putEntry(&registry, std.testing.allocator, 2, 0, 999);
    registry.removeConnection(std.testing.allocator, 1, destroyU64);
    try std.testing.expect(registry.get(.{ .connection = 1, .stream = 70 }) == null);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(u64, 999), registry.get(.{ .connection = 2, .stream = 0 }).?.*);
}
