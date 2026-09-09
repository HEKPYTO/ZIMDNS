const std = @import("std");
const journal_mod = @import("journal.zig");
const parser = @import("parser.zig");
const zone_index = @import("index.zig");

pub const StoreError = error{
    InvalidSnapshotPath,
    OriginMismatch,
    SerialEqual,
    SerialOlder,
    SerialUndefined,
};

const LoadedZone = struct {
    zone: zone_index.Zone,
    serial: u32,
};

pub const Store = struct {
    pub const Error = StoreError;
    dir: std.Io.Dir,
    io: std.Io,
    snapshot_path: []u8 = &.{},
    temporary_path: []u8 = &.{},
    journal_path: []u8 = &.{},
    primary_origin: []u8 = &.{},
    pending_zone: ?zone_index.Zone = null,
    begin_journal_hook: ?*const fn (journal_mod.Journal, []const u8, []const u8) anyerror!void = null,
    clear_journal_hook: ?*const fn (journal_mod.Journal) anyerror!void = null,
    serial: u32 = 0,

    pub fn init(dir: std.Io.Dir, io: std.Io, snapshot_path: []const u8) !Store {
        if (!validSnapshotPath(snapshot_path)) return Error.InvalidSnapshotPath;
        var store = Store{ .dir = dir, .io = io };
        errdefer store.deinit();

        store.snapshot_path = try std.heap.page_allocator.dupe(u8, snapshot_path);
        store.temporary_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.tmp", .{snapshot_path});
        store.journal_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.journal", .{snapshot_path});

        try store.journalHandle().recover(store.temporary_path, store.snapshot_path);
        const snapshot = try dir.readFileAlloc(io, snapshot_path, std.heap.page_allocator, .limited(16 * 1024 * 1024));
        defer std.heap.page_allocator.free(snapshot);
        var loaded = try loadZone(snapshot);
        errdefer loaded.zone.deinit();
        store.primary_origin = try std.heap.page_allocator.dupe(u8, loaded.zone.originText());
        store.pending_zone = loaded.zone;
        loaded.zone = .{ .backing = &.{} };
        store.serial = loaded.serial;
        return store;
    }

    pub fn deinit(self: *Store) void {
        if (self.pending_zone) |*zone| zone.deinit();
        if (self.snapshot_path.len != 0) std.heap.page_allocator.free(self.snapshot_path);
        if (self.temporary_path.len != 0) std.heap.page_allocator.free(self.temporary_path);
        if (self.journal_path.len != 0) std.heap.page_allocator.free(self.journal_path);
        if (self.primary_origin.len != 0) std.heap.page_allocator.free(self.primary_origin);
        self.snapshot_path = &.{};
        self.temporary_path = &.{};
        self.journal_path = &.{};
        self.primary_origin = &.{};
        self.pending_zone = null;
        self.begin_journal_hook = null;
        self.clear_journal_hook = null;
        self.serial = 0;
    }

    pub fn takeZone(self: *Store) ?zone_index.Zone {
        const zone = self.pending_zone orelse return null;
        self.pending_zone = null;
        return zone;
    }

    pub fn replaceText(self: *Store, text: []const u8) !zone_index.Zone {
        var candidate = try loadZone(text);
        errdefer candidate.zone.deinit();

        switch (journal_mod.compareSerial(candidate.serial, self.serial)) {
            .newer => {},
            .equal => return Error.SerialEqual,
            .older => return Error.SerialOlder,
            .undefined => return Error.SerialUndefined,
        }
        if (!std.ascii.eqlIgnoreCase(candidate.zone.originText(), self.primary_origin)) return Error.OriginMismatch;

        var rename_attempted = false;
        defer if (!rename_attempted) {
            self.dir.deleteFile(self.io, self.temporary_path) catch {};
            self.journalHandle().clear() catch {};
        };

        try writeAndSync(self.dir, self.io, self.temporary_path, text);
        try self.journalHandle().begin(self.temporary_path, self.snapshot_path);
        rename_attempted = true;
        try self.dir.rename(self.temporary_path, self.dir, self.snapshot_path, self.io);
        try journal_mod.syncDirectory(self.dir, self.io);

        self.serial = candidate.serial;

        self.clearJournal() catch {};
        return candidate.zone;
    }

    fn journalHandle(self: *const Store) journal_mod.Journal {
        var journal = journal_mod.Journal.init(self.dir, self.io, self.journal_path);
        journal.begin_hook = self.begin_journal_hook;
        return journal;
    }

    fn clearJournal(self: *const Store) !void {
        if (self.clear_journal_hook) |hook| return hook(self.journalHandle());
        return self.journalHandle().clear();
    }
};

fn validSnapshotPath(path: []const u8) bool {
    if (path.len == 0 or std.fs.path.isAbsolute(path) or
        std.mem.indexOfAny(u8, path, "\r\n") != null or std.mem.indexOfScalar(u8, path, 0) != null)
        return false;
    if (std.fs.path.dirname(path) != null) return false;
    return !std.mem.eql(u8, path, ".") and !std.mem.eql(u8, path, "..");
}

fn loadZone(text: []const u8) !LoadedZone {
    var zone_file = try parser.ZoneFile.parse(text);
    errdefer zone_file.deinit();
    const serial = try serialFromZoneFile(&zone_file);
    const zone = try zone_index.Zone.fromZoneFile(&zone_file);
    return .{ .zone = zone, .serial = serial };
}

fn serialFromZoneFile(zone_file: *const parser.ZoneFile) !u32 {
    for (zone_file.records.items[0..zone_file.records.len]) |record| {
        if (!record.rrtype.eql(.SOA)) continue;
        const soa = try parser.parseRData(.SOA, record.rdataText());
        return soa.SOA.serial;
    }
    return error.MissingSoa;
}

fn writeAndSync(dir: std.Io.Dir, io: std.Io, path: []const u8, data: []const u8) !void {
    var file = try dir.createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.sync(io);
}

const initial_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.1
    \\
;

const newer_zone =
    \\$ORIGIN example.
    \\$TTL 3600
    \\@ IN SOA ns.example. hostmaster.example. 11 3600 900 1209600 3600
    \\@ IN NS ns.example.
    \\www IN A 192.0.2.2
    \\
;

const mismatched_newer_zone =
    \\$ORIGIN other.
    \\$TTL 3600
    \\@ IN SOA ns.other. hostmaster.other. 11 3600 900 1209600 3600
    \\@ IN NS ns.other.
    \\www IN A 192.0.2.9
    \\
;

fn expectMissing(dir: std.Io.Dir, io: std.Io, path: []const u8) !void {
    var file = dir.openFile(io, path, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    file.close(io);
    return error.TestExpectedFileNotFound;
}

fn readText(dir: std.Io.Dir, io: std.Io, path: []const u8) ![]u8 {
    return dir.readFileAlloc(io, path, std.testing.allocator, .limited(1024 * 1024));
}

test "store durably replaces the snapshot with a newer valid zone" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    var replacement = try store.replaceText(newer_zone);
    defer replacement.deinit();

    const published = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(published);
    try std.testing.expectEqualStrings(newer_zone, published);
    try std.testing.expectEqual(@as(u32, 11), store.serial);
    try expectMissing(tmp.dir, io, "zone.snapshot.tmp");
    try expectMissing(tmp.dir, io, "zone.snapshot.journal");
}

test "store preserves the durable snapshot when the candidate is invalid" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    const before = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(before);

    try std.testing.expectError(error.BadRecord, store.replaceText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\this is not a zone record
        \\
    ));

    const after = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(@as(u32, 10), store.serial);
    try expectMissing(tmp.dir, io, "zone.snapshot.tmp");
    try expectMissing(tmp.dir, io, "zone.snapshot.journal");
}

test "store rejects a newer candidate from another origin before publishing" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    const before = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(before);

    try std.testing.expectError(error.OriginMismatch, store.replaceText(mismatched_newer_zone));

    const after = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(@as(u32, 10), store.serial);
}

test "store rejects equal older and undefined serials" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();

    const equal_zone =
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    ;
    const older_zone =
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 9 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    ;
    const undefined_zone =
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 2147483658 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\
    ;

    try std.testing.expectError(Store.Error.SerialEqual, store.replaceText(equal_zone));
    try std.testing.expectError(Store.Error.SerialOlder, store.replaceText(older_zone));
    try std.testing.expectError(Store.Error.SerialUndefined, store.replaceText(undefined_zone));
    try std.testing.expectEqual(@as(u32, 10), store.serial);
}

test "store recovery removes only the recorded temporary replacement" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.tmp", .data = newer_zone });

    var pending = journal_mod.Journal.init(tmp.dir, io, "zone.snapshot.journal");
    try pending.begin("zone.snapshot.tmp", "zone.snapshot");

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();

    const retained = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(retained);
    try std.testing.expectEqualStrings(initial_zone, retained);
    try expectMissing(tmp.dir, io, "zone.snapshot.tmp");
    try expectMissing(tmp.dir, io, "zone.snapshot.journal");
}

test "store rejects absolute and parent-traversal snapshot paths" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(Store.Error.InvalidSnapshotPath, Store.init(tmp.dir, io, "/zone.snapshot"));
    try std.testing.expectError(Store.Error.InvalidSnapshotPath, Store.init(tmp.dir, io, "../zone.snapshot"));
    try std.testing.expectError(Store.Error.InvalidSnapshotPath, Store.init(tmp.dir, io, "nested/../../zone.snapshot"));
    try std.testing.expectError(Store.Error.InvalidSnapshotPath, Store.init(tmp.dir, io, "nested/zone.snapshot"));
    try std.testing.expectError(Store.Error.InvalidSnapshotPath, Store.init(tmp.dir, io, "zone\x00snapshot"));
}

test "store refuses mismatched journal records without deleting unrelated files" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "unrelated.snapshot", .data = "keep" });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.tmp", .data = newer_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.journal", .data = "unrelated.snapshot\nzone.snapshot\n" });

    try std.testing.expectError(journal_mod.Error.InvalidRecord, Store.init(tmp.dir, io, "zone.snapshot"));

    const unrelated = try readText(tmp.dir, io, "unrelated.snapshot");
    defer std.testing.allocator.free(unrelated);
    try std.testing.expectEqualStrings("keep", unrelated);
    const pending = try readText(tmp.dir, io, "zone.snapshot.tmp");
    defer std.testing.allocator.free(pending);
    try std.testing.expectEqualStrings(newer_zone, pending);
    const journal_record = try readText(tmp.dir, io, "zone.snapshot.journal");
    defer std.testing.allocator.free(journal_record);
    try std.testing.expectEqualStrings("unrelated.snapshot\nzone.snapshot\n", journal_record);

    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.tmp", .data = newer_zone });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot.journal", .data = "zone.snapshot.tmp\n" });
    try std.testing.expectError(journal_mod.Error.InvalidRecord, Store.init(tmp.dir, io, "zone.snapshot"));
    const pending_after_corrupt = try readText(tmp.dir, io, "zone.snapshot.tmp");
    defer std.testing.allocator.free(pending_after_corrupt);
    try std.testing.expectEqualStrings(newer_zone, pending_after_corrupt);
}

test "store publishes memory before an injected journal clear failure" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    store.clear_journal_hook = failJournalClear;
    var replacement = try store.replaceText(newer_zone);
    defer replacement.deinit();

    try std.testing.expectEqual(@as(u32, 11), store.serial);
    const published = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(published);
    try std.testing.expectEqualStrings(newer_zone, published);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "zone.snapshot.tmp", .{}));

    store.clear_journal_hook = null;
    var recovered = try Store.init(tmp.dir, io, "zone.snapshot");
    defer recovered.deinit();
    try std.testing.expectEqual(@as(u32, 11), recovered.serial);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "zone.snapshot.journal", .{}));
}

fn failJournalClear(_: journal_mod.Journal) anyerror!void {
    return error.InjectedJournalClear;
}

test "store clears temp and partial journal after Journal.begin fails" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    store.begin_journal_hook = failJournalBegin;
    try std.testing.expectError(error.InjectedJournalBegin, store.replaceText(newer_zone));
    try expectMissing(tmp.dir, io, "zone.snapshot.tmp");
    try expectMissing(tmp.dir, io, "zone.snapshot.journal");

    const retained = try readText(tmp.dir, io, "zone.snapshot");
    defer std.testing.allocator.free(retained);
    try std.testing.expectEqualStrings(initial_zone, retained);

    store.begin_journal_hook = null;
    var reopened = try Store.init(tmp.dir, io, "zone.snapshot");
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u32, 10), reopened.serial);
}

fn failJournalBegin(journal: journal_mod.Journal, _: []const u8, _: []const u8) anyerror!void {
    var file = try journal.dir.createFile(journal.io, journal.path, .{});
    defer file.close(journal.io);
    try file.writeStreamingAll(journal.io, "partial");
    try file.sync(journal.io);
    return error.InjectedJournalBegin;
}

test "store serial transitions feed the delta log for IXFR fallback choices" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.snapshot", .data = initial_zone });

    var store = try Store.init(tmp.dir, io, "zone.snapshot");
    defer store.deinit();
    try std.testing.expectEqual(@as(u32, 10), store.serial);

    var deltas = journal_mod.DeltaLog{};
    const before = store.serial;
    var replacement = try store.replaceText(newer_zone);
    defer replacement.deinit();
    try deltas.record(before, store.serial);

    try std.testing.expect(deltas.canServeIncremental(10, 11));
    try std.testing.expect(!deltas.canServeIncremental(9, 11));

    // A rejected older candidate leaves both the snapshot and the delta log alone.
    try std.testing.expectError(Store.Error.SerialOlder, store.replaceText(initial_zone));
    try std.testing.expectEqual(@as(u32, 11), store.serial);
    try std.testing.expect(!deltas.hasSerial(9));
    try std.testing.expect(deltas.canServeIncremental(10, 11));
}
