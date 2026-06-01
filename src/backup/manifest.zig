const std = @import("std");
const config_parser = @import("../config/parser.zig");

const max_files = 64;
const max_path = 256;

pub const FileKind = enum { config, zone, blocklist };

pub const FileStats = struct {
    zone_size: u64 = 0,
    zone_checksum: u64 = 0,
    blocklist_size: u64 = 0,
    blocklist_checksum: u64 = 0,
};

pub const File = struct {
    kind: FileKind,
    path: [max_path]u8 = undefined,
    path_len: usize = 0,
    size: u64,
    checksum: u64,

    pub fn pathText(self: *const File) []const u8 {
        return self.path[0..self.path_len];
    }
};

pub const Manifest = struct {
    files: FileList = .{},

    pub fn add(self: *Manifest, file: struct { kind: FileKind, path: []const u8, size: u64, checksum: u64 }) !void {
        if (file.path.len > max_path) return error.PathTooLong;
        var entry = File{
            .kind = file.kind,
            .size = file.size,
            .checksum = file.checksum,
        };
        @memcpy(entry.path[0..file.path.len], file.path);
        entry.path_len = file.path.len;
        try self.files.append(entry);
    }

    pub fn addConfig(self: *Manifest, path: []const u8, text: []const u8) !void {
        try self.add(.{
            .kind = .config,
            .path = path,
            .size = text.len,
            .checksum = checksum(text),
        });
    }

    pub fn addConfigAssets(self: *Manifest, config: *const config_parser.Config, stats: FileStats) !void {
        var zone_index: usize = 0;
        while (zone_index < config.zones.len) : (zone_index += 1) {
            try self.add(.{
                .kind = .zone,
                .path = config.zones.items[zone_index].fileText(),
                .size = stats.zone_size,
                .checksum = stats.zone_checksum,
            });
        }
        var blocklist_index: usize = 0;
        while (blocklist_index < config.blocklists.len) : (blocklist_index += 1) {
            try self.add(.{
                .kind = .blocklist,
                .path = config.blocklists.items[blocklist_index].pathText(),
                .size = stats.blocklist_size,
                .checksum = stats.blocklist_checksum,
            });
        }
    }

    pub fn fromConfigFile(dir: std.Io.Dir, io: std.Io, path: []const u8, allocator: std.mem.Allocator) !Manifest {
        const config_text = try dir.readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        defer allocator.free(config_text);

        const config = try config_parser.Config.parse(config_text);
        var manifest = Manifest{};
        try manifest.addConfig(path, config_text);

        var zone_index: usize = 0;
        while (zone_index < config.zones.len) : (zone_index += 1) {
            const zone_path = config.zones.items[zone_index].fileText();
            const zone_text = try dir.readFileAlloc(io, zone_path, allocator, .limited(1024 * 1024));
            defer allocator.free(zone_text);
            try manifest.add(.{
                .kind = .zone,
                .path = zone_path,
                .size = zone_text.len,
                .checksum = checksum(zone_text),
            });
        }

        var blocklist_index: usize = 0;
        while (blocklist_index < config.blocklists.len) : (blocklist_index += 1) {
            const blocklist_path = config.blocklists.items[blocklist_index].pathText();
            const blocklist_text = try dir.readFileAlloc(io, blocklist_path, allocator, .limited(1024 * 1024));
            defer allocator.free(blocklist_text);
            try manifest.add(.{
                .kind = .blocklist,
                .path = blocklist_path,
                .size = blocklist_text.len,
                .checksum = checksum(blocklist_text),
            });
        }

        return manifest;
    }

    pub fn render(self: *const Manifest, buffer: []u8) ![]const u8 {
        var writer = TextWriter.init(buffer);
        var index: usize = 0;
        while (index < self.files.len) : (index += 1) {
            const file = self.files.items[index];
            try writer.writeBytes(kindName(file.kind));
            try writer.writeBytes(" ");
            try writer.writeBytes(file.pathText());
            try writer.print(" {d} {d}\n", .{ file.size, file.checksum });
        }
        return writer.written();
    }
};

const FileList = struct {
    items: [max_files]File = undefined,
    len: usize = 0,

    fn append(self: *FileList, file: File) !void {
        if (self.len >= self.items.len) return error.TooManyBackupFiles;
        self.items[self.len] = file;
        self.len += 1;
    }
};

fn kindName(kind: FileKind) []const u8 {
    return switch (kind) {
        .config => "config",
        .zone => "zone",
        .blocklist => "blocklist",
    };
}

pub fn checksum(text: []const u8) u64 {
    return std.hash.Fnv1a_64.hash(text);
}

const TextWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn init(buffer: []u8) TextWriter {
        return .{ .buffer = buffer };
    }

    fn written(self: TextWriter) []const u8 {
        return self.buffer[0..self.offset];
    }

    fn writeBytes(self: *TextWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.offset < bytes.len) return error.OutputTooSmall;
        @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn print(self: *TextWriter, comptime fmt: []const u8, args: anytype) !void {
        const out = std.fmt.bufPrint(self.buffer[self.offset..], fmt, args) catch return error.OutputTooSmall;
        self.offset += out.len;
    }
};

test "backup manifest includes config zones and blocklists" {
    const config = try config_parser.Config.parse(
        \\listen dns udp 0.0.0.0:1053
        \\admin socket /tmp/gcli-dns.sock
        \\recursion deny 0.0.0.0/0
        \\recursion deny ::/0
        \\blocklist file examples/blocklists/ads.txt
        \\zone home.arpa primary examples/zones/home.arpa.zone
        \\
    );
    var manifest = Manifest{};
    try manifest.addConfig("examples/config.gdns", "config text");
    try manifest.addConfigAssets(&config, .{
        .zone_size = 128,
        .zone_checksum = 11,
        .blocklist_size = 32,
        .blocklist_checksum = 22,
    });

    try std.testing.expectEqual(@as(usize, 3), manifest.files.len);
    try std.testing.expectEqual(FileKind.config, manifest.files.items[0].kind);
    try std.testing.expectEqual(FileKind.zone, manifest.files.items[1].kind);
    try std.testing.expectEqual(FileKind.blocklist, manifest.files.items[2].kind);
    try std.testing.expectEqualStrings("examples/zones/home.arpa.zone", manifest.files.items[1].pathText());
}

test "backup manifest renders deterministic text" {
    var manifest = Manifest{};
    try manifest.add(.{ .kind = .config, .path = "examples/config.gdns", .size = 10, .checksum = 123 });
    try manifest.add(.{ .kind = .zone, .path = "examples/zones/home.arpa.zone", .size = 20, .checksum = 456 });

    var buffer: [512]u8 = undefined;
    const text = try manifest.render(&buffer);
    try std.testing.expectEqualStrings(
        "config examples/config.gdns 10 123\nzone examples/zones/home.arpa.zone 20 456\n",
        text,
    );
}

test "backup manifest reads assets referenced by config" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "config.gdns", .data =
        \\listen dns udp 0.0.0.0:1053
        \\admin socket /tmp/gcli-dns.sock
        \\recursion deny 0.0.0.0/0
        \\recursion deny ::/0
        \\blocklist file block.txt
        \\zone home.arpa primary zone.txt
        \\
    });
    try dir.dir.writeFile(io, .{ .sub_path = "zone.txt", .data = "zone-data" });
    try dir.dir.writeFile(io, .{ .sub_path = "block.txt", .data = "ads.example.\n" });

    var manifest = try Manifest.fromConfigFile(dir.dir, io, "config.gdns", allocator);
    var buffer: [512]u8 = undefined;
    const text = try manifest.render(&buffer);

    try std.testing.expect(std.mem.indexOf(u8, text, "config config.gdns") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zone zone.txt 9") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "blocklist block.txt 13") != null);
}
