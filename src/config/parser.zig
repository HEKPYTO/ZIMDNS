const std = @import("std");

const max_items = 32;
const max_text = 256;

pub const Error = error{
    UnknownDirective,
    BadDirective,
    BadPort,
    TextTooLong,
    TooManyItems,
};

pub const Transport = enum { udp, tcp };
pub const RecursionAction = enum { allow, deny };

const Text = struct {
    bytes: [max_text]u8 = undefined,
    len: usize = 0,

    fn set(self: *Text, value: []const u8) Error!void {
        if (value.len > self.bytes.len) return Error.TextTooLong;
        @memcpy(self.bytes[0..value.len], value);
        self.len = value.len;
    }

    pub fn text(self: *const Text) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Listener = struct {
    transport: Transport,
    address: Text = .{},
    port: u16,
};

pub const AdminSocket = struct {
    path: Text = .{},

    pub fn pathText(self: *const AdminSocket) []const u8 {
        return self.path.text();
    }
};

pub const RecursionRule = struct {
    action: RecursionAction,
    cidr: Text = .{},
};

pub const Forwarder = struct {
    name: Text = .{},
    transport: Transport,
    address: Text = .{},
};

pub const CacheConfig = struct {
    max_entries: u32 = 0,
    serve_stale: bool = false,
    serve_stale_ttl: u32 = 0,
};

pub const Zone = struct {
    name: Text = .{},
    kind: Text = .{},
    file: Text = .{},

    pub fn nameText(self: *const Zone) []const u8 {
        return self.name.text();
    }

    pub fn fileText(self: *const Zone) []const u8 {
        return self.file.text();
    }
};

pub const BlocklistFile = struct {
    path: Text = .{},

    pub fn pathText(self: *const BlocklistFile) []const u8 {
        return self.path.text();
    }
};

fn List(comptime T: type) type {
    return struct {
        items: [max_items]T = undefined,
        len: usize = 0,

        fn append(self: *@This(), item: T) Error!void {
            if (self.len >= max_items) return Error.TooManyItems;
            self.items[self.len] = item;
            self.len += 1;
        }
    };
}

pub const Config = struct {
    listeners: List(Listener) = .{},
    admin_socket: AdminSocket = .{},
    recursion_rules: List(RecursionRule) = .{},
    forwarders: List(Forwarder) = .{},
    cache: CacheConfig = .{},
    zones: List(Zone) = .{},
    blocklists: List(BlocklistFile) = .{},

    pub fn parse(text: []const u8) !Config {
        var config = Config{};
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const stripped = stripComment(raw_line);
            const line = std.mem.trim(u8, stripped, " \t\r");
            if (line.len == 0) continue;
            try config.parseLine(line);
        }
        return config;
    }

    fn parseLine(self: *Config, line: []const u8) !void {
        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        const first = tokens.next() orelse return;
        if (std.mem.eql(u8, first, "listen")) return self.parseListen(&tokens);
        if (std.mem.eql(u8, first, "admin")) return self.parseAdmin(&tokens);
        if (std.mem.eql(u8, first, "recursion")) return self.parseRecursion(&tokens);
        if (std.mem.eql(u8, first, "forwarder")) return self.parseForwarder(&tokens);
        if (std.mem.eql(u8, first, "cache")) return self.parseCache(&tokens);
        if (std.mem.eql(u8, first, "zone")) return self.parseZone(&tokens);
        if (std.mem.eql(u8, first, "blocklist")) return self.parseBlocklist(&tokens);
        return Error.UnknownDirective;
    }

    fn parseListen(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "dns")) return Error.BadDirective;
        const transport = try parseTransport(tokens.next() orelse return Error.BadDirective);
        const endpoint = tokens.next() orelse return Error.BadDirective;
        var listener = Listener{ .transport = transport, .port = undefined };
        const parsed = try parseEndpoint(endpoint);
        try listener.address.set(parsed.address);
        listener.port = parsed.port;
        try self.listeners.append(listener);
    }

    fn parseAdmin(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "socket")) return Error.BadDirective;
        try self.admin_socket.path.set(tokens.next() orelse return Error.BadDirective);
    }

    fn parseRecursion(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const action_text = tokens.next() orelse return Error.BadDirective;
        var rule = RecursionRule{
            .action = if (std.mem.eql(u8, action_text, "allow")) .allow else if (std.mem.eql(u8, action_text, "deny")) .deny else return Error.BadDirective,
        };
        try rule.cidr.set(tokens.next() orelse return Error.BadDirective);
        try self.recursion_rules.append(rule);
    }

    fn parseForwarder(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var forwarder = Forwarder{ .transport = undefined };
        try forwarder.name.set(tokens.next() orelse return Error.BadDirective);
        forwarder.transport = try parseTransport(tokens.next() orelse return Error.BadDirective);
        try forwarder.address.set(tokens.next() orelse return Error.BadDirective);
        try self.forwarders.append(forwarder);
    }

    fn parseCache(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        const key = tokens.next() orelse return Error.BadDirective;
        const value = tokens.next() orelse return Error.BadDirective;
        if (std.mem.eql(u8, key, "max-entries")) {
            self.cache.max_entries = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        } else if (std.mem.eql(u8, key, "serve-stale")) {
            self.cache.serve_stale = if (std.mem.eql(u8, value, "on")) true else if (std.mem.eql(u8, value, "off")) false else return Error.BadDirective;
        } else if (std.mem.eql(u8, key, "serve-stale-ttl")) {
            self.cache.serve_stale_ttl = std.fmt.parseInt(u32, value, 10) catch return Error.BadDirective;
        } else return Error.BadDirective;
    }

    fn parseZone(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        var zone = Zone{};
        try zone.name.set(tokens.next() orelse return Error.BadDirective);
        try zone.kind.set(tokens.next() orelse return Error.BadDirective);
        try zone.file.set(tokens.next() orelse return Error.BadDirective);
        try self.zones.append(zone);
    }

    fn parseBlocklist(self: *Config, tokens: *std.mem.TokenIterator(u8, .any)) !void {
        if (!std.mem.eql(u8, tokens.next() orelse return Error.BadDirective, "file")) return Error.BadDirective;
        var file = BlocklistFile{};
        try file.path.set(tokens.next() orelse return Error.BadDirective);
        try self.blocklists.append(file);
    }
};

fn parseTransport(text: []const u8) !Transport {
    if (std.mem.eql(u8, text, "udp")) return .udp;
    if (std.mem.eql(u8, text, "tcp")) return .tcp;
    return Error.BadDirective;
}

fn parseEndpoint(text: []const u8) !struct { address: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return Error.BadDirective;
    const address = text[0..colon];
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return Error.BadPort;
    return .{ .address = address, .port = port };
}

fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |byte, index| {
        if (byte == '#') return line[0..index];
    }
    return line;
}

test "config parser loads documented directives" {
    const text =
        \\listen dns udp 0.0.0.0:1053
        \\listen dns tcp 0.0.0.0:1053
        \\admin socket /run/gcli-dns/admin.sock
        \\recursion deny 0.0.0.0/0
        \\recursion deny ::/0
        \\forwarder default udp 9.9.9.9
        \\cache max-entries 100000
        \\cache serve-stale on
        \\cache serve-stale-ttl 3600
        \\zone home.arpa primary /etc/gcli-dns/zones/home.arpa.zone
        \\blocklist file /etc/gcli-dns/blocklists/ads.txt
        \\
    ;

    const config = try Config.parse(text);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expectEqual(Transport.udp, config.listeners.items[0].transport);
    try std.testing.expectEqual(@as(u16, 1053), config.listeners.items[0].port);
    try std.testing.expectEqualStrings("/run/gcli-dns/admin.sock", config.admin_socket.pathText());
    try std.testing.expectEqual(@as(usize, 2), config.recursion_rules.len);
    try std.testing.expectEqual(@as(usize, 1), config.forwarders.len);
    try std.testing.expectEqual(@as(u32, 100000), config.cache.max_entries);
    try std.testing.expect(config.cache.serve_stale);
    try std.testing.expectEqual(@as(u32, 3600), config.cache.serve_stale_ttl);
    try std.testing.expectEqual(@as(usize, 1), config.zones.len);
    try std.testing.expectEqualStrings("home.arpa", config.zones.items[0].nameText());
    try std.testing.expectEqual(@as(usize, 1), config.blocklists.len);
    try std.testing.expectEqualStrings("/etc/gcli-dns/blocklists/ads.txt", config.blocklists.items[0].pathText());
}

test "config parser rejects unknown and malformed directives" {
    try std.testing.expectError(error.UnknownDirective, Config.parse("bogus thing\n"));
    try std.testing.expectError(error.BadDirective, Config.parse("listen dns quic 0.0.0.0:1053\n"));
    try std.testing.expectError(error.BadPort, Config.parse("listen dns udp 0.0.0.0:notaport\n"));
}
