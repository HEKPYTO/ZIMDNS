const std = @import("std");

pub const golden_fixture = @import("golden_fixture.zig");
pub const dns_message = @import("dns/message.zig");
pub const dns_name = @import("dns/name.zig");
pub const zone_parser = @import("zone/parser.zig");
pub const zone_index = @import("zone/index.zig");
pub const auth_response = @import("auth/response.zig");
pub const auth_runtime = @import("auth/runtime.zig");
pub const listener = @import("platform/listener.zig");
pub const cli_query = @import("cli/query.zig");
pub const config_parser = @import("config/parser.zig");
pub const config_loader = @import("config/loader.zig");
pub const doctor = @import("doctor.zig");
pub const cache_store = @import("cache/store.zig");
pub const metrics = @import("metrics.zig");
pub const blocklist = @import("blocklist.zig");
pub const admin_protocol = @import("admin/protocol.zig");
pub const admin_service = @import("admin/service.zig");
pub const admin_socket = @import("admin/socket.zig");
pub const backup_manifest = @import("backup/manifest.zig");

const ServerRunMode = enum { none, udp_once, tcp_once };
const version_text = "0.0.0";

test {
    _ = @import("dns/reader.zig");
    _ = @import("dns/writer.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/name.zig");
    _ = @import("dns/types.zig");
    _ = @import("dns/rdata.zig");
    _ = @import("dns/record.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/message.zig");
    _ = golden_fixture;
    _ = zone_parser;
    _ = zone_index;
    _ = auth_response;
    _ = auth_runtime;
    _ = listener;
    _ = cli_query;
    _ = config_parser;
    _ = config_loader;
    _ = doctor;
    _ = cache_store;
    _ = metrics;
    _ = blocklist;
    _ = admin_protocol;
    _ = admin_service;
    _ = admin_socket;
    _ = backup_manifest;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    const args = try init.minimal.args.toSlice(arena);
    const command = if (args.len > 1) args[1] else {
        try printHelp(stdout);
        return;
    };

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or std.mem.eql(u8, command, "help")) {
        try printHelp(stdout);
        return;
    }

    if (std.mem.eql(u8, command, "--version")) {
        try stdout.print("zimdns {s}\n", .{version_text});
        return;
    }

    if (std.mem.eql(u8, command, "server")) {
        try handleServer(args, io, arena, stdout);
        return;
    }

    if (std.mem.eql(u8, command, "query")) {
        try handleQuery(args, io, arena, stdout);
        return;
    }

    if (std.mem.eql(u8, command, "doctor")) {
        try handleDoctor(args, io, arena, stdout);
        return;
    }

    if (std.mem.eql(u8, command, "backup")) {
        try handleBackup(args, io, arena, stdout);
        return;
    }

    try stdout.print("error: command '{s}' is not implemented yet\n\n", .{command});
    try printHelp(stdout);
    try exitUsage(stdout);
}

fn printHelp(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\zimdns - Zig DNS server platform
        \\
        \\Usage:
        \\  zimdns --help
        \\  zimdns --version
        \\  zimdns server run
        \\  zimdns server run --config examples/config.gdns --once-udp
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --once-udp 1053
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --once-udp 1053 --max-queries 2 --print-metrics
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --once-tcp 1053
        \\  zimdns server admin --config examples/config.gdns --once
        \\  zimdns query @127.0.0.1 -p 1053 example.com A
        \\  zimdns zone list
        \\  zimdns record list <zone>
        \\  zimdns cache stats
        \\  zimdns doctor --config examples/config.gdns
        \\  zimdns backup manifest --config examples/config.gdns
        \\  zimdns metrics
        \\
        \\Implemented now:
        \\  --help, --version, server run --once-udp/--once-tcp, query, doctor
        \\
    );
}

fn handleQuery(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    var server_text: []const u8 = "127.0.0.1";
    var port: u16 = 1053;
    var use_tcp = false;
    var name: ?[]const u8 = null;
    var qtype = @import("dns/types.zig").RecordType.A;

    var index: usize = 2;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.startsWith(u8, arg, "@")) {
            server_text = arg[1..];
        } else if (std.mem.eql(u8, arg, "-p")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: -p requires a port\n");
                try exitUsage(writer);
            }
            port = std.fmt.parseInt(u16, args[index], 10) catch {
                try writer.writeAll("error: invalid query port\n");
                try exitUsage(writer);
            };
        } else if (std.mem.eql(u8, arg, "--tcp")) {
            use_tcp = true;
        } else if (name == null) {
            name = arg;
        } else {
            qtype = parseQueryType(arg) catch {
                try writer.writeAll("error: unsupported query type\n");
                try exitUsage(writer);
            };
        }
        index += 1;
    }

    const query_name = name orelse {
        try writer.writeAll("error: query requires a name\n");
        try exitUsage(writer);
    };
    var absolute_name_buffer: [256]u8 = undefined;
    const absolute_name = try ensureAbsoluteName(query_name, &absolute_name_buffer);

    var packet_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet_buffer, 0x1234, absolute_name, qtype);
    const server = std.Io.net.IpAddress.parse(server_text, port) catch {
        try writer.writeAll("error: query server must be an IP address for now\n");
        try exitUsage(writer);
    };

    var response_buffer: [512]u8 = undefined;
    const response = if (use_tcp)
        try queryTcp(allocator, io, &server, query, &response_buffer)
    else
        try queryUdp(allocator, io, &server, query, &response_buffer);
    var text_buffer: [2048]u8 = undefined;
    const text = try cli_query.formatResponse(response, &text_buffer);
    try writer.writeAll(text);
}

fn parseQueryType(text: []const u8) !@import("dns/types.zig").RecordType {
    if (std.mem.eql(u8, text, "A")) return .A;
    if (std.mem.eql(u8, text, "AAAA")) return .AAAA;
    if (std.mem.eql(u8, text, "NS")) return .NS;
    if (std.mem.eql(u8, text, "CNAME")) return .CNAME;
    if (std.mem.eql(u8, text, "MX")) return .MX;
    if (std.mem.eql(u8, text, "TXT")) return .TXT;
    if (std.mem.eql(u8, text, "SOA")) return .SOA;
    return error.UnsupportedType;
}

fn ensureAbsoluteName(name: []const u8, buffer: []u8) ![]const u8 {
    if (std.mem.endsWith(u8, name, ".")) return name;
    if (name.len + 1 > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = '.';
    return buffer[0 .. name.len + 1];
}

fn queryUdp(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8) !@import("dns/message.zig").Message {
    var client_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try cli_query.sendUdpQuery(&socket, io, server, query);
    return cli_query.receiveUdpResponse(allocator, &socket, io, response_buffer, 0x1234);
}

fn queryTcp(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8) !@import("dns/message.zig").Message {
    var stream = try std.Io.net.IpAddress.connect(server, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);
    try cli_query.sendTcpQuery(stream, io, query);
    return cli_query.receiveTcpResponse(allocator, stream, io, response_buffer, 0x1234);
}

fn handleServer(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (args.len < 3) {
        try writer.writeAll("error: expected 'server run' or 'server admin'\n");
        try exitUsage(writer);
    }
    if (std.mem.eql(u8, args[2], "admin")) return handleServerAdmin(args, io, allocator, writer);
    if (!std.mem.eql(u8, args[2], "run")) {
        try writer.writeAll("error: expected 'server run' or 'server admin'\n");
        try exitUsage(writer);
    }

    var config_file: ?[]const u8 = null;
    var zone_file: ?[]const u8 = null;
    var mode: ServerRunMode = .none;
    var port_set = false;
    var port: u16 = 1053;
    var max_queries: usize = 1;
    var print_metrics = false;

    var index: usize = 3;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--config")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --config requires a path\n");
                try exitUsage(writer);
            }
            config_file = args[index];
        } else if (std.mem.eql(u8, arg, "--zone-file")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --zone-file requires a path\n");
                try exitUsage(writer);
            }
            zone_file = args[index];
        } else if (std.mem.eql(u8, arg, "--once-udp")) {
            mode = .udp_once;
            if (index + 1 < args.len and !std.mem.startsWith(u8, args[index + 1], "--")) {
                index += 1;
                port = std.fmt.parseInt(u16, args[index], 10) catch {
                    try writer.writeAll("error: invalid UDP port\n");
                    try exitUsage(writer);
                };
                port_set = true;
            }
        } else if (std.mem.eql(u8, arg, "--once-tcp")) {
            mode = .tcp_once;
            if (index + 1 < args.len and !std.mem.startsWith(u8, args[index + 1], "--")) {
                index += 1;
                port = std.fmt.parseInt(u16, args[index], 10) catch {
                    try writer.writeAll("error: invalid TCP port\n");
                    try exitUsage(writer);
                };
                port_set = true;
            }
        } else if (std.mem.eql(u8, arg, "--max-queries")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --max-queries requires a count\n");
                try exitUsage(writer);
            }
            max_queries = std.fmt.parseInt(usize, args[index], 10) catch {
                try writer.writeAll("error: invalid max query count\n");
                try exitUsage(writer);
            };
        } else if (std.mem.eql(u8, arg, "--print-metrics")) {
            print_metrics = true;
        } else {
            try writer.print("error: unknown server option '{s}'\n", .{arg});
            try exitUsage(writer);
        }
        index += 1;
    }

    const explicit_zone_file = zone_file != null;
    var server_context: ?config_loader.ServerContext = null;
    defer if (server_context) |*context| context.deinit();

    if (config_file) |path| {
        server_context = try config_loader.ServerContext.load(std.Io.Dir.cwd(), io, path, allocator);
        if (!port_set) {
            if (findListenerPort(&server_context.?.config, mode)) |config_port| port = config_port;
        }
    }

    if (mode == .none) {
        try writer.writeAll("error: server run currently requires --once-udp or --once-tcp\n");
        try exitUsage(writer);
    }

    var runtime: auth_runtime.Runtime = undefined;
    if (!explicit_zone_file and server_context != null) {
        if (server_context.?.zones.items.len == 0) {
            try writer.writeAll("error: server run requires --zone-file or --config with a zone\n");
            try exitUsage(writer);
        }
        runtime = try server_context.?.takePrimaryRuntime();
    } else {
        const path = zone_file orelse {
            try writer.writeAll("error: server run requires --zone-file or --config with a zone\n");
            try exitUsage(writer);
        };
        const zone_text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        if (server_context) |*context| {
            runtime = try auth_runtime.Runtime.fromZoneTextWithBlocklist(zone_text, context.blocklist);
        } else {
            runtime = try auth_runtime.Runtime.fromZoneText(zone_text);
        }
    }
    defer runtime.deinit();
    var counters = metrics.Counters{};

    switch (mode) {
        .udp_once => {
            if (max_queries == 0) {
                try writer.writeAll("error: --max-queries must be greater than zero\n");
                try exitUsage(writer);
            }
            if (print_metrics) {
                try listener.serveUdpCountOnPortWithMetrics(io, &runtime, port, max_queries, &counters);
            } else if (max_queries == 1) {
                try listener.serveUdpOnceOnPort(io, &runtime, port);
            } else {
                try listener.serveUdpCountOnPort(io, &runtime, port, max_queries);
            }
        },
        .tcp_once => {
            if (print_metrics) {
                try writer.writeAll("error: --print-metrics is currently supported for UDP runs\n");
                try exitUsage(writer);
            }
            if (max_queries == 0 or max_queries > listener.TCP_MAX_MESSAGES_PER_CONNECTION) {
                try writer.print("error: TCP --max-queries must be between 1 and {d}\n", .{listener.TCP_MAX_MESSAGES_PER_CONNECTION});
                try exitUsage(writer);
            }
            try listener.serveTcpCountOnPort(io, &runtime, port, max_queries);
        },
        .none => unreachable,
    }

    if (print_metrics) {
        var metrics_buffer: [512]u8 = undefined;
        const text = try metrics.formatPrometheus(counters, &metrics_buffer);
        try writer.writeAll(text);
    }
}

fn handleServerAdmin(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    var config_file: ?[]const u8 = null;
    var once = false;
    var now_seconds: u64 = 0;

    var index: usize = 3;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--config")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --config requires a path\n");
                try exitUsage(writer);
            }
            config_file = args[index];
        } else if (std.mem.eql(u8, arg, "--once")) {
            once = true;
        } else if (std.mem.eql(u8, arg, "--now")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --now requires seconds\n");
                try exitUsage(writer);
            }
            now_seconds = std.fmt.parseInt(u64, args[index], 10) catch {
                try writer.writeAll("error: invalid --now value\n");
                try exitUsage(writer);
            };
        } else {
            try writer.print("error: unknown server admin option '{s}'\n", .{arg});
            try exitUsage(writer);
        }
        index += 1;
    }

    if (!once) {
        try writer.writeAll("error: server admin currently requires --once\n");
        try exitUsage(writer);
    }
    const config_path = config_file orelse {
        try writer.writeAll("error: server admin requires --config\n");
        try exitUsage(writer);
    };
    const config_text = try std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1024 * 1024));
    const parsed_config = try config_parser.Config.parse(config_text);
    const socket_path = parsed_config.admin_socket.pathText();
    if (socket_path.len == 0) {
        try writer.writeAll("error: config must define admin socket\n");
        try exitUsage(writer);
    }

    const service = admin_service.Service{
        .version = version_text,
        .started_at_seconds = now_seconds,
        .metrics = .{},
    };
    try admin_socket.serveUnixOnce(socket_path, io, service, now_seconds);
}

fn handleDoctor(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    var config_file: ?[]const u8 = null;
    var index: usize = 2;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--config")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --config requires a path\n");
                try exitUsage(writer);
            }
            config_file = args[index];
        } else {
            try writer.print("error: unknown doctor option '{s}'\n", .{arg});
            try exitUsage(writer);
        }
        index += 1;
    }

    const config_path = config_file orelse {
        try writer.writeAll("error: doctor requires --config\n");
        try exitUsage(writer);
    };

    const config_text = try std.Io.Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1024 * 1024));
    const parsed_config = try config_parser.Config.parse(config_text);
    var report = doctor.Report{};
    try doctor.inspectParsedConfig(&parsed_config, &report);

    var zone_index_value: usize = 0;
    while (zone_index_value < parsed_config.zones.len) : (zone_index_value += 1) {
        const zone = parsed_config.zones.items[zone_index_value];
        const zone_text = std.Io.Dir.cwd().readFileAlloc(io, zone.fileText(), allocator, .limited(1024 * 1024)) catch {
            try report.add(.invalid_zone);
            continue;
        };
        try doctor.inspectZoneText(zone.nameText(), zone_text, &report);
    }

    var blocklist_index: usize = 0;
    while (blocklist_index < parsed_config.blocklists.len) : (blocklist_index += 1) {
        const blocklist_file = parsed_config.blocklists.items[blocklist_index];
        const blocklist_text = std.Io.Dir.cwd().readFileAlloc(io, blocklist_file.pathText(), allocator, .limited(1024 * 1024)) catch {
            try report.add(.invalid_blocklist);
            continue;
        };
        try doctor.inspectBlocklistText(blocklist_text, &report);
    }

    if (report.ok()) {
        try writer.writeAll("doctor: ok\n");
        return;
    }

    try writer.writeAll("doctor: failed\n");
    var issue_index: usize = 0;
    while (issue_index < report.issue_count) : (issue_index += 1) {
        try writer.print("- {s}\n", .{doctor.issueName(report.issues[issue_index])});
    }
    try exitFailure(writer);
}

fn handleBackup(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (args.len < 3 or !std.mem.eql(u8, args[2], "manifest")) {
        try writer.writeAll("error: expected 'backup manifest'\n");
        try exitUsage(writer);
    }

    var config_file: ?[]const u8 = null;
    var index: usize = 3;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--config")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --config requires a path\n");
                try exitUsage(writer);
            }
            config_file = args[index];
        } else {
            try writer.print("error: unknown backup manifest option '{s}'\n", .{arg});
            try exitUsage(writer);
        }
        index += 1;
    }

    const config_path = config_file orelse {
        try writer.writeAll("error: backup manifest requires --config\n");
        try exitUsage(writer);
    };
    const manifest = try backup_manifest.Manifest.fromConfigFile(std.Io.Dir.cwd(), io, config_path, allocator);
    var manifest_buffer: [4096]u8 = undefined;
    const text = try manifest.render(&manifest_buffer);
    try writer.writeAll(text);
}

fn findListenerPort(config: *const config_parser.Config, mode: ServerRunMode) ?u16 {
    const want: config_parser.Transport = switch (mode) {
        .udp_once => .udp,
        .tcp_once => .tcp,
        .none => return null,
    };
    var index: usize = 0;
    while (index < config.listeners.len) : (index += 1) {
        if (config.listeners.items[index].transport == want) return config.listeners.items[index].port;
    }
    return null;
}

fn exitUsage(writer: *std.Io.Writer) !noreturn {
    try writer.flush();
    std.process.exit(2);
}

fn exitFailure(writer: *std.Io.Writer) !noreturn {
    try writer.flush();
    std.process.exit(1);
}
