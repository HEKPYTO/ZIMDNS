const std = @import("std");

pub const golden_fixture = @import("golden_fixture.zig");
pub const dns_message = @import("dns/message.zig");
pub const dns_name = @import("dns/name.zig");
pub const dns_tsig = @import("dns/tsig.zig");
pub const dns_writer = @import("dns/writer.zig");
pub const dns_rdata = @import("dns/rdata.zig");
pub const dns_record = @import("dns/record.zig");
pub const zone_parser = @import("zone/parser.zig");
pub const zone_index = @import("zone/index.zig");
pub const zone_store = @import("zone/store.zig");
pub const auth_response = @import("auth/response.zig");
pub const auth_runtime = @import("auth/runtime.zig");
pub const auth_keyring = @import("auth/keyring.zig");
pub const listener = @import("platform/listener.zig");
pub const cli_query = @import("cli/query.zig");
pub const config_parser = @import("config/parser.zig");
pub const config_loader = @import("config/loader.zig");
pub const metrics = @import("metrics.zig");
pub const blocklist = @import("blocklist.zig");
pub const resolver = @import("resolver.zig");

const ServerRunMode = enum { none, udp_once, tcp_once, udp_loop, tcp_loop };
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
    _ = @import("dns/tsig.zig");
    _ = golden_fixture;
    _ = @import("zone/journal.zig");
    _ = zone_parser;
    _ = zone_index;
    _ = zone_store;
    _ = auth_response;
    _ = auth_runtime;
    _ = auth_keyring;
    _ = listener;
    _ = cli_query;
    _ = config_parser;
    _ = config_loader;
    _ = metrics;
    _ = blocklist;
    _ = resolver;
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
        \\  zimdns server run --config examples/config.gdns --serve-udp --max-requests 2
        \\  zimdns query @127.0.0.1 -p 1053 example.com A
        \\
        \\Implemented now:
        \\  --help, --version, server run, query
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

    var query_id_bytes: [2]u8 = undefined;
    io.random(&query_id_bytes);
    const query_id = std.mem.readInt(u16, &query_id_bytes, .big);
    var packet_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacket(&packet_buffer, query_id, absolute_name, qtype);
    const server = std.Io.net.IpAddress.parse(server_text, port) catch {
        try writer.writeAll("error: query server must be an IP address for now\n");
        try exitUsage(writer);
    };

    var response_buffer: [listener.UDP_RESPONSE_BUFFER_SIZE]u8 = undefined;
    var response = if (use_tcp)
        try queryTcp(allocator, io, &server, query, &response_buffer)
    else
        try queryUdp(allocator, io, &server, query, &response_buffer);
    defer response.deinit();
    try cli_query.writeResponse(response, writer);
}

fn parseQueryType(text: []const u8) !@import("dns/types.zig").RecordType {
    if (std.mem.eql(u8, text, "A")) return .A;
    if (std.mem.eql(u8, text, "AAAA")) return .AAAA;
    if (std.mem.eql(u8, text, "NS")) return .NS;
    if (std.mem.eql(u8, text, "CNAME")) return .CNAME;
    if (std.mem.eql(u8, text, "MX")) return .MX;
    if (std.mem.eql(u8, text, "TXT")) return .TXT;
    if (std.mem.eql(u8, text, "SOA")) return .SOA;
    if (std.mem.eql(u8, text, "RP")) return .RP;
    if (std.mem.eql(u8, text, "RT")) return .RT;
    if (std.mem.eql(u8, text, "AFSDB")) return .AFSDB;
    if (std.mem.eql(u8, text, "X25")) return .X25;
    if (std.mem.eql(u8, text, "ISDN")) return .ISDN;
    if (std.mem.eql(u8, text, "SSHFP")) return .SSHFP;
    if (std.mem.eql(u8, text, "TLSA")) return .TLSA;
    if (std.mem.eql(u8, text, "NAPTR")) return .NAPTR;
    if (std.mem.eql(u8, text, "APL")) return .APL;
    if (std.mem.eql(u8, text, "URI")) return .URI;
    if (std.mem.eql(u8, text, "CAA")) return .CAA;
    if (std.mem.eql(u8, text, "SRV")) return .SRV;
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
    var client_addr = cli_query.udpClientBindAddress(server);
    var socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try cli_query.sendUdpQuery(&socket, io, server, query);
    return cli_query.receiveUdpResponse(allocator, &socket, io, response_buffer, server, query);
}

fn queryTcp(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8) !@import("dns/message.zig").Message {
    return cli_query.exchangeTcpQuery(allocator, io, server, query, response_buffer);
}

fn handleServer(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (args.len < 3) {
        try writer.writeAll("error: expected 'server run'\n");
        try exitUsage(writer);
    }
    if (!std.mem.eql(u8, args[2], "run")) {
        try writer.writeAll("error: expected 'server run'\n");
        try exitUsage(writer);
    }

    var config_file: ?[]const u8 = null;
    var zone_file: ?[]const u8 = null;
    var mode: ServerRunMode = .none;
    var port_set = false;
    var port: u16 = 1053;
    var configured_address: ?std.Io.net.IpAddress = null;
    var max_queries: usize = 1;
    var max_requests: ?usize = null;
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
        } else if (std.mem.eql(u8, arg, "--serve-udp")) {
            mode = .udp_loop;
        } else if (std.mem.eql(u8, arg, "--serve-tcp")) {
            mode = .tcp_loop;
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
        } else if (std.mem.eql(u8, arg, "--max-requests")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --max-requests requires a count\n");
                try exitUsage(writer);
            }
            max_requests = std.fmt.parseInt(usize, args[index], 10) catch {
                try writer.writeAll("error: invalid max request count\n");
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
            if (try findListenerAddress(&server_context.?.config, mode)) |address| {
                configured_address = address;
                port = address.getPort();
            }
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
        runtime = try server_context.?.takeRuntime(io);
    } else {
        const path = zone_file orelse {
            try writer.writeAll("error: server run requires --zone-file or --config with a zone\n");
            try exitUsage(writer);
        };
        const zone_text = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
        if (server_context) |*context| {
            runtime = try auth_runtime.Runtime.fromZoneTextWithBlocklistAndKeyring(zone_text, context.blocklist, &context.keyring);
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
            if (configured_address) |*address| {
                if (print_metrics) {
                    try listener.serveUdpCountOnAddressWithMetrics(io, &runtime, address, max_queries, &counters);
                } else if (max_queries == 1) {
                    try listener.serveUdpOnceOnAddress(io, &runtime, address);
                } else {
                    try listener.serveUdpCountOnAddress(io, &runtime, address, max_queries);
                }
            } else if (print_metrics) {
                var address = defaultListenerAddress(port);
                try listener.serveUdpCountOnAddressWithMetrics(io, &runtime, &address, max_queries, &counters);
            } else if (max_queries == 1) {
                var address = defaultListenerAddress(port);
                try listener.serveUdpOnceOnAddress(io, &runtime, &address);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveUdpCountOnAddress(io, &runtime, &address, max_queries);
            }
        },
        .tcp_once => {
            if (print_metrics) {
                try writer.writeAll("error: --print-metrics is currently supported for UDP runs\n");
                try exitUsage(writer);
            }
            if (max_queries != 1) {
                try writer.writeAll("error: TCP accepts exactly one query per connection\n");
                try exitUsage(writer);
            }
            if (configured_address) |*address| {
                try listener.serveTcpOnceOnAddress(io, &runtime, address);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveTcpOnceOnAddress(io, &runtime, &address);
            }
        },
        .udp_loop => {
            if (max_requests) |count| if (count == 0) {
                try writer.writeAll("error: --max-requests must be greater than zero\n");
                try exitUsage(writer);
            };
            if (print_metrics) {
                if (configured_address) |*address| {
                    try listener.serveUdpLoopOnAddressWithMetrics(io, &runtime, address, max_requests, &counters);
                } else {
                    var address = defaultListenerAddress(port);
                    try listener.serveUdpLoopOnAddressWithMetrics(io, &runtime, &address, max_requests, &counters);
                }
            } else if (configured_address) |*address| {
                try listener.serveUdpLoopOnAddress(io, &runtime, address, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveUdpLoopOnAddress(io, &runtime, &address, max_requests);
            }
        },
        .tcp_loop => {
            if (print_metrics) {
                try writer.writeAll("error: --print-metrics is currently supported for UDP runs\n");
                try exitUsage(writer);
            }
            var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
                .concurrent_limit = .limited(listener.TCP_MAX_CONNECTION_WORKERS),
            });
            defer io_backend.deinit();
            const tcp_io = io_backend.io();
            if (configured_address) |*address| {
                try listener.serveTcpLoopOnAddress(tcp_io, &runtime, address, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveTcpLoopOnAddress(tcp_io, &runtime, &address, max_requests);
            }
        },
        .none => unreachable,
    }

    if (print_metrics) {
        var metrics_buffer: [512]u8 = undefined;
        const text = try metrics.formatPrometheus(counters, &metrics_buffer);
        try writer.writeAll(text);
    }
}

fn findListenerAddress(config: *const config_parser.Config, mode: ServerRunMode) !?std.Io.net.IpAddress {
    const want: config_parser.Transport = switch (mode) {
        .udp_once, .udp_loop => .udp,
        .tcp_once, .tcp_loop => .tcp,
        .none => return null,
    };
    var index: usize = 0;
    while (index < config.listeners.len) : (index += 1) {
        const configured_listener = config.listeners.items[index];
        if (configured_listener.transport != want) continue;
        const address = try std.Io.net.IpAddress.parse(configured_listener.addressText(), configured_listener.port);
        return @as(?std.Io.net.IpAddress, address);
    }
    return null;
}

fn defaultListenerAddress(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .loopback(port) };
}

test "configured loop modes use their transport listener endpoint" {
    const config = try config_parser.Config.parse(
        \\listen dns udp 127.0.0.1:12053
        \\listen dns tcp 127.0.0.1:12054
        \\
    );
    const expected_udp = try std.Io.net.IpAddress.parse("127.0.0.1", 12053);
    const udp = try findListenerAddress(&config, .udp_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(udp.eql(&expected_udp));

    const expected_tcp = try std.Io.net.IpAddress.parse("127.0.0.1", 12054);
    const tcp = try findListenerAddress(&config, .tcp_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(tcp.eql(&expected_tcp));
}

test "no-config listener default is loopback" {
    const address = defaultListenerAddress(1053);
    const expected = std.Io.net.IpAddress{ .ip4 = .loopback(1053) };
    try std.testing.expect(address.eql(&expected));
}

fn exitUsage(writer: *std.Io.Writer) !noreturn {
    try writer.flush();
    std.process.exit(2);
}

fn exitFailure(writer: *std.Io.Writer) !noreturn {
    try writer.flush();
    std.process.exit(1);
}
test "query parser accepts SSHFP" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.SSHFP, try parseQueryType("SSHFP"));
}

test "query parser accepts TLSA" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.TLSA, try parseQueryType("TLSA"));
}

test "query parser accepts URI" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.URI, try parseQueryType("URI"));
}

test "query parser accepts NAPTR" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.NAPTR, try parseQueryType("NAPTR"));
}

test "query parser accepts APL" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.APL, try parseQueryType("APL"));
}

test "query parser accepts AFSDB" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.AFSDB, try parseQueryType("AFSDB"));
}

test "query parser accepts RP" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.RP, try parseQueryType("RP"));
}

test "query parser accepts CAA" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.CAA, try parseQueryType("CAA"));
}

test "query parser accepts X25" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.X25, try parseQueryType("X25"));
}

test "query parser accepts ISDN" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.ISDN, try parseQueryType("ISDN"));
}

test "query parser accepts RT" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.RT, try parseQueryType("RT"));
}

test "query parser accepts SRV" {
    try std.testing.expectEqual(@import("dns/types.zig").RecordType.SRV, try parseQueryType("SRV"));
}

test "query command renders a maximum escaped URI target" {
    const io = std.Io.Threaded.global_single_threaded.io();

    var zone_text: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer zone_text.deinit();
    try zone_text.writer.writeAll(
        "$ORIGIN home.arpa.\n" ++
            "$TTL 3600\n" ++
            "@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600\n" ++
            "@ IN NS ns1.home.arpa.\n" ++
            "_uri IN URI 0 0 \"",
    );
    var index: usize = 0;
    while (index < 508) : (index += 1) try zone_text.writer.writeAll("\\000");
    try zone_text.writer.writeAll("\"\n");

    var runtime = try auth_runtime.Runtime.fromZoneText(zone_text.written());
    defer runtime.deinit();

    var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try std.Io.net.IpAddress.listen(&server_addr, io, .{ .reuse_address = true });
    defer server.deinit(io);

    const ServerArgs = struct {
        io: std.Io,
        server: *std.Io.net.Server,
        runtime: *const auth_runtime.Runtime,
        ok: bool = false,

        fn run(self: *@This()) void {
            const stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);
            listener.serveTcpStreamOnce(stream, self.io, self.runtime) catch return;
            self.ok = true;
        }
    };
    var server_args = ServerArgs{ .io = io, .server = &server, .runtime = &runtime };
    const server_thread = try std.Thread.spawn(.{}, ServerArgs.run, .{&server_args});

    var port_buffer: [5]u8 = undefined;
    const port_text = try std.fmt.bufPrint(&port_buffer, "{}", .{server.socket.address.getPort()});
    const args = [_][]const u8{ "zimdns", "query", "@127.0.0.1", "-p", port_text, "--tcp", "_uri.home.arpa.", "URI" };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    handleQuery(&args, io, std.testing.allocator, &output.writer) catch |err| {
        server_thread.join();
        return err;
    };
    server_thread.join();
    try std.testing.expect(server_args.ok);

    var expected: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer expected.deinit();
    try expected.writer.writeAll("_uri.home.arpa. 3600 IN URI 0 0 \"");
    index = 0;
    while (index < 508) : (index += 1) try expected.writer.writeAll("\\000");
    try expected.writer.writeAll("\"\n");
    try std.testing.expect(expected.written().len > 2048);
    try std.testing.expectEqualSlices(u8, expected.written(), output.written());
}
