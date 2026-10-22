const std = @import("std");
const build_options = @import("build_options");

pub const golden_fixture = @import("golden_fixture.zig");
pub const dns_message = @import("dns/message.zig");
pub const dns_name = @import("dns/name.zig");
pub const dns_tsig = @import("dns/tsig.zig");
pub const dns_writer = @import("dns/writer.zig");
pub const dns_rdata = @import("dns/rdata.zig");
pub const dns_record = @import("dns/record.zig");
pub const dns_dnssec = @import("dns/dnssec.zig");
pub const dns_validate = @import("dns/validate.zig");
pub const zone_parser = @import("zone/parser.zig");
pub const zone_index = @import("zone/index.zig");
pub const zone_journal = @import("zone/journal.zig");
pub const zone_transfer = @import("zone/transfer.zig");
pub const auth_response = @import("auth/response.zig");
pub const auth_runtime = @import("auth/runtime.zig");
pub const auth_keyring = @import("auth/keyring.zig");
pub const listener = @import("platform/listener.zig");
pub const cli_query = @import("cli/query.zig");
pub const cli_zonemd = @import("cli/zonemd.zig");
pub const config_parser = @import("config/parser.zig");
pub const config_loader = @import("config/loader.zig");
pub const metrics = @import("metrics.zig");
pub const transport_tls = @import("transport/tls.zig");
pub const transport_tls_server = @import("transport/tls_server.zig");
pub const transport_dot = @import("transport/dot.zig");
pub const transport_doh = @import("transport/doh.zig");
/// The pinned TLS dependency, exported so the CLI guard can drive a DoH
/// exchange over the same client the server side uses.
pub const tls = @import("tls");
pub const transfer_axfr = @import("transfer/axfr.zig");
pub const transfer_xfr_tls = @import("transfer/xfr_tls.zig");
pub const blocklist = @import("blocklist.zig");
pub const resolver = @import("resolver.zig");
pub const local_zone = @import("local_zone.zig");
pub const zone_zonemd = @import("zone/zonemd.zig");
pub const zone_signer = @import("zone/signer.zig");

const ServerRunMode = enum { none, udp_once, tcp_once, udp_loop, tcp_loop, dot_loop, doh_loop, xfr_loop };

/// The runtime a SIGHUP asks to reload its zone. A signal handler cannot
/// take user data, so the running server is a process-wide pointer.
var reload_runtime: ?*auth_runtime.Runtime = null;

/// The SIGHUP handler sets the reload flag and nothing else: the zone file
/// is read and the zone is swapped by the serve path, outside the handler.
fn onSighup(_: std.posix.SIG) callconv(.c) void {
    if (reload_runtime) |runtime| runtime.requestZoneReload();
}

fn installReloadHandler(runtime: *auth_runtime.Runtime) void {
    reload_runtime = runtime;
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onSighup },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &action, null);
}

test {
    _ = @import("dns/reader.zig");
    _ = @import("dns/writer.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/name.zig");
    _ = @import("dns/types.zig");
    _ = @import("dns/rdata.zig");
    _ = @import("dns/dnssec.zig");
    _ = @import("dns/validate.zig");
    _ = @import("dns/record.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/message.zig");
    _ = @import("dns/tsig.zig");
    _ = golden_fixture;
    _ = @import("zone/journal.zig");
    _ = zone_parser;
    _ = zone_index;
    _ = zone_zonemd;
    _ = zone_signer;
    _ = @import("zone/transfer.zig");
    _ = auth_response;
    _ = auth_runtime;
    _ = auth_keyring;
    _ = listener;
    _ = transport_tls;
    _ = transport_tls_server;
    _ = transport_dot;
    _ = transport_doh;
    _ = transfer_axfr;
    _ = transfer_xfr_tls;
    _ = cli_query;
    _ = config_parser;
    _ = config_loader;
    _ = metrics;
    _ = blocklist;
    _ = resolver;
    _ = local_zone;
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
        try printVersion(stdout);
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

    if (std.mem.eql(u8, command, "zonemd")) {
        try handleZonemd(args, io, arena, stdout);
        return;
    }

    try stdout.print("error: command '{s}' is not implemented yet\n\n", .{command});
    try printHelp(stdout);
    try exitUsage(stdout);
}

fn printVersion(writer: *std.Io.Writer) !void {
    try writer.print("zimdns {s}\n", .{build_options.version});
}

test "--version prints the build version, not a placeholder" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try printVersion(&output.writer);
    try std.testing.expectEqualStrings("zimdns " ++ build_options.version ++ "\n", output.written());
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
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --serve-tcp
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --serve-doh
        \\  zimdns query @127.0.0.1 -p 1055 --dnssec signed.example. A
        \\  zimdns query @127.0.0.1 -p 1055 --zoneversion example.com A
        \\  zimdns query @127.0.0.1 -p 1055 --nsid example.com A
        \\  zimdns query @127.0.0.1 -p 1055 --0x20 example.com A
        \\  zimdns zonemd publish --zone-file examples/zones/home.arpa.zone
        \\
        \\  RFC 6303/6761/7793/8375 locally served zones are on by default and
        \\  are answered ahead of the cache and the forwarder. A configuration
        \\  turns them off with 'local-zones off'; examples/local-zones.gdns
        \\  is a worked configuration.
        \\
        \\  SIGHUP asks a running server to re-read its zone file and to
        \\  serve the new zone. A zone file that cannot be parsed, or that
        \\  carries no newer SOA serial, leaves the served zone in place.
        \\
        \\  --dnssec sets the RFC 6891 DO bit so the server returns its RRSIG
        \\  and NSEC records, which arrive in the answer and authority
        \\  sections and are printed under their section headings. Signing a
        \\  zone is a config directive: 'dnssec-key-file <path>' in
        \\  examples/dnssec/config.gdns is a worked configuration.
        \\
        \\  --nsid asks a server for its own identifier (RFC 5001 option
        \\  code 3) with an empty option. The answer prints the payload as
        \\  hexadecimal, two digits per octet. A server with no 'nsid'
        \\  directive answers no identifier at all.
        \\
        \\  --0x20 randomizes the case of the first letter of every label of
        \\  the question name, so a forged answer has to carry the exact case
        \\  to be accepted. The name still compares equal (RFC 1035 section
        \\  2.3.3) and the server copies the question into its answer, so the
        \\  CLI prints the question it asked, with the case it used. The
        \\  mechanism comes from the expired Internet-Draft
        \\  draft-vixie-dnsext-dns0x20 and is no RFC requirement, so it is
        \\  off unless the operator asks for it.
        \\
        \\  zonemd publish computes the RFC 8976 zone digest of a zone file
        \\  and prints the ZONEMD record in zone text, ready to paste into
        \\  the zone. The digest is computed over the zone as published: the
        \\  apex ZONEMD RRset and the RRSIG covering it stay outside it (RFC
        \\  8976 section 3.3.1.1), and the record carries the zone's SOA
        \\  serial (section 3.1). '--scheme' and '--hash' take the RFC 8976
        \\  registry codes: scheme 1 is SIMPLE, hash 1 is SHA384 and hash 2
        \\  is SHA512. A signed zone needs its ZONEMD RRset signed again
        \\  after the record is published (section 3.4).
        \\
        \\  --serve-dot serves DNS over TLS (RFC 7858) with the "dot" ALPN
        \\  token, --serve-doh serves DNS over HTTPS (RFC 8484) with the
        \\  "http/1.1" token, and --serve-xfr serves zone transfers over TLS
        \\  with the "dot" token (RFC 9103 section 7.1): each listener
        \\  terminates the handshake before it speaks DNS, so the port never
        \\  answers in cleartext. They need --enable-encrypted-dns and a
        \\  certificate and key.
        \\
        \\Implemented now:
        \\  --help, --version, server run, query, zonemd publish
        \\
    );
}

test "the help text documents the zonemd publish command" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try printHelp(&output.writer);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "zimdns zonemd publish --zone-file") != null);
}

fn handleQuery(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    var server_text: []const u8 = "127.0.0.1";
    var use_dnssec = false;
    var use_zoneversion = false;
    var use_nsid = false;
    var use_case_randomization = false;
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
        } else if (std.mem.eql(u8, arg, "--dnssec")) {
            use_dnssec = true;
        } else if (std.mem.eql(u8, arg, "--zoneversion")) {
            use_zoneversion = true;
        } else if (std.mem.eql(u8, arg, "--nsid")) {
            use_nsid = true;
        } else if (std.mem.eql(u8, arg, "--0x20")) {
            use_case_randomization = true;
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

    const qname = dns_name.Name.fromText(absolute_name) catch return cli_query.Error.BadName;
    // The 0x20 mechanism draws the case of the first letter of every label
    // from the system CSPRNG, so a forged answer has to match the exact case
    // to be accepted.
    var random_source = std.Random.IoSource{ .io = io };
    const question_name = if (use_case_randomization)
        qname.withRandomizedLabelFirstCase(random_source.interface())
    else
        qname;

    var packet_buffer: [512]u8 = undefined;
    const query = try cli_query.buildQueryPacketForName(&packet_buffer, query_id, question_name, qtype, .{ .dnssec_ok = use_dnssec, .zoneversion = use_zoneversion, .nsid = use_nsid });
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
    // The question the server echoed is what shows the case that went on the
    // wire, so it is printed only when the case was randomized.
    if (use_case_randomization) try cli_query.writeQuestion(response, writer);
    try cli_query.writeResponse(response, writer);
}

fn handleZonemd(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (args.len < 3 or !std.mem.eql(u8, args[2], "publish")) {
        try writer.writeAll("error: expected 'zonemd publish'\n");
        try exitUsage(writer);
    }

    var zone_path: ?[]const u8 = null;
    var scheme: u8 = 1;
    var hash: u8 = 1;

    var index: usize = 3;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--zone-file")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --zone-file requires a path\n");
                try exitUsage(writer);
            }
            zone_path = args[index];
        } else if (std.mem.eql(u8, arg, "--scheme")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --scheme requires a code\n");
                try exitUsage(writer);
            }
            scheme = std.fmt.parseInt(u8, args[index], 10) catch {
                try writer.writeAll("error: invalid scheme code\n");
                try exitUsage(writer);
            };
        } else if (std.mem.eql(u8, arg, "--hash")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --hash requires a code\n");
                try exitUsage(writer);
            }
            hash = std.fmt.parseInt(u8, args[index], 10) catch {
                try writer.writeAll("error: invalid hash code\n");
                try exitUsage(writer);
            };
        } else {
            try writer.print("error: unknown zonemd option '{s}'\n", .{arg});
            try exitUsage(writer);
        }
        index += 1;
    }

    const path = zone_path orelse {
        try writer.writeAll("error: zonemd publish requires --zone-file\n");
        try exitUsage(writer);
    };
    const zone_text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch {
        try writer.writeAll("error: cannot read the zone file\n");
        try exitFailure(writer);
    };

    // The publisher prints its own refusal line; the exit code says the
    // digest was not published.
    cli_zonemd.publish(zone_text, scheme, hash, allocator, writer) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => try exitFailure(writer),
    };
}

fn parseQueryType(text: []const u8) !@import("dns/types.zig").RecordType {
    const RecordType = @import("dns/types.zig").RecordType;
    if (std.ascii.eqlIgnoreCase(text, "A")) return .A;
    if (std.ascii.eqlIgnoreCase(text, "AAAA")) return .AAAA;
    if (std.ascii.eqlIgnoreCase(text, "NS")) return .NS;
    if (std.ascii.eqlIgnoreCase(text, "CNAME")) return .CNAME;
    if (std.ascii.eqlIgnoreCase(text, "MX")) return .MX;
    if (std.ascii.eqlIgnoreCase(text, "TXT")) return .TXT;
    if (std.ascii.eqlIgnoreCase(text, "SOA")) return .SOA;
    if (std.ascii.eqlIgnoreCase(text, "PTR")) return .PTR;
    if (std.ascii.eqlIgnoreCase(text, "DNAME")) return .DNAME;
    if (std.ascii.eqlIgnoreCase(text, "RP")) return .RP;
    if (std.ascii.eqlIgnoreCase(text, "RT")) return .RT;
    if (std.ascii.eqlIgnoreCase(text, "AFSDB")) return .AFSDB;
    if (std.ascii.eqlIgnoreCase(text, "X25")) return .X25;
    if (std.ascii.eqlIgnoreCase(text, "ISDN")) return .ISDN;
    if (std.ascii.eqlIgnoreCase(text, "SSHFP")) return .SSHFP;
    if (std.ascii.eqlIgnoreCase(text, "TLSA")) return .TLSA;
    if (std.ascii.eqlIgnoreCase(text, "NAPTR")) return .NAPTR;
    if (std.ascii.eqlIgnoreCase(text, "APL")) return .APL;
    if (std.ascii.eqlIgnoreCase(text, "URI")) return .URI;
    if (std.ascii.eqlIgnoreCase(text, "CAA")) return .CAA;
    if (std.ascii.eqlIgnoreCase(text, "SRV")) return .SRV;
    if (std.ascii.eqlIgnoreCase(text, "SVCB")) return RecordType.fromCode(64);
    if (std.ascii.eqlIgnoreCase(text, "HTTPS")) return RecordType.fromCode(65);
    if (std.ascii.eqlIgnoreCase(text, "DS")) return RecordType.fromCode(43);
    if (std.ascii.eqlIgnoreCase(text, "RRSIG")) return RecordType.fromCode(46);
    if (std.ascii.eqlIgnoreCase(text, "NSEC")) return RecordType.fromCode(47);
    if (std.ascii.eqlIgnoreCase(text, "DNSKEY")) return RecordType.fromCode(48);
    if (std.ascii.eqlIgnoreCase(text, "NSEC3")) return RecordType.fromCode(50);
    if (std.ascii.eqlIgnoreCase(text, "NSEC3PARAM")) return RecordType.fromCode(51);
    if (text.len > 4 and std.ascii.eqlIgnoreCase(text[0..4], "TYPE")) {
        const code = std.fmt.parseInt(u16, text[4..], 10) catch return error.UnsupportedType;
        return RecordType.fromCode(code);
    }
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
    var encrypted_dns_flag = false;
    var tls_cert_file: ?[]const u8 = null;
    var tls_key_file: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "--serve-dot")) {
            mode = .dot_loop;
        } else if (std.mem.eql(u8, arg, "--serve-doh")) {
            mode = .doh_loop;
        } else if (std.mem.eql(u8, arg, "--serve-xfr")) {
            mode = .xfr_loop;
        } else if (std.mem.eql(u8, arg, "--enable-encrypted-dns")) {
            encrypted_dns_flag = true;
        } else if (std.mem.eql(u8, arg, "--tls-cert-file")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --tls-cert-file requires a path\n");
                try exitUsage(writer);
            }
            tls_cert_file = args[index];
        } else if (std.mem.eql(u8, arg, "--tls-key-file")) {
            index += 1;
            if (index >= args.len) {
                try writer.writeAll("error: --tls-key-file requires a path\n");
                try exitUsage(writer);
            }
            tls_key_file = args[index];
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
        try writer.writeAll("error: server run currently requires --once-udp, --once-tcp, --serve-udp, --serve-tcp, --serve-dot, --serve-doh, or --serve-xfr\n");
        try exitUsage(writer);
    }

    // The identity of the encrypted listener, loaded before any socket is
    // bound: a broken identity refuses the run instead of leaving a port
    // open.
    var tls_identity: ?transport_tls_server.Server = null;
    defer if (tls_identity) |*server| server.deinit();

    if (mode == .dot_loop or mode == .doh_loop or mode == .xfr_loop) {
        const cert_path = tls_cert_file orelse (if (server_context) |*context| context.config.tlsCertFileText() else null);
        const key_path = tls_key_file orelse (if (server_context) |*context| context.config.tlsKeyFileText() else null);
        const enabled = encrypted_dns_flag or (if (server_context) |*context| context.config.encrypted_dns else false);
        transport_tls.requireEnabled(enabled) catch {
            try writer.writeAll("error: encrypted listeners require --enable-encrypted-dns or 'encrypted-dns on'\n");
            try exitUsage(writer);
        };
        // Every encrypted transport this build accepts has a listener of its
        // own, so the transport decides the ALPN token the handshake selects.
        const transport: transport_tls.Transport = switch (mode) {
            .dot_loop => .dot,
            .doh_loop => .doh,
            .xfr_loop => .xfr,
            else => unreachable,
        };
        if (cert_path == null or key_path == null) {
            try writer.writeAll("error: encrypted listeners require --tls-cert-file and --tls-key-file (or tls-cert-file/tls-key-file)\n");
            try exitUsage(writer);
        }
        transport_tls.validatePaths(cert_path.?, key_path.?) catch {
            try writer.writeAll("error: TLS certificate and key paths must be set and distinct\n");
            try exitUsage(writer);
        };
        const cert_bytes = std.Io.Dir.cwd().readFileAlloc(io, cert_path.?, allocator, .limited(1024 * 1024)) catch {
            try writer.writeAll("error: cannot read TLS certificate file\n");
            try exitUsage(writer);
        };
        defer allocator.free(cert_bytes);
        const key_bytes = std.Io.Dir.cwd().readFileAlloc(io, key_path.?, allocator, .limited(1024 * 1024)) catch {
            try writer.writeAll("error: cannot read TLS key file\n");
            try exitUsage(writer);
        };
        defer allocator.free(key_bytes);
        transport_tls.validatePemPair(cert_bytes, key_bytes) catch {
            try writer.writeAll("error: TLS identity failed validation (certificate must be PEM, key must be nonempty)\n");
            try exitUsage(writer);
        };
        // The identity is loaded before the bind, so a certificate or key
        // that cannot be loaded refuses the run and binds no port.
        var server: transport_tls_server.Server = undefined;
        server.init(allocator, io, std.Io.Dir.cwd(), cert_path.?, key_path.?, transport_tls.alpnFor(transport)) catch {
            try writer.writeAll("error: cannot load the TLS certificate and key\n");
            try exitUsage(writer);
        };
        tls_identity = server;
    }

    var runtime: auth_runtime.Runtime = undefined;
    // A configuration names the zone file it loads. Only a single-zone
    // configuration is reloadable: replacing a whole zone set is a different
    // operation this profile does not have.
    const config_zone_path: ?[]const u8 = if (server_context) |*context|
        if (context.config.zones.len == 1)
            try allocator.dupe(u8, context.config.zones.items[0].fileText())
        else
            null
    else
        null;
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
    // The handler must not reach a runtime that is already gone.
    defer reload_runtime = null;
    // SIGHUP replaces the zone from the zone file the server was started
    // from. The handler only sets a flag; the serve path reads the file and
    // swaps the zone.
    const reload_path: ?[]const u8 = if (explicit_zone_file) zone_file else config_zone_path;
    if (reload_path) |path| {
        if (runtime.zones.items.len == 1) {
            try runtime.setReloadSource(std.Io.Dir.cwd(), path, runtime.zones.items[0].originText());
        }
    }
    installReloadHandler(&runtime);
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
        .dot_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            // The encrypted listener runs on its own backend with the same
            // worker bound the cleartext TCP listener uses.
            var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
                .concurrent_limit = .limited(transport_dot.MAX_CONNECTION_WORKERS),
            });
            defer io_backend.deinit();
            const dot_io = io_backend.io();
            if (configured_address) |*address| {
                try transport_dot.serveDotLoopOnAddress(dot_io, &runtime, address, &server, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try transport_dot.serveDotLoopOnAddress(dot_io, &runtime, &address, &server, max_requests);
            }
        },
        .doh_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            // The encrypted listener runs on its own backend with the same
            // worker bound the cleartext TCP listener uses.
            var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
                .concurrent_limit = .limited(transport_doh.MAX_CONNECTION_WORKERS),
            });
            defer io_backend.deinit();
            const doh_io = io_backend.io();
            if (configured_address) |*address| {
                try transport_doh.serveDohLoopOnAddress(doh_io, &runtime, address, &server, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try transport_doh.serveDohLoopOnAddress(doh_io, &runtime, &address, &server, max_requests);
            }
        },
        // The strict-TLS transfer channel: the same handshake and the same
        // worker bound as the other encrypted listeners.
        .xfr_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            var io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
                .concurrent_limit = .limited(transfer_xfr_tls.MAX_CONNECTION_WORKERS),
            });
            defer io_backend.deinit();
            const xfr_io = io_backend.io();
            if (configured_address) |*address| {
                try transfer_xfr_tls.serveXfrLoopOnAddress(xfr_io, &runtime, address, &server, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try transfer_xfr_tls.serveXfrLoopOnAddress(xfr_io, &runtime, &address, &server, max_requests);
            }
        },
        .none => unreachable,
    }

    if (print_metrics) {
        try metrics.formatPrometheus(counters, writer);
    }
}

fn findListenerAddress(config: *const config_parser.Config, mode: ServerRunMode) !?std.Io.net.IpAddress {
    const want: config_parser.Transport = switch (mode) {
        .udp_once, .udp_loop => .udp,
        .tcp_once, .tcp_loop => .tcp,
        .dot_loop, .xfr_loop => .dot,
        .doh_loop => .doh,
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
        \\listen dns dot 127.0.0.1:12055
        \\listen dns doh 127.0.0.1:12056
        \\
    );
    const expected_udp = try std.Io.net.IpAddress.parse("127.0.0.1", 12053);
    const udp = try findListenerAddress(&config, .udp_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(udp.eql(&expected_udp));

    const expected_tcp = try std.Io.net.IpAddress.parse("127.0.0.1", 12054);
    const tcp = try findListenerAddress(&config, .tcp_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(tcp.eql(&expected_tcp));

    const expected_dot = try std.Io.net.IpAddress.parse("127.0.0.1", 12055);
    const dot = try findListenerAddress(&config, .dot_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(dot.eql(&expected_dot));
    const xfr = try findListenerAddress(&config, .xfr_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(xfr.eql(&expected_dot));

    const expected_doh = try std.Io.net.IpAddress.parse("127.0.0.1", 12056);
    const doh = try findListenerAddress(&config, .doh_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(doh.eql(&expected_doh));
}

test "no-config listener default is loopback" {
    const address = defaultListenerAddress(1053);
    const expected = std.Io.net.IpAddress{ .ip4 = .loopback(1053) };
    try std.testing.expect(address.eql(&expected));
}

test "the encrypted listeners exist and each speaks its own ALPN token" {
    // 1. Every encrypted transport this build accepts has a listener: each
    //    terminates the handshake with its own ALPN token before any DNS
    //    byte is written.
    try std.testing.expect(@hasDecl(transport_dot, "serveDotLoopOnAddress"));
    try std.testing.expect(@hasDecl(transport_doh, "serveDohLoopOnAddress"));
    try std.testing.expect(@hasDecl(transfer_xfr_tls, "serveXfrLoopOnAddress"));

    // 2. The zone-transfer channel speaks "dot", which RFC 9103 section 7.1
    //    requires for the transfer channel.
    try std.testing.expectEqualStrings("dot", transport_tls.alpnFor(.xfr));
    try std.testing.expectEqualStrings("dot", transfer_xfr_tls.XFR_ALPN);

    // 3. Each port speaks its own token and nothing else, so a client that
    //    offers another protocol is refused instead of served. The refusal
    //    itself is proven over a real handshake in src/transport/dot.zig and
    //    src/transport/doh.zig, not here.
    try std.testing.expectEqualStrings("dot", transport_tls.alpnFor(.dot));
    try std.testing.expectEqualStrings("http/1.1", transport_tls.alpnFor(.doh));
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

test "query parser accepts PTR case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.PTR, try parseQueryType("PTR"));
    try std.testing.expectEqual(RecordType.PTR, try parseQueryType("ptr"));
    try std.testing.expectEqual(RecordType.PTR, try parseQueryType("Ptr"));
}

test "query parser accepts DNAME case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.DNAME, try parseQueryType("DNAME"));
    try std.testing.expectEqual(RecordType.DNAME, try parseQueryType("dname"));
    try std.testing.expectEqual(RecordType.DNAME, try parseQueryType("Dname"));
}

test "query parser accepts SVCB and HTTPS case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.fromCode(64), try parseQueryType("SVCB"));
    try std.testing.expectEqual(RecordType.fromCode(64), try parseQueryType("svcb"));
    try std.testing.expectEqual(RecordType.fromCode(64), try parseQueryType("SvCb"));
    try std.testing.expectEqual(RecordType.fromCode(65), try parseQueryType("HTTPS"));
    try std.testing.expectEqual(RecordType.fromCode(65), try parseQueryType("https"));
    try std.testing.expectEqual(RecordType.fromCode(65), try parseQueryType("Https"));
}

test "query parser accepts DNSSEC types case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.fromCode(43), try parseQueryType("DS"));
    try std.testing.expectEqual(RecordType.fromCode(43), try parseQueryType("ds"));
    try std.testing.expectEqual(RecordType.fromCode(46), try parseQueryType("RRSIG"));
    try std.testing.expectEqual(RecordType.fromCode(46), try parseQueryType("rrsig"));
    try std.testing.expectEqual(RecordType.fromCode(47), try parseQueryType("NSEC"));
    try std.testing.expectEqual(RecordType.fromCode(47), try parseQueryType("nsec"));
    try std.testing.expectEqual(RecordType.fromCode(48), try parseQueryType("DNSKEY"));
    try std.testing.expectEqual(RecordType.fromCode(48), try parseQueryType("dnskey"));
    try std.testing.expectEqual(RecordType.fromCode(50), try parseQueryType("NSEC3"));
    try std.testing.expectEqual(RecordType.fromCode(50), try parseQueryType("nsec3"));
    try std.testing.expectEqual(RecordType.fromCode(51), try parseQueryType("NSEC3PARAM"));
    try std.testing.expectEqual(RecordType.fromCode(51), try parseQueryType("nsec3param"));
}

test "query parser accepts generic TYPE codes case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.fromCode(1), try parseQueryType("TYPE1"));
    try std.testing.expectEqual(RecordType.fromCode(65), try parseQueryType("TYPE65"));
    try std.testing.expectEqual(RecordType.fromCode(65), try parseQueryType("type65"));
    try std.testing.expectEqual(RecordType.fromCode(64), try parseQueryType("Type64"));
    try std.testing.expectEqual(RecordType.fromCode(255), try parseQueryType("TYPE255"));
    try std.testing.expectEqual(RecordType.fromCode(65535), try parseQueryType("TYPE65535"));
}

test "query parser rejects malformed TYPE codes" {
    try std.testing.expectError(error.UnsupportedType, parseQueryType("TYPE"));
    try std.testing.expectError(error.UnsupportedType, parseQueryType("type"));
    try std.testing.expectError(error.UnsupportedType, parseQueryType("TYPE65536"));
    try std.testing.expectError(error.UnsupportedType, parseQueryType("TYPEabc"));
    try std.testing.expectError(error.UnsupportedType, parseQueryType("TYPE-1"));
    try std.testing.expectError(error.UnsupportedType, parseQueryType("FOO"));
}

test "query parser matches named types case-insensitively" {
    const RecordType = @import("dns/types.zig").RecordType;
    try std.testing.expectEqual(RecordType.A, try parseQueryType("a"));
    try std.testing.expectEqual(RecordType.AAAA, try parseQueryType("aaaa"));
    try std.testing.expectEqual(RecordType.SRV, try parseQueryType("srv"));
}

test "the 0x20 query asks a randomized name and prints the question the server echoed" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN home.arpa.
        \\$TTL 3600
        \\@ IN SOA ns1.home.arpa. hostmaster.home.arpa. 1 3600 900 1209600 3600
        \\@ IN NS ns1.home.arpa.
        \\a.b.c.d.e.f.g.h IN A 192.0.2.1
        \\
    );
    defer runtime.deinit();

    // Many labels: the chance that every run draws the same case is
    // negligible.
    const typed = "a.b.c.d.e.f.g.h.home.arpa.";

    // One query against a one-shot server, and the CLI's output.
    const Query = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        runtime: *auth_runtime.Runtime,
        typed: []const u8,
        randomized: bool,

        fn run(self: *@This()) ![]const u8 {
            var server_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            var server_socket = try std.Io.net.IpAddress.bind(&server_addr, self.io, .{ .mode = .dgram, .protocol = .udp });
            defer server_socket.close(self.io);

            const Server = struct {
                io: std.Io,
                socket: *const std.Io.net.Socket,
                runtime: *auth_runtime.Runtime,
                ok: bool = false,

                fn run(server: *@This()) void {
                    listener.serveUdpOnce(server.socket, server.io, server.runtime) catch return;
                    server.ok = true;
                }
            };
            var server = Server{ .io = self.io, .socket = &server_socket, .runtime = self.runtime };
            const server_thread = try std.Thread.spawn(.{}, Server.run, .{&server});

            var port_buffer: [8]u8 = undefined;
            const port_text = try std.fmt.bufPrint(&port_buffer, "{}", .{server_socket.address.getPort()});
            var args: [8][]const u8 = undefined;
            var count: usize = 0;
            args[count] = "zimdns";
            count += 1;
            args[count] = "query";
            count += 1;
            args[count] = "@127.0.0.1";
            count += 1;
            args[count] = "-p";
            count += 1;
            args[count] = port_text;
            count += 1;
            if (self.randomized) {
                args[count] = "--0x20";
                count += 1;
            }
            args[count] = self.typed;
            count += 1;
            args[count] = "A";
            count += 1;

            var output: std.Io.Writer.Allocating = .init(self.allocator);
            defer output.deinit();
            try handleQuery(args[0..count], self.io, self.allocator, &output.writer);
            server_thread.join();
            try std.testing.expect(server.ok);
            return self.allocator.dupe(u8, output.written());
        }
    };

    const Printed = struct {
        // The question the CLI printed: the line under the section heading.
        fn question(output: []const u8) []const u8 {
            const marker = ";; QUESTION SECTION:\n";
            const start = std.mem.indexOf(u8, output, marker) orelse return "";
            const rest = output[start + marker.len ..];
            const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
            return rest[0..end];
        }

        // The printed name must differ from the typed one only in the case of
        // a label's first letter.
        fn onlyLabelFirstCaseChanged(wanted: []const u8, printed: []const u8) bool {
            if (wanted.len != printed.len) return false;
            var label_start = true;
            for (wanted, printed) |wanted_byte, printed_byte| {
                if (wanted_byte == '.') {
                    if (printed_byte != '.') return false;
                    label_start = true;
                    continue;
                }
                if (label_start) {
                    if (std.ascii.toLower(wanted_byte) != std.ascii.toLower(printed_byte)) return false;
                } else if (wanted_byte != printed_byte) {
                    return false;
                }
                label_start = false;
            }
            return true;
        }
    };

    var questions: [4][]const u8 = undefined;
    for (&questions) |*question| {
        var randomized = Query{
            .io = io,
            .allocator = allocator,
            .runtime = &runtime,
            .typed = typed,
            .randomized = true,
        };
        const output = try randomized.run();
        question.* = Printed.question(output);
        // The answer carries the zone's own case; the question carries the
        // case the client chose.
        try std.testing.expect(std.mem.indexOf(u8, output, "a.b.c.d.e.f.g.h.home.arpa. 3600 IN A 192.0.2.1") != null);
        try std.testing.expect(Printed.onlyLabelFirstCaseChanged(typed, question.*));
    }
    // The case is drawn, so the runs do not all ask the same name.
    var same = true;
    for (questions[1..]) |question| {
        if (!std.mem.eql(u8, question, questions[0])) same = false;
    }
    try std.testing.expect(!same);

    // Without the switch the query is unchanged: no question section, and the
    // answer as it was.
    var plain_query = Query{
        .io = io,
        .allocator = allocator,
        .runtime = &runtime,
        .typed = typed,
        .randomized = false,
    };
    const plain = try plain_query.run();
    try std.testing.expect(std.mem.indexOf(u8, plain, ";; QUESTION SECTION:") == null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "a.b.c.d.e.f.g.h.home.arpa. 3600 IN A 192.0.2.1") != null);
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
        runtime: *auth_runtime.Runtime,
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

test "the SIGHUP handler asks for a zone reload and does nothing else" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try auth_runtime.Runtime.fromZoneText(
        \\$ORIGIN example.
        \\$TTL 3600
        \\@ IN SOA ns.example. hostmaster.example. 10 3600 900 1209600 3600
        \\@ IN NS ns.example.
        \\www IN A 192.0.2.1
        \\
    );
    defer runtime.deinit();
    defer reload_runtime = null;
    installReloadHandler(&runtime);

    // No reload was asked for yet.
    try std.testing.expect(runtime.reloadZoneIfRequested(io) == null);

    try std.posix.raise(std.posix.SIG.HUP);

    // The handler only set the flag: the reload itself happens outside it.
    try std.testing.expectEqual(auth_runtime.ReloadOutcome.no_source, runtime.reloadZoneIfRequested(io).?);
    try std.testing.expect(runtime.reloadZoneIfRequested(io) == null);
}
