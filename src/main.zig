const std = @import("std");
const build_options = @import("build_options");

pub const golden_fixture = @import("golden_fixture.zig");
pub const dns_message = @import("dns/message.zig");
pub const dns_name = @import("dns/name.zig");
pub const dns_tsig = @import("dns/tsig.zig");
pub const dns_types = @import("dns/types.zig");
pub const dns_writer = @import("dns/writer.zig");
pub const dns_rdata = @import("dns/rdata.zig");
pub const dns_record = @import("dns/record.zig");
pub const dns_dnssec = @import("dns/dnssec.zig");
pub const dns_odoh = @import("dns/odoh.zig");
pub const dns_validate = @import("dns/validate.zig");
pub const zone_parser = @import("zone/parser.zig");
pub const zone_index = @import("zone/index.zig");
pub const zone_update = @import("zone/update.zig");
pub const zone_journal = @import("zone/journal.zig");
pub const zone_transfer = @import("zone/transfer.zig");
pub const auth_response = @import("auth/response.zig");
pub const auth_runtime = @import("auth/runtime.zig");
pub const auth_keyring = @import("auth/keyring.zig");
pub const listener = @import("platform/listener.zig");
pub const tcp_deadline = @import("platform/tcp_deadline.zig");
pub const cli_query = @import("cli/query.zig");
pub const config_parser = @import("config/parser.zig");
pub const config_loader = @import("config/loader.zig");
pub const metrics = @import("metrics.zig");
pub const transport_tls = @import("transport/tls.zig");
pub const transport_tls_server = @import("transport/tls_server.zig");
pub const transport_tls_client = @import("transport/tls_client.zig");
pub const transport_doh_client = @import("transport/doh_client.zig");
pub const transport_dot = @import("transport/dot.zig");
pub const transport_doh = @import("transport/doh.zig");
pub const transport_doq = @import("transport/doq.zig");
pub const transport_doh3 = @import("transport/doh3.zig");
pub const transport_stream_registry = @import("transport/stream_registry.zig");
/// The OpenSSL TLS wrapper, exported so the CLI guard can drive a DoH
/// exchange over the same client the server side uses.
pub const transport_openssl_tls = @import("transport/openssl_tls.zig");
pub const transfer_axfr = @import("transfer/axfr.zig");
pub const transfer_xfr_tls = @import("transfer/xfr_tls.zig");
pub const blocklist = @import("blocklist.zig");
pub const resolver = @import("resolver.zig");
pub const local_zone = @import("local_zone.zig");
pub const zone_zonemd = @import("zone/zonemd.zig");
pub const zone_signer = @import("zone/signer.zig");

const ServerRunMode = enum { none, udp_once, tcp_once, udp_loop, tcp_loop, dot_loop, doh_loop, doq_loop, doh3_loop, xfr_loop };

/// Which loops one `server run` serves. Every `--serve-*` flag adds a loop;
/// all selected loops run at once in one process against the same runtime.
const ServeSelection = struct {
    once: ?ServerRunMode = null,
    udp: bool = false,
    tcp: bool = false,
    dot: bool = false,
    doh: bool = false,
    doq: bool = false,
    doh3: bool = false,
    xfr: bool = false,

    fn anyServe(self: ServeSelection) bool {
        return self.udp or self.tcp or self.dot or self.doh or self.doq or self.doh3 or self.xfr;
    }

    fn anyEncrypted(self: ServeSelection) bool {
        return self.dot or self.doh or self.doq or self.doh3 or self.xfr;
    }

    fn loopModes(self: ServeSelection, out: *[7]ServerRunMode) usize {
        var count: usize = 0;
        if (self.udp) {
            out[count] = .udp_loop;
            count += 1;
        }
        if (self.tcp) {
            out[count] = .tcp_loop;
            count += 1;
        }
        if (self.dot) {
            out[count] = .dot_loop;
            count += 1;
        }
        if (self.doh) {
            out[count] = .doh_loop;
            count += 1;
        }
        if (self.doq) {
            out[count] = .doq_loop;
            count += 1;
        }
        if (self.doh3) {
            out[count] = .doh3_loop;
            count += 1;
        }
        if (self.xfr) {
            out[count] = .xfr_loop;
            count += 1;
        }
        return count;
    }
};

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
/// Every serve loop observes this stop: SIGTERM/SIGINT set it and exit 0
/// at once, so the process never waits out the compose grace period.
/// There is no in-flight drain: blocked accepts die with the process.
var signal_stop = std.atomic.Value(?*auth_runtime.SharedStop).init(null);
///
/// SIGTERM/SIGINT end the process at once: the shared stop is set so a
/// sibling that already observes it can finish its boundary, then exit(0)
/// ends the process without waiting. In-flight queries are not drained.
fn onTerminate(_: std.posix.SIG) callconv(.c) void {
    if (signal_stop.load(.acquire)) |stop| stop.requestStop();
    // Async-signal-safe: `_exit` skips atexit handlers and stdio flushes,
    // which `std.process.exit` runs and which are not safe in a handler.
    std.c._exit(0);
}
///
fn installTerminateHandlers(stop: *auth_runtime.SharedStop) void {
    signal_stop.store(stop, .release);
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onTerminate },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
}

test "terminate handler path sets the shared stop" {
    var old_term: std.posix.Sigaction = undefined;
    var old_int: std.posix.Sigaction = undefined;
    std.posix.sigaction(std.posix.SIG.TERM, null, &old_term);
    std.posix.sigaction(std.posix.SIG.INT, null, &old_int);
    defer {
        std.posix.sigaction(std.posix.SIG.TERM, &old_term, null);
        std.posix.sigaction(std.posix.SIG.INT, &old_int, null);
        signal_stop.store(null, .release);
    }
    var stop = auth_runtime.SharedStop{};
    installTerminateHandlers(&stop);
    try std.testing.expect(signal_stop.load(.acquire) == &stop);
    signal_stop.load(.acquire).?.requestStop();
    try std.testing.expect(stop.shouldStop());
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
    _ = @import("dns/managed_anchors.zig");
    _ = @import("dns/record.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/message.zig");
    _ = @import("dns/tsig.zig");
    _ = dns_odoh;
    _ = @import("dns/ed448.zig");
    _ = golden_fixture;
    _ = @import("zone/journal.zig");
    _ = zone_parser;
    _ = zone_index;
    _ = zone_update;
    _ = zone_zonemd;
    _ = zone_signer;
    _ = @import("zone/transfer.zig");
    _ = auth_response;
    _ = auth_runtime;
    _ = auth_keyring;
    _ = listener;
    _ = transport_tls;
    _ = transport_tls_server;
    _ = transport_openssl_tls;
    _ = tcp_deadline;
    _ = transport_tls_client;
    _ = transport_doh_client;
    _ = transport_dot;
    _ = transport_doh;
    _ = transport_doq;
    _ = transport_doh3;
    _ = transport_stream_registry;
    _ = transfer_axfr;
    _ = transfer_xfr_tls;
    _ = cli_query;
    _ = config_parser;
    _ = config_loader;
    _ = metrics;
    _ = blocklist;
    _ = resolver;
    _ = @import("iterate.zig");
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
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --serve-doq
        \\  zimdns server run --zone-file examples/zones/home.arpa.zone --serve-doh3
        \\  zimdns query @127.0.0.1 -p 1055 --dnssec signed.example. A
        \\  zimdns query @127.0.0.1 -p 1055 --zoneversion example.com A
        \\  zimdns query @127.0.0.1 -p 1055 --nsid example.com A
        \\  zimdns query @127.0.0.1 -p 1055 --0x20 example.com A
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
        \\  --serve-dot serves DNS over TLS (RFC 7858) with the "dot" ALPN
        \\  token, --serve-doh serves DNS over HTTPS (RFC 8484) with the
        \\  "http/1.1" token, --serve-doh3 serves DNS over HTTPS over HTTP/3
        \\  (RFC 9114) with the "h3" token, --serve-doq serves DNS over QUIC (RFC 9250)
        \\  with the "doq" token, and --serve-xfr serves zone transfers over TLS
        \\  with the "dot" token (RFC 9103 section 7.1): each listener
        \\  terminates the handshake before it speaks DNS, so the port never
        \\  answers in cleartext. They need --enable-encrypted-dns and a
        \\  certificate and key. An Oblivious DoH target is one config line:
        \\  'odoh-target on' with 'odoh-key-file <path>' (RFC 9230).
        \\
        \\  The server prints one startup banner on stderr: the version, the
        \\  config path, the selected transports with their listen addresses,
        \\  and every zone origin with its SOA serial. A live metrics listener
        \\  is one flag: '--metrics-addr 127.0.0.1:9090' serves the same
        \\  Prometheus text as --print-metrics on GET /metrics and readiness
        \\  on GET /healthz (200 once serving, 503 before). The address must
        \\  be loopback; anything else is refused. SIGTERM and SIGINT end the
        \\  process at once without waiting out the stop grace period, with
        \\  no in-flight drain: blocked accepts die with the process.
        \\
        \\  A healthcheck asks the server about itself: 'query --require-noerror'
        \\  fails on SERVFAIL, REFUSED and NXDOMAIN instead of printing them
        \\  and exiting 0, and '--require-answer' additionally fails on an
        \\  empty answer section. The default query behavior is unchanged.
        \\
        \\Implemented now:
        \\  --help, --version, server run, query
        \\
    );
}

fn handleQuery(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (try printHelpIfRequested(args, writer)) return;
    var server_text: []const u8 = "127.0.0.1";
    var use_dnssec = false;
    var use_zoneversion = false;
    var use_nsid = false;
    var use_case_randomization = false;
    var port: u16 = 1053;
    var use_tcp = false;
    var require_noerror = false;
    var require_answer = false;
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
        } else if (std.mem.eql(u8, arg, "--require-noerror")) {
            require_noerror = true;
        } else if (std.mem.eql(u8, arg, "--require-answer")) {
            require_answer = true;
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
    // from the system CSPRNG; the receive path requires the echoed question
    // to match those bytes exactly, so a forged answer has to match the case
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
        try queryTcp(allocator, io, &server, query, &response_buffer, use_case_randomization)
    else
        try queryUdp(allocator, io, &server, query, &response_buffer, use_case_randomization);
    defer response.deinit();
    // The question the server echoed is what shows the case that went on the
    // wire, so it is printed only when the case was randomized.
    if (use_case_randomization) try cli_query.writeQuestion(response, writer);
    try cli_query.writeResponse(response, writer);
    // A healthcheck fails on SERVFAIL/REFUSED/NXDOMAIN instead of printing
    // them and exiting 0; `--require-answer` additionally fails on an empty
    // answer section. Default query behavior is unchanged.
    if (require_noerror and response.header.rcode != .no_error) {
        try writer.print("error: query failed with rcode {t}\n", .{response.header.rcode});
        try writer.flush();
        std.process.exit(1);
    }
    if (require_answer and response.answers.len == 0) {
        try writer.writeAll("error: query returned no answers\n");
        try writer.flush();
        std.process.exit(1);
    }
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

/// Appends the trailing dot a relative question name is missing.
fn ensureAbsoluteName(name: []const u8, buffer: []u8) ![]const u8 {
    if (std.mem.endsWith(u8, name, ".")) return name;
    if (name.len + 1 > buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = '.';
    return buffer[0 .. name.len + 1];
}

fn queryUdp(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8, require_exact_qname_case: bool) !@import("dns/message.zig").Message {
    var client_addr = cli_query.udpClientBindAddress(server);
    var socket = try std.Io.net.IpAddress.bind(&client_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try cli_query.sendUdpQuery(&socket, io, server, query);
    return cli_query.receiveUdpResponse(allocator, &socket, io, response_buffer, server, query, require_exact_qname_case);
}

fn queryTcp(allocator: std.mem.Allocator, io: std.Io, server: *const std.Io.net.IpAddress, query: []const u8, response_buffer: []u8, require_exact_qname_case: bool) !@import("dns/message.zig").Message {
    return cli_query.exchangeTcpQuery(allocator, io, server, query, response_buffer, require_exact_qname_case);
}

/// A `--help` anywhere after the subcommand prints the same usage a bare
/// `zimdns --help` prints. Without this, `query --help` parsed the flag as the
/// query name and failed with BadName.
fn printHelpIfRequested(args: []const []const u8, writer: *std.Io.Writer) !bool {
    if (args.len <= 2) return false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp(writer);
            return true;
        }
    }
    return false;
}

/// The parsed `server run` command line. Pure data: parsing never touches
/// io or exits, so tests exercise the same path production dispatches from.
const ServerArgs = struct {
    config_file: ?[]const u8 = null,
    zone_file: ?[]const u8 = null,
    selection: ServeSelection = .{},
    port_set: bool = false,
    port: u16 = 1053,
    max_queries: usize = 1,
    max_requests: ?usize = null,
    print_metrics: bool = false,
    // Optional live metrics listener `ip:port` (CLI only, no config
    // directive). Loopback only; anything else is refused at startup.
    metrics_addr: ?[]const u8 = null,
    encrypted_dns_flag: bool = false,
    tls_cert_file: ?[]const u8 = null,
    tls_key_file: ?[]const u8 = null,

    const Error = error{
        MissingValue,
        InvalidPort,
        InvalidCount,
        UnknownOption,
        DuplicateOneShot,
        OneShotWithServe,
    };

    fn parse(args: []const []const u8) Error!ServerArgs {
        var parsed = ServerArgs{};
        var index: usize = 0;
        while (index < args.len) {
            const arg = args[index];
            if (std.mem.eql(u8, arg, "--config")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.config_file = args[index];
            } else if (std.mem.eql(u8, arg, "--zone-file")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.zone_file = args[index];
            } else if (std.mem.eql(u8, arg, "--once-udp")) {
                if (parsed.selection.once != null) return error.DuplicateOneShot;
                if (parsed.selection.anyServe()) return error.OneShotWithServe;
                parsed.selection.once = .udp_once;
                if (index + 1 < args.len and !std.mem.startsWith(u8, args[index + 1], "--")) {
                    index += 1;
                    parsed.port = std.fmt.parseInt(u16, args[index], 10) catch return error.InvalidPort;
                    parsed.port_set = true;
                }
            } else if (std.mem.eql(u8, arg, "--once-tcp")) {
                if (parsed.selection.once != null) return error.DuplicateOneShot;
                if (parsed.selection.anyServe()) return error.OneShotWithServe;
                parsed.selection.once = .tcp_once;
                if (index + 1 < args.len and !std.mem.startsWith(u8, args[index + 1], "--")) {
                    index += 1;
                    parsed.port = std.fmt.parseInt(u16, args[index], 10) catch return error.InvalidPort;
                    parsed.port_set = true;
                }
            } else if (std.mem.eql(u8, arg, "--serve-udp")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.udp = true;
            } else if (std.mem.eql(u8, arg, "--serve-tcp")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.tcp = true;
            } else if (std.mem.eql(u8, arg, "--serve-dot")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.dot = true;
            } else if (std.mem.eql(u8, arg, "--serve-doh")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.doh = true;
            } else if (std.mem.eql(u8, arg, "--serve-doq")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.doq = true;
            } else if (std.mem.eql(u8, arg, "--serve-doh3")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.doh3 = true;
            } else if (std.mem.eql(u8, arg, "--serve-xfr")) {
                if (parsed.selection.once != null) return error.OneShotWithServe;
                parsed.selection.xfr = true;
            } else if (std.mem.eql(u8, arg, "--enable-encrypted-dns")) {
                parsed.encrypted_dns_flag = true;
            } else if (std.mem.eql(u8, arg, "--tls-cert-file")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.tls_cert_file = args[index];
            } else if (std.mem.eql(u8, arg, "--tls-key-file")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.tls_key_file = args[index];
            } else if (std.mem.eql(u8, arg, "--max-queries")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.max_queries = std.fmt.parseInt(usize, args[index], 10) catch return error.InvalidCount;
            } else if (std.mem.eql(u8, arg, "--max-requests")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.max_requests = std.fmt.parseInt(usize, args[index], 10) catch return error.InvalidCount;
            } else if (std.mem.eql(u8, arg, "--print-metrics")) {
                parsed.print_metrics = true;
            } else if (std.mem.eql(u8, arg, "--metrics-addr")) {
                index += 1;
                if (index >= args.len) return error.MissingValue;
                parsed.metrics_addr = args[index];
            } else {
                return error.UnknownOption;
            }
            index += 1;
        }
        return parsed;
    }
};

/// Splits `ip:port` (`[v6]:port` for IPv6) the way `--metrics-addr` takes it.
fn parseMetricsAddr(text: []const u8) !std.Io.net.IpAddress {
    if (text.len > 0 and text[0] == '[') {
        const end = std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidMetricsAddr;
        if (end + 1 >= text.len or text[end + 1] != ':') return error.InvalidMetricsAddr;
        const port = std.fmt.parseInt(u16, text[end + 2 ..], 10) catch return error.InvalidMetricsAddr;
        if (port == 0) return error.InvalidMetricsAddr;
        return std.Io.net.IpAddress.parse(text[1..end], port) catch return error.InvalidMetricsAddr;
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidMetricsAddr;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidMetricsAddr;
    if (port == 0) return error.InvalidMetricsAddr;
    return std.Io.net.IpAddress.parse(text[0..colon], port) catch return error.InvalidMetricsAddr;
}

/// Only loopback listeners are allowed for now: the endpoint has no auth.
fn isLoopbackAddress(address: *const std.Io.net.IpAddress) bool {
    return switch (address.*) {
        .ip4 => |ip4| ip4.bytes[0] == 127,
        .ip6 => |ip6| std.mem.eql(u8, ip6.bytes[0..15], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }) and ip6.bytes[15] == 1,
    };
}

/// One HTTP connection on the metrics listener: `GET /metrics` renders the
/// same Prometheus text as `--print-metrics` from the same live counters,
/// `GET /healthz` reports readiness, anything else is 404.
fn serveMetricsConnection(stream: std.Io.net.Stream, io: std.Io, counters: *metrics.Counters, serving: *std.atomic.Value(bool)) void {
    defer stream.close(io);
    var request_buffer: [4096]u8 = undefined;
    // A local client that connects and sends nothing must not wedge the
    // listener: one short bounded read per connection, partial lines are
    // malformed and close.
    const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } };
    const incoming = stream.socket.receiveTimeout(io, &request_buffer, timeout) catch return;
    const newline = std.mem.indexOfScalar(u8, incoming.data, '\n') orelse return;
    const line = std.mem.trimEnd(u8, incoming.data[0..newline], "\r");
    const path: []const u8 = if (std.mem.startsWith(u8, line, "GET ")) path: {
        const rest = line[4..];
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse break :path "";
        break :path rest[0..end];
    } else "";
    var response_buffer: [8192]u8 = undefined;
    var writer = stream.writer(io, &response_buffer);
    const out = &writer.interface;
    if (std.mem.eql(u8, path, "/metrics")) {
        var counter_buffer: [8192]u8 = undefined;
        var counter_stream = std.Io.Writer.fixed(&counter_buffer);
        metrics.formatPrometheus(counters, &counter_stream) catch return;
        const body = counter_buffer[0..counter_stream.end];
        out.print("HTTP/1.0 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\nconnection: close\r\ncontent-length: {d}\r\n\r\n", .{body.len}) catch return;
        out.writeAll(body) catch return;
    } else if (std.mem.eql(u8, path, "/healthz")) {
        if (serving.load(.acquire)) {
            out.writeAll("HTTP/1.0 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 3\r\n\r\nok\n") catch return;
        } else {
            out.writeAll("HTTP/1.0 503 Service Unavailable\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 9\r\n\r\nstarting\n") catch return;
        }
    } else {
        out.writeAll("HTTP/1.0 404 Not Found\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 10\r\n\r\nnot found\n") catch return;
    }
    out.flush() catch {};
}

/// The live metrics/health listener. Runs on its own thread against the same
/// counters every serve loop shares, so `/metrics` reflects the running
/// server (unlike `--print-metrics`, which prints once at the end). The
/// thread is detached: a blocked accept dies with the process, the same as
/// every other loop's blocked accept.
const MetricsListener = struct {
    io: std.Io,
    counters: *metrics.Counters,
    serving: *std.atomic.Value(bool),
    address: std.Io.net.IpAddress,
    stop: *const auth_runtime.SharedStop,
    // Set when the bind fails, so startup can refuse the run instead of
    // serving DNS with no metrics endpoint.
    bind_err: ?anyerror = null,
    bound: std.atomic.Value(bool) = .init(false),

    fn run(self: *MetricsListener) void {
        var bind_address = self.address;
        var server = std.Io.net.IpAddress.listen(&bind_address, self.io, .{ .reuse_address = true }) catch |err| {
            self.bind_err = err;
            self.bound.store(true, .release);
            return;
        };
        defer server.deinit(self.io);
        self.bound.store(true, .release);
        while (!self.stop.shouldStop()) {
            // A poll with a short timeout makes the stop flag observable
            // without a wakeup, so the owner can join this thread before it
            // frees the counters and io backend behind it.
            var poll_fds = [_]std.posix.pollfd{.{ .fd = server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&poll_fds, 200) catch |err| {
                if (self.stop.shouldStop()) return;
                logMetricsListenerError(self.io, err);
                continue;
            };
            if (ready == 0) continue;
            const stream = listener.acceptWithRetry(&server, self.io) catch |err| {
                if (self.stop.shouldStop()) return;
                logMetricsListenerError(self.io, err);
                continue;
            };
            serveMetricsConnection(stream, self.io, self.counters, self.serving);
        }
    }
};

fn logMetricsListenerError(io: std.Io, err: anyerror) void {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.File.stderr().writer(io, &buffer);
    writer.interface.print("warning: metrics listener: {t}\n", .{err}) catch {};
    writer.interface.flush() catch {};
}

test "metrics addr parsing refuses non-loopback" {
    const loopback = try parseMetricsAddr("127.0.0.1:9090");
    try std.testing.expect(isLoopbackAddress(&loopback));
    const loopback2 = try parseMetricsAddr("127.0.0.2:9090");
    try std.testing.expect(isLoopbackAddress(&loopback2));
    try std.testing.expectError(error.InvalidMetricsAddr, parseMetricsAddr("127.0.0.1:0"));
    const v6 = try parseMetricsAddr("[::1]:9090");
    try std.testing.expect(isLoopbackAddress(&v6));
    const public = try parseMetricsAddr("0.0.0.0:9090");
    try std.testing.expect(!isLoopbackAddress(&public));
    try std.testing.expectError(error.InvalidMetricsAddr, parseMetricsAddr("not-an-addr"));
}

/// One startup banner on stderr: version, config path if any, selected
/// transports with their listen addresses, and every configured zone origin
/// with its SOA serial. Key paths and other secrets never print.
fn printStartupBanner(out: *std.Io.Writer, runtime: *const auth_runtime.Runtime, config_file: ?[]const u8, metrics_addr: ?std.Io.net.IpAddress, selection: ServeSelection, mode: ServerRunMode, multi: bool, modes: []const ServerRunMode, addresses: []const std.Io.net.IpAddress, configured: ?std.Io.net.IpAddress, port: u16) !void {
    try out.print("zimdns {s} starting", .{build_options.version});
    if (config_file) |path| try out.print(" config={s}", .{path});
    try out.writeAll(" transports=");
    if (multi) {
        for (modes, 0..) |loop_mode, i| {
            if (i > 0) try out.writeAll(",");
            try out.print("{s}@{f}", .{ loopName(loop_mode), addresses[i] });
        }
    } else if (mode == .udp_once or mode == .tcp_once) {
        const address = configured orelse defaultListenerAddress(port);
        try out.print("{s}@{f}", .{ loopName(mode), address });
    } else {
        var single: [7]ServerRunMode = undefined;
        const count = selection.loopModes(&single);
        for (single[0..count], 0..) |loop_mode, i| {
            if (i > 0) try out.writeAll(",");
            const address = configured orelse defaultListenerAddress(port);
            try out.print("{s}@{f}", .{ loopName(loop_mode), address });
        }
    }
    if (metrics_addr) |addr| try out.print(" metrics@{f}", .{addr});
    try out.writeAll(" zones=");
    const shown = @min(runtime.zones.items.len, 32);
    for (runtime.zones.items[0..shown], 0..) |*zone, i| {
        if (i > 0) try out.writeAll(",");
        if (zone.soaSerial()) |serial| {
            try out.print("{s}#{d}", .{ zone.originText(), serial });
        } else {
            try out.print("{s}#?", .{zone.originText()});
        }
    }
    if (runtime.zones.items.len > shown) try out.print(" ...and {d} more", .{runtime.zones.items.len - shown});
    try out.writeAll("\n");
    try out.flush();
}

test "startup banner carries version, origins and serials" {
    var runtime = try auth_runtime.Runtime.fromZoneText("$ORIGIN example.\n$TTL 3600\n@ IN SOA ns admin 42 3600 900 1209600 3600\n@ IN NS ns\n");
    defer runtime.deinit();
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try printStartupBanner(&output.writer, &runtime, null, null, .{}, .none, false, &.{}, &.{}, null, 1053);
    const text = output.written();
    try std.testing.expect(std.mem.indexOf(u8, text, build_options.version) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "example.#42") != null);
}

test "metrics connection serves health and metrics" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var counters = metrics.Counters{};
    var serving = std.atomic.Value(bool).init(true);
    inline for (.{ "/healthz", "/metrics" }) |path| {
        var listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var server = try std.Io.net.IpAddress.listen(&listen_addr, io, .{ .reuse_address = true });
        defer server.deinit(io);
        var client = try std.Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
        defer client.close(io);
        var write_buffer: [256]u8 = undefined;
        var writer = client.writer(io, &write_buffer);
        try writer.interface.print("GET {s} HTTP/1.1\r\nHost: metrics\r\n\r\n", .{path});
        try writer.interface.flush();
        const stream = try server.accept(io);
        serveMetricsConnection(stream, io, &counters, &serving);
        var read_buffer: [4096]u8 = undefined;
        var reader = client.reader(io, &read_buffer);
        const response = try reader.interface.allocRemaining(std.testing.allocator, .limited(4096));
        defer std.testing.allocator.free(response);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.0 200 OK"));
        if (std.mem.eql(u8, path, "/metrics")) {
            try std.testing.expect(std.mem.indexOf(u8, response, "zimdns_queries_total") != null);
        }
    }
}

fn handleServer(args: []const []const u8, io: std.Io, allocator: std.mem.Allocator, writer: *std.Io.Writer) !void {
    if (try printHelpIfRequested(args, writer)) return;
    if (args.len < 3) {
        try writer.writeAll("error: expected 'server run'\n");
        try exitUsage(writer);
    }
    if (!std.mem.eql(u8, args[2], "run")) {
        try writer.writeAll("error: expected 'server run'\n");
        try exitUsage(writer);
    }

    const cli = ServerArgs.parse(args[3..]) catch |err| {
        const message: []const u8 = switch (err) {
            error.MissingValue => "error: a server option is missing its value\n",
            error.InvalidPort => "error: invalid port\n",
            error.InvalidCount => "error: invalid count\n",
            error.UnknownOption => "error: unknown server option\n",
            error.DuplicateOneShot => "error: only one --once-udp/--once-tcp flag is accepted\n",
            error.OneShotWithServe => "error: --once-udp/--once-tcp cannot be combined with a --serve-* flag\n",
        };
        try writer.writeAll(message);
        try exitUsage(writer);
    };
    const config_file = cli.config_file;
    const zone_file = cli.zone_file;
    var selection = cli.selection;
    // The scalar is the one-shot or the single selected loop; multi-loop
    // runs dispatch on the selection and leave it unset.
    var mode: ServerRunMode = .none;
    if (cli.selection.once) |once| {
        mode = once;
    } else {
        var single: [7]ServerRunMode = undefined;
        if (cli.selection.loopModes(&single) == 1) mode = single[0];
    }
    const port_set = cli.port_set;
    var port: u16 = cli.port;
    var configured_address: ?std.Io.net.IpAddress = null;
    const max_queries: usize = cli.max_queries;
    const max_requests: ?usize = cli.max_requests;
    const print_metrics = cli.print_metrics;
    const encrypted_dns_flag = cli.encrypted_dns_flag;
    const tls_cert_file = cli.tls_cert_file;
    const tls_key_file = cli.tls_key_file;
    const metrics_addr_text = cli.metrics_addr;

    const explicit_zone_file = zone_file != null;
    var server_context: ?config_loader.ServerContext = null;
    defer if (server_context) |*context| context.deinit();

    if (config_file) |path| {
        // Referenced files resolve against the configuration file's own
        // directory, never the process cwd.
        const base_name = std.fs.path.basename(path);
        const parent_name = std.fs.path.dirname(path) orelse ".";
        var base_dir = if (std.fs.path.isAbsolute(parent_name))
            try std.Io.Dir.openDirAbsolute(io, parent_name, .{})
        else
            try std.Io.Dir.cwd().openDir(io, parent_name, .{});
        defer base_dir.close(io);
        server_context = try config_loader.ServerContext.load(base_dir, io, base_name, allocator);
        if (!port_set) {
            if (try findListenerAddress(&server_context.?.config, mode)) |address| {
                configured_address = address;
                port = address.getPort();
            }
        }
    }

    // The selection the arg loop built is the dispatch source of truth:
    // a one-shot never mixes with a serve flag (rejected above), and the
    // scalar keeps the one-shot or the single serve flag for the paths below.
    if (selection.once) |once| {
        mode = once;
    } else if (!selection.anyServe()) {
        try writer.writeAll("error: server run currently requires --once-udp, --once-tcp, --serve-udp, --serve-tcp, --serve-dot, --serve-doh, --serve-doq, --serve-doh3, or --serve-xfr\n");
        try exitUsage(writer);
    }

    // The identity of the encrypted listener, loaded before any socket is
    // bound: a broken identity refuses the run instead of leaving a port
    // open.
    var tls_identity: ?transport_tls_server.Server = null;
    var tls_identities: [7]transport_tls_server.Server = undefined;
    var tls_identity_modes: [7]ServerRunMode = undefined;
    var tls_identity_count: usize = 0;
    var encrypted_cert_path: ?[]const u8 = null;
    var encrypted_key_path: ?[]const u8 = null;
    defer if (tls_identity) |*server| server.deinit();
    defer for (tls_identities[0..tls_identity_count]) |*server| server.deinit();

    if (selection.anyEncrypted()) {
        const cert_path = tls_cert_file orelse (if (server_context) |*context| context.config.tlsCertFileText() else null);
        const key_path = tls_key_file orelse (if (server_context) |*context| context.config.tlsKeyFileText() else null);
        const enabled = encrypted_dns_flag or (if (server_context) |*context| context.config.encrypted_dns else false);
        transport_tls.requireEnabled(enabled) catch {
            try writer.writeAll("error: encrypted listeners require --enable-encrypted-dns or 'encrypted-dns on'\n");
            try exitUsage(writer);
        };
        encrypted_cert_path = cert_path;
        encrypted_key_path = key_path;
        // Every encrypted transport this build accepts has a listener of its
        // own, so the transport decides the ALPN token the handshake selects.
        const single_transport: transport_tls.Transport = if (selection.dot) .dot else if (selection.doh) .doh else if (selection.doq) .doq else if (selection.doh3) .doh3 else .xfr;
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
        defer {
            std.crypto.secureZero(u8, key_bytes);
            allocator.free(key_bytes);
        }
        transport_tls.validatePemPair(cert_bytes, key_bytes) catch {
            try writer.writeAll("error: TLS identity failed validation (certificate must be PEM, key must be nonempty)\n");
            try exitUsage(writer);
        };
        // The identity is loaded before the bind, so a certificate or key
        // that cannot be loaded refuses the run and binds no port. DoQ and
        // DoH/3 load their own identity inside the vendored ngtcp2 stack from
        // the same two paths, so they need the validation above but no TCP TLS server object.
        const single_count = countServeModes(selection);
        const single_needs_server = single_count == 1 and (selection.dot or selection.doh or selection.xfr);
        if (single_needs_server) {
            var server: transport_tls_server.Server = undefined;
            server.init(allocator, io, std.Io.Dir.cwd(), cert_path.?, key_path.?, transport_tls.alpnFor(single_transport)) catch {
                try writer.writeAll("error: cannot load the TLS certificate and key\n");
                try exitUsage(writer);
            };
            tls_identity = server;
        }
        // Multi-loop runs need one identity per TCP-TLS loop (ALPN differs
        // per transport: "dot" vs "http/1.1"), all sharing the same cert.
        if (selection.once == null and countServeModes(selection) > 1) {
            var multi_modes: [7]ServerRunMode = undefined;
            const multi_count = selection.loopModes(&multi_modes);
            for (multi_modes[0..multi_count]) |loop_mode| {
                const needs_server = loop_mode == .dot_loop or loop_mode == .doh_loop or loop_mode == .xfr_loop;
                if (!needs_server) continue;
                const loop_transport: transport_tls.Transport = switch (loop_mode) {
                    .dot_loop => .dot,
                    .doh_loop => .doh,
                    .xfr_loop => .xfr,
                    else => unreachable,
                };
                tls_identities[tls_identity_count].init(allocator, io, std.Io.Dir.cwd(), cert_path.?, key_path.?, transport_tls.alpnFor(loop_transport)) catch {
                    try writer.writeAll("error: cannot load the TLS certificate and key\n");
                    try exitUsage(writer);
                };
                tls_identity_modes[tls_identity_count] = loop_mode;
                tls_identity_count += 1;
            }
        }
    }

    // Multi-loop listen addresses resolve here: taking the runtime below
    // moves the configuration out of the context (`self.config = .{}`), so
    // anything resolved after would see no listeners and fall back to the
    // default port on every loop.
    const multi_loop = selection.once == null and countServeModes(selection) > 1;
    var loop_modes: [7]ServerRunMode = undefined;
    var addresses: [7]std.Io.net.IpAddress = undefined;
    var loop_count: usize = 0;
    if (multi_loop) {
        loop_count = selection.loopModes(&loop_modes);
        for (loop_modes[0..loop_count], 0..) |loop_mode, i| {
            addresses[i] = try resolveLoopAddress(config_file, if (server_context) |*context| &context.config else null, loop_mode, port_set, port);
        }
    }

    var runtime: auth_runtime.Runtime = undefined;
    // The reload sources come from the loader, through the same base dir it
    // read the zone files from. Taking the runtime moves the configuration
    // out of the context.
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
    // The read-write lock a reload waits on is woken through the serving io;
    // a runtime built from zone text carries none of its own.
    var server_backend = std.Io.Threaded.init(std.heap.page_allocator, .{
        .concurrent_limit = .limited(listener.UDP_WORKER_COUNT + listener.TCP_MAX_CONNECTION_WORKERS + 4),
    });
    defer server_backend.deinit();
    const server_io = server_backend.io();
    runtime.io = server_io;
    if (runtime.resolver) |*resolver_state| resolver_state.io = server_io;
    defer {
        runtime.io = io;
        if (runtime.resolver) |*resolver_state| resolver_state.io = io;
    }
    defer runtime.deinit();
    var maintenance_state = MaintenanceState{ .runtime = &runtime, .io = server_io };
    var maintenance_thread = std.Thread.spawn(.{}, maintenanceLoop, .{&maintenance_state}) catch |err| {
        try writer.print("error: cannot start the maintenance thread: {t}\n", .{err});
        try exitUsage(writer);
    };
    defer {
        maintenance_state.stop.store(true, .release);
        maintenance_thread.join();
    }
    // The handler must not reach a runtime that is already gone.
    defer reload_runtime = null;
    // SIGHUP re-reads every configured zone file. The handler only sets a
    // flag; the serve path reads the files and swaps the zones. A catalog or
    // blacklist zone is synthesized, so it has no file and is not a source.
    if (explicit_zone_file) {
        if (runtime.zones.items.len == 1) {
            try runtime.setReloadSource(std.Io.Dir.cwd(), zone_file.?, runtime.zones.items[0].originText());
        }
    }
    installReloadHandler(&runtime);
    var counters = metrics.Counters{};
    // The metrics listener is parsed and validated before any socket binds:
    // a bad address or a non-loopback address refuses the run outright.
    var metrics_addr: ?std.Io.net.IpAddress = null;
    if (metrics_addr_text) |text| {
        metrics_addr = parseMetricsAddr(text) catch {
            try writer.writeAll("error: invalid --metrics-addr, want ip:port\n");
            try exitUsage(writer);
        };
        if (!isLoopbackAddress(&metrics_addr.?)) {
            try writer.writeAll("error: --metrics-addr must be a loopback address for now\n");
            try exitUsage(writer);
        }
    }

    var stop = auth_runtime.SharedStop{};
    // SIGTERM/SIGINT end the process at once instead of waiting out the
    // compose stop grace period. No in-flight drain: blocked accepts die
    // with the process.
    installTerminateHandlers(&stop);
    defer signal_stop.store(null, .release);

    const odoh_target: ?*const dns_odoh.Target = if (server_context) |*context| if (context.odoh_target) |*target| target else null else null;

    // One startup banner on stderr: version, config path, transports and
    // addresses, zone origins with serials. No secrets: key paths never print.
    var banner_buffer: [4096]u8 = undefined;
    var banner = std.Io.File.stderr().writer(io, &banner_buffer);
    printStartupBanner(&banner.interface, &runtime, config_file, metrics_addr, selection, mode, multi_loop, loop_modes[0..loop_count], addresses[0..loop_count], configured_address, port) catch {};
    // The live listener shares the same counters every serve loop uses.
    var metrics_serving = std.atomic.Value(bool).init(false);
    var metrics_listener_state: ?MetricsListener = null;
    var metrics_thread: ?std.Thread = null;
    // The listener runs on its own backend: the caller's io may be
    // single-threaded and cannot be shared across threads.
    var metrics_io_backend: ?std.Io.Threaded = null;
    defer if (metrics_io_backend) |*backend| backend.deinit();
    if (metrics_addr) |bind_addr| {
        metrics_io_backend = std.Io.Threaded.init(std.heap.page_allocator, .{ .concurrent_limit = .limited(4) });
        metrics_listener_state = .{
            .io = metrics_io_backend.?.io(),
            .counters = &counters,
            .serving = &metrics_serving,
            .address = bind_addr,
            .stop = &stop,
        };
        metrics_thread = std.Thread.spawn(.{}, MetricsListener.run, .{&metrics_listener_state.?}) catch null;
        if (metrics_thread == null) {
            try writer.writeAll("error: cannot start the metrics listener thread\n");
            try exitUsage(writer);
        }
        // Wait for the bind so a colliding address refuses the run instead
        // of serving DNS with no metrics endpoint.
        while (!metrics_listener_state.?.bound.load(.acquire)) std.Thread.yield() catch {};
        if (metrics_listener_state.?.bind_err) |_| {
            try writer.writeAll("error: cannot bind --metrics-addr\n");
            try exitUsage(writer);
        }
    }
    // Function-scope join: the metrics thread must live for the whole serve
    // run, and the counters/stop/backend it reads must outlive it.
    defer {
        stop.requestStop();
        if (metrics_thread) |thread| thread.join();
    }
    metrics_serving.store(true, .release);
    defer metrics_serving.store(false, .release);

    if (multi_loop) {
        if (max_requests) |count| if (count == 0) {
            try writer.writeAll("error: --max-requests must be greater than zero\n");
            try exitUsage(writer);
        };
        if (print_metrics and selection.tcp) {
            try writer.writeAll("error: --print-metrics is currently supported for UDP runs\n");
            try exitUsage(writer);
        }
        // Multi-loop io: TCP-family loops need a threaded backend, and the
        // shared runtime lock wakes through the io it serves on, so one
        // threaded backend feeds every loop.
        runtime.shared_stop = &stop;
        serveConcurrentMulti(server_io, &runtime, &counters, print_metrics, max_requests, odoh_target, tls_identities[0..tls_identity_count], tls_identity_modes[0..tls_identity_count], encrypted_cert_path, encrypted_key_path, addresses[0..loop_count], loop_modes[0..loop_count], &stop) catch |err| {
            // A duplicate address is a usage error, not a serving failure.
            if (err == error.DuplicateLoopAddress) {
                try writer.writeAll("error: two selected loops share one listen address; give each loop its own listener\n");
                try exitUsage(writer);
            }
            return err;
        };
        if (print_metrics) {
            try metrics.formatPrometheus(&counters, writer);
        }
        return;
    }

    switch (mode) {
        .udp_once => {
            if (max_queries == 0) {
                try writer.writeAll("error: --max-queries must be greater than zero\n");
                try exitUsage(writer);
            }
            const once_live: ?*metrics.Counters = if (metrics_addr != null) &counters else null;
            if (configured_address) |*address| {
                if (print_metrics) {
                    try listener.serveUdpCountOnAddressWithMetrics(server_io, &runtime, address, max_queries, &counters);
                } else if (once_live) |counting| {
                    try listener.serveUdpCountOnAddressWithMetrics(server_io, &runtime, address, max_queries, counting);
                } else if (max_queries == 1) {
                    try listener.serveUdpOnceOnAddress(server_io, &runtime, address);
                } else {
                    try listener.serveUdpCountOnAddress(server_io, &runtime, address, max_queries);
                }
            } else if (print_metrics) {
                var address = defaultListenerAddress(port);
                try listener.serveUdpCountOnAddressWithMetrics(server_io, &runtime, &address, max_queries, &counters);
            } else if (once_live) |counting| {
                var address = defaultListenerAddress(port);
                try listener.serveUdpCountOnAddressWithMetrics(server_io, &runtime, &address, max_queries, counting);
            } else if (max_queries == 1) {
                var address = defaultListenerAddress(port);
                try listener.serveUdpOnceOnAddress(server_io, &runtime, &address);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveUdpCountOnAddress(server_io, &runtime, &address, max_queries);
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
                try listener.serveTcpOnceOnAddress(server_io, &runtime, address);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveTcpOnceOnAddress(server_io, &runtime, &address);
            }
        },
        .udp_loop => {
            if (max_requests) |count| if (count == 0) {
                try writer.writeAll("error: --max-requests must be greater than zero\n");
                try exitUsage(writer);
            };
            // The live listener shares these counters, so a metrics run
            // counts even without --print-metrics.
            const live: ?*metrics.Counters = if (metrics_addr != null) &counters else null;
            if (max_requests == null) {
                if (configured_address) |*address| {
                    try listener.serveUdpPoolOnAddress(server_io, &runtime, address, &counters);
                } else {
                    var address = defaultListenerAddress(port);
                    try listener.serveUdpPoolOnAddress(server_io, &runtime, &address, &counters);
                }
            } else if (print_metrics) {
                if (configured_address) |*address| {
                    try listener.serveUdpLoopOnAddressWithMetrics(server_io, &runtime, address, max_requests, &counters);
                } else {
                    var address = defaultListenerAddress(port);
                    try listener.serveUdpLoopOnAddressWithMetrics(server_io, &runtime, &address, max_requests, &counters);
                }
            } else if (live) |counting| {
                if (configured_address) |*address| {
                    try listener.serveUdpLoopOnAddressWithMetrics(server_io, &runtime, address, max_requests, counting);
                } else {
                    var address = defaultListenerAddress(port);
                    try listener.serveUdpLoopOnAddressWithMetrics(server_io, &runtime, &address, max_requests, counting);
                }
            } else if (configured_address) |*address| {
                try listener.serveUdpLoopOnAddress(server_io, &runtime, address, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveUdpLoopOnAddress(server_io, &runtime, &address, max_requests);
            }
        },
        .tcp_loop => {
            if (print_metrics) {
                try writer.writeAll("error: --print-metrics is currently supported for UDP runs\n");
                try exitUsage(writer);
            }
            const tcp_live: ?*metrics.Counters = if (metrics_addr != null) &counters else null;
            if (configured_address) |*address| {
                try listener.serveTcpLoopOnAddress(server_io, &runtime, address, max_requests, tcp_live);
            } else {
                var address = defaultListenerAddress(port);
                try listener.serveTcpLoopOnAddress(server_io, &runtime, &address, max_requests, tcp_live);
            }
        },
        .dot_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            // The counters reach the port, so the DoT query counter moves in
            // a metrics run.
            const dot_counters: ?*metrics.Counters = &counters;
            if (configured_address) |*address| {
                try transport_dot.serveDotLoopOnAddress(server_io, &runtime, address, &server, max_requests, dot_counters);
            } else {
                var address = defaultListenerAddress(port);
                try transport_dot.serveDotLoopOnAddress(server_io, &runtime, &address, &server, max_requests, dot_counters);
            }
        },
        .doh_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            // The DoH workers share the counters of the run, so the DoH
            // queries are counted the way the other transports count them.
            if (configured_address) |*address| {
                try transport_doh.serveDohLoopOnAddress(server_io, &runtime, address, &server, max_requests, &counters, odoh_target);
            } else {
                var address = defaultListenerAddress(port);
                try transport_doh.serveDohLoopOnAddress(server_io, &runtime, &address, &server, max_requests, &counters, odoh_target);
            }
        },
        .doq_loop => {
            const cert_path = encrypted_cert_path orelse return error.MissingTlsIdentity;
            const key_path = encrypted_key_path orelse return error.MissingTlsIdentity;
            // The DoQ server runs on its own thread with its own event loop,
            // joined inside serveDoqLoopOnAddress before it returns, so the
            // runtime outlives every use of it. The counters reach the port,
            // so the DoQ query counter moves in a metrics run.
            const doq_counters: ?*metrics.Counters = &counters;
            if (configured_address) |*address| {
                try transport_doq.serveDoqLoopOnAddress(server_io, &runtime, address, cert_path, key_path, max_requests, doq_counters);
            } else {
                var address = defaultListenerAddress(port);
                try transport_doq.serveDoqLoopOnAddress(server_io, &runtime, &address, cert_path, key_path, max_requests, doq_counters);
            }
        },
        .doh3_loop => {
            const cert_path = encrypted_cert_path orelse return error.MissingTlsIdentity;
            const key_path = encrypted_key_path orelse return error.MissingTlsIdentity;
            // The DoH/3 server runs on its own thread with its own event loop,
            // joined inside serveDoh3LoopOnAddress before it returns, so the
            // runtime outlives every use of it. The counters reach the port,
            // so the DoH/3 query counter moves in a metrics run.
            const doh3_counters: ?*metrics.Counters = &counters;
            if (configured_address) |*address| {
                try transport_doh3.serveDoh3LoopOnAddress(server_io, &runtime, address, cert_path, key_path, max_requests, doh3_counters, odoh_target);
            } else {
                var address = defaultListenerAddress(port);
                try transport_doh3.serveDoh3LoopOnAddress(server_io, &runtime, &address, cert_path, key_path, max_requests, doh3_counters, odoh_target);
            }
        },
        // The strict-TLS transfer channel: the same handshake and the same
        // worker bound as the other encrypted listeners.
        .xfr_loop => {
            var server = tls_identity orelse return error.MissingTlsIdentity;
            if (configured_address) |*address| {
                try transfer_xfr_tls.serveXfrLoopOnAddress(server_io, &runtime, address, &server, max_requests);
            } else {
                var address = defaultListenerAddress(port);
                try transfer_xfr_tls.serveXfrLoopOnAddress(server_io, &runtime, &address, &server, max_requests);
            }
        },
        .none => unreachable,
    }

    if (print_metrics) {
        try metrics.formatPrometheus(&counters, writer);
    }
}

const MaintenanceState = struct {
    runtime: *auth_runtime.Runtime,
    io: std.Io,
    stop: std.atomic.Value(bool) = .init(false),
};

fn maintenanceLoop(state: *MaintenanceState) void {
    while (!state.stop.load(.acquire)) {
        _ = state.runtime.tryBackgroundRefresh(state.io);
        _ = state.runtime.tryMaintenanceTick(state.io);
        std.Io.sleep(state.io, .fromMilliseconds(250), .awake) catch {};
    }
    auth_runtime.releaseAnswerScratch();
}

fn countServeModes(selection: ServeSelection) usize {
    var modes: [7]ServerRunMode = undefined;
    return selection.loopModes(&modes);
}

/// Shared state for one serve-loop thread. Every loop serves the same
/// runtime, counters, and TLS identity pointer; the identity outlives all
/// threads because the owner joins every thread before its defer frees it.
/// Runners bind their own listener, register its fd with the shared stop,
/// and run the serve function on the bound socket, so a bind failure in any
/// loop surfaces through the stop and wakes the loops already serving.
const LoopRunner = struct {
    io: std.Io,
    runtime: *auth_runtime.Runtime,
    counters: *metrics.Counters,
    print_metrics: bool,
    max_requests: ?usize,
    odoh_target: ?*const dns_odoh.Target,
    tls_server: ?*transport_tls_server.Server,
    cert_path: ?[]const u8,
    key_path: ?[]const u8,
    address: std.Io.net.IpAddress,
    mode: ServerRunMode,
    stop: *auth_runtime.SharedStop,
    err: ?anyerror = null,

    fn run(self: *LoopRunner) void {
        // Fail-fast: a loop that fails after startup prints its error and
        // ends the process with a nonzero status, so a supervisor restarts
        // it instead of leaving a sibling to serve half the transports.
        // No thread ever wakes or joins another loop: blocked accepts die
        // with the process. Normal `--max-requests` completion returns and
        // the owner joins every thread.
        self.serve() catch |err| {
            self.err = err;
            self.stop.failFast(self.io, err, loopName(self.mode));
        };
    }

    fn serve(self: *LoopRunner) !void {
        switch (self.mode) {
            .udp_loop => {
                var bind_address = self.address;
                var socket = try std.Io.net.IpAddress.bind(&bind_address, self.io, .{ .mode = .dgram, .protocol = .udp });
                defer socket.close(self.io);
                // Multi loops always count: the live listener shares these
                // counters, and --print-metrics only adds the end print.
                // An unbounded run shares the bound socket across the UDP
                // worker pool so one slow recursion does not stall the
                // authoritative answers queued behind it.
                if (self.max_requests == null) {
                    try listener.serveUdpPoolOnSocket(&socket, self.io, self.runtime, self.counters);
                } else {
                    try listener.serveUdpLoopWithMetrics(&socket, self.io, self.runtime, self.max_requests, self.counters);
                }
            },
            .tcp_loop => {
                var bind_address = self.address;
                var server = try std.Io.net.IpAddress.listen(&bind_address, self.io, .{ .reuse_address = true });
                defer server.deinit(self.io);
                try listener.serveTcpLoop(&server, self.io, self.runtime, self.max_requests, self.counters);
            },

            .dot_loop => {
                const server = self.tls_server orelse return error.MissingTlsIdentity;
                var bind_address = self.address;
                var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, self.io, .{ .reuse_address = true });
                defer listener_socket.deinit(self.io);
                const dot_counters: ?*metrics.Counters = self.counters;
                try transport_dot.serveDotLoop(&listener_socket, self.io, self.runtime, server, self.max_requests, dot_counters);
            },
            .doh_loop => {
                const server = self.tls_server orelse return error.MissingTlsIdentity;
                var bind_address = self.address;
                var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, self.io, .{ .reuse_address = true });
                defer listener_socket.deinit(self.io);
                try transport_doh.serveDohLoop(&listener_socket, self.io, self.runtime, server, self.max_requests, self.counters, self.odoh_target);
            },
            .doq_loop => {
                const cert_path = self.cert_path orelse return error.MissingTlsIdentity;
                const key_path = self.key_path orelse return error.MissingTlsIdentity;
                // The QUIC core observes the shared stop at its own boundary.
                const doq_counters: ?*metrics.Counters = self.counters;
                try transport_doq.serveDoqLoopOnAddressStop(self.io, self.runtime, &self.address, cert_path, key_path, self.max_requests, doq_counters, self.stop);
            },
            .doh3_loop => {
                const cert_path = self.cert_path orelse return error.MissingTlsIdentity;
                const key_path = self.key_path orelse return error.MissingTlsIdentity;
                const doh3_counters: ?*metrics.Counters = self.counters;
                try transport_doh3.serveDoh3LoopOnAddressStop(self.io, self.runtime, &self.address, cert_path, key_path, self.max_requests, doh3_counters, self.odoh_target, self.stop);
            },
            .xfr_loop => {
                const server = self.tls_server orelse return error.MissingTlsIdentity;
                var bind_address = self.address;
                var listener_socket = try std.Io.net.IpAddress.listen(&bind_address, self.io, .{ .reuse_address = true });
                defer listener_socket.deinit(self.io);
                try transfer_xfr_tls.serveXfrLoop(&listener_socket, self.io, self.runtime, server, self.max_requests);
            },
            else => unreachable,
        }
    }
};

/// Flag name for a loop mode, for fail-fast error reports.
fn loopName(mode: ServerRunMode) []const u8 {
    return switch (mode) {
        .udp_once => "once-udp",
        .tcp_once => "once-tcp",
        .udp_loop => "serve-udp",
        .tcp_loop => "serve-tcp",
        .dot_loop => "serve-dot",
        .doh_loop => "serve-doh",
        .doq_loop => "serve-doq",
        .doh3_loop => "serve-doh3",
        .xfr_loop => "serve-xfr",
        .none => "none",
    };
}

/// True for loops that listen on TCP: they share one port namespace, so two
/// of them on the same address would collide no matter what SO_REUSEPORT
/// allows. UDP loops (plain DNS, DoQ, DoH3) share the datagram namespace.
fn isStreamLoop(mode: ServerRunMode) bool {
    return switch (mode) {
        .tcp_loop, .dot_loop, .doh_loop, .xfr_loop => true,
        else => false,
    };
}

/// Runs all selected loops at once on one thread per loop against the same
/// runtime. Binds happen in the runners, so a bad bind surfaces through the
/// shared stop and wakes the loops already serving instead of stranding
/// them on a join. The first failing loop's error ends the run after every
/// thread joins exactly once; surviving loops observe the stop at their
/// next receive/accept boundary. `--max-requests` applies per loop;
/// `--print-metrics` prints once after every loop ends.
fn serveConcurrentMulti(
    io: std.Io,
    runtime: *auth_runtime.Runtime,
    counters: *metrics.Counters,
    print_metrics: bool,
    max_requests: ?usize,
    odoh_target: ?*const dns_odoh.Target,
    tls_servers: []transport_tls_server.Server,
    tls_modes: []ServerRunMode,
    cert_path: ?[]const u8,
    key_path: ?[]const u8,
    addresses: []const std.Io.net.IpAddress,
    modes: []const ServerRunMode,
    stop: *auth_runtime.SharedStop,
) !void {
    std.debug.assert(addresses.len == modes.len);
    // Two stream loops on one address would collide; two datagram loops
    // would split traffic under SO_REUSEPORT. UDP and TCP never collide:
    // they are different port namespaces.
    for (modes, 0..) |a, ai| {
        for (modes[0..ai], 0..) |b, bi| {
            if (isStreamLoop(a) == isStreamLoop(b) and addresses[ai].eql(&addresses[bi])) {
                return error.DuplicateLoopAddress;
            }
        }
    }
    var runners: [7]LoopRunner = undefined;
    var threads: [7]std.Thread = undefined;
    // Each TCP-TLS loop gets the identity with its own ALPN ("dot" vs
    // "http/1.1"); DoQ/DoH3 carry paths and load their own QUIC identity.
    for (modes, 0..) |loop_mode, i| {
        var loop_tls: ?*transport_tls_server.Server = null;
        for (tls_servers, 0..) |*server, k| {
            if (tls_modes[k] == loop_mode) loop_tls = server;
        }
        runners[i] = .{
            .io = io,
            .runtime = runtime,
            .counters = counters,
            .print_metrics = print_metrics,
            .max_requests = max_requests,
            .odoh_target = odoh_target,
            .tls_server = loop_tls,
            .cert_path = cert_path,
            .key_path = key_path,
            .address = addresses[i],
            .mode = loop_mode,
            .stop = stop,
        };
    }

    var started: usize = 0;
    errdefer {
        // Spawn failed after failFast ended the process: this only runs in
        // tests that stub the exit. Joins exactly the threads that exist;
        // the normal path resets `started` after its own join, so a later
        // error return cannot join twice.
        for (threads[0..started]) |thread| thread.join();
    }
    for (runners[0..modes.len], 0..) |*runner, i| {
        threads[i] = std.Thread.spawn(.{}, LoopRunner.run, .{runner}) catch |err| {
            stop.failFast(io, err, loopName(modes[i]));
            return err;
        };
        started += 1;
    }
    for (threads[0..modes.len]) |thread| thread.join();
    started = 0;
}

/// Address for one loop: the config listener with the same transport,
/// or the loopback default on the shared port when unconfigured.
fn resolveLoopAddress(config_file: ?[]const u8, config: ?*const config_parser.Config, mode: ServerRunMode, port_set: bool, port: u16) !std.Io.net.IpAddress {
    _ = config_file;
    if (!port_set) {
        if (config) |parsed| {
            if (try findListenerAddress(parsed, mode)) |address| return address;
        }
    }
    return defaultListenerAddress(port);
}

fn findListenerAddress(config: *const config_parser.Config, mode: ServerRunMode) !?std.Io.net.IpAddress {
    const want: config_parser.Transport = switch (mode) {
        .udp_once, .udp_loop => .udp,
        .tcp_once, .tcp_loop => .tcp,
        .dot_loop, .xfr_loop => .dot,
        .doh_loop => .doh,
        .doq_loop => .doq,
        .doh3_loop => .doh3,
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

test "query and server run accept --help without treating it as an operand" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const query_args = [_][]const u8{ "zimdns", "query", "--help" };
    var query_output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer query_output.deinit();
    try handleQuery(&query_args, io, std.testing.allocator, &query_output.writer);
    try std.testing.expect(std.mem.indexOf(u8, query_output.written(), "Usage:") != null);

    const server_args = [_][]const u8{ "zimdns", "server", "run", "--help" };
    var server_output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer server_output.deinit();
    try handleServer(&server_args, io, std.testing.allocator, &server_output.writer);
    try std.testing.expect(std.mem.indexOf(u8, server_output.written(), "Usage:") != null);
}

test "configured loop modes use their transport listener endpoint" {
    const config = try config_parser.Config.parse(
        \\listen dns udp 127.0.0.1:12053
        \\listen dns tcp 127.0.0.1:12054
        \\listen dns dot 127.0.0.1:12055
        \\listen dns doh 127.0.0.1:12056
        \\listen dns doq 127.0.0.1:12057
        \\listen dns doh3 127.0.0.1:12058
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

    const expected_doq = try std.Io.net.IpAddress.parse("127.0.0.1", 12057);
    const doq = try findListenerAddress(&config, .doq_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(doq.eql(&expected_doq));

    const expected_doh3 = try std.Io.net.IpAddress.parse("127.0.0.1", 12058);
    const doh3 = try findListenerAddress(&config, .doh3_loop) orelse return error.TestExpectedEqual;
    try std.testing.expect(doh3.eql(&expected_doh3));
}

test "the real arg path combines serve flags and rejects one-shots" {
    // The production parser: serve flags combine freely into one selection.
    const udp_tcp = [_][]const u8{ "--serve-udp", "--serve-tcp" };
    const both = try ServerArgs.parse(&udp_tcp);
    try std.testing.expect(both.selection.udp and both.selection.tcp and both.selection.once == null);
    var modes: [7]ServerRunMode = undefined;
    try std.testing.expectEqual(@as(usize, 2), both.selection.loopModes(&modes));
    try std.testing.expect(modes[0] == .udp_loop and modes[1] == .tcp_loop);

    // The same path production dispatches from: a one-shot with a serve
    // flag, and two one-shots, are both refused.
    const clash = [_][]const u8{ "--serve-udp", "--once-udp" };
    try std.testing.expectError(error.OneShotWithServe, ServerArgs.parse(&clash));
    const clash_port = [_][]const u8{ "--once-udp", "1053", "--serve-tcp" };
    try std.testing.expectError(error.OneShotWithServe, ServerArgs.parse(&clash_port));
    const dup = [_][]const u8{ "--once-udp", "--once-tcp" };
    try std.testing.expectError(error.DuplicateOneShot, ServerArgs.parse(&dup));
    const dup_port = [_][]const u8{ "--once-udp", "1053", "--once-tcp", "1054" };
    try std.testing.expectError(error.DuplicateOneShot, ServerArgs.parse(&dup_port));

    // A one-shot keeps its port operand on the same path.
    const once = [_][]const u8{ "--once-udp", "1053" };
    const parsed_once = try ServerArgs.parse(&once);
    try std.testing.expect(parsed_once.selection.once == .udp_once and parsed_once.port == 1053 and parsed_once.port_set);
}

test "maintenance tick is single-owner" {
    var runtime = try auth_runtime.Runtime.fromZoneText("$ORIGIN example.\n$TTL 3600\n@ IN SOA ns admin 1 3600 900 1209600 3600\n@ IN NS ns\n");
    defer runtime.deinit();
    const io = std.Io.Threaded.global_single_threaded.io();
    try std.testing.expect(runtime.tryMaintenanceTick(io));
    // A held maintenance mutex means a second loop skips the tick.
    runtime.maintenance_mutex.lockUncancelable(io);
    defer runtime.maintenance_mutex.unlock(io);
    try std.testing.expect(!runtime.tryMaintenanceTick(io));
}

test "two stream loops on one address are rejected, udp plus tcp are not" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try auth_runtime.Runtime.fromZoneText("$ORIGIN example.\n$TTL 3600\n@ IN SOA ns admin 1 3600 900 1209600 3600\n@ IN NS ns\n");
    defer runtime.deinit();
    var counters = metrics.Counters{};
    var stop = auth_runtime.SharedStop{};
    runtime.shared_stop = &stop;
    const addr = std.Io.net.IpAddress{ .ip4 = .loopback(1053) };
    const dup_addrs = [_]std.Io.net.IpAddress{ addr, addr };
    const dup_modes = [_]ServerRunMode{ .tcp_loop, .dot_loop };
    // Same address for two stream loops: usage-level refusal, no thread starts.
    try std.testing.expectError(error.DuplicateLoopAddress, serveConcurrentMulti(io, &runtime, &counters, false, @as(?usize, 0), null, &.{}, &.{}, null, null, &dup_addrs, &dup_modes, &stop));
    // UDP and TCP share one port number in different namespaces: accepted.
    const ok_modes = [_]ServerRunMode{ .udp_loop, .tcp_loop };
    try serveConcurrentMulti(io, &runtime, &counters, false, @as(?usize, 0), null, &.{}, &.{}, null, null, &dup_addrs, &ok_modes, &stop);
}

test "a bad TLS identity fails the loop before it serves" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var runtime = try auth_runtime.Runtime.fromZoneText("$ORIGIN example.\n$TTL 3600\n@ IN SOA ns admin 1 3600 900 1209600 3600\n@ IN NS ns\n");
    defer runtime.deinit();
    var stop = auth_runtime.SharedStop{};
    runtime.shared_stop = &stop;
    // A DoT loop with no identity fails in its own runner: the error is
    // recorded on the runner (production prints it and exits nonzero via
    // failFast, which tests never call).
    var counters = metrics.Counters{};
    var runner = LoopRunner{
        .io = io,
        .runtime = &runtime,
        .counters = &counters,
        .print_metrics = false,
        .max_requests = null,
        .odoh_target = null,
        .tls_server = null,
        .cert_path = null,
        .key_path = null,
        .address = .{ .ip4 = .loopback(0) },
        .mode = .dot_loop,
        .stop = &stop,
    };
    const result = runner.serve();
    try std.testing.expectError(error.MissingTlsIdentity, result);
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
    try std.testing.expect(@hasDecl(transport_doq, "serveDoqLoopOnAddress"));
    try std.testing.expect(@hasDecl(transfer_xfr_tls, "serveXfrLoopOnAddress"));
    try std.testing.expect(@hasDecl(transport_doh3, "serveDoh3LoopOnAddress"));

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
    try std.testing.expectEqualStrings("doq", transport_tls.alpnFor(.doq));
    try std.testing.expectEqualStrings("h3", transport_tls.alpnFor(.doh3));
    try std.testing.expectEqualStrings("h3", transport_doh3.DOH3_ALPN);
    try std.testing.expectEqualStrings("doq", transport_doq.DOQ_ALPN);
}

fn exitUsage(writer: *std.Io.Writer) !noreturn {
    try writer.flush();
    std.process.exit(2);
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

    const QueryServer = struct {
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
    var server_args = QueryServer{ .io = io, .server = &server, .runtime = &runtime };
    const server_thread = try std.Thread.spawn(.{}, QueryServer.run, .{&server_args});

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
