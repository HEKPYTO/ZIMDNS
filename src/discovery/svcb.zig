/// Contract: Builds and validates the DNS-side publication artifacts for
/// encrypted-resolver discovery: RFC 9461 section 4 `_dns` service bindings
/// and the RFC 9462 section 3 `_dns.resolver.arpa.` designated-resolver
/// record. Bindings are generated only for listeners ZIMDNS actually runs;
/// advertising a disabled encrypted endpoint is a typed error. The client
/// discovery algorithm itself is out of scope for this DNS server.
/// Ownership: Endpoint slices are borrowed; returned Svcb values are inline.
/// Errors: Disabled-endpoint advertisement and malformed bindings are typed.
const std = @import("std");
const dns_name = @import("../dns/name.zig");
const dns_rdata = @import("../dns/rdata.zig");

/// RFC 9461 section 4 service binding label prefix.
pub const dns_prefix = "_dns.";
/// RFC 9462 section 3 special-use domain for designated resolvers.
pub const resolver_arpa = "resolver.arpa.";
/// RFC 9462 section 3 SVCB owner for DDR discovery queries.
pub const dns_resolver_arpa = "_dns.resolver.arpa.";
/// RFC 8484 default DoH path advertised in dohpath parameters.
pub const default_doh_path = "/dns-query";

pub const Error = error{
    AdvertisesDisabledListener,
    MissingDohPath,
    BadEndpoint,
};

pub const Protocol = enum {
    dot,
    doh,
};

/// One advertised designated-resolver endpoint. port 0 selects the
/// protocol default (853 for DoT, 443 for DoH).
pub const Endpoint = struct {
    protocol: Protocol,
    port: u16 = 0,
    target: []const u8 = ".",
    doh_path: []const u8 = default_doh_path,
    advertise_h2: bool = true,
};

pub fn effectivePort(endpoint: Endpoint) u16 {
    if (endpoint.port != 0) return endpoint.port;
    return switch (endpoint.protocol) {
        .dot => @import("../transport/tls.zig").dot_port,
        .doh => @import("../transport/tls.zig").doh_port,
    };
}

/// Rejects publication sets that advertise an encrypted endpoint ZIMDNS does
/// not run, and malformed DoH bindings. There is no fallback: a record must
/// not name a listener that is disabled.
pub fn validatePublication(endpoints: []const Endpoint, encrypted_enabled: bool) Error!void {
    for (endpoints) |endpoint| {
        switch (endpoint.protocol) {
            .dot, .doh => if (!encrypted_enabled) return Error.AdvertisesDisabledListener,
        }
        if (endpoint.protocol == .doh and endpoint.doh_path.len == 0) return Error.MissingDohPath;
        if (endpoint.target.len == 0) return Error.BadEndpoint;
    }
}

/// Builds one RFC 9460 service-mode Svcb value for an endpoint: alpn plus
/// port for DoT; alpn plus port plus dohpath for DoH. Keys are emitted in
/// increasing order as section 8 requires.
pub fn buildServiceMode(endpoint: Endpoint) !dns_rdata.Svcb {
    var params: [dns_rdata.max_svcb_params_len]u8 = undefined;
    var offset: usize = 0;

    var alpn_ids: [8][]const u8 = undefined;
    var alpn_count: usize = 0;
    switch (endpoint.protocol) {
        .dot => {
            alpn_ids[0] = @import("../transport/tls.zig").dot_alpn;
            alpn_count = 1;
        },
        .doh => {
            if (endpoint.advertise_h2) {
                alpn_ids[alpn_count] = @import("../transport/tls.zig").doh_alpn_h2;
                alpn_count += 1;
            }
            alpn_ids[alpn_count] = @import("../transport/tls.zig").doh_alpn_http11;
            alpn_count += 1;
        },
    }
    var alpn_value: [256]u8 = undefined;
    var alpn_len: usize = 0;
    for (alpn_ids[0..alpn_count]) |id| {
        if (id.len == 0 or id.len > 255) return Error.BadEndpoint;
        if (alpn_len + 1 + id.len > alpn_value.len) return Error.BadEndpoint;
        alpn_value[alpn_len] = @intCast(id.len);
        alpn_len += 1;
        @memcpy(alpn_value[alpn_len .. alpn_len + id.len], id);
        alpn_len += id.len;
    }
    offset = writeParam(&params, offset, dns_rdata.SVCB_ALPN_KEY, alpn_value[0..alpn_len]);

    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, effectivePort(endpoint), .big);
    offset = writeParam(&params, offset, dns_rdata.SVCB_PORT_KEY, &port_bytes);

    if (endpoint.protocol == .doh) {
        if (endpoint.doh_path.len == 0) return Error.MissingDohPath;
        offset = writeParam(&params, offset, dns_rdata.SVCB_DOHPATH_KEY, endpoint.doh_path);
    }

    const target = try dns_name.Name.fromText(endpoint.target);
    return dns_rdata.Svcb.init(1, target, params[0..offset]);
}

fn writeParam(buffer: *[dns_rdata.max_svcb_params_len]u8, offset: usize, key: u16, value: []const u8) usize {
    std.mem.writeInt(u16, buffer[offset..][0..2], key, .big);
    std.mem.writeInt(u16, buffer[offset + 2 ..][0..2], @intCast(value.len), .big);
    @memcpy(buffer[offset + 4 .. offset + 4 + value.len], value);
    return offset + 4 + value.len;
}

test "DoT binding carries the dot ALPN and default port" {
    const svcb = try buildServiceMode(.{ .protocol = .dot, .target = "resolver.example." });
    try std.testing.expectEqual(@as(u16, 1), svcb.priority);
    try dns_rdata.validateSvcParams(svcb.paramsBytes(), svcb.priority);
    try std.testing.expect(std.mem.indexOf(u8, svcb.paramsBytes(), "dot") != null);
    // alpn(1) + port(3), default 853.
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, svcb.paramsBytes()[0..2], .big));
    try std.testing.expectEqual(@as(u16, 853), std.mem.readInt(u16, svcb.paramsBytes()[svcb.paramsBytes().len - 2 ..][0..2], .big));
}

test "DoH binding carries h2 ALPN, port, and the DNS query path" {
    const svcb = try buildServiceMode(.{ .protocol = .doh, .port = 8443, .target = "resolver.example." });
    try dns_rdata.validateSvcParams(svcb.paramsBytes(), svcb.priority);
    try std.testing.expect(std.mem.indexOf(u8, svcb.paramsBytes(), "h2") != null);
    try std.testing.expect(std.mem.indexOf(u8, svcb.paramsBytes(), "/dns-query") != null);
}

test "publication rejects encrypted endpoints when the flag is off" {
    const dot_only = [_]Endpoint{.{ .protocol = .dot, .target = "resolver.example." }};
    try std.testing.expectError(Error.AdvertisesDisabledListener, validatePublication(&dot_only, false));
    const doh_only = [_]Endpoint{.{ .protocol = .doh, .target = "resolver.example." }};
    try std.testing.expectError(Error.AdvertisesDisabledListener, validatePublication(&doh_only, false));
    try validatePublication(&dot_only, true);
    try validatePublication(&doh_only, true);
    try validatePublication(&.{}, false);
}

test "publication rejects DoH bindings without a path" {
    const missing = [_]Endpoint{.{ .protocol = .doh, .target = "resolver.example.", .doh_path = "" }};
    try std.testing.expectError(Error.MissingDohPath, validatePublication(&missing, true));
    try std.testing.expectError(Error.MissingDohPath, buildServiceMode(missing[0]));
}

test "DDR special names use the resolver.arpa domain" {
    try std.testing.expectEqualStrings("resolver.arpa.", resolver_arpa);
    try std.testing.expectEqualStrings("_dns.resolver.arpa.", dns_resolver_arpa);
    try std.testing.expect(std.mem.startsWith(u8, dns_resolver_arpa, dns_prefix));
}
