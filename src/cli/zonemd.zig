/// Contract: Publishes the RFC 8976 ZONEMD record of a zone file: it computes
/// the SIMPLE digest with the same code path the verifier uses and prints the
/// record in zone text, ready to paste into the zone.
/// Ownership: borrows the zone text, owns the zone it parses, and writes only
/// to the caller's writer.
/// Errors: a zone it cannot digest is refused with a typed error and one
/// operator line; a refused zone never prints a digest.
const std = @import("std");
const dns_rdata = @import("../dns/rdata.zig");
const zone_index = @import("../zone/index.zig");
const zone_parser = @import("../zone/parser.zig");
const zone_zonemd = @import("../zone/zonemd.zig");

pub const Error = error{
    MalformedZone,
    NoSoa,
    UnsupportedScheme,
    UnsupportedHash,
    OutOfMemory,
    WriteFailed,
};

/// Publishes the ZONEMD record of `zone_text` on `writer` in zone text.
///
/// The digest is computed over the zone as it will be published: the apex
/// ZONEMD RRset and the RRSIG covering it are outside the digest (RFC 8976
/// section 3.3.1.1), so the record the operator pastes in does not change it.
/// The record carries the zone's SOA serial (RFC 8976 section 3.1) and the
/// SOA's TTL, which the RFC recommends for the ZONEMD record.
pub fn publish(zone_text: []const u8, scheme_code: u8, hash_code: u8, allocator: std.mem.Allocator, writer: *std.Io.Writer) Error!void {
    const scheme = zone_zonemd.schemeFromCode(scheme_code) orelse {
        try writer.print("error: zonemd publish: scheme {d} is not the standardized SIMPLE scheme\n", .{scheme_code});
        return Error.UnsupportedScheme;
    };
    const hash = zone_zonemd.hashFromCode(hash_code) orelse {
        try writer.print("error: zonemd publish: hash algorithm {d} is not supported\n", .{hash_code});
        return Error.UnsupportedHash;
    };

    var zone_file = zone_parser.ZoneFile.parse(zone_text) catch |err| switch (err) {
        error.MissingSoa => {
            try writer.writeAll("error: zonemd publish: the zone has no SOA record\n");
            return Error.NoSoa;
        },
        else => {
            try writer.print("error: zonemd publish: the zone file is malformed: {s}\n", .{@errorName(err)});
            return Error.MalformedZone;
        },
    };
    defer zone_file.deinit();
    var zone = zone_index.Zone.fromZoneFile(&zone_file) catch return Error.OutOfMemory;
    defer zone.deinit();

    const soa = zone.soa orelse {
        try writer.writeAll("error: zonemd publish: the zone has no SOA record\n");
        return Error.NoSoa;
    };
    const serial = zone.soaSerial() orelse {
        try writer.writeAll("error: zonemd publish: the zone has no SOA record\n");
        return Error.NoSoa;
    };

    var digest: [dns_rdata.max_zonemd_digest_len]u8 = undefined;
    zone_zonemd.computeDigest(&zone, hash, allocator, &digest) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => {
            try writer.print("error: zonemd publish: the zone cannot be digested: {s}\n", .{@errorName(err)});
            return Error.MalformedZone;
        },
    };

    try writer.print("{s} {d} IN ZONEMD {d} {d} {d} ", .{
        zone.originText(),
        soa.ttl,
        serial,
        @backingInt(scheme),
        @backingInt(hash),
    });
    for (digest[0..hash.digestLen()]) |byte| try writer.print("{x:0>2}", .{byte});
    try writer.writeAll("\n");
}
