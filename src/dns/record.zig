/// Contract: Parses and encodes DNS resource records and their RDATA.
/// Ownership: Records contain inline/borrowed name data; message and Writer storage remain borrowed.
/// Errors: Wire and RDATA failures are typed; transport/file I/O is outside this module.
const std = @import("std");
const Reader = @import("reader.zig").Reader;
const Writer = @import("writer.zig").Writer;
const CompressionTable = @import("writer.zig").CompressionTable;
const Name = @import("name.zig").Name;
const rdata_mod = @import("rdata.zig");
const RData = @import("rdata.zig").RData;
const RecordType = @import("types.zig").RecordType;
const Class = @import("types.zig").Class;

pub const Error = error{
    EndOfInput,
    BadName,
    BadRData,
    MalformedOption,
    OptionsTooLong,
};

pub const ParseResult = struct {
    record: ResourceRecord,
    next_offset: usize,
};

pub const ResourceRecord = struct {
    owner: Name,
    rrtype: RecordType,
    class: Class,
    ttl: u32,
    rdata: RData,

    pub fn parse(message: []const u8, offset: usize) !ParseResult {
        const owner_result = Name.parse(message, offset) catch return Error.BadName;
        var reader = Reader.init(message[owner_result.next_offset..]);
        const rrtype_code = reader.readU16() catch return Error.EndOfInput;
        const class_code = reader.readU16() catch return Error.EndOfInput;
        const ttl = reader.readU32() catch return Error.EndOfInput;
        const rdlength = reader.readU16() catch return Error.EndOfInput;

        const rdata_offset = owner_result.next_offset + reader.position();
        const rdata = RData.parse(RecordType.fromCode(rrtype_code), message, rdata_offset, rdlength) catch |err| switch (err) {
            rdata_mod.Error.MalformedOption => return Error.MalformedOption,
            rdata_mod.Error.OptionsTooLong => return Error.OptionsTooLong,
            else => return Error.BadRData,
        };

        return .{
            .record = .{
                .owner = owner_result.name,
                .rrtype = RecordType.fromCode(rrtype_code),
                .class = Class.fromCode(class_code),
                .ttl = ttl,
                .rdata = rdata,
            },
            .next_offset = rdata_offset + rdlength,
        };
    }

    pub fn encode(self: ResourceRecord, writer: *Writer) !void {
        try self.owner.encode(writer);
        try writer.writeU16(self.rrtype.code());
        try writer.writeU16(self.class.code());
        try writer.writeU32(self.ttl);

        var rdata_buffer: [512]u8 = undefined;
        var rdata_writer = Writer.init(&rdata_buffer);
        try self.rdata.encode(&rdata_writer);
        try writer.writeU16(@intCast(rdata_writer.len()));
        try writer.writeBytes(rdata_writer.written());
    }

    pub fn encodeCompressed(self: ResourceRecord, writer: *Writer, table: *CompressionTable) !void {
        try table.writeName(writer, self.owner.asWire());
        try writer.writeU16(self.rrtype.code());
        try writer.writeU16(self.class.code());
        try writer.writeU32(self.ttl);
        const length_offset = writer.len();
        try writer.writeU16(0);
        const rdata_start = writer.len();
        try self.rdata.encodeCompressed(writer, table);
        try writer.patchU16(length_offset, @intCast(writer.len() - rdata_start));
    }
};

test "resource record parses and encodes A answer" {
    const bytes = [_]u8{
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o', 'm', 0,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 192, 0,   2,
        1,
    };

    const parsed = try ResourceRecord.parse(&bytes, 0);
    try std.testing.expectEqual(RecordType.A, parsed.record.rrtype);
    try std.testing.expectEqual(Class.IN, parsed.record.class);
    try std.testing.expectEqual(@as(u32, 3600), parsed.record.ttl);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &parsed.record.rdata.A);
    try std.testing.expectEqual(@as(usize, bytes.len), parsed.next_offset);

    var output: [64]u8 = undefined;
    var writer = Writer.init(&output);
    try parsed.record.encode(&writer);
    try std.testing.expectEqualSlices(u8, &bytes, writer.written());
}

test "resource record parses compressed owner and compressed RDATA name" {
    const bytes = [_]u8{
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',  0,
        3,    'w',  'w',  'w',  0xc0, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x02, 0xc0, 0x00,
    };

    const parsed = try ResourceRecord.parse(&bytes, 13);
    var owner_text: [64]u8 = undefined;
    var target_text: [64]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try parsed.record.owner.toText(&owner_text));
    try std.testing.expectEqualStrings("example.com.", try parsed.record.rdata.CNAME.toText(&target_text));
}
