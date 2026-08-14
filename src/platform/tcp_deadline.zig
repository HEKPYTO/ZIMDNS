/// Contract: supplies one absolute deadline for a bounded TCP frame exchange.
/// Ownership: callers own the socket and buffers; helpers only poll/read/write.
const std = @import("std");
const builtin = @import("builtin");

const tcp_deadlines_supported = switch (builtin.os.tag) {
    .linux, .macos => true,
    else => false,
};

pub const Timeout = struct {
    seconds: u32,
    microseconds: u32 = 0,
};

pub fn deadline(io: std.Io, timeout: Timeout) std.Io.Clock.Timestamp {
    const duration = std.Io.Clock.Duration{ .raw = .fromNanoseconds(
        @as(i96, timeout.seconds) * std.time.ns_per_s + @as(i96, timeout.microseconds) * std.time.ns_per_us,
    ), .clock = .awake };
    return std.Io.Clock.Timestamp.fromNow(io, duration);
}

pub fn deadlineFromTimeout(io: std.Io, timeout: std.Io.Timeout) ?std.Io.Clock.Timestamp {
    const duration = timeout.toDurationFromNow(io) orelse return null;
    return std.Io.Clock.Timestamp.fromNow(io, duration);
}

pub fn readExact(fd: std.posix.fd_t, io: std.Io, buffer: []u8, frame_deadline: std.Io.Clock.Timestamp) !void {
    return readExactWith(fd, io, buffer, frame_deadline, PosixIo{});
}

fn readExactWith(fd: std.posix.fd_t, io: std.Io, buffer: []u8, frame_deadline: std.Io.Clock.Timestamp, operation: anytype) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        waitForSocket(fd, io, frame_deadline, std.posix.POLL.IN) catch |err| {
            if (err == error.EndOfStream and offset > 0) return error.Truncated;
            return err;
        };
        const count = try operation.read(fd, buffer[offset..]);
        if (count == 0) return if (offset == 0) error.EndOfStream else error.Truncated;
        offset += count;
    }
}

pub fn writeExact(fd: std.posix.fd_t, io: std.Io, buffer: []const u8, frame_deadline: std.Io.Clock.Timestamp) !void {
    return writeExactWith(fd, io, buffer, frame_deadline, PosixIo{});
}

fn writeExactWith(fd: std.posix.fd_t, io: std.Io, buffer: []const u8, frame_deadline: std.Io.Clock.Timestamp, operation: anytype) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        try waitForSocket(fd, io, frame_deadline, std.posix.POLL.OUT);
        const count = operation.write(fd, buffer[offset..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (count == 0) return error.WriteFailed;
        offset += count;
    }
}

const PosixIo = struct {
    fn read(_: @This(), fd: std.posix.fd_t, buffer: []u8) !usize {
        return std.posix.read(fd, buffer);
    }

    fn write(_: @This(), fd: std.posix.fd_t, buffer: []const u8) !usize {
        const result = std.posix.system.sendto(fd, buffer.ptr, buffer.len, std.posix.MSG.NOSIGNAL, null, 0);
        return switch (std.posix.errno(result)) {
            .SUCCESS => @intCast(result),
            .AGAIN, .INTR => error.WouldBlock,
            else => error.WriteFailed,
        };
    }
};

fn waitForSocket(fd: std.posix.fd_t, io: std.Io, frame_deadline: std.Io.Clock.Timestamp, events: i16) !void {
    const remaining = frame_deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining <= 0) return error.Timeout;
    const millis = @divTrunc(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms);
    const poll_timeout: i32 = @intCast(@min(millis, std.math.maxInt(i32)));
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = events,
        .revents = 0,
    }};
    const count = try std.posix.poll(&poll_fds, poll_timeout);
    if (count == 0) return error.Timeout;
    const revents: i16 = poll_fds[0].revents;
    if ((revents & std.posix.POLL.NVAL) != 0) return error.ReadFailed;
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0 and (revents & events) == 0) {
        return if (events == std.posix.POLL.IN) error.EndOfStream else error.WriteFailed;
    }
}

const ScriptedIo = struct {
    counts: []const usize,
    index: usize = 0,
    calls: usize = 0,

    fn read(self: *@This(), fd: std.posix.fd_t, buffer: []u8) !usize {
        self.calls += 1;
        const count = @min(self.counts[self.index], buffer.len);
        self.index += 1;
        return std.posix.read(fd, buffer[0..count]);
    }

    fn write(self: *@This(), fd: std.posix.fd_t, buffer: []const u8) !usize {
        self.calls += 1;
        const count = @min(self.counts[self.index], buffer.len);
        self.index += 1;
        const result = std.posix.system.sendto(fd, buffer[0..count].ptr, count, std.posix.MSG.NOSIGNAL, null, 0);
        return switch (std.posix.errno(result)) {
            .SUCCESS => @intCast(result),
            .AGAIN, .INTR => error.WouldBlock,
            else => error.WriteFailed,
        };
    }
};

test "readExact loops over scripted partial reads" {
    if (comptime !tcp_deadlines_supported) return;
    const io = std.Io.Threaded.global_single_threaded.io();
    var sockets: [2]std.posix.fd_t = undefined;
    const socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(sockets[0]);
    defer _ = std.posix.system.close(sockets[1]);

    const payload = "partial read payload";
    const result = std.posix.system.sendto(sockets[1], payload.ptr, payload.len, std.posix.MSG.NOSIGNAL, null, 0);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
    try std.testing.expectEqual(payload.len, @as(usize, @intCast(result)));
    var received: [payload.len]u8 = undefined;
    var scripted = ScriptedIo{ .counts = &.{ 2, 3, payload.len - 5 } };
    try readExactWith(sockets[0], io, &received, deadline(io, .{ .seconds = 1 }), &scripted);
    try std.testing.expectEqualSlices(u8, payload, &received);
    try std.testing.expectEqual(@as(usize, 3), scripted.calls);
}

test "writeExact loops over scripted partial writes" {
    if (comptime !tcp_deadlines_supported) return;
    const io = std.Io.Threaded.global_single_threaded.io();
    var sockets: [2]std.posix.fd_t = undefined;
    const socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(sockets[0]);
    defer _ = std.posix.system.close(sockets[1]);

    const payload = "partial write payload";
    var scripted = ScriptedIo{ .counts = &.{ 2, 3, payload.len - 5 } };
    try writeExactWith(sockets[0], io, payload, deadline(io, .{ .seconds = 1 }), &scripted);
    var received: [payload.len]u8 = undefined;
    try readExact(sockets[1], io, &received, deadline(io, .{ .seconds = 1 }));
    try std.testing.expectEqualSlices(u8, payload, &received);
    try std.testing.expectEqual(@as(usize, 3), scripted.calls);
}
