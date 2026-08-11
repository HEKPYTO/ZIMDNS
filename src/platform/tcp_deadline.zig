/// Contract: supplies one absolute deadline for a bounded TCP frame exchange.
/// Ownership: callers own the socket and buffers; helpers only poll/read/write.
const std = @import("std");

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
    var offset: usize = 0;
    while (offset < buffer.len) {
        try waitForSocket(fd, io, frame_deadline, std.posix.POLL.IN);
        const count = try std.posix.read(fd, buffer[offset..]);
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

pub fn writeExact(fd: std.posix.fd_t, io: std.Io, buffer: []const u8, frame_deadline: std.Io.Clock.Timestamp) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        try waitForSocket(fd, io, frame_deadline, std.posix.POLL.OUT);
        const result = std.posix.system.sendto(fd, buffer[offset..].ptr, buffer.len - offset, std.posix.MSG.NOSIGNAL, null, 0);
        switch (std.posix.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.WriteFailed;
                offset += @intCast(result);
            },
            .AGAIN, .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

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
