/// Contract: supplies one absolute deadline for a bounded TCP frame exchange,
/// and the reader and writer that carry a frame over a raw descriptor under
/// that deadline.
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

/// Installs SO_RCVTIMEO/SO_SNDTIMEO on `fd`, best effort.
///
/// darwin rejects *every* SOL_SOCKET option with EINVAL once both directions
/// are shut down: the kernel raises SS_CANTRCVMORE when a peer FIN arrives
/// (XNU `tcp_input`, `socantrcvmore`) and SS_CANTSENDMORE on shutdown(SHUT_WR),
/// after which `sosetoptlock` refuses the whole level. `std.posix.setsockopt`
/// maps that EINVAL to `unreachable`, so calling it on a half-closed connection
/// aborts the process. Talk to the syscall directly instead: a connection that
/// is already finished simply keeps no socket timeout, and every frame exchange
/// stays bounded by the poll deadlines below.
pub fn setSocketTimeout(fd: std.posix.fd_t, timeout: Timeout) void {
    const value: std.posix.timeval = .{
        .sec = @intCast(timeout.seconds),
        .usec = @intCast(timeout.microseconds),
    };
    const bytes = std.mem.asBytes(&value);
    for ([_]u32{ std.posix.SO.RCVTIMEO, std.posix.SO.SNDTIMEO }) |option| {
        const result = std.posix.system.setsockopt(fd, std.posix.SOL.SOCKET, option, bytes.ptr, @intCast(bytes.len));
        _ = std.posix.errno(result);
    }
}

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

/// The reader of a channel that carries frames over a raw descriptor. The
/// io's own socket read cannot carry a deadline: a blocked read that hits
/// SO_RCVTIMEO surfaces as EAGAIN, which the threaded backend treats as a
/// programmer bug and answers with a panic, so the deadline is enforced
/// over the raw descriptor with poll instead of a socket option.
pub const DeadlineReader = struct {
    interface: std.Io.Reader,
    fd: std.posix.fd_t,
    io: std.Io,
    timeout: Timeout,
    /// The absolute end of the frame in flight. Null means the timeout
    /// applies to every read on its own.
    frame_deadline: ?std.Io.Clock.Timestamp = null,

    pub fn init(fd: std.posix.fd_t, io: std.Io, buffer: []u8, timeout: Timeout) DeadlineReader {
        return .{
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .fd = fd,
            .io = io,
            .timeout = timeout,
        };
    }

    /// Bounds the reads that follow to one absolute deadline, so a frame
    /// cannot outlive it however many reads it takes.
    pub fn setFrameDeadline(self: *DeadlineReader, frame_deadline: std.Io.Clock.Timestamp) void {
        self.frame_deadline = frame_deadline;
    }

    fn effectiveDeadline(self: *const DeadlineReader) std.Io.Clock.Timestamp {
        return self.frame_deadline orelse deadline(self.io, self.timeout);
    }

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *DeadlineReader = @alignCast(@fieldParentPtr("interface", reader));
        const buffer = limit.slice(try writer.writableSliceGreedy(1));
        const count = readWithDeadline(self.fd, self.io, buffer, self.effectiveDeadline()) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            else => return error.ReadFailed,
        };
        writer.advance(count);
        return count;
    }
};

/// The writer of a channel that carries frames over a raw descriptor, under
/// the same deadline the reader keeps.
pub const DeadlineWriter = struct {
    interface: std.Io.Writer,
    fd: std.posix.fd_t,
    io: std.Io,
    timeout: Timeout,
    /// The absolute end of the frame in flight. Null means the timeout
    /// applies to every write on its own.
    frame_deadline: ?std.Io.Clock.Timestamp = null,

    pub fn init(fd: std.posix.fd_t, io: std.Io, buffer: []u8, timeout: Timeout) DeadlineWriter {
        return .{
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
                .end = 0,
            },
            .fd = fd,
            .io = io,
            .timeout = timeout,
        };
    }

    /// Bounds the writes that follow to one absolute deadline, so a frame
    /// cannot outlive it however many writes it takes.
    pub fn setFrameDeadline(self: *DeadlineWriter, frame_deadline: std.Io.Clock.Timestamp) void {
        self.frame_deadline = frame_deadline;
    }

    fn effectiveDeadline(self: *const DeadlineWriter) std.Io.Clock.Timestamp {
        return self.frame_deadline orelse deadline(self.io, self.timeout);
    }

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *DeadlineWriter = @alignCast(@fieldParentPtr("interface", writer));
        try self.writeAll(writer.buffered());
        writer.end = 0;
        if (data.len == 0) return 0;
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            try self.writeAll(bytes);
            written += bytes.len;
        }
        const pattern = data[data.len - 1];
        written += pattern.len * splat;
        switch (pattern.len) {
            0 => {},
            1 => {
                const repeated: [256]u8 = @splat(pattern[0]);
                var remaining = splat;
                while (remaining > 0) {
                    const chunk = @min(remaining, repeated.len);
                    try self.writeAll(repeated[0..chunk]);
                    remaining -= chunk;
                }
            },
            else => for (0..splat) |_| try self.writeAll(pattern),
        }
        return written;
    }

    fn writeAll(self: *DeadlineWriter, bytes: []const u8) std.Io.Writer.Error!void {
        const frame_deadline = self.effectiveDeadline();
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = writeWithDeadline(self.fd, self.io, bytes[offset..], frame_deadline) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return error.WriteFailed,
            };
            if (count == 0) return error.WriteFailed;
            offset += count;
        }
    }
};

/// The deadline holders of one channel: the raw descriptor the reads and the
/// writes of a frame travel over. A frame sets its deadline on them, so the
/// whole frame shares one absolute deadline.
pub const FrameDeadlines = struct {
    reader: *DeadlineReader,
    writer: *DeadlineWriter,

    pub fn apply(self: *const FrameDeadlines, frame_deadline: std.Io.Clock.Timestamp) void {
        self.reader.setFrameDeadline(frame_deadline);
        self.writer.setFrameDeadline(frame_deadline);
    }
};

/// Reads what the descriptor holds, waiting at most until the deadline.
fn readWithDeadline(fd: std.posix.fd_t, io: std.Io, buffer: []u8, frame_deadline: std.Io.Clock.Timestamp) !usize {
    try waitForSocket(fd, io, frame_deadline, std.posix.POLL.IN);
    const count = std.posix.read(fd, buffer) catch |err| switch (err) {
        error.WouldBlock => return error.Timeout,
        else => return err,
    };
    if (count == 0) return error.EndOfStream;
    return count;
}

/// Writes what the descriptor takes, waiting at most until the deadline.
fn writeWithDeadline(fd: std.posix.fd_t, io: std.Io, buffer: []const u8, frame_deadline: std.Io.Clock.Timestamp) !usize {
    try waitForSocket(fd, io, frame_deadline, std.posix.POLL.OUT);
    const result = std.posix.system.sendto(fd, buffer.ptr, buffer.len, std.posix.MSG.NOSIGNAL, null, 0);
    return switch (std.posix.errno(result)) {
        .SUCCESS => @intCast(result),
        .AGAIN, .INTR => error.WouldBlock,
        else => error.WriteFailed,
    };
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
test "socket timeout fails a stalled peer read instead of blocking forever" {
    if (comptime !tcp_deadlines_supported) return;
    var sockets: [2]std.posix.fd_t = undefined;
    const socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(sockets[0]);
    defer _ = std.posix.system.close(sockets[1]);

    setSocketTimeout(sockets[0], .{ .seconds = 0, .microseconds = 50_000 });
    var buffer: [8]u8 = undefined;
    // The peer never writes, so the only outcome is SO_RCVTIMEO firing: without
    // the option this read would hang until the test runner is killed.
    try std.testing.expectError(error.WouldBlock, std.posix.read(sockets[0], &buffer));
}

test "setSocketTimeout tolerates a socket that is shut down on both sides" {
    if (comptime !tcp_deadlines_supported) return;
    var sockets: [2]std.posix.fd_t = undefined;
    const socket_result = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets);
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(socket_result));
    defer _ = std.posix.system.close(sockets[0]);
    defer _ = std.posix.system.close(sockets[1]);

    // SHUT_RDWR is 2 on both linux and darwin; std.posix has no shutdown wrapper.
    for (sockets) |fd| _ = std.posix.system.shutdown(fd, @as(u32, 2));
    // darwin's sosetoptlock answers EINVAL for every SOL_SOCKET option once
    // SS_CANTRCVMORE|SS_CANTSENDMORE are set, which std.posix.setsockopt
    // turns into an unreachable panic. Reaching the next line is the assertion.
    setSocketTimeout(sockets[0], .{ .seconds = 5 });
}
