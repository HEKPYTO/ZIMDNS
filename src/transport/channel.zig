/// Contract: The channel a strict-TLS connection carries DNS frames over,
/// with the bounds the operator configured: the lifetime of the connection
/// and the deadline of every frame, both applied to the raw descriptor under
/// the TLS connection. The DoT port and the RFC 9103 transfer channel share
/// it, so both hold the same bounds. A socket timeout cannot carry a frame:
/// a blocked read that hits SO_RCVTIMEO surfaces as EAGAIN, which the
/// threaded backend treats as a programmer bug and answers with a panic, so a
/// stalled peer would take the whole server down.
/// Ownership: the channel borrows the reader, the writer and the deadline
/// holders of the connection; the caller owns the socket and the buffers.
/// Errors: none; the channel only computes and applies deadlines.
const std = @import("std");
const listener = @import("../platform/listener.zig");
const tcp_deadline = @import("../platform/tcp_deadline.zig");

/// One connection: the channel the frames travel over and the deadlines that
/// bound them. The frames travel over the TLS connection or over the socket,
/// and the deadlines are applied to the raw descriptor under it, so a stalled
/// peer holds neither a frame nor a connection past its bound.
pub const Channel = struct {
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    deadlines: tcp_deadline.FrameDeadlines,
    timeout: tcp_deadline.Timeout,
    connection_deadline: ?std.Io.Clock.Timestamp,

    /// The deadline of the frame that starts now: the per-frame timeout,
    /// shortened to what is left of the connection's lifetime. Null means
    /// the connection is over. A caller that reads and writes one frame
    /// takes the deadline once and applies it to both, so one frame cannot
    /// take two windows.
    pub fn frameDeadline(self: *const Channel) ?std.Io.Clock.Timestamp {
        const frame_timeout = listener.frameTimeout(self.io, self.connection_deadline, self.timeout) orelse return null;
        return tcp_deadline.deadline(self.io, frame_timeout);
    }

    /// Bounds the frame that starts now to the raw descriptor under the
    /// channel. False means the connection has outlived its duration and
    /// ends here.
    pub fn applyFrameDeadline(self: *const Channel) bool {
        const frame_deadline = self.frameDeadline() orelse return false;
        self.deadlines.apply(frame_deadline);
        return true;
    }
};

/// The end of one connection: the operator may bound the lifetime of a
/// connection (RFC 9210 section 4.2), and that deadline covers the whole
/// connection. Null means the connection lives as long as the transport
/// allows.
pub fn connectionDeadline(io: std.Io) ?std.Io.Clock.Timestamp {
    const seconds = listener.tcpLimits().max_connection_duration orelse return null;
    return tcp_deadline.deadline(io, .{ .seconds = seconds });
}
