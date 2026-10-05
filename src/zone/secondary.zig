/// Contract: Minimal RFC 1996 secondary timing and refresh decisions driven by
/// SOA refresh/retry/expire timers.
/// Ownership: All state is inline with no allocation; timestamps are seconds.
/// Errors: No fallible operations; malformed input is expressed as Action.
const std = @import("std");
const dns_rdata = @import("../dns/rdata.zig");

/// Refresh timing taken from the zone's SOA record. Field bounds follow the
/// zone parser: every value is an unsigned 32-bit second count.
pub const Timers = struct {
    refresh: u32,
    retry: u32,
    expire: u32,

    pub fn fromSoa(soa: dns_rdata.Soa) Timers {
        return .{ .refresh = soa.refresh, .retry = soa.retry, .expire = soa.expire };
    }
};

/// Volatile secondary copy state for one zone. `has_data` is false before the
/// first successful transfer; `last_attempt_failed` selects the retry interval
/// after a failed refresh until one succeeds.
pub const State = struct {
    serial: u32 = 0,
    has_data: bool = false,
    last_refresh: u64 = 0,
    last_success: u64 = 0,
    last_attempt_failed: bool = false,
    expired: bool = false,
};

pub const Action = enum {
    /// No timer has fired; keep serving the current copy.
    none,
    /// The refresh or retry interval elapsed: send an SOA query, then IXFR
    /// when the primary serial is newer.
    refresh,
    /// The expire interval elapsed without contact: stop serving the copy.
    expire,
};

fn elapsed(now: u64, since: u64) u64 {
    return now -| since;
}

/// Picks the timer action for `now` (seconds). Expire wins over refresh so a
/// stale copy is never kept past its SOA expire bound.
pub fn nextAction(state: *const State, timers: *const Timers, now: u64) Action {
    if (!state.has_data) return .refresh;
    if (state.expired) return .expire;
    if (elapsed(now, state.last_success) >= timers.expire) return .expire;
    const interval: u64 = if (state.last_attempt_failed) timers.retry else timers.refresh;
    if (elapsed(now, state.last_refresh) >= interval) return .refresh;
    return .none;
}

/// Seconds until the next refresh or expire decision, saturating at zero when
/// an action is already due.
pub fn secondsUntilAction(state: *const State, timers: *const Timers, now: u64) u64 {
    if (!state.has_data) return 0;
    if (state.expired) return 0;
    const since_success = elapsed(now, state.last_success);
    if (since_success >= timers.expire) return 0;
    const interval: u64 = if (state.last_attempt_failed) timers.retry else timers.refresh;
    const since_refresh = elapsed(now, state.last_refresh);
    if (since_refresh >= interval) return 0;
    const to_refresh = interval - since_refresh;
    const to_expire = @as(u64, timers.expire) - since_success;
    return @min(to_refresh, to_expire);
}

/// Records a successful refresh or transfer at `now`.
pub fn applySuccess(state: *State, new_serial: u32, now: u64) void {
    state.serial = new_serial;
    state.has_data = true;
    state.last_refresh = now;
    state.last_success = now;
    state.last_attempt_failed = false;
    state.expired = false;
}

/// Records a failed refresh attempt at `now`; the retry interval applies
/// until a later attempt succeeds. Marks the copy expired when the SOA
/// expire bound has passed without contact.
pub fn applyFailure(state: *State, timers: *const Timers, now: u64) void {
    state.last_refresh = now;
    state.last_attempt_failed = true;
    if (state.has_data and elapsed(now, state.last_success) >= timers.expire) {
        state.expired = true;
    }
}

test "secondary refreshes when empty and after the SOA refresh interval" {
    const timers = Timers{ .refresh = 3600, .retry = 900, .expire = 1209600 };
    const empty = State{};
    try std.testing.expectEqual(Action.refresh, nextAction(&empty, &timers, 100));
    try std.testing.expectEqual(@as(u64, 0), secondsUntilAction(&empty, &timers, 100));

    var fresh = State{ .serial = 10, .has_data = true, .last_refresh = 1000, .last_success = 1000 };
    try std.testing.expectEqual(Action.none, nextAction(&fresh, &timers, 1000 + 3599));
    try std.testing.expectEqual(Action.refresh, nextAction(&fresh, &timers, 1000 + 3600));
    try std.testing.expectEqual(@as(u64, 1), secondsUntilAction(&fresh, &timers, 1000 + 3599));
}

test "secondary retries failed attempts on the SOA retry interval" {
    const timers = Timers{ .refresh = 3600, .retry = 900, .expire = 1209600 };
    var state = State{ .serial = 10, .has_data = true, .last_refresh = 1000, .last_success = 1000 };
    applyFailure(&state, &timers, 2000);
    try std.testing.expectEqual(Action.none, nextAction(&state, &timers, 2000 + 899));
    try std.testing.expectEqual(Action.refresh, nextAction(&state, &timers, 2000 + 900));
    applySuccess(&state, 11, 3000);
    try std.testing.expectEqual(@as(u32, 11), state.serial);
    try std.testing.expect(!state.last_attempt_failed);
    try std.testing.expectEqual(Action.none, nextAction(&state, &timers, 3000 + 3599));
}

test "secondary expires the copy past the SOA expire bound" {
    const timers = Timers{ .refresh = 3600, .retry = 900, .expire = 1200 };
    var state = State{ .serial = 10, .has_data = true, .last_refresh = 1000, .last_success = 1000 };
    try std.testing.expectEqual(Action.expire, nextAction(&state, &timers, 1000 + 1200));
    applyFailure(&state, &timers, 1000 + 1200);
    try std.testing.expect(state.expired);
    try std.testing.expectEqual(Action.expire, nextAction(&state, &timers, 1000 + 1300));
    try std.testing.expectEqual(@as(u64, 0), secondsUntilAction(&state, &timers, 1000 + 1300));
    applySuccess(&state, 11, 5000);
    try std.testing.expect(!state.expired);
    try std.testing.expectEqual(Action.none, nextAction(&state, &timers, 5000));
}

test "secondary derives timers from the zone SOA record" {
    const soa = dns_rdata.Soa{
        .mname = try @import("../dns/name.zig").Name.fromText("ns.example."),
        .rname = try @import("../dns/name.zig").Name.fromText("hostmaster.example."),
        .serial = 10,
        .refresh = 7200,
        .retry = 600,
        .expire = 2419200,
        .minimum = 3600,
    };
    const timers = Timers.fromSoa(soa);
    try std.testing.expectEqual(@as(u32, 7200), timers.refresh);
    try std.testing.expectEqual(@as(u32, 600), timers.retry);
    try std.testing.expectEqual(@as(u32, 2419200), timers.expire);
}
