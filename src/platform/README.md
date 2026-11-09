# src/platform

Sockets, listeners, and deadlines.

| File | Owns |
|---|---|
| `listener.zig` | Binding, accepting, the per-source connection limit, and the per-frame deadline. |
| `tcp_deadline.zig` | The raw-descriptor poll deadline shared by every transport. |

## Rules

- One absolute deadline covers a complete exchange or a complete frame. The
  bound comes from a `poll` on the raw descriptor, not from a socket timeout:
  the io's own socket read surfaces a timed-out read as `EAGAIN`, which the
  threaded backend treats as a programmer bug. The socket timeout is set on
  the descriptor as well, but it is only a backstop.
- The shared TCP-family worker cap is 64 (`TCP_MAX_CONNECTION_WORKERS`),
  enforced by TCP, DoT, DoH, and XFR as a clean close on
  `ConcurrencyUnavailable`. The per-source cap defaults to 8
  (`tcp-max-connections-per-source`; unset means 8). The 64-slot source
  table covers every worker, so a full table refuses only at the real
  worker cap. The limit is checked when a connection is accepted, and
  the count is live rather than sampled.
