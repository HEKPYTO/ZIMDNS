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
- The per-source connection limit is checked when a connection is accepted, and
  the count is live rather than sampled.
