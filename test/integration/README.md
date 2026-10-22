# test/integration

The socket group. `zig build test-integration` runs it.

Starts the server on a loopback socket and talks to it with a real client.

## Rules

- Each test starts and stops its own server. No test depends on another test's server.
- A bound port is chosen by the operating system, never hard-coded.
