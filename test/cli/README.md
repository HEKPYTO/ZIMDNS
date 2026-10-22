# test/cli

The command-line group. `zig build test-cli` runs it.

Runs the invocations the README prints, with the arguments the README prints, and checks the exit code and the output.

## Rules

- A documented invocation that changes must fail here first.
- Each case states the exit code it expects and the line it expects to see, so
  a changed output fails the group that documents it.
