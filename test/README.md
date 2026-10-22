# test

The test suite. Six groups, one command each.

| Group | Command | What it covers |
|---|---|---|
| `unit/` | `zig build test` | The tests embedded in `src/`, plus the roots in `test/unit/`. |
| `golden/` | `zig build test-golden` | Byte-exact answers against stored fixtures. |
| `config/` | `zig build test-config` | The configuration grammar and the loader's refusals. |
| `fuzz/` | `zig build test-fuzz` | The message, name, zone, configuration, and blocklist parsers against malformed input. |
| `integration/` | `zig build test-integration` | A real server on a real socket. |
| `cli/` | `zig build test-cli` | The documented invocations, exactly as the README prints them. |
| `interop/` | `python3 test/interop/tls_channel_test.py` | An offline mirror of the encrypted-channel unit tests, written in Python so the contract is stated twice. |

## Rules

- A test asserts behavior, not the shape of the implementation.
- A test that repeats the implementation earns nothing and is deleted.
- No test reaches outside the loopback interface.
