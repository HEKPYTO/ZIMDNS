# test/fuzz

The fuzz group. `zig build test-fuzz` runs it.

Feeds malformed bytes to the message, name, zone, configuration, and blocklist
parsers and asserts that each one either parses them or refuses them with a
named error.

## Rules

- A crash is a failure. A wrong error code is a failure.
- The generator is deterministic: the seed and the iteration budget come from
  the build, and the seed is printed with the iteration that failed, so a
  failure is reproducible with `-Dfuzz-seed=<decimal>` and
  `-Dfuzz-iterations=<count>`. The build option takes a decimal number; the
  failure line prints the seed in hexadecimal. The default seed is
  `0x5eed7a57` and the default budget is 4096 iterations, about twelve
  seconds of work.
