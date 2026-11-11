# test/golden

The golden group. `zig build test-golden` runs it.

Each fixture carries `input_hex` with the query bytes and `expect:` with the
parsed-query fields — `parse_ok`, `id`, `qname`, `qtype`, `qclass`. Most
fixtures also carry `response_hex`, the exact answer bytes; the test that
loads one answers the query and compares the answer byte for byte. The
simple query fixture has no response and checks the parse expectations only.

## Rules

- A fixture changes only when the standard changes the bytes. A fixture is not a snapshot of a bug.
- The encoder and the decoder are not allowed to agree on a wrong answer. Where a second implementation exists, the interoperability group carries the proof.
