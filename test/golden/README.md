# test/golden

The golden group. `zig build test-golden` runs it.

Each fixture is three blocks: `input_hex` holds the query bytes, `response_hex`
holds the exact bytes of the answer, and `expect:` states what the parsed
query must look like — `parse_ok`, `id`, `qname`, `qtype`, `qclass`. The test
answers the query and compares the answer byte for byte.

## Rules

- A fixture changes only when the standard changes the bytes. A fixture is not a snapshot of a bug.
- The encoder and the decoder are not allowed to agree on a wrong answer. Where a second implementation exists, the interoperability group carries the proof.
