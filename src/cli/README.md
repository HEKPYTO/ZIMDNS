# src/cli

The command line.

| File | Owns |
|---|---|
| `query.zig` | The `query` command: send one question to a server and print the answer. |
| `zonemd.zig` | The `zonemd publish` command: compute a zone's RFC 8976 digest and print the record. |

## Rules

- A question needs a name. The command refuses without one.
- The `query` command asks `127.0.0.1` on port 1053 unless the operator names
  another server with `@<server>` or another port with `-p`.
- A malformed invocation exits with the usage code. A refused answer is not a
  malformed invocation: the command prints the rcode and the answers, and
  exits zero.
