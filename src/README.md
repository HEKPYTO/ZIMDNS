# src

The server and the CLI. One binary. The commands are `server run` and `query`.

| Path | Owns |
|---|---|
| `main.zig` | Argument parsing and process wiring. |
| `resolver.zig` | Upstream lookups, caching, DNS64 synthesis, the reporting resolver, and the iterative answer path. |
| `iterate.zig` | Iterative resolution from the root hints: referrals, glue hints, alias chains, and their bounds. |
| `metrics.zig` | Counters exported by the server. |
| `blocklist.zig` | Blocked-name policy: exact domain names, matched after normalization. |
| `local_zone.zig` | Locally served zones that are not loaded from files. |
| `golden_fixture.zig` | Shared helpers for the golden test group. |
| `auth/` | TSIG keys and authenticated request handling. |
| `cli/` | The `query` subcommand. |
| `config/` | The configuration grammar and its loader. |
| `dns/` | Wire format: header, question, name, record types, RDATA, reader, writer, TSIG, DNSSEC signing and validation, padding, and the error report. |
| `platform/` | Sockets, listeners, and deadlines. |
| `transfer/` | Zone transfers, plain and over TLS. |
| `transport/` | The encrypted request paths: the shared channel, DoT, DoH, and the TLS policy. |
| `zone/` | Zone parsing, storage, signing, journaling, ZONEMD, and the transfer client. |

## Conventions

- A new public function carries a doc comment that states the rule it implements,
  not the mechanics. (The tree is not uniform here yet: 59 of its 187 public
  functions carry none.)
- A capability with no reachable caller is a defect, not a style note.
- `zig fmt` is the only formatter; the pre-commit hook enforces it.
