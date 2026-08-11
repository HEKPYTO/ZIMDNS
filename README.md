# ZIMDNS

ZIMDNS is a minimal, local-first DNS server and CLI written in Zig. The declared first-release profile is one scriptable binary with a small authoritative path, safe forwarding over DNS/UDP and DNS/TCP, and standards evidence for every advertised behavior. There is no web UI or remote administration surface in this profile.

The [RFC standards matrix](docs/standards-matrix.md) is the source of truth for what is implemented, partial, planned, or out of scope. A roadmap item is not a supported feature, and a `partial` row names only its tested subset.

The internal quality goal is to make this declared profile explicit, test-backed, and safe to operate. Any comparison with a comparable DNS server is an internal measurement target, not product copy or a general superiority claim. The immutable comparison source is the [a comparable DNS server `SupportedRFCs.md` inventory at commit ``]().

## Current status

The repository is a Phase 1 foundation and wire-core slice. It currently contains DNS message/name/RDATA parsing, a bounded authoritative runtime, UDP/TCP one-exchange listeners, a CLI query client, configuration/zone/blocklist parsers, a cache helper, metrics, a local admin socket, backup manifest support, and `doctor` checks. These pieces are not the complete first-release profile; consult the matrix for each boundary and its evidence.

Key documents:

- [Master specification](docs/specs/zimdns-master-spec.md)
- [RFC-first long-range design](docs/plans/2026-05-30-zimdns-long-range-design.md)
- [RFC-first implementation plan](docs/plans/2026-05-30-zimdns-implementation.md)
- [Historical revision findings](docs/notes/specs/2026-08-10-zimdns-revision-findings.md)

## Development

```sh
zig fmt .
zig build
zig build test
zig build test-golden
zig build test-config
```

## Security defaults

- Recursion is denied unless explicit client ACLs enable it; the process is not an open resolver by accident.
- Listeners use loopback/high ports by default. Privileged binding and non-loopback exposure require explicit configuration.
- Administration is local Unix socket only, with restrictive filesystem permissions.
- ECS forwarding, full packet logging, and secret/cookie logging are disabled by default.
- The Docker runtime is non-root.
- DNS semantics stay in this repository. Vetted crypto, TLS, HTTP, QUIC, or platform dependencies require a recorded dependency decision.
