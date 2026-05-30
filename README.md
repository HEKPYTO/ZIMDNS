# gcli-dns

gcli-dns is a from-scratch DNS server platform written in Zig. The long-range target includes authoritative DNS, forwarding and iterative recursion, cache, policy, DNSSEC, encrypted DNS transports, local administration, Docker deployment, metrics, backup, and advanced resolver features.

The project is intentionally dependency-light. DNS wire parsing, encoding, resolver policy, zone handling, cache, configuration, CLI, metrics, and backup are implemented in this repository.

## Current Status

The repository is in the foundation and DNS wire-core stage. See:

- `docs/specs/gcli-dns-master-spec.md`
- `docs/plans/2026-05-30-gcli-dns-long-range-design.md`
- `docs/plans/2026-05-30-gcli-dns-implementation.md`

## Development

```sh
zig fmt .
zig build
zig build test
zig build test-golden
```

## Security Defaults

- No open recursion by default.
- Local admin socket only until a remote admin security model exists.
- Non-root Docker runtime.
- No third-party DNS parser, resolver, or server libraries.
