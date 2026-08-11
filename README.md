# ZIMDNS

ZIMDNS is a minimal, local-first DNS server and CLI written in Zig. The current profile is one scriptable binary with a small authoritative path, safe DNS/UDP and DNS/TCP transport, and standards evidence for every advertised behavior. There is no web UI or remote administration surface in this profile.

The [RFC standards matrix](docs/standards-matrix.md) is the source of truth for what is `supported`, `partial`, `planned`, `not-applicable`, or `out of scope`. A roadmap item is not a supported feature, and a `partial` row names only its tested subset.

The internal quality goal is to make this declared profile explicit, test-backed, and safe to operate. Any comparison with a comparable DNS server is an internal measurement target, not product copy or a general superiority claim. The immutable comparison source is the [a comparable DNS server `SupportedRFCs.md` inventory at commit ``]().

## Current status

The repository contains the bounded authoritative and forwarding profile. It currently has DNS message/name/RDATA parsing, continuous authoritative UDP listeners, fail-closed authoritative TCP ingress, opt-in UDP forwarding with source/ID/question checks and TC-to-TCP upstream fallback only where upstream TCP deadlines are available (TC fails closed otherwise), bounded positive/negative caching with serve-stale, EDE diagnostics, DNS Cookie validation, a CLI query client, and strict configuration/zone/blocklist parsers. Forwarding is disabled unless both an explicit recursion ACL and a forwarder are configured; consult the matrix for each exact boundary and its evidence.

RFC 9463 DNR is `not-applicable` to this DNS-only server because it defines DHCP/Router Advertisement provisioning; no DNR parser, CLI/config surface, DHCP, RA, or output artifact is planned.

Key documents:

- [DNS RFC parity roadmap](docs/plans/2026-08-12-dns-rfc-parity-roadmap.md)
- [Master specification](docs/specs/zimdns-master-spec.md)
- [Historical revision findings](docs/notes/specs/2026-08-10-zimdns-revision-findings.md)

## Development

```sh
zig fmt .
zig build
zig build test
zig build test-golden
zig build test-config
zig build test-fuzz
zig build test-integration
```

## Security defaults

- Recursion is denied unless explicit client ACLs enable it; the process is not an open resolver by accident.
- Listeners use loopback/high ports by default. Privileged binding and non-loopback exposure require explicit configuration.
- No administrative socket or remote control plane is exposed.
- Forwarding is disabled by default and requires explicit recursion ACLs plus a configured forwarder.
- Full packet logging and secret/cookie logging are disabled by default.
- The Docker runtime is non-root.
- DNS semantics stay in this repository. Vetted crypto, TLS, HTTP, QUIC, or platform dependencies require a recorded dependency decision.
