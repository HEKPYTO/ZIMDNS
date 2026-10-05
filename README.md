# ZIMDNS

ZIMDNS is a minimal, local-first DNS server and CLI written in Zig. The current profile is one scriptable binary with a small authoritative path, safe DNS/UDP and DNS/TCP transport, and a standards matrix that names the exact evidence behind every advertised behavior. There is no web UI or remote administration surface in this profile.

The [RFC standards matrix](docs/standards-matrix.md) is the source of truth for what is `supported`, `partial`, `planned`, `not-applicable`, or `out of scope`. A roadmap item is not a supported feature, and a `partial` row names only its tested subset.

The internal quality goal is to make this declared profile explicit, test-backed, and safe to operate. Any comparison with a comparable DNS server is an internal measurement target, not product copy or a general superiority claim. The immutable comparison source is the [a comparable DNS server `SupportedRFCs.md` inventory at commit ``]().

## Current status

The repository contains the bounded authoritative and forwarding profile. It currently has DNS message/name/RDATA parsing, continuous authoritative UDP listeners, fail-closed authoritative TCP ingress, opt-in UDP forwarding with source/ID/question checks and TC-to-TCP upstream fallback only where upstream TCP deadlines are available (TC fails closed otherwise), bounded positive/negative caching with serve-stale, forwarding-path-only EDE diagnostics, DNS Cookie validation, a CLI query client, and strict configuration/zone/blocklist parsers. Forwarding is disabled unless both an explicit recursion ACL and a forwarder are configured; consult the matrix for each exact boundary and its evidence.

Locally served DNS zones (RFC 6303, RFC 6761, RFC 7793, RFC 8375) are answered by this server by default, ahead of the cache and the forwarder, so a configured upstream never sees a name reserved for private, test, invalid, loopback, or home-network use. A configuration turns them off with `local-zones off`. See [`examples/local-zones.gdns`](examples/local-zones.gdns) and the matrix row for the exact zone list and treatment.

A zone that carries an apex ZONEMD record (RFC 8976, type 63) is verified when it loads, and the server refuses to start if the digest does not match the zone data, naming the zone, the expected digest, and the computed one. The SIMPLE scheme with SHA384 and SHA512 is supported; see the matrix row for what is and is not implemented.

A zone is signed at startup by naming a key file in the configuration: `dnssec-key-file <path>`. Every configured zone then gets an apex DNSKEY and DS, one NSEC per authoritative owner, and one RRSIG per RRset (RFC 4034 §§3.1.8.1 and 5.1.4, RFC 4035 §2.3), served from memory without touching the zone file. ECDSA P-256 (RFC 6605 algorithm 13), ECDSA P-384 (RFC 6605 algorithm 14), and Ed25519 (RFC 8080 algorithm 15) are implemented; RSA and Ed448 are absent because the standard library has no primitive for either. `zimdns query --dnssec` sets the RFC 6891 DO bit so the server returns its signatures, and the CLI prints the answer, authority, and additional sections, which is where RRSIG and NSEC actually arrive. [`examples/dnssec/`](examples/dnssec/config.gdns) is a worked configuration. Signing is all this build does: it never validates a chain, never sets AD, and has no trust anchors, NSEC3 denial serving, or key rollover.

Two EDNS(0) options that identify *this* server are configuration directives, and neither is ever sent to a client that did not ask for it. `nsid <hex>` (RFC 5001 §2.3, option code 3) answers a resolver's NSID request with the operator's own identifier, written in the two-hex-digits-per-octet presentation format the RFC requires; nothing is derived from an address or a hostname, so a server with no `nsid` line answers no NSID at all. `zoneversion on|off` (RFC 9660, option code 19) answers a ZONEVERSION request with the responding zone's SOA serial — TYPE 0, or SOA-SERIAL — for answers, NXDOMAIN, NODATA, and referrals alike; it is on by default, and a malformed request is answered FORMERR as §3.2.1 requires. A forwarder configured with `trust-anchor-file` also signals its anchors' Key Tags on its own upstream DNSKEY queries (RFC 8145 §4.2, option code 14) and never answers with that option. The bundled `query` CLI prints no OPT pseudosection, so read these with a client that does, such as `dig +nsid` and `dig +zoneversion`; the matrix rows record exactly what is and is not implemented.

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
zig build test-cli
```

## Security defaults

- Recursion is denied unless explicit client ACLs enable it; the process is not an open resolver by accident.
- Listeners use loopback/high ports by default. Privileged binding and non-loopback exposure require explicit configuration.
- No administrative socket or remote control plane is exposed.
- Forwarding is disabled by default and requires explicit recursion ACLs plus a configured forwarder.
- Full packet logging and secret/cookie logging are disabled by default.
- The Docker runtime is non-root.
- DNS semantics stay in this repository. Vetted crypto, TLS, HTTP, QUIC, or platform dependencies require a recorded dependency decision.
