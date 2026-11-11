# ZIMDNS

A small, auditable DNS server for one box you control. It serves authoritative
zones, optional forwarding and recursion, DNSSEC, and encrypted transports from
one binary with no admin plane. Configuration is a file; durable state is on
disk.

## What it does

- Authoritative zones: signing, NSEC/NSEC3 denial, ZONEMD verification, AXFR,
  IXFR, NOTIFY, RFC 2136 updates, and TSIG.
- Forwarding and recursion with DNSSEC validation, ECS, NAT64, and an answer
  cache bounded by both entry count and response size.
- UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, and Oblivious DoH.
- Prometheus counters on demand, a startup banner, readiness checks, and
  immediate SIGTERM/SIGINT shutdown. There is no remote control plane.

The test suite exercises the documented behavior. A roadmap item is not a
supported feature, and a partial implementation names only its tested subset.
Module details live in the `README.md` beside each source directory.

## Try it

```sh
docker compose -f docker-compose.dev.yml up --build
dig @127.0.0.1 -p 1053 home.arpa. SOA
```

For production, pin a release image by digest and point `ZIMDNS_CONFIG_DIR` at
the directory holding `config.gdns`, `zones/`, and `blocklists/`:

```sh
export ZIMDNS_IMAGE=ghcr.io/hekpyto/zimdns@sha256:<digest>
export ZIMDNS_CONFIG_DIR=/srv/zimdns
docker compose up -d
```

`docker-compose.yml` runs non-root, read-only, with dropped capabilities,
resource limits, and a health check. The health check queries `localhost. A`
from the RFC 6761 local zones; if you disable local zones, set
`ZIMDNS_HEALTH_NAME` to a name that exists in a zone you serve. Rollback: set
`ZIMDNS_IMAGE` to the previous digest-pinned image and run
`docker compose up -d`.

## Configure

The configuration file is line-oriented; `examples/config.gdns` is the starting
point. Paths resolve against the config file's directory, except TLS
certificate and key paths, which resolve from the process working directory, so
use absolute paths for those.

```sh
zimdns server run --config /etc/zimdns/config.gdns --serve-udp --serve-tcp
zimdns query @127.0.0.1 -p 1053 home.arpa. SOA
```

`zimdns --help` lists the server and query flags. The repository examples cover
authoritative zones, DNSSEC, forwarding, blocklists, and local zones; ACLs,
transfers, and encrypted listeners are documented by `zimdns --help` and the
module READMEs.

## Performance

Measured on an 8-core Linux host with dnsperf over UDP at 400 clients: about
56k queries/s, ~1 ms mean, 0% loss. A native ReleaseSafe run with 5000 distinct
forwarded names sustained 62k queries/s, p99 6.8 ms, and 0% loss over 10
minutes, with RSS staying under 36 MiB.

The documented envelope is explicit: 16,384 cached responses of at most 4 KiB
each, 16 UDP workers, concurrent plain-UDP forwarding, and serialized
iterative/TLS/DoH/DDR/DNSSEC-proof paths per resolver. A working set larger than
16,384 pays a cold upstream resolution per name. Numbers on another host will
differ; reproduce with dnsperf.

## Security defaults

- Recursion and forwarding are denied unless explicit ACLs and a forwarder are
  configured. Listeners default to loopback or high ports.
- No administrative socket or remote control plane is exposed.
- Packet payloads, keys, and cookies are never logged.
- The compose service runs as UID 10001 with all capabilities dropped.
- A public authoritative deployment still needs network-level UDP rate
  limiting; DNS Cookies reduce spoofed traffic but are not a rate limit. This
  server does not implement RRL.

## Build and test

Zig 0.17.0, OpenSSL 3.x, and GnuTLS development files are required. On
Debian/Ubuntu install `libssl-dev libgnutls28-dev`; on macOS run
`brew install openssl@3 gnutls` and export
`OPENSSL_PREFIX=$(brew --prefix openssl@3)` before building.

```sh
zig build
zig build test
zig build test-golden
zig build test-config
zig build test-fuzz
zig build test-integration
zig build test-cli
```

Test roots live under `test/{unit,golden,config,fuzz,integration,cli}/`.
`scripts/install-hooks` installs the formatting pre-commit hook.

## License and releases

AGPL-3.0-only (`LICENSE`). Vendored QUIC/HTTP3 sources keep their own MIT
notices under `third_party/`.

Release images carry source revision and version labels, and `zimdns --version`
reports the build version. Pushing a `v*` tag to GitHub runs the gated release
workflow; it can also be started manually:

```sh
gh workflow run Release --repo HEKPYTO/ZIMDNS --ref v0.1.0
```

The workflow builds a multi-arch `ghcr.io/hekpyto/zimdns` image with SBOM and
provenance, signs it with cosign keyless, and creates the GitHub release. Set
the GHCR package visibility to public when the repository becomes public;
package visibility is separate. Verify the digest before deployment:

```sh
cosign verify ghcr.io/hekpyto/zimdns@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/HEKPYTO/ZIMDNS/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
