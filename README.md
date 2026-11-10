# ZIMDNS

A small, auditable DNS server for one box you control. It serves authoritative
zones, optional forwarding and recursion, DNSSEC, and encrypted transports from
one binary with no admin plane. Configuration is a file; state is on disk.

## What it does

- Authoritative zones: signing, NSEC/NSEC3 denial, ZONEMD verification, AXFR,
  IXFR, NOTIFY, RFC 2136 updates, and TSIG.
- Forwarding and recursion with DNSSEC validation, ECS, NAT64, and an answer
  cache bounded by both entry count and response size.
- UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, and Oblivious DoH.
- Prometheus counters on demand, a startup banner, health checks, and graceful
  drain. There is no remote control plane.

Every advertised behavior names its test. A roadmap item is not a supported
feature, and a partial implementation names only its tested subset. Module
details live in the `README.md` beside each source directory.

## Try it

```sh
docker compose -f docker-compose.dev.yml up --build
dig @127.0.0.1 -p 1053 home.arpa. SOA
```

For production, set `ZIMDNS_CONFIG_DIR` to the directory holding `config.gdns`,
`zones/`, and `blocklists/`, then run:

```sh
docker compose up -d
```

`docker-compose.yml` runs non-root, read-only, with dropped capabilities,
resource limits, and a health check. Rollback: set `ZIMDNS_IMAGE` to the
previous digest-pinned image and run `docker compose up -d`.

## Configure

The configuration file is line-oriented; `examples/config.gdns` is the starting
point. Paths resolve against the config file's directory, except TLS
certificate and key paths, which resolve from the process working directory, so
use absolute paths for those.

```sh
zimdns server run --config /etc/zimdns/config.gdns --serve-udp --serve-tcp
zimdns query @127.0.0.1 -p 1053 home.arpa. SOA
```

`zimdns --help` lists every server and query flag. The repository examples cover
authoritative zones, DNSSEC, forwarding, ACLs, transfers, DoH, and DoT.

## Performance

Measured on an 8-core Linux host with dnsperf over UDP at 400 clients: about
57k queries/s, ~1 ms mean, 0% loss. A native ReleaseSafe run with 5000 distinct
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
- Full packet logging and secret/cookie logging are off by default.
- The container runs as UID 10001 and drops all capabilities.
- A public authoritative deployment still needs network-level UDP rate limiting
  or DNS Cookies. This server does not implement RRL.

## Build and test

Zig 0.17.0 and OpenSSL 3.x development files are required. On Debian/Ubuntu
install `libssl-dev`; on macOS run `brew install openssl@3` and export
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
reports the build version. The release workflow builds a multi-arch `ghcr.io`
image with SBOM and provenance and signs it with cosign keyless. Public release
is deferred until the source and security gates pass.
