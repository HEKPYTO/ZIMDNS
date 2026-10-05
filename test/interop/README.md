# Interop probes (offline evidence + deferred live probes)

The channel logic is covered offline by `tls_channel_test.py` (13/13,
stdlib only, no sockets) and by module unit tests; the per-row logs live
under `docs/reports/`. Live loopback probes are blocked: `--serve-dot`,
`--serve-doh`, and `--serve-xfr` refuse to start and bind no port because no
TLS-server dependency is linked, so there is nothing for `kdig`, `curl`, or
`dig` to connect to (see `docs/decisions/encrypted-transport.md`).

## Offline channel evidence (no socket, runs anywhere)

```sh
python3 test/interop/tls_channel_test.py   # 13/13: 5 tls.zig + 4 doh.zig + 4 dot.zig
```

Transcripts: `docs/reports/interop-final/doh-get-post-transcript.log`
(DoH GET + POST mapping vectors) and
`docs/reports/interop-final/axfr-transcript.log` (SOA-framed AXFR
sequence + refusal matrix); run summary in
`docs/reports/interop-final/SUMMARY.md`.

## Environment prerequisites (2026-09-09)

- `kdig` is not installed in this environment (`command -v kdig` fails;
  `/usr/bin/dig` exists but cannot substitute for the DoT probe).
- All loopback socket binds are env-blocked: code-independent probe
  `socket.bind(127.0.0.1:0)` and `(::1)` both fail `errno=1 EPERM`
  (see `docs/reports/gates-final/env-bind-probe.log`); system
  `dig @127.0.0.1` fails identically (`isc_socket_bind: Operation not
  permitted`). Live DoT/DoH/XFR probes are therefore ENV-BLOCKED, not
  run (see `docs/reports/gates-final/SUMMARY.md`). The NSEC3 oracle
  passes 3/3 (see `docs/reports/gates-final/interop-nsec3-oracle.log`).

## DoT (RFC 7858) — `kdig` — BLOCKED, no listener

```sh
./zig-out/bin/zimdns server run --zone-file examples/zones/home.arpa.zone \
  --serve-dot --enable-encrypted-dns \
  --tls-cert-file tls/cert.pem --tls-key-file tls/key.pem
```

Exits 2 with `error: --serve-dot, --serve-doh, and --serve-xfr require TLS
termination, which this build cannot provide ... The listener was not started
and the port was not bound.` No port is bound, so `kdig +tls` cannot connect.
Re-run this probe once a reviewed TLS-server dependency lands.

## DoH (RFC 8484) — `curl` — BLOCKED, no listener

```sh
curl --doh-url https://localhost:443/dns-query --cacert tls/cert.pem \
  -H 'accept: application/dns-message' \
  'https://localhost/dns-query?dns=<base64url-wire-query>' -o resp.bin
```

Nothing is listening: `--serve-doh` refuses to start for the same reason as
DoT. The HTTP/1.1 GET/POST mapping it would serve is covered by the
`src/transport/doh.zig` unit tests instead.

## XFR-over-TLS (RFC 9103) — `dig` — BLOCKED, no listener

```sh
dig @127.0.0.1 -p <xfr-port> +tls example. AXFR
```

Nothing is listening: `--serve-xfr` refuses to start for the same reason as
DoT. The SOA-framed sequence (apex SOA first and last) and the out-of-zone
and TSIG-signed refusals are covered by the `src/transfer/axfr.zig` and
`src/transfer/xfr_tls.zig` unit tests instead.

## NSEC3 oracle rerun

```sh
python3 - <<'EOF'
import hashlib
def wire(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        lb = label.encode().lower()
        out += bytes([len(lb)]) + lb
    return out + b'\x00'
def nsec3(name, salt, iters):
    h = hashlib.sha1(wire(name) + salt).digest()
    for _ in range(iters):
        h = hashlib.sha1(h + salt).digest()
    return h.hex()
print(nsec3('example.', b'salt', 2))
print(nsec3('example.', b'', 0))
print(nsec3('www.example.', b'\xaa', 1))
EOF
```

Expected (also pinned in `src/dns/dnssec.zig`):

```text
76ed9c9f42b4c9122acfc75d39d96e8d566a14d0
1db8efa7dcb348bda7893fca1d8badfdb6996b01
8a854c07f2242e7c6cc556a4fa83d3c9c68d6903
```
