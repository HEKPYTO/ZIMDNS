# Interop probes (deferred)

These loopback interop probes are deferred until native TLS termination
lands (see `docs/decisions/encrypted-transport.md`). The channel logic
they exercise is covered now by module unit tests; the per-row logs live
under `docs/reports/`.

## DoT (RFC 7858) — `kdig`

```sh
zig build
./zig-out/bin/zimdns server run --zone-file examples/zones/home.arpa.zone \
  --serve-dot --enable-encrypted-dns \
  --tls-cert-file tls/cert.pem --tls-key-file tls/key.pem
kdig -d @127.0.0.1 +tls +tls-host=localhost example.com A
```

Expect the same answer section as the plaintext `zimdns query` output.

## DoH (RFC 8484) — `curl`

```sh
curl --doh-url https://localhost:443/dns-query --cacert tls/cert.pem \
  -H 'accept: application/dns-message' \
  'https://localhost/dns-query?dns=<base64url-wire-query>' -o resp.bin
```

Expect `content-type: application/dns-message` and a parseable wire
response matching the GET/POST mapping in `src/transport/doh.zig`.

## XFR-over-TLS (RFC 9103) — `dig` against BIND/Knot/NSD

```sh
dig @127.0.0.1 -p <xfr-port> +tls example. AXFR
```

Expect an SOA-framed sequence (apex SOA first and last) per
`src/transfer/axfr.zig`; plaintext-port AXFR must be REFUSED.

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
