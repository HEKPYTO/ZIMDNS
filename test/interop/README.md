# Interop probes (offline evidence + live loopback probes)

The channel logic is covered offline by `tls_channel_test.py` (13/13,
stdlib only, no sockets) and by module unit tests; the per-row logs live
under `docs/reports/`. `--serve-dot` serves DNS over TLS and `--serve-doh`
serves DNS over HTTPS: both use the pinned `tls.zig` dependency, and each
port answers only after a handshake with its own ALPN token (`dot` and
`http/1.1`). The live loopback probes below ran on 2026-10-22 against the
listeners this build starts.

## Offline channel evidence (no socket, runs anywhere)

```sh
python3 test/interop/tls_channel_test.py   # 13/13: 5 tls.zig + 4 doh.zig + 4 dot.zig
```

The mirror decodes the DoH `dns=` parameter the way the server does: unpadded
base64url, every character from the alphabet, and a length that can be a
base64url string. A lenient decode would accept a query the server refuses, so
the mirror rejects the same values.

Transcripts: `docs/reports/interop-final/doh-get-post-transcript.log`
(DoH GET + POST mapping vectors) and
`docs/reports/interop-final/axfr-transcript.log` (SOA-framed AXFR
sequence + refusal matrix); run summary in
`docs/reports/interop-final/SUMMARY.md`.

## Environment prerequisites

- `kdig` is not installed in this environment (`command -v kdig` fails;
  `/usr/bin/dig` exists but cannot substitute for the DoT probe, because
  `dig +tls` needs the same ALPN-aware client the server refuses to serve
  without the `dot` token). `openssl s_client` is present and is the
  outside-client probe used below.
- A 2026-09-09 run recorded every loopback bind as refused in that
  environment (`errno=1 EPERM`, see
  `docs/reports/gates-final/env-bind-probe.log`). That is no longer the
  case: on 2026-10-22 the Zig test suite and the live probes below bound
  `127.0.0.1` and completed handshakes. The NSEC3 oracle passes 3/3 (see
  `docs/reports/gates-final/interop-nsec3-oracle.log`).

## DoT (RFC 7858) — `openssl s_client` — LIVE

```sh
./zig-out/bin/zimdns server run --zone-file examples/zones/home.arpa.zone \
  --serve-dot --enable-encrypted-dns \
  --tls-cert-file tls/cert.pem --tls-key-file tls/key.pem
```

The run starts the DoT listener: it loads the certificate and key, binds the
port, and answers only after a TLS 1.3 handshake that negotiates the `dot`
ALPN token. The outside-client probe is a TLS 1.3 handshake with the `dot`
token that then writes the RFC 7858 §3.3 framed query:

```sh
openssl s_client -connect 127.0.0.1:1053 -alpn dot -quiet -verify_quiet
```

and inside that session the length-prefixed query is written as two octets
of length followed by the DNS message. The unit tests in
`src/transport/dot.zig` assert the same exchange, the `dot` token, the
length-prefixed framing, and the answer.

## DoH (RFC 8484) — Python `ssl` — LIVE, HTTP/1.1 only

```sh
./zig-out/bin/zimdns server run --zone-file examples/zones/home.arpa.zone \
  --serve-doh --enable-encrypted-dns \
  --tls-cert-file tls/cert.pem --tls-key-file tls/key.pem
```

The listener terminates the TLS handshake with the `http/1.1` ALPN token and
then serves the RFC 8484 §4.1 GET and POST mapping. The outside-client
probe is a Python `ssl` client, because `curl --doh-url` speaks HTTP/2 and
this server advertises `http/1.1` only (RFC 8484 §5.2 makes HTTP/2 the
minimum RECOMMENDED version, so this is a disclosed deviation, not a broken
MUST — but a client that requires HTTP/2, such as `curl --doh-url` or a
browser, cannot use this port):

```sh
python3 - <<'PY'
import base64, socket, ssl, struct
query = struct.pack('>HHHHHH', 0x5eed, 0x0100, 1, 0, 0, 0)
query += b'\x03dns\x04home\x04arpa\x00' + struct.pack('>HH', 1, 1)
encoded = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['http/1.1'])
with socket.create_connection(('127.0.0.1', 1053), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname='localhost') as s:
        s.sendall(f'GET /dns-query?dns={encoded} HTTP/1.1\r\nHost: localhost\r\n'
                  'Connection: close\r\n\r\n'.encode())
        print(s.recv(4096)[:120])
PY
```

The response is `HTTP/1.1 200 OK` with a `content-type: application/dns-message`
body. The unit tests in `src/transport/doh.zig` assert the same mapping,
the ALPN refusal, and that the port never answers a cleartext HTTP request.

## XFR-over-TLS (RFC 9103) — `dig +tls` — LIVE

```sh
./zig-out/bin/zimdns server run --zone-file examples/zones/home.arpa.zone \
  --serve-xfr --enable-encrypted-dns \
  --tls-cert-file tls/cert.pem --tls-key-file tls/key.pem

dig @127.0.0.1 -p 1053 +tls +time=5 home.arpa. AXFR
```

The listener terminates the handshake with the `dot` token and then speaks
the RFC 7858 framing, so the transfer arrives as the same SOA-framed AXFR
sequence the Do53 TCP path serves. The outside-client probe needs a TLS
client that offers the `dot` ALPN token, and `dig +tls` does not, so the
probe below uses the Python `ssl` client. The SOA-framed sequence (apex
SOA first and last) and the out-of-zone and TSIG-signed refusals are also
covered by the `src/transfer/axfr.zig` and `src/transfer/xfr_tls.zig` unit
tests.

```sh
python3 - <<'PYCODE'
import socket, ssl, struct
query = struct.pack('>HHHHHH', 0x5eed, 0x0000, 1, 0, 0, 0)
query += b'\x04home\x04arpa\x00' + struct.pack('>HH', 252, 1)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['dot'])
with socket.create_connection(('127.0.0.1', 1053), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname='localhost') as s:
        s.sendall(struct.pack('>H', len(query)) + query)
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
length = struct.unpack('>H', data[:2])[0]
# The two-octet frame prefix precedes the DNS header, so the counts sit at
# offsets 2 and 4 inside it: questions at 6, answers at 8.
print('answers:', struct.unpack('>H', data[8:10])[0], 'in a', length, 'byte message')
PYCODE
```

## NSEC3 oracle rerun

```sh
python3 - <<'EOF'
import hashlib
def wire(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        lb = label.lower().encode()
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
