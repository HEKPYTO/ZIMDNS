# External interop and differential-oracle suite

This directory proves behavior from outside the repository. Nothing here is
an in-repo unit test: the suite drives the built `zimdns` binary with BIND
(`dig`, `delv`, `nsupdate`, `named-checkzone`), Knot (`kdig`, `kzonecheck`),
ldns, curl, and compares authoritative answers against a BIND 9 authoritative
server that serves the same zone file.

## Requirements

- `zig build` produced `zig-out/bin/zimdns`.
- External tools on `PATH`: `dig`, `delv`, `named`, `named-checkzone`,
  `nsupdate`, `kdig`, `kzonecheck`, `ldns-verify-zone`, `curl`, `openssl`.
  macOS: `brew install bind knot ldns`.
- `dnspython`, `aioquic`, `pyhpke`, `cryptography`: create a virtual environment once. `aioquic` proves DoH/3, `pyhpke` (with `cryptography`) proves ODoH, and `cryptography` proves BIND RSA key conversion.

```sh
python3 -m venv .interop-venv
.interop-venv/bin/pip install dnspython aioquic pyhpke cryptography
.interop-venv/bin/python test/interop/harness.py --zimdns zig-out/bin/zimdns
```

Exit code 0 means every external check and every differential comparison
passed. A missing tool is a hard failure; the suite exists to produce external
evidence, not to skip when the evidence is unavailable.

## What runs

- Authoritative differential oracle: ZIMDNS and BIND 9 answer a corpus that
  covers positive answers, NXDOMAIN, NODATA, wildcard, CNAME, DNAME, a
  delegation referral with glue, and typed RDATA. Rcode, the AA/TC bits, the
  answer RRsets, and the negative proof/authority section must match exactly.
  This runs over UDP and TCP.
- External clients: `dig` and `kdig` over UDP and TCP, `dig AXFR` and
  `dig IXFR`, `named-checkzone` and `kzonecheck` over the transferred zone.
- DNSSEC algorithms: RSA/SHA-256, ECDSA P-384, and Ed25519 zones each
  pass `dnssec-verify` and `ldns-verify-zone`; the ECDSA zone carries a
  published ZONEMD that `ldns-verify-zone` checks.
- DoH: `curl` GET and POST against the encrypted listener with a
  self-signed certificate.
- Obsolete RDATA: a separate X25/ISDN zone is compared with BIND 9.
- CLI: the shipped `query` command answers the BIND oracle and refuses
  an unknown flag.
- Error reporting: an upstream EDE plus agent domain must produce the
  RFC 9567 report TXT query at the agent.
- Forged answers: wrong-ID and wrong-question upstream responses are
  ignored; the retry's real answer is served and the forged address is not.
- DNS64: `dig AAAA` through a forwarding resolver with `dns64 on` and a
  scripted A-only upstream synthesizes the RFC 6052 address.
- Catalog and blacklist: a producer/consumer pair serves a member zone over
  AXFR, and a blacklist zone answers listed entries with 127.0.0.2.
- Cache behavior: a TTL-1 answer goes stale when the upstream starts
  failing, is served with TTL 30 and EDE 3, and an SOA-backed NXDOMAIN is
  cached without a second upstream query.
- Truncation and header bits: a 512-octet UDP query with an 80-record A
  RRset gets TC, the TCP retry gets every record, CD is copied, and a
  two-question query is FORMERR.
- EDNS options: `dig +nsid`, `+cookie`, `+keepalive`, `+ednsopt=19`, and a
  UDP `ANY` (RFC 8482 minimal HINFO) against the authoritative listener.
- ECS: `dig +subnet` through a configured resolver reaches a scripted
  ECS-aware upstream with the trimmed source prefix, and the client sees the
  upstream's scope.
- DDR: a plaintext resolver designates a real DoT endpoint through
  `_dns.resolver.arpa.`; the client must verify the endpoint certificate
  against the designating resolver's IP SAN with no SNI before it upgrades,
  and the plaintext server has no zone for the test name, so only a verified
  upgrade answers.

The harness uses temporary directories and free ports; it does not modify the
repository.
