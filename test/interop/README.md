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
- `dnspython`: create a virtual environment once.

```sh
python3 -m venv .interop-venv
.interop-venv/bin/pip install dnspython
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
- DoH: `curl` GET and POST against the encrypted listener with a
  self-signed certificate.

The harness uses temporary directories and free ports; it does not modify the
repository.
