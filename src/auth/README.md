# src/auth

TSIG: request authentication and the responses that answer it.

| File | Owns |
|---|---|
| `keyring.zig` | The configured TSIG keys, their algorithms, and the signing helper that adds a TSIG record to a reply. |
| `response.zig` | The authoritative answers: the response sections, the EDNS options, the denial proofs, and the truncation of a signed reply. |
| `runtime.zig` | The request path that verifies a TSIG, applies the authenticated policy, and signs the reply with the key that authenticated the request. |

## Rules this directory implements

- RFC 8945 §5.2: the key, then the MAC, then the time window, then the
  truncation policy.
- A key file entry may carry an optional `expires YYYYMMDDHHMMSS;` (UTC, 14
  digits). At or after that second the key is inactive, and a request naming
  it is answered NOTAUTH with an unsigned BADKEY (17) record, the same answer
  an unknown key gets.
- A name may carry several algorithms. Every key holding the name is a
  candidate, the algorithm the request names selects one, and the key that
  authenticated the request signs the reply.
- The MAC primitives live in `src/dns/tsig.zig`. `verify` and `verifyChained`
  return the MAC exactly as it appears in the message, so a caller that chains
  on it uses the transmitted value.
- AXFR/IXFR is denied by default. `allow-transfer <apex> <cidr>` is
  repeatable for distinct zone/CIDR pairs and grants one zone to one client
  CIDR; both the cleartext TCP ingress and the strict-TLS transfer channel
  consult it, and a zone with no matching entry answers REFUSED before any
  transfer sequence is built. The decision runs under the shared lock; a
  non-shorter journal chain is drained under the exclusive lock after the
  read.
- A request copies its TSIG key under the keyring shared lock, so a SIGHUP
  key reload cannot clear the key mid-verify.
- At most four whole-zone transfers encode concurrently; the cap bounds the
  frame array plus the response blob.
