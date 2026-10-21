# `src/dns` — DNS message, crypto, and validation decisions

## TSIG cryptography (RFC 8945)

Use the Zig standard library for raw-wire TSIG over the RFC 8945 section 6
HMAC-SHA family (HMAC-SHA1, SHA-224, SHA-256, SHA-384, SHA-512): wire
parsing, MAC construction, verification, request/response chaining,
strict key-file loading, ordinary authoritative query authentication, and
response signing. No third-party crypto dependency — the tree already uses
stdlib HMAC and timing-safe comparison for DNS Cookies. Secrets are cleared
at keyring deinit and never logged. Accepted 2026-08-20; re-check stdlib
crypto APIs at each compiler bump.

## TSIG vectors

Fixed SHA-256, chained, altered-intermediary-ID, and SHA-1 known-answer
vectors are reproduced independently in `src/dns/tsig.zig` tests, together
with the SHA-224, SHA-384, and SHA-512 answers of the same request. See
that file for the packets.

## DNSSEC deferral — current status

Accepted 2026-09-09 for the authoritative-serving-minimum profile; partially
superseded 2026-10-19. What landed since: zone signing (`dnssec-key-file`,
`src/zone/signer.zig`), chain validation on the forwarding path
(`trust-anchor-file`, `src/dns/validate.zig`, AD on secure / SERVFAIL+EDE on
bogus / EDE on an insecure answer that says why it is insecure), and a static
trust-anchor store (`Anchors.parse`). Still deferred:
iterative recursion, root priming, RFC 5011 automated rollover, KSK/ZSK
rollover tooling. Matrix rows 77/91/96 describe the shipped split.
