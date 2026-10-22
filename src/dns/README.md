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

## Report-Channel (RFC 9567)

`src/dns/error_report.zig` holds the RFC 9567 report channel: the option code
lives with the other EDNS(0) codes in `src/dns/rdata.zig` (option code 18),
and the module builds the two values the option needs. The option payload is
the agent domain in uncompressed wire form, and the report query name is the
`_er` label, the QTYPE as a decimal label, the labels of the name that
failed, the extended DNS error code as a decimal label, the `_er` label
again, and the agent domain. A payload is parsed as its own buffer, so a
compression pointer can never reach outside it, and a payload that is not
exactly one name is refused. The module allocates nothing: a name is an
inline fixed-size value, so the answer policy that carries the agent domain
owns no memory for it.

The authoritative answer path (`src/auth/response.zig`) advertises the
channel: the option is added once to the OPT record of an authoritative
answer, whether or not the query asked for it. A refusal, a FORMERR, a
referral, and every other answer the server builds without the operator's
policy carry none. The root domain is never advertised (§4), and an agent
domain that is a subdomain of the zone the server reports on is left out of
that zone's answers (§8.1). The two names are compared on label boundaries,
so "xfoo.example." is not taken for a subdomain of "foo.example.".

## DNSSEC deferral — current status

Accepted 2026-09-09 for the authoritative-serving-minimum profile; partially
superseded 2026-10-19. What landed since: zone signing (`dnssec-key-file`,
`src/zone/signer.zig`), chain validation on the forwarding path
(`trust-anchor-file`, `src/dns/validate.zig`, AD on secure / SERVFAIL+EDE on
bogus / EDE on an insecure answer that says why it is insecure), and a static
trust-anchor store (`Anchors.parse`). Still deferred:
iterative recursion, root priming, RFC 5011 automated rollover, KSK/ZSK
rollover tooling. Matrix rows 77/91/96 describe the shipped split.
