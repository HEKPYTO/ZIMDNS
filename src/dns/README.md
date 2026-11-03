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

## Monitoring agent (RFC 9567)

The other side of the same RFC is the monitoring agent: the server that
hosts the agent domain a reporting resolver sends its error reports to. The
`error-report-monitor <domain>` directive names that domain, and the answer
policy (`src/auth/response.zig`) carries it as an inline name, so the policy
owns no memory for it. A query name is at or below the monitored domain when
the domain's wire form is a label-aligned suffix of the query name's wire
form, which is the same label-by-label test the Report-Channel option uses
for §8.1.

A name the zone does not have but that is at or below the monitored domain
is answered by the monitoring agent and never with a name error (§8.2): a
report-shaped name — one the report-channel module recognizes with
`isReportName` — is answered positively with one synthesized TXT record at
the queried name, a TTL of 60 seconds, and the text `RFC 9567 error report`,
because the report itself is in the query name (§6.3). Any other name at or
below the domain is answered with no data and the zone's SOA in the
authority section, so the negative answer is cacheable with the zone's own
negative TTL. The answer that is no longer a denial keeps no denial proof,
and the synthesized TXT record is not in the zone, so it carries no RRSIG:
the monitored domain belongs in an unsigned zone, as §8.2 recommends, so the
reporting resolver is never asked to validate an answer it has no use for. A
monitored answer carries the truncation bit when the query arrived over UDP
and carried no DNS Cookie (§6.3), so the reporting resolver requeries over
TCP.

## DNSSEC deferral — current status

Accepted 2026-09-09 for the authoritative-serving-minimum profile; partially
superseded 2026-10-19 and 2026-11-03. What landed since: zone signing
(`dnssec-key-file`, `src/zone/signer.zig`), chain validation on the forwarding
and iterative paths (`trust-anchor-file`, `src/dns/validate.zig`, AD on secure /
SERVFAIL+EDE on bogus / EDE on an insecure answer that says why it is insecure),
and a static trust-anchor store (`Anchors.parse`). The child-side half of the
RFC 6781 §4.1.2 key-signing key rollover landed with it (`dnssec-new-ksk-file`;
see `src/zone/README.md`), and with it the revoke phase of §4.1.2.1
(`dnssec-new-ksk-file <path> revoked`), which publishes the key being removed
with the RFC 5011 §3 REVOKE bit set. Iterative recursion from the built-in root
hints lives in `src/iterate.zig` and runs when `recursion allow` is configured
without a `forwarder`; its hops carry DO=1 and validate through the DS/DNSKEY
chain up to the configured anchor. Root priming is implemented (RFC 9609 §2):
the walk primes the root with the `. NS` query and reuses the addresses until
their TTL expires, falling back to the built-in hints. Still deferred by decision
or open work: RFC 5011 automated anchor rollover (the operator's anchor file is
the trust configuration), the parent-side half of a key-signing key rollover,
and the zone-signing key rollover tooling. Matrix rows 51, 91, 92, 117, and 126
describe the shipped split.
