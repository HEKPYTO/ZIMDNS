# `src/zone` — zone loading, signing, and transfer

## The signing roles (RFC 6781 §3.1)

A zone is signed at startup by the key `dnssec-key-file` names, and that key
signs every RRset. A zone that separates the roles names a second key with
`dnssec-ksk-file`: the key-signing key carries the Secure Entry Point flag
(257), the DS the zone publishes states it, and it signs the DNSKEY RRset and
nothing else. The zone-signing key then carries the Zone Key flag alone
(256) and signs every other RRset.

`src/zone/signer.zig` holds the signer; `src/config/loader.zig` reads the
key files and hands the keys over; `src/config/parser.zig` knows the
directives.

## The key file

One `<algorithm> <secret>` line per key. `ECDSAP256SHA256`, `ECDSAP384SHA384`,
and `ED25519` take the raw private scalar or seed in base64; `ED448` takes
the raw 57-octet secret in base64. `RSASHA256` and
`RSASHA512` take a base64 PKCS#1 `RSAPrivateKey` DER, which an operator makes
with `openssl rsa -traditional -outform DER | base64`; the signature is one
modular exponentiation and the primes are not needed. RSA/SHA-1 (algorithms 5
and 7) is not offered because the IANA "DNS Security Algorithm Numbers"
registry, as revised by RFC 9904, marks it NOT RECOMMENDED under "Implement
for DNSSEC Signing".

## The catalog zone's shape (RFC 9432)

`src/zone/catalog.zig` is the one reader of a catalog zone's fixed shape: the
schema-2 `version.<apex>` TXT RRset (exactly one record, value `"2"`) and the
`<label>.zones.<apex>` PTR records that name the member zones. It refuses a
catalog that lists itself or names the same member twice, and returns the
member names it finds. `src/config/loader.zig` uses it at startup and
`src/auth/runtime.zig` uses it again when a NOTIFY for the catalog asks for a
new read, so the two paths cannot disagree about what a valid catalog is.

## The NSEC3 chain (RFC 9276 §3.1)

The chain is opt-in: the zone's own apex NSEC3PARAM decides it, and the
`dnssec-chain` directive names the chain instead. The chain this server
publishes is unsalted. RFC 9276 §3.1 says "Operators SHOULD NOT use a salt by
indicating a zero-length salt value instead (represented as a '-' in the
presentation format)", and the parameters it recommends are SHA-1, no extra
iterations, and an empty salt, so the signer refuses a chain that names a
salt:

- a `dnssec-chain nsec3 <iterations> <salt>` directive whose salt is not `-`
  is refused while the configuration is parsed, with `Error.BadDirective`, so
  a configuration that names a salt never starts;
- a zone whose own apex NSEC3PARAM states a salt is refused when the zone is
  signed, with `Error.InsecureChainParameters` — the same error a chain with
  an iteration count above zero is refused with, because RFC 9276 §3.1 asks
  for a count of zero and a validator treats the answer such a chain proves
  as insecure (RFC 9276 §3.2).

What the server publishes is therefore always SHA-1 with no extra iteration
and no salt. The validator is a separate path and is not touched by this: a
chain another publisher signed with a salt is still validated as it was.

## The child-side key-signing key rollover (RFC 6781 §4.1.2)

RFC 6781 is an Informational memo — its own Status of This Memo says "This
document is not an Internet Standards Track specification; it is published
for informational purposes." What follows is prescribed practice, not a
Standards Track requirement, and nothing here is a MUST or a SHOULD of any
RFC.

The scheme implemented is the Double-Signature one: during the overlap the
zone publishes **two** key-signing keys and signs its DNSKEY RRset with
both, while the parent keeps **one** DS. The old key set and the new key set
can therefore both verify the apex key set, which is what §4.1.2 asks a
Double-Signature scheme to guarantee.

### The four stages of Figure 4, and the revoke phase of §4.1.2.1

| Figure 4 stage | configuration | at the parent |
| --- | --- | --- |
| initial | `dnssec-key-file zsk.key`, `dnssec-ksk-file k1.key` | the DS states k1 |
| new DNSKEY | `dnssec-key-file zsk.key`, `dnssec-ksk-file k1.key`, `dnssec-new-ksk-file k2.key` | the DS still states k1 |
| DS change | `dnssec-key-file zsk.key`, `dnssec-ksk-file k2.key`, `dnssec-new-ksk-file k1.key` | the DS is replaced with the one for k2 |
| revoke (§4.1.2.1) | `dnssec-key-file zsk.key`, `dnssec-ksk-file k2.key`, `dnssec-new-ksk-file k1.key revoked` | the DS states k2 |
| DNSKEY removal | `dnssec-key-file zsk.key`, `dnssec-ksk-file k2.key` | the DS states k2 |

The operator drives the stages by swapping the two key files between the two
directives. The zone-signing key never changes during a key-signing key
rollover, so `dnssec-key-file` stays as it is.

The word `revoked` after the second key's path marks that key as the one
being removed: it is the key the parent no longer points at, and the server
publishes it with the RFC 5011 §3 REVOKE bit set.

### What the server does

- publishes the apex DNSKEY RRset with the zone-signing key (flags 256) and
  both key-signing keys (flags 257);
- signs that DNSKEY RRset once per key-signing key: two RRSIGs over one
  RRset, each with its own key's key tag, which RFC 4034 §3.1.3 allows;
- signs every other RRset with the zone-signing key alone;
- publishes exactly one DS, for the key `dnssec-ksk-file` names — the
  Double-Signature scheme, not the Double-DS one;
- publishes a key marked `revoked` with the RFC 5011 §3 REVOKE bit set
  (flags 385), keeps signing the DNSKEY RRset with it so the revocation is
  self-signed as RFC 6781 §4.1.2.1 asks, and publishes no DS for it: RFC
  5011 §2.1 notes that a DNSKEY with the REVOKE bit set has a different
  fingerprint, so it no longer matches a DS that names it;
- claims the second key for the zone, so the RFC 8080 §8 rule that one key
  signs one zone still holds, and wipes its material when the key is
  released.

### What the server does not do

- the **TTL_DS wait**: §4.1.2 asks the zone administrator to wait at least
  the TTL of the DS RR before the parent's DS is changed. The server has no
  key-scheduling clock; it signs the zone when it loads and re-signs it on a
  reload. The wait is the operator's.
- the **parent-side DS edit**: the server reads no parent zone and changes no
  DS. The rollover is the child-side half only, and the parent-side change
  has to be made where the parent is served.
- the **one more Maximum Zone TTL**: §4.1.2.1 asks the revoked key to be
  published for one more Maximum Zone TTL before it is removed. The server
  has no clock and removes no key; the wait and the removal are the
  operator's.

### What the server refuses

Startup fails with `Error.BadDnssecKey` when the second key-signing key

- has no zone-signing key to sign the rest of the zone with, or no
  key-signing key for the DS to state;
- is the same key as the first key-signing key or as the zone-signing key,
  because the DNSKEY RRset would then hold the same record twice, and an
  RRset with a duplicate RR is not the RRset a signature covers;
- is in a file that is missing or does not parse, which every other key file
  is also refused for.

The DNSSEC key files are read at startup only, so a key change needs a
restart; a SIGHUP re-reads the zone file and re-signs it with the keys the
server already holds.

## Where the proof lives

- `src/zone/signer.zig`: "RFC 6781 section 4.1.2: a double-signature KSK
  rollover publishes both key-signing keys and signs the DNSKEY RRset with
  both" — the three published keys, the two signatures over the DNSKEY
  RRset, the one DS, and the project's own validator accepting the zone —
  and "RFC 6781 section 4.1.2.1: a revoked key-signing key is published with
  the REVOKE bit and still signs the DNSKEY RRset" — the revoked key's
  flags, its own signature over the RRset, the one DS, and the validator
  accepting the zone through that DS.
- `src/config/loader.zig`: "a zone with a second key-signing key publishes
  both DNSKEYs at the apex", "a revoked second key-signing key is published
  with the REVOKE bit", and one test per refusal above.
- `src/config/parser.zig`: "config parser accepts one DNSSEC new
  key-signing key-file path and no other shape", "config parser marks the
  second key-signing key as revoked with one word", and "config parser takes
  one signed chain and refuses every other shape" — the directive that names
  a salt refused, and the directive that names the empty one accepted with an
  empty salt.
- `src/zone/signer.zig`: "RFC 9276 section 3.1: the signer refuses an NSEC3
  chain that states a salt" — the zone whose apex NSEC3PARAM names a salt
  refused, the same zone with an empty salt signed, and the apex NSEC3PARAM
  the zone publishes stating the empty salt — and "RFC 9276 section 3.1: the
  signer refuses an NSEC3 chain whose iteration count is not 0".
