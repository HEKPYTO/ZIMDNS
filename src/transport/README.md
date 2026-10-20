# `src/transport` — encrypted-transport decisions

## Encrypted transport (fail-closed)

Accepted 2026-09-09 (amended 2026-10-05). DNS-layer behavior for DoT
(RFC 7858), DoH (RFC 8484, HTTP/1.1 mapping), and XoT (RFC 9103) runs on the
post-handshake byte channel, reusing the runtime answer path and TCP framing
bounds. `requireTlsServer` (`tls.zig`) fails closed: `--serve-dot`,
`--serve-doh`, `--serve-xfr` exit before binding. No encrypted transport is a
user-facing capability today. No TLS, HTTP/2, or QUIC code is in the tree and
`build.zig.zon` lists no dependency; whether one is added is the open
decision below.

The invariants hold whichever way that decision goes: no cleartext on a port
the operator configured as encrypted, ALPN `dot` selected on a strict-TLS
transfer channel (RFC 9103 §7.1), TLS 1.3 or later on that channel (RFC 9103
§7.2), and a fail-closed refusal when the transport cannot be provided.

## TLS-server dependency

Accepted 2026-10-05: add no TLS-server dependency on the old 0.16 baseline
(the only pure-Zig 0.16 server pin cannot select any ALPN token, failing
RFC 9103 §7.1). Recommended path: Zig 0.17 baseline (done) + `tls.zig`
(pinned commit) in the change that opens the gate. Reaching `supported`
needs: pinned dep, handshake-before-parse accept loop, `dot`-token test,
TLS-1.3-on-transfer test, loopback `openssl s_client`/`kdig`/`curl` interop.
DoH additionally needs HTTP/2 (RFC 8484 §5.2). ALPN note: the `dot` token
comes from the IANA registry (ref RFC 7858), not RFC 7858 §3.1; RFC 9103
§§7.1–7.2 scope to transfers.

### The ALPN objection no longer holds (re-checked 2026-10-21)

The reason given on 2026-10-05 — that no pure-Zig server can select an ALPN
token — is no longer true. What did not change is the fail-closed gate: no
dependency is linked, so the encrypted listeners still refuse to start.

- The standard library is not a source. Zig 0.17.0 ships
  `std.crypto.tls.Client` only: `std/crypto/tls/` holds `Client.zig` and no
  server, and `std/crypto/tls.zig` exports `Client` and no `Server`.
  Upstream issue ziglang/zig#14171 ("add std.crypto.tls.Server") is still
  open, its last comment is from March 2024, and the pull request it
  references (#19308) is closed and unmerged, so nothing upstream is in
  flight to deliver one.
- A pure-Zig TLS 1.3 server with server-side ALPN does exist for Zig 0.17.0.
  `tls.zig` (<https://github.com/ianic/tls.zig>, MIT) declares
  `.minimum_zig_version = "0.17.0"`, and its server handshake picks the ALPN
  token by server preference (RFC 7301) and refuses a client that offers no
  common token. Checked 2026-10-21 at commit `bd22bcb73f`: it builds on Zig
  0.17.0 and its test suite passes; a scratch server offering only `dot`
  negotiated TLS 1.3 and ALPN `dot` with `openssl s_client -alpn dot`, a
  client offering only `h2` was refused with TLS alert 120 (no application
  protocol), and a TLS 1.2 client was refused, so the RFC 9103 §7.2 floor
  holds by default. A second MIT server with TLS 1.2 and 1.3
  (<https://github.com/zig-utils/zig-tls>) also builds on Zig 0.17.0.

## Open decision (pending the owner): the project's first dependency

The tree has no dependencies today, and every path from `planned` to a
`supported` encrypted-transport row adds one: a TLS server for DoT and DoH,
an HTTP/2 implementation for DoH as well (RFC 8484 §5.2 makes HTTP/2 the
minimum RECOMMENDED version; an HTTP/1.1-only DoH breaks no RFC but will not
interoperate with mainstream clients), and a QUIC stack for DoQ (RFC 9250,
which cannot be approximated by TCP plus TLS). Adding the project's first
dependency is the owner's call, so the options are stated here and none is
chosen.

- (a) Pin one MIT TLS dependency: the cheapest credible path to a
  `supported` DoT row. The candidate the evidence supports is `tls.zig`
  (<https://github.com/ianic/tls.zig>) at a pinned commit. A 2026-10-21
  survey put DoT at 16–30 hours, most of it refactoring the transport layer
  from file-descriptor I/O to a byte channel, because socket deadlines have
  no meaning over a TLS socket. DoH adds 2–4 days on top of that with an
  HTTP/2 dependency (<https://github.com/dnsoa/zig-http2>, MIT,
  dependency-free, builds on Zig 0.17.0, but publishes no interop results),
  or 5–10 days if HTTP/2 is written in-tree. DoQ is 1.5–3 weeks on a
  pure-Zig QUIC stack (<https://github.com/ericsssan/zquic>, MIT,
  dependency-free, with its own TLS 1.3 and ALPN) plus RFC 9250 framing and
  interop.
- (b) Keep the tree dependency-free and accept that the encrypted-transport
  rows stay `planned`, DoQ stays out of scope, and the state in the first
  section above stands.
- (c) Hand-roll TLS in-tree. Not credible: handshake parsing is the attack
  surface, and the project would own the security fixes.

No option is recorded as chosen. The owner decides, and this record is
updated when the decision is made.
