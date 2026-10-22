# `src/transport` — encrypted-transport decisions

## What is served

DNS-over-TLS (RFC 7858) is served: `--serve-dot` terminates a TLS 1.3
handshake with the `dot` ALPN token and then speaks the RFC 7858 §3.3
two-octet length-prefixed framing over that channel, reusing the runtime
answer path and the TCP framing bounds. The port never answers DNS in
cleartext: the handshake comes first, a client that offers no common ALPN
token is refused with the RFC 7301 no_application_protocol alert, and the
identity is loaded before the port is bound, so a broken certificate or key
refuses the run and leaves no port open.

DoH (RFC 8484) is served too: `--serve-doh` terminates a TLS 1.3 handshake
with the `http/1.1` ALPN token and then maps the RFC 8484 section 4.1 GET
and POST requests to DNS wire bytes, answering with `application/dns-message`.
RFC 8484 section 5.2 makes HTTP/2 the minimum RECOMMENDED version of HTTP
for DoH, so an HTTP/1.1-only server breaks no MUST of that document, but the
negotiated token is `http/1.1` and never `h2`, so a client that requires
HTTP/2 cannot use this port.

The port this build binds by default is 1053 for both encrypted listeners,
not the IANA-registered 853 for DoT nor the HTTPS default 443 for DoH: the
default has to be unprivileged. An operator reaches the registered ports
with a `listen dns dot <address>:853` or `listen dns doh <address>:443`
line.

The strict-TLS transfer channel (RFC 9103) is served: `--serve-xfr`
terminates a TLS 1.3 handshake with the `dot` token, as section 7.1 requires,
and then speaks the RFC 7858 framing over that channel, so a secondary can
pull an AXFR or IXFR over an encrypted session. Section 7.3 recommends port
853; this build binds 1053 by default, like the other two encrypted
listeners, and an operator reaches 853 with a `listen dns dot
<address>:853` line, the same endpoint the DoT port uses. DoQ (RFC 9250) is deferred with a typed error.

The invariants that hold whichever transport is served: no cleartext on a
port the operator configured as encrypted, ALPN `dot` selected on a
strict-TLS transfer channel (RFC 9103 §7.1), TLS 1.3 or later on that
channel (RFC 9103 §7.2), and a fail-closed refusal when the transport
cannot be provided.

One limit of the pinned dependency is recorded in the code: the standard
library's DER parser aborts the process on a truncated length field, and the
dependency calls that parser directly, so a certificate whose DER is
truncated ends the run with a stack trace rather than a typed error. The
port is not bound either way, so nothing is served in the clear.

## The TLS-server dependency (decided)

Accepted 2026-10-22 by the owner: the project's first dependency is
`tls.zig` (<https://github.com/ianic/tls.zig>, MIT), pinned to commit
`bd22bcb73f423389441a1de80bf031ef1b623cce` in `build.zig.zon` with the
package hash `tls-0.1.0-ER2e0l6qBgDEYo6RBkVZw5UrxOqtI6-OqLwyFJvEr3RK`.
The handshake comes from that dependency; this repository owns the
operator's identity paths, the ALPN token, the opt-in gate, and the
refusal of a transport that has no listener. The dependency is fetched
into `zig-pkg/`, which is not tracked.

## What the DoT slice still owes

Reaching `supported` for the DoT row needs: the pinned dependency (done),
a handshake-before-parse accept loop (done), a `dot`-token test (done), and
loopback interop with an outside client (`openssl s_client`, `kdig`) — the
interop run is still open. The RFC 9103 §7.2 TLS 1.3 floor applies to the
strict-TLS transfer channel, so the transfer row stays `partial` until
that channel exists. DoH is served over HTTP/1.1 (RFC 8484 §5.2 makes HTTP/2 the minimum RECOMMENDED version, so this is a disclosed deviation and not a broken MUST). ALPN
note: the `dot` token comes from the IANA registry (ref RFC 7858), not
RFC 7858 §3.1; RFC 9103 §§7.1–7.2 scope to transfers.

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

## The decision that was open (resolved 2026-10-22)

The tree had no dependencies, and every path from `planned` to a
`supported` encrypted-transport row adds one: a TLS server for DoT and DoH,
an HTTP/2 implementation for DoH as well (RFC 8484 §5.2 makes HTTP/2 the
minimum RECOMMENDED version; an HTTP/1.1-only DoH breaks no RFC but will not
interoperate with mainstream clients), and a QUIC stack for DoQ (RFC 9250,
which cannot be approximated by TCP plus TLS). The owner chose option (a):
one pinned MIT TLS dependency, `tls.zig`. The record of the options is kept
here because the reasons still hold for the transports that remain.

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

Option (a) is chosen and implemented; the other two are closed. DoT and DoH
now run on it. The next dependency question is the same shape: DoQ needs a
QUIC stack.

## The bounds the encrypted ports hold

The three encrypted listeners — DoT, DoH, and the RFC 9103 strict-TLS
transfer channel — share one channel helper, `src/transport/channel.zig`,
so their bounds cannot drift apart. A connection is bounded by the
operator's `tcp-max-connection-duration` and every frame runs under one
absolute deadline on the raw descriptor under the TLS connection, never
under a socket timeout: a blocked read that hits `SO_RCVTIMEO` surfaces
as `EAGAIN`, which the threaded standard-library backend treats as a
fatal error and answers with a panic, so a stalled peer would take the
whole server down. The DoH channel adds one absolute deadline per
exchange on top of that, and the strict-TLS transfer channel applies the
same SIGHUP zone reload the cleartext paths apply.

Every encrypted listener also applies the per-client policy the cleartext
TCP listener applies: the peer address reaches the runtime, so the
recursion ACL and the DNS cookie check see the same client whichever
port the query arrived on.

## The request mapping the DoH channel refuses

RFC 9112 section 6.1 says a server must reject a request whose headers
disagree about the body. The DoH channel answers 400 to a request that
carries both a transfer coding and a content length, and to a request
that declares two different content lengths. A head over the 8192-octet
budget is answered 431, a body over the 65535-octet budget is answered
413, a POST whose media type is not `application/dns-message` is answered
415, and the last exchange of a connection carries `connection: close` so
the client does not reuse a connection the server is about to close.
