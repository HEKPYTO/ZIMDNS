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

The resolver also *speaks* DoT as a client: a `forwarder <address>:853 tls
<name>` configuration sends every upstream query, including the DS and DNSKEY
chain fetches it needs to validate an answer, over one TLS connection
(`tls_client.zig`). The handshake offers the `dot` ALPN token and accepts a
server that negotiates none, refuses a server that selects a different token,
verifies the certificate against the platform trust store (or the
`forwarder-ca-file` bundle when the operator configured one) and the
operator's name, and never falls back to a cleartext exchange. Under
`ddr-client on` the same client is reused for a verified DDR designation: it
verifies the designating resolver's IP in the certificate's iPAddress SAN
with no SNI on the wire (RFC 9462 §6.3), and the DoH client gains the same
`postWithVerification` split for its DDR path.

A `forwarder <address>:443 doh <name> <path>` configuration speaks DoH as a
client (`doh_client.zig`): one RFC 8484 §4.1 POST per query with
`application/dns-message` on the request and required on the answer, a
content-length or chunked response body, and no cleartext fallback. It speaks
HTTP/1.1 with the `http/1.1` ALPN token, the same disclosed deviation the
serving side carries; a provider whose endpoint requires HTTP/2 answers with a
non-200 status and the hop fails closed.

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
pull an AXFR or IXFR over an encrypted session. A transfer is served only
for a zone an `allow-transfer` line grants; a zone with no matching entry
gets REFUSED. Section 7.3 recommends port
853; this build binds 1053 by default, like the other two encrypted
listeners, and an operator reaches 853 with a `listen dns dot
<address>:853` line.

DoH over HTTP/3 (RFC 9114) is served too: `--serve-doh3` terminates the QUIC handshake with the `h3` ALPN token (RFC 9114 section 3.1) and then maps the same RFC 8484 section 4.1/4.2 requests as the HTTP/1.1 port, answering with `application/dns-message` and `cache-control: max-age=<TTL>`. The port never answers cleartext DNS.

DNS-over-QUIC (RFC 9250) is served: `--serve-doq` terminates the QUIC
handshake with the `doq` ALPN token (RFC 9250 §4.2) over one UDP port and
then speaks RFC 9250 §4.1 framing: one client-initiated bidirectional
stream per query, carrying a single DNS message behind the same two-octet
length prefix as DNS-over-TCP. A second query on one stream (§4.3) and a
zero-length frame (§4.1) are protocol errors closed with
DOQ_PROTOCOL_ERROR (0x2). The IANA-registered DoQ port is 853/UDP; this
build binds 1053 by default like the other encrypted listeners, and an
operator reaches 853 with a `listen dns doq <address>:853` line. The port
never answers non-QUIC traffic: a cleartext DNS/UDP or DNS/TCP frame gets
no DNS answer.
Per-stream state for DoQ and DoH/3 is keyed by `{ connection, stream }` in
`stream_registry.zig`, shared by both handlers; closing a connection drops
every entry that connection owned, so stream ids never collide across
connections and dead connections leave no state behind.

## QUIC bounds

- ngtcp2 caps: 32 connections, 16 bidirectional streams per connection,
  advertised from the same constants (`MAX_CONNECTIONS`,
  `MAX_STREAMS_PER_CONN`). The advertised flow windows
  (`INITIAL_MAX_DATA` 1 MiB per connection, `INITIAL_MAX_STREAM_DATA_BIDI`
  128 KiB, `INITIAL_MAX_STREAM_DATA_UNI` 16 KiB) bound the bytes in
  flight. Worst case per QUIC port: 32 x (connection struct with its
  64 KiB chunk scratch and bounded pending queue + 1 MiB connection
  window + 16 x the larger handler stream state, DoQ parser ~64 KiB or
  DoH3 state ~133 KiB), which the `@sizeOf` budget test in `doh3.zig`
  holds under 150 MiB. Both QUIC ports (DoQ + DoH3) together stay under
  300 MiB.

The QUIC stack is ngtcp2 1.26.0 + nghttp3 1.19.0, vendored under
`third_party/` and compiled with the Zig C compiler, with the GnuTLS crypto
backend and system GnuTLS linked at build time. The migration from the
pure-Zig QUIC dependency was motivated by the X41/OSTIF 2025 audit of the
ngtcp2-family stack; neither the Zig integration nor the vendored versions
are independently audited. DoQ and DoH/3 are proven by the external interop
harness (`test/interop/harness.py`, aioquic client), not by in-process
drivers. This repository owns the operator's identity paths,
the `doq` ALPN token, the opt-in gate, and the RFC 9250 §4 framing.

The invariants that hold whichever transport is served: no cleartext on a
port the operator configured as encrypted, ALPN `dot` selected on a
strict-TLS transfer channel (RFC 9103 §7.1), TLS 1.3 or later on that
channel (RFC 9103 §7.2), and a fail-closed refusal when the transport
cannot be provided.

## The TLS-server dependency (decided)

Accepted 2026-11-05 by the owner: transport crypto comes from the
system OpenSSL 3.x (`ssl` + `crypto`, linked, never vendored), replacing the
former pinned `tls.zig` dependency, which is deleted. `src/transport/openssl_tls.zig`
owns the thin seam: one `SSL*` per connection directly on the nonblocking
socket fd (`SSL_set_fd`), an immutable shared read-only `SSL_CTX`, TLS 1.3
minimum, an ALPN select callback restricted to the transport's configured
token, and verification (`SSL_VERIFY_PEER` with `SSL_set1_host` for DNS
names, IP SAN via `X509_VERIFY_PARAM_set1_ip_asc` with no SNI for IP
literals) before any DNS byte. `SSL_ERROR_WANT_READ/WRITE` polls the fd
against one absolute deadline per iteration; expiry is typed, and fatal
errors close without sending close_notify. The ABI surface is the small
set in `src/transport/openssl_abi.zig` (hand-set `extern` declarations:
Zig 0.17 removed `@cImport`); OpenSSL >= 3.0 is required at configure time
and refused otherwise. This repository still owns the operator's identity
paths, the ALPN token, the opt-in gate, and the refusal of a transport
that has no listener. No test-only bypass exists outside tests: production
paths never set `insecure`.

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
token — was no longer true. It is now moot: the shipped stack is the system
OpenSSL 3.x described above, whose ALPN select callback restricts the
handshake to the transport's configured token.

- The standard library is not a source. Zig 0.17.0 ships
  `std.crypto.tls.Client` only: `std/crypto/tls/` holds `Client.zig` and no
  server, and `std/crypto/tls.zig` exports `Client` and no `Server`.
  Upstream issue ziglang/zig#14171 ("add std.crypto.tls.Server") is still
  open, its last comment is from March 2024, and the pull request it
  references (#19308) is closed and unmerged, so nothing upstream is in
  flight to deliver one.

## The earlier decision record (superseded 2026-11-05)

The tree once had no dependencies, and every path from `planned` to a
`supported` encrypted-transport row added one: a TLS server for DoT and DoH,
an HTTP/2 implementation for DoH as well (RFC 8484 §5.2 makes HTTP/2 the
minimum RECOMMENDED version; an HTTP/1.1-only DoH breaks no RFC but will not
interoperate with mainstream clients), and a QUIC stack for DoQ (RFC 9250,
which cannot be approximated by TCP plus TLS). The owner first chose one
pinned MIT TLS dependency, `tls.zig`; on 2026-11-05 that choice was
superseded by the system OpenSSL 3.x stack above, and the vendored `tls.zig`
dependency is deleted. The record of the options is kept here because the
reasons still hold for the transports that remain.

- (a) Pin one MIT TLS dependency (superseded): the cheapest credible path to
  a `supported` DoT row at the time. DoH adds 2–4 days on top of that with an
  HTTP/2 dependency (<https://github.com/dnsoa/zig-http2>, MIT,
  dependency-free, builds on Zig 0.17.0, but publishes no interop results),
  or 5–10 days if HTTP/2 is written in-tree.
- (b) Keep the tree dependency-free and accept that the encrypted-transport
  rows stay `planned` and DoQ stays out of scope. Closed: options (a) and
  then OpenSSL were chosen instead.
- (c) Hand-roll TLS in-tree. Not credible: handshake parsing is the attack
  surface, and the project would own the security fixes.

DoT and DoH run on the OpenSSL stack. DoQ (RFC 9250) and DoH/3 (RFC 9114)
run on the vendored ngtcp2 1.26.0 + nghttp3 1.19.0 stack with GnuTLS
described above.

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

## Oblivious DoH (RFC 9230) on both DoH channels

Both the HTTP/1.1 port (`doh.zig`) and the HTTP/3 port (`doh3.zig`) serve ODoH target behavior behind the same request mapping: a POST to `/dns-query` whose content-type is `application/oblivious-dns-message` is opened with `odoh.openQuery`, the inner DNS query is answered through the same `runtime.answerFromTcp` entry point (peer address, recursion policy, cookie check, and local zones all apply), and the answer is sealed with `odoh.sealResponse` and returned as 200 with content-type `application/oblivious-dns-message`. The crypto is the RFC 9230 section 9 mandatory suite: DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-128-GCM 0x0001. Status codes: 200 on a sealed answer, 401 on an unknown key id, 400 on a decrypt or padding failure, 404 when ODoH is requested but no target is configured (the resource is not served). GET with the ODoH media type is not a thing: the GET path is unchanged plain DoH. Plain DoH (`application/dns-message` GET/POST) is otherwise unchanged on both channels.
