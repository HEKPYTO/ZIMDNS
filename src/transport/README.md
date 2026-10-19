# `src/transport` — encrypted-transport decisions

## Encrypted transport (fail-closed)

Accepted 2026-09-09 (amended 2026-10-05). DNS-layer behavior for DoT
(RFC 7858), DoH (RFC 8484, HTTP/1.1 mapping), and XoT (RFC 9103) runs on the
post-handshake byte channel, reusing the runtime answer path and TCP framing
bounds. No TLS/HTTP2/QUIC dependency is linked and no handshake code is
written here. `requireTlsServer` (`tls.zig`) fails closed: `--serve-dot`,
`--serve-doh`, `--serve-xfr` exit before binding. No encrypted transport is a
user-facing capability today.

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
