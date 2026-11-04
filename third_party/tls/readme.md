# Vendored tls.zig

Upstream: https://github.com/ianic/tls.zig (Zig TLS library, MIT licensed),
pinned at commit bd22bcb73f423389441a1de80bf031ef1b623cce. The tree under
`src/` (plus `build.zig`, `build.zig.zon`, `readme.md`) is a verbatim copy of
the upstream release at that commit; see `readme.md` for the upstream
documentation.

One patch is applied relative to upstream, in `src/handshake_client.zig`:
the client options gained an optional `sni` field (`?[]const u8`, default
`null`). Certificate verification keeps using `host`; the ClientHello
`server_name` extension uses `sni orelse host`. This lets the client verify
a certificate against one host (for example an IP literal) while sending a
different SNI value, or no SNI at all. When `sni` is null the behavior is
unchanged from upstream.
