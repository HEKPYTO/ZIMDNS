# src/transfer

The transfer side of the server: how a zone leaves this server.

| File | Owns |
|---|---|
| `axfr.zig` | The RFC 5936 answer sequence: the apex SOA first, every zone record once, the apex SOA last, each message inside the 64 KiB framing bound. |
| `xfr_tls.zig` | The same sequences over the RFC 9103 strict-TLS transfer channel. |

## Rules

- The transfer channel is TLS 1.3 with the `dot` ALPN token, and it uses the
  RFC 7858 two-octet framing. It never falls back to cleartext.
- A transfer query for a zone this server does not serve is refused, and a
  signed transfer is served with the chained signed sequence the cleartext
  path serves.
- The size of a message is estimated while its records are added and measured
  exactly once the estimate nears the limit. A record that would not fit
  starts the next message.
