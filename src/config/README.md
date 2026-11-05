# src/config

The configuration grammar and the loader that reads it.

| File | Owns |
|---|---|
| `parser.zig` | The directives, their arity, their ranges, and their defaults. |
| `loader.zig` | Reading a configuration file, resolving the files it names, and building the runtime settings. |

## Rules

- One format. A directive that carries a trailing token, carries an empty
  value, or repeats a directive that may appear once is
  `Error.BadDirective`; a directive the grammar does not know is
  `Error.UnknownDirective`. Neither is a warning and neither is a silent
  default.
- A file the configuration names must stay inside the configuration's own
  directory. A path that leaves it is `Error.InvalidReferencedPath`, and a
  file that is not there is `Error.MissingReferencedFile`.
- `forwarder <address>:<port>` sends recursion to that server in cleartext.
  `forwarder <address>:<port> tls <name>` sends it over DNS over TLS instead
  (RFC 7858): the name is both the SNI value and the name the server
  certificate must match, so it must be a DNS name and never an address
  literal. The port is the operator's, so a DoT forwarder names `853`
  explicitly; a server that negotiates no ALPN token is still accepted once
  its certificate verifies, because RFC 8310 section 8.1 makes the token a
  client request. A server that selects a different token is refused.
  `forwarder <address>:<port> doh <name> <path>` sends recursion over DNS
  over HTTPS (RFC 8484 POST, `application/dns-message`); the name is the SNI
  and certificate name and the path must start at the root. This client
  speaks HTTP/1.1, so a provider whose DoH endpoint requires HTTP/2 answers
  with a non-200 status and the hop fails closed.
- `forwarder-ca-file <path>` replaces the platform trust store for that
  forwarder's DoT and DoH certificate verification with one PEM bundle
  inside the configuration directory. Without it the platform store is used.
- `ddr-client on` (RFC 9462 §4) turns the plaintext forwarder into a DDR
  bootstrap: discovery queries `_dns.resolver.arpa.` over that plaintext
  channel, and a verified designation switches the resolver's own upstream
  to the designated DoT or DoH endpoint. It requires a plaintext `forwarder`
  and at least one `recursion allow` entry. The client supports the `dot`
  and `http/1.1` ALPNs and the `port` values 853 and 443; a designation that
  asks for anything else is ignored. `ddr-client-port <port>` (repeatable)
  adds an operator-authorized port to that set, for an endpoint that cannot
  use the registered ones; up to eight ports are accepted.
- `odoh-target on|off` (default off, RFC 9230) enables this server as an
  Oblivious DoH target. `odoh-key-file <path>` is required when on: 64 hex
  characters (32 bytes) with surrounding whitespace allowed. `odoh-config-out
  <path>` optionally writes the 46-byte `ObliviousDoHConfigs` at startup,
  atomically (temp file + rename in the same directory). Both paths stay
  confined to the configuration directory like every other loader path.
  Startup refuses: on without a key file; a malformed key; an unconfined key
  or config-out path; a key file set while the target is off (dead config
  misleads the operator). Rotation is the operator's action: replace the key
  file and restart. RFC 9230 §5 recommends daily rotation, not a MUST, so
  there is no background rotation timer.
