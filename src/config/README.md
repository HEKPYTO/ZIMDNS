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
