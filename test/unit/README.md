# test/unit

The unit group. `zig build test` runs it.

The group is two things: the tests embedded in `src/`, which the main test
artifact carries, and the roots in this directory. The embedded tests cover the
message encoder and decoder, name handling and comparison, the record types,
the EDNS options, the TSIG MAC, the signer, the validator, the cache, and the
configuration parser. The roots here are the cases that need their own file:
the host-name syntax, the RFC 2181 name-server rules, the typed SSHFP and
TLSA records, the SHA-512 TSIG runtime, and the ZONEMD publisher.

## Rules

- A test names the rule it protects, so a failure says which rule broke.
- A test that repeats the implementation earns nothing and is deleted.
- An embedded test may bind a loopback socket or read a file when the rule it
  protects needs one. A test that talks to another host belongs nowhere in
  this tree.
