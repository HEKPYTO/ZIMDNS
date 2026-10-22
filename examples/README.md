# examples

Configuration and zone files that the test suite and the README use.

| Path | Holds |
|---|---|
| `config.gdns` | A configuration with the directives the README documents. |
| `local-zones.gdns` | Locally served zones that are not loaded from files. |
| `zones/` | The primary zones used by the golden and integration tests. |
| `dnssec/` | A signed zone, its key material, and a configuration that loads it. |
| `blocklists/` | The blocked-name list. |

## Rules

- Every file here is a working input. Nothing in this directory is illustrative.
- A zone with DNSSEC material carries the key that signs it. The anchor that
  validates it belongs to the operator's trust-anchor file, not to this folder.
