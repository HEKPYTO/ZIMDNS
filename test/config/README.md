# test/config

The configuration group. `zig build test-config` runs it.

Covers the grammar: arity, ranges, defaults, and every refusal the loader
owes an operator. The RFC 9567 report directives have their own roots here,
because their refusals are their own rule.

## Rules

- A refused configuration is a named error, never a warning and never a silent
  default.
- A directive that points outside the configuration's directory is refused.
