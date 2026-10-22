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
