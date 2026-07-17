# Recall-gap closure — lot 2

**Date:** 2026-07-18  
**Status:** closed

Lot 2 reuses the shared, source-ordered unsafe-origin snapshots introduced by
the path-flow consolidation. The graph is computed once per function and is
parameterized by family policy; sinks decide which argument position is
dangerous.

## SQL injection

The SQL detector now inspects only argument zero of `execute`, `executemany`,
and `executescript`: the SQL expression, never the parameter tuple/dict. This
separation is essential because bound values are the safe channel.

It detects unsafe parameter origins through concatenation, percent formatting,
`.format`, f-strings, and local aliases when they reach that expression. It
does not infer an injection merely because a parameter occurs in a bound-value
tuple or as a key selecting a constant query from a mapping.

| Measure | Before SQL cluster | After SQL cluster |
|---|---:|---:|
| SQL variants | 2/4 | 4/4 |
| Overall variants | 23/36 | 25/36 |
| Benign-twin false positives | 0 | 0 |
| Precision corpus | 1.0 | 1.0 |

The two closed gaps are `str.format` and a one-hop query alias. The already
detected concat and percent-interpolation forms are retained as mechanism-
checked positives. Each requires `sql`, `execute`, and `interpolation` in the
finding description, so an incidental family match cannot inflate recall.

## Command injection

The command detector shares the same unsafe-origin engine but uses a different
sink policy. `os.system` and `os.popen` are shell sinks. For `subprocess`, the
detector requires a string-like command whose unsafe origin reaches argument
zero with literal `shell=True`. argv lists, constants, `shlex.quote(...)`, and
mapping-key selection of constant commands are explicit benign forms.

| Measure | Before command cluster | After command cluster |
|---|---:|---:|
| Command variants | 0/3 | 2/3 |
| Overall variants | 25/36 | 27/36 |
| Benign-twin false positives | 0 | 0 |
| Precision corpus | 1.0 | 1.0 |

`os.system("ls " + name)` and a local command alias flowing to
`subprocess.run(..., shell=True)` now carry sink-specific mechanism checks.
`shell=<variable>` remains an undecided MISS: resolving it needs a separate
constant-propagation policy.

This work also corrected FP-006. An argv-list call without `shell=True` is not
shell interpolation, so the canonical command fixture now uses an actual
string command with literal `shell=True`. The original argv form is covered by
the benign corpus rather than retained as a false positive to preserve a
metric.
