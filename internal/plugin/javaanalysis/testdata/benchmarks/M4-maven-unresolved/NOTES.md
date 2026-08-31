# M4 maven-unresolved — the negative control

This project declares three shapes the resolver must keep distinct:

| coordinate | shape | expected inventory verdict |
|---|---|---|
| `com.ferralon.absent:env-gated-lib:${env.FERRALON_MISSING_VERSION}` | `${env.*}`-gated version, env unset | honest-absent (declared, version unresolvable) |
| `com.ferralon.absent:ghost-managed-lib` (version via missing `ghost-bom`) | BOM-cache-miss | honest-absent (declared, no managed version) |

The RESOLVED-vs-honest-absent distinction is cross-fixture: M1/M3 resolve cleanly;
M4 declares only unresolvable shapes. Maven's native tool aborts the whole model
rather than emit a partial tree — the resolver's job is to read the on-disk POM +
(empty) cache slice and emit honest-absent where Maven aborts.

**Negative control (genuinely-absent):** `com.ferralon.absent:never-declared-lib`
appears in NO manifest anywhere. The resolver must NOT emit it — proving that
honest-absent (declared-but-unresolvable) is distinct from absent (never declared).
There is deliberately no fixture artifact for it; its correctness is "does not appear."

The committed `native.tree.txt` is the native tool's faithful (non-zero-exit)
report of what it could and could not resolve — the honest-absent oracle.
