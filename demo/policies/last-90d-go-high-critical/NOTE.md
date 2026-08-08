# last 90d go high critical

Precomputed `-advisory-corpus` root: advisories **published within the last 90d** of the snapshot's latest data (t0 = 2026-08-07T17:16:13+00:00), ecosystem = **go**, severity = **critical/high**.

Severity is the OSV `database_specific.severity` label; records without one are `unspecified` and are excluded from a severity-scoped policy rather than guessed. Windows key on the advisory's OSV **published** date.

**This is the policy the top-level README demonstrates.** Go carries the deepest analyzer, and this slice provably surfaces symbol-bearing advisories, so a scan against it exercises the reachability stage rather than stopping at the version axis.
