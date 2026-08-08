# last 60d java high critical

Precomputed `-advisory-corpus` root: advisories **published within the last 60d** of the snapshot's latest data (t0 = 2026-08-07T17:16:13+00:00), ecosystem = **java**, severity = **critical/high**.

Severity is the OSV `database_specific.severity` label; records without one are `unspecified` and are excluded from a severity-scoped policy rather than guessed. Windows key on the advisory's OSV **published** date.

Java (Maven) advisories **are** present in the corpus, but the symbol-enrichment pass extracted essentially no Java symbols — so this policy scans on the version axis only (`undetermined` rather than a reachability verdict). It is committed to show the language is covered, not omitted.
