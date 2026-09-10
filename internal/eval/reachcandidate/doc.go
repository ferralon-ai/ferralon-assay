// Package reachcandidate is the 50-CVE reachable-candidate precision/recall eval
// harness for affected-symbol and guard-symbol list completeness. It is a MEASUREMENT
// scaffold: it runs the real, deterministic Assess symbol-resolution + reachability stages
// over a fixture set and tabulates, per CVE, whether a candidate pair formed and whether the
// resolved sink is the correct (upstream-verified) fix-guarded symbol.
//
// It adds NO engine behavior. It only drives the already-wired consumer path
// (symbol_mapping → reachability_ingress) through exported stage constructors and reads
// back the artifacts those stages produce. Populating the corpus symbol lists is the
// upstream producer's job; this harness measures the effect of that populate and lets a
// caller diff a "corpus vN (partial)" run against a "corpus vN+1 (complete)" run for its
// before/after delta.
//
// # The symbol-form decision: resolve first
//
// The wire never specified whether the corpus `symbols`/`guard_symbols` arrays should
// carry SCIP-qualified symbol strings or bare, source-level package-path identifiers.
// This is the single highest-leverage thing to get right: a wrong form silently drops
// EVERY CVE (an unresolved sink → no candidate pair → the CVE fails open, invisibly).
//
// DECISION: the corpus carries **bare, source-level (DisplayName-form) identifiers**,
// NOT SCIP-qualified strings.
//
// This is not a preference — it is what the resolver actually matches. Every language's
// ResolveDependencySymbols (ferralon-assay/plugin/{go,java,js,python,dotnet}analysis) matches
// each advisory identifier against the symbol's `DisplayName` (a human-readable,
// language-native qualified name) and its dotted-suffix / last-dot-leaf forms,
// arity-tolerant — it NEVER matches against `sym.SCIP`. Concretely, the accepted forms are:
//
//   - Go     : "(*Service).Handle", "language.Parse", "main.fetchHandler", or bare "Parse"
//     (matchesAdvisorySymbol, goanalysis/packages.go:389). The PURL package
//     (pkg:golang/<import-path>) scopes the match separately, so a
//     package-qualified-or-leaf identifier is sufficient.
//   - Java   : "com.example.web.UrlFetcher.fetch" or bare "fetch" (javaSymbolMatches)
//   - JS/TS  : "util/fetcher.fetchUrl", "Fetcher.fetch", or bare "fetchUrl" (jsSymbolMatches)
//   - Python : "deepdiff.delta.Delta", "delta.Delta", "JpegImagePlugin._save", or bare leaf
//   - .NET   : "Ionic.Zip.ZipEntry.Extract", "Zip.ZipEntry.Extract", or bare "Extract"
//
// A SCIP-qualified string (e.g. `scip-go gomod golang.org/x/text v0.3.0 language/Parse().`)
// would fail every one of those comparisons — its whitespace-separated scheme/manager/
// version prefix and descriptor-suffixed leaf never equal the DisplayName or its clean
// leaf — so a SCIP-form corpus would resolve nothing and drop the whole 50-set to zero
// recall. The engine RESOLVES the bare corpus identifier to a SCIP internally
// (SymbolResolutionResult.Resolved[i].SCIP), which then anchors the reachability BFS;
// the SCIP is the engine's OUTPUT, never the corpus's input.
//
// Guard symbols (`guard_symbols`) are matched the same way: guardsOnPath
// (trigger/assess.go) compares a declared guard against the leaf of each on-path callee
// SCIP id — so guards are bare leaf names too.
//
// Recommended canonical corpus form: the fully-qualified source identifier
// (package/namespace-qualified "Pkg.Symbol" or receiver-qualified "(*T).Method"). The
// resolver tolerates the bare leaf, but the qualified form is the most precise and avoids
// leaf collisions across packages.
//
// # Invariant (BINDING)
//
// A symbol is an identifier the resolver MATCHES; the call graph decides reachability.
// Populating one NEVER states a verdict. This harness measures candidate FORMATION and
// resolved-sink correctness; it does not adjudicate exploitability. GuardSymbols are
// presence candidates only — never a sufficiency claim; deciding whether a guard is
// SUFFICIENT is the Prove tier's two-trace job. Precision is measured against a curated,
// upstream-verified expected-sink annotation, never against the symbol list under test
// (which would be circular).
//
// # Phase-0 metric surface (PLAN-020)
//
// The Report rollups computable now are the analysis-completion rate (CompletionRate,
// §4.7.12), the symbol-resolution rate (SymbolResolutionRate, §4.7.11), path recall
// (Recall, §4.7.9 — n/a until expected_sinks is populated), and per-case runtime
// (RuntimeMS, §4.7.13; environment-variant, so it is EXCLUDED from the golden diff/gate).
// Precision (§4.7.8) is schema-only — no curated annotations, no threshold yet. Memory
// (§4.7.14) and cache-hit rate (§4.7.15) are deliberately NOT stubbed here: their CI-budget
// and semantics do not exist yet, and an empty stub would misrepresent coverage — they land
// with their insertion plans (PLAN-490 and PLAN-421 respectively).
package reachcandidate
