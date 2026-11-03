# Go capabilities

Every feature in every capability group for Go, with its status and the caveats that bound it. The [overview](README.md) explains the groups and statuses.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 5 / 🟨 4 / 🟥 0 | 🟩 4 / 🟨 2 / 🟥 0 | 🟩 2 / 🟨 4 / 🟥 0 | 🟩 6 / 🟨 1 / 🟥 0 | 🟩 4 / 🟨 6 / 🟥 0 | 🟩 5 / 🟨 2 / 🟥 2 | 🟩 1 / 🟨 4 / 🟥 0 | 🟩 2 / 🟨 0 / 🟥 1 |

🟩 Complete, 🟨 Partial, 🟥 Planned. Features marked N/A do not apply to the language and are not counted.

## 1. Dependency inventory

Go reads the module graph the Go toolchain itself resolves (`go mod graph`, merged with `go.mod` replace directives and `go.sum` digests), so the inventory is the selected build list, not the `require` list. Nested modules are scanned from their own root. The inventory feeds version clearing, the outside-build module search and the toolchain axis.

| Feature | Status | Caveats |
|---|---|---|
| Selected build list from `go mod graph` + modfile | Complete |  |
| `replace` redirects and `go.sum` digests | Complete |  |
| Nested `go.mod` (module not at repo root) | Complete |  |
| `replace` read identically by the SBOM inventory and the version axis (versioned replace beats module-wide) | Complete |  |
| Local-path (filesystem) or fork `replace` | Partial | [GO-LOCAL-REPLACE](#go-local-replace) |
| Vendored module trees (`-mod=vendor`) | Partial | [GO-VENDORED](#go-vendored) |
| `go.work` workspaces | Partial | [GO-WORKSPACE](#go-workspace) |
| Build manifest (go directive, toolchain, replace/exclude) | Partial | [GO-MANIFEST-REPLACE](#go-manifest-replace) |
| Dependency SBOM (shared S1-S2 stages over the Go inventory) | Complete |  |

## 2. Version clearing

Advisory ranges are placed against the resolved module version with the semver comparator, honouring both `introduced` and `fixed` bounds. Go standard-library advisories are cleared on the Go toolchain version with its own comparator and multi-range backports. Any version the comparator cannot place stays admitted.

| Feature | Status | Caveats |
|---|---|---|
| Semver introduced/fixed bounds (both sides) | Complete |  |
| Pseudo-version / prerelease upper bounds | Partial | [GO-PSEUDOVERSION](#go-pseudoversion) |
| Stdlib/toolchain ranges (`go1.X.Y`), multi-range backport | Complete |  |
| Toolchain fact from `go` / `toolchain` directive | Partial | [GO-TOOLCHAIN-PRE121](#go-toolchain-pre121) |
| Module found at multiple versions in the build | Complete |  |
| Module absent from the build (`no_manifest_entry`): under a `go.work`, the go command's build list; outside one, a `replace` is presence, from `go 1.17` a missing `require` is absence, and below `go 1.17` or with no `go` line `vendor/modules.txt` and `go.sum` module hashes decide; a missing or unparseable file fails open | Complete |  |

## 3. Build-graph fidelity

The graph is the one `go` computes for the job's GOOS and GOARCH: `./...` under the `go.work` the build runs under (`subject-gowork`, or the one the go command finds that uses the module; otherwise `GOWORK=off`), test files excluded. A file left out for another platform or behind a build tag is read for calls into the advisory's module ([GO-EXCLUDED-FILES](#go-excluded-files)). With `subject-toolchain-reachability` on and an exact toolchain, the subject's own Go release is selected through GOTOOLCHAIN, so the code is typed the way the subject builds it.

| Feature | Status | Caveats |
|---|---|---|
| Toolchain-resolved package graph (`go/packages`) | Complete |  |
| The build's own `go.work` (`subject-gowork`), never an ambient one | Complete |  |
| Files excluded by build constraints on the analysed platform | Partial | [GO-EXCLUDED-FILES](#go-excluded-files) |
| Subject-toolchain switching (GOTOOLCHAIN, loader floor go1.20) | Partial | [GO-TOOLCHAIN-NOT-SCANNED](#go-toolchain-not-scanned) |
| cgo packages | Partial | [GO-CGO](#go-cgo) |
| Private modules / registries / `GOFLAGS=-modfile` | Partial | [GO-VENDORED](#go-vendored) |

## 4. Call graph

Go analyses the whole build as SSA, first-party and dependency source alike, so a path can run from an entry point through any dependency into the advisory symbol. VTA is the default graph, with CHA and RTA available. Advisory symbols resolve to SCIP-form identifiers against the admitted package.

| Feature | Status | Caveats |
|---|---|---|
| Whole-build SSA incl. dependency source | Complete |  |
| VTA (default) / CHA / RTA | Complete |  |
| Entry roots (main, govulncheck entries, unsearched exported methods) | Complete |  |
| SCIP symbol resolution in dependencies | Complete |  |
| Interface dispatch | Complete |  |
| Calls the graph cannot follow (reflect Call/Method, template Execute, plugin.Open) | Partial | [GO-REFLECT-CALL](#go-reflect-call) |
| Generic origin functions | Complete |  |

## 5. Reachability clearing

A Go dependency advisory gets per-advisory govulncheck evidence. `reachable_candidate` carries the stack. `not_exploitable` is emitted only on positive grounds: the admitted version resolved, every advisory symbol resolved in the admitted package and searched (from a vetted symbol set), and the lane's own refutation not withheld. First-party advisories outside the build are refuted by searching every module's source.

| Feature | Status | Caveats |
|---|---|---|
| Path-bearing `reachable_candidate` (govulncheck `-mode=source -scan=symbol`) | Complete |  |
| `not_exploitable` on resolved + searched symbols | Complete |  |
| Target-conditional symbol absent ground | Complete |  |
| Withhold on unsearched methods | Complete |  |
| Withhold on library escape (importable package reaches the refuted module) | Partial | [GO-LIBRARY-ESCAPE](#go-library-escape) |
| Withhold on excluded files | Partial | [GO-EXCLUDED-FILES](#go-excluded-files) |
| Outside-build first-party advisory ground (module search) | Partial | [GO-VENDORED](#go-vendored), [GO-MULTIPACKAGE-ADVISORY](#go-multipackage-advisory), [GO-LOCAL-REPLACE](#go-local-replace) |
| Advisories with no symbol coordinates | Partial | [GO-NO-SYMBOLS](#go-no-symbols) |
| Go stdlib / toolchain advisories | Partial | [GO-TOOLCHAIN-NOT-SCANNED](#go-toolchain-not-scanned), [GO-TOOLCHAIN-PRE121](#go-toolchain-pre121) |
| Run-wide did-not-run gate on `not_exploitable` | Partial | [GO-CGO](#go-cgo), [GO-PLUGIN-LOAD](#go-plugin-load) |

## 6. Framework & dynamic-dispatch modeling

Ingress discovery recognises net/http handlers and route registrars, the macaron, go-chi, gin and echo/v4 routers, and SSH server handlers. Reachability does not depend on ingress for dependency advisories (govulncheck supplies the entry roots), so ingress only decides whether a first-party path is rooted at a network surface. Taint is tracked at variable level over SSA, with an explicit sanitizer allow-list.

| Feature | Status | Caveats |
|---|---|---|
| net/http handler signatures and route registrars | Complete |  |
| macaron.v1 | Complete |  |
| SSH server handlers | Complete |  |
| go-chi router (`chi` and `chi/v5`: verb methods, Handle/HandleFunc, Method/MethodFunc, Mount; Route/Group/With closures via interface calls) | Complete |  |
| chi catch-all handlers, handlers bound through var/field/factory, composed Mount prefixes | Planned |  |
| gin and echo/v4 route registration (verb methods, Handle/Any/Match/Add, groups, gin NoRoute/NoMethod and WrapF/WrapH) | Complete |  |
| gRPC, Connect, Cobra/CLI entry points | Planned |  |
| Variable-level SSA taint with sanitizer allow-list | Partial | [GO-TAINT-ECHO](#go-taint-echo) |
| Reflection and text/html template Execute | Partial | [GO-REFLECT-CALL](#go-reflect-call) |
| DI containers (wire, fx, dig) | N/A | [GO-REFLECT-CALL](#go-reflect-call) (wiring is resolved by the same SSA graph as ordinary calls; no container-specific model needed for static wire, fx/dig fall under reflection) |

## 7. Hazard bounding

Go limits are mostly scoped to the advisory they affect: the withholds in group 5 and reflective calls act on one refutation, and cgo limits are carried per package or path where the loader can bound them. Plugin loading is run-wide, and a run-wide did-not-run reason blocks `not_exploitable` for every advisory in the scan. `reachable_candidate` is unaffected, because a govulncheck path outranks the did-not-run gate.

| Feature | Status | Caveats |
|---|---|---|
| Per-advisory withholds (unsearched methods, library escape, excluded files) | Complete |  |
| cgo bounded to scoped limits | Partial | [GO-CGO](#go-cgo) |
| Reflective call / template Execute, reached from entry points | Partial | [GO-REFLECT-CALL](#go-reflect-call) |
| `plugin.Open` reached | Partial | [GO-PLUGIN-LOAD](#go-plugin-load) |
| Can a typical Go app receive a clear? | Partial | [GO-REFLECT-CALL](#go-reflect-call), [GO-LIBRARY-ESCAPE](#go-library-escape), [GO-NO-SYMBOLS](#go-no-symbols) |

## 8. Runtime confirmation

Go hands the paid tier a reach path set and a harness skeleton: a generated Go source that calls the sink (function or method) with a seed hook, which the paid tier completes and runs. The skeleton is always marked `dynamic_dispatch` partial, since the inputs are the paid tier's to choose.

| Feature | Status | Caveats |
|---|---|---|
| Harness skeleton generation (fn and method sinks) | Complete |  |
| Reach paths + taint discovery for the paid tier | Complete |  |
| Sandboxed Go fuzz execution | Planned |  |
| Value-flow proof beyond call-graph path presence | N/A | taint baseline across lanes is path presence; Go adds variable-level taint as an extra |

## Caveats

### GO-WORKSPACE

**Trigger.** The scanned module's directory holds a `go.work` while the build runs with `GOWORK=off` (`subject-gowork: off`), or the `go.work` the build runs under cannot be read or does not use the scanned module.

**Effect.** With `GOWORK=off` beside a `go.work`, the inventory declares the workspace unsupported, which blocks `not_exploitable` for the scan; `reachable_candidate` is unaffected. A `go.work` that cannot be read or does not use the scanned module withholds every verdict. Under a `go.work` that uses the module, the inventory is the workspace's build list, and its other members are main modules, not dependencies.

### GO-MANIFEST-REPLACE

**Trigger.** Go.mod with `replace` or `exclude`, or no `go` directive.

**Effect.** `BuildManifest` returns `Partial(tool_failure)`, a did-not-run class reason.

### GO-LOCAL-REPLACE

**Trigger.** A `replace` pointing at a filesystem path or a fork.

**Effect.** The inventory declares `source_unpinned` and the version axis stays open. The outside-build module search cannot apply, so the advisory ends `undetermined`.

### GO-VENDORED

**Trigger.** Build uses `-mod=vendor` (vendor directory with `modules.txt`) or `GOFLAGS=-modfile`.

**Effect.** Module search returns nil, so the outside-build first-party ground withholds and the advisory is `undetermined`; dependency-advisory paths via govulncheck still work.

### GO-MULTIPACKAGE-ADVISORY

**Trigger.** An advisory that names more than one package, evaluated by the outside-build ground.

**Effect.** Ground withholds (`undetermined`).

### GO-PSEUDOVERSION

**Trigger.** Resolved module version is a pseudo-version or prerelease.

**Effect.** The upper-bound test is not applied, so the advisory stays admitted (fail-open to admission, precision only).

### GO-TOOLCHAIN-PRE121

**Trigger.** A stdlib/toolchain-ranged advisory on a module whose `go.mod` has no `toolchain` line and a `go` line that is two-part (`go 1.21`) or below 1.21.

**Effect.** The `go` line is not a minimum, because a go command before 1.21 does not enforce it, so it is left out of the toolchain fact. The Go the build's own go command resolves stands in only with `ASSAY_TRUST_OBSERVED_GO=true`; without that, or a declaration, the fact is unresolved and the advisory is `undetermined` with `go_toolchain_unresolved`.

### GO-TOOLCHAIN-NOT-SCANNED

**Trigger.** A Go standard-library advisory whose search found no path while the analysis ran under the scanner's toolchain: `subject-toolchain-reachability` is off (the default), the toolchain fact is only a minimum, or the subject's release could not be run (below go1.20, or not obtainable).

**Effect.** The row is `undetermined` with `undetermined_reason` `go_toolchain_not_scanned`. A version range the toolchain fact clears still disqualifies the advisory.

### GO-EXCLUDED-FILES

**Trigger.** A first-party file excluded by build constraints on the analysed platform (or otherwise left out of the load) that calls into the refuted module.

**Effect.** The refutation is withheld with `excluded_files`, or `excluded_files:assembly`, `excluded_files:linkname` or `excluded_files:cgo_include` naming what the file reaches. The withhold is scoped to the advisory, and the row is `undetermined` with `refutation_withheld`.

### GO-CGO

**Trigger.** A package using cgo.

**Effect.** Where the loader can bound cgo, limits are scoped per package or path. Where it cannot, a run-wide `cgo` did-not-run reason blocks `not_exploitable` scan-wide.

### GO-REFLECT-CALL

**Trigger.** The call graph, from govulncheck entry roots and the unsearched exported methods, reaches `reflect.Value.Call/CallSlice/Method/MethodByName` or `text/template` / `html/template` `Execute`/`ExecuteTemplate`.

**Effect.** `reflection:call`, declared per advisory: when what those calls can reach holds one of the advisory's vulnerable symbols, or cannot be computed, that advisory's refutation and searched sinks are withheld and the row is `undetermined` with `refutation_withheld`. Other advisories are unaffected. Does not affect `reachable_candidate`.

### GO-PLUGIN-LOAD

**Trigger.** `plugin.Open` reached from entry roots.

**Effect.** `plugin_load`, run-wide did-not-run.

### GO-LIBRARY-ESCAPE

**Trigger.** A library entry point reaches one of the refuted module's vulnerable packages. `library-entrypoints` (`-library-entrypoints`, `ASSAY_LIBRARY_ENTRYPOINTS`) names the entry points: `auto` (the default) takes every importable package outside `cmd/`, `example(s)/`, `test(s)/` and `testdata/`, `none` takes none, and a list of paths relative to the repository root names them, with `!path` taking a path out.

**Effect.** The refutation is withheld with `library_escape`, and the row is `undetermined` with `refutation_withheld`. A `not_exploitable` that stands only because of what you declared carries that declaration on the report as an assumption.

### GO-NO-SYMBOLS

**Trigger.** An advisory with no symbol coordinates.

**Effect.** No vetted symbol set, so no `not_exploitable`; verdict is `reachable_candidate` if a path exists, else `undetermined`.

### GO-TAINT-ECHO

**Trigger.** Request data read through echo's context helpers other than those modelled.

**Effect.** Taint source not recognised, so a flow is not asserted (a missed `taint` signal, not a missed path).
