# Python capabilities

Every feature in every capability group for Python, with its status and the caveats that bound it. The [overview](README.md) explains the groups and statuses.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 4 / 🟨 4 / 🟥 1 | 🟩 4 / 🟨 4 / 🟥 1 | 🟩 1 / 🟨 1 / 🟥 1 | 🟩 5 / 🟨 4 / 🟥 0 | 🟩 2 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 2 / 🟥 2 | 🟩 1 / 🟨 2 / 🟥 1 | 🟩 2 / 🟨 0 / 🟥 0 |

🟩 Complete, 🟨 Partial, 🟥 Planned. Features marked N/A do not apply to the language and are not counted.

## 1. Dependency inventory

The lane reads the declared Python dependency surface directly from the checkout — requirements files, lockfiles and project metadata — and produces a whole-graph inventory with PEP 508 markers and extras evaluated against a declared target environment. Nothing is executed, so the inventory is deterministic and needs no network or resolver.

| Feature | Status | Caveats |
|---|---|---|
| Manifest/lockfile readers: requirements*.txt, poetry.lock, Pipfile.lock, pdm.lock, uv.lock, pyproject.toml (PEP 621 + poetry), setup.cfg, setup.py (literal only), hatch_build.py | Partial | [PYTHON-UNPARSEABLE-MANIFEST](#python-unparseable-manifest), [PYTHON-COMPUTED-SETUP](#python-computed-setup) |
| Whole-graph inventory (ResolveInventory), PEP 508 markers three-valued, extras vs Selection | Complete |  |
| Parent edges + direct/transitive for uv, pdm, poetry, pip-compile (`# via`) | Partial | [PYTHON-NO-EDGES-NONLOCK](#python-no-edges-nonlock) |
| Fail-open inventory (unresolved markers/unreadable files never silently drop a node) | Complete |  |
| Deterministic output | Complete |  |
| Import-name to distribution mapping (curated ~37 rows + PEP 503 identity for declared dists) | Partial | [PYTHON-IMPORT-MAP-GAP](#python-import-map-gap) |
| First-party import packages derived from source layout (DeriveFirstParty) | Complete |  |
| Workspace / multi-root enumeration | Planned | [PYTHON-SINGLE-ROOT-BUILD](#python-single-root-build) |
| SBOM projection from inventory | Partial | [PYTHON-SBOM-OTHER-BRANCH](#python-sbom-other-branch) |

## 2. Version clearing

The lane resolves a coordinate to a concrete installed version when a lock or exact pin names one, and matches it against advisory ranges with PEP 440 semantics. A confirmed out-of-range version, or a coordinate absent from a fully read build, disqualifies the finding before any reachability work.

| Feature | Status | Caveats |
|---|---|---|
| Exact `==` pin / lock version resolution | Complete |  |
| Ranges / prefixes / unpinned left unresolved (fail open) | Partial | [PYTHON-RANGE-UNRESOLVED](#python-range-unresolved) |
| PEP 440 range matching | Complete |  |
| Install-surface walk: unread surface vetoes the pin | Partial | [PYTHON-UNREAD-SURFACE-RUNWIDE](#python-unread-surface-runwide) |
| Installed copies (site-packages dist-info/egg-info) counted as extra copies | Complete |  |
| Every-version disqualification (Matches/MatchesComplete) | Complete |  |
| Exhaustive: `no_manifest_entry` disqualification | Partial | [PYTHON-EXHAUSTIVE-NEEDS-LOCK](#python-exhaustive-needs-lock) |
| Installs outside manifests (Dockerfile, shell/CI scripts, Makefile, package.json scripts): script surfaces read; any installer form not provably equal to the manifests withholds every pin and Exhaustive | Partial | [PYTHON-SCRIPT-INSTALL-WITHHOLD](#python-script-install-withhold) |
| Ubiquitous script lines (`pip install --upgrade pip`) precision | Planned | [PYTHON-SCRIPT-INSTALL-WITHHOLD](#python-script-install-withhold) |

## 3. Build-graph fidelity

Fidelity here means declared metadata, not a resolver run: the lane reports the interpreter version, extras, constraint files and resolver the project declares, and never guesses an undeclared one.

| Feature | Status | Caveats |
|---|---|---|
| Build manifest: requires-python / .python-version / lock python constraint, extras, constraint files, resolver detection | Complete |  |
| Build-tool-resolved graph (run pip/uv/poetry resolve) | N/A |  |
| Private registries / indexes, vendoring | Planned | [PYTHON-NO-REGISTRY-MODEL](#python-no-registry-model) |
| Platform/marker target environment | Partial | [PYTHON-TARGET-ENV-DECLARED](#python-target-env-declared) |

## 4. Call graph

A first-party, source-lexical call graph with module-init roots and boundary nodes where first-party code calls into a dependency. It is the substrate for sink resolution and ingress-to-sink path search.

| Feature | Status | Caveats |
|---|---|---|
| First-party call graph (source-lexical, name+arity, self/cls tolerant) | Partial | [PYTHON-AMBIGUOUS-CALLEE-NO-EDGE](#python-ambiguous-callee-no-edge), [PYTHON-DYNAMIC-DISPATCH](#python-dynamic-dispatch) |
| Boundary nodes `pypi:<dist>#<dotted>` for calls through import bindings | Partial | [PYTHON-IMPORT-MAP-GAP](#python-import-map-gap), [PYTHON-RELATIVE-STAR-IMPORT](#python-relative-star-import) |
| Dependency-source call graph | N/A |  |
| Symbol resolution (first-party by name/dotted/module-leaf, arity-tolerant) | Partial | [PYTHON-SYMBOL-IDENTITY-NAME-ARITY](#python-symbol-identity-name-arity) |
| Dependency advisory symbols onto boundary nodes (exact dotted equality) | Partial | [PYTHON-REEXPORT-PATH](#python-reexport-path) |
| Dynamic import detection (`importlib`, `__import__`, entry_points, walk_packages) | Complete |  |
| Declaration parser (def/class/nested/methods, arity; comments and strings blanked first) | Complete |  |
| Standard-library imports recognised per declared interpreter range (2.7, 3.0-3.14 tables), so stdlib is never an undeclared import | Complete |  |
| Test modules excluded from roots | Complete |  |
| Call-graph partiality always `dynamic_dispatch` (+tool_failure / unsupported_phase1) | Complete |  |

## 5. Reachability clearing

The Python lane cannot clear a finding as `not_exploitable`. The plugin returns ingress-to-sink paths as structural candidates and never sets `ReachabilityResult.Searched` or `.Refutation`, which are the only inputs the verdict gate accepts for a clear. Python findings land as reachable candidates, disqualified (by version or absence), or undetermined.

| Feature | Status | Caveats |
|---|---|---|
| Ingress-to-sink path search (reverse BFS, ingress preferred, root fallback) | Partial | [PYTHON-DYNAMIC-DISPATCH](#python-dynamic-dispatch) |
| `not_exploitable` producer (Searched sink / Refutation) | Planned | [PYTHON-NO-CLEAR-PRODUCER](#python-no-clear-producer) |
| Guard: no lane refutes without a search | Complete |  |
| Taint (path presence, not value flow) | Partial | [PYTHON-TAINT-PATH-ONLY](#python-taint-path-only) |
| First-party route chain to CandidatePair through pipeline | Complete |  |

## 6. Framework & dynamic-dispatch modeling

Entry points are recognised for the three common Python web frameworks by decorator. Everything else dynamic is covered by a single standing hazard rather than modeled.

| Feature | Status | Caveats |
|---|---|---|
| Flask / FastAPI route decorators as ingress (route/get/post/put/delete/patch/options/head/trace/websocket/api_route) | Partial | [PYTHON-INGRESS-LEAF-MATCH](#python-ingress-leaf-match), [PYTHON-INGRESS-FRAMEWORKS](#python-ingress-frameworks) |
| Django URLconf, Celery tasks, raw WSGI/ASGI callables as ingress | Planned | [PYTHON-INGRESS-FRAMEWORKS](#python-ingress-frameworks) |
| getattr / eval / exec / decorator rewriting / monkeypatching | Partial | [PYTHON-DYNAMIC-DISPATCH](#python-dynamic-dispatch) |
| Dependency-injection / middleware modeling | Planned | [PYTHON-DYNAMIC-DISPATCH](#python-dynamic-dispatch) |

## 7. Hazard bounding

Hazards are reported per call-graph run as machine-readable partiality reasons. The standing `dynamic_dispatch` is classified as an inherent limit and does not block a verdict; unrecognised reasons such as `tool_failure` and `relationship_unexpressed:dynamic_import` do.

| Feature | Status | Caveats |
|---|---|---|
| Standing `dynamic_dispatch` classed inherent (non-blocking) | Complete |  |
| Per-symbol / per-path hazard scoping | Planned | [PYTHON-HAZARDS-RUN-WIDE](#python-hazards-run-wide) |
| Unread manifest surface or dynamic import specifier turns the whole run `analysis_did_not_run` | Partial | [PYTHON-UNREAD-SURFACE-RUNWIDE](#python-unread-surface-runwide), [PYTHON-DYNAMIC-IMPORT-RUNWIDE](#python-dynamic-import-runwide) |
| Typical-project clear rate | Partial | [PYTHON-NO-CLEAR-PRODUCER](#python-no-clear-producer) |

## 8. Runtime confirmation

The lane hands the paid tier a call-graph path and the sink's package coordinate. Python runtime confirmation rides the corpus repro-runtime sandbox rather than a generated harness.

| Feature | Status | Caveats |
|---|---|---|
| GenerateHarness | N/A |  |
| Hand-off of candidate path to paid tier | Complete |  |
| Plugin subprocess protocol (index, resolve, versions, call_graph, ingresses, reachability, taint, inventory, build_manifest) | Complete |  |

## Caveats

### PYTHON-NO-CLEAR-PRODUCER

**Trigger.** Any Python finding whose verdict would be a clear.

**Effect.** Never `not_exploitable`; ends as reachable_candidate, disqualified or undetermined.

### PYTHON-UNREAD-SURFACE-RUNWIDE

**Trigger.** An install surface the lane classifies but cannot fully read (e.g. Pipfile/conda/tox forms it cannot parse, symlink leaving the build dir), or a partly read manifest.

**Effect.** The pin is vetoed like an unparseable manifest and the run becomes `analysis_did_not_run` for all advisories, not just the affected package.

### PYTHON-UNPARSEABLE-MANIFEST

**Trigger.** A manifest that fails to parse.

**Effect.** Every Found match is unresolved with `tool_failure` partiality.

### PYTHON-COMPUTED-SETUP

**Trigger.** Setup.py or hatch_build.py computing dependencies (not literal).

**Effect.** Dependencies unread; Exhaustive fails open; no `no_manifest_entry` disqualification.

### PYTHON-RANGE-UNRESOLVED

**Trigger.** Dependency declared as a range/prefix with no lock.

**Effect.** Version unresolved; version-based disqualification unavailable.

### PYTHON-EXHAUSTIVE-NEEDS-LOCK

**Trigger.** No complete edge-bearing lock (uv/pdm/poetry) governing every manifest, or any non-fully-read install surface, or an installed copy present.

**Effect.** No absence-based disqualification.

### PYTHON-SCRIPT-INSTALL-WITHHOLD

**Trigger.** A Dockerfile, shell/CI script, Makefile or package.json script runs a Python installer in any form outside the allowlist (a named package, extra flags, pipx, uvx, `uv run`, bare `uv sync`/`pdm install`, conda/mamba/easy_install), or sets a PIP_*/UV_* variable.

**Effect.** Every pin in the build is withheld (Resolved=false) and Exhaustive is withheld, so version and absence disqualifications are unavailable; the finding is admitted and ends undetermined, never wrongly disqualified. Scoped to the whole build, not the one package.

### PYTHON-NO-EDGES-NONLOCK

**Trigger.** Pipfile.lock, pyproject, setup.cfg, setup.py or hatch inputs.

**Effect.** No parent edges; nodes classified relationship-unexpressed.

### PYTHON-IMPORT-MAP-GAP

**Trigger.** An import name that differs from the distribution name, is not in the curated mapping (for example sklearn, cv2, yaml) and is not PEP 503 identical.

**Effect.** No boundary edge for calls into that dependency (silent recall loss); if manifests were partly read, `tool_failure` instead.

### PYTHON-RELATIVE-STAR-IMPORT

**Trigger.** Relative imports or `from x import *` of a dependency.

**Effect.** No bindings, so no boundary edge; covered only by standing `dynamic_dispatch`.

### PYTHON-AMBIGUOUS-CALLEE-NO-EDGE

**Trigger.** A call whose (name, arity) matches zero or more than one declared function (e.g. same method name on two classes).

**Effect.** No edge. Silently missing edge, mitigated only by standing `dynamic_dispatch`.

### PYTHON-DYNAMIC-DISPATCH

**Trigger.** Getattr, eval, exec, decorators that rewrite callables, monkeypatching, duck-typed calls.

**Effect.** Edges absent; every call graph and path is Partial(dynamic_dispatch). Inherent class, does not block verdicts.

### PYTHON-DYNAMIC-IMPORT-RUNWIDE

**Trigger.** Non-literal `importlib` / `__import__` / entry_points / walk_packages call.

**Effect.** `relationship_unexpressed:dynamic_import` added; unrecognised by the classifier, so it makes the run `analysis_did_not_run`.

### PYTHON-SYMBOL-IDENTITY-NAME-ARITY

**Trigger.** Overloaded or same-named functions in one module.

**Effect.** Collapse to one symbol; structured fields (Kind, Enclosing, Descriptor) empty.

### PYTHON-REEXPORT-PATH

**Trigger.** Advisory symbol named at a re-export path (`jwt.encode`) vs the defining path (`jwt.api_jwt.encode`).

**Effect.** Advisory sink does not resolve onto the boundary node; no candidate.

### PYTHON-TAINT-PATH-ONLY

**Trigger.** Any taint query.

**Effect.** Structural path only, no value flow, no sanitiser awareness.

### PYTHON-INGRESS-LEAF-MATCH

**Trigger.** Any call or decorator with a leaf in the route set (e.g. `.get`, `.post`) on a non-framework object.

**Effect.** False-positive ingress (over-approximation; not a missed edge).

### PYTHON-INGRESS-FRAMEWORKS

**Trigger.** Django, Celery or raw WSGI/ASGI entry points.

**Effect.** No ingress recognised; reachability falls back to module-init roots; path-to-ingress may be absent (`no_known_ingress`).

### PYTHON-SINGLE-ROOT-BUILD

**Trigger.** Monorepo with several Python projects.

**Effect.** One build manifest per run; multi-root enumeration not available.

### PYTHON-SBOM-OTHER-BRANCH

**Trigger.** `analyze.ref` is a branch other than the checked-out one.

**Effect.** Python SBOM resolves 0-1 packages.

### PYTHON-NO-REGISTRY-MODEL

**Trigger.** Private index or vendored dependencies.

**Effect.** Not modelled; versions come from declarations only.

### PYTHON-TARGET-ENV-DECLARED

**Trigger.** Target interpreter/platform not declared.

**Effect.** Markers evaluate unresolved, nodes stay selected-unknown.

### PYTHON-HAZARDS-RUN-WIDE

**Trigger.** Any non-inherent hazard.

**Effect.** Scoped to the run, not the path or symbol.
