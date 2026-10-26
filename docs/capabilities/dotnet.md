# .NET capabilities

Every feature in every capability group for .NET, with its status and the caveats that bound it. The [overview](README.md) explains the groups and statuses.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 2 / 🟨 2 / 🟥 1 | 🟩 3 / 🟨 2 / 🟥 3 | 🟩 1 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 5 / 🟥 1 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 1 / 🟨 4 / 🟥 2 | 🟩 0 / 🟨 3 / 🟥 1 | 🟩 0 / 🟨 1 / 🟥 3 |

🟩 Complete, 🟨 Partial, 🟥 Planned. Features marked N/A do not apply to the language and are not counted.

## 1. Dependency inventory

The .NET lane reads the NuGet restore output when present and otherwise the declared project files, and reports every package it can name with the strength of evidence behind it. Solutions and multi-project repositories are inventoried per project with project references kept as edges. Ranges are never guessed.

| Feature | Status | Caveats |
|---|---|---|
| Inventory from `obj/project.assets.json` (full transitive closure) | Complete |  |
| Inventory from `packages.lock.json`, declared `PackageReference`, `packages.config`, Central Package Management (`Directory.Packages.props`) | Partial | [DOTNET-UNPINNED-VERSION](#dotnet-unpinned-version) |
| Solutions / multi-project (`.sln` or >=2 project files; ProjectReference as edge) | Complete |  |
| Inventory/membership readers vs. resolver manifest rules | Planned |  |
| SBOM emission from the .NET inventory | Partial |  |

## 2. Version clearing

A dependency's installed version is resolved only from evidence that pins it: restore output, a lockfile, packages.config, or an exact `[x]` pin. NuGet range semantics are applied when disqualifying an advisory by version. Inputs the resolver does not model withhold the answer with a named reason instead of producing a guess.

| Feature | Status | Caveats |
|---|---|---|
| Installed-version resolution (exact pin / lockfile / packages.config / trusted restore output) | Complete |  |
| NuGet range matching and advisory disqualification | Complete |  |
| Restore-output trust check (stale or untrusted output rejected) | Complete |  |
| Floating / range / plain `Version="x"` (a minimum, not a pin) with no restore output or lockfile | Partial | [DOTNET-UNPINNED-VERSION](#dotnet-unpinned-version) |
| Unmodeled build inputs withhold (`Directory.Build.rsp`, `*.user`, `project.json`, `packages.*.lock.json`, unevaluated conditions) | Partial | [DOTNET-BUILD-INPUT-UNMODELED](#dotnet-build-input-unmodeled) |
| Resolver reports a version while unread copies exist (catalogs, force, profiles, Directory.Build.props) | Planned |  |
| Recover coverage the version allow-list withholds | Planned |  |
| CI-supplied MSBuild properties steering legacy restore | Planned |  |

## 3. Build-graph fidelity

The lane evaluates the build statically: csproj, props, targets, global.json, nuget.config and restore-output presence are read as modeled inputs, and a restore that cannot be trusted is declared rather than assumed. It does not invoke MSBuild.

| Feature | Status | Caveats |
|---|---|---|
| Modeled MSBuild/NuGet inputs (Directory.Build.props/.targets, Directory.Packages.props, global.json, nuget.config, lockfiles, `project.nuget.cache`, dgspec) | Complete |  |
| `BuildManifest` (lexical; declares `multi_target_framework`, `multi_project_solution`, `property_set_unhomed`) | Partial | [DOTNET-SINGLE-TFM-RID](#dotnet-single-tfm-rid), [DOTNET-MULTI-PROJECT](#dotnet-multi-project) |
| Locating the first-party compiled assembly (`bin/`, `publish/`, TFM canonicalization) | Partial | [DOTNET-IL-REQUIRES-BUILD-OUTPUT](#dotnet-il-requires-build-output) |
| MSBuild-evaluated property/target graph | N/A |  |
| CI-supplied properties / env as build inputs | Planned |  |

## 4. Call graph

Two tiers. The IL tier reads the compiled first-party assembly and its NuGet dependency assemblies (PE/metadata reader, class-hierarchy analysis) and is the basis for any clear. The lexical tier scans `.cs` source and supplies a first-party graph when no build output exists. Dependency code is covered only through the IL tier.

| Feature | Status | Caveats |
|---|---|---|
| IL call graph over first-party + NuGet assemblies (CHA) | Partial | [DOTNET-IL-REQUIRES-BUILD-OUTPUT](#dotnet-il-requires-build-output), [DOTNET-MULTI-PROJECT](#dotnet-multi-project), [DOTNET-DEP-ARTIFACT-MISS](#dotnet-dep-artifact-miss) |
| Lexical source call graph (`.cs`, `Algorithm: source-lexical`, always Partial) | Partial | [DOTNET-LEXICAL-DYNAMIC-DISPATCH](#dotnet-lexical-dynamic-dispatch), [DOTNET-CALLEE-AMBIGUITY](#dotnet-callee-ambiguity) |
| Advisory-symbol resolution inside restored NuGet assemblies | Partial | [DOTNET-DEP-ARTIFACT-MISS](#dotnet-dep-artifact-miss) |
| SCIP-style symbol spelling | Partial | [DOTNET-SYMBOL-SPELLING](#dotnet-symbol-spelling) |
| Virtual dispatch precision (fans out by method slot, not receiver type; sound, over-approximate) | Partial | [DOTNET-IL-DISPATCH-SLOT](#dotnet-il-dispatch-slot) |
| `reachable_candidate` evidence.call_path entries name their methods | Planned |  |

## 5. Reachability clearing

`not_exploitable` is emitted only on positive grounds: the installed version resolved, every advisory symbol resolved inside the admitted package from a vetted symbol set, and the IL search listed the sink as `Searched` with a complete partiality. Any did-not-run reason blocks the clear. The lexical tier never clears.

| Feature | Status | Caveats |
|---|---|---|
| Provably-absent dependency (`dependency_not_in_build`: closed build, every project's restore output trusted, every MSBuild input modeled, no foreign assemblies/package managers) settles the advisory without a reachability search; scoped to the package PURL, never run-wide | Partial | [DOTNET-ABSENT-CLOSED-BUILD-ONLY](#dotnet-absent-closed-build-only) |
| IL reachability emits a path for a reachable sink | Complete |  |
| IL `Searched` -> `not_exploitable` (Main-rooted, hazard-free search) | Partial | [DOTNET-IL-FRAMEWORK-HAZARD](#dotnet-il-framework-hazard), [DOTNET-IL-NO-MAIN](#dotnet-il-no-main), [DOTNET-IL-REQUIRES-BUILD-OUTPUT](#dotnet-il-requires-build-output), [DOTNET-MULTI-PROJECT](#dotnet-multi-project), [DOTNET-DEP-ARTIFACT-MISS](#dotnet-dep-artifact-miss) |
| Degrade to lexical on IL failure with `tool_failure` (never a clear) | Complete |  |
| Clear grounds (resolved version, vetted symbols and a Searched sink; any did-not-run reason blocks) | Complete |  |
| Lexical fallback paths for first-party sinks (candidate only) | Complete |  |
| IL search rooted at recognized ingresses (controllers, handlers) | Planned |  |

## 6. Framework & dynamic-dispatch modeling

ASP.NET ingress is recognized from controller/action attributes and from minimal-API registrations that name a method group. Hazards that defeat static resolution (reflection, dynamic, native calls) are declared as completeness hazards, never skipped.

| Feature | Status | Caveats |
|---|---|---|
| ASP.NET attribute ingress (`[HttpGet]` etc.) | Partial | [DOTNET-INGRESS-SHAPES](#dotnet-ingress-shapes) |
| Minimal API `MapGet/Post/Put/Delete/Patch/Methods` with a named method-group handler | Partial | [DOTNET-INGRESS-SHAPES](#dotnet-ingress-shapes) |
| Minimal API inline lambdas; top-level statements (default modern template) | Planned |  |
| Blazor, gRPC, SignalR | Planned |  |
| Reflection / DLR dynamic / P-Invoke / calli / out-of-set receiver as completeness hazards | Complete |  |
| Interface / virtual / DI dispatch in the lexical graph | Partial | [DOTNET-LEXICAL-DYNAMIC-DISPATCH](#dotnet-lexical-dynamic-dispatch) |
| Taint (ingress-to-sink) | Partial | [DOTNET-TAINT-PATH-PRESENCE](#dotnet-taint-path-presence) |

## 7. Hazard bounding

Dependency-artifact misses are attributed to the advisories whose search they affect. The remaining question for a typical project is whether the framework boundary lets a search finish. An empty `Main` plus an unreferenced sink completes with the sink searched, a clean clear. A `Main` that calls the BCL or instantiates a class is `reachability_undetermined`, because the framework boundary is out of the span; libraries (no `Main`) always are.

| Feature | Status | Caveats |
|---|---|---|
| Dependency misses scoped to affected advisories | Partial | [DOTNET-DEP-ARTIFACT-MISS](#dotnet-dep-artifact-miss) |
| Framework/BCL boundary: out-of-set callee bodies | Partial | [DOTNET-IL-FRAMEWORK-HAZARD](#dotnet-il-framework-hazard) |
| Trusted-framework-boundary relaxation (so a typical app can receive a clear) | Planned |  |
| Typical project receives a clear | Partial | [DOTNET-IL-FRAMEWORK-HAZARD](#dotnet-il-framework-hazard) |

## 8. Runtime confirmation

The .NET lane does not generate harnesses; confirmation rides the corpus repro-runtime sandbox in the paid tier.

| Feature | Status | Caveats |
|---|---|---|
| `generate_harness` | N/A |  |
| Sink-scheme mapping for the paid tier's proof of non-exploitability | Planned |  |
| Patch-synthesis locator for .NET | Planned |  |
| Published capability manifest | Planned |  |
| Built-in advisory floor (3 public advisories) is a default floor, not coverage | Partial | [DOTNET-FLOOR-NOT-COVERAGE](#dotnet-floor-not-coverage) |

## Caveats

### DOTNET-IL-FRAMEWORK-HAZARD

**Trigger.** A Main-rooted program whose reachable closure calls any method whose body is outside the spanning set: any BCL/shared-framework call, any `Object::.ctor` (any `new`).

**Effect.** Run-wide `reachability_undetermined` for the Reachability call; no sink is Searched; no `not_exploitable`. Reachable paths are still reported.

### DOTNET-IL-NO-MAIN

**Trigger.** No `Main` entry point (libraries, class-library projects, test projects).

**Effect.** The IL search has no root that may license a clean clear; the result is undetermined.

### DOTNET-IL-REQUIRES-BUILD-OUTPUT

**Trigger.** No compiled `<csproj basename>.dll` under `bin/` or `publish/` (not built before the scan, or `AssemblyName` overrides the csproj name).

**Effect.** IL tier degrades to the lexical tier with `tool_failure`; no clear.

### DOTNET-MULTI-PROJECT

**Trigger.** A `.sln` or >=2 project files in the scanned tree.

**Effect.** `multiple_projects_unsupported`; the IL search is withheld (`searched = nil`), run-wide. Inventory is still per-project.

### DOTNET-DEP-ARTIFACT-MISS

**Trigger.** A NuGet dependency dll that is missing, unreadable, a reference-assembly stub, RID-unknown/ambiguous, or framework-supplied.

**Effect.** Declared miss, attributed to the affected advisories and also run-wide; blocks the clear.

### DOTNET-ABSENT-CLOSED-BUILD-ONLY

**Trigger.** The not-in-build claim needs a closed build: trusted restore output for every project, all MSBuild files modeled, and no foreign assembly, script, package manager or opaque Import/property in the tree.

**Effect.** Otherwise the claim is not made and the lane answers through the version and IL path. Deploy-time additions (Dockerfile, base image, host runtime) are outside the claim.

### DOTNET-LEXICAL-DYNAMIC-DISPATCH

**Trigger.** Interface, virtual, DI-resolved or reflection-invoked calls on a path.

**Effect.** Lexical call graph is always Partial(dynamic_dispatch); never clears.

### DOTNET-CALLEE-AMBIGUITY

**Trigger.** A call whose (simple name, arity) matches more than one declared method in the program, or a BCL/library call.

**Effect.** No edge in the lexical graph.

### DOTNET-INGRESS-SHAPES

**Trigger.** Minimal-API inline lambdas, top-level statements, Blazor, gRPC, SignalR.

**Effect.** No ingress recognized (lexical graph roots empty for top-level-statement programs).

### DOTNET-UNPINNED-VERSION

**Trigger.** No restore output and no lockfile, with `Version="x"` (a minimum) or a range/float.

**Effect.** Version UNRESOLVED; no version-based disqualification and no clear.

### DOTNET-BUILD-INPUT-UNMODELED

**Trigger.** `Directory.Build.rsp`, `<proj>.user`, `project.json`, `packages.*.lock.json`, unevaluated conditions, stale lockfile/restore output.

**Effect.** Resolver withholds (`build_input_unmodeled`, `lockfile_stale`, `restore_output_stale`, ...).

### DOTNET-SINGLE-TFM-RID

**Trigger.** Multi-targeted projects, or RID-dependent restore.

**Effect.** `multi_target_framework` declared; runtime_identifier_unknown/ambiguous withholds the IL search.

### DOTNET-IL-DISPATCH-SLOT

**Trigger.** Any virtual call.

**Effect.** Over-approximate fan-out by method slot (sound; extra paths and more undetermined).

### DOTNET-TAINT-PATH-PRESENCE

**Trigger.** Any taint query.

**Effect.** Call-graph path presence, not value flow or sanitizer awareness.

### DOTNET-SYMBOL-SPELLING

**Trigger.** SCIP symbols use a local placeholder coordinate (`scip-dotnet nuget . . Ns/Type#Method(arity).`).

**Effect.** Symbol matching against external symbol sources does not apply.

### DOTNET-FLOOR-NOT-COVERAGE

**Trigger.** Advisory source is the built-in floor.

**Effect.** 3 advisories only; real coverage comes from the external opt-in corpus.
