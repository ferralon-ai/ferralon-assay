# Language capability matrix

Ferralon Assay analyzes Go, Java, Kotlin, JavaScript/TypeScript, Python and .NET repositories in your CI build. Each language advances through eight capability groups, from reading the dependency inventory to handing a reachable path to runtime confirmation, and each group unlocks a stronger verdict. The matrix below shows where every language stands today. Each language page lists every feature in every group with its status and names the caveats that bound it. The matrix moves with every release.

## Capability groups

| # | Group | What it unlocks |
|---|---|---|
| 1 | Dependency inventory | Every package in the build is a named node: the SBOM, and a place to attach each advisory. |
| 2 | Version clearing | An advisory is `disqualified` when the resolved version sits outside its affected range. |
| 3 | Build-graph fidelity | The inventory and versions are the ones your build actually uses: scopes, overrides, registries, platforms. |
| 4 | Call graph | First-party and dependency code become one searchable graph, so a path to an advisory's symbol can be found. |
| 5 | Reachability clearing | A completed search with no path yields `not_exploitable`, on named positive grounds. |
| 6 | Framework & dynamic-dispatch modeling | Framework entry points, dependency injection and dynamic calls are modeled, so real applications are searched from their real entry points. |
| 7 | Hazard bounding | A limit withholds only the verdicts it could affect, so a typical project receives `not_exploitable` verdicts. |
| 8 | Runtime confirmation | Candidate paths and sink coordinates hand off to Ferralon's runtime proof. |

**Status values.** `Complete`: the feature works for its stated scope. `Partial`: it works, with named caveats. `Planned`: it is not built yet. `N/A`: it does not apply to the language's architecture.

Go's call graph is built from whole-build SSA that spans first-party and dependency source, and 6 of its 7 call-graph features are Complete (group 4). Each language page lists the same detail for its own lane.

## Matrix

| Language | 1 Inventory | 2 Versions | 3 Build graph | 4 Call graph | 5 Clearing | 6 Frameworks | 7 Hazard bounding | 8 Runtime handoff |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| [Go](go.md) | 🟩 5 / 🟨 4 / 🟥 0 | 🟩 3 / 🟨 2 / 🟥 0 | 🟩 3 / 🟨 4 / 🟥 0 | 🟩 6 / 🟨 1 / 🟥 0 | 🟩 4 / 🟨 6 / 🟥 0 | 🟩 4 / 🟨 2 / 🟥 3 | 🟩 1 / 🟨 4 / 🟥 0 | 🟩 2 / 🟨 0 / 🟥 1 |
| [Java](java.md) | 🟩 3 / 🟨 3 / 🟥 2 | 🟩 4 / 🟨 1 / 🟥 0 | 🟩 3 / 🟨 3 / 🟥 0 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 4 / 🟨 3 / 🟥 1 | 🟩 1 / 🟨 5 / 🟥 3 | 🟩 3 / 🟨 3 / 🟥 1 | 🟩 1 / 🟨 0 / 🟥 1 |
| [Kotlin](kotlin.md) | 🟩 1 / 🟨 2 / 🟥 1 | 🟩 4 / 🟨 0 / 🟥 0 | 🟩 4 / 🟨 1 / 🟥 0 | 🟩 3 / 🟨 4 / 🟥 0 | 🟩 5 / 🟨 2 / 🟥 0 | 🟩 3 / 🟨 6 / 🟥 1 | 🟩 2 / 🟨 1 / 🟥 1 | 🟩 1 / 🟨 1 / 🟥 0 |
| [JavaScript / TypeScript](javascript.md) | 🟩 5 / 🟨 2 / 🟥 2 | 🟩 1 / 🟨 3 / 🟥 1 | 🟩 1 / 🟨 6 / 🟥 1 | 🟩 4 / 🟨 6 / 🟥 0 | 🟩 3 / 🟨 0 / 🟥 2 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 3 / 🟥 1 | 🟩 0 / 🟨 3 / 🟥 1 |
| [Python](python.md) | 🟩 4 / 🟨 4 / 🟥 1 | 🟩 4 / 🟨 4 / 🟥 1 | 🟩 1 / 🟨 1 / 🟥 1 | 🟩 5 / 🟨 4 / 🟥 0 | 🟩 2 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 2 / 🟥 2 | 🟩 1 / 🟨 2 / 🟥 1 | 🟩 2 / 🟨 0 / 🟥 0 |
| [.NET](dotnet.md) | 🟩 2 / 🟨 2 / 🟥 1 | 🟩 3 / 🟨 2 / 🟥 3 | 🟩 1 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 5 / 🟥 1 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 1 / 🟨 4 / 🟥 2 | 🟩 0 / 🟨 3 / 🟥 1 | 🟩 0 / 🟨 1 / 🟥 3 |

Each cell reads `C / P / L`, counted from the language page's feature table for that group: 🟩 C = Complete, 🟨 P = Partial, 🟥 L = Planned. Features marked N/A do not apply to the language and are not counted.

### Binding caveats

A binding caveat withholds `not_exploitable` across the whole run when a project triggers it. † marks a caveat that applies to every project in the ecosystem today.

| Language | Binding caveats |
|---|---|
| Go | [GO-REFLECT-CALL](go.md#go-reflect-call), [GO-CGO](go.md#go-cgo), [GO-WORKSPACE](go.md#go-workspace), [GO-PLUGIN-LOAD](go.md#go-plugin-load) |
| Java | [JAVA-MULTI-MODULE-NO-SEARCH](java.md#java-multi-module-no-search), [JAVA-LAUNCH-ENTRY-UNLICENSED](java.md#java-launch-entry-unlicensed), [JAVA-FRAMEWORK-HAZARD](java.md#java-framework-hazard), [JAVA-GRAPH-PRECONDITION](java.md#java-graph-precondition), [JAVA-OTHER-TOOL-BUILD](java.md#java-other-tool-build) |
| Kotlin | [KOTLIN-MULTI-PROJECT](kotlin.md#kotlin-multi-project), [KOTLIN-LAUNCH-ENTRY](kotlin.md#kotlin-launch-entry), [KOTLIN-BUILD-GRAPH-ABSENT](kotlin.md#kotlin-build-graph-absent), [KOTLIN-BUILD-OUTPUT-LAYOUT](kotlin.md#kotlin-build-output-layout) |
| JavaScript / TypeScript | [JS-UNINSPECTABLE-RUNWIDE](javascript.md#js-uninspectable-runwide), [JS-NO-CLEAR-GROUNDS](javascript.md#js-no-clear-grounds)†, [JS-LOADTIME-CODEGEN](javascript.md#js-loadtime-codegen) |
| Python | [PYTHON-NO-CLEAR-PRODUCER](python.md#python-no-clear-producer)†, [PYTHON-UNREAD-SURFACE-RUNWIDE](python.md#python-unread-surface-runwide), [PYTHON-DYNAMIC-IMPORT-RUNWIDE](python.md#python-dynamic-import-runwide), [PYTHON-SCRIPT-INSTALL-WITHHOLD](python.md#python-script-install-withhold) |
| .NET | [DOTNET-IL-FRAMEWORK-HAZARD](dotnet.md#dotnet-il-framework-hazard)†, [DOTNET-MULTI-PROJECT](dotnet.md#dotnet-multi-project), [DOTNET-IL-NO-MAIN](dotnet.md#dotnet-il-no-main), [DOTNET-IL-REQUIRES-BUILD-OUTPUT](dotnet.md#dotnet-il-requires-build-output), [DOTNET-DEP-ARTIFACT-MISS](dotnet.md#dotnet-dep-artifact-miss) |

## Caveats

A caveat is a named, stable ID such as `GO-REFLECT-CALL` or `KOTLIN-MULTI-PROJECT`. Each language page states the caveat's trigger (the code or project shape that activates it) and its effect on the verdict, and links it from every feature it bounds.

## Verdicts and scope

The five verdict values, and how they map to OpenVEX, are in [Language support](../language-support.md#verdicts).

C/C++ is in development and is not in the scanner release asset. A scan of a C/C++ tree stops at the empty-work-set gate and fails the run, so it never publishes a Report that reads as clean.
