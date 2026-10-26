# Kotlin capabilities

Every feature in every capability group for Kotlin, with its status and the caveats that bound it. The [overview](README.md) explains the groups, statuses and stages.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 2 / 🟨 2 / 🟥 1 | 🟩 4 / 🟨 0 / 🟥 0 | 🟩 4 / 🟨 1 / 🟥 1 | 🟩 4 / 🟨 4 / 🟥 0 | 🟩 5 / 🟨 2 / 🟥 0 | 🟩 3 / 🟨 6 / 🟥 1 | 🟩 2 / 🟨 1 / 🟥 1 | 🟩 2 / 🟨 1 / 🟥 0 |

🟩 Complete or N/A, 🟨 Partial, 🟥 Planned.

## 1. Dependency inventory

Kotlin takes its dependency inventory from the build graph that Maven or Gradle resolved for the repository, through the shared JVM inventory engine. The inventory is what the dependency closure and version clearing build on.

| Feature | Status | Caveats |
|---|---|---|
| Inventory from the build-tool-resolved graph (Maven + Gradle) | Complete | [KOTLIN-BUILD-GRAPH-ABSENT](#kotlin-build-graph-absent) |
| Gradle lockfiles / start-script classpath as inventory source | N/A | the graph supersedes them; no file reads remain |
| Multi-module / composite builds | Partial | [KOTLIN-MULTI-PROJECT](#kotlin-multi-project) |
| Build of the other tool beside the graph's | Partial | [KOTLIN-BUILD-GRAPH-ABSENT](#kotlin-build-graph-absent) |
| SBOM emission | Planned |  |

## 2. Version clearing

Versions are the ones the build tool resolved, read from the graph; a coordinate resolved at more than one runtime version is reported ambiguous rather than guessed.

| Feature | Status | Caveats |
|---|---|---|
| Graph-resolved versions (catalogs, platforms, force, profiles included) | Complete | [KOTLIN-BUILD-GRAPH-ABSENT](#kotlin-build-graph-absent) |
| Disagreeing modules reported honestly | Complete |  |
| No graph => declared, no version guessed | Complete |  |
| Maven range / ordering schemes | Complete |  |

## 3. Build-graph fidelity

The host runs the repository's own Maven or Gradle to produce an `assay.buildgraph/v2` graph, validated against the checkout before the plugin sees it. Scope, node set, versions and artifact files all come from it; JARs are read only while their sha256 still matches the graph.

| Feature | Status | Caveats |
|---|---|---|
| Build-tool-resolved graph as the only dependency source | Complete | [KOTLIN-BUILD-GRAPH-ABSENT](#kotlin-build-graph-absent) |
| Runtime classpath selection with digest check | Complete |  |
| Runtime JDK from the graph | Complete |  |
| Launch options / agents withheld | Complete |  |
| Scopes (test, kapt, ksp excluded), private registries, vendoring | Partial | [KOTLIN-BUILD-GRAPH-ABSENT](#kotlin-build-graph-absent) |
| delete the static build model | Planned |  |

## 4. Call graph

The call graph is built from bytecode with class-hierarchy analysis (CHA) over the first-party program and its dependency closure. Calls resolve to the declared owner; Spring bean wiring adds edges. Kotlin file facades (`FooKt`), `$default` and `access$` members are marked generated in the symbol identity.

| Feature | Status | Caveats |
|---|---|---|
| First-party bytecode ingestion (Gradle/Maven/IDE layouts) | Partial | [KOTLIN-BUILD-OUTPUT-LAYOUT](#kotlin-build-output-layout) |
| Dependency JAR ingestion (CHA over closure) | Complete |  |
| Symbol identity incl. Kotlin facades, `$default`, `access$` | Complete |  |
| Advisory symbol resolution against the graph's dependency JAR | Partial | [KOTLIN-SYMBOL-NAME-FORM](#kotlin-symbol-name-form) |
| Spring DI edges (unique resolution only) | Complete |  |
| CallGraph op: indy edges dropped, `dynamic_dispatch` declared | Partial | [KOTLIN-CALLGRAPH-OP-INDY](#kotlin-callgraph-op-indy) |
| Multi-release JAR overrides | Partial | [KOTLIN-MULTI-RELEASE](#kotlin-multi-release) |
| `@kotlin.Metadata` awareness | N/A | JVM semantics are complete in bytecode; metadata only carries source-level names |

## 5. Reachability clearing

A sink is Searched, and so eligible for `not_exploitable`, only when a hazard-free search from a named first-party `main` root finds nothing and no other withholding reason applies. Otherwise the verdict is Undetermined with the reason attached. Framework roots yield candidates or Undetermined, never a clear.

| Feature | Status | Caveats |
|---|---|---|
| Reachable verdict with ordered path | Complete |  |
| Searched / empty clear with positive grounds | Complete |  |
| Launch-entry licence (named first-party main class required) | Partial | [KOTLIN-LAUNCH-ENTRY](#kotlin-launch-entry) |
| Root = `main(String[])` and Kotlin `fun main()` (`()V`) | Complete |  |
| Abstract / boot-only sinks never cleared | Partial | [KOTLIN-ABSTRACT-SINK](#kotlin-abstract-sink) |
| Static/companion initializer roots | Complete |  |
| Split-package / duplicate-class handling | Complete |  |

## 6. Framework & dynamic-dispatch modeling

Ingress is recognized from bytecode annotations through the shared registry: Spring MVC mappings (with class-level prefix), JAX-RS, `@Scheduled`, `@EventListener`, lifecycle callbacks, Kafka/JMS/Rabbit listeners and servlets. Spring DI is overlaid on first-party classes. The engine resolves lambda and string-concatenation `invokedynamic` sites to their real targets.

| Feature | Status | Caveats |
|---|---|---|
| Spring MVC / JAX-RS / scheduler / event / messaging ingress | Complete |  |
| Servlet ingress (direct `HttpServlet` subclass) | Partial | [KOTLIN-SERVLET-TRANSITIVE](#kotlin-servlet-transitive) |
| Spring bean wiring; ambiguity declared | Complete |  |
| Ktor, Micronaut, Quarkus, http4k, Vert.x, Android entry points | Planned |  |
| Lambda sites (`LambdaMetafactory.metafactory` / `altMetafactory`) | Complete |  |
| String-template sites (`StringConcatFactory.makeConcat` / `makeConcatWithConstants`) | Partial | [KOTLIN-DYNAMIC-DISPATCH](#kotlin-dynamic-dispatch) |
| Other bootstraps (e.g. `ObjectMethods`, `SwitchBootstraps`, unknown), missing bootstrap entry | Partial | [KOTLIN-DYNAMIC-DISPATCH](#kotlin-dynamic-dispatch) |
| Reflection | Partial | [KOTLIN-DYNAMIC-DISPATCH](#kotlin-dynamic-dispatch) |
| Coroutines (suspend lambdas, `invokeSuspend`) | Partial | [KOTLIN-COROUTINES](#kotlin-coroutines) |
| Inline functions | Partial | [KOTLIN-INLINE](#kotlin-inline) |

## 7. Hazard bounding

Engine hazards (reflection, unresolved invokedynamic, native, unloaded dependency, re-entry, unknown receiver) are scoped to the reachable frontier, so a hazard in code the search cannot reach from the root does not block a clear. Build-shape reasons (multi-project, launch entry, graph absent, other-tool build, launch options) are run-wide. The Kotlin clear rate has not been measured on a reference set.

| Feature | Status | Caveats |
|---|---|---|
| Frontier-scoped engine hazards | Complete |  |
| Scoped dependency-closure reasons (`Targets`) | Complete |  |
| Typical-project clear rate | Planned | unmeasured |
| Calls into classes absent from the linked classpath raise `unloaded_dependency` | Partial | [KOTLIN-UNLOADED-DEP](#kotlin-unloaded-dep) |

## 8. Runtime confirmation

The Kotlin lane produces the build manifest and symbol evidence the paid tier consumes; the exploit proof runs in the Prove-tier sandbox rather than as an in-lane harness.

| Feature | Status | Caveats |
|---|---|---|
| BuildManifest | Complete |  |
| GenerateHarness | N/A | JVM effect proof runs in the Prove-tier sandbox |
| Taint (call-graph path presence from ingress) | Partial | [KOTLIN-TAINT-PATH-ONLY](#kotlin-taint-path-only) |

## Caveats

### KOTLIN-MULTI-PROJECT

**Trigger.** Gradle `include`/`includeBuild`, Maven `<module>`, or any subdirectory (depth <= 6) with build output or a build file next to `src`.

**Effect.** `multiple_projects_unsupported`; no sink is cleared anywhere in the run (run-wide Undetermined).

### KOTLIN-LAUNCH-ENTRY

**Trigger.** No literal `mainClass`/`mainClassName`/`Main-Class`/`start-class` the interim check accepts: Spring Boot `main` with no configured mainClass, Ktor `EngineMain`, WAR packaging, container-callback class, unnamed launcher. The check still reads `build.gradle(.kts)`, `pom.xml`, start scripts and manifests (not the build graph).

**Effect.** `relationship_unexpressed:{launch_entry_unnamed|launch_entry_unmapped|war_packaging|container_callback}`; run-wide withhold of Searched (reachable verdicts unaffected).

### KOTLIN-BUILD-GRAPH-ABSENT

**Trigger.** The host cannot produce a build graph (no toolchain, JDK mismatch, a registry refusing credentials, a step failing), the scan runs with the graph off, or a build of the other tool sits beside the graph's build.

**Effect.** `tool_failure:build_graph_absent` or `other_tool_build`; run-wide, no dependency is loaded and no Searched. Resolution and symbol ops declare partial.

### KOTLIN-DYNAMIC-DISPATCH

**Trigger.** A reachable method contains an `invokedynamic` site the engine does not resolve, or reflection. Resolved: `LambdaMetafactory.metafactory/altMetafactory` (Kotlin 2.x indy lambdas, SAM conversions) and `StringConcatFactory.makeConcat/makeConcatWithConstants` (string templates at jvmTarget >= 9). Still hazards: any other bootstrap or a site without a bootstrap entry, reflection, and string-concat arguments whose `toString` cannot be resolved: an `Object`/`Any`-typed or JDK-collection-typed template argument is an out-of-classpath receiver, so Undetermined.

**Effect.** Depreach hazard (frontier-scoped) makes the search Undetermined with `reachability_undetermined`, plus `dynamic_dispatch`/`reflection` reasons.

### KOTLIN-CALLGRAPH-OP-INDY

**Trigger.** Any `CallGraph` op request over code containing `invokedynamic`.

**Effect.** The CallGraph op (not Reachability) drops every `EdgeDynamic` edge, including lambda and string-concat sites the engine resolves, and declares `dynamic_dispatch`. The graph is declared incomplete, never silently so; callers using it as a complete graph get fewer edges than Reachability sees.

### KOTLIN-COROUTINES

**Trigger.** Suspend functions / coroutine builders on the path.

**Effect.** Suspend lambdas compile to `SuspendLambda` subclasses reached via `resumeWith`; the manifest declares `coroutine_dispatch` as a boundary but no code signal exists, so the outcome rides generic hazards or stdlib load state.

### KOTLIN-INLINE

**Trigger.** Calls to Kotlin `inline` functions (stdlib or library).

**Effect.** Bodies are copied into the caller's bytecode, so calls inside appear as ordinary edges; the declared `inline_function` boundary has no emitted signal. Risk is symbol identity (an advisory naming an inline function that leaves no call to its own symbol), not missed edges.

### KOTLIN-BUILD-OUTPUT-LAYOUT

**Trigger.** Build output not under `build/classes/kotlin/main`, `build/classes/java/main`, `target/classes`, `out/production/classes`: KMP JVM targets, Android variants, custom source sets.

**Effect.** `tool_failure:no_build_output`; no program loaded, no clear.

### KOTLIN-UNLOADED-DEP

**Trigger.** First-party or dependency code calls a class neither loaded nor platform on a linked classpath.

**Effect.** The `unloaded_dependency` hazard makes the search Undetermined.

### KOTLIN-JAR-UNREADABLE

**Trigger.** A runtime JAR the graph names is missing, unreadable, changed since resolution (digest mismatch), or partly unparseable; or duplicate class across JARs.

**Effect.** Scoped `tool_failure`/`duplicate_class`/`runtime_version_ambiguous`/`no_dependency_artifact` bounded to the affected closure targets; other sinks unaffected.

### KOTLIN-SYMBOL-NAME-FORM

**Trigger.** Advisory symbol that names a Kotlin top-level function or property by its source name rather than the JVM facade (`FooKt`) name.

**Effect.** `advisory_symbol_unresolved` (honest, Undetermined). Matching is package-qualified dotted names ignoring descriptors.

### KOTLIN-MULTI-RELEASE

**Trigger.** A first-party root, first-party JAR or loaded dependency JAR with `META-INF/versions/N` overrides.

**Effect.** Base class read only; `tool_failure:multi_release_override_unread` declared, withholding Searched.

### KOTLIN-SERVLET-TRANSITIVE

**Trigger.** Servlet reached through an intermediate base class not named `*HttpServlet` directly.

**Effect.** Not recognized as ingress; affects candidates/taint, not the main-gated clear.

### KOTLIN-ABSTRACT-SINK

**Trigger.** Advisory sink is abstract, or only a boot-only copy exists.

**Effect.** Never searched; an empty result is Undetermined.

### KOTLIN-TAINT-PATH-ONLY

**Trigger.** Any taint query.

**Effect.** Result is call-graph path presence from ingress, not value flow; `PrecisionNote` always set.
