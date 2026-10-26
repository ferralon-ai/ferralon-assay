# Java capabilities

Every feature in every capability group for Java, with its status and the caveats that bound it. The [overview](README.md) explains the groups, statuses and stages.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 3 / 🟨 3 / 🟥 2 | 🟩 4 / 🟨 1 / 🟥 0 | 🟩 3 / 🟨 3 / 🟥 0 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 5 / 🟨 3 / 🟥 1 | 🟩 1 / 🟨 5 / 🟥 3 | 🟩 3 / 🟨 3 / 🟥 1 | 🟩 2 / 🟨 0 / 🟥 1 |

🟩 Complete or N/A, 🟨 Partial, 🟥 Planned.

## 1. Dependency inventory

Java dependencies come from the repository's own Maven or Gradle build: Assay asks the build tool for the resolved graph, binds the result to the checkout by the sha256 of every build input, and renders the inventory from it, with module, scope and coordinate for every install. Kotlin delegates to the same reader.

| Feature | Status | Caveats |
|---|---|---|
| Maven and Gradle resolved-graph inventory (modules, scopes, transitives) | Complete |  |
| Graph binding to checkout (input digests, module paths, node files; v1 graphs rejected) | Complete |  |
| Graph production (`-build-graph auto\|<path>\|off`, `resolve-graph` subcommand) with typed failures | Partial | [JAVA-GRAPH-PRECONDITION](#java-graph-precondition) |
| Completeness (`Graph.Complete` earned only when every install path is observed) | Partial | [JAVA-INSTALL-UNLISTED](#java-install-unlisted), [JAVA-OTHER-TOOL-BUILD](#java-other-tool-build) |
| Maven/Gradle multi-module and Gradle included builds | Complete |  |
| Inventory without a graph | Partial | [JAVA-GRAPH-PRECONDITION](#java-graph-precondition) |
| Gradle file dependencies, Android toolchain | Planned | Android JDK toolchain never known |
| Action inputs for graph/JDK/profiles | Planned | set env in the step meanwhile |

## 2. Version clearing

A dependency is cleared on version when the resolved version sits outside every affected range of the advisory. The resolved version comes from the graph; the comparison is a Maven ComparableVersion port.

| Feature | Status | Caveats |
|---|---|---|
| Resolved version lookup across modules and scopes (match only when all copies agree) | Complete | disagreement returns unresolved, never guesses |
| Maven version ordering (ComparableVersion port) | Complete | [JAVA-VERSION-GRAMMAR](#java-version-grammar) (fails open, never clears) |
| Range bounds (lower-inclusive/upper-exclusive; last-affected-only and lower-only never clear; GIT ranges prove nothing) | Complete |  |
| End-to-end disqualification on patched version | Complete |  |
| Provided-scope and loaded-GAV cross-check | Partial | [JAVA-PROVIDED-SCOPE](#java-provided-scope) |

## 3. Build-graph fidelity

The graph is what the repo's own build resolved, under a stated JDK and profile set, so BOMs, exclusions, dependency management, and repository configuration are the build's own decisions rather than a reimplementation.

| Feature | Status | Caveats |
|---|---|---|
| Build-tool-resolved graph (Maven, Gradle) | Complete |  |
| JDK and profile binding (mismatch fails closed) | Complete |  |
| Private registries / credentials | Partial | [JAVA-GRAPH-PRECONDITION](#java-graph-precondition) (typed `credentials` failure, no fallback) |
| Gradle detached configs, unknown task types, unknown Maven plugin goals | Partial | [JAVA-INSTALL-UNLISTED](#java-install-unlisted) (withholds Complete) |
| Vendored/checked-in archives | Complete | positively detected, withholds Complete |
| Real-tool end-to-end | Partial | real-tool tests are not part of the default CI run |

## 4. Call graph

Two graphs. First-party source gets a lexical declaration parser; compiled output, dependency JARs and the JDK get a bytecode class-hierarchy (CHA) graph. Only the bytecode graph can support a clear.

| Feature | Status | Caveats |
|---|---|---|
| First-party lexical graph (simple name + arity; ambiguous calls become `dynamic_dispatch`) | Partial | [JAVA-LEXICAL-INITIALIZERS](#java-lexical-initializers), [JAVA-LEXICAL-ARITY-ONLY](#java-lexical-arity-only) |
| SCIP via scip-java (optional, container, Prove path) | Partial | [JAVA-SCIP-OPTIONAL](#java-scip-optional) |
| First-party bytecode from build output (trusted only if covering the sources and newer) | Complete | else `first_party_bytecode_absent` |
| Dependency bytecode from graph JARs (digest recheck, multi-release) | Complete |  |
| CHA engine with JDK platform tables, lambdas, `<clinit>` and init closure, hidden-seed bounding in linked mode | Complete | [JAVA-CHA-IMPRECISION](#java-cha-imprecision) (precision, not soundness) |
| RTA, JDK receiver model | Planned | not in this release; design only |
| Dependency symbol resolution inside the dependency's own JAR | Complete |  |

## 5. Reachability clearing

`not_exploitable` is emitted only from a bytecode search that ran to completion with no path and no hazard on the frontier. A sink is Searched only when every main and mapped-ingress search is clean, the build names a first-party launch entry that licenses it, first-party bytecode is complete, no ingress is unmapped, no reasons remain, and the sink is concrete. The trigger then requires vetted symbols before it emits the ground.

| Feature | Status | Caveats |
|---|---|---|
| Searched gate (all conditions above) | Complete |  |
| Hazards block the clear (sound abstention to Undetermined) | Complete |  |
| Launch-entry licence (allowlist of entry forms, Spring Boot via `bootMain`) | Partial | [JAVA-LAUNCH-ENTRY-UNLICENSED](#java-launch-entry-unlicensed) |
| Multi-module builds | Partial | [JAVA-MULTI-MODULE-NO-SEARCH](#java-multi-module-no-search) |
| Trigger grounds, arm A (Searched + vetted symbol set) | Partial | [JAVA-VETTED-SYMBOLS](#java-vetted-symbols) |
| Trigger grounds, arm B (`ReachabilityResult.Refutation`) | N/A | Java sets none; arm A is the only route |
| Lexical-only path | Complete | a sink is never listed Searched on this path (by construction) |
| Reachable-candidate paths (first-party to sink) | Complete |  |
| Free-tier sound JVM verdicts | Planned |  |

## 6. Framework & dynamic-dispatch modeling

First-party Spring structure is modeled on the lexical side to add edges and partiality. On the bytecode side every framework channel (reflection, invokedynamic, generated proxies, ServiceLoader, JNDI, provider re-entry) is a hazard, so a framework app is sound but not yet clearable. Nothing modeled here can license a clear.

| Feature | Status | Caveats |
|---|---|---|
| Ingress recognition: servlet, route annotations, container entry points (lexical and SCIP recognizers kept in step) | Partial | [JAVA-INGRESS-LIST](#java-ingress-list) |
| Spring bean model and DI edge resolution (unique impl only; `bean_ambiguous` otherwise) | Partial | [JAVA-DI-LEXICAL-ONLY](#java-di-lexical-only) |
| AOP proxy overlay (`@Async`, `@Transactional`, `@Aspect` add partiality) | Partial | [JAVA-DI-LEXICAL-ONLY](#java-di-lexical-only) |
| SpEL / placeholder presence | Partial | [JAVA-DI-LEXICAL-ONLY](#java-di-lexical-only) |
| Reflection, invokedynamic, native, class-loading hazards | Complete | [JAVA-FRAMEWORK-HAZARD](#java-framework-hazard) (run-wide for framework apps) |
| Spring core contracts (lifecycle, events, scheduling roots/dispatchers) | Planned | not in this release; queued |
| Spring DI at bytecode level | Planned |  |
| Launch-config class names, CONSTANT_Dynamic | Planned |  |
| Annotation values: Java first-party from source (values blanked), Kotlin/deps from bytecode | Partial | [JAVA-ANNOTATION-VALUES-SOURCE](#java-annotation-values-source) |

## 7. Hazard bounding

Hazards are scoped per search: the first hazard on the frontier sets `HazardOnFrontier` and the kinds met are recorded per result (sink_not_loaded, ingress_not_found, native, invokedynamic, reflection, unloaded_dependency, reentry, unknown_receiver, other). The measured picture is that a Spring Boot application does not yet receive a clear, and the cause is hazard breadth on the frontier, not an unsound or missing model.

| Feature | Status | Caveats |
|---|---|---|
| Per-search hazard kinds reported (diagnosable) | Complete |  |
| Signature-bound provider roots (rule 1) | Complete |  |
| Link-bound loadability (rule 2) | Partial | [JAVA-HAZARD-BREADTH](#java-hazard-breadth) (any duplicate class disables rule 2 run-wide) |
| CHA hidden-seed bounding in linked mode | Partial | [JAVA-HAZARD-BREADTH](#java-hazard-breadth) |
| Multi-release merge for linking | Complete |  |
| JDK callback / receiver model | Planned | not in this release; JDK unknown receivers remain a hazard |
| Typical-project outcome | Partial | [JAVA-HAZARD-BREADTH](#java-hazard-breadth), [JAVA-FRAMEWORK-HAZARD](#java-framework-hazard) |

## 8. Runtime confirmation

The Java lane hands candidate paths and resolved sink coordinates to the paid tier, which proves them in the microVM runtime. The lane ships no harness generator by design.

| Feature | Status | Caveats |
|---|---|---|
| GenerateHarness | N/A | architectural: the JVM is proved by microVM execution, not a generated seed |
| Candidate path and symbol handoff to Prove | Complete |  |
| Runtime tracer oracle | Planned | not in this release |

## Caveats

### JAVA-GRAPH-PRECONDITION

**Trigger.** A scan with no build graph: toolchain absent, JDK mismatch, credentials missing for a private registry, or the build tool failing; also any Action user, since the Action has no inputs for graph/JDK/profiles (env only).

**Effect.** Typed failure, no fallback. Every op declares `tool_failure:build_graph_absent`; inventory is empty and no clear is possible.

### JAVA-INSTALL-UNLISTED

**Trigger.** A Gradle task outside the allowlist, a detached configuration, a Maven plugin goal outside the allowlist, an orphan build file, or checked-in archives.

**Effect.** The graph is not Complete; inventory and version results carry `unlisted_install`/`dependency_not_in_build`, so absence is never concluded.

### JAVA-OTHER-TOOL-BUILD

**Trigger.** Both a Maven and a Gradle build present in the checkout.

**Effect.** Every result partial (`other_tool_build`).

### JAVA-VERSION-GRAMMAR

**Trigger.** Version string outside `[0-9A-Za-z._+-]`.

**Effect.** Comparison fails open: not cleared.

### JAVA-PROVIDED-SCOPE

**Trigger.** A dependency in provided scope.

**Effect.** Treated as a runtime scope and searched at the declared version; loaded GAV not cross-checked against the admitted version.

### JAVA-LEXICAL-INITIALIZERS

**Trigger.** A call in a field initializer, static or instance initializer block.

**Effect.** No call site recorded in the lexical graph although the file counts as parsed.

### JAVA-LEXICAL-ARITY-ONLY

**Trigger.** Two same-name same-arity methods in the program.

**Effect.** The call stays `dynamic_dispatch` (Undetermined for lexical paths).

### JAVA-SCIP-OPTIONAL

**Trigger.** No scip-java available (Action without container).

**Effect.** Lexical call graph only on the Assess path; type resolution absent.

### JAVA-CHA-IMPRECISION

**Trigger.** Any dispatch closure with an unopened supertype.

**Effect.** Hidden subtypes seeded into every closure, widening the frontier and the hazard set.

### JAVA-MULTI-MODULE-NO-SEARCH

**Trigger.** A build with more than one module that has a `src` directory.

**Effect.** Falls back to the lexical lane; no sink is ever Searched, so no clear. Run-wide.

### JAVA-LAUNCH-ENTRY-UNLICENSED

**Trigger.** No build-named first-party main, WAR packaging, container callbacks, a launch entry set by profile, plugin, or CLI property, or an unmapped entry shape.

**Effect.** Searched withheld run-wide (`launch_entry_*`, `war_packaging`, `container_callback`); framework ingress roots never license.

### JAVA-VETTED-SYMBOLS

**Trigger.** An advisory without a vetted symbol set (not osv-declared, curated, or built-in).

**Effect.** The trigger does not emit `not_exploitable` even from a Searched result. The built-in Java advisory floor is 3 and is a floor, not coverage; real advisories come from the external opt-in corpus.

### JAVA-INGRESS-LIST

**Trigger.** A framework ingress not in the recognizer registry.

**Effect.** Unmapped ingress blocks Searched (sound) or the ingress is missed for candidate paths.

### JAVA-DI-LEXICAL-ONLY

**Trigger.** Spring injection with more than one implementation, AOP-wrapped target, or SpEL.

**Effect.** Lexical edges only add partiality (`bean_ambiguous`, `proxy_mediated`, `async_boundary`, `spel_present`); never licenses a clear.

### JAVA-FRAMEWORK-HAZARD

**Trigger.** A framework app whose search walks into reflection, invokedynamic, proxies, ServiceLoader, or provider re-entry (Spring `instantiateClass`, Jackson, Hibernate, Tomcat, Jersey bootstraps).

**Effect.** Undetermined, every sink. Run-wide for such apps. Deliberate: it is what keeps framework dispatch from producing a false clear.

### JAVA-HAZARD-BREADTH

**Trigger.** A Spring Boot application of realistic size.

**Effect.** The frontier meets hazards from unopened dependencies, JDK unknown receivers, and re-entry; result Undetermined.

### JAVA-ANNOTATION-VALUES-SOURCE

**Trigger.** Annotation-value-dependent feature (Qualifier, SpEL, Query) on Java first-party code.

**Effect.** Values blanked from source, so those features see presence only.
