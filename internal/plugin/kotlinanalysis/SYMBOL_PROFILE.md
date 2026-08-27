# Kotlin canonical symbol profile

Cycle `2026-08-27_1344_kotlin-parity-lane`. Lane: kotlin. Package
`internal/plugin/kotlinanalysis/`.

This is the published profile of the Kotlin symbol identifier. Unlike the Java lane — whose
source-lexical producer collapses overloads to an arity count and cannot see `<init>` or
compiler synthetics — the Kotlin lane analyzes **JVM bytecode** (convergence A4), so every
identity below is the exact `classfile.MethodRef` a Java caller of the same class resolves.
That is the whole point: **a Kotlin-declared symbol normalizes to the identical
`plugin.Symbol` match key as its Java-visible form** (K4, the GRANITE interop seam). The
mapping is `symbol.go`'s `SymbolFromMethodRef` / `SymbolFromClass`; the executable proof is
`plugin/symboltest/kotlinref.go` + `kotlinref_test.go`.

## Identity model

Frozen `plugin.Symbol` match key = `Kind` / `Package` / `Enclosing` / `Name` / `Descriptor`
(`SCIP` and `DisplayName` are rendering-only, never the key). The Kotlin lane populates all
five structured fields directly from bytecode:

- **Package** — the internal owner name up to the last `/`, dotted (`com/example/kref` →
  `com.example.kref`). `splitInternalName`.
- **Enclosing** — for a method, the binary class name after the package, **`$`-preserved**
  (`UrlService$Companion`); for a type, its `$`-joined outer chain rendered `.`-joined
  (`splitNestedName`). The `$` is the JVM/interop truth both languages share.
- **Name** — the method/type name **verbatim**, including Kotlin mangling (`internal`→`-hash`,
  value-class `-impl`, `access$…`, `$default`). A Java caller must use the exact JVM name, so
  it is never stripped in the identity; only `DisplayName` is de-mangled.
- **Descriptor** — the **full JVM descriptor verbatim** (`(Ljava/lang/String;)V`). This is
  where the lane beats Java-source: same-name overloads separate by descriptor, never collapse
  to arity.
- **Generated** — `true` for every compiler synthetic: the `<File>Kt` facade class and its
  members, `$default` argument bridges, `access$` accessors (`isGeneratedClass` /
  `isGeneratedMember`).

## §4.3 categories (mirrors `KotlinReferenceProfile`, all must-match GREEN)

| Category | Kotlin construct | Bytecode form | Canonical `plugin.Symbol` |
|---|---|---|---|
| packages/modules | `package com.example.kref` | — | `Kind=package Package=com.example.kref` |
| types | `class UrlService` | `com/example/kref/UrlService` | `Kind=type Name=UrlService` |
| functions | top-level `fun topLevel(String)` | static method on `DemoKt` facade | `Kind=method Enclosing=DemoKt Name=topLevel Descriptor=(Ljava/lang/String;)V Generated=true` |
| methods | `UrlService.fetch(String): String` | instance method | `Kind=method Enclosing=UrlService Name=fetch Descriptor=(Ljava/lang/String;)Ljava/lang/String;` |
| constructors | `UrlService(String)` | `<init>` | `Kind=constructor Name=<init> Descriptor=(Ljava/lang/String;)V` |
| overloads/generics | `fetch(Int): String` | descriptor-distinct sibling | `Kind=method Name=fetch Descriptor=(I)Ljava/lang/String;` — **distinct** from `fetch(String)` |
| nested declarations | companion object | `UrlService$Companion` | `Kind=type Enclosing=UrlService Name=Companion Generated=true` |
| generated symbols | default-arg bridge | `topLevel$default` | `Kind=method Enclosing=DemoKt Name=topLevel$default Generated=true` |

**Kotlin-specific desugaring note:** Kotlin free functions have no bytecode of their own — a
top-level `fun` is lowered onto the file's `<File>Kt` facade as an ordinary static method. So
the "functions" category's canonical form is a `Generated=true` method on the facade class,
not a free function. This is the Java-visible truth (a Java caller writes `DemoKt.topLevel(…)`).

## Extension functions and companions (R3 specifics)

- **Extension function** `fun String.ext()` compiles to a static method whose **receiver is
  parameter 0** of the descriptor — carried verbatim in `Descriptor`, no special handling.
- **Companion / object** members' declaring class is `Outer$Companion` / the object's own
  class, **not** the outer type — `Enclosing` keeps the `$Companion` segment.
- **Coroutines / `suspend`** add a trailing `Continuation` param to the descriptor; a direct
  `suspend`→`suspend` call is an ordinary invoke and is sound. Resumption through a coroutine
  builder (`launch`/`async`/`withContext`) is dispatched by the runtime scheduler via
  `invokedynamic` — see partiality below.

## Partiality boundaries (declared, honest-absent — inv.5)

These are the frontiers where a sound static graph must fail OPEN toward candidate; each is a
`DynamicBoundaries` entry in `CapabilityManifest()` and, when it lies on a searched frontier,
a declared per-run partiality:

- **`invokedynamic`** (SAM conversion, lambda metafactory) — opaque callee; `CallGraph` drops
  the edge and raises `dynamic_dispatch`, `depreach` treats it as an undetermined hazard.
- **inline functions** — the call edge is *erased* at every call site (body copied inline), so
  absence of an edge is not absence of a call. Declared, never read as unreachable.
- **coroutine builder dispatch** — `invokeSuspend` is scheduler-dispatched, under-reporting
  reachability through builders.
- **reflection** — `depreach.isReflection` already forces undetermined.
- **Gradle build-file version resolution** — the JAR *locator* (`depcache.go`) supports both
  the Gradle module cache and Maven `.m2`; deriving a dependency's version from
  `build.gradle.kts` is deferred, so `ResolveDependencyVersions` declares `no_manifest`.
- **absent build output** — no compiled `.class` under the checkout → tool-unavailable
  partiality (`tool_failure:no_build_output`), never a confident-empty result.

`@kotlin.Metadata` is **not** read: raw bytecode identity is sufficient for Assess-tier
soundness (R3), and the classfile attributes table is a shared-file coordination point owned
outside this lane.
