// Package kotlinanalysis is the Kotlin language analyzer. Per the cycle's settled
// architecture (convergence amendment A4), Kotlin — first-party AND dependency code —
// is analyzed as JVM bytecode: the Kotlin compiler lowers every source construct to
// ordinary .class files, so the sound Assess-tier signal is the bytecode itself, not a
// Kotlin-source lexer.
//
// It therefore REUSES the javaanalysis JVM substrate UNMODIFIED:
//
//   - internal/plugin/javaanalysis/classfile — the pure-Go .class parser (ParseClass /
//     LoadJar), whose method Code edges (EdgeStatic/Special/Virtual/Interface/Dynamic)
//     are already what a call graph needs;
//   - internal/plugin/javaanalysis/depreach — the CHA + two-trace proof-of-non-
//     exploitability engine, which consumes Kotlin .class bytecode unchanged.
//
// It does NOT reuse javaanalysis's callgraph/ingress/reachability/taint code: those walk
// .java-suffixed SOURCE and see zero Kotlin. This package writes Kotlin-native equivalents
// over bytecode instead.
//
// Honest-absent is the governing invariant (inv.5). First-party code is read from the
// compiled .class BUILD OUTPUT (build/classes/kotlin/main, build/libs/*.jar, target/classes,
// …); when no build output is present the analyzer emits a declared tool-unavailable
// partiality, never a confident-empty result. An opaque invokedynamic edge (coroutine-
// builder dispatch, inline-lambda SAM conversion) is treated as evidence that fails OPEN
// toward candidate, never as "no path" — depreach already enforces this and this package
// declares the boundary in its capability manifest.
//
// The Kotlin symbol identity is JVM-canonical (see symbol.go): the same bytecode a Java
// caller would see, so a Kotlin-declared symbol resolves EQUAL to its Java-visible form
// (the interop seam K4/GRANITE rides). @kotlin.Metadata is deliberately NOT read — raw
// bytecode identity is sufficient for Assess-tier soundness (research R3), and the
// classfile attributes table is a shared-file coordination point owned elsewhere.
package kotlinanalysis
