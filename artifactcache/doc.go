// Package artifactcache defines the content-addressed, read-through view a lane's
// dependency indexer uses to reach the exact selected artifact bytes, keyed by
// PURL + integrity digest. It is a stdlib-only leaf package (context, io, errors):
// it imports neither plugin nor any internal/plugin/* indexer, so the dependency
// flows strictly indexer -> artifactcache -> stdlib and cannot cycle.
//
// # Acquisition-agnostic
//
// Store.Lookup is a pure content-addressed read. It never blocks on the network and
// never touches a credential: on a miss it returns ErrDeclaredAbsent, the honest
// Phase-1 answer (nothing has acquired this artifact yet), NOT a failure. The
// ACQUIRER — the thing that fetches from a third-party registry (Maven Central, npm,
// PyPI, NuGet) or a customer private registry, and therefore holds a credential — is
// a SEPARATE seam that lands in PLAN-200. Keeping acquisition out of this interface
// locates the credential trust boundary and the third-party supply-chain surface
// entirely in that later seam (see threatmodel.md), while letting a Phase-1 lane code
// against Store today: every Lookup simply returns ErrDeclaredAbsent.
//
// # Inert Handle (mechanical no-execution)
//
// Lookup returns a Handle, not []byte and not a bare path string. Dependency
// artifacts are large binaries, so the inline-payload model does not transfer; a bare
// path would drop the capability guarantee. Handle is INERT: it exposes io.ReaderAt
// (pure-Go indexers read a zip central directory), Path (a foreign-toolchain indexer
// hands scip-java a jar on disk), Size, and io.Closer — and DELIBERATELY exposes no
// Run/Exec/Start/Command/Spawn/Fork and no open-for-write. A fetched dependency
// artifact is untrusted third-party code; to the cache it is inert data. That absence
// of an execution capability IS the no-execution guarantee, and it is pinned
// mechanically by the reflect-based test in this package (see noexec_test.go) plus the
// exported ConformanceTest harness that PLAN-200 impls run against. The only sanctioned
// execution anywhere in Assay is microVM/sandbox detonation, never here.
package artifactcache
