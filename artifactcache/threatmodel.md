# artifactcache threat model

Scope: the `artifactcache.Store` content-addressed read seam (PLAN-002, Phase 0) and the
acquisition seam it defers to PLAN-200 (Phase 2). `Store.Lookup` is a pure
content-addressed read: it never blocks on the network and never touches a credential,
returning `ErrDeclaredAbsent` on a miss. The ACQUIRER — the thing that fetches an artifact
from a third-party registry (Maven Central, npm, PyPI, NuGet) or a customer private
registry, and therefore holds a credential — is a separate seam that lands in PLAN-200.
This document scores both halves so PLAN-200 inherits the analysis; entries flagged
`(PLAN-200)` describe the acquisition seam that is sketched, not landed, here.

## Assets

- **The cached artifact bytes.** The locally-cached dependency artifact a `Handle`
  exposes. It is untrusted third-party code and, to the cache, is inert data.
- **The customer private-registry credential (PLAN-200).** The credential the Acquirer
  would hold to fetch from a customer's private Maven/npm/PyPI/NuGet registry. It does not
  exist in the Phase-0 read seam; it is a new asset at risk that arrives with PLAN-200.

## Scored threats

1. **Untrusted-artifact execution.** A fetched dependency artifact is untrusted
   third-party code. To the cache it is INERT DATA: `Handle` exposes `io.ReaderAt`,
   `Path`, `Size`, and `io.Closer` and no execution capability — no `Run`/`Exec`/`Start`/
   `Command`/open-for-write. The only sanctioned execution anywhere in Assay is the
   microVM/sandbox detonation; a dependency artifact is never run outside it.
   **Mitigation:** the mechanical no-execution test (`noexec_test.go`) walks the `Store`
   and `Handle` method sets and fails if any method name reads as execution or any
   parameter/return type is `*exec.Cmd` or satisfies `interface{ Run() error }`, plus the
   exported `ConformanceTest` harness that asserts zero process spawns during a
   Lookup-and-read. A future author cannot add an exec method to `Handle` without going
   red.

2. **Cache / supply-chain integrity.** A cache — or a third-party registry (PLAN-200) —
   may serve wrong or tampered bytes. The third-party package registries the Acquirer
   would reach (Maven Central, npm, PyPI, NuGet) are a DISTINCT supply-chain surface from
   the GitHub and public-OSV endpoints Assay already uses: they deliver untrusted
   third-party bytes rather than first-party GitHub/OSV data. **Mitigation:** `ref.Digest`
   is BOTH the content-address AND the integrity check — content whose hash does not match
   `ref.Digest` is rejected, exactly as the advisory corpus verifies each record's
   `sha256:<hex>` on every read (`pipeline/advisory_source.go:721`). A cache serving the
   wrong bytes fails the digest and is refused.

3. **Credential trust boundary (PLAN-200 Acquirer).** Holding a customer's private-registry
   credential is a NEW asset at risk, distinct from the short-lived, GitHub-scoped GitHub
   App installation token Assay already carries. A leaked registry credential grants an
   attacker standing access to the customer's private package registry. **Mitigation:**
   inherit the `checkout.Credential` posture verbatim — the token is an unexported field
   (`checkout/credential.go:16`), `String()`/`GoString()` REDACT under every fmt verb so a
   stray `%v`/`%s`/`%#v` cannot leak it (`credential.go:29`), it is carried in-process only
   and request-scoped via context (`WithCredential`/`CredentialFrom`), never written to
   disk, never placed in a URL or a process argv, never logged, and never reaches the
   `report.Report` or any persisted statestore tree.

4. **Path traversal.** A crafted PURL or digest must not let a lookup escape the cache
   root and read or write an arbitrary host path. **Mitigation:** the content-addressed
   local path is derived from the (validated) `ref.Digest`, not from attacker-controlled
   PURL path segments; the digest is a fixed-shape `algorithm:hex` string, so a lookup
   cannot be steered outside the cache root.

## Explicitly NOT a threat

**Egress is not, by itself, a threat.** Zero-egress means Assay does not exfiltrate the
customer's code, data, or keys back to Ferralon — not that the scanner makes no network
calls. Fetching an artifact from a public registry is sanctioned CI behavior, categorically
like the scanner-tarball download and advisory-corpus clone Assay already performs. The
cost to score is CREDENTIALS and THIRD-PARTY SUPPLY-CHAIN integrity (scored threats 2 and
3 above), never "this adds a network call." (Eric's ruling, 2026-08-06.)

The reciprocal — the actual zero-egress boundary — is exfiltration of Assay's own output:
its results carry sensitive findings about the customer's systems, which is why that output
must not leave the customer's trust boundary unredacted (`.github/SECURITY.md:21-30`). That
exfiltration boundary is the thing zero-egress protects; a sanctioned artifact fetch is not
a breach of it.
