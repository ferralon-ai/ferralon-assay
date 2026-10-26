# Ferralon Assay

Assay answers one question for each advisory in your dependency tree: **does this build actually reach the vulnerable code?**
It answers "not affected" only when it can name the fact that makes it true. When it can't, it says it doesn't know, and why.

"A vulnerable version is in your lockfile" is true and not very useful on its own: the advisory
names a few functions, and the question that decides your afternoon is whether anything you ship
calls them. Assay resolves your dependency versions, maps each advisory
onto the symbols it names, builds a call graph from your entry points, and reports what it found,
with the evidence attached. It runs in your own CI runner, reads your repository without executing
it (one exception for JVM builds, [below](#how-it-decides)), and never runs a model.

It scans **Go, Java, Kotlin, JavaScript/TypeScript, Python and .NET**.

## What a finding looks like

Real output, not a mock-up. This is Ferralon's public demo service,
[`ferralon-demo/demo-go-svc`](https://github.com/ferralon-demo/demo-go-svc) at `044d534`, a small Go
SSH/HTTP server pinned to `golang.org/x/crypto v0.30.0`. Scanned with `ferralon-assay` built from
this repository's `main` at `a368257`, against the public
[vulnerability corpus](https://github.com/ferralon-ai/vulnerability-corpus) at `8fd3b31`
(`-advisory-corpus <dir> -advisory-corpus-policy full`). Two findings from `report.json`, verbatim
except that the EPSS/KEV `priority` block is dropped:

```json
{
  "advisory": { "id": "CVE-2024-45337", "source": "ghsa", "aliases": ["GHSA-v778-237x-gjrc", "GO-2024-3321"] },
  "package": { "ecosystem": "Go", "name": "golang.org/x/crypto", "version": "v0.30.0",
               "purl": "pkg:golang/golang.org/x/crypto", "direct": false },
  "verdict": "reachable_candidate",
  "evidence": {
    "reachable_path": "entrypoint → advisory symbol",
    "reachability_grade": "control_flow_only",
    "entry_point": {
      "symbol": "scip-go gomod example.com/demo-go-svc . example.com/demo-go-svc/main().",
      "kind": "main",
      "attacker_controllable": false
    },
    "call_path": [
      { "symbol": "scip-go gomod example.com/demo-go-svc . example.com/demo-go-svc/main()." },
      { "symbol": "scip-go gomod example.com/demo-go-svc . example.com/demo-go-svc/serveSSH()." },
      { "symbol": "scip-go gomod example.com/demo-go-svc . example.com/demo-go-svc/handleSSHConn()." },
      { "symbol": "scip-go gomod golang.org/x/crypto v0.30.0 golang.org/x/crypto/ssh/NewServerConn()." }
    ]
  }
}
```

```json
{
  "advisory": { "id": "GO-2025-4116", "source": "osv", "aliases": ["CVE-2025-47913", "GHSA-56w8-48fp-6mgv"] },
  "package": { "ecosystem": "Go", "name": "golang.org/x/crypto", "version": "v0.30.0" },
  "verdict": "not_exploitable",
  "evidence": {
    "basis": "vulnerable_symbol_absent",
    "detail": "golang.org/x/crypto@v0.30.0: govulncheck matched the advisory to golang.org/x/crypto v0.30.0 and found no call path to its vulnerable functions; a vulnerable package is not imported (GOOS=darwin GOARCH=arm64, default build tags, tests excluded) (analyzer_symbol_not_reached)"
  }
}
```

Same module, same version, two different answers. The first comes with the call path that reaches
`ssh.NewServerConn`. The second names its grounds, including the build configuration they hold
for. Every run also writes `report.html`, `report.sarif.json` (SARIF 2.1.0) and `openvex.json`
(OpenVEX). [docs/sample-report.md](docs/sample-report.md) annotates the full `Report` shape.

## Quickstart — GitHub Action

Drop this at `.github/workflows/ferralon-assay.yml`. It's a complete workflow:

```yaml
name: Ferralon Assay

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  assay:
    runs-on: ubuntu-latest
    permissions:
      contents: read          # checkout, and the scan reads the tree
      issues: write           # pinned dashboard Issue (`issue` input)
      pull-requests: write    # sticky PR comment (`pr-comment` input)
      security-events: write  # SARIF upload below (`code-scanning` input)
    steps:
      - uses: actions/checkout@v4

      - name: Run the Ferralon Assay
        id: assay
        uses: ferralon-ai/ferralon-assay@v0.5
        with:
          # Scan every corpus advisory that names one of your dependencies.
          advisory-corpus-repo: ferralon-ai/vulnerability-corpus
          advisory-corpus-policy: full
          # Whose signature on the corpus release you trust. Values from the
          # corpus's CONSUMING.md; Assay ships no default.
          corpus-signer-identity: ferralon-intel-publisher@ferralon.iam.gserviceaccount.com
          corpus-signer-issuer: https://accounts.google.com

      - name: Upload the SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        continue-on-error: true
        with:
          sarif_file: ${{ steps.assay.outputs.sarif-file }}
          category: ferralon-assay
```

Each write scope buys one result surface, and each surface is an input you can switch off (`issue`,
`pr-comment`, `code-scanning` set to `"false"`); drop the matching scope with it. The job summary
always lands. On a pull request from a fork GitHub hands out a read-only token, the write surfaces
skip themselves, and the job still passes or fails on the scan.

`@v0.5` floats to the newest 0.5.x release. No binary is committed to your repository: the Action
fetches the scanner release its `scanner-version` names. To freeze the exact bytes, set
`scanner-sha256` to the `.sha256` asset a release publishes, alongside an exact `scanner-version`.
Every input is documented in [`action.yml`](action.yml).

Leave the corpus out and the scan still runs, against a small built-in advisory set that exists so
the engine works standalone. It's a floor for testing, not coverage. See
[Advisory corpus](#advisory-corpus).

## Quickstart — command line

```sh
go install github.com/ferralon-ai/ferralon-assay/cmd/ferralon-assay@latest
go install github.com/ferralon-ai/ferralon-assay/cmd/assay-plugin-go@latest   # analyzers are separate binaries, found on PATH

git clone https://github.com/ferralon-demo/demo-go-svc
ferralon-assay baseline -target demo-go-svc -out scan-out
```

```text
ferralon-assay baseline — work set: 10 advisories (built-in language set)
ferralon-assay baseline complete
  subject:    demo-go-svc@
  SBOM:       51 package(s)
  findings:   10 advisory finding(s)
    - disqualified         3
    - reachable_candidate  5
    - undetermined         2
```

That's a real `v0.5.0` run against the built-in set (the module declares `go 1.26.3`). Each language
has its own analyzer, `assay-plugin-<lang>` for `go`, `java`, `kotlin`, `js`, `python` and `dotnet`;
install the ones you need. Point `-advisory-corpus` at a corpus directory or bundle file, and set
`-advisory-corpus-policy`, to scan against the corpus. `ferralon-assay baseline -h` lists every flag.

## How it decides

For each advisory, the pipeline:

1. resolves the dependency versions your build actually uses into an SBOM;
2. rules the advisory out if your resolved version is provably outside its affected range;
3. locates the advisory's vulnerable symbols in the code your build carries;
4. builds a call graph and searches it from your framework entry points (`main`, HTTP routes, RPC
   handlers and the like) to those symbols.

Every finding lands as one of five verdicts:

| Verdict | Means |
|---|---|
| `reachable_candidate` | A path from an entry point reaches the advisory's symbols. The path is in the report. |
| `malicious_package_present` | A known-malicious package resolved to a version the advisory lists. |
| `not_exploitable` | The vulnerable code is provably absent from what you build, or provably unreachable from its entry points. `evidence.basis` names which. |
| `disqualified` | Your resolved version is outside the affected range, or the package isn't in your dependency graph or ecosystem at all. |
| `undetermined` | The scan established nothing. `undetermined_reason` says what was missing. |

Underneath, that's three positions: something reaches the code, nothing does on stated grounds, or
we don't know. OpenVEX gets exactly that: `affected` only for a malicious package,
`under_investigation` for candidates and unknowns, and `not_affected` only for the two grounded
negatives.

The rule that matters most is that **finding no path is not, by itself, a "not affected."** A
missing path can just as easily be the analyzer's blind spot: the version wasn't resolved, the
advisory named no symbol, a step failed. So `not_exploitable` requires positive grounds, such as
the package admitted at a resolved version and every advisory symbol located in it and searched
from the entry points. Anything short of that is `undetermined`, with the missing ground as the
reason ([`trigger/assess.go`](trigger/assess.go)). `undetermined` means unassessed, never safe. To
close one, supply the missing fact: resolve the version, state the build condition, fix the failing
step. The [operator guide](docs/operator-guide.md#reading-the-report) lists the grounds and the
reasons.

A candidate can carry a reachability grade. `attacker_tainted` means an attacker-controllable
entry point (an HTTP route, say) heads the path. `control_flow_only` means a path exists but no
such entry point heads it. Taint here is path presence on the call graph, not value-level dataflow.
EPSS and KEV, when you supply a signals file, only order the findings. Nothing that decides a
verdict reads them.

Assay never says "exploitable." A path that exists is a candidate. Confirming exploitability takes
running the code, and Assay doesn't run your code. That step is Ferralon's paid product
([ferralon.com](https://ferralon.com)).

The one place Assay does execute something of yours: for a Java or Kotlin repository, your own Maven
or Gradle resolves the dependency graph, which runs your build scripts and plugins. Nothing else in
the project runs.

## Languages

All six get the same core: dependency versions resolved into an SBOM, version-range
disqualification, first-party-sink reachability, and every `Report` format. Where they differ is how
far reachability goes into your dependencies:

- **Go** goes deepest. It locates advisory symbols in dependency source and computes reachability
  from entry points, using `golang.org/x/vuln`'s engine in-process.
- **Java and Kotlin** search the compiled program and its dependency JARs.
- **.NET** resolves advisory symbols inside the restored NuGet assemblies for the build's target.
- **JavaScript/TypeScript and Python** bind imports to the packages that provide them and trace
  first-party calls to the dependency boundary.

Per-language depth, framework entry points and known limits are in
[docs/capabilities/](docs/capabilities/README.md).

## Scope

Assay is a static reachability engine. It doesn't generate or apply patches, doesn't run the scanned
code, and doesn't confirm exploitability. It produces the evidence those steps build on.

It also won't hand you an empty report that looks clean. If the set of advisories to evaluate
resolves to nothing (a C/C++ tree, say, or a corpus with nothing for your language), the run fails
instead of publishing a findings-free `Report` (`scanWorkSet` in
[`cmd/ferralon-assay/run.go`](cmd/ferralon-assay/run.go)). Anything the analysis couldn't resolve,
such as reflection or dynamic dispatch, is recorded in the report's `partiality` notes.

## Your data

Your code, your build and your credentials stay in your runner. Assay sends nothing to Ferralon
unless you set `link-to-console: true`.

### Network egress

No run mode is offline. The traffic is dependency metadata (module paths, versions, package
coordinates), never source and never results:

- **Go**: `proxy.golang.org` to resolve the module graph, and `vuln.go.dev` for the Go vulnerability
  database, fetched on every run. These are the same fetches `go build` and `govulncheck` make.
- **Java/Kotlin**: your Maven or Gradle fetches from the repositories your build configures.
- **Advisory corpus**: an unauthenticated fetch of the public corpus from `github.com`. The signed
  release route also downloads cosign and reaches the Sigstore TUF CDN to verify the signature.
- **`cve-watch`**, and opt-in work-set widening, query `api.osv.dev`.
- **JavaScript with `-dependency-code=fetch`** (off by default) downloads lock-pinned package
  tarballs from your configured registry, as `npm ci` would.

Every host, and what each request carries, is in [docs/threat-model.md](docs/threat-model.md).

### Self-cleanup / console-link disclosure

`link-to-console` (default `"false"`) is the only switch that lets a run talk to Ferralon. Leave it
unset, or delete the line, and the scan runs standalone; deleting it never silently re-enables it.

With it on, each run sends its `Report` to the ingest endpoint built into the scanner release (no
Ferralon hostname goes in your workflow). A run of your canonical ref also pushes its verdict layer
under the workflow's GitHub OIDC token (`id-token: write`). That push is fail-open: a refused or
unreachable endpoint warns and never fails the job. If two consecutive runs receive a signed
install-revoke bound to your repository (the Ferralon App was uninstalled), the scanner removes its
own footprint: the workflow file (by push, or a removal PR) and the default state ref
`refs/assay/state`. If those writes are refused, it disables itself and opens an Issue instead. Set
`self-cleanup-on-revoke: false` to keep the link and hold the removal. The revoke signature check
runs inside the released binary against a key baked in at build time. Your code and credentials
never leave the runner, whichever way this is set.

## Advisory corpus

Advisories come from the public
[`ferralon-ai/vulnerability-corpus`](https://github.com/ferralon-ai/vulnerability-corpus), versioned
independently of the scanner. Two inputs, two different jobs:

- `advisory-corpus-repo` supplies advisory **facts**: ranges, symbols, aliases.
- `advisory-corpus-policy` decides **what gets scanned**: every advisory in that policy whose affected
  package is one of your dependencies, matched by package identity (`full`, `published-7d` and
  others; the corpus's `policies/` lists them).

Without a policy, the work set stays the built-in floor, so set one. For a policy the latest corpus
release publishes a bundle for, the Action downloads that single bundle and verifies it before the
scan: the release's `bundles.json` against its Sigstore signature for the exact signer you name,
then the bundle's sha256, then its members against the policy manifest. Any failure fails the run;
there is no unverified mode. The same verified release supplies the EPSS/KEV signals findings are
ordered by.

Leave `advisory-corpus-ref` on `main` so every run sees the latest intel. Reproducibility comes from
the `corpus_digest` each `Report` records, not from freezing the input. An advisory with no affected
package can't be matched against your dependencies, so it isn't assessed; the report's
analysis-limits footer gives the count and the first ids. [`action.yml`](action.yml) and the
[operator guide](docs/operator-guide.md#epss-and-kev) carry the full verification and signals
contract.

## Scanning another branch

By default the scan analyzes whatever `actions/checkout` put in the workspace. If your source lives
on another ref (a default branch that only holds docs, say), commit this to the default branch:

```yaml
# .github/ferralon.yml
version: 1
analyze:
  ref: baseline   # a branch, tag or commit SHA
```

The scan fetches that ref from `origin` into a separate worktree and analyzes it; your workspace
isn't touched, and the `Report` records the ref and commit actually analyzed. The file is treated as
untrusted input: a malformed file, an unsupported `version`, or a ref that isn't a plain name fails
the run. Unknown keys warn and are ignored.

## Run modes

- **`baseline`**: a full scan. What the quickstarts run.
- **`pr-inherit`**: diffs a PR head's resolved dependency set against a stored baseline. Unchanged
  dependencies inherit the baseline's findings; changed ones re-scan only the affected advisories.
  The PR's report is published, not stored.
- **`cve-watch`**: a scheduled check against OSV.dev for advisories newly affecting the stored SBOM.

State is a `Report` stored at a git ref (`refs/assay/state` by default), in a local repository
(`-git-dir`) or a GitHub repository over the Refs API (`-repo`, or the `state-repo` input, which
needs `contents: write`). `ferralon-assay state show` and `state export` are read-only views. The
[operator guide](docs/operator-guide.md#state-and-run-modes) covers the store, each mode, a
scheduled `cve-watch` workflow, and which surface publishes under which permissions.

## Using Assay as a Go library

```sh
go get github.com/ferralon-ai/ferralon-assay
```

Everything under `internal/` is implementation detail. The importable surface:

| Package | What it is |
|---|---|
| `trigger` | The run-mode entry points (`RunBaseline`, `RunPRInherit`, `RunCVEWatch`). The CLI calls these. |
| `pipeline` | The Assess stages and the `Stage` / `AdvisorySource` extension seams. |
| `plugin` | The `LanguagePlugin` contract, the subprocess client and the wire protocol. |
| `report` | The `Report`, the tool's output contract. |
| `verdict` | The exploitability vocabulary (direction, strength, evidence) and the `Validate` rules for when a claim may be called proven. |
| `projection` | Pure projectors from a verdict or report to SARIF, OpenVEX and SSVC. |
| `assessment` | Request and record types for one scan pass. |
| `artifact` | The content-addressed store the pipeline writes intermediate evidence into. |
| `checkout` | Codebase acquisition (`Checkout`) and language detection. |
| `statestore` | Persisted state (`StateStore`) and its git-ref implementations. |
| `resultsink` | Publishing (`ResultSink`) and the GitHub adapters under `resultsink/github`. |
| `buildgraph` | The `assay.buildgraph/v2` JVM dependency graph schema, and `Resolve`, which runs Maven or Gradle. |
| `capability` | The per-language capability manifest an analyzer declares. |
| `artifactcache` | A content-addressed view of dependency artifact bytes, keyed by PURL and integrity digest. |
| `signals` | Loads the corpus's EPSS/KEV signals file, for callers outside this module. |
| `vulnclass`, `hostmatch`, `telemetry` | CWE → vulnerability class, a host-allowlist matcher, OpenTelemetry wiring. |
| `corpus`, `plugin/symboltest` | Test fixtures and a conformance harness. No stability promise. |

Four interfaces are the extension points:

- **`plugin.LanguagePlugin`** ([`plugin/plugin.go`](plugin/plugin.go)) teaches Assay a language:
  index symbols, map advisories onto them, read dependency versions, build the call graph, find
  entry points. It returns evidence, never verdicts, and declares partiality instead of hiding it;
  an unresolvable version comes back `Resolved=false` so nothing downstream reads "unknown" as "not
  affected." Language detection is a closed set
  ([`checkout/language.go`](checkout/language.go)), so a plugin for a new language needs the
  detector extended too.
- **`pipeline.Stage`** adds an analysis step. Stages communicate only through the artifact store,
  so a new one slots in without the others referring to it.
- **`pipeline.AdvisorySource`** ([`pipeline/advisory_source.go`](pipeline/advisory_source.go)) feeds
  advisory facts from somewhere else: a private set, a mirror, an enrichment layer. Every failure
  collapses to `(zero, false)`; a source never returns partial facts.
- **`resultsink.ResultSink`** publishes a result somewhere other than GitHub.

[`trigger/example_test.go`](trigger/example_test.go) is a compiled example that runs `RunBaseline`
against an in-memory `StateStore`, with no git, no refs and no filesystem.

## API stability

The module is pre-1.0 and the public API can change. No exported signature carries a
`golang.org/x/tools` or `golang.org/x/vuln` type, so importing Assay doesn't pin you to our versions
of them. A few exported variables (`pipeline.AdvisoryTable`, `pipeline.SetDefaultAdvisorySource`,
`trigger.AnalyzerVersion`, and the marker/title variables in `resultsink/github`) are process-wide
and must be set before any goroutines start. [docs/api-stability.md](docs/api-stability.md) has the
audit and the full list.

## Contributing and support

- [CONTRIBUTING.md](.github/CONTRIBUTING.md): how to propose a change, and the project's scope.
- [SUPPORT.md](.github/SUPPORT.md): where to ask, and what response time to expect.
- [SECURITY.md](.github/SECURITY.md): reporting a vulnerability in Assay itself.
- [docs/releases/README.md](docs/releases/README.md): how releases are cut. CI builds every
  release from a pushed tag, never from a workstation.

## License

[Business Source License 1.1](LICENSE), licensed by Ferralon, Inc. You may copy, modify,
redistribute and make non-production use of the code. The Additional Use Grant is `None`, so
production use needs a commercial license (contact operators@ferralon.com). Each released version
converts to its Change License on its Change Date, or on the fourth anniversary of that version's
first public distribution, whichever comes first. On `main` both parameters read `TBD`; the release
workflow fills them in on each release. `v0.5.0`'s, for example, converts to MIT on 2030-10-20.
