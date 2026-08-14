# Ferralon Assay

Ferralon Assay is a CI vulnerability scanner that answers one question per advisory: **is the
vulnerable code actually reachable in this build?** Given a CVE/GHSA/OSV identifier and a codebase,
it resolves dependency versions, maps the advisory to vulnerable symbols, builds a call graph, and
computes reachability from framework entry points to those symbols. A CVE sitting in a function
nothing calls reports as not-reachable, instead of landing on your desk as a finding to triage away.

It runs entirely in your own runner. It never runs a model, and it never executes code from the
scanned repository — every stage is static analysis over the checked-out tree and its build metadata.

Point it at a **Go, Java, JavaScript, Python or .NET** repository and every one gets a full scan and a
`Report`. Go's analysis runs deepest — dependency-level reachability into the code an advisory names —
and the [Language support](docs/language-support.md) fit matrix shows at a glance how deep the analysis
reaches in each.

## Quickstart — GitHub Action

Drop this at `.github/workflows/ferralon-assay.yml`. It is a complete workflow, not a fragment:

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
      # actions/checkout, and the scan reads the checked-out tree.
      contents: read
      # The pinned-Issue dashboard surface (the `issue` input, on by default).
      issues: write
      # The sticky PR-comment surface (the `pr-comment` input, on by default).
      pull-requests: write
      # The SARIF upload step below (the `code-scanning` input, on by default).
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run the Ferralon Assay
        id: assay
        uses: ferralon-ai/ferralon-assay@<sha>
        with:
          mode: baseline
          target: .

      # The Action materializes report.sarif.json; the upload to code scanning is this
      # step, so drop it and the `code-scanning` surface produces a file and nothing else.
      - name: Upload the SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        continue-on-error: true
        with:
          sarif_file: ${{ steps.assay.outputs.sarif-file }}
          category: ferralon-assay
```

Each write scope buys exactly one result surface, and each surface is an input you can turn
off — set `issue`, `pr-comment` or `code-scanning` to `"false"` and drop the matching scope.
Two more scopes are conditional on inputs this Quickstart does not set: `state-repo`/`state-ref`
(persisting the baseline through the GitHub Refs API) needs `contents: write`, and
`link-to-console: true` needs `id-token: write` for the run push. On a pull request from a fork
GitHub issues a read-only token whatever you declare, and every write surface skips itself; the
job summary still lands.

**Pinning by commit SHA** (`@<sha>`) is the strict-supply-chain choice: the SHA transitively pins the
exact scanner bytes the Action fetches — `scanner-version` and `scanner-sha256` are baked into the
Action itself — so nothing runs that you did not pin, and no binary is ever committed into your
repository. Tracking a moving ref instead (a branch, or a release tag you let float) is a legitimate
trade for auto-updates: the built-in **drift guard** verifies the fetched scanner tarball's checksum
on every run **regardless of which ref you use**, and fails the run loudly on any mismatch.

## Quickstart — command line

Requires Go (see `go.mod` for the minimum version):

```sh
go build -o ferralon-assay ./cmd/ferralon-assay
go build -o tegron-plugin-go ./cmd/tegron-plugin-go
./ferralon-assay baseline -target /path/to/repo -out ./scan-out
```

This scans every advisory in the built-in Go advisory set against the target and writes `report.json`
plus its projections — `report.html`, `report.sarif.json` (SARIF 2.1.0), and `openvex.json`
(OpenVEX) — into `-out`.

A language analyzer is a separate subprocess binary spoken to over a small stdin/stdout JSON
protocol; the scanner never links analysis libraries such as `golang.org/x/tools` into its own
binary. The CLI resolves the analyzer for the detected language on `PATH` under the name
`tegron-plugin-<lang>`, or takes an explicit path from the run mode's `-plugin-go`-style flag. The
other analyzers build the same way (`./cmd/tegron-plugin-java`, `-js`, `-python`, `-dotnet`); build one
and a default scan of that ecosystem completes against the same populated advisory floor the shipped
Action uses. What halts a run is a *resolved* work set of zero advisories — for example pointing
`-advisory-corpus` at a table that has nothing for your detected language. See
[Scope](#scope).

Run `./ferralon-assay baseline -h` for the full flag list, including `-advisory-corpus` to scan
against a filesystem corpus instead of the built-in table, and `-subject-go-version` to state the
target's Go toolchain explicitly.

## What it reports

The output is a neutral scan `Report`: one finding per advisory, each backed by the evidence the
pipeline actually collected — a resolved dependency version, candidate reachability paths, or a
documented disqualification.

A finding the pipeline could not soundly resolve is reported as exactly that. Assay **fails open**:
it never narrates an absence of evidence as "not affected." That distinction is the whole point of
the report — an unresolved advisory and a disqualified one are different claims, and conflating them
is how a scanner quietly loses your trust.

## Advisory corpus

Advisories load from an external advisory corpus, and **a real run should consume one** — point the
Action's `advisory-corpus-repo` at the public [`ferralon-ai/vulnerability-corpus`](https://github.com/ferralon-ai/vulnerability-corpus),
which the Action fetches unauthenticated at run time, or hand an already-checked-out corpus directory
to `advisory-corpus`. Advisory sourcing does not vary by language; a corpus supplies whatever
advisories it carries for whichever languages it covers, and the `Report` records the corpus's own
`corpus_digest` so a run's advisory state is independently identifiable. With neither input set the
scan falls back to a small built-in table so the engine still runs standalone — Go carries 10 of
these, the other four carry 3 each
([`cmd/ferralon-assay/acquire.go`](cmd/ferralon-assay/acquire.go)); that built-in table is a
standalone default floor, so consume the corpus for real coverage.

Let the corpus track its default `main` (`advisory-corpus-ref` defaults to `main`). New advisories land
in it continuously, so pinning the corpus ref would freeze your vulnerability intel and miss everything
published after the pin — you want the latest intel on every run. Reproducibility of *which* advisories
a given run saw comes from the `corpus_digest` the `Report` records, not from pinning the input. (How
you pin the Action itself is a separate, supply-chain question — see the Quickstart.)

## Scope

Assay is the free, open-source reachability engine: it resolves dependency versions, maps advisories
onto vulnerable symbols, builds a call graph, and computes reachability, then reports what it found.
What each of the five languages resolves today is laid out in
[Language support](docs/language-support.md).

It stops at reachability — there is no execution of the target codebase, no exploit synthesis, and no
live confirmation step, and it neither generates nor validates patches. It produces the evidence those
steps build on.

A scan will never emit a findings-free `Report` from a work set that resolved to nothing: that halts
the run instead — see `scanWorkSet` in [`cmd/ferralon-assay/run.go`](cmd/ferralon-assay/run.go). A
report with nothing in it is indistinguishable from an assessment that found nothing wrong, and we
will not ship you the second one when we performed the first.

The `verdict` package is published on purpose. It carries the complete vocabulary a finding can be
expressed in — `PoE`, `Direction`, `Strength`, the evidence flags, and the `Validate` rules that
decide when a claim may be called proven. It is deliberately wider than what this module produces:
defining the whole grammar up front keeps a verdict's shape stable as the analysis behind it deepens,
instead of renegotiating the contract every time a new stage lands. Several terms are declared here
and reserved for implementation.

## Run modes

Three run modes, all built on the same S1–S6 pipeline:

- **`baseline`** — a full scan of every advisory against the target. The entry point above.
- **`pr-inherit`** — diffs a PR head's resolved dependency set (SBOM) against a stored baseline. If
  nothing relevant changed it inherits the baseline's findings instead of re-scanning; otherwise it
  re-scans only the affected advisories.
- **`cve-watch`** — a scheduled check against OSV.dev for advisories newly affecting the stored SBOM.

`pr-inherit` and `cve-watch` read persisted state from a prior `baseline` run. State is stored as a
`Report` object at a git ref (`refs/assay/state` by default) — either a local git or bare repository
(`-git-dir`), or a remote GitHub repository over the Refs API (`-repo owner/repo`, with a token).
`./ferralon-assay state show` and `./ferralon-assay state export` are read-only operator views over
that stored state.

Run inside GitHub Actions, the CLI also publishes to the standard GitHub surfaces it has permission
for: a job summary (always), and — with a write token — SARIF code scanning, a sticky PR comment, and
a pinned dashboard Issue.

## Network egress

**Your code and your credentials never leave the runner.** No run mode is offline, though, and it is
worth being precise about what does leave.

A default `baseline` or `pr-inherit` run contacts two public hosts:

- **`proxy.golang.org`** — when it resolves the subject's module graph.
- **`vuln.go.dev`** — the Go analyzer's reachability stage runs govulncheck with no `-db` flag
  (`internal/plugin/goanalysis/reach.go`), so it resolves `golang.org/x/vuln`'s default vulnerability
  database, uncached, on every run. The module paths it looks up are visible to that host.

These are the same fetches `go build` and `govulncheck` perform.

`cve-watch` adds **`api.osv.dev`**. The scan modes reach OSV only when work-set widening is switched
on explicitly (`-osv-work-set` / `ASSAY_OSV_WORK_SET`, off by default); that query sends package
coordinates — ecosystem, name, version — and nothing else. Enabling subject-toolchain reachability
(`ASSAY_SUBJECT_TOOLCHAIN_REACHABILITY`, also off by default) additionally downloads a Go toolchain
from the module proxy.

What all of these carry is dependency metadata — module paths, versions, package coordinates — never
source, and never analysis results.

Findings do travel to GitHub, by design: the StateStore ref and the publish surfaces above write the
`Report` and its projections into **your own** repository, under a token you supply.

Talking to Ferralon is a separate, explicit switch. The Action's `link-to-console` input is the only
control that decides whether a scan contacts Ferralon at all; it defaults to `false`, and on that
default the scan runs fully standalone.

## Automatic upgrades

This project does not open pull requests against your repository, and no automation here rewrites the
`uses: ferralon-ai/ferralon-assay@…` ref on your workflow line. That ref is yours to move — or to let
float. Open [`action.yml`](action.yml): the composite action has exactly three steps — fetch the
scanner and verify its checksum, fetch the advisory corpus, and run the scan. None of them write to a
workflow file or open anything against your repository.

Whether you pin the ref or track a moving one, the check that matters is already running: the drift
guard described in [Quickstart — GitHub Action](#quickstart--github-action) verifies the fetched
scanner tarball's checksum against the `scanner-sha256` baked into the Action revision you resolve,
before anything unpacks or runs — regardless of which ref you use or who changed it.

## Using Assay as a Go library

```sh
go get github.com/ferralon-ai/ferralon-assay
```

The module is split into public packages and `internal/` ones. Everything under `internal/` is
implementation detail with no compatibility promise; the packages below are the importable surface.

| Package | What it is |
|---|---|
| `trigger` | The three run-mode entry points (`RunBaseline`, `RunPRInherit`, `RunCVEWatch`) — the top-level API the CLI itself calls. |
| `pipeline` | The S1–S6 Assess stages and the `Stage` / `AdvisorySource` extension seams. |
| `plugin` | The `LanguagePlugin` contract every language analyzer implements, plus the subprocess client and wire protocol. |
| `assessment` | The neutral request/record types for one scan pass: what codebase, at what revision, against which advisory. |
| `verdict` | The Proof of Exploitability vocabulary (direction, strength, evidence). |
| `report` | The neutral scan `Report` — the tool's output contract. |
| `projection` | Pure projectors from a verdict or report to SARIF, OpenVEX, and SSVC. |
| `artifact` | The content-addressed store the pipeline writes its intermediate evidence into. |
| `checkout` | The codebase-acquisition seam (`Checkout`) and its git implementation. |
| `statestore` | The persisted-state seam (`StateStore`) and its git-ref implementations. |
| `resultsink` | The publish seam (`ResultSink`) and the GitHub adapters under `resultsink/github`. |
| `corpus` | The built-in advisory corpus and its loader. |
| `vulnclass` | Maps an advisory's CWE to a closed vulnerability-class enum. |
| `hostmatch` | A standalone host-allowlist matcher used by the checkout credential seam. |
| `telemetry` | OpenTelemetry wiring for the pipeline's spans and metrics. |

## Extending Assay

Four interfaces are the intended extension points. Each is a place where the pipeline delegates a
decision it does not want to own itself, and each can be implemented from outside the module.
`go doc` has the signatures; what follows is what they are for.

### `plugin.LanguagePlugin` — evidence for one language

`LanguagePlugin` ([`plugin/plugin.go`](plugin/plugin.go)) is the contract every language analyzer
implements: index symbols, map an advisory's vulnerable symbols onto this codebase, read declared
dependency versions, build a call graph, find framework entry points, derive reachability. Implement
it to teach Assay a language, or to swap a better analyzer in for one it already handles.

Two rules bind an implementation. It returns **evidence, never verdicts** — the pipeline decides what
the evidence means, and an operation that returns a judgement has taken a decision that is not its
own. And **partiality is declared, not hidden**: an operation that cannot fully resolve its answer
says so on the result, because a confident-looking incomplete answer is the failure mode the whole
design exists to prevent. `ResolveDependencyVersions` is the sharp case — an unresolvable version
comes back `Resolved=false` so the disqualification predicate fails open, since "unknown" must never
be read as "not affected".

**A plugin for an unlisted language is constructed and then never called.** Language detection is a
closed set: [`checkout.DetectLanguage`](checkout/language.go) can only return `go`, `java`, `js`,
`python`, `dotnet`, or unknown. `NewMultiPlugin` routes each operation by that detected tag
([`plugin/multiplugin.go`](plugin/multiplugin.go)), and the `codebase_inventory` stage gates its
manifest and version reads on `Language()` matching it, so a plugin registered as, say, `ruby` is
never selected — it produces no error, and the run reports partiality with reason
`no_language_plugin` rather than telling you your plugin was ignored. Adding a language means
extending the detector too.

### `pipeline.Stage` — one step of the Assess pipeline

`Stage` is three methods: a stable `Name()` used as the artifact's `ProducedBy`, the `Status()` the
stage advances the assessment to, and `Run`, which reads and writes through an `artifact.Store`.
`AssessStages()` composes the built-in S1–S6 sequence.

Stages pass their work through the artifact store rather than through each other: a stage reads its
predecessors' artifacts and writes its own, so a new one slots into the sequence without any other
stage referring to it. Implement `Stage` to add an analysis step, or to record evidence the built-in
stages do not collect.

### `pipeline.AdvisorySource` — where advisory facts come from

`AdvisorySource` ([`pipeline/advisory_source.go`](pipeline/advisory_source.go)) is a single
`Lookup(vulnID) (AdvisoryFacts, bool)`, and it is the only route S1 reads advisories through.
Implement it to feed Assay a private advisory set, an internal mirror, or an enrichment layer over
the built-in corpus. `NewChainSource` composes several — it tries each in order and returns the first
whole fact any of them resolves, never merging across sources; `NewArtifactSource` reads a
digest-pinned directory of facts.

The contract is unusually strict about failure, and the strictness is the point: **every** failure
mode — unknown id, unreadable artifact, failed shape validation, digest mismatch — collapses to the
same `(zero, false)`. A source never returns partial or laundered facts, because a half-populated
advisory would silently weaken a verdict downstream while looking exactly like a complete one.

### `resultsink.ResultSink` — publishing the result

`ResultSink` is one method, `Publish(ctx, Result) error`. It is where a completed scan reaches a CI
surface; the GitHub adapters under `resultsink/github` are the built-in implementations. Implement it
to publish somewhere else — a different forge, a chat channel, an internal dashboard.

An implementation must be safe to call exactly once per run and should be idempotent under retry. An
error means the surface could not be written; a sink that deliberately discards results returns nil.

### A runnable example

`RunBaseline` assesses a set of advisories and persists the resulting `Report` to a `StateStore`.
`statestore.MemStore` is an in-memory implementation of that interface, so an example — or your own
tests — can exercise the full path with no git repository, no refs, and no filesystem. This is the
compiled `Example` in [`trigger/example_test.go`](trigger/example_test.go):

```go
func Example_runBaseline() {
	store := statestore.NewMemStore()

	rep, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:    trigger.Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "abc123"},
		Codebase:   assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		panic(err)
	}
	for _, f := range rep.Advisories {
		fmt.Printf("%s: %s\n", f.Advisory.ID, f.Verdict)
	}

	state, err := store.Read(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Printf("stored %d advisories for %s\n", len(state.Report.Advisories), state.Report.Subject.Repo)
	// Output:
	// GO-2021-0113: reachable_candidate
	// stored 1 advisories for example.com/app
}
```

With no `AssessOptions`, the stages run their hermetic stub path — no checkout, no analyzer
subprocess. Pass `pipeline.WithPlugin` and `pipeline.WithCheckout` to run against a real codebase.

## API stability

This module is pre-1.0 and the public API may change. Two specific things are worth knowing before
you import it:

- **Third-party types on the public surface.** An exported signature carrying a `golang.org/x/tools`
  or `golang.org/x/vuln` type would pin every consumer to our version of it. The public surface is
  audited for this, and the exceptions found were removed rather than kept.
- **Exported process-wide mutable state.** A few exported variables and setters
  (`pipeline.AdvisoryTable`, `pipeline.SetDefaultAdvisorySource`, `trigger.AnalyzerVersion`, and the
  marker/title variables in `resultsink/github`) are writable at runtime and are not `-race`-safe.
  Their contract is set-before-spawn.

[`docs/api-stability.md`](docs/api-stability.md) has the audit, the method that produced it, and the
full list.

## Contributing and support

- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — how to propose a change, and the project's scope
  boundaries.
- [SUPPORT.md](.github/SUPPORT.md) — where to ask a question, and what response time to expect.
- [SECURITY.md](.github/SECURITY.md) — how to report a vulnerability in Assay itself.

Upgrade pull requests are opened by the Ferralon Team bot; you can reply on any of them with
questions.

## License

Apache License 2.0. See [LICENSE](LICENSE).
