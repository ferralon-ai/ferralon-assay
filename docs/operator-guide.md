# Operator guide

The [README](../README.md) gets a scan running. This page is for after that: how to read what a
`Report` tells you, how persisted state and the three run modes fit together, and which GitHub
surfaces a run publishes to under which permissions. The Action's own inputs are documented in
[`action.yml`](../action.yml); network egress is covered in the README's
[Network egress](../README.md#network-egress) section and in [threat-model.md](threat-model.md).

## Reading the Report

Every finding carries one verdict. [Language support](language-support.md#the-three-valued-verdict)
explains the three-valued core — `reachable_candidate`, `disqualified`, `undetermined` — and why an
`undetermined` row is an open question, never a clean bill. The rest of this section is the evidence
that sits next to the verdict. None of it changes the verdict; it tells you which findings to look at
first.

### Reachability grade

A `reachable_candidate` can carry a grade describing how strong its reachability evidence is:

- `attacker_tainted` — an attacker-controllable ingress (for example an HTTP route) reaches the
  vulnerable symbol, and tainted data flows along that path. The strongest candidate signal a scan
  emits.
- `control_flow_only` — a control-flow path to the symbol exists, but the analysis found no
  attacker-controllable data flowing along it.

A graded candidate also reports its **entry point** — the symbol, its kind (`http_route`, `rpc`,
`cli`, `test` or `unknown`), and whether that kind is attacker-controllable — and, when the analyzer
resolved them, the **call path** frames from entry point to sink. Taint here is path presence on the
call graph, not value-level dataflow. Either grade is still a candidate: neither proves the code can be
exploited.

### EPSS and KEV

A finding whose advisory has a CVE identifier (as its id or one of its aliases) may carry a `priority`
block:

- **EPSS** — FIRST.org's probability-of-exploitation score and percentile for the CVE.
- **KEV** — whether the CVE is in CISA's Known Exploited Vulnerabilities catalog, and the date it was
  added.
- **Snapshot** — the date of the data the values came from.

The values come from EPSS and KEV snapshots embedded in the scanner binary
([`internal/intel`](../internal/intel)), so the lookup is offline and a given scanner release always
returns the same values. The snapshot moves when a release refreshes it. A finding with no match in
either feed carries no `priority` block at all.

EPSS and KEV describe how often a CVE is exploited in the wild, across all software. They say nothing
about whether this codebase calls the vulnerable code — that is what the verdict and grade are for.

### Ordering

Findings are sorted most-actionable first, and every projection keeps that order:

1. `reachable_candidate`
2. `undetermined` — unassessed, so it owes you an action a refuted advisory does not
3. KEV-listed
4. `attacker_tainted` over `control_flow_only`
5. higher EPSS score, then higher EPSS percentile
6. advisory id, then source, as a stable tiebreak

### Where the evidence shows up

| Output | What it carries |
|---|---|
| `report.json` | The full `evidence` block (grade, entry point, call path) and the `priority` block. See [sample-report.md](sample-report.md) for the shape. |
| `report.sarif.json` | Under each result's `properties.scanner`: `reachability_grade`, `entry_point`, `attacker_controllable`, `epss_score`, `epss_percentile`, `kev_listed`, `kev_date_added`, `intel_snapshot`. The SARIF `rank` is the EPSS percentile × 100, and KEV-listed findings get a `CISA-KEV` tag. |
| `report.html` | Grade and EPSS/KEV badges, the call path, and a note on where the intel came from. |
| PR comment and pinned Issue | The grade and EPSS/KEV columns, with a one-line reminder that neither is an exploitability claim. |
| `openvex.json` | No priority data. OpenVEX has no field for it, so none is projected. |

## The Go toolchain your repository builds with

For a Go standard-library advisory, the question is about the Go **you** build with, which is not
necessarily the Go the scanner analyzes with. The scan resolves your toolchain as one fact, from the
first source that yields a usable version:

1. **Your declaration** — `-subject-go-version` on the CLI (for example `go1.21.3`), or the
   `ASSAY_SUBJECT_GO_VERSION` environment variable. Exact.
2. **Your `go.mod` directives** — `toolchain goX.Y.Z` and `go X.Y` (read as `goX.Y.0`). Each is a
   **minimum**, not an exact version: `GOTOOLCHAIN=auto` only ever switches up from them. When both
   are present, the higher one wins.
3. Otherwise, unresolved.

A declaration below your own `go.mod` floor is discarded in favor of the floor, because a module
cannot build with a Go older than its directives require. A stale `subject-go-version` therefore
weakens the fact to a minimum rather than letting the scan rely on a version your repository has
already moved past.

The difference between exact and minimum matters. A minimum is enough to disqualify an advisory when
even your floor is past the fix. It is not enough to conclude anything from a vulnerable symbol being
absent, because the analysis did not run on your toolchain.

### `subject-toolchain-reachability`

By default the reachability analysis runs under the scanner's toolchain, so its "the vulnerable
symbol is not present" result is evidence about the scanner's Go, not yours. Standard-library
advisories it cannot otherwise settle are reported `undetermined`, with `undetermined_reason` set to
`go_toolchain_not_scanned` (or `go_toolchain_unresolved` when no toolchain fact resolved at all), and
OpenVEX carries them as `under_investigation`.

Set the Action input `subject-toolchain-reachability: "true"` (or `ASSAY_SUBJECT_TOOLCHAIN_REACHABILITY`
on the CLI) and, when your toolchain resolved **exactly**, the analysis runs under that Go release,
downloading it if the runner doesn't already have it. Its results then become ordinary verdicts: an
absent symbol can be reported `not_exploitable`, and a present one becomes a `reachable_candidate`.
Before turning it on:

- **Findings can appear on scans that are green today.** A repository on an older Go has
  standard-library vulnerabilities a newer Go does not show. That is the point, and it changes what a
  clean report means.
- **It needs an exact toolchain.** `go.mod` floors are not enough. The Action has no input for the
  declaration, so set `ASSAY_SUBJECT_GO_VERSION` in the `env:` of the step that runs the Action.
  Without an exact toolchain the input changes nothing, and that is not an error.
- **It never fails the scan.** If the toolchain can't be downloaded or can't load your module, the
  analysis falls back to the scanner's toolchain and the advisory stays `undetermined`. The report
  never claims your toolchain was scanned when it was not.
- **Go 1.20 is the floor.** The analyzer cannot drive an older `go` command; below 1.20 the advisory
  stays `undetermined` whatever you set.
- **The first run is slower.** It downloads a Go toolchain from the module proxy.

## The Python analyzer

Python repositories are analyzed by a lexical source scanner by default. Setting
`ASSAY_PYTHON_LANE=cgx` swaps in `assay-plugin-python-cgx`, which answers the call-graph questions
(symbol resolution, call graph, entry points, reachability, taint) from a
[cgx](https://github.com/ferralon-ai/cgx) index and answers everything else (installed versions,
build manifest, dependency inventory) exactly as the default analyzer does. Only the exact value
`cgx` selects it; anything else, including a typo, keeps the default. An explicit `-plugin-go` path
takes precedence over the variable.

The cgx analyzer copies the files of the scanned directory, minus those its `.gitignore` files
exclude, into a git repository under its cache directory and keeps the index there, so the
scanned checkout is only read and an unchanged tree is indexed once. It needs git 2.25 or later on
`PATH` whichever transport it uses. Its settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ASSAY_PYTHON_CGX_TRANSPORT` | `wasm` | `wasm` runs cgx in-process; `native` drives a `cgx session` subprocess. |
| `ASSAY_PYTHON_CGX_BIN` | `cgx` on `PATH` | The `cgx` binary for the native transport. |
| `ASSAY_PYTHON_CGX_WASM` | the module embedded in the SDK | A cgx engine module file, for builds that embed none. |
| `ASSAY_PYTHON_CGX_CACHE_DIR` | the user cache directory | Where indexes and compiled modules are kept. |
| `ASSAY_PYTHON_CGX_POOL_SIZE` | the SDK's | Parallel extractors for the wasm transport. |
| `ASSAY_PYTHON_CGX_MIN_CONFIDENCE` | `probable` | Lowest cgx edge confidence kept in the call graph: `certain`, `probable` or `possible`. |
| `ASSAY_PYTHON_CGX_STATS` | unset | A file to append one JSON timing record per analyzer call to. |
| `ASSAY_PYTHON_CGX_FALLBACK` | unset | `native`: when the wasm engine traps while indexing (its memory limit included), retry once on the native transport with `ASSAY_PYTHON_CGX_BIN`. |

The call graph keeps only edges at or above the confidence floor, because cgx's `possible` tier
holds over-approximated candidate sets that run to millions of edges on large Python trees. The
floor is declared in the call graph's partiality. HTTP entry points still come from the
lexical scanner's Flask/FastAPI decorator detection; a route handler cgx cannot match to a node is
declared, and an advisory with no path is then reported `undetermined` rather than
`not_exploitable`.

If the cgx engine fails while indexing a tree (the wasm engine reaching its memory limit, or the
native process exiting), the analyzer call fails with an error that starts
`tool_failure:cgx_index_failed` and names the setting to change. The failure is recorded under the
cache directory for the rest of that scan, so the scan's later calls on the same tree fail at once
with the same error instead of indexing again; the next scan tries again. With
`ASSAY_PYTHON_CGX_FALLBACK=native`, a wasm trap is retried once on the native transport instead, and
the scan's later calls go to the native transport directly.

## State and run modes

`baseline` works on its own. `pr-inherit` and `cve-watch` build on a prior baseline, which lives in a
StateStore.

### The StateStore

State is a single commit on an orphan git ref, `refs/assay/state` by default: the last `Report`, the
resolved SBOM, the advisory cursor, and an OpenVEX log. It is not on any branch. Every write is a
fast-forward-only compare-and-swap — a writer whose view of the ref went stale re-reads, merges its
change onto the winner's state, and retries — so concurrent runs don't clobber each other.

| Store | CLI flags | Action inputs |
|---|---|---|
| GitHub Refs API | `-repo owner/repo`, `-token` (default `$GITHUB_TOKEN`), `-api-url` for GitHub Enterprise | `state-repo`, `state-token` |
| Local git ref | `-git-dir <path>` (a repo or bare repo) | — |

Give one of `-repo` and `-git-dir`, never both. `pr-inherit`, `cve-watch` and the `state` views
require one; `baseline` runs without (see below). `-ref` (the `state-ref` input) picks a
different ref, which is how you keep separate state for separate environments in one repository.
Writing through the Refs API needs `contents: write`.

### `baseline`

A full scan of every advisory in the work set: the built-in floor, plus — when an advisory policy is
declared (the [scan window](../README.md#choosing-the-scan-window): `.github/ferralon.yml`
`scan.window`, else `advisory-corpus-policy`) — every advisory in that policy whose affected
package is one of the repository's own dependencies. With a store selected, the result is persisted so later
runs can read it. With **no** store selected, `baseline` uses a throwaway store in a temporary
directory: the scan runs and the output directory is written, but nothing persists. That is the
zero-config path the README Quickstart uses.

### `pr-inherit`

Resolves the SBOM of the checked-out PR head and diffs it against the stored baseline. If the
dependency set is unchanged, it inherits the baseline's findings without re-scanning. If it changed, it
re-analyzes only the affected advisories and merges them over the inherited findings. Either way it
publishes the PR's Report without storing it: the baseline stays the default branch's, so later PRs
inherit from it and `cve-watch` diffs against it, and a read-only token is enough — including a
fork's. With no baseline in the selected store it stops with:

```text
no baseline in state at the selected StateStore — run `ferralon-assay baseline` against the default branch first
```

### `cve-watch`

Queries OSV.dev for advisories now affecting the stored SBOM and compares them with the stored cursor:

- **Heartbeat** — nothing new. Only the cursor is written, and nothing is republished.
- **Re-analysis** — new advisories affect the SBOM. The scan re-analyzes them and publishes a Report
  the way any run does.

It needs a prior baseline, and stops with the same message as `pr-inherit` without one.

A scheduled workflow for it:

```yaml
name: Ferralon Assay CVE watch

on:
  schedule:
    - cron: "17 7 * * *"   # daily, off the top of the hour
  workflow_dispatch:

permissions:
  contents: read

jobs:
  cve-watch:
    runs-on: ubuntu-latest
    permissions:
      # The cursor bump (and a re-analysis) writes the state ref.
      contents: write
      # The pinned-Issue dashboard, updated on a re-analysis.
      issues: write
      # The SARIF upload below.
      security-events: write
    steps:
      # A re-analysis scans the checked-out tree.
      - uses: actions/checkout@v4

      - name: Run the Ferralon Assay
        id: assay
        # Pin the same ref as your main workflow (see the README Quickstart).
        uses: ferralon-ai/ferralon-assay@163061bb0fb4b0f1cea8bb4991032d680b9d300c # v0.2.0
        with:
          mode: cve-watch
          state-repo: ${{ github.repository }}

      # A heartbeat publishes nothing, so there is only a SARIF file to upload after a re-analysis.
      - name: Upload the SARIF to code scanning
        if: hashFiles('ferralon-assay-out/report.sarif.json') != ''
        uses: github/codeql-action/upload-sarif@v3
        continue-on-error: true
        with:
          sarif_file: ${{ steps.assay.outputs.sarif-file }}
          category: ferralon-assay
```

A scheduled run has no pull request, so the PR comment never fires here.

### Looking at stored state

Two read-only CLI views; neither writes to the ref. Both take the store flags above.

```sh
# Render the stored report.html and open it in your browser.
./ferralon-assay state show -repo owner/repo
# Print the file:// path instead of opening a browser; -out picks the directory.
./ferralon-assay state show -repo owner/repo -no-open

# Write report.json, report.html, report.sarif.json and openvex.json into a ZIP
# (default: ferralon-assay-state.zip).
./ferralon-assay state export -repo owner/repo -out state-snapshot.zip
```

## Publish surfaces and permissions

Inside GitHub Actions, a run picks its surfaces from the environment and the token it was given. You
don't configure anything beyond the job's `permissions:` block and the surface toggles.

| Surface | Toggle | Needs | Default | Fires on |
|---|---|---|---|---|
| Output directory (`report.json` and projections) | — | nothing | always | every run, in or out of Actions |
| Job summary + `::warning::` annotations on reachable candidates | — | nothing | always | every Actions run, forked PRs included |
| SARIF file for code scanning | `code-scanning` | a write-capable token | on | push and PR runs |
| Sticky PR comment, updated in place | `pr-comment` | `pull-requests: write` | on | `pull_request` / `pull_request_target` runs only |
| Pinned dashboard Issue, one issue rewritten each run | `issue` | `issues: write` | on | any write-capable run |

The Action writes `report.sarif.json`; getting it into code scanning is a separate
`github/codeql-action/upload-sarif` step, as in the README Quickstart. That step needs
`security-events: write`.

### When a surface can't be written

The PR comment and the dashboard Issue are best-effort. If GitHub won't take one of those writes —
Issues are disabled on the repository, the job's token lacks the scope, or GitHub has a bad moment —
the run logs a `::warning::` and adds a "Surfaces not updated" note under the scan headline in the
job summary, naming the surface, the HTTP status when GitHub answered and, for a refusal, the input
that turns it off. The job still passes or fails on the scan alone. A failure to write the output directory, the job summary,
or the SARIF or Pages files still fails the run: those are writes on the runner itself, not GitHub's
call.

### Forked pull requests

On a pull request from a fork, GitHub hands the workflow a read-only token. The scan detects this by
reading the event payload and comparing the head repository with the base repository. When they
differ, every write surface skips itself — cleanly, without failing the job — and the output directory
and job summary still land.

A toggle can only turn a surface off. It cannot turn one on where the token can't write: each surface
fires only when its toggle is on **and** the run is write-capable. Keep that in mind for state too:
a run that writes state (`baseline` with `state-repo` set, or `cve-watch`) needs a token that can
write, which a fork's token cannot. `pr-inherit` never stores its Report, so it runs the same on a fork.
