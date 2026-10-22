# Operator guide

The [README](../README.md) gets a scan running. This page is for after that: how to read what a
`Report` tells you, how persisted state and the three run modes fit together, and which GitHub
surfaces a run publishes to under which permissions. The Action's own inputs are documented in
[`action.yml`](../action.yml); network egress is covered in the README's
[Network egress](../README.md#network-egress) section and in [threat-model.md](threat-model.md).

## Reading the Report

Every finding carries one of five verdicts: `reachable_candidate`, `not_exploitable`, `disqualified`,
`malicious_package_present` and `undetermined`. [Language support](language-support.md#verdicts)
defines each. The rest of this section is the evidence that sits next to the verdict. None of it
changes the verdict; it tells you which findings to look at first.

### `not_exploitable` grounds

A `not_exploitable` row stands on named grounds in every ecosystem. It needs an admitted package with a
resolved version, and either every advisory symbol resolved inside that package and searched from the
entry points, or a positive refutation of the package. In Go it can also rest on the build itself: no
module in the build holds the advisory's package, and none of the build's modules declares an advisory
symbol. The row's `evidence.basis` and `evidence.detail` state which. Anything short of that is
`undetermined`, with the missing ground as its reason.

### `undetermined` reasons

An `undetermined` row is an open question, never a clean bill. Its `undetermined_reason` names what
the scan did not establish:

| Reason | What was missing |
|---|---|
| `analysis_did_not_run` | A step the verdict rests on failed or did not run. The scan-level `partiality` notes name the step; when the step failed outright, the row's detail also carries the redacted error. |
| `package_version_unresolved` | The package's installed version was not resolved, so nothing establishes which code the build carries. |
| `advisory_symbol_absent` | The advisory names no vulnerable symbol, so there was nothing to search for. |
| `vulnerable_symbol_unresolved` | The advisory names vulnerable symbols, and not every one was located in the affected package and searched. |
| `advisory_unknown_to_analyzer` | The analyzer reported nothing about the advisory at all. |
| `advisory_range_absent` | A path reaches the advisory's code, but the advisory records no version range the scan can bound. The path stays as evidence, and `advisory_bounds` records what the advisory does state. |
| `go_toolchain_unresolved`, `go_toolchain_not_scanned` | A Go standard-library advisory could not be adjudicated against your toolchain; see [the Go toolchain](#the-go-toolchain-your-repository-builds-with). |

To close a row, supply the missing fact: resolve the version, state the build condition, or fix the
failing step.

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

A finding may carry a `priority` block when the run was given an EPSS/KEV **signals file** and that
file has a value for the advisory's id or one of its aliases:

- **EPSS** — FIRST.org's probability-of-exploitation score and percentile, with `epss_as_of`, the
  EPSS model date they come from.
- **KEV** — whether the CVE was in CISA's Known Exploited Vulnerabilities catalog (and the date it was
  added), with `kev_catalog_version` and `kev_date_released`, the catalog it was read from. A KEV stamp
  without `kev_listed` means the CVE was not in **that** catalog, released at that time — not that it
  is unlisted today.

Every value carries its own date because the values are captures of different ages; there is no
report-wide "as of" date. `provenance.intel.signals_digest` names the signals file once. Assay
recomputes that digest from the file's payload when it loads the file, and refuses a file whose
stated `signals_digest` does not match, so the digest a report names is one the scan verified.

The scanner holds no EPSS or KEV data of its own and never contacts FIRST or CISA. Signals are a
provided input, read from, in order:

1. `-advisory-signals <path>` — a `signals.json` or `signals.json.gz` (gzip is detected from the
   content);
2. the `ASSAY_ADVISORY_SIGNALS` environment variable;
3. the `signals.json` at the root of an `-advisory-corpus` **directory**, when it has one.

The file is the corpus's signals sidecar (`signals_version` 1.x — see the vulnerability corpus's
`CONSUMING.md`, "The signals sidecar"). Any other `signals_version`, or a file that is malformed or
carries a value without its stamp, fails the run: a broken signals file never turns silently into no
priority. A corpus directory without a `signals.json` is not an error.

Every run summary has a `signals:` line. With no signals source it says so, and **no finding carries a
`priority` block**: a run without signals reports no priority rather than an old one. When the newest
EPSS `as_of` in the file is older than `-advisory-signals-max-age` (default `168h`, 7 days), the line
carries a warning naming its age; the file still loads.

Every run re-ranks every finding with its own signals, including findings a PR run inherits from the
baseline, so no row keeps a value from a signals file this run did not read.

EPSS and KEV describe how often a CVE is exploited in the wild, across all software. They say nothing
about whether this codebase calls the vulnerable code — that is what the verdict and grade are for.
Nothing that decides a verdict reads them; they only order the findings.

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
| `report.sarif.json` | Under each result's `properties.scanner`: `reachability_grade`, `entry_point`, `attacker_controllable`, `epss_score`, `epss_percentile` and `epss_as_of` when there is an EPSS value, and `kev_listed`, `kev_date_added`, `kev_catalog_version` and `kev_date_released` when there is a KEV observation. The SARIF `rank` is the EPSS percentile × 100, and KEV-listed findings get a `CISA-KEV` tag. |
| `report.html` | Grade and EPSS/KEV badges, each with its own date, the call path, and a note on where the intel came from. |
| PR comment and pinned Issue | The grade and EPSS/KEV columns, each value with its own date, and a one-line reminder that neither is an exploitability claim. |
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

### Observed CI toolchain

The CLI also reads `ASSAY_CI_GO_VERSION`, the Go the CI runner has installed. The scan uses it as a
toolchain source only when you also set `ASSAY_TRUST_OBSERVED_GO=true`, which asserts that the
observed Go is the one your repository builds with: true in a job that ran `actions/setup-go` ahead
of the scan, false in a dedicated scan workflow where the observed Go is the runner image's. Any
other value leaves the observation out and resolution falls back to your `go.mod` directives. When
trusted, it counts as an exact toolchain, ranked after your declaration and above your `go.mod`
directives. The Action sets neither variable; set them in the `env:` of the step that runs it. These,
like `ASSAY_SUBJECT_GO_VERSION`, take effect in `pr-inherit` and `cve-watch`; `baseline` resolves the Go
toolchain from `go.mod` alone.

## Subject build conditions for Java and Maven

Maven profile activation depends on the JVM and the profile selection your build runs with, which the
scan does not look up. State them:

| What you state | CLI flag | Environment variable |
|---|---|---|
| The `java.version` of the JDK your program runs on, the same major version as the JVM that runs your build, as `mvn -v` reports it (for example `17.0.12` or `1.8.0_382`) | `-subject-java-version` | `ASSAY_SUBJECT_JAVA_VERSION` |
| The build's explicit profile selection in `-P` syntax: its `-P` list together with `settings.xml` `<activeProfiles>` (for example `release,!docs`, or `,` for none) | `-subject-maven-profiles` | `ASSAY_SUBJECT_MAVEN_PROFILES` |

The flag wins over the environment variable. The Action has no inputs for these; set the variables in
the `env:` of the step that runs it, as for `ASSAY_SUBJECT_GO_VERSION`. Profiles activated by `<jdk>`
stay undecided until you state the Java version, and every profile of the reactor and its parents stays
undecided until you state the selection.

The Java version you state is also the JDK your program runs on. It must be the same major version
as the JVM that runs the build, or the run fails. When your program runs on another JDK than the build,
including a runtime image newer than the build JDK, leave the version unstated. Don't state the build's
JDK in its place: the scan checks the statement against the build's JVM and toolchains, never against
the image you deploy, so a wrong statement goes unnoticed.
Bytecode reachability uses its table of the JDK's own methods only when the stated JDK is the release
that table describes, so on any other release, or none, more methods count as possible entry points.
The scan does the same for the whole build when a module's Maven or Gradle toolchain selects a JDK
other than the stated one, or when the graph cannot say which JDK a module uses: an Android project,
or a graph file written before toolchains were recorded.

## Resolving the JVM build graph

`resolve-graph` runs your repository's own Maven or Gradle and writes the resolved dependency graph as
`assay.buildgraph/v2` JSON, with the sha256 of each build file in the repository the tool read (POMs, Gradle scripts, properties,
version catalogs and lockfiles):

```sh
ferralon-assay resolve-graph -dir . -out "$RUNNER_TEMP/graph"
```

| Flag | Meaning |
|---|---|
| `-dir` | Repository root (default `.`). |
| `-out` | Output directory for `buildgraph.json` and its sidecars (required). It must be empty and outside the repository; the command rejects any other path, so a previous run's files are never read as this one's. |
| `-tool` | `auto` (default), `maven` or `gradle`. |
| `-profiles` | Comma-separated Maven profiles to activate. |
| `-java-version` | The JDK the job states, which the program runs on; a build tool on a different major version fails. |

A resolution that fails prints a typed cause, exits non-zero and writes no graph. A scan reads the
graph with `-build-graph <out>/buildgraph.json`, and accepts it only when the scan states the same JDK
and profiles (`-subject-java-version`, `-subject-maven-profiles`). This command runs your build's scripts and plugins, and the build tool fetches from
the repositories your build configures; see [threat-model.md](threat-model.md).

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
declared (`advisory-corpus-policy`) — every advisory in that policy whose affected package is one of
the repository's own dependencies. With a store selected, the result is persisted so later
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
        # Use the same ref as your main workflow (see the README Quickstart).
        uses: ferralon-ai/ferralon-assay@v0.5
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
| Pinned dashboard Issue, one issue rewritten each run | `issue` | `issues: write` | on | non-PR runs on the default branch, scheduled runs included |

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
