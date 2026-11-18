# The floor run

The floor is a diagnostic test suite for the engine. Each fixture under
`cmd/floorcheck/fixtures/<owner>__<repo>@<sha12>/` pins a repository at a full commit, the lane's
runtime, and the advisories it is judged on (`intel/advisories/`, a records-shape directory corpus
pinned by sha256). Its `expect.yaml` lists the expected finding per advisory: the adjudicated truth
and the weakest verdict that still counts as met. Expectations change only by hand, in the PR that
moves the finding.

`.github/workflows/floor.yml` runs every fixture nightly on `main`, and by hand through
`workflow_dispatch` with a `fixtures` selector (empty runs all of them): it builds the scanner and
`floorcheck` once, then runs one matrix job per fixture. Each job installs the runtimes the fixture's
`scenario.yaml` pins, and the Debian packages its `build.apt` names (C headers a cgo build needs).
Locally, `floorcheck run <fixture>… --out DIR` does the same scan and
comparison. A fixture passes when its scan is complete, every advisory it carries was assessed, and
every finding meets its floor. A worse verdict is a regression (exit 1); a scan that failed, was cut
short or left an advisory unassessed is incomplete (exit 2).

The sections below describe `floorcheck check`, which compares a scan's `report.json` with a demo
repository listed in `floor/targets.json` and its ledger in `floor/expect/`. `floor.yml` does not
run it.

## What fails a repository

`cmd/floorcheck` reads each scan's `report.json` the way Assay does (decode, upgrade an older
schema, `Validate`) and fails the repository for any of these reasons:

| Kind | Meaning |
|---|---|
| `ungrounded_not_exploitable` | A `not_exploitable` finding whose `evidence.basis` is empty or isn't one of `version_not_in_affected_range`, `vulnerable_symbol_absent`, `vulnerable_symbol_unreachable` or `static_refutation`. |
| `ungrounded_disqualified` | A `disqualified` finding whose basis is something other than a version, symbol or intake basis. |
| `path_outside_module` | A Go `reachable_candidate` finding whose `call_path` has no frame under the finding's own module path, so the path belongs to another package instance (another major version of the module). Standard-library rows, rows with no package and rows with no recorded frames are exempt. One failure per row, naming it. |
| `scan_truncated` | The scan hit its time limit (a `scan_cut_short` limit on the report), so some advisories weren't assessed. |
| `ledger_mismatch` | A showcase target's pinned scan differs from its ledger (`floor/expect/<name>.yaml`) by a missing, extra or changed row, by a reviewed row whose `bound_to` inputs are not the scan's, or the ledger's header is not the pinned scope, or the ledger breaks its own rules (a featured row that is not fully reviewed). See [The showcase lane](#the-showcase-lane). |
| `incomplete_scan` | A showcase scan that did not see the whole build: see [Incomplete scans](#incomplete-scans). |
| `scan_failed` | The scanner exited non-zero, or the scan step failed, was stopped or never ran. A report the scan still published is checked too. |
| `no_report` | The scanner exited cleanly but wrote no `report.json`. |
| `malformed_report` | `report.json` doesn't decode, has an unknown `schema_version`, or fails `Validate`. |
| `no_result` | The scan job left nothing behind: it failed before the scan, timed out, or was cancelled. |

**The grounds field is `evidence.basis`** (`report.EvidenceSummary.Basis`). It is the only grounds
field in `report.json`. `non_exploitable_basis` and `reasoned_grounds` belong to the service-tier
verdict (`verdict.Verdict`), which a report never contains, so floorcheck doesn't treat them as
grounds. `evidence.detail` is human-readable text, not grounds.

**`disqualified` findings.** On the version or symbol axis, the report carries that axis's basis
(`trigger/assess.go`, `disqualBasis`), and floorcheck checks it. An intake disqualification
carries its own basis, `advisory_ecosystem_mismatch` or `no_manifest_entry`, which says why the
row is disqualified. No comparison was made, so there is nothing to check. (Reports written before
this change carry no basis on these rows, which floorcheck treats the same way.) These findings are counted as unverifiable in the summary but
don't fail the repository.

`undetermined` never fails a repository. It is the honest result when nothing was established, and
the summary counts it and lists its most common `undetermined_reason` codes.

## How the run works

1. **Check secrets.** If `FLOOR_DEMO_TOKEN` is missing, the run posts one notice and stops. Nothing
   is scanned and the run is not marked failed.
2. **Build the scanner.** One job builds the scanner, its analyzers and `floorcheck` from the
   triggering commit. It validates `floor/targets.json` (`floorcheck matrix`), then fetches the
   corpus bundle for each policy from one corpus release (and the showcase lane's pinned release, by its tag), verifying its signature and digest with the same scripts
   `action.yml` uses. Everything goes into one artifact that the scan jobs share.
3. **Scan.** One job per target (and, for each showcase target, a second job on the floating corpus), in parallel, each with `timeout-minutes: 30`. Each job checks out
   the repository (a demo repository with `FLOOR_DEMO_TOKEN`, a public one with the workflow's own
   token), sets up the toolchain that repository's own workflow
   uses (Go from its `go.mod`, Java 11), and runs `floor/scan.sh`. The scanner's own limit is 22
   minutes, so it stops itself and publishes what it assessed. Each job records `meta.json`
   (scan outcome, exit code, duration, Assay commit) whatever happens.
4. **Check the floor.** `floorcheck check` reads every result and writes three files:
   `floor-summary.json`, the job summary, and, if anything failed, the alert text. All of them go
   into one `floor-summary` artifact together with every report. The job fails if any repository
   failed.
5. **Alert.** If the build, a scan or the check failed and `FLOOR_SLACK_WEBHOOK` is set, the run
   posts at most four short bullets to Slack, ending with the run link.

The demo targets use the corpus policy in `floor/targets.json`. Today that is `published-24h`, the
policy each demo repository's own `ferralon-assay.yml` uses. `floorcheck` refuses `full` there,
because a demo repository's default branch moves. The `pinned` lane holds real public repositories,
each at a full commit id, under its own policy, today `full`. A fixed commit bounds the scan, so the
lane measures what Assay finds on real code under the whole corpus; `floorcheck` refuses a pinned
target whose ref is not a 40-hex commit. The same floor checks apply to both lanes. The scanner's GitHub surfaces (Issue, PR comment, code scanning) and the
console link stay off: the job runs in this repository, not in the scanned one.

## The showcase lane

The `showcase` block of `floor/targets.json` holds real Go applications scanned at a pinned commit:
traefik v3.3.2 and gitea v1.23.1. Where the pinned lane measures what Assay finds, the showcase lane
**checks it against a written record**: an expected-verdict ledger per target, under
`floor/expect/<name>.yaml`. It exists to make verdict movement visible: a regression, an improvement
and the gap between what Assay emits and what is true.

What the lane pins, all in the `showcase` block, so a ledger holds on any runner:

| Pin | Where | Today |
|---|---|---|
| Upstream commit | each target's `ref` (a full commit id; `tag` is for the reader) | traefik `020ab5f3…`, gitea `fcbbc24c…` |
| Corpus release | `corpus_release`, fetched by tag (not the latest) | `corpus-92d72057330c` |
| Go toolchain | `go_version`, an exact release, and `GOTOOLCHAIN=local` | `1.23.12` |
| Build | `goos`, `goarch`, `cgo`; build tags and test scope are the scanner's defaults (none, tests excluded) | linux/amd64, cgo off |
| Corpus policy | `policy` | `full` |

Each target is scanned **twice** by the same `floor/scan.sh`:

- **Pinned** (`traefik`, `gitea`): on the pinned corpus release. `floorcheck` fails it on any ledger row
  that is **missing, extra, duplicated or changed** against `engine_expected`, whether the change is a
  regression or an improvement, and on a ledger whose header is not the pinned scope. Each difference
  is one line with the old and the new value: `changed: <alias set> | <package@version> | <target>: undetermined/refutation_withheld -> not_exploitable/static_refutation`.
- **Floating** (`traefik-floating`, `gitea-floating`): on the latest corpus release of the same policy.
  **Report-only**: it never fails the run. The job summary lists its drift from the ledger (and any
  failure the scan would otherwise have had), which shows what the next corpus release will change.

A scan that exceeds the runner's time or memory is not given more: record the measurement and take the
target out of `showcase.targets`.

### The ledger

One row per advisory **alias set**, **resolved package instance** (`module@version`) and **scan
target**. Findings on the same package that share any id or alias are one set; where they disagree the
stronger verdict is recorded, so a set is never shown cleaner than its worst finding. The header is the
build scope: upstream SHA, entry packages, GOOS/GOARCH, build tags, cgo, test scope, Go version, corpus
release and the comparator's name, version and database timestamp. A row has:

| Field | Meaning |
|---|---|
| `comparator_observed` | `reachable`, `not_reachable`, `out_of_range`, `not_present`, `conditional` or `unknown`: what the comparator (govulncheck) said. An observation, not ground truth. |
| `basis`, `source` | With `comparator_observed`: why, and where it came from. |
| `adjudicated` | A person's conclusion, apart from the comparator: see [Comparator and adjudication](#comparator-and-adjudication). Seeded `status: unknown` on every row. |
| `engine_expected` | `verdict` and `reason` as Assay emits them today (`undetermined_reason` for an undetermined finding, the evidence basis for a refutation). `not_emitted` is a row the comparator reports in a module and Assay emits no finding for at all; it is kept so the blind spot is on record, and the check fails when Assay starts to emit it. |
| `path_review` | On every row whose `engine_expected` verdict is `reachable_candidate`, and only those: see [Path review](#path-review). |
| `featured` | `true` marks a row a demo shows. Allowed only when `path_review.status` is `real` (reachable rows) **and** `adjudicated.status` is not `unknown`. |
| `gap` | The tracker issue, required when `comparator_observed` and `engine_expected` contradict each other. `#790` covers `refutation_withheld`; `unfiled: …` marks a gap with no issue yet. |

### Comparator and adjudication

**`comparator_observed` is seeded from a comparator and is not ground truth.** `govulncheck -mode source
-format json ./...` (its version is pinned in the header) runs on each target, and its output, normalized,
is committed under `floor/expect/evidence/`. Assay's own Go reachability also runs govulncheck as a library,
so the comparator is **not independent** of the engine: agreement between the two is not confirmation.
`comparator_observed` is derived by these rules and none other:

1. `stdlib` and toolchain rows: `unknown`, "depends on toolchain".
2. govulncheck reached the advisory in the module at symbol level: `reachable`; at package level:
   `not_reachable`, "imported, vulnerable function not called"; at module level: `not_reachable`,
   "required, vulnerable package never imported". `source: govulncheck <version>`.
3. Assay's own out-of-range verdict: `out_of_range`.
4. Anything else: `unknown`: the comparator has no view.

A comparator finding in a module Assay emitted nothing for becomes a `not_emitted` row (its observation by rules
2 to 4). Comparator findings in `stdlib` are not rows: they depend on the toolchain.

`floorcheck seed` applies the rules; nothing else writes a `comparator_observed`.

**`adjudicated` is where a human conclusion goes.** Nothing in this repository sets it but a person:

```yaml
adjudicated:
  status: unknown          # unknown | reachable | not_reachable | out_of_range | not_present | conditional
  by: <reviewer>           # by, date and evidence are required unless the status is unknown
  date: 2026-11-16
  evidence: traefik/pkg/x/y.go:120   # checkable: file:line in the pinned upstream, a vendor advisory's
                                     # preconditions, or a reviewed call graph
  note: one line why
  bound_to: {…}            # required with a conclusion; see below
```

Who may set it: a **named reviewer**, who puts their name in `by`. **A featured row needs a second
reviewer, named in the pull request**, who is not the one who edited the file. `floorcheck seed` and
`seed -update` never set a status other than `unknown`.

### Path review

A reachable finding is only as convincing as the call path shown with it. An interface-dispatch edge
(`io.Reader`, `error`, `http.Handler`…) can make a path look like a real route when it is not, so every
reachable row records the path Assay shows today and whether a person has read it:

```yaml
path_review:
  path: [code.gitea.io/gitea/routers/web/repo.UpdatePullRequestTarget, github.com/andybalholm/brotli.decodeError.Error]
  hops: 2
  path_sha: 3f1c9a0b7d2e4a55   # first 16 hex of sha256 of the path's functions, joined by newlines
  status: unreviewed           # unreviewed | real | artifact | unclear
  by: <reviewer>               # by, date and note are required unless the status is unreviewed
  date: 2026-11-16
  note: one line why
```

| Status | Meaning |
|---|---|
| `unreviewed` | Nobody has read the path. Every row is seeded this way, and a changed path returns to it. |
| `real` | A reviewer read the path and each hop is a call the program makes. |
| `artifact` | A reviewer read the path and a hop is not real (typically an interface-dispatch edge to code the program never wires there). |
| `unclear` | A reviewer could not tell from the source. Treated like `unreviewed` for featuring. |

`floorcheck check` fails a showcase target when:

- a reachable row has no `path_review` block (or a block's `hops` or `path_sha` does not describe its
  `path`);
- the engine's current path for a row hashes differently from `path_sha`. The failure names the row, the
  old path and the new path. Fix it by updating `path` and `path_sha` (`floorcheck seed -update` does) and
  resetting `status` to `unreviewed` in the same pull request: a review is of one path;
- a reviewed row's `bound_to` is not the scan's: see [What a review is bound to](#what-a-review-is-bound-to);
- a row has `featured: true` and its `path_review` status is not `real`, or its `adjudicated.status` is
  `unknown` (or lacks `by`, `date` or `evidence`). The failure is one line naming the row and the rule.

**Only rows a person has fully reviewed may be featured in a demo: a `real` path (reachable rows) and an adjudication.** Marking a row `real` or `artifact` is a human call and
needs a reviewer named in the pull request; the one who edits the file does not review their own change.
`floorcheck seed -update` keeps a review while the path is unchanged and never sets a status other than
`unreviewed`.

Assay's report does not yet say what kind of edge joins two frames, so the ledger has no `dynamic_edges`
count. The review aid marks the hops it reads as likely interface dispatch: a standard-library method named
for a generic interface (`Read`, `Write`, `ReadFrom`, `Close`, `Error`, `String`, `ServeHTTP`,
`RoundTrip`…), and a standard-library hop whose next hop is back in the target or a dependency (the
standard library can reach that code only through an interface or a function value). It is a reading
aid, not a verdict: the reviewer still reads the source.

**The review aid** prints every reachable row with its path, one hop per line, each hop marked `target`,
`dependency` or `stdlib`:

```
floorcheck paths -targets floor/targets.json [-target gitea]
```

### What a review is bound to

The same path text can mean something else when what produced it changes. A `path_review` past
`unreviewed`, and any `adjudicated` conclusion, therefore carries a `bound_to` block: the analysis inputs
the person read it against.

```yaml
bound_to:
  target: traefik@020ab5f34703ea523895ab004825dbfa6f7de060   # target name @ the scan's resolved commit
  component: github.com/andybalholm/brotli@v1.1.0            # module@version
  symbol: github.com/andybalholm/brotli.decodeError.Error     # the vulnerable symbol the call path ends at
  symbol_confidence: high                                     # the engine's reading of the symbol set's provenance
  analysis:
    assay_version: <the report's provenance.analyzer_version>
    assay_commit: <the scanner's build commit, from the scan's meta.json>
    corpus_release: corpus-92d72057330c
    go_version: 1.23.12
```

`floorcheck check` compares every field with the current scan for each reviewed row and fails naming the
field: `review stale: <row>: path_review bound_to.analysis.corpus_release: recorded "…", scan has "…"`.
**Fix it by re-reviewing**: `floorcheck seed -update` records the new inputs and resets `path_review.status`
to `unreviewed` (and `adjudicated.status` to `unknown`, and `featured` off), as it does for a changed path.
An unreviewed row is not held to its inputs; `seed` refreshes them.

Assay's report does not carry the advisory's full vulnerable-symbol set or its raw `symbol_provenance`
tag. It carries the symbol the call path ends at and `symbol_confidence` (`high`: osv-declared or curated;
`moderate`: diff-lexed; empty: cna-declared, unrecognized or absent), so those are what is recorded.
`floorcheck seed` reads `meta.json` beside `report.json` for the scanner commit, corpus release and Go
version, and falls back to the lane's pins for the last two.

### Review a row

A reviewer judges one row from its **packet**, not from the ledger and a checkout assembled by hand:

```
floorcheck packet -target gitea -row CVE-2025-47911 \
    -report report.json -source ./src [-modcache DIR] [-goroot DIR] [-verify-links]
floorcheck packet -target gitea -featured -report report.json -source ./src
```

`-row` takes a row's full key or any advisory id of its alias set, and a reachable row only (a row with no
`path_review` has no path to read); an id that names several reachable rows is refused with their keys.
`-featured` writes every featured row. Each row gets a directory, `<target>-<CVE>-<module>-<version>/`, of
`packet.md` (for reading) and `packet.json` (the same, for tools), under `floor/expect/packets/` unless `-out` says
otherwise. The packet holds:

- **the row as stored**, and any note on it, such as an `ATTRIBUTION MISMATCH` where the path ends in a module other
  than the row's component;
- **the call path, one hop per line**: kind (target, dependency or stdlib), a likely interface dispatch marked, a
  GitHub permalink at the pinned upstream commit for a target hop, one at the exact module version (or the Go release
  tag, for the standard library) for a dependency hop, and the versioned pkg.go.dev entry. The file and line are the
  declaration of the hop's function in the **build the header pins** (GOOS, GOARCH, tags, cgo, tests excluded), read from
  `-source` (a checkout at the pinned commit, which the command refuses to read from any other), from `-modcache`
  (default `go env GOMODCACHE`) and from `-goroot` (the pinned toolchain's). A target hop's file and line come from the
  report when it has them (the source's own declaration wins where the two differ, and the packet says so). A hop with no
  file and line says why (`source not available here`, a name declared twice in the build, a module at a host with no
  line link) and carries no link: nothing is guessed. `-verify-links` fetches each permalink's file and records
  whether the linked line declares the function;
- **the analysis inputs**: Assay version and commit, corpus release and digest, Go toolchain, policy, GOOS/GOARCH, build
  tags, test scope, and the exact scan command. A reviewed row's `bound_to` supplies the Assay inputs; for an unreviewed
  row they come from `-report` and its `meta.json`, and read `not recorded` without them;
- **Assay's raw finding** for the row (from `-report`: the pinned scan's `report.json`, downloaded from the floor run)
  and **govulncheck's entry** for the same advisory and instance, from `floor/expect/evidence/`;
- **a rerun section**: the commands that reproduce the row from a clean machine.

A packet decides nothing. Read the path, hop by hop, against the source it links to. Decide `real`, `artifact` or
`unclear` for the path, and an `adjudicated` status for the row, then record both in the ledger in a pull request that
names the reviewer ([Path review](#path-review), [Comparator and adjudication](#comparator-and-adjudication)); the one who
edits the file does not review their own change. A changed path or analysis puts the row back to `unreviewed`, and a
packet is generated again from the new scan. The committed packets under `floor/expect/packets/` are the worked
example: the five gitea shortlist rows and the traefik one. They were generated from the pinned sources with
`-verify-links` and the pinned scan's `report.json`, so each carries Assay's raw finding and the scanner commit;
regenerate them from the next pinned scan's `report.json` whenever the ledger is re-seeded.

### Incomplete scans

A broken toolchain once produced a clean-looking scan of zero packages. A clean-looking report has no
findings to differ from, so the showcase lane also fails the **pinned** scan, one line each, when:

- the package inventory is empty (`the scan's package inventory is empty`), or lacks more than
  `inventoryTolerance` (3, in `cmd/floorcheck/incomplete.go`) of the ledger's distinct component instances
  (module@version, without `stdlib`, `toolchain` and `-`);
- the report's partiality says the scan was cut short (`scan_truncated`, raised on every lane), or records a
  `tool_failure` (a wrapped tool or the toolchain failed);
- fewer ledger rows are answered than the ledger holds: a row is answered when the engine emitted a row under
  its key, or the ledger expects `not_emitted` and the engine emitted none.

These are `incomplete_scan` failures. On the floating scan they are reported and never fail the run.
`go_toolchain_unresolved` and `go_toolchain_not_scanned` are not failures here: they are per-finding reasons the
ledger records and compares like any other.

### Updating a ledger row

A change in Assay's output fails the pinned showcase scan until the ledger agrees, in the same pull
request:

1. Read the failure lines in the job summary (or `floorcheck check` output). Decide whether the move is
   the intended one.
2. Download the pinned scan's `report.json` and run
   `floorcheck seed -target <name> -report report.json -update`. `-update` keeps every existing row's
   `comparator_observed`, `basis`, `source` and `gap` and follows the report for `engine_expected`; a gap the
   engine closed is dropped and a new disagreement gets one. New rows get their observation by the rules
   above. A review (path or adjudication) whose path or `bound_to` inputs changed is reset and the row
   loses `featured`.
3. Commit `floor/expect/<name>.yaml`.

**A change to a `comparator_observed`, or to its `basis` or `source`, needs a second reviewer, named in the
pull request.** The rules above are the only way it is set; a hand edit is a judgment, and judgments
are reviewed by someone who did not make them. Re-seeding without `-update` (a new comparator run, a new
pin) rewrites every row and is that kind of change.

### Bumping the pinned corpus (or the toolchain, or a commit)

1. Choose the release: the latest `corpus-<12 hex>` of `ferralon-ai/vulnerability-corpus`.
2. Edit `showcase.corpus_release` (and `go_version` or a target's `ref`, if bumping those) in
   `floor/targets.json`, and the same fields in each ledger header: the check fails a ledger whose header
   does not match.
3. Re-run the comparator on each target at the new pins (`govulncheck -mode source -format json ./...`
   under the pinned `go_version`, `GOOS`, `GOARCH` and `CGO_ENABLED`) and run
   `floorcheck seed -target <name> -report report.json -govulncheck govulncheck.json`.
4. Review the ledger diff as a `comparator_observed` change (a second reviewer), and say in the pull request why the
   pin moved. A release is bumped deliberately, never because the floating scan drifted.

## Adding a target

Add an entry to `targets` in `floor/targets.json`:

```json
{ "repo": "ferralon-demo/<name>", "language": "go", "ref": "baseline", "include_house_canaries": true }
```

- `repo` (required): `owner/name`. The name must be unique among targets, because it names the
  scan job and its artifact.
- `language` (required): the language the repository's build files show. Use one of `go`, `java`,
  `kotlin`, `js`, `python`, `dotnet`, `cfamily` or `rust`.
- `ref` (optional): the branch, tag or commit to scan. Leave it out to scan the default branch.
  The case-study repositories keep their code on `baseline`.
- `include_house_canaries` (optional): set it when the repository's own workflow sets
  `include-house-canaries`.

A repository you deliberately leave out goes under `excluded`, with a `reason`. The summary lists
it under "Not scanned". `go test ./cmd/floorcheck` checks the file with the same parser the build
job uses. If the target is private, make sure `FLOOR_DEMO_TOKEN` can read it.

## Secrets

Add both under the repository's **Settings → Secrets and variables → Actions**.

| Secret | Required | Narrowest scope that works |
|---|---|---|
| `FLOOR_DEMO_TOKEN` | yes; without it the run ends with a notice | A fine-grained personal access token whose resource owner is `ferralon-demo`. Grant it access to only the target repositories, with **Contents: read-only** (GitHub adds **Metadata: read-only** automatically). Give it no other permission. |
| `FLOOR_SLACK_WEBHOOK` | no; without it the run posts a notice and sends no alert | A Slack incoming-webhook URL for the one channel the alert should reach. It can post only to that channel. |

The run uses no other secret. The workflow's own `GITHUB_TOKEN` is read-only
(`permissions: contents: read`), and the corpus is public, so it is fetched without credentials.

## Reading the summary

The job summary (and `floor-summary.md` in the artifact) starts with **PASS** or **FAIL**, then:

- **By language**: the number of targets per language across both lanes, how many passed, and the
  qualified findings (`reachable_candidate`, `malicious_package_present`) on each lane, counted
  once per alias set per repository, so a finding filed under PYSEC, CVE and GHSA ids counts once.
  A language marked **no target** has no demo repository yet. Today that is `kotlin`, `dotnet`,
  `cfamily` and `rust`.
  There is no .NET, Kotlin or Rust target today.
- **By repo**: one row per target. The columns are the Assay commit the scanner was built from, the
  corpus policy, verdict counts, the qualified alias sets, the three most common `undetermined_reason` codes, whether the
  scan was truncated, how long the scan took, and the result.
- **Failures**: each failure kind with its details and the offending finding ids (advisory id and
  package).
- **Showcase lane**: per scan (pinned and floating): corpus release, Go version, duration, peak memory,
  the number of differences from the ledger, and the verdict counts by reason; the `comparator_observed` × `engine_expected`
  table over the ledgers and the count of adjudications by status; and the floating scan's drift, which is report-only.
- **Not scanned**: the excluded repositories and why.

`floor-summary.json` holds the same data in machine-readable form (`schema:
ferralon.floor-summary.v1`), and the artifact includes every `report.json` and `meta.json`.

## The caveat tally

The language capability matrix names the caveats that stop Assay from reaching a verdict in each
language, such as `JS-UNINSPECTABLE-RUNWIDE` or `JAVA-GRAPH-PRECONDITION`. The matrix is
`docs/capabilities/`, one page per language, added by
[#246](https://github.com/ferralon-ai/ferralon-assay/pull/246) and shipped with the v0.6.0 release
([#184](https://github.com/ferralon-ai/ferralon-assay/pull/184)). The floor run measures
which of its caveats fire on each demo repository, every night, so the matrix's prevalence figures
come from real scans instead of estimates. [Caveat ids](#caveat-ids) lists the ids the tally uses.

**What it counts.** `floorcheck check` reads every machine-readable reason a readable
`report.json` carries:

- each `partiality[].reason`. A note that names no `package` and no `path` is **run-wide**;
- each `advisories[].undetermined_reason`;
- each package's `partial_reason`, on a finding or in the SBOM.

It looks each reason up in `floor/caveats.json` for the repository's language. Per repository,
`floor-summary.json` lists under `caveats` each caveat that fired, with:

- `findings`: how many findings it affected;
- `run_wide`: whether a reason behind it was declared for the whole run;
- `reasons`: the raw reason codes behind it.

A finding is affected when it names the reason itself, as its `undetermined_reason` or as its
package's `partial_reason`. A did-not-run partiality note whose reason is no finding's
`undetermined_reason` keeps the run's refutations from standing, so it affects every finding left `undetermined` with
`analysis_did_not_run`. The report doesn't say which limit held which of those findings, so each
such caveat counts all of them. Read that number as an upper bound. This holds for a note that
names a `package` too. That package is where the blind spot is, not which findings it held: the
analyzer also records the packages the hidden code could reach, and the trigger counts the limit
against a finding on that package or any of those, or on every finding when the list is empty.
`report.json` doesn't carry that list, so counting only the findings on the note's `package` could
leave out findings the limit held. A methodology note (`class: inherent_limit`) holds no verdict
and affects no finding.

Under `caveats` at the top level, the summary rolls the tally up per language: for each caveat, how
many of that language's targets it fired on (`repos`, `fired_on`) and the findings it affected
across them. The job summary shows the same roll-up under **Caveats by language**, with one table
per language that has a target. Caveats that hold for every scan of a language and have no reason
code (`JS-NO-CLEAR-GROUNDS`, `PYTHON-NO-CLEAR-PRODUCER`) are listed as **always applies**.

**Unmapped reasons are shown raw.** A reason with no mapping for the repository's language is
never dropped. It appears as `unmapped:<reason>`, both per repository and in the roll-up. The
same goes for the scoped form of a reason that is mapped only run-wide.

**Caveats are informational.** They never fail a repository, never change the run's result and
never reach the Slack alert. If `floor/caveats.json` can't be read, `floorcheck` logs the error,
records it as `caveat_mapping_error`, and shows every reason unmapped. The run's result is
unaffected.

### Caveat ids

These are the caveat ids `floor/caveats.json` may name, and where each is defined. A matrix page is
a page of `docs/capabilities/`, one page per language, added by
[#246](https://github.com/ferralon-ai/ferralon-assay/pull/246) and shipped with the v0.6.0 release
([#184](https://github.com/ferralon-ai/ferralon-assay/pull/184)).
`TestShippedCaveatIDs` fails if a mapping's `caveat` or a `structural` caveat is not in this
table, so a misspelt id fails the tests.

| Caveat | Language | Defined in |
|---|---|---|
| `JS-UNINSPECTABLE-RUNWIDE` | js | matrix, `javascript.md` |
| `JS-LOADTIME-CODEGEN` | js | matrix, `javascript.md` |
| `JS-UNLISTED-RESIDUE` | js | matrix, `javascript.md` |
| `JS-NO-CLEAR-GROUNDS` | js | matrix, `javascript.md` (structural) |
| `JAVA-GRAPH-PRECONDITION` | java | matrix, `java.md` |
| `JAVA-LAUNCH-ENTRY-UNLICENSED` | java | matrix, `java.md` |
| `JAVA-OTHER-TOOL-BUILD` | java | matrix, `java.md` |
| `JAVA-INSTALL-UNLISTED` | java | matrix, `java.md` |
| `JAVA-FRAMEWORK-HAZARD` | java | matrix, `java.md` |
| `JAVA-FIRST-PARTY-BYTECODE-ABSENT` | java | this tally, named after `first_party_bytecode_absent`; not a matrix id |
| `PYTHON-DYNAMIC-IMPORT-RUNWIDE` | python | matrix, `python.md` |
| `PYTHON-NO-CLEAR-PRODUCER` | python | matrix, `python.md` (structural) |
| `SCAN-CUT-SHORT` | any | this tally, for `scan_cut_short`; not a matrix id |

### Adding a mapping

Add an entry to `mappings` in `floor/caveats.json`:

```json
{
  "reason": "tool_failure:build_graph_absent",
  "language": "java",
  "run_wide": true,
  "caveat": "JAVA-GRAPH-PRECONDITION",
  "defined_in": "internal/plugin/javaanalysis/graph.go",
  "note": "every Java op without a build graph declares it"
}
```

- `reason` (required): the code exactly as the report carries it, suffix included.
- `language` (required): one of the target languages, or `any`. A language's own mapping wins over
  an `any` mapping.
- `run_wide`: set it to `true` when the caveat is only the run-wide form of the reason. Scoped
  notes, finding reasons and package reasons then don't fire it. Set it to `false` to fire the
  caveat on every occurrence. One reason can have one mapping of each kind per language.
- `caveat` (required): the matrix's caveat id, in upper case with hyphens. A new id needs a row
  under [Caveat ids](#caveat-ids).
- `defined_in` (required): the non-test Go file that declares the reason's constant.
  `TestShippedCaveatReasons` evaluates that file's string constants (literals, `plugin.X`,
  `report.X`, same-package names and `+`) and fails if none has the reason's value, so the mapping
  can't drift away from the code.
- `note` (optional): what emits the reason, for the next reader.

A caveat with no reason code, one that holds for every scan of a language, goes under
`structural` as `{ "caveat": "...", "language": "..." }`. Run `go test ./cmd/floorcheck` after
any change. It checks the file with the same parser `floorcheck` uses.
