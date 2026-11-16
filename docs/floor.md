# The floor run

Every night, `.github/workflows/floor.yml` builds the scanner from `main` and scans each demo
repository listed in `floor/targets.json`. It fails if any repository shows a `not_exploitable`
finding without grounds, or if a scan failed, timed out or was cut short. The job summary shows
what Assay returned for each repository, grouped by language. Two things depend on it:

- **No ungrounded `not_exploitable`.** The grounds gate in `trigger/grounds.go` only lets a finding
  become `not_exploitable` when it has evidence. G0: an analysis step that did not run leaves the
  advisory `undetermined`, even when grounds exist. G1: the advisory was admitted on a package
  whose installed version resolved. G2: either every advisory symbol resolved inside that package
  and was searched from the entry points, or the analyzer refuted the package on positive
  evidence. Otherwise the finding is `undetermined`, with its reason. The gate is tested in-process;
  the floor run checks its output on real repositories after every merge.
- **The language claim.** The per-language table is the measured answer to "what does Assay
  return for a Go, Java, JavaScript or Python repository today?". Languages that have no target
  are listed as gaps.

## What fails a repository

`cmd/floorcheck` reads each scan's `report.json` the way Assay does (decode, upgrade an older
schema, `Validate`) and fails the repository for any of these reasons:

| Kind | Meaning |
|---|---|
| `ungrounded_not_exploitable` | A `not_exploitable` finding whose `evidence.basis` is empty or isn't one of `version_not_in_affected_range`, `vulnerable_symbol_absent`, `vulnerable_symbol_unreachable` or `static_refutation`. |
| `ungrounded_disqualified` | A `disqualified` finding whose basis is something other than a version or symbol basis. |
| `scan_truncated` | The scan hit its time limit (a `scan_cut_short` limit on the report), so some advisories weren't assessed. |
| `ledger_mismatch` | A showcase target's pinned scan differs from its ledger (`floor/expect/<name>.yaml`) by a missing, extra or changed row, or the ledger's header is not the pinned scope. See [The showcase lane](#the-showcase-lane). |
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
(`advisory_ecosystem_mismatch`, `no_manifest_entry`) carries no basis, because no comparison was
made, so there is nothing to check. These findings are counted as unverifiable in the summary but
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
| `truth` | `reachable`, `not_reachable`, `out_of_range`, `not_present`, `conditional` or `unknown`: what is the case, not what Assay says. |
| `basis`, `source` | A checkable pointer: why, and where it came from. |
| `engine_expected` | `verdict` and `reason` as Assay emits them today (`undetermined_reason` for an undetermined finding, the evidence basis for a refutation). `not_emitted` is a row the comparator reports in a module and Assay emits no finding for at all; it is kept so the blind spot is on record, and the check fails when Assay starts to emit it. |
| `gap` | The tracker issue, required when `truth` and `engine_expected` contradict each other. `#790` covers `refutation_withheld`; `unfiled: …` marks a gap with no issue yet. |

**Truth is seeded from a comparator and is not ground truth.** `govulncheck -mode source -format json ./...`
(its version is pinned in the header) runs on each target, and its output, normalized, is committed under
`floor/expect/evidence/`. `truth` is derived by these rules and none other:

1. `stdlib` and toolchain rows: `unknown`, "depends on toolchain".
2. govulncheck reached the advisory in the module at symbol level: `reachable`; at package level:
   `not_reachable`, "imported, vulnerable function not called"; at module level: `not_reachable`,
   "required, vulnerable package never imported". `source: govulncheck <version>`.
3. Assay's own out-of-range verdict: `out_of_range`.
4. Anything else: `unknown`: the comparator has no view.

A comparator finding in a module Assay emitted nothing for becomes a `not_emitted` row (its truth by rules
2 to 4). Comparator findings in `stdlib` are not rows: they depend on the toolchain.

`floorcheck seed` applies the rules; nothing else writes a `truth`.

### Updating a ledger row

A change in Assay's output fails the pinned showcase scan until the ledger agrees, in the same pull
request:

1. Read the failure lines in the job summary (or `floorcheck check` output). Decide whether the move is
   the intended one.
2. Download the pinned scan's `report.json` and run
   `floorcheck seed -target <name> -report report.json -update`. `-update` keeps every existing row's
   `truth`, `basis`, `source` and `gap` and follows the report for `engine_expected`; a gap the engine
   closed is dropped and a new disagreement gets one. New rows get their truth by the rules above.
3. Commit `floor/expect/<name>.yaml`.

**A change to a `truth`, or to its `basis` or `source`, needs a second reviewer, named in the pull
request.** The rules above are the only way a `truth` is set; a hand edit is a judgment, and judgments
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
4. Review the ledger diff as a `truth` change (a second reviewer), and say in the pull request why the
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
  the number of ledger rows that differ, and the verdict counts by reason; the truth × `engine_expected`
  table over the ledgers; and the floating scan's drift, which is report-only.
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
