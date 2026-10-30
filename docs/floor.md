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
   corpus bundle for the policy, verifying its signature and digest with the same scripts
   `action.yml` uses. Everything goes into one artifact that the scan jobs share.
3. **Scan.** One job per target, in parallel, each with `timeout-minutes: 30`. Each job checks out
   the repository with `FLOOR_DEMO_TOKEN`, sets up the toolchain that repository's own workflow
   uses (Go from its `go.mod`, Java 11), and runs `floor/scan.sh`. The scanner's own limit is 22
   minutes, so it stops itself and publishes what it assessed. Each job records `meta.json`
   (scan outcome, exit code, duration, Assay commit) whatever happens.
4. **Check the floor.** `floorcheck check` reads every result and writes three files:
   `floor-summary.json`, the job summary, and, if anything failed, the alert text. All of them go
   into one `floor-summary` artifact together with every report. The job fails if any repository
   failed.
5. **Alert.** If the build, a scan or the check failed and `FLOOR_SLACK_WEBHOOK` is set, the run
   posts at most four short bullets to Slack, ending with the run link.

Every scan uses the corpus policy in `floor/targets.json`. Today that is `published-24h`, the
policy each demo repository's own `ferralon-assay.yml` uses. `floorcheck` refuses `full`, so the
run stays bounded. The scanner's GitHub surfaces (Issue, PR comment, code scanning) and the
console link stay off: the job runs in this repository, not in the scanned one.

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

- **By language**: the number of targets per language and how many passed. A language marked
  **no target** has no demo repository yet. Today that is `kotlin`, `dotnet`, `cfamily` and `rust`.
  There is no .NET, Kotlin or Rust target today.
- **By repo**: one row per target. The columns are the Assay commit the scanner was built from, the
  corpus policy, verdict counts, the three most common `undetermined_reason` codes, whether the
  scan was truncated, how long the scan took, and the result.
- **Failures**: each failure kind with its details and the offending finding ids (advisory id and
  package).
- **Not scanned**: the excluded repositories and why.

`floor-summary.json` holds the same data in machine-readable form (`schema:
ferralon.floor-summary.v1`), and the artifact includes every `report.json` and `meta.json`.
