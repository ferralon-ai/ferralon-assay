# Glossary

This page defines the terms, labels and identifier schemes a newcomer meets in this repository's
README, its `docs/`, its Action and its code. Every definition is taken from the files it cites and
says nothing they do not; where no file defines a term, the entry says so and describes only how the
term is used. Each entry cites one to three `path:line` locations, the defining one first. Where two
sources disagree, or one word names two things, the entry is marked **Collision** and gives both. A
term that belongs to Ferralon's paid product is described only as far as this repository's own docs
describe it. All citations were taken at commit `6ca71c51ab6faab120fce4c416156145cb8e3b36`; a line
number can drift once the cited file changes. Each entry has an anchor (`#term-name`) for deep links.

## Label schemes

<a id="scheme-pipeline-stages"></a>**Pipeline stages S1–S6** — The six built-in Assess stages, in
order: S1 `advisory_intake`, S2 `codebase_inventory`, S3 `disqualification_discovery`, S4
`symbol_mapping`, S5 `reachability_ingress`, S6 `exposure_footprint`. The canonical list is
`AssessStages()` in `pipeline/stages.go`; stages after S6 are not part of this repository.
*Source:* `pipeline/stages.go:3`, `README.md:369`, `README.md:508`. *See also:* [stage](#stage),
[Assess](#assess).

<a id="scheme-grounds"></a>**Grounds conditions G0–G2** — The conditions the grounds gate checks
before a finding may become `not_exploitable`. G0: an analysis step that did not run leaves the
advisory `undetermined`, even when grounds exist. G1: the advisory was admitted on a package whose
installed version resolved. G2: every advisory symbol resolved inside that package and was searched
from the entry points, on a vetted symbol set (arm A); an unvetted set leaves the advisory
`undetermined` unless arm B grounds it. Arm B: the analyzer refuted the package on positive
evidence. *Source:* `docs/floor.md:9`, `trigger/grounds.go:23`. *See also:* [grounds](#grounds),
[not_exploitable](#not-exploitable), [vetted symbol set](#vetted-symbols).

<a id="scheme-capability-groups"></a>**Capability groups 1–8** — The eight stages each language
advances through, each unlocking a stronger verdict: 1 Dependency inventory, 2 Version clearing, 3
Build-graph fidelity, 4 Call graph, 5 Reachability clearing, 6 Framework & dynamic-dispatch
modeling, 7 Hazard bounding, 8 Runtime confirmation. The canonical table is in
`docs/capabilities/README.md`. *Source:* `docs/capabilities/README.md:3`,
`docs/capabilities/README.md:9`. *See also:* [capability status](#complete-partial),
[caveat](#caveat).

<a id="scheme-caveat-ids"></a>**Caveat IDs (`<LANG>-<NAME>`)** — A caveat is a named, stable ID such
as `GO-REFLECT-CALL` or `KOTLIN-MULTI-PROJECT`, prefixed by its language (`GO-`, `JAVA-`, `KOTLIN-`,
`JS-`, `PYTHON-`, `DOTNET-`). Each language page under `docs/capabilities/` defines its caveats under
its "Caveats" heading, with a trigger and an effect; the binding ones are also listed in the
overview. *Source:* `docs/capabilities/README.md:50`, `docs/capabilities/README.md:39`,
`docs/capabilities/go.md:124`. *See also:* [caveat](#caveat), [binding caveat](#binding-caveat).

<a id="scheme-capability-status"></a>**Capability status values** — `Complete`: the feature works for
its stated scope. `Partial`: it works, with named caveats. `Planned`: it is not built yet. `N/A`: it
does not apply to the language's architecture. Matrix cells read `C / P / L` (Complete / Partial /
Planned counts). *Source:* `docs/capabilities/README.md:18`, `docs/capabilities/README.md:33`.
*See also:* [Complete / Partial](#complete-partial).

<a id="scheme-verdicts"></a>**Verdict values** — Every advisory in a Report lands as one of five
values: `reachable_candidate`, `not_exploitable`, `disqualified`, `malicious_package_present`,
`undetermined`. The canonical list is the `report.Verdict` constants. *Source:*
`docs/language-support.md:21`, `report/report.go:125`. *See also:* [verdict](#verdict).

<a id="scheme-undetermined-reasons"></a>**`undetermined_reason` codes** — The machine-readable reason
on an `undetermined` row, for example `analysis_did_not_run`, `package_version_unresolved`,
`refutation_withheld` or `go_toolchain_not_scanned`. The operator guide tables the common ones; the
`Reason*` constants in `report/report.go` define the codes, one open vocabulary also used for
partiality notes. *Source:* `docs/operator-guide.md:56`, `report/report.go:960`. *See also:* [undetermined](#undetermined).

<a id="scheme-basis"></a>**Basis values** — The grounds a `not_exploitable` or `disqualified` row
records in `evidence.basis`: `version_not_in_affected_range`, `vulnerable_symbol_absent`,
`vulnerable_symbol_unreachable`, `static_refutation`. *Source:* `docs/floor.md:26`,
`verdict/verdict.go:86`. *See also:* [basis](#basis).

<a id="scheme-floor-kinds"></a>**Floor failure kinds** — The reasons `floorcheck` fails a repository
in the floor run: `ungrounded_not_exploitable`, `ungrounded_disqualified`, `scan_truncated`,
`scan_failed`, `no_report`, `malformed_report`, `no_result`. *Source:* `docs/floor.md:24`,
`docs/floor.md:26`. *See also:* [floor run](#floor-run).

<a id="scheme-partiality-reasons"></a>**Partiality reason codes** — Stable, machine-readable strings an
analyzer declares for a limit, for example `reflection`, `cgo`, `tool_failure`, `no_manifest` or
`no_language_plugin`. Some carry a detail after a colon, such as
`tool_failure:dependency_code_unavailable` or `relationship_unexpressed:computed_require`. The
vocabulary is open, and `plugin/plugin.go` holds it. *Source:* `plugin/plugin.go:107`,
`docs/sample-report.md:114`, `report/report.go:1152`. *See also:* [partiality](#partiality).

<a id="scheme-advisory-ids"></a>**Advisory identifiers** — An advisory is named by a CVE, GHSA or
OSV identifier (Go advisories look like `GO-2021-0001`); a `VulnRef` records the id and where it was
read from (`osv`, `nvd` or `ghsa`). `FERRALON-APP-*` ids are first-party house canaries. *Source:* `README.md:4`,
`assessment/assessment.go:25`, `action.yml:247`. *See also:* [house canary](#house-canary),
[malicious_package_present](#malicious-package-present).

<a id="scheme-release-versions"></a>**Release tags and the minor alias** — Releases are
`vMAJOR.MINOR.PATCH` tags. `vX.Y` is a minor alias that floats to that minor's newest patch release;
`@v0.6` in a workflow fetches the scanner of the patch it currently points at, while a full tag or a
commit SHA freezes it. A release PR is titled `Release: vA.B.C`. *Source:* `README.md:113`,
`docs/releases/README.md:29`, `.github/CONTRIBUTING.md:70`. *See also:* [minted leaf](#minted-leaf),
[scanner-version](#scanner-version).

<a id="scheme-corpus-release-tags"></a>**Corpus release tags (`corpus-<12 hex>`)** — A release of the
advisory corpus repository. With `advisory-corpus-policy` set, such a tag is the reproducible
`advisory-corpus-ref`, and the default `main` resolves to the most recent corpus release. *Source:*
`action.yml:359`, `README.md:287`. *See also:* [corpus bundle](#corpus-bundle).

<a id="scheme-schema-ids"></a>**Schema identifiers** — Versioned names written into documents so a
reader can detect their shape: `tegron.report.v3` (the Report; v1 and v2 are read and upgraded),
`tegron.poe.v2` (PoE), `tegron.objection.v1` (Objection), `assay.buildgraph/v2` (resolved JVM
dependency graph), `ferralon.floor-summary.v1` (floor summary). The `tegron.` prefix is not defined in
the docs. *Source:* `report/report.go:52`, `verdict/verdict.go:40`, `buildgraph/schema.go:19`.
*See also:* [Report](#report), [PoE](#poe), [build graph](#build-graph).

<a id="scheme-corpus-file-versions"></a>**Corpus file versions** — The corpus release's `bundles.json` carries a
`bundle_version`; one older than 1.1.0 predates the signals asset, and the bundle route fails on it.
The signals file carries a `signals_version`; the scanner reads 1.x and fails on any other. *Source:*
`README.md:302`, `docs/operator-guide.md:131`. *See also:* [corpus bundle](#corpus-bundle),
[signals file](#signals-file).

<a id="scheme-surface-tiers"></a>**Surface tiers 0–2** — The permission tiers of the GitHub result
sinks, each defined by the least GitHub permission it can run under. Tier 0: the job summary and
`::warning::` annotations, zero permission. Tier 1: needs a write token (SARIF to code scanning,
sticky PR comment, pinned-Issue dashboard). Tier 2: opt-in hosted URL (GitHub Pages), off by
default. Source files carry the tier in their name (`tier1_issue.go`). *Source:*
`resultsink/github/detect.go:10`, `docs/api-stability.md:79`. *See also:* [surface](#surface),
[tier](#tier).

<a id="scheme-telemetry-levels"></a>**Telemetry levels** — The coverage tiers of the `telemetry`
package, ordered `essential` < `standard` < `full`; `essential` is the default. *Source:*
`telemetry/level.go:5`, `telemetry/level.go:7`, `telemetry/level.go:13`. *See also:* [tier](#tier).

<a id="scheme-review-severities"></a>**Review verdicts and severities** — A review ends as **clean**
or **needs changes**. Each finding is rated `blocker`, `major`, `minor`, `nit` or `question`, by
consumer impact. *Source:* `docs/review-guide.md:13`, `docs/review-guide.md:24`. *See also:*
[clean](#clean).

<a id="scheme-issue-labels"></a>**Issue labels** — New issues get `needs-triage`; a maintainer adds
the kind (`bug`, `enhancement`, `question`, `documentation`) and may set `needs-info`, after which a
quiet issue may be closed. *Source:* `.github/CONTRIBUTING.md:22`,
`.github/ISSUE_TEMPLATE/1-bug.yml:3`, `.github/ISSUE_TEMPLATE/2-feature.yml:3`.

<a id="scheme-issue-refs"></a>**`#NN` references** — `#NN` means a PR or issue in this repository;
another repository's item is written `ferralon-ai/<repo>#NN`. *Source:* `docs/review-guide.md:400`.

<a id="scheme-invariants"></a>**Invariant numbers (`inv. N`)** — Code comments cite numbered
invariants. `inv. 5` is "no proven verdict without execution proof", which the code attributes to
RFC 0001 and which bounds what the Report may say; `inv.4` is cited for a tool failure that is
surfaced, not retried. The numbered list itself is not in this repository. *Source:*
`verdict/verdict.go:257`, `report/report.go:8`, `plugin/plugin.go:113`. *See also:*
[RFC](#rfc), [PoE](#poe).

<a id="scheme-rfc-numbers"></a>**Design RFC numbers (`RFC 0001`–`RFC 0011`)** — Code comments cite
four-digit design RFCs, for example RFC 0003 for the PoE schema and RFC 0010 for adversarial review.
The RFC documents are not in this repository. *Source:* `verdict/verdict.go:40`,
`verdict/verdict.go:89`. *See also:* [RFC](#rfc) (Collision).

<a id="scheme-plan-numbers"></a>**`PLAN-NNN`** — Not defined in the docs; code and test comments
cite `PLAN-` numbers (for example `PLAN-220`, `PLAN-221`) as the origin of a change. The plans are
not in this repository. *Source:* `pipeline/resolution_accessors.go:3`.

<a id="scheme-phases"></a>**`Phase N`** — Not defined in the docs; code comments label work by phase
(Phase 1 vulnerability classes, the Phase-2 substrate the run modes build on, the Phase 3 GitHub
Refs-API store), and one partiality code is `unsupported_phase1`. *Source:*
`trigger/osv.go:4`, `statestore/statestore.go:23`, `plugin/plugin.go:112`.

<a id="scheme-test-codes"></a>**Test case codes (`C5`, `M4`, `U7`, …)** — Not defined in the docs;
some test files carry a letter-number code in their name and header that refers to an item of a
`PLAN-` number (for example "PLAN-173 C5"). *Source:* `trigger/python_cvewatch_c5_test.go:3`.
*See also:* [`PLAN-NNN`](#scheme-plan-numbers).

## Terms

### A

<a id="acquisition-mode"></a>**acquisition mode** — How checkout materializes the codebase: empty
means clone `Repo@Revision`, `vendored_repro` reads a local path, `pinned_ref` is the third value.
*Source:* `assessment/assessment.go:29`. *See also:* [subject](#subject).

<a id="admitted"></a>**admitted / admission** — Not defined in the docs; as used, an advisory is
"admitted" on a package it was matched to, and a version the version comparator cannot place "stays
admitted". G1 requires an admitted package whose installed version resolved. *Source:*
`docs/floor.md:10`, `docs/capabilities/go.md:29`, `docs/operator-guide.md:18`. *See also:*
[grounds](#grounds).

<a id="advisory-corpus"></a>**advisory corpus** — The external source of advisories a run must
consume, such as the public `ferralon-ai/vulnerability-corpus`; the scanner carries no advisories of
its own. A corpus directory holds `manifest.json` plus the digest-pinned per-advisory JSON records it
indexes. `-require-advisory-corpus` (which the Action sets whenever a corpus input is set) makes a
missing corpus a failure. *Source:* `README.md:253`, `action.yml:326`, `README.md:323`. *See also:* [corpus](#corpus) (Collision),
[corpus policy](#corpus-policy), [work set](#work-set).

<a id="advisory-cursor"></a>**advisory cursor** — The advisory-corpus position a scan evaluated
against, stored with the state; `cve-watch` compares OSV.dev results with it to decide between a
heartbeat and a re-analysis. *Source:* `report/report.go:716`, `docs/operator-guide.md:307`.
*See also:* [heartbeat](#heartbeat), [StateStore](#statestore).

<a id="advisory-source"></a>**`AdvisorySource`** — The extension point S1 reads advisory facts
through: one `Lookup(vulnID) (AdvisoryFacts, bool)`. Every failure collapses to `(zero, false)`, so
a source never returns partial facts. `NewChainSource` tries several in order and returns the first
whole fact. *Source:* `README.md:517`, `README.md:524`, `README.md:520`. *See also:*
[seam](#seam), [fact source](#fact-source).

<a id="analyze-ref"></a>**`analyze.ref` (`.github/ferralon.yml`)** — An optional key in a config file
committed to the default branch; it names a branch, tag or SHA the scan fetches and analyzes in a
separate worktree instead of the checked-out tree. *Source:* `README.md:187`, `README.md:196`.
*See also:* [canonical ref](#canonical-ref).

<a id="analyzer"></a>**analyzer (language analyzer, `assay-plugin-<lang>`)** — A separate subprocess
binary, spoken to over a small stdin/stdout JSON protocol, that does a language's analysis; the CLI
resolves it on `PATH` as `assay-plugin-<lang>` or from a `-plugin-go`-style flag. *Source:*
`README.md:156`, `README.md:158`. *See also:* [`LanguagePlugin`](#language-plugin),
[lane](#lane).

<a id="apidiff"></a>**`apidiff`** — The check reviewers run against the base for the exported
packages; every incompatible line on an exported package is a break the PR body and release notes
must name. *Source:* `docs/review-guide.md:194`, `docs/review-guide.md:252`. *See also:*
[breaking (library API)](#breaking-library-api).

<a id="artifact-store"></a>**artifact store** — The content-addressed store the pipeline writes its
intermediate evidence into; stages pass work by reading predecessors' artifacts and writing their
own. *Source:* `README.md:461`, `README.md:510`. *See also:* [stage](#stage).

<a id="assay-env"></a>**`ASSAY_*` variables** — The environment variables the scanner reads, for
example `ASSAY_SCAN_TIMEOUT`. The Action maps its inputs onto them, so a caller's workflow never writes
them, and a CLI flag paired with one wins over it. *Source:* `action.yml:100`,
`docs/review-guide.md:339`, `docs/review-guide.md:345`. *See also:* [breaking (library API)](#breaking-library-api).

<a id="assess"></a>**Assess (Assess pass)** — The deterministic analysis this repository performs:
the S1–S6 Assess stages, run once per advisory in an Assess pass. A Report is a projection of one
Assess pass. *Source:* `README.md:455`, `assessment/assessment.go:1`, `report/report.go:30`.
*See also:* [pipeline stages](#scheme-pipeline-stages), [assessment](#assessment),
[Prove](#prove).

<a id="assessment"></a>**assessment** — The durable, recallable record of one assessment pass (the
`assessment.Assessment` type), with a coarse status `queued` → `inventory` → `analysis` →
`complete`, or `failed`. A Report is not an Assessment. *Source:* `assessment/assessment.go:78`,
`assessment/assessment.go:11`, `report/report.go:30`. *See also:* [Assess](#assess).

<a id="attacker-tainted"></a>**`attacker_tainted`** — **Collision.** The stronger reachability grade.
The operator guide says the call path passes through an attacker-controllable ingress, that the grade
is decided by which entry points lie on the path and not by tracking data values, and that on its own
it does not say attacker-supplied data reaches the symbol. The `report` type's comment says an
attacker-controllable ingress reaches the symbol *and* tainted data flows along the path to it.
*Source:* `docs/operator-guide.md:77`, `docs/operator-guide.md:83`, `report/report.go:275`.
*See also:* [reachability grade](#reachability-grade), [control_flow_only](#control-flow-only).

### B

<a id="baseline"></a>**baseline** — **Collision.** (1) The run mode that fully scans every advisory
in the work set and, with a store selected, persists the result for `pr-inherit` and `cve-watch`.
(2) A branch name: the case-study demo repositories keep their code on a branch called `baseline`,
which is also the README's example `analyze.ref`. *Source:* `README.md:371`,
`docs/operator-guide.md:324`, `docs/floor.md:90`. *See also:* [run modes](#run-modes),
[floor run](#floor-run).

<a id="basis"></a>**basis (`evidence.basis`)** — The grounds field of a finding and the only grounds
field in `report.json`; it says which grounds a `not_exploitable` (or a version- or symbol-axis
`disqualified`) row stands on. `evidence.detail` is human-readable text, not grounds. *Source:*
`docs/floor.md:34`, `docs/operator-guide.md:22`, `verdict/verdict.go:86`. *See also:*
[basis values](#scheme-basis), [grounds](#grounds).

<a id="binding-caveat"></a>**binding caveat** — A caveat that withholds `not_exploitable` across the
whole run when a project triggers it; † marks one that applies to every project in the ecosystem
today. *Source:* `docs/capabilities/README.md:37`. *See also:* [caveat](#caveat),
[withhold](#withhold).

<a id="breaking-library-api"></a>**breaking (library API)** — A consumer-visible break, named in the
release notes under *Breaking (library API)*: the exported Go API, the Report's JSON shape, SARIF or
OpenVEX output, a new value in a vocabulary consumers switch on, or a CLI flag, `ASSAY_*` variable or
Action input. *Source:* `docs/review-guide.md:171`, `docs/review-guide.md:175`. *See also:*
[apidiff](#apidiff).

<a id="build-graph"></a>**build graph (`-build-graph`, `resolve-graph`)** — For Java and Kotlin, the
dependency graph the repository's own Maven or Gradle resolves, written as `assay.buildgraph/v2`
JSON (`buildgraph.json`). `-build-graph auto` (the default) has the scan run the build tool;
`resolve-graph` runs it ahead of a scan; `-build-graph off` or a pre-resolved graph file does not
run it. *Source:* `docs/operator-guide.md:278`, `README.md:176`, `docs/threat-model.md:88`.
*See also:* [schema identifiers](#scheme-schema-ids).

<a id="busl"></a>**BUSL (Business Source License 1.1)** — The license Assay is published under; see
`LICENSE` and the README's License section for what it permits. *Source:* `README.md:329`,
`README.md:606`. *See also:* [Change Date](#change-date).

### C

<a id="canary"></a>**canary** — **Collision.** (1) A *house canary*: a first-party synthetic advisory
a run reads only when it opts in. (2) In the PoE vocabulary, the `canary_triggered` proof flag records
that a canary planted in the codebase's execution fired. *Source:* `docs/review-guide.md:215`,
`verdict/verdict.go:149`. *See also:* [house canary](#house-canary),
[evidence flag](#evidence-flag).

<a id="canonical-ref"></a>**canonical ref** — The ref a linked run treats as the repository's own:
the `analyze.ref` in `.github/ferralon.yml`, else the default branch. Only a run of the canonical ref
pushes a run snapshot. *Source:* `action.yml:455`, `README.md:134`. *See also:*
[link-to-console](#link-to-console), [`analyze.ref`](#analyze-ref).

<a id="capability-manifest"></a>**capability manifest** — The per-language, static declaration of
what a language's analyzer supports; the compile-time complement to per-run partiality. *Source:*
`capability/doc.go:1`, `README.md:470`. *See also:* [partiality](#partiality).

<a id="caveat"></a>**caveat** — A named, stable ID for a limit on a language feature. Each language
page states its trigger (the code or project shape that activates it) and its effect on the verdict,
and links it from every feature it bounds. *Source:* `docs/capabilities/README.md:50`.
*See also:* [caveat IDs](#scheme-caveat-ids), [binding caveat](#binding-caveat).

<a id="cfamily"></a>**C/C++ (`cfamily`)** — A language the detector can return as `cfamily`. It is in
development and not in the scanner release asset: a release scan of a C/C++ tree publishes a Report
with no findings and one `did_not_run` note, and exits 0. *Source:*
`docs/capabilities/README.md:56`, `docs/language-support.md:8`, `README.md:496`.
*See also:* [language detection](#language-detection).

<a id="change-date"></a>**Change Date** — The BUSL date on which the license changes. `LICENSE`
carries `Change Date: TBD` on every branch; the release workflow mints the real date (today + 4 years)
onto a release-only leaf. `license-guard.yml` fails any push or pull request whose `LICENSE` names a
Change Date. *Source:* `docs/releases/README.md:20`, `docs/releases/README.md:21`,
`docs/releases/README.md:42`.
*See also:* [minted leaf](#minted-leaf), [BUSL](#busl).

<a id="clean"></a>**clean** — **Collision.** (1) A review verdict: no blocker or major open, build,
vet and test pass, soundness claims checked, earlier findings accounted for. (2) A release term: a
"clean (TBD) commit" is one whose `LICENSE` still carries `Change Date: TBD`. *Source:*
`docs/review-guide.md:35`, `docs/releases/README.md:49`. *See also:*
[review verdicts](#scheme-review-severities), [Change Date](#change-date).

<a id="clearing"></a>**clearing / a clear** — "Version clearing" and "Reachability clearing" are
capability groups 2 and 5: an advisory is `disqualified` when the resolved version sits outside its
affected range, and a completed search with no path yields `not_exploitable` on named grounds. The
noun "a clear" is not defined in the docs; as used, it is a verdict that rules an advisory out, which
a withheld verdict does not deliver. *Source:* `docs/capabilities/README.md:10`,
`docs/capabilities/README.md:13`, `docs/review-guide.md:389`. *See also:* [withhold](#withhold).

<a id="complete-partial"></a>**Complete / Partial** — **Collision.** (1) Capability status values on
a language page: `Complete` works for its stated scope, `Partial` works with named caveats. (2)
Per-run plugin partiality: a result's `Partiality.Complete` flag, with reason codes when it is not
complete. *Source:* `docs/capabilities/README.md:18`, `plugin/plugin.go:82`. *See also:*
[capability status](#scheme-capability-status), [partiality](#partiality).

<a id="completion-status"></a>**completion status** — Why analysis ended, orthogonal to the verdict:
`completed`, `stopped_budget`, `stopped_capability`, `environment_unavailable`. *Source:*
`verdict/verdict.go:121`. *See also:* [PoE](#poe).

<a id="control-flow-only"></a>**`control_flow_only`** — The weaker reachability grade: a call path to
the symbol exists, but no attacker-controllable ingress lies on it (it starts from an internal entry
point such as `main` or a CLI command, or one the analyzer could not classify). *Source:*
`docs/operator-guide.md:79`, `report/report.go:271`. *See also:*
[reachability grade](#reachability-grade).

<a id="corpus"></a>**corpus** — **Collision.** (1) The external *advisory corpus* a run reads its
advisories from. (2) The `corpus` Go package: checked-in golden regression fixtures and their
loader, with no API-stability promise. *Source:* `README.md:253`, `README.md:465`. *See also:*
[advisory corpus](#advisory-corpus).

<a id="corpus-bundle"></a>**corpus bundle (`bundles.json`)** — For a policy a corpus release publishes
one for, the single `<policy>.jsonl.gz` the Action downloads instead of git-fetching the record tree.
The release's `bundles.json` is verified with cosign, then the bundle's sha256 against it and its
members against the policy manifest; any mismatch fails the run. *Source:* `README.md:287`,
`README.md:290`, `action.yml:75`. *See also:* [corpus signer](#corpus-signer),
[signals file](#signals-file).

<a id="corpus-digest"></a>**`corpus_digest`** — The corpus's own digest, recorded on the Report so a
run's advisory state is independently identifiable; reproducibility of which advisories a run saw
comes from it, not from pinning the corpus ref. *Source:* `README.md:257`, `README.md:264`,
`report/report.go:782`. *See also:* [advisory corpus](#advisory-corpus).

<a id="corpus-policy"></a>**corpus policy (`advisory-corpus-policy`)** — A named selection of the
corpus (for example `published-7d`, `published-24h`, `full`). Declared, it defines the work set:
every advisory in the policy whose affected package is one of the repository's dependencies. Without
one, the corpus supplies facts only. The floor run sets one per lane: demo targets use
`published-24h` (`full` is refused there), the `pinned` lane of commit-pinned public repositories
uses its own policy, today `full`. *Source:* `README.md:275`, `README.md:286`,
`docs/floor.md:69`. *See also:* [work set](#work-set).

<a id="corpus-signer"></a>**corpus signer (`corpus-signer-identity`, `corpus-signer-issuer`)** — The
exact certificate identity and OIDC issuer the corpus release's signature must verify against on the
bundle route. They have no default; the Report records the verified signer as `corpus_signer`.
*Source:* `README.md:290`, `action.yml:395`, `README.md:296`. *See also:*
[corpus bundle](#corpus-bundle).

<a id="cve-watch"></a>**`cve-watch`** — The run mode that checks OSV.dev on a schedule for advisories
newly affecting the stored SBOM; it needs a prior baseline. *Source:* `README.md:375`,
`docs/operator-guide.md:348`. *See also:* [heartbeat](#heartbeat), [run modes](#run-modes).

### D

<a id="dependency-code"></a>**dependency code (`dependency-code`)** — Whether a JavaScript scan reads
its npm dependencies' code: `fetch` downloads each locked package and reads it once its bytes match
the lockfile's integrity hash, `offline` reads only a cache already on the runner, `off` reads none.
*Source:* `action.yml:263`, `report/report.go:1131`, `README.md:85`. *See also:*
[persist-dependency-cache](#persist-dependency-cache).

<a id="dependency-inventory"></a>**dependency inventory** — Capability group 1: every package in the
build is a named node, forming the SBOM and a place to attach each advisory. Go's is the selected
build list the Go toolchain resolves. *Source:* `docs/capabilities/README.md:9`,
`docs/capabilities/go.md:13`. *See also:* [SBOM](#sbom).

<a id="did-not-run"></a>**`did_not_run` / `inherent_limit` (partiality class)** — The two arms a
partiality reason is disclosed in. `inherent_limit` is a property of static analysis itself,
disclosed quietly in a methodology footer. `did_not_run` is a step that did not happen on this run;
it drives the headline qualifier and blocks `not_exploitable`, and is the default for an unrecognized
reason. *Source:* `report/partiality_class.go:21`, `report/partiality_class.go:29`,
`report/partiality_class.go:35`. *See also:* [partiality](#partiality).

<a id="direction"></a>**direction** — In the PoE vocabulary, which way the evidence points:
`exploitable`, `not_exploitable` or `indeterminate`. *Source:* `verdict/verdict.go:43`.
*See also:* [strength](#strength), [indeterminate](#indeterminate), [PoE](#poe).

<a id="disqualified"></a>**`disqualified`** — **Collision.** The language-support table says the
resolved version is provably outside the advisory's affected range, *or* the advisory's package is
not in the dependency manifest or ecosystem at all. The `report` type's comment names only the
version case. The floor doc calls the second kind an intake disqualification
(`advisory_ecosystem_mismatch`, `no_manifest_entry`), which carries no basis. *Source:*
`docs/language-support.md:27`, `report/report.go:80`, `docs/floor.md:40`. *See also:*
[verdict values](#scheme-verdicts), [basis](#basis).

### E

<a id="entry-point"></a>**entry point (ingress)** — The ingress at the head of a candidate path, where
untrusted input can enter the program. A graded candidate reports its symbol, its kind (`http_route`,
`rpc`, `cli`, `test` or `unknown`) and whether that kind is attacker-controllable. *Source:*
`report/report.go:430`, `docs/operator-guide.md:90`. *See also:*
[reachability grade](#reachability-grade), [library entry points](#library-entrypoints).

<a id="episode"></a>**Episode** — Not defined in the docs; as used, the `assessment.Assessment` and
`verdict.PoE` types carry a list of Episode IDs recorded during the run or that produced the verdict.
*Source:* `assessment/assessment.go:84`, `verdict/verdict.go:193`.

<a id="epss"></a>**EPSS** — FIRST.org's probability-of-exploitation score and percentile, carried in a
finding's `priority` block with `epss_as_of`, the EPSS model date. It only orders findings; nothing
that decides a verdict reads it. *Source:* `docs/operator-guide.md:100`,
`docs/operator-guide.md:146`. *See also:* [KEV](#kev), [priority](#priority),
[signals file](#signals-file).

<a id="evidence-flag"></a>**evidence flag / proof flag** — A concrete, machine-checkable observed fact
in the PoE vocabulary: `static_taint_path_complete`, `public_poc_replayed`, and the two proof flags
`canary_triggered` and `syscall_consistent_with_class`, the only flags that can gate a proven
verdict. No code in this module emits either proof flag. *Source:* `verdict/verdict.go:138`,
`verdict/verdict.go:27`. *See also:* [strength](#strength), [canary](#canary).

<a id="exploit-preconditions"></a>**`exploit_preconditions`** — Advisory-declared preconditions
(`trigger_condition`, `prerequisite`) surfaced on a `reachable_candidate` as descriptive context; it
is never evaluated as met or unmet and never changes the verdict. *Source:* `report/report.go:332`,
`report/report.go:510`. *See also:* [mitigating guards](#mitigating-guards).

### F

<a id="fact-source"></a>**fact source (`fact_source`)** — Where a pass resolved advisory facts:
`none`, `corpus`, `house_canaries` or `corpus_then_house_canaries` (facts never merged across the
two). *Source:* `report/report.go:868`. *See also:* [work set](#work-set),
[`AdvisorySource`](#advisory-source).

<a id="fail-open"></a>**fail open** — Assay never narrates an absence of evidence as "not affected": a
finding it could not soundly resolve is reported as exactly that. For an unresolvable version, the
disqualification predicate fails open, since "unknown" must never be read as "not affected".
*Source:* `README.md:216`, `README.md:491`. *See also:* [undetermined](#undetermined).

<a id="floor-run"></a>**floor run (`floorcheck`)** — The nightly workflow that builds the scanner
from `main`, scans each demo repository in `floor/targets.json` plus a `pinned` lane of real public repositories
(each at a full commit id, under its own corpus policy), and fails on an ungrounded
`not_exploitable` or a failed, timed-out or cut-short scan. `cmd/floorcheck` reads each
`report.json` and assigns a failure kind. *Source:* `docs/floor.md:3`, `docs/floor.md:21`, `docs/floor.md:69`.
*See also:* [grounds conditions](#scheme-grounds).

### G

<a id="generate-harness"></a>**`GenerateHarness` / harness skeleton** — A `LanguagePlugin` operation
that Go and JavaScript implement and the other lanes return `Unsupported` for by design. Go's is a
generated Go source that calls the sink with a seed hook, handed to the paid tier. *Source:*
`docs/review-guide.md:146`, `docs/capabilities/go.md:115`. *See also:* [paid tier](#prove),
[`Unsupported`](#unsupported).

<a id="govulncheck"></a>**govulncheck** — Not defined in the docs beyond its role: the Go analyzer's
reachability stage runs it with no `-db` flag, so it reads the `vuln.go.dev` database uncached on
every run; it supplies Go's path-bearing `reachable_candidate` and entry roots. *Source:*
`docs/threat-model.md:11`, `docs/capabilities/go.md:73`, `docs/capabilities/go.md:86`.

<a id="grounds"></a>**grounds / grounds gate** — The named evidence a `not_exploitable` row stands
on, recorded in `evidence.basis`. The grounds gate in `trigger/grounds.go` lets a finding become
`not_exploitable` only when it has evidence; anything short of the grounds is `undetermined`, with
the missing ground as its reason. *Source:* `docs/floor.md:8`, `docs/operator-guide.md:18`.
*See also:* [grounds conditions](#scheme-grounds), [basis](#basis).

<a id="guard-sufficiency"></a>**guard sufficiency** — On a `reachable_candidate`, an annotation of an
on-path guard with the advisory's declared label, `sufficient` or `insufficient`; descriptive only,
never a met/unmet evaluation. *Source:* `report/report.go:364`, `report/report.go:518`.
*See also:* [mitigating guards](#mitigating-guards).

### H

<a id="hazard-bounding"></a>**hazard bounding / hazard gate / refutation gate** — Capability group 7:
a limit withholds only the verdicts it could affect. A refutation gate is any condition that can let
a row become `not_exploitable` or `disqualified`; a hazard gate is any condition that withholds one.
*Source:* `docs/capabilities/README.md:15`, `docs/review-guide.md:82`. *See also:*
[withhold](#withhold), [mutation-test](#mutation-test).

<a id="heartbeat"></a>**heartbeat / re-analysis** — The two outcomes of `cve-watch`. Heartbeat: nothing
new, only the cursor is written. Re-analysis: new advisories affect the SBOM, and the scan
re-analyzes them and publishes a Report. Code comments call a re-analysis an "earnest run". *Source:*
`docs/operator-guide.md:350`, `report/report.go:718`. *See also:* [cve-watch](#cve-watch),
[advisory cursor](#advisory-cursor).

<a id="hermetic-stub-path"></a>**hermetic stub path** — What the stages run when a library caller passes
no `AssessOptions`: no checkout and no analyzer subprocess. `pipeline.WithPlugin` and
`pipeline.WithCheckout` run against a real codebase instead. *Source:* `README.md:572`. *See also:*
[stage](#stage).

<a id="house-canary"></a>**house canary (`include-house-canaries`)** — A first-party synthetic advisory
(the `FERRALON-APP-*` Go application-sink findings and synthetic Java, Kotlin, JS, Python and .NET
advisories) that a run reads only when it opts in. It is not a coverage control, and a doc that
presents the canaries as coverage is a review finding. *Source:* `action.yml:247`,
`docs/review-guide.md:215`, `cmd/ferralon-assay/acquire.go:405`. *See also:* [canary](#canary)
(Collision), [work set](#work-set).

### I

<a id="indeterminate"></a>**`indeterminate`** — A `verdict.Direction` (and the matching `Strength`)
meaning analysis established nothing; projections must render it as negative space (OpenVEX
`under_investigation`), never as a positive status. It is a different word from `undetermined`,
which is a Report verdict. *Source:* `verdict/verdict.go:53`, `verdict/verdict.go:56`,
`docs/review-guide.md:398`. *See also:* [undetermined](#undetermined), [direction](#direction).

<a id="install-revoke"></a>**install-revoke / self-cleanup** — With `link-to-console: true`, a
cryptographically signed HTTP-410 install-revoke (the backing Ferralon App was uninstalled) confirmed
on two consecutive runs makes the scan delete its workflow file and the default state ref.
`self-cleanup-on-revoke: false` holds that removal. *Source:* `README.md:134`, `action.yml:427`.
*See also:* [link-to-console](#link-to-console).

### K

<a id="kev"></a>**KEV** — Whether the CVE was in CISA's Known Exploited Vulnerabilities catalog,
stamped with `kev_catalog_version` and `kev_date_released`. A stamp without `kev_listed` means the
CVE was not in that catalog. *Source:* `docs/operator-guide.md:102`. *See also:* [EPSS](#epss),
[priority](#priority).

### L

<a id="lane"></a>**lane (language lane)** — The per-language analysis path; the capability matrix
records what each lane does, and parity across lanes is the default expectation. *Source:*
`docs/review-guide.md:141`, `docs/review-guide.md:143`. *See also:* [analyzer](#analyzer).

<a id="language-detection"></a>**language detection** — A closed set: `checkout.DetectLanguage`
returns `go`, `java`, `kotlin`, `js`, `python`, `dotnet`, `cfamily` or unknown, and `NewMultiPlugin`
routes each operation by that tag. A plugin for any other language is never called, and the run
reports `no_language_plugin`. *Source:* `README.md:495`, `README.md:497`, `README.md:500`.
*See also:* [`LanguagePlugin`](#language-plugin).

<a id="language-plugin"></a>**`LanguagePlugin`** — The contract every language analyzer implements:
index symbols, map an advisory's vulnerable symbols, read declared dependency versions, build a call
graph, find framework entry points, derive reachability. It returns evidence, never verdicts, and
declares partiality instead of hiding it. *Source:* `README.md:482`, `README.md:487`.
*See also:* [partiality](#partiality), [seam](#seam).

<a id="library-entrypoints"></a>**library entry points / library escape** — In Go, the packages code
outside the build may import (`library-entrypoints`: `auto`, `none`, or a list with `!path`
exclusions). When one of them reaches the advisory's vulnerable package, the refutation is withheld
(`library_escape`) and the row is `undetermined` with `refutation_withheld`. *Source:*
`docs/operator-guide.md:25`, `docs/capabilities/go.md:200`. *See also:* [withhold](#withhold).

<a id="link-to-console"></a>**`link-to-console` (Ferralon console)** — The only switch that decides
whether a scan contacts Ferralon; default `false`. When on, the scan sends results to the ingest
endpoint baked into the release and, for a run of the canonical ref, pushes a `tegron.report.v3`
verdict layer to a run-snapshot endpoint. *Source:* `README.md:126`, `README.md:134`,
`action.yml:414`. *See also:* [canonical ref](#canonical-ref),
[install-revoke](#install-revoke).

### M

<a id="malicious-package-present"></a>**`malicious_package_present`** — A known-malicious package
resolved to a version the advisory lists as affected; OpenVEX carries it as `affected`. *Source:*
`docs/language-support.md:28`, `report/report.go:114`. *See also:*
[verdict values](#scheme-verdicts).

<a id="minted-leaf"></a>**minted leaf** — The single release-only commit the release workflow writes
when a tag is pushed: it changes only `LICENSE`'s Change Date and Change License lines and the
`scanner-version` default in `action.yml`, the tag is re-pointed at it, and it never merges back to a
branch. *Source:* `docs/releases/README.md:22`, `docs/releases/README.md:29`. *See also:*
[Change Date](#change-date), [release tags](#scheme-release-versions).

<a id="mitigating-guards"></a>**mitigating guards** — Advisory-declared guard or validation functions
found on a candidate path; their presence is mitigating evidence, but the row stays
`reachable_candidate` because presence is not sufficiency. *Source:* `report/report.go:491`.
*See also:* [guard sufficiency](#guard-sufficiency).

<a id="mutation-test"></a>**mutation-test (a gate)** — For each condition that can let a row become
`not_exploitable` or `disqualified`, or that withholds one, flip or drop it, run the package's tests,
confirm one fails, then restore it. *Source:* `docs/review-guide.md:275`. *See also:*
[hazard gate](#hazard-bounding).

### N

<a id="no-work-gate"></a>**no-work gate (`scanWorkSet`)** — A run given no input that chooses
advisories halts with an error instead of publishing a findings-free Report; a supplied input that
matched nothing publishes and says so. *Source:* `README.md:340`, `docs/review-guide.md:78`,
`cmd/ferralon-assay/run.go:660`. *See also:* [work set](#work-set).

<a id="not-exploitable"></a>**`not_exploitable`** — The vulnerable code is provably absent from what
the build compiles, or provably unreachable from its entry points; the row names its grounds in
`evidence.basis`. OpenVEX carries it as `not_affected`. *Source:* `docs/language-support.md:26`,
`docs/operator-guide.md:18`, `docs/language-support.md:31`. *See also:* [grounds](#grounds),
[basis](#basis).

### O

<a id="objection"></a>**Objection (adversarial review)** — In the PoE vocabulary, a record of a
sustained adversarial-review downgrade, with the label attacked and the attack class. Nil unless a
downgrade applied. *Source:* `verdict/objection.go:9`, `verdict/verdict.go:194`. *See also:*
[PoE](#poe).

<a id="openvex"></a>**OpenVEX (`openvex.json`)** — One of the Report's projections. `undetermined` and
`reachable_candidate` map to `under_investigation`, `not_exploitable` and `disqualified` to
`not_affected`, and `malicious_package_present` to `affected`; it carries no priority data.
*Source:* `docs/language-support.md:31`, `README.md:153`, `docs/operator-guide.md:167`.
*See also:* [projection](#projection).

<a id="osv-work-set"></a>**OSV widening (`-osv-work-set`)** — Work-set widening that queries OSV.dev
for advisories affecting the repository's dependencies, used only when switched on and no policy is
declared; the corpus then admits only advisories it holds facts for. *Source:*
`docs/threat-model.md:35`, `README.md:321`. *See also:* [work set](#work-set).

### P

<a id="partiality"></a>**partiality** — A declared limit on what a step or a scan could establish.
A plugin declares it on a result instead of returning a confident-looking incomplete answer; the
Report carries scan-level partiality notes, each with a reason code. *Source:* `README.md:489`,
`report/report.go:882`, `docs/sample-report.md:93`. *See also:*
[partiality reason codes](#scheme-partiality-reasons), [`did_not_run`](#did-not-run),
[Complete / Partial](#complete-partial).

<a id="persist-dependency-cache"></a>**`persist-dependency-cache`** — Which fetched npm packages persist
between runs in the GitHub Actions cache: `auto` (default; on a public repository, never a package
from a registry the `.npmrc` holds an auth entry for), `always` or `never`. *Source:*
`action.yml:283`, `docs/threat-model.md:57`. *See also:* [dependency code](#dependency-code).

<a id="poe"></a>**PoE (Proof of Exploitability)** — The published `verdict` vocabulary a finding can
be expressed in: direction, strength, evidence flags and the `Validate` rules that decide when a
claim may be called proven. It is wider than what this module produces; several terms are declared
and reserved for implementation, and nothing outside the package's tests constructs a PoE. *Source:*
`README.md:345`, `verdict/verdict.go:1`, `verdict/verdict.go:27`. *See also:*
[direction](#direction), [strength](#strength), [PoNE](#pone).

<a id="pone"></a>**PoNE** — Not expanded in the docs; as used in `verdict`, the "two-trace PoNE" is the
only `proven not_exploitable` path and carries `PatchValidation` (a positive and a negative trace);
code elsewhere spells out "two-trace proof-of-non-exploitability". *Source:*
`verdict/verdict.go:90`, `verdict/verdict.go:197`,
`internal/plugin/javaanalysis/depreach/descriptor.go:2`. *See also:* [PoE](#poe).

<a id="pr-inherit"></a>**`pr-inherit`** — The run mode that diffs a PR head's resolved dependency set
against the stored baseline: unchanged, it inherits the baseline's findings; changed, it re-analyzes
only the affected advisories. It publishes the PR's Report without storing it. *Source:*
`README.md:372`, `docs/operator-guide.md:335`. *See also:* [run modes](#run-modes).

<a id="priority"></a>**priority (block)** — EPSS/KEV context on a finding, present only when the run
was given a signals file with a value for the advisory's id or an alias; each value carries its own
date. It orders findings and never decides a verdict. *Source:* `docs/operator-guide.md:97`,
`docs/operator-guide.md:107`, `report/report.go:530`. *See also:* [EPSS](#epss), [KEV](#kev),
[signals file](#signals-file).

<a id="projection"></a>**projection** — A rendering of the Report (or a verdict) into another format:
`report.html`, `report.sarif.json` (SARIF 2.1.0), `openvex.json`; the `projection` package also
projects to SSVC. *Source:* `README.md:153`, `README.md:460`. *See also:* [OpenVEX](#openvex),
[SARIF](#sarif), [SSVC](#ssvc).

<a id="prove"></a>**Prove / paid tier / runtime confirmation** — Capability group 8: candidate paths
and sink coordinates hand off to Ferralon's runtime proof. The language pages call the receiver the
paid tier, and the Java and Kotlin pages name it Prove. *Source:* `docs/capabilities/README.md:16`,
`docs/capabilities/java.md:118`, `docs/capabilities/kotlin.md:105`. *See also:*
[`GenerateHarness`](#generate-harness), [tier](#tier) (Collision).

<a id="provenance"></a>**provenance** — **Collision.** Three different blocks share the name. (1)
The policy manifest's `provenance` block, recorded on the Report as `corpus_manifest` for audit; it
affects no verdict. (2) The per-advisory `provenance` block inside each corpus document, whose
`trust_tier` gates refute eligibility. (3) The Report's own `provenance`: commit, analyzer version,
advisory cursor, timestamp and intel inputs. *Source:* `README.md:268`,
`pipeline/advisory_source.go:320`, `report/report.go:702`. *See also:*
[`corpus_digest`](#corpus-digest).

<a id="purl"></a>**PURL** — Not expanded in the docs; as used, a package identifier string such as
`pkg:golang/golang.org/x/example@v0.3.7`, by which dependency artifacts and partiality targets are
keyed. Code comments call it a "package URL". *Source:* `docs/sample-report.md:25`, `README.md:471`,
`cmd/ferralon-assay/depcode.go:572`.

### R

<a id="reachability-grade"></a>**reachability grade** — The strength of a `reachable_candidate`'s
reachability evidence: `attacker_tainted` or `control_flow_only`. It is not a verdict; either grade is
still a candidate. *Source:* `docs/operator-guide.md:75`, `report/report.go:262`. *See also:*
[`attacker_tainted`](#attacker-tainted), [`control_flow_only`](#control-flow-only).

<a id="reachable-candidate"></a>**`reachable_candidate`** — A path from an entry point reaches the
advisory's symbols. A candidate, not a proof of exploitability; OpenVEX carries it as
`under_investigation`. *Source:* `docs/language-support.md:25`, `README.md:363`.
*See also:* [reachability grade](#reachability-grade).

<a id="reflection-call"></a>**`reflection:call`** — The scan-level note a Go run carries when calls
through `reflect` or a template's `Execute` can reach one of an advisory's vulnerable symbols, or the
reachable set cannot be computed; the row is then `undetermined`. *Source:*
`docs/operator-guide.md:34`, `docs/operator-guide.md:44`, `docs/capabilities/go.md:190`. *See also:*
[refutation_withheld](#refutation-withheld).

<a id="refutation"></a>**refutation** — Not defined as a word in the docs; as used, positive evidence
that rules an advisory out for a package, such as an analyzer refuting the package (G2 arm B). A
refutation gate is any condition that can let a row become `not_exploitable` or `disqualified`.
*Source:* `docs/floor.md:12`, `docs/operator-guide.md:19`, `docs/review-guide.md:82`. *See also:*
[grounds](#grounds), [`refutation_withheld`](#refutation-withheld).

<a id="refutation-withheld"></a>**`refutation_withheld`** — An `undetermined_reason`: the analysis ran
and found no path, but code the search did not cover may reach the vulnerable code (excluded files,
unsearched methods, library importers, reflection). *Source:* `docs/operator-guide.md:66`.
*See also:* [withhold](#withhold), [undetermined reasons](#scheme-undetermined-reasons).

<a id="report"></a>**Report (`report.json`)** — The neutral scan output: one finding per advisory,
each backed by the evidence the pipeline collected; the tool's output contract, schema
`tegron.report.v3`. *Source:* `README.md:212`, `README.md:459`, `report/report.go:61`.
*See also:* [projection](#projection), [schema identifiers](#scheme-schema-ids).

<a id="result-sink"></a>**`ResultSink`** — The publish extension point: one method,
`Publish(ctx, Result) error`, where a completed scan reaches a CI surface; the GitHub adapters under
`resultsink/github` are the built-in ones. *Source:* `README.md:531`. *See also:*
[surface](#surface), [seam](#seam).

<a id="rfc"></a>**RFC** — **Collision.** (1) Four-digit internal design RFCs (`RFC 0003`,
`RFC 0010`) cited in code comments; the documents are not in this repository. (2) IETF RFCs cited for
formats, for example RFC 3339 timestamps. *Source:* `verdict/verdict.go:40`,
`pipeline/advisory_source.go:324`. *See also:* [design RFC numbers](#scheme-rfc-numbers).

<a id="run-modes"></a>**run modes** — Three modes on the same S1–S6 pipeline: `baseline`,
`pr-inherit`, `cve-watch`. `pr-inherit` and `cve-watch` read persisted state from a prior baseline.
*Source:* `README.md:369`, `README.md:377`. *See also:* [baseline](#baseline),
[pr-inherit](#pr-inherit), [cve-watch](#cve-watch).

### S

<a id="sarif"></a>**SARIF (`report.sarif.json`)** — The SARIF 2.1.0 projection the Action writes for
code scanning; the upload is a separate `upload-sarif` step. Grade, entry point and EPSS/KEV values
sit under each result's `properties.scanner`. *Source:* `README.md:153`, `docs/operator-guide.md:164`,
`docs/operator-guide.md:431`. *See also:* [projection](#projection).

<a id="sbom"></a>**SBOM** — The resolved dependency set of the scanned build, stored with the state;
`pr-inherit` diffs it and `cve-watch` checks it against OSV.dev. *Source:* `README.md:372`,
`docs/operator-guide.md:307`. *See also:* [StateStore](#statestore).

<a id="scan-timeout"></a>**`scan-timeout` / `scan-truncated` / scan cut short** — `scan-timeout`
bounds a scan; analysis stops early enough to publish, and every advisory not reached is reported as
not assessed. The `scan-truncated` output is `true` when that or a job timeout happened; the floor
run's `scan_truncated` kind is a `scan_cut_short` limit on the report. *Source:* `README.md:242`,
`action.yml:471`, `docs/floor.md:28`.

<a id="scanner-version"></a>**`scanner-version` / `scanner-sha256`** — `scanner-version` names the
scanner release the Action fetches: an exact `vX.Y.Z` or a `vX.Y` alias. `scanner-sha256` is an
optional pin that verifies the fetched tarball's bytes and needs an exact version. *Source:*
`action.yml:150`, `README.md:118`. *See also:* [release tags](#scheme-release-versions).

<a id="scip"></a>**SCIP** — Not expanded in the docs; as used, the form of symbol identifier Go
advisory symbols resolve to, and the second of Java's two annotation-recognizer tracks (alongside the
lexical one). *Source:* `docs/capabilities/go.md:55`, `docs/review-guide.md:149`.

<a id="seam"></a>**seam (extension point)** — Not defined as a word in the docs; as used, an
interface where the pipeline delegates a decision it does not own (`Stage`, `AdvisorySource`,
`Checkout`, `StateStore`, `ResultSink`, `LanguagePlugin`). *Source:* `README.md:476`,
`README.md:455`, `README.md:462`. *See also:* [stage](#stage),
[`AdvisorySource`](#advisory-source), [`ResultSink`](#result-sink).

<a id="self-scan"></a>**self-scan** — The CI job that runs the Action against this repository, on every
PR alongside build, vet, gofmt and test. *Source:* `.github/workflows/ci.yml:64`,
`docs/review-guide.md:382`.

<a id="service-tier"></a>**service tier (Service-side)** — Not defined in the docs; as used, the side that
the full verdict grammar belongs to and that a Report never contains: `exploitable` and `reasoned_*`
verdicts, and fields such as `non_exploitable_basis` and `reasoned_grounds`, are service-tier
concepts. *Source:* `docs/floor.md:35`, `report/report.go:23`. *See also:* [tier](#tier),
[PoE](#poe).

<a id="set-before-spawn"></a>**set-before-spawn (exported mutable state)** — The contract for the few exported
package-level variables and setters that are writable at runtime and not `-race`-safe, such as
`pipeline.SetDefaultAdvisorySource` and `trigger.AnalyzerVersion`: set them once, from a single
goroutine, before use. *Source:* `README.md:583`, `docs/api-stability.md:83`.

<a id="signals-file"></a>**signals file (`signals.json`, `-advisory-signals`)** — The provided
EPSS/KEV input findings are ranked with: the corpus's signals sidecar (`signals_version` 1.x), read
from `-advisory-signals`, `ASSAY_ADVISORY_SIGNALS`, or a corpus directory's root. Its
`signals_digest` is recomputed and checked on load. *Source:* `docs/operator-guide.md:115`,
`docs/operator-guide.md:131`, `docs/operator-guide.md:108`. *See also:* [priority](#priority).

<a id="ssa"></a>**SSA** — Not expanded in the docs; as used, the program form Go's analysis builds the
whole build as, and over which Go's taint analysis follows values. *Source:*
`docs/capabilities/go.md:55`, `docs/operator-guide.md:85`. *See also:*
[VTA / CHA / RTA](#vta-cha-rta).

<a id="ssvc"></a>**SSVC** — Stakeholder-Specific Vulnerability Categorization, one of the formats the
`projection` package projects to. *Source:* `projection/ssvc.go:3`, `README.md:460`.
*See also:* [projection](#projection).

<a id="stage"></a>**stage (`pipeline.Stage`)** — One step of the Assess pipeline: a stable `Name()`
used as the artifact's `ProducedBy`, the `Status()` it advances the assessment to, and `Run`, which
reads and writes through an `artifact.Store`. *Source:* `README.md:506`. *See also:*
[pipeline stages](#scheme-pipeline-stages), [artifact store](#artifact-store).

<a id="state-views"></a>**`state show` / `state export`** — Read-only CLI views over stored state:
`show` renders the stored `report.html`, `export` writes the Report and projections into a ZIP.
*Source:* `README.md:380`, `docs/operator-guide.md:405`. *See also:* [StateStore](#statestore).

<a id="statestore"></a>**StateStore (`refs/assay/state`)** — Persisted state: a single commit on an
orphan git ref, `refs/assay/state` by default, holding the last Report, the resolved SBOM, the
advisory cursor and an OpenVEX log. Every write is a fast-forward-only compare-and-swap. *Source:*
`docs/operator-guide.md:307`, `docs/operator-guide.md:309`. *See also:* [SBOM](#sbom),
[advisory cursor](#advisory-cursor).

<a id="strength"></a>**strength** — In the PoE vocabulary, how a verdict is known: `proven` (backed by
a ground-truth execution observation), `reasoned` (a defended lean that must state its grounds), or
`indeterminate`. *Source:* `verdict/verdict.go:64`. *See also:* [direction](#direction),
[evidence flag](#evidence-flag).

<a id="subject"></a>**subject** — The codebase actually assessed; the Report records its repository
identity, revision and resolved commit (`subject.repo`, `subject.revision`,
`subject.resolved_commit`). *Source:* `assessment/assessment.go:63`, `action.yml:218`,
`README.md:199`. *See also:* [toolchain fact](#toolchain-fact).

<a id="subject-gowork"></a>**`subject-gowork`** — The `GOWORK` the subject's Go build runs under: `off`,
`auto`, or the path of its `go.work`; the scan uses that `go.work`, never an ambient one. *Source:*
`action.yml:194`, `docs/capabilities/go.md:47`. *See also:* [subject](#subject).

<a id="subject-toolchain-reachability"></a>**`subject-toolchain-reachability`** — Opt-in setting that,
when the subject's toolchain resolved exactly, runs Go reachability under that Go release, so a
standard-library advisory can get an ordinary verdict instead of `go_toolchain_not_scanned`.
*Source:* `docs/operator-guide.md:209`, `docs/operator-guide.md:203`. *See also:*
[toolchain fact](#toolchain-fact).

<a id="surface"></a>**surface** — **Collision.** (1) A publish surface: where a run's result lands
(output directory, job summary, SARIF file, sticky PR comment, pinned dashboard Issue), each with its
toggle and permission. (2) The exported surface: the importable Go API, kept free of third-party
types. *Source:* `docs/operator-guide.md:420`, `docs/api-stability.md:10`. *See also:*
[surface tiers](#scheme-surface-tiers), [`ResultSink`](#result-sink).

<a id="symbol-confidence"></a>**symbol confidence** — On a `reachable_candidate`, how the vulnerable
symbol set was derived: `high` (osv-declared or curated) or `moderate` (diff-lexed); a strength
signal, never a verdict. *Source:* `report/report.go:292`, `report/report.go:308`. *See also:*
[vetted symbol set](#vetted-symbols).

<a id="symboltest"></a>**`plugin/symboltest`** — The symbol-profile golden-equality harness for
language-lane conformance tests; a test helper with no API-stability promise. *Source:*
`README.md:472`, `docs/review-guide.md:283`. *See also:* [lane](#lane).

### T

<a id="taint"></a>**taint** — The analysis whose path, when it reports one, a reachability grade is
read from (otherwise the reachability search's path is used). Go's follows values through SSA from an
ingress parameter to the sink's argument; every other language reports call-graph path presence from
an ingress to the sink. *Source:* `docs/operator-guide.md:84`,
`docs/capabilities/go.md:86`. *See also:* [reachability grade](#reachability-grade),
[`attacker_tainted`](#attacker-tainted).

<a id="tier"></a>**tier** — **Collision.** The word names several schemes. (1) Surface tiers 0–2,
by the GitHub permission a result sink needs. (2) Telemetry levels, described as coverage tiers. (3)
The paid tier that receives candidate paths for runtime confirmation. *Source:*
`resultsink/github/detect.go:10`, `telemetry/level.go:5`, `docs/capabilities/go.md:115`. *See also:*
[surface tiers](#scheme-surface-tiers), [telemetry levels](#scheme-telemetry-levels),
[Prove](#prove), [service tier](#service-tier).

<a id="toolchain-fact"></a>**toolchain fact (exact / minimum)** — The Go toolchain the scan resolves
for the subject, from the first usable source: a declaration (`-subject-go-version`), exact; the
`go.mod` `go` line under stated conditions, a minimum; otherwise unresolved. A trusted observed CI
toolchain counts as exact. *Source:* `docs/operator-guide.md:171`, `docs/operator-guide.md:197`,
`docs/operator-guide.md:238`. *See also:*
[subject-toolchain-reachability](#subject-toolchain-reachability).

<a id="trial"></a>**Trial** — Not defined in the docs; as used, the unit the `full` telemetry level
records fine-grained span detail for. *Source:* `telemetry/level.go:19`. *See also:*
[telemetry levels](#scheme-telemetry-levels).

### U

<a id="undetermined"></a>**`undetermined`** — The scan established nothing about the advisory;
`undetermined_reason` says why. Treat it as unassessed, never as safe. OpenVEX carries it as
`under_investigation`. *Source:* `docs/language-support.md:29`, `docs/operator-guide.md:56`,
`report/report.go:97`. *See also:* [undetermined reasons](#scheme-undetermined-reasons),
[indeterminate](#indeterminate).

<a id="unsupported"></a>**`Unsupported`** — What a plugin returns for an operation it does not
implement (`plugin.Unsupported()`); for an operation marked `N/A` it is by design, not a gap.
*Source:* `docs/review-guide.md:76`, `docs/review-guide.md:387`. *See also:*
[`LanguagePlugin`](#language-plugin).

### V

<a id="verdict"></a>**verdict** — The per-advisory result in a Report, one of five values. The
`verdict` package holds a wider vocabulary (direction × strength) that a Report never carries.
*Source:* `docs/language-support.md:21`, `report/report.go:72`. *See also:*
[verdict values](#scheme-verdicts), [PoE](#poe).

<a id="version-axis"></a>**version axis / symbol axis** — Not defined in the docs; as used, the two
grounds a `disqualified` row's basis can come from: the version comparison against the advisory's
range, and the symbol check. *Source:* `docs/floor.md:39`, `docs/capabilities/go.md:142`.
*See also:* [disqualified](#disqualified).

<a id="vetted-symbols"></a>**vetted symbol set (`symbol_provenance`)** — A symbol set complete enough
for an absence of its symbols to ground `not_exploitable`: osv-declared or curated, or a house
canary's; a diff-lexed or cna-declared set is not. *Source:* `trigger/grounds.go:92`,
`pipeline/advisory_source.go:434`. *See also:* [symbol confidence](#symbol-confidence),
[grounds](#grounds).

<a id="vta-cha-rta"></a>**VTA / CHA / RTA** — Not expanded in the docs; as used, the call-graph
algorithms Go's analysis offers, VTA being the default. *Source:* `docs/capabilities/go.md:55`,
`docs/capabilities/go.md:60`. *See also:* [SSA](#ssa).

<a id="vulnclass"></a>**vulnerability class (`vulnclass`)** — **Collision.** The class recognized
from an advisory's CWE (and, in the code, its summary), for example `injection`, `path_traversal` or
`dos`; recognition never decides a verdict. The README calls it a closed enum. The package calls
`Class` an open string, with constants for the recognized classes and `ClassUnknown` for the rest.
*Source:* `README.md:466`, `vulnclass/vulnclass.go:12`, `vulnclass/vulnclass.go:3`.

### W

<a id="withhold"></a>**withhold / withheld** — **Collision.** (1) Current usage: a limit or hazard
withholds a verdict, so a row that might have been `not_exploitable` is `undetermined` instead. (2)
`PartialityNote.Advisories` carries the ids of advisories withheld under a limit; they are still
read when upgrading stored v1 Report documents. A JavaScript scan also
"withholds each package it could not" fetch. *Source:* `docs/capabilities/README.md:37`,
`report/report.go:936`, `README.md:92`. *See also:* [hazard bounding](#hazard-bounding),
[refutation_withheld](#refutation-withheld).

<a id="work-set"></a>**work set (`work_set_source`)** — The set of advisories a scan evaluates. With a
declared policy, it is every advisory in the policy whose affected package is one of the
repository's dependencies, plus any opted-in house canaries. `work_set_source` records how it was
chosen: `none`, `house_canaries`, `policy` or `osv_query`. *Source:* `README.md:276`,
`docs/operator-guide.md:324`, `report/report.go:851`. *See also:* [corpus policy](#corpus-policy),
[no-work gate](#no-work-gate), [fact source](#fact-source).

## Unresolved

### Collisions

- [`attacker_tainted`](#attacker-tainted) — entry-point classification (operator guide) vs. tainted data flow (`report` comment).
- [baseline](#baseline) — the run mode vs. the demo repositories' branch name.
- [canary](#canary) — house canary vs. the `canary_triggered` proof flag.
- [clean](#clean) — the review verdict vs. a "clean (TBD)" release commit.
- [Complete / Partial](#complete-partial) — capability status vs. per-run plugin partiality.
- [corpus](#corpus) — the external advisory corpus vs. the `corpus` fixture package.
- [`disqualified`](#disqualified) — version-or-intake (language support) vs. version-only (`report` comment).
- [provenance](#provenance) — manifest provenance vs. per-advisory provenance vs. the Report's provenance.
- [RFC](#rfc) — internal design RFCs vs. IETF RFCs.
- [surface](#surface) — publish surface vs. exported API surface.
- [tier](#tier) — surface tiers vs. telemetry levels vs. the paid tier.
- [vulnerability class](#vulnclass) — a closed enum (README) vs. an open string (`vulnclass` package).
- [withhold](#withhold) — a withheld verdict vs. the v1 advisory left out of `advisories[]`.

### Not defined in source

- [admitted / admission](#admitted) — used for advisory-to-package matching, never defined.
- [clearing / a clear](#clearing) — the noun "a clear" is used, not defined.
- [Episode](#episode) — an ID list on assessments and PoEs, never defined.
- [govulncheck](#govulncheck) — an external tool, described only by its role.
- [PoNE](#pone) — not expanded in the docs.
- [PURL](#purl) — not expanded in the docs.
- [refutation](#refutation) — used throughout, not defined as a word.
- [SCIP](#scip) — not expanded in the docs.
- [seam](#seam) — used for the extension interfaces, not defined as a word.
- [service tier](#service-tier) — used for the side a Report never contains, never defined.
- [SSA](#ssa) — not expanded in the docs.
- [Trial](#trial) — named in telemetry, never defined.
- [version axis / symbol axis](#version-axis) — used, never defined.
- [VTA / CHA / RTA](#vta-cha-rta) — not expanded in the docs.
- [`PLAN-NNN`](#scheme-plan-numbers) — plan documents not in this repository.
- [`Phase N`](#scheme-phases) — phases never defined.
- [Test case codes](#scheme-test-codes) — item codes of plans not in this repository.
- [Design RFC numbers](#scheme-rfc-numbers) — RFC documents not in this repository.
- [Invariant numbers](#scheme-invariants) — the numbered list is not in this repository.
- [`tegron.` schema prefix](#scheme-schema-ids) — never defined.
