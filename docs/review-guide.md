# Review guide

This guide is for anyone reviewing a Ferralon Assay pull request: a maintainer, a contributor, or an
automated reviewer. It says what a review is for, which properties of Assay a change must never
weaken, and how to check them. A reviewer new to the codebase who follows it should produce a
review a maintainer can act on without redoing the work.

Two other files set the ground rules this guide builds on: [AGENTS.md](../AGENTS.md) for build,
test and the release rule, and [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for how changes arrive.

## What a review produces

A review ends in one of two verdicts, **clean** or **needs changes**, followed by its findings.
Every finding carries:

- **Where:** `path/to/file.go:123`, opened at the PR's head commit. A citation you did not open at
  that commit does not go in the review.
- **What fails, and for whom:** the concrete scenario. "A Go module with a `replace` directive to
  a local path gets `disqualified` on the required version" is a finding; "this looks fragile" is
  not.
- **Severity**, from the table below.
- **The fix**, when it is clear.

| Severity | Meaning |
|---|---|
| **blocker** | Assay can claim more than its evidence supports: a `not_exploitable` or `disqualified` without its grounds, a row that drops out of the Report, a findings-free Report from an empty work set. Also a change that defeats a release or licence gate, or sends code or credentials anywhere the [threat model](threat-model.md) does not list. |
| **major** | A consumer-visible change nobody is told about: an exported API, Report, SARIF or OpenVEX break, or a changed flag, environment variable or Action input meaning. Also a verdict change at scale in either direction, or a test that does not exercise the gate it claims to cover. |
| **minor** | Correct behaviour that is described wrongly: a doc comment, README line or release note that disagrees with the code, a count that is off, or a missing edge-case test. |
| **nit** | Wording, layout and naming that do not change what a reader understands. |
| **question** | Something the tree cannot answer. Say what you checked. If the source answers it, it is a finding at its real severity, not a question. |

Rate by consumer impact. An omission that changes a verdict outranks a miscounted list, even when
the list is easier to spot.

**Clean** means no blocker or major is open, `go build`, `go vet` and `go test` pass at the head,
every soundness claim in the PR body is checked against the code, and every finding from an earlier
round on the PR is marked addressed or still open.

### Priorities

Review in this order, and spend your time the same way:

1. **Soundness.** Can this make Assay say something its evidence does not support?
2. **Correctness.** Does it do what it says, on the inputs real repositories have?
3. **Compatibility.** Does it break a library caller, a Report reader, a VEX consumer, a workflow
   or a stored state ref?
4. **Operability.** Can an operator tell what happened and fix it, from the Report, the job
   summary and the docs?
5. **Clarity.** Do the comments, docs and PR body say what the code does?

## What Assay holds to

These are the properties that make Assay worth running. A change that weakens one needs a reason
the reviewer can verify, not just a reason.

### Never claim more than the evidence

Assay fails open. It never presents an absence of evidence as "not affected"
([README, What it reports](../README.md#what-it-reports)). Every advisory lands as one of five
verdicts ([language support](language-support.md#verdicts)), and `undetermined` is an open
question that a consumer must treat as unassessed.

- `not_exploitable` stands on named grounds, recorded in `evidence.basis`
  ([operator guide](operator-guide.md#not_exploitable-grounds)). Anything short of those grounds is
  `undetermined`, with the missing ground as its `undetermined_reason`.
- Underneath, the verdict vocabulary is three-valued: `exploitable`, `not_exploitable` and
  `indeterminate` ([`verdict/verdict.go`](../verdict/verdict.go)). `indeterminate` asserts nothing
  and is projected as OpenVEX `under_investigation`. `PoE.Validate` enforces that a grounded
  `not_exploitable` names its basis and that `proven` requires a ground-truth observation.
- `undetermined` is the correct answer whenever a step failed, a version did not resolve, a symbol
  was not located, or a hazard could reach the sink. A change that turns any of these into
  `not_exploitable` or `disqualified` needs a new, named ground, a test that shows it, and a
  release-note line.
- A plugin returns evidence, never verdicts, and declares partiality instead of hiding it
  ([README, Extending Assay](../README.md#pluginlanguageplugin--evidence-for-one-language)). An
  unresolved version comes back `Resolved=false`; an unimplemented operation returns
  `plugin.Unsupported()` ([`plugin/plugin.go`](../plugin/plugin.go)).
- An empty work set halts the run rather than publish a findings-free Report (`scanWorkSet` in
  [`cmd/ferralon-assay/run.go`](../cmd/ferralon-assay/run.go)).

**Refutation and hazard gates are the highest-stakes code in the repository.** A refutation gate is
any condition that can let a row become `not_exploitable` or `disqualified`. A hazard gate is any
condition that withholds one (capability group 7, *Hazard bounding*, in the
[capability matrix](capabilities/README.md)). A refutation gate that is too loose produces a false
"not affected", which is the one failure Assay exists to prevent. A hazard gate that is too tight
withholds verdicts a project should get. Review both line by line, and mutation-test them (see
[How to review](#how-to-review)).

When a fix closes a soundness bypass by adding one more spelling to a deny-list, look for the next
spelling before you approve. A second bypass of the same class means the gate is shaped wrong.
Ask for an allowlist, or a default-deny at the level where the spellings collapse, rather than a
third spelling.

### Deterministic output

The same inputs produce the same Report, byte for byte. The builder sorts every collection before
it serializes ([`report/builder.go`](../report/builder.go)), so an unchanged SBOM writes no new
state. Look for map iteration, unsorted slices, timestamps and goroutine completion order reaching
output. The release build is held to the same standard: `release.yml` builds the asset twice and
fails unless the two sha256 digests match.

### Your data stays yours

The promise is about the operator's data, not about the network. Your code and your credentials
never leave the runner ([threat model](threat-model.md)). No run mode is offline, though, and Assay
contacts the public hosts the threat model lists to resolve dependencies and read advisories.

So the review question for a new network call is not "does this make a request?" It is:

- Does it carry anything beyond dependency metadata (module paths, versions, package coordinates)?
- Does a credential reach any host other than the one it is bound to?
- Is the host listed in [threat-model.md](threat-model.md) and the README's
  [Network egress](../README.md#network-egress) section?

Contacting Ferralon is a separate, explicit switch, `link-to-console`, which defaults to `false`.
On that default the scan runs fully standalone.

### Inputs are handed in, never resolved

Assay runs with the conditions it is given and records what it used. It does not decide policy or
fetch its run conditions from anywhere. Signals are a provided input
([operator guide, EPSS and KEV](operator-guide.md#epss-and-kev)), and the corpus release route
verifies only the signer the operator names, with no default
([README, Advisory corpus](../README.md#advisory-corpus)). Flag a
change that puts a policy lookup, a fallback chain to a service, or a vendor-specific API call
inside Assay. The decision belongs to whatever runs Assay: a workflow step, or the caller of the
library.

### The scanned repository is the operator's own

Assay runs inside the operator's CI against the operator's repository. Running that repository's
own Maven or Gradle is intended behaviour: it is how Java and Kotlin scans get the dependency graph
the build really uses ([v0.6.0 notes, Before you upgrade](releases/v0.6.0.md#before-you-upgrade)).
"This executes repository code" is not a finding by itself. The finding is when that execution is
undisclosed, or when it hands a credential to a host the operator did not choose.

### Language lanes

Assay analyzes Go, Java, Kotlin, JavaScript/TypeScript, Python and .NET. The
[capability matrix](capabilities/README.md) records, feature by feature, what each lane does.

- **Parity is the default expectation.** A feature added to one lane should name what the other
  lanes do for the same question, or say why the answer differs.
- **`N/A` is architectural, not a gap.** A feature marked `N/A` on a language page does not apply to
  that language's architecture. `GenerateHarness` is the clearest case: Go and JavaScript implement
  it, and the other lanes return `Unsupported` by design ([`plugin/plugin.go`](../plugin/plugin.go),
  [java.md](capabilities/java.md)). Do not ask a PR to fill an `N/A`.
- **Java's two recognizers move together.** Java annotations are recognized on two tracks, the
  lexical one in `internal/plugin/javaanalysis/calls.go` and the SCIP one in
  `internal/plugin/javaanalysis/scipindex.go`. The SCIP registries must stay in step with their
  lexical twins (see the comments on `registerMappingSelector` and the container-entrypoint
  registry in `scipindex.go`). A new annotation on one track without the other is a finding.
- **Java and Kotlin see annotations differently.** First-party Java is read from source with string
  values blanked, while Kotlin and dependencies are read from bytecode with values visible
  ([JAVA-ANNOTATION-VALUES-SOURCE](capabilities/java.md#java-annotation-values-source)). A feature
  that depends on an annotation's value must declare partiality on the Java source path, never
  assume a default.

### Close gaps rather than document them

When a PR meets a limit that more engineering could remove, the better change removes it. Saying
honestly that a limit exists is the floor for what genuinely cannot be resolved, such as a dynamic
version range or a build rule that is invisible on disk. It is not the goal. A PR that adds a caveat
should say why the gap cannot be closed in this change. The review asks whether it could be.

## Constraints and limits

### Compatibility and versions

Assay versions are `vMAJOR.MINOR.PATCH`. While the module is pre-1.0
([api-stability.md](api-stability.md)), any change since the last release that breaks a consumer
makes the next release a minor bump; compatible fixes and additions make it a patch. "Consumer"
covers every surface:

- the exported Go API of every non-`internal` package;
- the Report's JSON shape and `report.SchemaVersion`, SARIF and OpenVEX output;
- a new value in a vocabulary consumers switch on, such as a verdict, a basis or a reason code;
- the name or meaning of a CLI flag, an `ASSAY_*` variable or an Action input.

A break is never argued down to a patch because it is "additive" or because nothing in this module
produces the new value. The release notes for v0.5.0 and v0.6.0 each carry a *Breaking (library
API)* section.

`corpus` and `plugin/symboltest` carry no API-stability promise
([README, Using Assay as a Go library](../README.md#using-assay-as-a-go-library)), so a change there
is not a library break.

Two library rules from [api-stability.md](api-stability.md) bind every PR:

- No third-party type reaches an exported signature. The page has the regression check.
- The exported mutable process-wide variables listed there stay set-once-before-use. Do not add to
  the list without a reason.

`apidiff` is the check for the exported API. A reviewer runs it rather than reading the diff for
breaks, because a break such as a struct losing comparability is invisible in a diff (see
[How to review](#how-to-review)).

### Releases happen in CI only

A release is minted by `.github/workflows/release.yml` from a pushed tag, never from a workstation
([AGENTS.md](../AGENTS.md), [docs/releases/README.md](releases/README.md)). A review never suggests
`gh release create`, a hand-made tag or a locally built asset as a way to ship.

- `LICENSE` keeps `Change Date: TBD` on every branch; `license-guard.yml` fails any push or pull
  request whose `LICENSE` names a Change Date.
- `release.yml` is not edited by hand.
- `action.yml`'s `scanner-version` default stays a `vX.Y` minor alias. A branch moves the alias in
  the change that needs the new minor's scanner, never as a release step.

### The built-in advisory table is a floor

Real runs read advisories from an external corpus. With no corpus configured, the scan falls back
to a small built-in table so the engine still runs standalone
([README, Advisory corpus](../README.md#advisory-corpus)). The table is a default floor. A doc,
release note or comment that presents its counts as Assay's advisory coverage is a finding.

### Performance and size

No published benchmark exists yet
([README, Expected scan duration](../README.md#expected-scan-duration)). The README names the cost
drivers instead. A PR that adds a per-run fetch, an uncached download or work that scales with the
dependency graph should update that section and say what it measured in the PR body.

## How to review

### Set up

1. **Check out the PR head; don't review from the diff alone.** Use a fresh worktree at the head
   commit. Most review errors come from a question the tree would have answered: whether every
   producer sorts, who calls the changed function, what the doc comment two screens up promises.
2. Build and test, the way CI does:

   ```sh
   go build ./... && go vet ./... && go test ./...
   ```

   If the PR touches `plugins/cfamily`, that is its own module; run the same three commands there
   with `GOWORK=off`.
3. Run `apidiff` against the base for the exported packages:

   ```sh
   go install golang.org/x/exp/cmd/apidiff@latest
   mkdir -p /tmp/assay-base
   git archive <base-ref> | tar -x -C /tmp/assay-base
   (cd /tmp/assay-base && GOWORK=off apidiff -m -w /tmp/old.exp github.com/ferralon-ai/ferralon-assay)
   GOWORK=off apidiff -m -w /tmp/new.exp github.com/ferralon-ai/ferralon-assay
   apidiff -m -incompatible /tmp/old.exp /tmp/new.exp
   ```

   Every incompatible line on an exported package is a break that the PR body, and later the
   release notes, must name. On a release PR, use the previous release tag as the base.

### Read

- **Read the callers of every changed function**, not just the function. A tightened precondition
  breaks a caller the diff never shows.
- **Check that each doc comment still matches the behaviour**, including comments the PR did not
  touch. A comment that says a change "never affects a verdict" while it raises a grade or a rank
  is a finding.
- **Check every surface that carries the same fact.** One result reaches `report.json`, SARIF,
  OpenVEX, the HTML report, the PR comment, the pinned Issue and the job summary
  ([operator guide, Where the evidence shows up](operator-guide.md#where-the-evidence-shows-up)).
  When Reports merge or inherit, as in `pr-inherit`, confirm that the summary and the published
  Report describe the same run.
- **Check the PR body against the code.** Claims about what changed, what was tested and what the
  risk is are part of what a reviewer verifies.

### Test

- Tests follow the repository's pattern: table-driven, named for the property, and placed beside the
  code. A test should assert the property ("a row with no resolved version is never
  `not_exploitable`"), not echo the implementation.
- **Mutation-test refutation and hazard gates.** For each condition that can let a row become
  `not_exploitable` or `disqualified`, or that withholds one, flip it or drop it, run the package's
  tests, and confirm one fails; then restore it. A guard no test notices can disappear in a later
  refactor and leave a false "not affected" behind. Do it once, on the final head. Producers,
  plumbing, docs and deletions do not need it.
- **Evidence is recorded, not committed.** A one-time proof, such as "this refactor changes no
  output", belongs in the PR's *How did you test it?* section as a command and its result. New
  golden files or harnesses belong in a PR only when the change needs a standing regression net.
  A new test file much larger than the change it guards is scope to question. Lane conformance has
  its own harness, [`plugin/symboltest`](../plugin/symboltest).
- Tests that need the network carry the `//go:build live` tag; the CI test job runs without network
  access.

### Across rounds

- Each round lists every earlier finding as **addressed** or **still open**, with a fresh citation.
- Cite only what the author can open: the repository at the reviewed commit, and reviews posted on
  the PR. An "earlier round" that was never posted on the PR does not exist for the author.
- A gap listed as "not checked" for two rounds gets checked in the third.

## Checklists by change type

Tick the ones that apply. The general sections above still hold.

### A language-lane feature

- [ ] Partiality is declared for every case the feature cannot resolve; nothing defaults to a clean
      answer.
- [ ] The lane's page under `docs/capabilities/` is updated: feature status, caveats, and the
      matrix counts in [capabilities/README.md](capabilities/README.md).
- [ ] The other lanes are considered: parity, an architectural `N/A`, or a stated reason.
- [ ] Java annotations are taught to both the lexical and the SCIP recognizers.
- [ ] Any new refutation or hazard gate is mutation-tested.
- [ ] Any new network fetch or toolchain run is in the threat model and the README.
- [ ] A new language also extends `checkout.DetectLanguage`; otherwise its plugin is never called
      ([README, Extending Assay](../README.md#pluginlanguageplugin--evidence-for-one-language)).

### Call-graph and call-resolution changes

- [ ] An edge the analysis could not resolve is declared, for example as an unresolved call site or
      a partiality reason. It is never dropped silently.
- [ ] Resolution is deterministic: the same input gives the same graph, in the same order.
- [ ] Tests cover both directions: a path that now resolves, and a case that must stay open.
- [ ] Verdict movement is stated in the PR body: which rows can change, and to what.

### Verdict, Report, SARIF and OpenVEX changes

- [ ] Every new `not_exploitable` or `disqualified` route names its basis and has a test for it.
- [ ] `undetermined` and `indeterminate` still project as negative space (OpenVEX
      `under_investigation`), never as a positive status.
- [ ] A change to the Report's JSON shape bumps `report.SchemaVersion` and extends `report.Upgrade`
      ([`report/migrate.go`](../report/migrate.go)).
- [ ] A changed OpenVEX justification or SARIF message text is called out: consumers match on those
      strings.
- [ ] The five-verdict table in [language-support.md](language-support.md) and the operator guide's
      grounds and reasons tables still match the code.

### Action inputs

- [ ] The input's description says what it does, its default, and any scanner-version requirement.
      `action.yml` states requirements, never what a given release carries (see the comment above
      `scanner-version`).
- [ ] A branch's Action runs the released scanner its minor alias selects, which may predate the
      change. A new input must degrade safely against a scanner that ignores it.
- [ ] Inputs reach the scanner through `ASSAY_*` variables set inside the Action, so a caller never
      writes them.
- [ ] Any credential or cache exposure is covered in the threat model.

### CLI flags

- [ ] Each flag has its `ASSAY_*` variable where the CLI pairs them, and the precedence matches its
      neighbours.
- [ ] The README or operator guide documents it, and the Action forwards it if operators need it
      there.
- [ ] A renamed or re-meant flag is a break and is named as one.

### Release notes

Release PRs are titled `Release: vA.B.C` and carry `docs/releases/vA.B.C.md`
([CONTRIBUTING.md](../.github/CONTRIBUTING.md#releasing)). On every round:

- [ ] **Set difference.** List the PRs merged since the previous tag
      (`git log --first-parent <prev-tag>..<head>`) and compare them with the PRs the notes cite.
      Each missing one is either listed or knowingly left out.
- [ ] **API diff.** Run `apidiff -incompatible` from the previous tag to the head and compare it with
      *Breaking (library API)*.
- [ ] Every Action input added or removed since the previous tag is listed.
- [ ] Every change that can move a verdict is listed under the change, not only in a summary.
- [ ] The notes are written for someone deciding whether to adopt the release
      ([docs/releases/README.md](releases/README.md#cutting-a-release)): what changed and what a
      consumer must do, stated flatly. Commentary on the version scheme, or on whether a change
      counts as breaking, does not help that reader.
- [ ] Every claim is verifiable from the repository or the release.
- [ ] The built-in advisory table is not described as coverage.
- [ ] No step asks a reader to cut, tag or publish anything by hand.

### Docs-only changes

- [ ] Every link and every repository path resolves.
- [ ] Every claim about behaviour matches the code at the head. Open it; don't trust the old doc.
- [ ] Docs describe what is, in the present tense. History belongs in the commit message and the PR
      body, not in "formerly", "no longer" or "previously" notes.
- [ ] A capability is not claimed for a language that the capability matrix does not show.
- [ ] Docs-only PRs skip the build and mutation steps; the link and claim checks are the review.

## What not to flag

- **What CI already gates.** Every PR runs build, vet, gofmt and the hermetic test suite, the same
  for `plugins/cfamily`, a self-scan of the Action, and the `LICENSE` Change Date guard
  (`.github/workflows/ci.yml`, `license-guard.yml`). Report a red check; don't repeat it as a
  finding.
- **Style that `gofmt` owns.**
- **Architectural absences.** Anything marked `N/A` in the capability matrix, and `Unsupported`
  operations a lane does not implement by design.
- **Withholding a verdict.** A change that makes Assay say `undetermined` where it cannot ground a
  clear is the sound default. Flag it only when the PR claims a clear it does not deliver, or when it
  withholds far more than its stated hazard needs.
- **Running the repository's build tool**, as covered under
  [The scanned repository is the operator's own](#the-scanned-repository-is-the-operators-own).

## A few more things worth knowing

- **Don't ask what the source answers.** If the tree confirms a defect, report it at its severity.
- **Undetermined and indeterminate are different words.** `undetermined` is a Report verdict;
  `indeterminate` is a `verdict.Direction`. Keep them apart in reviews and docs.
- **`#NN` means a PR or issue in this repository.** Refer to another repository's item as
  `ferralon-ai/<repo>#NN`.
- **Exported state is shared.** `pipeline.AdvisoryTable` and the other exported variables in
  [api-stability.md](api-stability.md) are not safe to write concurrently. A test or feature that
  writes them needs a reason.
- **The PR template is the shape of the body:** what changed, why, and how it was tested
  ([PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md)). A PR that could break a
  consumer says so there.
