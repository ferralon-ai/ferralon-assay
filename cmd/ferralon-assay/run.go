package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/resultsink/ferralon"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Env var names for the flag/env-dual-channel run inputs (advisory corpus dir and requirement,
// OSV work-set widening, declared and observed subject Go toolchain). Brand-derived so a
// rebranded fork's --help output and action.yml env mapping carry no prior codename (see
// brand.EnvPrefix); the retired NUCLEON_ and TEGRON_ literals are still honored via
// brand.EnvOrLegacy for anything already set by hand — the shipped build was -tags stealth, so an
// operator's workflow YAML may carry either name.
const (
	envAdvisoryCorpusDir        = brand.EnvPrefix + "_ADVISORY_CORPUS_DIR"
	nucleonEnvAdvisoryCorpusDir = "NUCLEON_ADVISORY_CORPUS_DIR"
	legacyEnvAdvisoryCorpusDir  = "TEGRON_ADVISORY_CORPUS_DIR"
	// envAdvisoryCorpusRequired declares that this run EXPECTS a corpus — see
	// advisoryCorpusRequired for why the declaration has to come from somewhere OTHER than the
	// corpus path itself.
	envAdvisoryCorpusRequired        = brand.EnvPrefix + "_ADVISORY_CORPUS_REQUIRED"
	nucleonEnvAdvisoryCorpusRequired = "NUCLEON_ADVISORY_CORPUS_REQUIRED"
	legacyEnvAdvisoryCorpusRequired  = "TEGRON_ADVISORY_CORPUS_REQUIRED"
	// envOSVWorkSet is the second channel for the OSV work-set widening (see osvWorkSetEnabled).
	// The widening is off by default, so this is normally an opt-IN; it also carries an explicit
	// off for an operator whose orchestrator would otherwise turn it on.
	envOSVWorkSet              = brand.EnvPrefix + "_OSV_WORK_SET"
	nucleonEnvOSVWorkSet       = "NUCLEON_OSV_WORK_SET"
	legacyEnvOSVWorkSet        = "TEGRON_OSV_WORK_SET"
	envSubjectGoVersion        = brand.EnvPrefix + "_SUBJECT_GO_VERSION"
	nucleonEnvSubjectGoVersion = "NUCLEON_SUBJECT_GO_VERSION"
	legacyEnvSubjectGoVersion  = "TEGRON_SUBJECT_GO_VERSION"
	envCIGoVersion             = brand.EnvPrefix + "_CI_GO_VERSION"
	nucleonEnvCIGoVersion      = "NUCLEON_CI_GO_VERSION"
	legacyEnvCIGoVersion       = "TEGRON_CI_GO_VERSION"
)

// envTrustObservedGo carries the action's `trust-observed-go` input: the caller's assertion that the
// Go installed when the Action started is the toolchain the SCANNED repository builds with. True in a
// same-job setup that ran actions/setup-go (or otherwise provisioned its build toolchain) ahead of
// the scan; false in a dedicated scan workflow, where the observed Go is the hosted runner image's
// and says nothing about the subject. Brand-derived with the retired NUCLEON_ and TEGRON_ literals
// honored — see brand.EnvOrLegacy — for the same reason as
// envAdvisoryCorpusDir/envSubjectGoVersion/envCIGoVersion.
const (
	envTrustObservedGo        = brand.EnvPrefix + "_TRUST_OBSERVED_GO"
	nucleonEnvTrustObservedGo = "NUCLEON_TRUST_OBSERVED_GO"
	legacyEnvTrustObservedGo  = "TEGRON_TRUST_OBSERVED_GO"
)

// selectSinks composes the ACTIVE set of ResultSinks for a run, deterministically,
// from the detected GitHub Actions Env snapshot and the local output directory.
//
// Policy (sinks are published in this order; see publishAll for the error contract):
//
//   - Local is ALWAYS first. It writes report.json + the projections into outDir,
//     which is also what the SARIF-upload and Pages workflow steps read. A purely
//     local / non-Actions run gets ONLY this sink.
//   - Tier 0 (NewTier0Summary) is added whenever the run is inside GitHub Actions
//     (env.InActions). It is zero-permission (job summary + ::warning:: annotations)
//     and therefore survives forked PRs.
//   - Tier 1 is gated per-surface on the detected capabilities: SARIF when
//     caps.CanSARIF, PR comment when caps.CanComment, pinned Issue when caps.CanIssue.
//     Each of these three surfaces is now individually toggle-gated (default-on,
//     opt-out via TEGRON_CODE_SCANNING / TEGRON_PR_COMMENT / TEGRON_ISSUE), while
//     Pages stays opt-in. Every toggle is AND-ed with write capability inside Detect,
//     so on a forked PR (read-only token) all three are absent regardless of the
//     toggles — a forked PR composes only Tier 0 + Local, the forked-PR safety
//     guarantee. A push build has CanComment=false (no PR), so it gets SARIF + Issue
//     but no PR comment.
//   - Tier 2 (NewTier2Pages) is added only when caps.CanPages (TEGRON_PAGES opt-in
//     AND a write token).
//   - The Ferralon run-snapshot sink (runSnapshot, resolved by the caller from the
//     FERRALON_RUNS_URL + default-branch env) is appended when non-nil. It is the
//     only sink in the set that contacts Ferralon: it pushes the run's report to the backend
//     /runs endpoint so the console can render a live assessment. It is gated OUTSIDE
//     the selector (default-branch + URL) and only reached inside the InActions block,
//     so a local / forked-PR / non-default-branch run never files a run.
//
// The selector reads no live environment: every decision flows from the passed Env,
// so it is pure and unit-testable (construct an Env literal, assert the composition).
func selectSinks(env github.Env, outDir string, runSnapshot resultsink.ResultSink) []resultsink.ResultSink {
	sinks := []resultsink.ResultSink{resultsink.NewLocal(outDir)}

	if !env.InActions {
		return sinks
	}

	caps := github.Detect(env)

	sinks = append(sinks, github.NewTier0Summary(env))

	if caps.CanSARIF {
		sinks = append(sinks, github.NewTier1SARIF(outDir))
	}
	if caps.CanComment {
		sinks = append(sinks, github.NewTier1PRComment(env, nil))
	}
	if caps.CanIssue {
		sinks = append(sinks, github.NewTier1Issue(env, nil))
	}
	if caps.CanPages {
		sinks = append(sinks, github.NewTier2Pages(env))
	}
	if runSnapshot != nil {
		sinks = append(sinks, runSnapshot)
	}

	return sinks
}

// selectRunSnapshotSink decides whether this run pushes a run snapshot to the backend
// /runs endpoint, returning the sink or nil. It is the load-bearing gate:
// the push fires ONLY when (a) a run-snapshot URL resolved non-empty (resolveEndpoint in
// link.go — the caller opted in via link-to-console AND the release carries or overrides a
// runs endpoint; empty on the OSS/dogfood path and on an explicit opt-out) AND (b) the run is
// on the repository's DEFAULT branch (refName == defaultBranch, both non-empty). A PR /
// non-default-branch run returns nil and stays stateless — it never files a report_run,
// mirroring how the StateStore -repo persistence is default-branch-gated by the caller.
// It is pure (env is read by the caller) so the gate is unit-testable.
func selectRunSnapshotSink(url, refName, defaultBranch string, token ferralon.TokenSource) resultsink.ResultSink {
	if url == "" {
		return nil
	}
	if refName == "" || defaultBranch == "" || refName != defaultBranch {
		return nil
	}
	return ferralon.NewRunSnapshot(url, token)
}

// publishResult renders the projections once and publishes the Result to every sink
// the selector composed for the current environment.
//
// intel is stamped onto the Report first, so every sink and every projection carries the
// disclosure of which work set and which advisory facts this pass actually used. It is stamped HERE
// rather than inside the trigger because the trigger knows nothing about how the entrypoint resolved
// its sources — this is the only place both facts are in hand.
func publishResult(ctx context.Context, outDir string, rep *report.Report, intel report.IntelProvenance) error {
	rep.Provenance.Intel = &intel
	res, err := buildResult(rep)
	if err != nil {
		return err
	}
	runsURL := resolveEndpoint(linkedToConsole(), os.Getenv(envRunsURL), bakedRunsURL)
	runSnapshot := selectRunSnapshotSink(runsURL, os.Getenv(envRefName), os.Getenv(envDefaultBranch), resolveOIDCToken)
	return publishAll(ctx, selectSinks(github.DetectEnv(), outDir, runSnapshot), res)
}

// buildResult renders the three projections from rep into a resultsink.Result.
func buildResult(rep *report.Report) (resultsink.Result, error) {
	vex, err := projection.MarshalReportVEX(*rep)
	if err != nil {
		return resultsink.Result{}, fmt.Errorf("project OpenVEX: %w", err)
	}
	sarif, err := projection.MarshalReportSARIF(*rep)
	if err != nil {
		return resultsink.Result{}, fmt.Errorf("project SARIF: %w", err)
	}
	html, err := projection.MarshalReportHTML(*rep)
	if err != nil {
		return resultsink.Result{}, fmt.Errorf("project HTML: %w", err)
	}
	return resultsink.Result{
		Report:      *rep,
		Projections: resultsink.Projections{OpenVEX: vex, SARIF: sarif, HTML: html},
	}, nil
}

// publishAll publishes res to every sink in order. It attempts ALL sinks even if an
// earlier one fails (so a Tier-1 surface outage never suppresses the always-on Local
// + Tier-0 deposit) and returns the joined set of errors (nil when all succeeded).
func publishAll(ctx context.Context, sinks []resultsink.ResultSink, res resultsink.Result) error {
	var errs []error
	for _, s := range sinks {
		if err := s.Publish(ctx, res); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// runConfig holds the resolved shared inputs for the pr-inherit / cve-watch run modes:
// the selected StateStore, the neutral subject/codebase coordinates, the language-scoped
// advisory corpus, the Assess pipeline seams, and the local output directory. cleanup
// releases any transient resource — the temp clone dir when -target is a remote URL, a
// no-op when it is a local directory.
type runConfig struct {
	store         statestore.StateStore
	subject       trigger.Subject
	codebase      assessment.CodebaseRef
	workSet       workSet
	advisories    []assessment.VulnRef
	assessOptions []pipeline.AssessOption
	outDir        string
	cleanup       func()
}

// runFlags registers the flags common to the pr-inherit / cve-watch modes. It reuses
// the StateStore-selection flags (registerStateStoreFlags) so every run mode selects a
// store the same way the `state` subcommands do.
type runFlags struct {
	fs               *flag.FlagSet
	sf               *stateStoreFlags
	target           *string
	outDir           *string
	repo             *string
	revision         *string
	commit           *string
	plugin           *string
	advisoryCorpus   *string
	requireCorpus    *bool
	houseCanaries    *bool
	osvWorkSet       *bool
	subjectGo        *string
	resolvedFacts    string // FactSource* — set by advisoryCorpusOption
	resolvedCorpus   pipeline.CorpusInfo
	resolvedCorpusOK bool
	resolvedSource   pipeline.AdvisorySource // the chain the pass resolves facts through
}

// osvWorkSetDefault is whether a scan-path run (baseline / pr-inherit) widens its work set by
// querying OSV.dev, when neither -osv-work-set nor TEGRON_OSV_WORK_SET says otherwise.
//
// THIS IS THE SINGLE LINE THAT DECIDES WHETHER A SCAN-PATH RUN CONTACTS api.osv.dev. Flip it to
// true and every baseline and pr-inherit run POSTs the repository's dependency coordinates there;
// nothing else has to change for the widening to take effect.
//
// It is NOT the line between the scanner and every third party. A default scan already contacts
// https://vuln.go.dev on every run — the Go analyzer's reachability stage runs govulncheck with no
// -db flag, so it resolves golang.org/x/vuln's default database uncached
// (internal/plugin/goanalysis/reach.go) — and proxy.golang.org when it resolves the subject's module graph.
// README.md ("Network egress") is the authoritative enumeration.
//
// It is FALSE because api.osv.dev is the one host the customer-facing surface commits to keeping
// off the scan path. The scaffolded workflow never sets `mode`, so it runs `baseline`; the workflow
// committed into a customer's repository enumerates the endpoints the run contacts; and the Action
// exposes no input that could turn a third-party query off. A default that silently adds a
// counterparty the shipped, auditable disclosure does not name is the wrong default regardless of
// how useful the capability is — so the capability ships intact and dormant.
//
// Flipping this to true REQUIRES, in the same change: an `osv-work-set` input on the Action, that
// input written into the scaffold's `with:` block, and the OUTBOUND paragraph in the scaffolded
// workflow + bootstrap PR body rewritten to name api.osv.dev and say what is sent to it (package
// coordinates; never source, never analysis results).
const osvWorkSetDefault = false

func registerRunFlags(fs *flag.FlagSet) *runFlags {
	return &runFlags{
		fs:             fs,
		sf:             registerStateStoreFlags(fs),
		target:         fs.String("target", ".", "local path to a source tree to scan, or a remote repo URL / module path to clone (git)"),
		outDir:         fs.String("out", brand.Name+"-out", "directory to write report.json / report.html / SARIF into"),
		repo:           fs.String("subject-repo", "", "neutral repository identity recorded on the Report (default: target basename)"),
		revision:       fs.String("revision", "", "revision recorded on the Report (e.g. a PR head branch)"),
		commit:         fs.String("commit", "", "resolved commit SHA recorded on the Report"),
		plugin:         fs.String("plugin-go", "", "explicit path to the analyzer binary for the detected language (tegron-plugin-<lang>; default: PATH lookup)"),
		advisoryCorpus: fs.String("advisory-corpus", "", "path to a filesystem advisory corpus (manifest.json + digest-pinned per-advisory JSON) consulted BEFORE the built-in advisory table; overrides "+envAdvisoryCorpusDir),
		// requireCorpus declares that this run EXPECTS a corpus. Without it, an absent corpus
		// path is indistinguishable from a corpus fetch that failed and left the path empty.
		requireCorpus: fs.Bool("require-advisory-corpus", false, "fail the run when no advisory corpus resolves, instead of falling back to the built-in advisory table; overrides "+envAdvisoryCorpusRequired),
		// houseCanaries opts the first-party house canaries (the FERRALON-APP-* Go application-sink
		// advisories and the synthetic Java/JS/Python corpus advisories) into the corpus. OFF by
		// default so a customer/investor scan never evaluates them; the Ferralon demo scan sets it
		// so the DOS canary surfaces as a reachable_candidate.
		houseCanaries: fs.Bool("include-house-canaries", false, "include the first-party house-canary advisories in the scan corpus (off by default; the Ferralon demo scan sets this)"),
		// osvWorkSet widens the scan's work set with the advisories OSV.dev reports against the
		// repository's real dependencies. OPT-IN — see osvWorkSetDefault for why, and
		// envOSVWorkSet for the second channel that switches it on.
		osvWorkSet: fs.Bool("osv-work-set", osvWorkSetDefault, "query OSV.dev over the repository's dependencies to widen the advisory work set beyond the built-in language set (off by default: it sends this repository's dependency coordinates to a third party); overrides "+envOSVWorkSet),
		subjectGo:  fs.String("subject-go-version", "", "the Go toolchain version the SCANNED repository builds with, e.g. go1.21.3 — an exact statement, not the scanner's own toolchain; overrides "+envSubjectGoVersion+" (default: resolved from the CI runner, then the target's go.mod directives)"),
	}
}

// osvWorkSetEnabled reports whether this run widens its work set by querying OSV.dev over the
// repository's real dependencies. It is OFF unless explicitly switched on (osvWorkSetDefault).
//
// PRECEDENCE. The flag wins over the env var, and the Visit is what makes that true in BOTH
// directions: without it an unset flag is indistinguishable from one explicitly set to the default,
// so -osv-work-set=false could not override TEGRON_OSV_WORK_SET=1. Asking the FlagSet which flags
// were actually named keeps the flag authoritative whichever way it points.
//
// An unparseable env value is an ERROR, never a default, on the same reasoning as
// advisoryCorpusRequired: a typo must not silently change what the scan covers.
//
// NOT SWITCHING IT ON IS NOT A PARTIALITY. A run that never asked to widen is a supported
// configuration — the default one — and its Report says so plainly (WorkSetSource stays
// builtin_language_set). A widening that was asked for and FAILED is different and does emit a
// note; the distinction is intent, exactly as with the corpus require gate. What is disclosed is
// the gap between what was asked for and what happened.
func (f *runFlags) osvWorkSetEnabled() (bool, error) {
	explicit := false
	f.fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "osv-work-set" {
			explicit = true
		}
	})
	if explicit {
		return *f.osvWorkSet, nil
	}
	raw := brand.EnvOrLegacy(envOSVWorkSet, nucleonEnvOSVWorkSet, legacyEnvOSVWorkSet)
	if raw == "" {
		return *f.osvWorkSet, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s=%q is not a boolean (want 1/0, true/false): refusing to guess whether the OSV work-set query is enabled", envOSVWorkSet, raw)
	}
	return v, nil
}

// scanWorkSet resolves the work set for a SCAN-path run (baseline / pr-inherit): the compiled-in
// language floor, OPTIONALLY widened with the advisories OSV.dev reports against the repository's
// real dependencies. The widening is off unless it is explicitly switched on (osvWorkSetDefault),
// so by default this resolves to the floor and makes no network call.
//
// cve-watch deliberately does NOT call this. That mode already drives its analysis from an OSV query
// (against the stored SBOM, diffed against a cursor) and its behaviour is unchanged here.
//
// A RESOLVED WORK SET OF ZERO HALTS THE RUN. This is the one place that judgement is made, and it is
// made HERE rather than at acquisition because the compiled-in floor is not the set the pass
// evaluates: the widening above takes the acquired target as input and can populate a floor that
// resolved to nothing. Gating the floor failed every Java/JS/Python scan that asked for the widening,
// with an error naming remedies the user had not asked for.
//
// It is a HARD error, not a warning, on the precedent this CLI already sets for a degraded advisory
// input: advisoryCorpusOption hard-fails a wholly-unusable -advisory-corpus rather than silently
// falling back to the built-in table (decisions.md #1), and a target whose language has no analyzer
// hard-fails in selectPlugin. Both refuse to produce a Report the inputs cannot support. An empty
// work set is the worst-consequence member of that family: the run succeeds, exits 0, and publishes
// a findings-free Report a reader cannot distinguish from an assessed all-clear.
//
// The condition is strictly THE SET IS EMPTY — never a language, never a source. An ecosystem that
// resolves nothing today stops failing the moment anything populates its work set, with no code
// change and nothing to remove.
func (f *runFlags) scanWorkSet(ctx context.Context, acq *acquired) (workSet, error) {
	enabled, err := f.osvWorkSetEnabled()
	if err != nil {
		return workSet{}, err
	}
	ws := floorWorkSet(acq.advisories)
	if enabled {
		ws = resolveWorkSet(ctx, acq, &trigger.HTTPOSVClient{}, f.resolvedSource)
	}
	if len(ws.advisories) == 0 {
		return workSet{}, errEmptyWorkSet(acq.language)
	}
	return ws, nil
}

// errEmptyWorkSet is the run-halting error for a work set that resolved to no advisories.
//
// The message states the fact and names the inputs that populate a work set, flatly. It does NOT
// branch on which input was supplied: the compiled-in advisory table is temporary scaffolding, and
// under the policy/manifest corpus that replaces it the honest sentence becomes "your policy
// resolved no advisories for this ecosystem" — a rewrite of one string, which a remedy decision tree
// would turn into an unpicking job.
func errEmptyWorkSet(language string) error {
	return fmt.Errorf("work set is empty: 0 advisories resolved for the detected %s ecosystem — the scan would emit a findings-free Report without having assessed anything, which reads as an all-clear it did not establish; a work set is populated by the built-in advisory table, -advisory-corpus, -include-house-canaries and -osv-work-set", language)
}

// advisoryCorpusOption resolves the optional filesystem-corpus AssessOption for a run, realizing the
// flag > env precedence (decisions.md #3): the -advisory-corpus flag wins; absent it, the
// envAdvisoryCorpusDir env var (the orchestrator's channel; brand-derived, legacy TEGRON_
// literal honored — see brand.EnvOrLegacy) is consulted; absent both it returns
// (nil, nil) — the built-in AdvisoryTable default, unchanged. This is the CLI half of the
// system-wide "both flag + env, flag wins" surface (tegrond is env-only by its own idiom).
//
// THE CORPUS SUPPLEMENTS THE TABLE, IT DOES NOT REPLACE IT. This used to install the corpus as THE
// source, which meant every id the corpus did not carry resolved to zero facts and failed open.
// Measured against the 2026-07-23 published corpus, that emptied the ENTIRE 16-id scan work set. The
// source is now a chain — corpus first, built-in table behind it — so a corpus can only ever add
// facts (pipeline.NewChainSource; first hit wins, no merging across sources).
//
// A resolved path is preflight-Validated and a wholly-unusable corpus HARD-FAILS the run
// (decisions.md #1) with a descriptive error, so a broken corpus is loud, never silently degraded
// to stale built-in intel. When the run declares that it EXPECTS a corpus, an ABSENT one hard-fails
// too — see advisoryCorpusRequired. It also records what it resolved on f, so the run can put its
// intel provenance on the Report.
func (f *runFlags) advisoryCorpusOption() (pipeline.AssessOption, error) {
	f.resolvedFacts = report.FactSourceBuiltinTable
	f.resolvedCorpus, f.resolvedCorpusOK = pipeline.CorpusInfo{}, false
	// The built-in table is the source until a corpus resolves in front of it. Recorded so the
	// work-set widener can ask the REAL fact source what it can answer for.
	f.resolvedSource = pipeline.NewTableSource()

	required, err := f.advisoryCorpusRequired()
	if err != nil {
		return nil, err
	}

	dir := *f.advisoryCorpus
	if dir == "" {
		dir = brand.EnvOrLegacy(envAdvisoryCorpusDir, nucleonEnvAdvisoryCorpusDir, legacyEnvAdvisoryCorpusDir)
	}
	if dir == "" {
		if required {
			return nil, fmt.Errorf("advisory corpus is required for this run (-require-advisory-corpus / %s) but no corpus path resolved:"+
				" neither -advisory-corpus nor %s is set. A corpus fetch step that failed leaves exactly this state, and analysis"+
				" against stale built-in intel would render as a clean scan. Fix the fetch, or drop the requirement to scan with built-in intel only",
				envAdvisoryCorpusRequired, envAdvisoryCorpusDir)
		}
		return nil, nil
	}

	src := pipeline.NewArtifactSource(dir)
	if v, ok := src.(pipeline.CorpusValidator); ok {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("advisory corpus %q is unusable: %w", dir, err)
		}
	}
	if d, ok := src.(pipeline.CorpusDescriber); ok {
		f.resolvedCorpus, f.resolvedCorpusOK = d.Describe()
	}
	// An EMPTY corpus is a fetch that "succeeded" and delivered nothing. Under a declared
	// requirement that is the same failure as an absent one: the run would resolve every fact from
	// built-in intel while reporting a corpus digest.
	if required && f.resolvedCorpusOK && f.resolvedCorpus.Records == 0 {
		return nil, fmt.Errorf("advisory corpus %q is required for this run but contains zero records", dir)
	}
	f.resolvedFacts = report.FactSourceCorpusThenBuiltinTable

	chain := pipeline.NewChainSource(src, pipeline.NewTableSource())
	f.resolvedSource = chain
	return pipeline.WithAdvisorySource(chain), nil
}

// advisoryCorpusRequired reports whether this run declares that it EXPECTS an advisory corpus.
//
// THE PROBLEM IT SOLVES. "No corpus was configured" and "the corpus fetch failed, so no corpus was
// configured" are byte-identical at this seam: both are an empty path. The first is a legitimate
// zero-config local scan; the second is analysis that did not happen, and degrading it silently to
// built-in intel renders a failed scan as a clean one. Distinguishing them needs a signal that does
// NOT come from the corpus path, because the corpus path is the thing that went missing.
//
// THE MECHANISM. An explicit declaration, from the caller that knows a corpus was supposed to be
// there: the -require-advisory-corpus flag or envAdvisoryCorpusRequired. It is deliberately
// INDEPENDENT of the fetch's outcome — a CI step that only exports its result on success cannot
// express this, which is the whole failure mode. The declaration is a property of the workflow's
// configuration, not of the run's success.
//
// An unparseable value is an ERROR, not a default. A typo in the requirement flag must not silently
// disable the requirement — that would reintroduce the exact silent downgrade this gate closes.
func (f *runFlags) advisoryCorpusRequired() (bool, error) {
	if *f.requireCorpus {
		return true, nil
	}
	raw := brand.EnvOrLegacy(envAdvisoryCorpusRequired, nucleonEnvAdvisoryCorpusRequired, legacyEnvAdvisoryCorpusRequired)
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s=%q is not a boolean (want 1/0, true/false): refusing to guess whether an advisory corpus is required", envAdvisoryCorpusRequired, raw)
	}
	return v, nil
}

// intelProvenance renders what this run resolved into the Report's disclosure block: which set of
// advisory ids the pass evaluated and how that set was chosen (ws), and which fact sources it
// resolved them through (f). The two are deliberately separate — a corpus is a fact lookup, not a
// work list, and conflating them is what let "72 records" read as "72 advisories evaluated".
func (f *runFlags) intelProvenance(ws workSet) report.IntelProvenance {
	p := report.IntelProvenance{
		WorkSetSource: ws.source,
		WorkSetSize:   len(ws.advisories),
		FactSource:    f.resolvedFacts,
	}
	if f.resolvedCorpusOK {
		p.CorpusDigest = f.resolvedCorpus.Digest
		p.CorpusRecords = f.resolvedCorpus.Records
	}
	return p
}

// subjectToolchainOption resolves the two candidate subject-toolchain sources — the caller's
// declaration and the CI runner's observation — into an AssessOption, or nil when neither is present — in which case the fact falls back to the
// target's go.mod floors, which is the normal local-CLI case.
//
// The DECLARED value follows this CLI's usual flag > env precedence (-subject-go-version, then
// envSubjectGoVersion). The OBSERVED value is env-only (envCIGoVersion) on purpose: it
// is a measurement of the CI runner taken by the Action's pre-setup-go step, not a knob a human
// sets, and giving it a flag would invite passing the scanner's own toolchain as if it were the
// subject's. Neither value is validated here — an unorderable version resolves nothing in the
// pipeline rather than failing the scan. Both env names are brand-derived with the legacy
// TEGRON_ literal honored as a fallback — see brand.EnvOrLegacy.
//
// The observation's TRUST is env-only for the same reason and read from the same channel as the
// measurement it qualifies (envTrustObservedGo, the Action's trust-observed-go input — likewise
// brand-derived with the legacy TEGRON_TRUST_OBSERVED_GO literal honored). It fails closed exactly
// like FERRALON_LINK_TO_CONSOLE: anything but an explicit true leaves the observation out of
// resolution, so a typo degrades to the go.mod floors rather than to a stronger claim than the
// operator asserted.
func (f *runFlags) subjectToolchainOption() pipeline.AssessOption {
	declared := *f.subjectGo
	if declared == "" {
		declared = brand.EnvOrLegacy(envSubjectGoVersion, nucleonEnvSubjectGoVersion, legacyEnvSubjectGoVersion)
	}
	observed := brand.EnvOrLegacy(envCIGoVersion, nucleonEnvCIGoVersion, legacyEnvCIGoVersion)
	if declared == "" && observed == "" {
		return nil
	}
	return pipeline.WithSubjectToolchain(declared, observed, trustObservedGo())
}

// trustObservedGo reports whether the observed runner toolchain may be treated as a statement about
// the subject. Fails closed: any value that is not an explicit true reads as untrusted.
func trustObservedGo() bool {
	trusted, err := strconv.ParseBool(strings.TrimSpace(brand.EnvOrLegacy(envTrustObservedGo, nucleonEnvTrustObservedGo, legacyEnvTrustObservedGo)))
	return err == nil && trusted
}

// envSubjectToolchainReach / legacyEnvSubjectToolchainReach is the release gate on running the Go
// reachability analysis under the SUBJECT's toolchain rather than the scanner's. It follows the env-gate idiom of TEGRON_JAVA_ANALYZER_IMAGE (env-only, no flag)
// because it is an operator's rollout switch for one release, not a per-scan knob, and the Action
// input is its real surface — action.yml exports the legacy name (see subject-toolchain-
// reachability), honored here via brand.EnvOrLegacy alongside the brand-derived name.
const (
	envSubjectToolchainReach        = brand.EnvPrefix + "_SUBJECT_TOOLCHAIN_REACHABILITY"
	nucleonEnvSubjectToolchainReach = "NUCLEON_SUBJECT_TOOLCHAIN_REACHABILITY"
	legacyEnvSubjectToolchainReach  = "TEGRON_SUBJECT_TOOLCHAIN_REACHABILITY"
)

// subjectToolchainReachOption resolves the M4 gate into an AssessOption, or nil when it is off —
// which is the default, and leaves every scan byte-identical to the pre-M4 behavior.
//
// OFF is the safe direction and the reason it exists: with the gate off, a stdlib advisory the scan
// could not adjudicate against the subject's toolchain is withheld and disclosed. Turning it on does
// not weaken that; it lets a scan that genuinely ran under the subject's toolchain report a verdict.
// The cost of turning it on is that findings appear on scans that are green today — which is the
// point, and why it is a deliberate opt-in for one release.
func subjectToolchainReachOption() pipeline.AssessOption {
	if !envEnabled(brand.EnvOrLegacy(envSubjectToolchainReach, nucleonEnvSubjectToolchainReach, legacyEnvSubjectToolchainReach)) {
		return nil
	}
	return pipeline.WithSubjectToolchainReachability(true)
}

// envEnabled reads a boolean env gate. Only the affirmative spellings enable it; anything else —
// including empty, "0", "false", or junk — leaves the gate off, because a gate that guards a
// verdict-behavior change must never be opened by a typo.
func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// resolve materializes the target (local dir in place, or a GitCheckout clone for a remote
// URL), selects the language-matched analyzer plugin + advisory corpus (acquireTarget),
// selects the StateStore, and assembles the neutral subject/codebase coordinates plus the
// Assess pipeline seam (WithPlugin). The codebase_inventory stage inventories the resolved
// BuildDir as a vendored_repro path, so no Checkout seam is injected — the acquisition
// already happened here.
// widen selects whether this run's work set is widened by an OSV query over the repository's real
// dependencies (the scan path) or is the compiled-in floor alone (cve-watch, which drives its own
// OSV query against the stored SBOM and must be left alone).
func (f *runFlags) resolve(ctx context.Context, widen bool) (*runConfig, error) {
	acq, err := acquireTarget(ctx, *f.target, *f.revision, *f.repo, *f.plugin, *f.houseCanaries)
	if err != nil {
		return nil, err
	}

	store, err := f.sf.resolve()
	if err != nil {
		acq.cleanup()
		return nil, err
	}

	assessOptions := []pipeline.AssessOption{pipeline.WithPlugin(acq.plugin)}
	if opt, err := f.advisoryCorpusOption(); err != nil {
		acq.cleanup()
		return nil, err
	} else if opt != nil {
		assessOptions = append(assessOptions, opt)
	}
	if opt := f.subjectToolchainOption(); opt != nil {
		assessOptions = append(assessOptions, opt)
	}
	if opt := subjectToolchainReachOption(); opt != nil {
		assessOptions = append(assessOptions, opt)
	}

	// Resolved AFTER advisoryCorpusOption, which is what decides the fact source the widener
	// consults when admitting an OSV-reported id.
	ws := floorWorkSet(acq.advisories)
	if widen {
		if ws, err = f.scanWorkSet(ctx, acq); err != nil {
			acq.cleanup()
			return nil, err
		}
	}

	return &runConfig{
		workSet: ws,
		store:   store,
		subject: trigger.Subject{Repo: acq.repo, Revision: *f.revision, ResolvedCommit: *f.commit},
		codebase: assessment.CodebaseRef{
			Repo:        acq.repo,
			Revision:    *f.revision,
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: acq.buildDir},
		},
		advisories:    ws.advisories,
		assessOptions: assessOptions,
		outDir:        *f.outDir,
		cleanup:       acq.cleanup,
	}, nil
}

// runPRInherit runs the `pr-inherit` mode: it diffs the PR head's resolved SBOM
// against the stored baseline and either inherits the baseline Report (fast path) or
// re-analyzes the affected advisory slice (slow path), then publishes through the
// env-driven sink selector.
//
// A baseline must already exist in the selected StateStore. Absent one, the trigger
// returns ErrNoBaseline and we exit non-zero with a clear "run a baseline first"
// message — a PR run has nothing to inherit until the default branch is scanned once.
//
// PR-head SBOM resolution: the SBOM is resolved locally from -target by resolving the
// codebase's whole dependency inventory (pipeline.ResolveCodebaseInventory, no analysis),
// then diffed against the stored baseline SBOM — deps unchanged → the inherit fast path;
// else the affected advisory slice is re-analyzed. No PR adapter and no GitHub API; and no
// OSV query unless the work-set widening is explicitly switched on, which osvWorkSetDefault
// means it is not. That is not the same as offline: resolving the inventory may contact the
// ecosystem's resolver, and re-analysis runs the Go reachability stage, which contacts
// vuln.go.dev (see the Rung 0 doc on package trigger).
// -target is the PR head tree already on disk (vendored_repro). Post-PLAN-100 the SBOM is
// INVENTORY-keyed, so "unchanged" means "no resolved dependency changed" — whether or not any
// advisory names it. A target with no dependencies (or whose inventory could not be resolved,
// yielding a declared-partial empty SBOM on both sides) takes the inherit fast path.
func runPRInherit(args []string) error {
	fs := flag.NewFlagSet("pr-inherit", flag.ContinueOnError)
	f := registerRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()

	cfg, err := f.resolve(ctx, true)
	if err != nil {
		return err
	}
	defer cfg.cleanup()

	prSBOM, sbomLimits, err := trigger.ResolveSBOM(ctx, trigger.ResolveSBOMRequest{
		Codebase:      cfg.codebase,
		AssessOptions: cfg.assessOptions,
	})
	if err != nil {
		return fmt.Errorf("resolve pr head sbom: %w", err)
	}

	res, err := trigger.RunPRInherit(ctx, cfg.store, trigger.PRInheritRequest{
		Subject:       cfg.subject,
		Codebase:      cfg.codebase,
		PRSBOM:        prSBOM,
		Advisories:    cfg.advisories,
		WorkSetLimits: cfg.workSet.partiality,
		// The head inventory's own partiality bounds the diff — disclosed on the fast
		// path so an inherit forced by an unresolvable head SBOM is not read as "clean".
		DiffLimits:    sbomLimits,
		AssessOptions: cfg.assessOptions,
	})
	if errors.Is(err, trigger.ErrNoBaseline) {
		return fmt.Errorf("no baseline in state at the selected StateStore — run `%s baseline` against the default branch first", brand.Name)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "%s pr-inherit complete\n", brand.Name)
	if res.Inherited {
		fmt.Fprintf(os.Stdout, "  path:       inherited baseline (dependency set unchanged)\n")
	} else {
		fmt.Fprintf(os.Stdout, "  path:       re-analyzed affected slice\n")
		fmt.Fprintf(os.Stdout, "  changed:    %s\n", strings.Join(res.ChangedPackages, ", "))
	}
	rescan := rescanFromEnv()
	if err := publishResult(ctx, cfg.outDir, res.Report, f.intelProvenance(cfg.workSet)); err != nil {
		return err
	}
	printSummary(cfg.outDir, res.Report)
	printRescanContext(rescan)
	postScan(ctx, cfg.store, cfg.subject, rescan)
	return nil
}

// runCVEWatch runs the scheduled `cve-watch` mode: it queries OSV.dev for advisories
// now affecting the stored SBOM, diffs them against the stored cursor, and either
// heartbeats (no new advisories — no scan Report to publish) or runs an earnest
// re-analysis scoped to the newly-relevant advisories and publishes its Report.
//
// The OSVClient is trigger.HTTPOSVClient (OSV.dev querybatch, Rung 0). At the shipped
// defaults this is the only call to api.osv.dev the tool makes: the scan path can query
// the same endpoint over the repository's live dependencies, but only when the work-set
// widening is explicitly switched on, and osvWorkSetDefault is false. It is not the only
// outbound call — every run mode also contacts vuln.go.dev and proxy.golang.org (see the
// Rung 0 doc on package trigger).
//
// A baseline must already exist; absent one the trigger
// returns ErrNoBaseline and we exit non-zero with a clear message.
func runCVEWatch(args []string) error {
	fs := flag.NewFlagSet("cve-watch", flag.ContinueOnError)
	f := registerRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()

	// widen=false: cve-watch's work set is the OSV query it makes below, against the STORED SBOM and
	// diffed against a cursor. That mechanism is the one the scan path now borrows; re-widening the
	// acquisition here would query OSV twice and change a mode whose behaviour is deliberately fixed.
	cfg, err := f.resolve(ctx, false)
	if err != nil {
		return err
	}
	defer cfg.cleanup()

	osv := &trigger.HTTPOSVClient{}

	res, err := trigger.RunCVEWatch(ctx, cfg.store, osv, trigger.CVEWatchRequest{
		Subject:       cfg.subject,
		Codebase:      cfg.codebase,
		AssessOptions: cfg.assessOptions,
	})
	if errors.Is(err, trigger.ErrNoBaseline) {
		return fmt.Errorf("no baseline in state at the selected StateStore — run `%s baseline` against the default branch first", brand.Name)
	}
	if err != nil {
		return err
	}

	rescan := rescanFromEnv()
	if res.Heartbeat {
		fmt.Fprintf(os.Stdout, "%s cve-watch heartbeat\n", brand.Name)
		fmt.Fprintf(os.Stdout, "  no new advisories affect the stored SBOM; cursor bumped, nothing republished\n")
		fmt.Fprintf(os.Stdout, "  cursor:     %s\n", res.Cursor)
		// A scheduled heartbeat still beacons: an uninstall must be detected even when
		// no advisory moved, since a dormant repo may only ever run on this cadence.
		postScan(ctx, cfg.store, cfg.subject, rescan)
		return nil
	}

	fmt.Fprintf(os.Stdout, "%s cve-watch — new advisories, earnest re-analysis\n", brand.Name)
	fmt.Fprintf(os.Stdout, "  new:        %s\n", strings.Join(res.NewAdvisories, ", "))
	fmt.Fprintf(os.Stdout, "  cursor:     %s\n", res.Cursor)
	if err := publishResult(ctx, cfg.outDir, res.Report, f.intelProvenance(cfg.workSet)); err != nil {
		return err
	}
	printSummary(cfg.outDir, res.Report)
	printRescanContext(rescan)
	postScan(ctx, cfg.store, cfg.subject, rescan)
	return nil
}
