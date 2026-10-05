package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
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
// rebranded fork's --help output and action.yml env mapping carry its own prefix (see
// brand.EnvPrefix). This command is the only place they are read; the library packages take the
// resolved values as explicit options.
const (
	// envAdvisoryCorpusDir keeps its _DIR name for compatibility; like -advisory-corpus it accepts a
	// corpus directory or a corpus bundle file (corpusSourceFor).
	envAdvisoryCorpusDir = brand.EnvPrefix + "_ADVISORY_CORPUS_DIR"
	// envAdvisoryCorpusRequired declares that this run EXPECTS a corpus — see
	// advisoryCorpusRequired for why the declaration has to come from somewhere OTHER than the
	// corpus path itself.
	envAdvisoryCorpusRequired = brand.EnvPrefix + "_ADVISORY_CORPUS_REQUIRED"
	// envAdvisoryCorpusPolicy declares the advisory policy the corpus was selected by — see
	// advisoryCorpusPolicy. Declaring one is what makes the corpus define the work set.
	envAdvisoryCorpusPolicy = brand.EnvPrefix + "_ADVISORY_CORPUS_POLICY"
	// envOSVWorkSet is the second channel for the OSV work-set widening (see osvWorkSetEnabled).
	// The widening is off by default, so this is normally an opt-IN; it also carries an explicit
	// off for an operator whose orchestrator would otherwise turn it on.
	envOSVWorkSet       = brand.EnvPrefix + "_OSV_WORK_SET"
	envSubjectGoVersion = brand.EnvPrefix + "_SUBJECT_GO_VERSION"
	envCIGoVersion      = brand.EnvPrefix + "_CI_GO_VERSION"
)

// envTrustObservedGo carries the action's `trust-observed-go` input: the caller's assertion that the
// Go installed when the Action started is the toolchain the SCANNED repository builds with. True in a
// same-job setup that ran actions/setup-go (or otherwise provisioned its build toolchain) ahead of
// the scan; false in a dedicated scan workflow, where the observed Go is the hosted runner image's
// and says nothing about the subject. Brand-derived for the same reason as
// envAdvisoryCorpusDir/envSubjectGoVersion/envCIGoVersion.
const envTrustObservedGo = brand.EnvPrefix + "_TRUST_OBSERVED_GO"

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
//     opt-out via ASSAY_CODE_SCANNING / ASSAY_PR_COMMENT / ASSAY_ISSUE), while
//     Pages stays opt-in. Every toggle is AND-ed with write capability inside Detect,
//     so on a forked PR (read-only token) all three are absent regardless of the
//     toggles — a forked PR composes only Tier 0 + Local, the forked-PR safety
//     guarantee. A push build has CanComment=false (no PR), so it gets SARIF + Issue
//     but no PR comment.
//   - Tier 2 (NewTier2Pages) is added only when caps.CanPages (ASSAY_PAGES opt-in
//     AND a write token).
//   - The Ferralon run-snapshot sink (runSnapshot, resolved by the caller from
//     FERRALON_RUNS_URL plus the canonical-ref pair) is appended when non-nil. It is the
//     only sink in the set that contacts Ferralon: it pushes the run's report to the backend
//     /runs endpoint so the console can render a live assessment. It is gated OUTSIDE
//     the selector (canonical ref + URL — selectRunSnapshotSink) and only reached inside the
//     InActions block, so a local / forked-PR run, and any run that assessed a ref other than
//     the repository's canonical one, never files a run.
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

// canonicalDeliveryRefs derives the two refs the delivery gate compares: the ref this run
// actually ANALYZED, and the CANONICAL ref of this repository — the one whose assessment the
// repository asked Ferralon Assay to carry.
//
// analyzeRef is the repository-owned .github/ferralon.yml `analyze.ref` AS ACTUALLY RESOLVED by
// acquireTarget. It is empty on every path where no redirect happened: no config file, a config
// naming no ref, or a remote-URL target (the config is read only from a local checked-out tree).
// refName is the TRIGGERING ref (GITHUB_REF_NAME) and defaultBranch the repository default
// (FERRALON_DEFAULT_BRANCH).
//
//   - No analyze.ref — the scan inventories the tree CI checked out, so the analyzed ref IS the
//     triggering ref, and the canonical ref is the repository's default branch. The comparison
//     the gate then makes is refName == defaultBranch: the pre-TEG-060 gate, unchanged, on
//     every input.
//   - analyze.ref resolved — the scan analyzed THAT ref (acquire.provenance records the same
//     pair on the Report's subject, so the delivered assessment and this decision agree by
//     construction), and that ref is by definition the canonical one, because the repository
//     itself designated it in a file it owns.
//
// Worth stating plainly, because it follows from that second case: the config is read from the
// tree CI checked out, so the canonical ref is whatever THIS run's checked-out ferralon.yml
// names. A branch carrying a modified ferralon.yml therefore designates — and delivers — its own
// choice of ref. That is the same trust boundary the analyze.ref redirect itself already sits on
// (a writer who can change that file can already change what is scanned), and narrowing it would
// mean reading the default branch's copy of the config, which is a change to what is READ, not to
// delivery selection. Out of scope here; recorded so it is a decision and not an oversight.
func canonicalDeliveryRefs(analyzeRef, refName, defaultBranch string) (analyzed, canonical string) {
	if analyzeRef != "" {
		return analyzeRef, analyzeRef
	}
	return refName, defaultBranch
}

// selectRunSnapshotSink decides whether this run pushes a run snapshot to the backend
// /runs endpoint, returning the sink or nil. It is the load-bearing gate:
// the push fires ONLY when (a) a run-snapshot URL resolved non-empty (resolveEndpoint in
// link.go — the caller opted in via link-to-console AND the release carries or overrides a
// runs endpoint; empty on the OSS/dogfood path and on an explicit opt-out) AND (b) THIS RUN
// ANALYZED THE REPOSITORY'S CANONICAL REF (analyzedRef == canonicalRef, both non-empty), the
// pair canonicalDeliveryRefs derives from the run's environment.
//
// The question is "did this run assess the ref the repository asked to see", NOT "was this run
// TRIGGERED on the default branch". For a repository with no analyze.ref the two questions have
// the same answer on every run — analyzed ref is the triggering ref, canonical ref is the
// default branch — so this is a STRICT SUPERSET of the pre-TEG-060 gate: identical delivery for
// a plain repository (TestPlainRepoDeliveryEquivalence pins that against a verbatim transcript
// of the old condition), and it only ever ADDS delivery, for an analyze.ref repository whose
// designated ref was assessed by a run triggered somewhere else. A run that assessed some other
// ref returns nil and stays stateless — it never files a report_run, mirroring how the
// StateStore -repo persistence is default-branch-gated by the caller.
// It is pure (env is read by the caller) so the gate is unit-testable.
func selectRunSnapshotSink(url, analyzedRef, canonicalRef string, token ferralon.TokenSource) resultsink.ResultSink {
	if url == "" {
		return nil
	}
	if analyzedRef == "" || canonicalRef == "" || analyzedRef != canonicalRef {
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
//
// analyzeRef is the resolved .github/ferralon.yml analyze.ref (acquired.analyzeRef; empty on the
// default path). It reaches the delivery gate IN PROCESS — the redirect is decided by acquireTarget
// in this same binary, so nothing about the analyzed ref needs to travel through the environment.
// It is the ONLY thing it is used for here: it selects the delivery channel and changes neither
// what was analyzed nor what is published on any other sink.
func publishResult(ctx context.Context, outDir string, rep *report.Report, intel report.IntelProvenance, analyzeRef string) error {
	rep.Provenance.Intel = &intel
	res, err := buildResult(rep)
	if err != nil {
		return err
	}
	runsURL := resolveEndpoint(linkedToConsole(), os.Getenv(envRunsURL), bakedRunsURL)
	analyzedRef, canonicalRef := canonicalDeliveryRefs(analyzeRef, os.Getenv(envRefName), os.Getenv(envDefaultBranch))
	runSnapshot := selectRunSnapshotSink(runsURL, analyzedRef, canonicalRef, resolveOIDCToken)
	env := github.DetectEnv(surfaceToggles())
	return publishAll(ctx, selectSinks(env, outDir, runSnapshot), res, env.StepSummaryPath, os.Stderr)
}

// Env var names for the per-surface GitHub output toggles, mapped from the action's inputs in
// action.yml. Pages is an opt-IN; the other three are opt-OUT (on unless explicitly "false"/"0").
const (
	envPages        = brand.EnvPrefix + "_PAGES"
	envCodeScanning = brand.EnvPrefix + "_CODE_SCANNING"
	envPRComment    = brand.EnvPrefix + "_PR_COMMENT"
	envIssue        = brand.EnvPrefix + "_ISSUE"
)

// surfaceToggles reads the output-surface toggles for github.DetectEnv.
func surfaceToggles() github.Toggles {
	return github.Toggles{
		Pages:               github.OptIn(os.Getenv(envPages)),
		DisableCodeScanning: github.OptedOut(os.Getenv(envCodeScanning)),
		DisablePRComment:    github.OptedOut(os.Getenv(envPRComment)),
		DisableIssue:        github.OptedOut(os.Getenv(envIssue)),
	}
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
// earlier one fails, so a Tier-1 surface outage never suppresses the always-on Local
// + Tier-0 deposit, and returns the joined errors of the load-bearing sinks (nil when
// they all succeeded).
//
// A best-effort surface (bestEffortSurface) never decides the result. Its failure is
// reported as a ::warning:: on warn and a note appended to the job summary at
// summaryPath (when set), and the run carries on: by then Local and Tier 0 have
// deposited the scan result, and a repository that cannot accept a comment or a
// dashboard Issue (Issues disabled, a token without the permission) says nothing about
// that result.
func publishAll(ctx context.Context, sinks []resultsink.ResultSink, res resultsink.Result, summaryPath string, warn io.Writer) error {
	var errs []error
	var notes []string
	for _, s := range sinks {
		err := s.Publish(ctx, res)
		if err == nil {
			continue
		}
		sf, ok := bestEffortSurface(s)
		if !ok {
			errs = append(errs, err)
			continue
		}
		note := surfaceFailureNote(sf, err)
		notes = append(notes, note)
		fmt.Fprintf(warn, "::warning title=%s::%s\n", brand.Name, escapeWorkflowData(note+" ("+err.Error()+")"))
	}
	if len(notes) > 0 && summaryPath != "" {
		if err := appendSurfaceFailures(summaryPath, notes); err != nil {
			fmt.Fprintf(warn, "%s: %v\n", brand.Name, err)
		}
	}
	return errors.Join(errs...)
}

// surface names a best-effort result surface for a failure report: what it is called,
// the likely reason GitHub refuses it, and the Action input that turns it off.
type surface struct {
	name    string
	refusal string
	input   string
}

// bestEffortSurface reports whether a failure of s is best-effort, and which surface it
// is. The best-effort set is exactly the two Tier 1 surfaces that write to the
// repository through the GitHub REST API: the sticky PR comment and the dashboard
// Issue. They are views of a result already deposited elsewhere, and whether GitHub
// accepts them depends on repository settings and token scope, not on the scan.
//
// Every other sink stays load-bearing. Local writes the output directory every later
// workflow step reads; Tier 0 is the zero-permission summary that always lands; the
// SARIF and Pages sinks write local files a workflow step uploads, so a failure there is
// the runner's disk, not GitHub's say-so. The run-snapshot push is fail-open on its own.
func bestEffortSurface(s resultsink.ResultSink) (surface, bool) {
	switch s.(type) {
	case *github.Tier1PRComment:
		return surface{
			name:    "pull request comment",
			refusal: "The workflow token may lack `pull-requests: write`",
			input:   "pr-comment",
		}, true
	case *github.Tier1Issue:
		return surface{
			name:    "dashboard Issue",
			refusal: "Issues may be disabled on this repository, or the workflow token may lack `issues: write`",
			input:   "issue",
		}, true
	}
	return surface{}, false
}

// surfaceFailureNote is the one-line, user-facing account of a best-effort surface that
// could not be written, with the remedy when GitHub refused the write outright.
func surfaceFailureNote(sf surface, err error) string {
	var se *github.StatusError
	if !errors.As(err, &se) {
		return fmt.Sprintf("The %s could not be updated; the next run tries again.", sf.name)
	}
	if se.Status >= 400 && se.Status < 500 {
		return fmt.Sprintf("GitHub refused the %s write (HTTP %d). %s; set the Action input `%s: false` to turn this surface off.",
			sf.name, se.Status, sf.refusal, sf.input)
	}
	return fmt.Sprintf("GitHub could not take the %s write (HTTP %d); the next run tries again.", sf.name, se.Status)
}

// appendSurfaceFailures appends the best-effort surface failures to the job summary,
// under the scan headline Tier 0 already wrote there.
func appendSurfaceFailures(summaryPath string, notes []string) error {
	var b strings.Builder
	b.WriteString("\n### Surfaces not updated\n\n")
	b.WriteString("The scan finished and its result above stands. These GitHub surfaces could not be written:\n\n")
	for _, n := range notes {
		b.WriteString("- " + n + "\n")
	}
	f, err := os.OpenFile(summaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open step summary: %w", err)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return fmt.Errorf("write step summary: %w", err)
	}
	return f.Close()
}

// escapeWorkflowData escapes a GitHub Actions workflow-command message.
func escapeWorkflowData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
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

	// analyzeRef is the resolved .github/ferralon.yml analyze.ref (empty on the default path),
	// carried from acquireTarget so publishResult can gate delivery on the canonical ref.
	analyzeRef string
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
	corpusPolicy     *string
	requireCorpus    *bool
	houseCanaries    *bool
	osvWorkSet       *bool
	subjectGo        *string
	resolvedFacts    string // FactSource* — set by advisoryCorpusOption
	resolvedCorpus   pipeline.CorpusInfo
	resolvedCorpusOK bool
	resolvedSource   pipeline.AdvisorySource // the chain the pass resolves facts through
	corpusReader     pipeline.AdvisorySource // the configured corpus's own reader; nil when none
	resolvedPolicy   string                  // the declared advisory policy id; "" when none
	repoWindow       repoconfig.Window       // the scanned tree's scan.window; set from acquireTarget
	resolvedWindow   *report.ScanWindow      // the scan window the declared policy stands for; nil when none
}

// osvWorkSetDefault is whether a scan-path run (baseline / pr-inherit) widens its work set by
// querying OSV.dev, when neither -osv-work-set nor ASSAY_OSV_WORK_SET says otherwise.
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
		plugin:         fs.String("plugin-go", "", "explicit path to the analyzer binary for the detected language (assay-plugin-<lang>; default: PATH lookup)"),
		advisoryCorpus: fs.String("advisory-corpus", "", "path to an advisory corpus consulted BEFORE the built-in advisory table: a directory (manifest.json + digest-pinned per-advisory JSON) or a compressed corpus bundle file (<policy>.jsonl.gz). Without -advisory-corpus-policy it supplies facts only and does not change what is scanned; overrides "+envAdvisoryCorpusDir),
		// corpusPolicy declares which advisory policy the corpus was selected by. Declaring one makes
		// the corpus define the work set (selectWorkSet); without it the corpus is fact scope only.
		corpusPolicy: fs.String("advisory-corpus-policy", "", "the advisory policy -advisory-corpus was selected by (e.g. published-7d, full). When set, the work set is the built-in floor plus every advisory in the corpus whose affected package is one of the repository's dependencies, and no OSV.dev query is made; requires -advisory-corpus; overrides "+envAdvisoryCorpusPolicy),
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
		osvWorkSet: fs.Bool("osv-work-set", osvWorkSetDefault, "query OSV.dev over the repository's dependencies to widen the advisory work set beyond the built-in language set, unless -advisory-corpus-policy defines the work set (off by default: it sends this repository's dependency coordinates to a third party); overrides "+envOSVWorkSet),
		subjectGo:  fs.String("subject-go-version", "", "the Go toolchain version the SCANNED repository builds with, e.g. go1.21.3 — an exact statement, not the scanner's own toolchain; overrides "+envSubjectGoVersion+" (default: resolved from the CI runner, then the target's go.mod directives)"),
	}
}

// osvWorkSetEnabled reports whether this run widens its work set by querying OSV.dev over the
// repository's real dependencies. It is OFF unless explicitly switched on (osvWorkSetDefault).
//
// PRECEDENCE. The flag wins over the env var, and the Visit is what makes that true in BOTH
// directions: without it an unset flag is indistinguishable from one explicitly set to the default,
// so -osv-work-set=false could not override ASSAY_OSV_WORK_SET=1. Asking the FlagSet which flags
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
	raw := os.Getenv(envOSVWorkSet)
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
// language floor, widened with the ids of the declared advisory policy that match the repository's
// own dependencies when a policy is declared, or otherwise OPTIONALLY with the advisories OSV.dev
// reports against those dependencies (selectWorkSet). The OSV widening is off unless it is
// explicitly switched on (osvWorkSetDefault) and never runs when the policy defines the work set, so
// by default this makes no network call.
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
	ws := selectWorkSet(ctx, acq, f.corpusReader, f.resolvedSource, f.resolvedPolicy, enabled, &trigger.HTTPOSVClient{})
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

// advisoryCorpusOption resolves the optional corpus AssessOption for a run, realizing the
// flag > env precedence (decisions.md #3): the -advisory-corpus flag wins; absent it, the
// envAdvisoryCorpusDir env var (the orchestrator's channel) is consulted; absent both it returns
// (nil, nil) — the built-in AdvisoryTable default, unchanged. This is the CLI half of the
// system-wide "both flag + env, flag wins" surface.
//
// THE CORPUS SUPPLEMENTS THE TABLE, IT DOES NOT REPLACE IT. This used to install the corpus as THE
// source, which meant every id the corpus did not carry resolved to zero facts and failed open.
// Measured against the 2026-07-23 published corpus, that emptied the ENTIRE 16-id scan work set. The
// source is now a chain — corpus first, built-in table behind it — so a corpus can only ever add
// facts (pipeline.NewChainSource; first hit wins, no merging across sources).
//
// The resolved path is either a corpus directory or a corpus bundle file (corpusSourceFor); both
// readers carry the same Validate/Describe contract, so everything below is shape-agnostic.
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
	f.corpusReader = nil
	f.resolvedPolicy = ""
	f.resolvedWindow = nil

	required, err := f.advisoryCorpusRequired()
	if err != nil {
		return nil, err
	}
	policy, err := f.advisoryCorpusPolicy()
	if err != nil {
		return nil, err
	}
	if err := f.recordScanWindow(policy); err != nil {
		return nil, err
	}

	dir := *f.advisoryCorpus
	if dir == "" {
		dir = os.Getenv(envAdvisoryCorpusDir)
	}
	if dir == "" && policy != "" {
		return nil, fmt.Errorf("advisory corpus policy %q is declared (-advisory-corpus-policy / %s) but no corpus path resolved: a policy names the advisories of a corpus, so it needs -advisory-corpus or %s",
			policy, envAdvisoryCorpusPolicy, envAdvisoryCorpusDir)
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

	src := corpusSourceFor(dir)
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
	f.corpusReader = src
	f.resolvedPolicy = policy
	return pipeline.WithAdvisorySource(chain), nil
}

// corpusSourceFor picks the reader for a resolved -advisory-corpus path. The path names one of two
// on-disk corpus shapes, and the shape is told apart by what is on disk rather than by a second flag:
//
//   - a DIRECTORY is a corpus tree (manifest.json + digest-pinned per-advisory JSON) →
//     pipeline.NewArtifactSource;
//   - a REGULAR FILE is a compressed corpus bundle (<policy>.jsonl.gz, one gzip stream of JSONL
//     records) → pipeline.NewBundleSource.
//
// A path that does not exist is routed by name: a ".gz" suffix is plainly a bundle, and anything
// else stays on the directory reader, whose Validate error explains a missing tree. Either way
// the caller's preflight Validate hard-fails it — routing never decides whether a broken corpus is
// loud, only which reader explains why.
//
// Anything else that exists (a socket, a device) also goes to the directory reader, which rejects
// it. Nothing here opens or reads the corpus; both constructors are free, and the one-time load
// happens in Validate.
func corpusSourceFor(path string) pipeline.AdvisorySource {
	fi, err := os.Stat(path)
	switch {
	case err == nil && fi.Mode().IsRegular():
		return pipeline.NewBundleSource(path)
	case err != nil && strings.HasSuffix(path, ".gz"):
		return pipeline.NewBundleSource(path)
	default:
		return pipeline.NewArtifactSource(path)
	}
}

// corpusPolicyPattern is the shape of an advisory policy id — the same check action.yml and
// scripts/fetch-corpus-bundle.sh apply to the advisory-corpus-policy input.
var corpusPolicyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// advisoryCorpusPolicy returns the advisory policy this run declares its corpus was selected by, or
// "" when none is declared. The -advisory-corpus-policy flag wins; absent it, envAdvisoryCorpusPolicy
// is consulted.
//
// The declaration is what makes the corpus define the work set. A corpus with no declared policy —
// a whole-corpus fetch, or a bundle handed over with no policy named — stays a fact source only, so
// a run's work set never changes because of what shape of corpus happened to be on disk.
//
// A malformed id is an ERROR, never ignored: silently dropping it would quietly turn a policy run
// back into a fact-scope run.
func (f *runFlags) advisoryCorpusPolicy() (string, error) {
	policy := *f.corpusPolicy
	if policy == "" {
		policy = os.Getenv(envAdvisoryCorpusPolicy)
	}
	if policy == "" {
		return "", nil
	}
	if !corpusPolicyPattern.MatchString(policy) {
		return "", fmt.Errorf("advisory corpus policy %q is not a policy id (lowercase letters, digits, '-')", policy)
	}
	return policy, nil
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
	raw := os.Getenv(envAdvisoryCorpusRequired)
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
// resolved them through (f). The two are deliberately separate — even when a declared policy makes
// the corpus choose the work set, the set is the corpus advisories that match the repository, not
// the corpus, and conflating them is what let "72 records" read as "72 advisories evaluated".
func (f *runFlags) intelProvenance(ws workSet) report.IntelProvenance {
	p := report.IntelProvenance{
		WorkSetSource: ws.source,
		WorkSetSize:   len(ws.advisories),
		FactSource:    f.resolvedFacts,
	}
	if f.resolvedCorpusOK {
		p.CorpusDigest = f.resolvedCorpus.Digest
		p.CorpusRecords = f.resolvedCorpus.Records
		if m := f.resolvedCorpus.Manifest; m != (pipeline.ManifestProvenance{}) {
			p.CorpusManifest = &report.CorpusManifestProvenance{
				GeneratedAt:          m.GeneratedAt,
				Generator:            m.Generator,
				PolicyID:             m.PolicyID,
				PolicyQuery:          m.PolicyQuery,
				SourceCorpusDigest:   m.SourceCorpusDigest,
				SelectionIndexDigest: m.SelectionIndexDigest,
			}
		}
	}
	p.CorpusPolicy = f.resolvedPolicy
	p.ScanWindow = f.resolvedWindow
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
// pipeline rather than failing the scan.
//
// The observation's TRUST is env-only for the same reason and read from the same channel as the
// measurement it qualifies (envTrustObservedGo, the Action's trust-observed-go input). It fails closed exactly
// like FERRALON_LINK_TO_CONSOLE: anything but an explicit true leaves the observation out of
// resolution, so a typo degrades to the go.mod floors rather than to a stronger claim than the
// operator asserted.
func (f *runFlags) subjectToolchainOption() pipeline.AssessOption {
	declared := *f.subjectGo
	if declared == "" {
		declared = os.Getenv(envSubjectGoVersion)
	}
	observed := os.Getenv(envCIGoVersion)
	if declared == "" && observed == "" {
		return nil
	}
	return pipeline.WithSubjectToolchain(declared, observed, trustObservedGo())
}

// trustObservedGo reports whether the observed runner toolchain may be treated as a statement about
// the subject. Fails closed: any value that is not an explicit true reads as untrusted.
func trustObservedGo() bool {
	trusted, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(envTrustObservedGo)))
	return err == nil && trusted
}

// envSubjectToolchainReach is the release gate on running the Go reachability analysis under the
// SUBJECT's toolchain rather than the scanner's. It is env-only, no flag, because it is an operator's
// rollout switch for one release, not a per-scan knob, and the Action input is its real surface —
// action.yml exports it (see subject-toolchain-reachability).
const envSubjectToolchainReach = brand.EnvPrefix + "_SUBJECT_TOOLCHAIN_REACHABILITY"

// subjectToolchainReachOption resolves the M4 gate into an AssessOption, or nil when it is off —
// which is the default, and leaves every scan byte-identical to the pre-M4 behavior.
//
// OFF is the safe direction and the reason it exists: with the gate off, a stdlib advisory the scan
// could not adjudicate against the subject's toolchain is withheld and disclosed. Turning it on does
// not weaken that; it lets a scan that genuinely ran under the subject's toolchain report a verdict.
// The cost of turning it on is that findings appear on scans that are green today — which is the
// point, and why it is a deliberate opt-in for one release.
func subjectToolchainReachOption() pipeline.AssessOption {
	if !envEnabled(os.Getenv(envSubjectToolchainReach)) {
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

	f.repoWindow = acq.window
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

	revision, commit := acq.provenance(*f.revision, *f.commit)
	return &runConfig{
		workSet: ws,
		store:   store,
		subject: trigger.Subject{Repo: acq.repo, Revision: revision, ResolvedCommit: commit},
		codebase: assessment.CodebaseRef{
			Repo:        acq.repo,
			Revision:    revision,
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: acq.buildDir},
		},
		advisories:    ws.advisories,
		assessOptions: assessOptions,
		outDir:        *f.outDir,
		cleanup:       acq.cleanup,
		analyzeRef:    acq.analyzeRef,
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
	if err := publishResult(ctx, cfg.outDir, res.Report, f.intelProvenance(cfg.workSet), cfg.analyzeRef); err != nil {
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
	if err := publishResult(ctx, cfg.outDir, res.Report, f.intelProvenance(cfg.workSet), cfg.analyzeRef); err != nil {
		return err
	}
	printSummary(cfg.outDir, res.Report)
	printRescanContext(rescan)
	postScan(ctx, cfg.store, cfg.subject, rescan)
	return nil
}
