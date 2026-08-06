// Package github provides the GitHub-specific ResultSink adapters, tiered by the
// permission each surface requires. It is the platform-specific counterpart to the
// portable sinks in package resultsink (Noop, Local): everything here knows about
// GitHub Actions environment variables, workflow commands, and (in later tiers)
// the GitHub REST API. Keeping it in its own sub-package isolates that surface so
// the resultsink core stays dependency-light and host-agnostic.
//
// # Tier model
//
// The free OSS communicate layer is split into three permission tiers, each defined by
// the least GitHub permission it can run under:
//
//   - Tier 0 — universal, ZERO permission, survives forked PRs. The GitHub job
//     summary ($GITHUB_STEP_SUMMARY) plus ::warning:: file annotations. Always
//     active inside GitHub Actions; needs no token. Implemented here (tier0_summary.go).
//   - Tier 1 — needs a WRITE token; auto-skips when the token is absent or
//     read-only (e.g. forked PRs). SARIF → code scanning, sticky PR comment,
//     pinned-Issue dashboard.
//   - Tier 2 — opt-in hosted URL (GitHub Pages); off by default.
//
// All tiers implement resultsink.ResultSink, so the CLI's sink selector (Item 5)
// composes the active set uniformly.
//
// # Why this file is a shared scaffold
//
// Tier detection is one decision made once per run from the process environment:
// "are we in GitHub Actions, and what may we do here?" Tiers 0/1/2 all read the
// same Env snapshot, so the detector lives here and Items 3/4 EXTEND it rather than
// re-deriving environment facts. See the "Extension seam" notes on Tier and Detect.
package github

import (
	"encoding/json"
	"os"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// Tier is the permission level a GitHub ResultSink surface requires. Tiers are
// ordered by privilege; a run is cleared for a surface only when its detected
// capability is at least that surface's Tier.
//
// Extension seam (Items 3/4): the enum is deliberately a small ordered set so a
// follow-on tier can be gated with a simple `caps.Allows(TierN)` check. Do not add
// surface-specific booleans here — add a Tier constant and an accessor on
// Capabilities (e.g. CanComment) so the selector stays a uniform comparison.
type Tier int

const (
	// Tier0 is the universal, zero-permission surface (job summary + annotations).
	// Always available inside GitHub Actions; never gated on a token.
	Tier0 Tier = iota
	// Tier1 is the write-token surface (SARIF upload, PR comment, Issue dashboard).
	// Gated on a usable write token; auto-skipped on forked-PR read-only tokens.
	Tier1
	// Tier2 is the opt-in hosted surface (GitHub Pages). Off unless explicitly
	// enabled; gated on both an opt-in flag and a usable token.
	Tier2
)

// GitHub Actions environment variables read by the detector. They are the stable
// public contract documented by GitHub Actions; centralized here so every tier
// references one definition.
const (
	// EnvActions is "true" when running inside a GitHub Actions runner.
	EnvActions = "GITHUB_ACTIONS"
	// EnvStepSummary is the path to the per-step Markdown summary file. Tier 0
	// appends GFM here. Present on every Actions runner (including forked PRs).
	EnvStepSummary = "GITHUB_STEP_SUMMARY"
	// EnvToken is the workflow token. Present but READ-ONLY on forked pull_request
	// runs, so presence alone does not imply write capability (see EnvEventName).
	EnvToken = "GITHUB_TOKEN"
	// EnvRepository is "owner/repo" — needed by Tier 1 REST calls (Items 3/4).
	EnvRepository = "GITHUB_REPOSITORY"
	// EnvEventName is the triggering event ("pull_request", "push", "schedule", …).
	// A forked-PR run is "pull_request" with a token that GitHub scoped read-only;
	// Tier 1 detection uses this plus the parsed event payload to refuse writes.
	EnvEventName = "GITHUB_EVENT_NAME"
	// EnvEventPath is the path to the JSON file holding the full webhook event
	// payload. For a pull_request event it carries pull_request.head.repo.full_name
	// and pull_request.base.repo.full_name; when head != base the PR comes from a
	// fork (a read-only GITHUB_TOKEN) and Tier 1 must auto-skip. It is the single
	// authoritative signal that distinguishes a same-repo PR from a forked one.
	EnvEventPath = "GITHUB_EVENT_PATH"
	// EnvServerURL is the GitHub server base (github.com or GHES). Tier 1/2 build
	// API/Pages URLs from it.
	EnvServerURL = "GITHUB_SERVER_URL"
	// EnvWorkspace is the checkout root. Tier 0 makes annotation file paths
	// repo-relative to it so the GitHub UI can anchor them to the right file.
	EnvWorkspace = "GITHUB_WORKSPACE"

	// EnvPagesOptIn is the opt-in switch for Tier 2 (GitHub Pages). Off by default
	// (empty/"false"); Item 4 reads it. Declared here so the env contract is in one
	// place. Not a standard Actions variable — an ferralon-assay input.
	EnvPagesOptIn = brand.EnvPrefix + "_PAGES"

	// EnvCodeScanning is the per-surface opt-OUT switch for the Tier 1 SARIF →
	// code-scanning upload. ENABLED by default; a run disables it only with an
	// explicit "false"/"0" (absent/empty → enabled, preserving auto-on for
	// direct-CLI and non-action runs). Not a standard Actions variable — an
	// ferralon-assay input.
	EnvCodeScanning = brand.EnvPrefix + "_CODE_SCANNING"
	// EnvPRComment is the per-surface opt-OUT switch for the Tier 1 sticky PR
	// comment. ENABLED by default; disabled only with an explicit "false"/"0"
	// (absent/empty → enabled). Not a standard Actions variable — an ferralon-assay input.
	EnvPRComment = brand.EnvPrefix + "_PR_COMMENT"
	// EnvIssue is the per-surface opt-OUT switch for the Tier 1 pinned-Issue
	// dashboard. ENABLED by default; disabled only with an explicit "false"/"0"
	// (absent/empty → enabled). Not a standard Actions variable — an ferralon-assay input.
	EnvIssue = brand.EnvPrefix + "_ISSUE"
)

// Env is an immutable snapshot of the GitHub Actions environment relevant to sink
// selection. Snapshotting once (via DetectEnv) keeps detection deterministic and
// makes tests trivial: construct an Env literal instead of mutating os.Environ.
//
// Extension seam (Items 3/4): add fields here for any new environment fact a tier
// needs (e.g. a head-repo-fork flag for accurate write detection). Populate them in
// DetectEnv and consume them in the Capabilities derivation — never call os.Getenv
// from inside a tier's Publish.
type Env struct {
	// InActions is true when GITHUB_ACTIONS=="true".
	InActions bool
	// StepSummaryPath is the GITHUB_STEP_SUMMARY file path ("" when unset).
	StepSummaryPath string
	// Token is the GITHUB_TOKEN value ("" when absent — the forked-PR / no-token case).
	Token string
	// Repository is GITHUB_REPOSITORY ("owner/repo").
	Repository string
	// EventName is GITHUB_EVENT_NAME (the triggering event).
	EventName string
	// ServerURL is GITHUB_SERVER_URL.
	ServerURL string
	// Workspace is GITHUB_WORKSPACE (checkout root for repo-relative annotation paths).
	Workspace string
	// PagesOptIn is true when the Tier 2 opt-in (EnvPagesOptIn) is enabled.
	PagesOptIn bool
	// CodeScanningEnabled is true when the SARIF → code-scanning surface is enabled
	// (the opt-OUT default: EnvCodeScanning absent or anything but "false"/"0").
	// AND-ed with CanWrite in Detect, so a toggle never overrides forked-PR safety.
	CodeScanningEnabled bool
	// PRCommentEnabled is true when the sticky PR-comment surface is enabled (the
	// opt-OUT default: EnvPRComment absent or anything but "false"/"0").
	// AND-ed with CanWrite (and PR context) in Detect.
	PRCommentEnabled bool
	// IssueEnabled is true when the pinned-Issue dashboard surface is enabled (the
	// opt-OUT default: EnvIssue absent or anything but "false"/"0").
	// AND-ed with CanWrite in Detect.
	IssueEnabled bool
	// HeadRepoFork is true when this run is a pull_request whose head repository
	// differs from the base repository — i.e. a PR from a fork, whose GITHUB_TOKEN
	// GitHub scopes read-only. It is parsed from the event payload at GITHUB_EVENT_PATH
	// by DetectEnv (the only os-touching site) so the capability derivation and every
	// Tier 1 sink consume a snapshot, never the live filesystem. False for pushes,
	// same-repo PRs, and any event without a parseable fork signal.
	HeadRepoFork bool
	// PRNumber is the pull-request number for a pull_request event (0 when absent or
	// not a PR run). Parsed from the event payload by DetectEnv; the sticky-comment
	// sink addresses .../issues/{PRNumber}/comments with it.
	PRNumber int
}

// DetectEnv snapshots the GitHub-relevant environment from the process. It is the
// single point that touches os.Getenv; everything downstream consumes the returned
// Env, so detection is pure and testable.
func DetectEnv() Env {
	env := Env{
		InActions:       truthy(os.Getenv(EnvActions)),
		StepSummaryPath: os.Getenv(EnvStepSummary),
		Token:           os.Getenv(EnvToken),
		Repository:      os.Getenv(EnvRepository),
		EventName:       os.Getenv(EnvEventName),
		ServerURL:       os.Getenv(EnvServerURL),
		Workspace:       os.Getenv(EnvWorkspace),
		PagesOptIn:      truthy(os.Getenv(EnvPagesOptIn)),

		CodeScanningEnabled: enabledUnlessDisabled(os.Getenv(EnvCodeScanning)),
		PRCommentEnabled:    enabledUnlessDisabled(os.Getenv(EnvPRComment)),
		IssueEnabled:        enabledUnlessDisabled(os.Getenv(EnvIssue)),
	}
	env.HeadRepoFork, env.PRNumber = parseEvent(env.EventName, os.Getenv(EnvEventPath))
	return env
}

// parseEvent reads the pull_request webhook payload at eventPath and returns the
// fork flag (head.repo.full_name != base.repo.full_name) and the PR number. It is
// the only filesystem read in detection and is called solely from DetectEnv, so the
// parsed facts then flow through the immutable Env snapshot. It returns (false, 0)
// for non-PR events, a missing/unreadable/unparseable payload, or a payload missing
// either repo full name — the safe defaults that pair with the token check to keep a
// fork read-only.
func parseEvent(eventName, eventPath string) (forked bool, prNumber int) {
	if !isPRevent(eventName) || eventPath == "" {
		return false, 0
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		return false, 0
	}
	var payload struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				Repo struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"head"`
			Base struct {
				Repo struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false, 0
	}
	num := payload.PullRequest.Number
	if num == 0 {
		num = payload.Number
	}
	head := payload.PullRequest.Head.Repo.FullName
	base := payload.PullRequest.Base.Repo.FullName
	if head == "" || base == "" {
		return false, num
	}
	return head != base, num
}

// isPRevent reports whether eventName addresses a pull request.
func isPRevent(eventName string) bool {
	return eventName == "pull_request" || eventName == "pull_request_target"
}

// Capabilities is the detected verdict on what this run may do, derived from an Env.
// It is the value the CLI sink selector (Item 5) consults to compose the active
// sinks: Tier 0 always; Tier 1 when CanWrite; Tier 2 when CanPages.
//
// Extension seam (Items 3/4): add an accessor per new surface (e.g. CanComment,
// CanIssue) computed in Detect, rather than re-deriving from Env at each call site.
// Keep the booleans here so callers ask a capability, not an environment.
type Capabilities struct {
	// MaxTier is the highest Tier this run is cleared for. Allows(t) is the uniform
	// gate the selector uses.
	MaxTier Tier
	// CanSummary is true when the Tier 0 job summary is writable (a step-summary path
	// exists). True on every Actions runner, including forked PRs.
	CanSummary bool
	// CanWrite is true when this run holds a write-capable token (Tier 1). It is the
	// seam Item 3 tightens: a token must be present AND the run must not be a forked
	// pull_request (whose token GitHub scopes read-only). The conservative default
	// here treats a token-bearing non-forked event as writable; Item 3 refines fork
	// detection (e.g. comparing head/base repos) without changing this field's meaning.
	CanWrite bool
	// CanSARIF is true when this run may upload SARIF to code scanning — it requires
	// the code-scanning surface to be enabled (the opt-OUT toggle EnvCodeScanning,
	// default on) AND write capability. The toggle is AND-ed with CanWrite, so turning
	// it on never overrides forked-PR safety: a forked PR (CanWrite=false) stays
	// SARIF-incapable regardless of the toggle. The SARIF sink gates on it.
	CanSARIF bool
	// CanComment is true when this run may create/update a pull-request comment — it
	// requires the PR-comment surface to be enabled (the opt-OUT toggle EnvPRComment,
	// default on), write capability, AND a PR context (an event that addresses a PR).
	// The toggle is AND-ed with CanWrite, so it never overrides forked-PR safety. The
	// sticky-comment sink gates on it so a push build (no PR to comment on) skips
	// cleanly rather than erroring. Computed in Detect; sinks ask the capability
	// rather than re-deriving the event shape.
	CanComment bool
	// CanIssue is true when this run may create/overwrite the pinned-issue dashboard —
	// it requires the Issue surface to be enabled (the opt-OUT toggle EnvIssue,
	// default on) AND write capability (issues are repo-scoped, not PR-scoped, so any
	// write-capable event qualifies). The toggle is AND-ed with CanWrite, so it never
	// overrides forked-PR safety. The pinned-issue sink gates on it.
	CanIssue bool
	// CanPages is true when Tier 2 is both opted in and write-capable (Item 4 reads
	// this; it never activates by default).
	CanPages bool
}

// Allows reports whether this run is cleared for tier t.
func (c Capabilities) Allows(t Tier) bool { return t <= c.MaxTier }

// Detect derives the run's Capabilities from an Env snapshot. This is the central
// policy; Items 3/4 extend it (refine CanWrite fork detection, set CanPages) rather
// than scattering env checks across sinks.
//
// Policy:
//   - Tier 0 is available whenever a step-summary path exists (every Actions runner).
//   - Tier 1 (CanWrite) requires a non-empty token on a non-forked event. Fork
//     detection is conservative here (refined by Item 3); a forked pull_request must
//     NOT be treated as writable — that is the forked-PR safety guarantee.
//   - Tier 2 (CanPages) requires both the opt-in and write capability.
func Detect(env Env) Capabilities {
	caps := Capabilities{
		MaxTier:    Tier0,
		CanSummary: env.StepSummaryPath != "",
	}

	// Tier 1: a usable write token. Presence is necessary but not sufficient — a
	// forked pull_request carries a read-only token. Item 3 sharpens isForkedPR with
	// head/base-repo comparison; the current heuristic keeps the forked-PR path safe
	// by erring toward read-only when the run looks like an external PR.
	caps.CanWrite = env.Token != "" && !isForkedPR(env)
	if caps.CanWrite {
		caps.MaxTier = Tier1
	}

	// Per-surface Tier 1 capabilities, derived once here so each sink asks a
	// capability rather than re-inspecting the event. Each is the per-surface opt-OUT
	// toggle AND-ed with the underlying capability — the toggle can DISABLE a surface
	// but never override forked-PR safety (CanWrite stays false on a fork regardless
	// of any toggle). SARIF and the pinned-issue dashboard need only write; a PR
	// comment additionally needs a PR to comment on.
	caps.CanSARIF = env.CodeScanningEnabled && caps.CanWrite
	caps.CanComment = env.PRCommentEnabled && caps.CanWrite && isPullRequestEvent(env)
	caps.CanIssue = env.IssueEnabled && caps.CanWrite

	// Tier 2: opt-in AND write-capable.
	caps.CanPages = env.PagesOptIn && caps.CanWrite
	if caps.CanPages {
		caps.MaxTier = Tier2
	}

	return caps
}

// isForkedPR reports whether the run is a forked pull_request — the case where
// GITHUB_TOKEN is read-only and Tier 1 surfaces MUST auto-skip. It reads the
// authoritative head-vs-base-repo comparison snapshotted into Env by DetectEnv
// (detectHeadRepoFork parses GITHUB_EVENT_PATH). This is the load-bearing half of
// forked-PR safety: a fork's read-only token is still a non-empty Token, so without
// this check CanWrite would wrongly clear Tier 1 to attempt an unauthorized write on
// a fork. The contract is that a forked PR returns true.
func isForkedPR(env Env) bool {
	return env.HeadRepoFork
}

// isPullRequestEvent reports whether the run is operating on a pull request, the
// precondition for the sticky-comment surface (there must be a PR to comment on). It
// additionally requires a resolved PR number so the comment sink has an address.
func isPullRequestEvent(env Env) bool {
	return isPRevent(env.EventName) && env.PRNumber > 0
}

// truthy interprets a GitHub-style boolean env var ("true"/"1" → true). Used for
// the opt-IN Pages switch, where absent/empty means OFF.
func truthy(v string) bool { return v == "true" || v == "1" }

// enabledUnlessDisabled interprets a per-surface opt-OUT toggle: ENABLED unless the
// value is an explicit "false"/"0". Absent/empty → enabled, preserving auto-on for
// the SARIF/PR-comment/Issue surfaces on direct-CLI and non-action runs.
func enabledUnlessDisabled(v string) bool { return v != "false" && v != "0" }
