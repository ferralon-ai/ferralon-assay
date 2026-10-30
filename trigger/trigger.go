package trigger

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// Subject identifies the codebase a run targets, in neutral coordinates (no account
// or tenant identity). It is copied verbatim into Report.Subject.
type Subject struct {
	Repo           string
	Revision       string
	ResolvedCommit string
}

// BaselineRequest configures a full S1–S6 baseline run: every advisory in Advisories
// is assessed against the codebase identified by Subject + Codebase, the results are
// assembled into one canonical Report, and the Report (with SBOM + cursor) is stored.
type BaselineRequest struct {
	// Subject is the neutral identity of the scanned codebase, recorded on the Report.
	Subject Subject
	// Codebase tells the pipeline how to acquire the codebase (clone / vendored repro).
	Codebase assessment.CodebaseRef
	// Advisories is the corpus of vulnerabilities to evaluate this pass. Each is run
	// through S1–S6 and contributes one finding to the Report.
	Advisories []assessment.VulnRef
	// WorkSetLimits discloses what the CALLER could not put into Advisories — the advisory
	// ids it could not determine or could not resolve facts for. It is the only limit the
	// pipeline cannot observe for itself: every other PartialityNote is derived from a stage
	// that ran, whereas this one is about analysis that never started, and a Report that
	// omitted it would be indistinguishable from one whose work set was complete.
	//
	// Disclosure only (inv.5). No finding, verdict or count depends on it.
	WorkSetLimits []report.PartialityNote
	// AnalyzerVersion is stamped into provenance; "" uses the AnalyzerVersion default.
	AnalyzerVersion string
	// Cursor is the advisory-corpus position this scan evaluated against, written into
	// provenance and the stored cursor. CVE-watch later diffs OSV.dev results against it.
	Cursor string
	// AssessOptions are the pipeline seams (WithPlugin / WithCheckout) the Assess
	// stages run with. Empty = the hermetic stub path.
	AssessOptions []pipeline.AssessOption
	// Signals is the EPSS/KEV signals file the run was given; nil for none, in which case no
	// finding carries a Priority. Ranking context only: it is applied after every verdict is final.
	// A caller outside this module sets it with signals.Feed. The Report the run builds records
	// the file's verified digest as Provenance.Intel.SignalsDigest; with none it records nothing.
	// The Report it returns is the committed one: after a conflicting write that is
	// statestore.Merge's, which may name no file, or the other run's.
	Signals *intel.Signals
	// Bands is the OPTIONAL scheduler-only prioritization hint: advisory id → Band. It is
	// read ONLY by the admission gate (admitAdvisories), above S1, to decide whether/when a
	// case is admitted this pass. It is dropped before an Assessment is constructed and NEVER
	// reaches any pipeline/verdict struct (inv.5). A nil map ⇒ every case BandUnknown ⇒ all
	// admitted (byte-identical to the pre-gate behavior). An absent band never drops a case.
	Bands map[string]Band
	// Analysis bounds the inventory and the per-advisory assessments. When it is done, the
	// advisories not yet assessed get scan_cut_short rows and the run still writes its Report
	// under ctx. Nil means ctx.
	Analysis context.Context
	// DependencyFetch, when set, computes the dependency-fetch record the run writes from the
	// stored one, after every assessment and before the write. Nil carries the stored record.
	DependencyFetch DependencyFetchUpdate
}

// DependencyFetchUpdate computes the dependency-fetch record a writing run leaves in state from
// the stored record (nil when there is none) and what the run did. It must not modify prior.
type DependencyFetchUpdate func(prior *statestore.DepFetch, run DependencyFetchRun) *statestore.DepFetch

// DependencyFetchRun is what a writing run did, as a DependencyFetchUpdate sees it.
type DependencyFetchRun struct {
	// Baseline is set for a baseline run and clear for a cve-watch earnest run.
	Baseline bool
	// Held reports that a cve-watch earnest run kept the stored cursor. Always false for a
	// baseline, which has no cursor to hold.
	Held bool
	// Assessed lists the advisories whose assessment this run completed, sorted by ID: neither
	// cut short nor failed. Each carries the aliases its advisory record names, so a caller can
	// match an advisory a different run knew by another ID.
	Assessed []report.Advisory
}

// RunBaseline runs the full S1–S6 pipeline for every advisory in the request, builds
// one canonical report.Report, and persists it to the StateStore under the FF-only
// CAS. It returns the committed Report.
//
// Storage protocol (statestore): Read first to capture the CAS token, then Write the
// fresh full-scan Report. A baseline REPLACES prior state (a full scan is the complete
// current evaluation, not an accumulation); the StateStore merge unions only across
// concurrent racers. On a fresh repo Read returns ErrNotFound and the Write creates
// the ref.
//
// A baseline stopped before its dependency inventory resolved keeps the stored SBOM: replacing it
// with an empty one would leave CVE-watch nothing to query until the next baseline finishes.
func RunBaseline(ctx context.Context, store statestore.StateStore, req BaselineRequest) (*report.Report, error) {
	rep, assessed, err := baselineReport(ctx, req, func() (report.SBOM, error) {
		prior, err := readForUpdate(ctx, store)
		if err != nil {
			return report.SBOM{}, err
		}
		return prior.SBOM, nil
	})
	if err != nil {
		return nil, err
	}

	next, err := readForUpdate(ctx, store)
	if err != nil {
		return nil, err
	}
	next.Report = rep
	next.SBOM = rep.SBOM
	next.Cursor = req.Cursor
	if req.DependencyFetch != nil {
		next.DepFetch = req.DependencyFetch(next.DepFetch, DependencyFetchRun{Baseline: true, Assessed: assessed})
	}

	committed, err := store.Write(ctx, next)
	if err != nil {
		return nil, fmt.Errorf("trigger: baseline write: %w", err)
	}
	return committed.Report, nil
}

// buildBaselineReport runs S1–S6 per advisory and assembles the Report. It does not
// touch the StateStore — the offline pipeline test exercises it directly.
func buildBaselineReport(ctx context.Context, req BaselineRequest) (*report.Report, error) {
	rep, _, err := baselineReport(ctx, req, nil)
	return rep, err
}

// baselineReport is buildBaselineReport with priorSBOM, which reads the stored SBOM a baseline
// stopped before its inventory resolved carries forward. Nil carries nothing forward. It also
// returns the advisories whose assessment completed, sorted by ID.
func baselineReport(ctx context.Context, req BaselineRequest, priorSBOM func() (report.SBOM, error)) (*report.Report, []report.Advisory, error) {
	analyzer := req.AnalyzerVersion
	if analyzer == "" {
		analyzer = AnalyzerVersion
	}

	b := report.NewBuilder(report.Subject{
		Repo:           req.Subject.Repo,
		Revision:       req.Subject.Revision,
		ResolvedCommit: req.Subject.ResolvedCommit,
	})

	// Admission gate (above S1): the scheduler consults each advisory's band and admits,
	// defers, or skips it BEFORE any Assessment is constructed. Band is read here and only
	// here; the admitted slice is plain VulnRefs with band stripped, so band never crosses
	// the S1 seam into a pipeline/verdict struct (inv.5). Fail-open: an absent band admits.
	admitted := admitAdvisories(scheduleFor(req.Advisories, req.Bands))

	// Declared BEFORE any finding, so a pass whose work set could not be fully determined
	// discloses that even if it goes on to produce zero findings — the case the note exists for.
	b.AddPartiality(req.WorkSetLimits...)

	// Whole-graph SBOM (§4.1, PLAN-100): resolve the codebase's dependency inventory ONCE,
	// independent of the advisory work set, and project it to the report SBOM. A dependency reaches
	// the SBOM whether or not any admitted advisory names it — the property §4.1's closing sentence
	// requires and the advisory-keyed producer denied. An inventory that could not be resolved is
	// DECLARED as a scan-level partiality note (C3), never a silently short SBOM that would feed a
	// later CVE-watch a shrunken query set. Coordinate-specific advisory resolution is RETAINED
	// unchanged in the loop below (advisoryFromArtifacts still serves the finding path — §4.1 / C5).
	analysis := analysisOr(req.Analysis, ctx)
	inv, invLanguage, err := inventoryWithin(analysis, req.Codebase, req.AssessOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("trigger: resolve codebase inventory: %w", err)
	}
	sbom, invNotes := sbomFromInventory(inv, ecosystemFor(invLanguage))
	if inventoryCutShort(invNotes) && priorSBOM != nil {
		prior, err := priorSBOM()
		if err != nil {
			return nil, nil, fmt.Errorf("trigger: read the stored SBOM: %w", err)
		}
		if len(prior.Packages) > 0 {
			sbom = prior
			b.AddPartiality(priorSBOMNote)
		}
	}
	b.AddPackages(sbom.Packages...)
	b.SetRelationships(sbom.Relationships)
	b.AddPartiality(invNotes...)
	mods := goModulesOf(sbom, invNotes)

	cut := 0
	var assessed []report.Advisory
	for _, adv := range admitted.Admitted {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, stopped, err := assessWithin(analysis, areq, req.AssessOptions...)
		if stopped {
			b.AddFinding(cutShortFinding(adv))
			cut++
			continue
		}
		if err != nil {
			// One advisory's analysis failing must not abort the scan: a run with no Report
			// renders downstream as a run with no findings. The advisories that resolved keep
			// their verdicts, and the one that did not gets an undetermined row.
			b.AddFinding(assessFailureFinding(adv, err))
			b.AddPartiality(assessFailureNote(adv, err))
			continue
		}
		// Coordinate-specific advisory resolution, RETAINED unchanged (§4.1 / C5): advisoryFromArtifacts
		// still resolves the advisory's own package for the finding, but it no longer DEFINES the SBOM —
		// the whole-graph inventory above does.
		advisory, pkg := advisoryFromArtifacts(st, assessmentID, areq, sbom.Packages)
		// A toolchain advisory the scan could not adjudicate is a first-class `undetermined`
		// row, plus the scan-level limit that explains it. The report has carried such rows
		// since v2; v1 withheld the row entirely, having no cell for "the advisory applies and
		// we established nothing". The row is what makes the omission legible at the count.
		f := withInventoryLimits(findingInBuild(st, assessmentID, advisory, pkg, mods), invNotes)
		b.AddFinding(f)
		b.WithLibraryEntrypoints(libraryEntrypoints(st, assessmentID)...)
		if note, ok := limitNoteFor(f); ok {
			b.AddPartiality(note)
		}
		b.AddPartiality(partialityNotes(st, assessmentID)...)
		assessed = append(assessed, advisory)
	}
	if cut > 0 {
		b.AddPartiality(cutShortNote(cut, len(admitted.Admitted), stopCause(analysis)))
	}

	b.WithProvenance(withSignals(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzer,
		AdvisoryCursor:  req.Cursor,
		Timestamp:       time.Now().UTC(),
	}, req.Signals))
	rankWith(b, req.Signals, req.Advisories, pipeline.AdvisorySourceOf(req.AssessOptions...))

	rep, err := b.BuildValidated()
	if err != nil {
		return nil, nil, fmt.Errorf("trigger: build baseline report: %w", err)
	}
	return &rep, sortedAdvisories(assessed), nil
}

// PRInheritRequest configures a PR-adjacent run. It diffs the PR's resolved SBOM
// against the stored baseline; if the dependency set is unchanged it inherits the
// baseline Report (the fast path — no re-analysis), otherwise it re-analyzes the
// affected slice (the advisories touching changed packages). Either way the result
// is returned to the caller and the stored baseline is left untouched.
type PRInheritRequest struct {
	// Subject is the PR head's neutral identity.
	Subject Subject
	// Codebase tells the pipeline how to acquire the PR head.
	Codebase assessment.CodebaseRef
	// PRSBOM is the PR head's resolved dependency set, already computed by the caller
	// (the GH adapter resolves it cheaply). It is diffed against the baseline SBOM.
	PRSBOM report.SBOM
	// Advisories is the corpus to re-evaluate when the fast path does not apply. Only
	// the advisories whose package changed are actually re-run (the affected slice).
	Advisories []assessment.VulnRef
	// WorkSetLimits mirrors BaselineRequest.WorkSetLimits: what the caller could not put
	// into Advisories. It is disclosed on BOTH paths — an inherited Report is still a
	// Report about THIS run's work set, so a widening that failed on the PR run must be
	// visible even when no re-analysis happened.
	WorkSetLimits []report.PartialityNote
	// DiffLimits is what the PR-head SBOM resolution could not resolve — the partiality
	// the head inventory carried (a lane whose resolver was unavailable, an ecosystem
	// left unresolved). It is what bounds the diff itself: an unresolved head inventory
	// can make a changed dependency set look unchanged. Disclosed on BOTH paths (§4.1 /
	// C3), and above all on the inherited fast path, so a run that inherited because it
	// could not compare something is distinguishable in the Report from one that
	// inherited because nothing changed. Populated by trigger.ResolveSBOM's partiality.
	DiffLimits []report.PartialityNote
	// AnalyzerVersion / Cursor mirror BaselineRequest.
	AnalyzerVersion string
	Cursor          string
	// AssessOptions are the pipeline seams for any re-analysis.
	AssessOptions []pipeline.AssessOption
	// Signals mirrors BaselineRequest.Signals. Every row is ranked by it — inherited rows too, so
	// none keeps a value from the signals file the baseline run read.
	Signals *intel.Signals
	// Analysis bounds the per-advisory re-assessments. When it is done, the advisories not yet
	// assessed get scan_cut_short rows and the run still returns its Report. Nil means ctx.
	Analysis context.Context
}

// PRInheritResult reports the outcome of a PR-inherit run.
type PRInheritResult struct {
	// Report is the run's Report — the inherited baseline (fast path) or a freshly
	// re-analyzed Report (slow path).
	Report *report.Report
	// Inherited is true when the fast path applied (deps unchanged): the baseline
	// Report was inherited with a baseline pointer and no re-analysis ran.
	Inherited bool
	// ChangedPackages names the SBOM packages that differ from the baseline. Empty on
	// the fast path.
	ChangedPackages []string
}

// RunPRInherit decides between the fast path and re-analysis and returns the PR's Report.
//
// Fast path (Inherited): the PR SBOM equals the baseline SBOM → emit a Report that
// inherits the baseline's findings, carrying a Baseline pointer, with no S1–S6 run.
// Slow path: at least one package changed → re-run S1–S6 for the advisories whose
// package changed and merge those findings over the inherited baseline findings.
//
// RunPRInherit only reads the store. The state ref holds the default branch's
// baseline, which later PR runs inherit from and cve-watch diffs against; a Report of
// unmerged code never belongs there. Reading only also means a run whose token cannot
// write the ref — a pull request from a fork — takes both paths.
//
// A baseline must already exist; absent one, RunPRInherit returns ErrNoBaseline (a PR
// run has nothing to inherit from until the default branch has been scanned once).
func RunPRInherit(ctx context.Context, store statestore.StateStore, req PRInheritRequest) (*PRInheritResult, error) {
	state, err := store.Read(ctx)
	if errors.Is(err, statestore.ErrNotFound) {
		return nil, ErrNoBaseline
	}
	if err != nil {
		return nil, fmt.Errorf("trigger: pr-inherit read baseline: %w", err)
	}
	if state.Report == nil {
		return nil, ErrNoBaseline
	}
	baseline := state.Report

	changed := changedPackages(baseline.SBOM, req.PRSBOM)

	if len(changed) == 0 {
		rep := inheritBaseline(baseline, req, state)
		return &PRInheritResult{Report: rep, Inherited: true}, nil
	}

	rep, err := reanalyzeSlice(ctx, baseline, req, state, changed)
	if err != nil {
		return nil, err
	}
	return &PRInheritResult{
		Report:          rep,
		Inherited:       false,
		ChangedPackages: changed,
	}, nil
}

// CVEWatchRequest configures a scheduled CVE-watch run. It queries OSV.dev for the
// advisories now affecting the stored SBOM, diffs them against the stored cursor, and
// either heartbeats (cursor-only bump, no overlap) or runs an earnest re-analysis
// scoped to the newly-relevant advisories (overlap).
type CVEWatchRequest struct {
	// Subject / Codebase identify the codebase for any earnest re-analysis.
	Subject  Subject
	Codebase assessment.CodebaseRef
	// AnalyzerVersion is stamped into provenance on an earnest run; "" uses the default.
	AnalyzerVersion string
	// AssessOptions are the pipeline seams for an earnest re-analysis.
	AssessOptions []pipeline.AssessOption
	// Signals mirrors PRInheritRequest.Signals.
	Signals *intel.Signals
	// Advisories is the run's work set. CVE-watch assesses only the newly-relevant advisories, but
	// every advisory here still claims its aliases when the report is ranked, so an inherited row
	// ranks as it did in the baseline over the same work set.
	Advisories []assessment.VulnRef
	// HoldCursor keeps the stored cursor on an earnest run, so its new advisories are assessed
	// again next run. Set it when this run's analysis inputs could not be had (a failed build
	// graph): the Report is still written, but the advisories it could not assess stay new.
	HoldCursor bool
	// Hold, when set, is consulted on an earnest run after the re-assessments and before the
	// state write, with the stored dependency-fetch record (nil when there is none); true holds
	// the cursor as HoldCursor does. It is for a condition the re-assessments themselves
	// discover, which a value fixed before the run cannot see.
	Hold func(stored *statestore.DepFetch) bool
	// Analysis bounds the earnest re-assessments. When it is done, the advisories not yet assessed
	// get scan_cut_short rows, the stored cursor is held so they stay new, and the run still
	// writes its Report under ctx. Nil means ctx.
	Analysis context.Context
	// DependencyFetch, when set, computes the dependency-fetch record an earnest run writes from
	// the stored one, after the hold is decided and before the write. A heartbeat never calls it
	// and carries the stored record. Nil carries the stored record.
	DependencyFetch DependencyFetchUpdate
}

// CVEWatchResult reports the outcome of one scheduled CVE-watch run.
type CVEWatchResult struct {
	// Heartbeat is true when no newly-relevant advisory overlapped the SBOM beyond the
	// stored cursor: only the cursor was bumped, no re-analysis ran, no new report/sbom
	// objects were written (statestore heartbeat semantics).
	Heartbeat bool
	// NewAdvisories are the advisory IDs OSV.dev reported that were NOT in the stored
	// cursor — the forcing function for an earnest run. Empty on a heartbeat.
	NewAdvisories []string
	// Report is the re-analyzed Report on an earnest run; nil on a heartbeat.
	Report *report.Report
	// Truncated is true when the Report left in state discloses a scan cut short: the earnest
	// Report, or on a heartbeat the stored one, which the heartbeat keeps.
	Truncated bool
	// NoInventory is true on a heartbeat over an empty stored SBOM that a baseline stopped before
	// resolving: there was nothing to query, so the heartbeat says nothing about new advisories.
	NoInventory bool
	// Cursor is the new cursor written to state (the full sorted advisory-ID set).
	Cursor string
}

// RunCVEWatch performs one scheduled CVE-watch pass.
//
//  1. Query OSV.dev querybatch over the stored SBOM (this package's only network
//     egress; see the Rung 0 package doc for the tool's others).
//  2. Diff the returned advisory IDs against the stored cursor.
//  3. No new IDs → heartbeat: write only the cursor (set to the full current ID set);
//     report/sbom/vex blobs are reused (zero new objects). Returns Heartbeat=true.
//  4. New IDs overlap the SBOM → earnest run: re-analyze S1–S6 scoped to the newly-
//     relevant advisories, build a Report, write it with the bumped cursor.
//
// The cursor is the canonical sorted advisory-ID set; "new" means present in the OSV
// result but absent from the stored cursor.
func RunCVEWatch(ctx context.Context, store statestore.StateStore, osv OSVClient, req CVEWatchRequest) (*CVEWatchResult, error) {
	state, err := store.Read(ctx)
	if errors.Is(err, statestore.ErrNotFound) {
		return nil, ErrNoBaseline
	}
	if err != nil {
		return nil, fmt.Errorf("trigger: cve-watch read: %w", err)
	}
	if state.Report == nil {
		return nil, ErrNoBaseline
	}

	osvResult, err := osv.QueryBatch(ctx, state.SBOM.Packages)
	if err != nil {
		return nil, fmt.Errorf("trigger: cve-watch query: %w", err)
	}

	current := osvResult.IDs()
	sort.Strings(current)
	newCursor := strings.Join(current, ",")

	prior := cursorSet(state.Cursor)
	var newIDs []string
	for _, id := range current {
		if _, ok := prior[id]; !ok {
			newIDs = append(newIDs, id)
		}
	}

	if len(newIDs) == 0 {
		state.Cursor = newCursor
		committed, err := store.Write(ctx, state)
		if err != nil {
			return nil, fmt.Errorf("trigger: cve-watch heartbeat: %w", err)
		}
		return &CVEWatchResult{
			Heartbeat:   true,
			Cursor:      committed.Cursor,
			Truncated:   hasCutShort(state.Report.Partiality),
			NoInventory: len(state.SBOM.Packages) == 0 && inventoryCutShort(state.Report.Partiality),
		}, nil
	}

	// The Report's provenance carries the cursor too, and a conflicting write merges the
	// cursor from it, so a held cursor is the one both record.
	cursor := newCursor
	if req.HoldCursor {
		cursor = state.Cursor
	}
	rep, assessed, err := earnestRun(ctx, state, req, osvResult, newIDs, cursor)
	if err != nil {
		return nil, err
	}
	held := rep.Provenance.AdvisoryCursor == state.Cursor
	state.Report = rep
	state.SBOM = rep.SBOM
	state.Cursor = rep.Provenance.AdvisoryCursor
	if req.DependencyFetch != nil {
		state.DepFetch = req.DependencyFetch(state.DepFetch, DependencyFetchRun{Held: held, Assessed: assessed})
	}
	committed, err := store.Write(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("trigger: cve-watch earnest write: %w", err)
	}
	return &CVEWatchResult{
		NewAdvisories: newIDs,
		Report:        committed.Report,
		Cursor:        committed.Cursor,
		Truncated:     hasCutShort(committed.Report.Partiality),
	}, nil
}
