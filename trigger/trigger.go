package trigger

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
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
	// Bands is the OPTIONAL scheduler-only prioritization hint: advisory id → Band. It is
	// read ONLY by the admission gate (admitAdvisories), above S1, to decide whether/when a
	// case is admitted this pass. It is dropped before an Assessment is constructed and NEVER
	// reaches any pipeline/verdict struct (inv.5). A nil map ⇒ every case BandUnknown ⇒ all
	// admitted (byte-identical to the pre-gate behavior). An absent band never drops a case.
	Bands map[string]Band
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
func RunBaseline(ctx context.Context, store statestore.StateStore, req BaselineRequest) (*report.Report, error) {
	rep, err := buildBaselineReport(ctx, req)
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

	committed, err := store.Write(ctx, next)
	if err != nil {
		return nil, fmt.Errorf("trigger: baseline write: %w", err)
	}
	return committed.Report, nil
}

// buildBaselineReport runs S1–S6 per advisory and assembles the Report. It does not
// touch the StateStore — the offline pipeline test exercises it directly.
func buildBaselineReport(ctx context.Context, req BaselineRequest) (*report.Report, error) {
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
	inv, invLanguage, _, err := pipeline.ResolveCodebaseInventory(ctx, req.Codebase, "", req.AssessOptions...)
	if err != nil {
		return nil, fmt.Errorf("trigger: resolve codebase inventory: %w", err)
	}
	sbom, invNotes := sbomFromInventory(inv, ecosystemFor(invLanguage))
	b.AddPackages(sbom.Packages...)
	b.SetRelationships(sbom.Relationships)
	b.AddPartiality(invNotes...)

	for _, adv := range admitted.Admitted {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, err := assess(ctx, areq, req.AssessOptions...)
		if err != nil {
			// One advisory's analysis failing used to abort the entire scan, so a single
			// broken tool produced no Report at all — and a run with no Report renders
			// downstream as a run with no findings. Disclose the failure and keep going:
			// the advisories that DID resolve keep their verdicts, and the one that did not
			// is named rather than silently missing.
			b.AddPartiality(assessFailureNote(adv, err))
			continue
		}
		// Coordinate-specific advisory resolution, RETAINED unchanged (§4.1 / C5): advisoryFromArtifacts
		// still resolves the advisory's own package for the finding, but it no longer DEFINES the SBOM —
		// the whole-graph inventory above does.
		advisory, pkg := advisoryFromArtifacts(st, assessmentID, areq)
		// A toolchain advisory the scan could not adjudicate is a first-class `undetermined`
		// row in tegron.report.v2, plus the scan-level limit that explains it.
		// v1 had to withhold the row entirely, having no cell for "the advisory applies and
		// we established nothing"; the row is what makes the omission legible at the count.
		f := finding(st, assessmentID, advisory, pkg)
		b.AddFinding(f)
		if note, ok := limitNoteFor(f); ok {
			b.AddPartiality(note)
		}
		b.AddPartiality(partialityNotes(st, assessmentID)...)
	}

	b.WithProvenance(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzer,
		AdvisoryCursor:  req.Cursor,
		Timestamp:       time.Now().UTC(),
	})

	rep, err := b.BuildValidated()
	if err != nil {
		return nil, fmt.Errorf("trigger: build baseline report: %w", err)
	}
	return &rep, nil
}

// PRInheritRequest configures a PR-adjacent run. It diffs the PR's resolved SBOM
// against the stored baseline; if the dependency set is unchanged it inherits the
// baseline Report (the fast path — no re-analysis), otherwise it re-analyzes the
// affected slice (the advisories touching changed packages) and writes the result.
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
	// AnalyzerVersion / Cursor mirror BaselineRequest.
	AnalyzerVersion string
	Cursor          string
	// AssessOptions are the pipeline seams for any re-analysis.
	AssessOptions []pipeline.AssessOption
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

// RunPRInherit decides between the fast path and re-analysis and stores the result.
//
// Fast path (Inherited): the PR SBOM equals the baseline SBOM → emit a Report that
// inherits the baseline's findings, carrying a Baseline pointer, with no S1–S6 run.
// Slow path: at least one package changed → re-run S1–S6 for the advisories whose
// package changed, merge those findings over the inherited baseline findings, and
// write.
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
	state.Report = rep
	state.SBOM = rep.SBOM
	if req.Cursor != "" {
		state.Cursor = req.Cursor
	}
	committed, err := store.Write(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("trigger: pr-inherit write: %w", err)
	}
	return &PRInheritResult{
		Report:          committed.Report,
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
		return &CVEWatchResult{Heartbeat: true, Cursor: committed.Cursor}, nil
	}

	rep, err := earnestRun(ctx, state, req, osvResult, newIDs, newCursor)
	if err != nil {
		return nil, err
	}
	state.Report = rep
	state.SBOM = rep.SBOM
	state.Cursor = newCursor
	committed, err := store.Write(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("trigger: cve-watch earnest write: %w", err)
	}
	return &CVEWatchResult{
		NewAdvisories: newIDs,
		Report:        committed.Report,
		Cursor:        committed.Cursor,
	}, nil
}
