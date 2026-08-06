package trigger

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// ErrNoBaseline is returned by RunPRInherit / RunCVEWatch when no baseline Report has
// been stored yet. A PR-inherit has nothing to diff against and CVE-watch has no SBOM
// to query until a baseline run has populated the state.
var ErrNoBaseline = errors.New("trigger: no baseline report in state (run a baseline first)")

// readForUpdate reads the current State to capture the CAS token before a Write,
// translating ErrNotFound (fresh repo, no ref) into an empty create-if-absent State.
// This is the Read→mutate→Write protocol the statestore contract requires.
func readForUpdate(ctx context.Context, store statestore.StateStore) (*statestore.State, error) {
	state, err := store.Read(ctx)
	if err != nil {
		if errors.Is(err, statestore.ErrNotFound) {
			return &statestore.State{}, nil
		}
		return nil, err
	}
	return state, nil
}

// changedPackages returns the names of packages that differ between the baseline and
// the candidate SBOM: added, removed, or version-changed. The result is sorted and
// de-duplicated. An empty result is the PR-inherit fast-path condition (deps + their
// versions unchanged).
func changedPackages(baseline, candidate report.SBOM) []string {
	base := indexSBOM(baseline)
	cand := indexSBOM(candidate)

	changed := make(map[string]struct{})
	for key, bv := range base {
		if cv, ok := cand[key]; !ok || cv != bv {
			changed[key] = struct{}{}
		}
	}
	for key := range cand {
		if _, ok := base[key]; !ok {
			changed[key] = struct{}{}
		}
	}

	out := make([]string, 0, len(changed))
	for key := range changed {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// indexSBOM keys packages by ecosystem+name → version so a version bump on the same
// package counts as a change.
func indexSBOM(s report.SBOM) map[string]string {
	idx := make(map[string]string, len(s.Packages))
	for _, p := range s.Packages {
		idx[p.Ecosystem+"\x00"+p.Name] = p.Version
	}
	return idx
}

// inheritBaseline produces the PR-inherit fast-path Report: it re-emits the baseline's
// findings/SBOM verbatim for the PR head's subject, carrying a Baseline pointer back
// to the baseline it inherited (so a reader knows the verdicts were not re-derived).
func inheritBaseline(baseline *report.Report, req PRInheritRequest, state *statestore.State) *report.Report {
	b := report.NewBuilder(report.Subject{
		Repo:           req.Subject.Repo,
		Revision:       req.Subject.Revision,
		ResolvedCommit: req.Subject.ResolvedCommit,
	})
	b.AddPackages(baseline.SBOM.Packages...)
	for i := range baseline.Advisories {
		b.AddFinding(baseline.Advisories[i])
	}
	// The inherited verdicts were not re-derived, so the baseline's coverage limits
	// are still exactly the limits of what this Report asserts. Dropping them here
	// would make an inherited partial scan render clean on the PR surface.
	b.AddPartiality(baseline.Partiality...)
	// THIS run's work-set limits too. Inheriting findings does not inherit the reason the
	// PR run's own work set was narrower than intended.
	b.AddPartiality(req.WorkSetLimits...)
	b.WithProvenance(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  cursorOr(req.Cursor, baseline.Provenance.AdvisoryCursor),
		Timestamp:       time.Now().UTC(),
	})
	b.WithBaseline(baselinePointer(baseline, state))
	rep := b.Build()
	return &rep
}

// reanalyzeSlice re-runs S1–S6 for the advisories whose package changed, then merges
// those fresh findings over the inherited baseline findings (changed advisories take
// the new verdict; unchanged advisories inherit the baseline's). The PR head's SBOM
// becomes the Report SBOM. The Report carries a Baseline pointer.
func reanalyzeSlice(ctx context.Context, baseline *report.Report, req PRInheritRequest, state *statestore.State, changed []string) (*report.Report, error) {
	changedSet := make(map[string]struct{}, len(changed))
	for _, c := range changed {
		changedSet[c] = struct{}{}
	}

	// Re-run only the advisories whose evaluated package is in the changed set.
	reFindings := make(map[string]report.AdvisoryFinding)
	freshIDs := make(map[string]struct{})
	var notes []report.PartialityNote
	for _, adv := range req.Advisories {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, err := assess(ctx, areq, req.AssessOptions...)
		if err != nil {
			notes = append(notes, assessFailureNote(adv, err))
			continue
		}
		// Harvested before the skips below: a limit observed on this head commit is
		// true whether or not the re-run finding replaced the baseline's — and the
		// commonest limit (no manifest) is itself why pkg comes back nil.
		notes = append(notes, partialityNotes(st, assessmentID)...)
		advisory, pkg := advisoryFromArtifacts(st, assessmentID, areq)
		f := finding(st, assessmentID, advisory, pkg)
		// An undetermined toolchain advisory is keyed in like any other fresh finding, so it
		// REPLACES the baseline's row below. It has to be harvested ahead of the two skips: a
		// toolchain advisory carries no SBOM package, so `pkg == nil` would drop it and leave
		// the baseline's stale verdict standing — which is exactly the claim this pass declines
		// to make.
		if note, ok := limitNoteFor(f); ok {
			notes = append(notes, note)
			reFindings[advisory.ID+"\x00"+advisory.Source] = f
			freshIDs[advisory.ID] = struct{}{}
			continue
		}
		if pkg == nil {
			continue
		}
		if _, ok := changedSet[pkg.Ecosystem+"\x00"+pkg.Name]; !ok {
			continue
		}
		reFindings[advisory.ID+"\x00"+advisory.Source] = f
		freshIDs[advisory.ID] = struct{}{}
	}

	b := report.NewBuilder(report.Subject{
		Repo:           req.Subject.Repo,
		Revision:       req.Subject.Revision,
		ResolvedCommit: req.Subject.ResolvedCommit,
	})
	b.AddPackages(req.PRSBOM.Packages...)

	for i := range baseline.Advisories {
		f := baseline.Advisories[i]
		if supersededByFresh(f, freshIDs) {
			continue
		}
		key := f.Advisory.ID + "\x00" + f.Advisory.Source
		if re, ok := reFindings[key]; ok {
			b.AddFinding(re)
			delete(reFindings, key)
			continue
		}
		b.AddFinding(f)
	}
	for _, re := range reFindings {
		b.AddFinding(re)
	}
	// Baseline limits apply to the findings inherited verbatim; the fresh notes apply
	// to the re-analyzed slice. Build de-duplicates the union.
	b.AddPartiality(baseline.Partiality...)
	b.AddPartiality(notes...)
	b.AddPartiality(req.WorkSetLimits...)

	b.WithProvenance(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  cursorOr(req.Cursor, baseline.Provenance.AdvisoryCursor),
		Timestamp:       time.Now().UTC(),
	})
	b.WithBaseline(baselinePointer(baseline, state))

	rep, err := b.BuildValidated()
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// earnestRun is the CVE-watch overlap path: re-run S1–S6 for the newly-relevant
// advisories OSV.dev flagged, merge the fresh findings over the prior Report's
// findings, and build a Report stamped with the new cursor. The prior Report's SBOM
// is reused (CVE-watch does not re-resolve dependencies — only advisories changed).
func earnestRun(ctx context.Context, state *statestore.State, req CVEWatchRequest, osvResult OSVResult, newIDs []string, newCursor string) (*report.Report, error) {
	prior := state.Report

	newSet := make(map[string]struct{}, len(newIDs))
	for _, id := range newIDs {
		newSet[id] = struct{}{}
	}

	reFindings := make(map[string]report.AdvisoryFinding)
	freshIDs := make(map[string]struct{})
	var notes []report.PartialityNote
	for _, a := range osvResult.Advisories {
		if _, ok := newSet[a.ID]; !ok {
			continue
		}
		areq := assessment.Request{
			Vulnerability: assessment.VulnRef{ID: a.ID, Source: "osv"},
			Codebase:      req.Codebase,
		}
		st, assessmentID, err := assess(ctx, areq, req.AssessOptions...)
		if err != nil {
			notes = append(notes, assessFailureNote(areq.Vulnerability, err))
			continue
		}
		notes = append(notes, partialityNotes(st, assessmentID)...)
		advisory, tcPkg := advisoryFromArtifacts(st, assessmentID, areq)
		pkg := a.Package
		f := finding(st, assessmentID, advisory, &pkg)
		if note, ok := limitNoteFor(f); ok {
			// The toolchain is not an SBOM dependency, so the undetermined row takes the
			// package advisoryFromArtifacts adjudicated (nil for a toolchain subject) rather
			// than the OSV query's package — pairing the advisory's top-level module with a
			// go1.x.y toolchain release would emit a coordinate that does not exist.
			f.Package = tcPkg
			notes = append(notes, note)
		}
		reFindings[advisory.ID+"\x00"+advisory.Source] = f
		freshIDs[advisory.ID] = struct{}{}
	}

	b := report.NewBuilder(report.Subject{
		Repo:           req.Subject.Repo,
		Revision:       req.Subject.Revision,
		ResolvedCommit: stateCommit(prior, req.Subject.ResolvedCommit),
	})
	b.AddPackages(prior.SBOM.Packages...)

	for i := range prior.Advisories {
		f := prior.Advisories[i]
		if supersededByFresh(f, freshIDs) {
			continue
		}
		key := f.Advisory.ID + "\x00" + f.Advisory.Source
		if re, ok := reFindings[key]; ok {
			b.AddFinding(re)
			delete(reFindings, key)
			continue
		}
		b.AddFinding(f)
	}
	for _, re := range reFindings {
		b.AddFinding(re)
	}
	// CVE-watch re-resolves no dependencies, so the prior pass's limits still bound
	// every inherited finding; the fresh notes cover the newly-relevant advisories.
	b.AddPartiality(prior.Partiality...)
	b.AddPartiality(notes...)

	b.WithProvenance(report.Provenance{
		CommitSHA:       stateCommit(prior, req.Subject.ResolvedCommit),
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  newCursor,
		Timestamp:       time.Now().UTC(),
	})
	if prior.Baseline != nil {
		b.WithBaseline(*prior.Baseline)
	}

	rep, err := b.BuildValidated()
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// supersededByFresh reports whether an inherited finding must yield to this pass's fresh
// finding for the same advisory even though the (id, source) merge key cannot match it.
//
// It exists for exactly one shape: an `undetermined` row produced by report.Upgrade from a
// stored tegron.report.v1 document. A v1 partiality note named the withheld id alone, so the
// migrated row carries NO source (inventing the advisory database it came from would be a
// fabricated fact) — and without this, a re-analysis would emit both the migrated row and its
// own fresh row for one advisory. Every other inherited finding merges on the full key.
func supersededByFresh(f report.AdvisoryFinding, freshIDs map[string]struct{}) bool {
	if f.Verdict != report.VerdictUndetermined || f.Advisory.Source != "" {
		return false
	}
	_, ok := freshIDs[f.Advisory.ID]
	return ok
}

func baselinePointer(baseline *report.Report, state *statestore.State) report.BaselineRef {
	ref := report.BaselineRef{CommitSHA: baseline.Provenance.CommitSHA}
	if baseline.Baseline != nil && baseline.Baseline.StateRef != "" {
		ref.StateRef = baseline.Baseline.StateRef
	}
	if state.CommitSHA != "" {
		ref.CommitSHA = baseline.Provenance.CommitSHA
	}
	return ref
}

func cursorSet(cursor string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, id := range strings.Split(cursor, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			set[id] = struct{}{}
		}
	}
	return set
}

func analyzerOr(v string) string {
	if v == "" {
		return AnalyzerVersion
	}
	return v
}

func cursorOr(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func stateCommit(prior *report.Report, fallback string) string {
	if fallback != "" {
		return fallback
	}
	return prior.Subject.ResolvedCommit
}
