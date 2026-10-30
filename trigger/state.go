package trigger

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
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

// packageSignature captures every axis of a package that can change which advisories
// apply to it (§4.1 / §8 checkbox 12 "relevant dependency ... changes"): its exact
// version, whether it is a direct or transitive dependency, and its immediate
// neighbourhood in the selected graph. It is the relevance predicate this cycle makes
// explicit — a change in any field is a relevant change that forces re-analysis of the
// package's advisories; nothing else is.
//
// The one deliberate suppression: neighbours are recorded by version-independent
// ecosystem+name, not by Package.Key() (which embeds version). So a *descendant's*
// version bump does not change this package's signature — that descendant re-runs on
// its own version delta, and re-running its parent as well would evaluate the same
// advisories against the same coordinate for no applicability change. This is the only
// churn a whole-graph diff introduces that the rule quiets, and it is quieted by an
// advisory-applicability argument, never by latency (C2). Every other delta — an added
// or removed edge, a direct/transitive flip, a version change — falls through to
// "changed", so the rule's failure direction is re-analysis, never inheritance.
type packageSignature struct {
	version  string
	direct   bool
	parents  string // sorted \x00-joined ecosystem+name of immediate parents
	children string // sorted \x00-joined ecosystem+name of immediate children
}

// changedPackages returns the ecosystem\x00name keys of packages whose signature
// differs between the baseline and the candidate SBOM — added, removed, version-,
// direct/transitive-, or parent/child-edge-changed. The result is sorted and
// de-duplicated. An empty result is the PR-inherit fast-path condition (nothing
// relevant changed). Relationship changes are now visible: before this cycle the
// comparison was keyed on {ecosystem, name} → version alone and a package that became
// direct, or whose parent edge moved, inherited a stale Report silently.
//
// A name is compared over every copy the SBOM carries of it, as a multiset: one name may
// be installed at several versions (npm nests them), and a PR that moves one copy while
// another stays put has changed the package. Comparing one signature per name let the
// last copy stand for the rest, so lodash {4.17.10, 4.17.21} → {4.17.4, 4.17.21} read as
// unchanged and inherited the baseline's verdicts for a version the PR replaced.
func changedPackages(baseline, candidate report.SBOM) []string {
	base := indexSignatures(baseline)
	cand := indexSignatures(candidate)

	changed := make(map[string]struct{})
	for key, bsigs := range base {
		if csigs, ok := cand[key]; !ok || !slices.Equal(csigs, bsigs) {
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

// indexSignatures builds the relevance signature of every copy of every package in an
// SBOM, keyed by ecosystem+name and sorted so two SBOMs listing the same copies compare
// equal in any order. It resolves the relationship edges (keyed by Package.Key()) onto
// version-independent ecosystem+name neighbour lists. An edge whose endpoint names no
// package in this SBOM is dropped here exactly as report.Validate rejects it at build
// time, so a validated SBOM loses no edge.
func indexSignatures(s report.SBOM) map[string][]packageSignature {
	keyToName := make(map[string]string, len(s.Packages))
	for _, p := range s.Packages {
		keyToName[p.Key()] = p.Ecosystem + "\x00" + p.Name
	}

	parents := make(map[string][]string)
	children := make(map[string][]string)
	for _, e := range s.Relationships {
		pn, pok := keyToName[e.Parent]
		cn, cok := keyToName[e.Child]
		if !pok || !cok {
			continue
		}
		children[pn] = append(children[pn], cn)
		parents[cn] = append(parents[cn], pn)
	}

	sigs := make(map[string][]packageSignature, len(s.Packages))
	for _, p := range s.Packages {
		name := p.Ecosystem + "\x00" + p.Name
		sigs[name] = append(sigs[name], packageSignature{
			version:  p.Version,
			direct:   p.Direct,
			parents:  joinSortedUnique(parents[name]),
			children: joinSortedUnique(children[name]),
		})
	}
	for _, copies := range sigs {
		slices.SortFunc(copies, func(a, b packageSignature) int {
			return cmp.Or(
				strings.Compare(a.version, b.version),
				compareBool(a.direct, b.direct),
				strings.Compare(a.parents, b.parents),
				strings.Compare(a.children, b.children),
			)
		})
	}
	return sigs
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// joinSortedUnique sorts, de-duplicates, and \x00-joins neighbour names so the
// signature is order-stable regardless of edge emission order.
func joinSortedUnique(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	out := names[:0]
	var last string
	for i, n := range names {
		if i == 0 || n != last {
			out = append(out, n)
			last = n
		}
	}
	return strings.Join(out, "\x00")
}

// inheritBaseline produces the PR-inherit fast-path Report: it re-emits the baseline's
// findings/SBOM verbatim for the PR head's subject, carrying a Baseline pointer back
// to the baseline it inherited (so a reader knows the inherited rows were not re-derived).
// fresh and notes are assessUnrowed's rows and limits for the advisories the baseline
// holds no row for; those rows were derived on this run, and a fresh row never shares a
// key with a baseline row. A Report carrying fresh rows is validated, as the slow path's
// is; a pure inherit is built as before, re-emitting only what the baseline already held.
func inheritBaseline(baseline *report.Report, req PRInheritRequest, state *statestore.State, fresh []report.AdvisoryFinding, notes []report.PartialityNote) (*report.Report, error) {
	b := report.NewBuilder(report.Subject{
		Repo:           req.Subject.Repo,
		Revision:       req.Subject.Revision,
		ResolvedCommit: req.Subject.ResolvedCommit,
	})
	b.AddPackages(baseline.SBOM.Packages...)
	// Forward the whole-graph relationships (PLAN-100 added them to report.SBOM; the
	// re-emit paths deferred forwarding them to this cycle). Without this the inherited
	// SBOM would silently flatten to packages-only, and the next PR diff against it
	// would see every relationship as newly-absent.
	b.SetRelationships(baseline.SBOM.Relationships)
	// The head's inventory limits apply to the inherited rows as to fresh ones: a package the head
	// could not inventory may be installed where the baseline's analysis never looked.
	rows := make([]report.AdvisoryFinding, 0, len(baseline.Advisories))
	for i := range baseline.Advisories {
		f := withInventoryLimits(baseline.Advisories[i], req.DiffLimits)
		rows = append(rows, f)
		b.AddFinding(f)
	}
	for _, f := range fresh {
		b.AddFinding(f)
	}
	b.AddPartiality(notes...)
	// Disclose, on the inherited fast path, what the head-SBOM resolution could not
	// resolve — so a diff that inherited because a lane's inventory was unavailable is
	// distinguishable in the Report from one that inherited because nothing changed
	// (C3). Same precedent as WorkSetLimits: an inherited Report is still a Report about
	// THIS run, and a comparison it could not fully perform must be visible.
	b.AddPartiality(req.DiffLimits...)
	// The diff compared dependencies but not build context (§8 checkbox 12's second
	// clause is unimplemented — see the note's doc). A build-context-only change would
	// take this very fast path and inherit a stale Report silently, so the gap is
	// disclosed HERE, on the inherited path, as a quiet inherent_limit (C6). Declaring
	// it is the honest state; claiming the checkbox without it is the failure.
	b.AddPartiality(buildContextNotComparedNote())
	// The inherited rows' verdicts were not re-derived, so the baseline's coverage limits
	// are still exactly the limits of what this Report asserts. Dropping them here
	// would make an inherited partial scan render clean on the PR surface.
	b.AddPartiality(withoutCutShortCount(baseline.Partiality)...)
	if note, ok := recountCutShort(rows, baseline.Partiality, ""); ok {
		b.AddPartiality(note)
	}
	// THIS run's work-set limits too. Inheriting findings does not inherit the reason the
	// PR run's own work set was narrower than intended.
	b.AddPartiality(req.WorkSetLimits...)
	// The inherited refutations' assumptions rest on the baseline's entry points.
	b.WithLibraryEntrypoints(baseline.LibraryEntrypoints...)
	b.WithProvenance(withSignals(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  cursorOr(req.Cursor, baseline.Provenance.AdvisoryCursor),
		Timestamp:       time.Now().UTC(),
	}, req.Signals))
	b.WithBaseline(baselinePointer(baseline, state))
	rankWith(b, req.Signals, req.Advisories, pipeline.AdvisorySourceOf(req.AssessOptions...))
	if len(fresh) == 0 {
		rep := b.Build()
		return &rep, nil
	}
	rep, err := b.BuildValidated()
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// unrowedAdvisories returns the work-set advisories the baseline holds no row for, each once,
// in work-set order. A row is looked up as reanalyzeSlice looks it up: by (id, source) and, for
// a migrated v1 row with no source, by id.
func unrowedAdvisories(baseline *report.Report, advisories []assessment.VulnRef) []assessment.VulnRef {
	rows := make(map[string]struct{}, len(baseline.Advisories))
	for _, f := range baseline.Advisories {
		rows[f.Advisory.ID+"\x00"+f.Advisory.Source] = struct{}{}
	}
	var out []assessment.VulnRef
	for _, adv := range advisories {
		_, ok := rows[adv.ID+"\x00"+adv.Source]
		if !ok {
			_, ok = rows[adv.ID+"\x00"]
		}
		if ok {
			continue
		}
		rows[adv.ID+"\x00"+adv.Source] = struct{}{}
		out = append(out, adv)
	}
	return out
}

// assessUnrowed runs S1–S6 for the fast path's unrowed advisories, building each row as
// reanalyzeSlice builds a fresh one: against the PR head's SBOM and its Go module list. The
// baseline's would not do, though the fast path found no package changed: changedPackages
// does not compare a replace directive, the main module or the build-list source, and each
// of those changes the module list a row is checked against. A failed assessment gets an
// undetermined row and a note naming it, so no advisory comes back without a row.
func assessUnrowed(ctx context.Context, req PRInheritRequest, advisories []assessment.VulnRef) ([]report.AdvisoryFinding, []report.PartialityNote) {
	var findings []report.AdvisoryFinding
	var notes []report.PartialityNote
	for _, adv := range advisories {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, err := assess(ctx, areq, req.AssessOptions...)
		if err != nil {
			findings = append(findings, assessFailureFinding(adv, err))
			notes = append(notes, assessFailureNote(adv, err))
			continue
		}
		notes = append(notes, partialityNotes(st, assessmentID)...)
		advisory, pkg := advisoryFromArtifacts(st, assessmentID, areq, req.PRSBOM.Packages)
		f := withInventoryLimits(findingInBuild(st, assessmentID, advisory, pkg, goModulesOf(req.PRSBOM, req.DiffLimits)), req.DiffLimits)
		if note, ok := limitNoteFor(f); ok {
			notes = append(notes, note)
		}
		findings = append(findings, f)
	}
	return findings, notes
}

// reanalyzeSlice re-runs S1–S6 for the advisories whose package changed, then merges
// those fresh findings over the inherited baseline findings (changed advisories take
// the new verdict; unchanged advisories inherit the baseline's; an advisory the baseline
// holds no row for takes the new one, so it is never left rowless). The PR head's SBOM
// becomes the Report SBOM. The Report carries a Baseline pointer.
func reanalyzeSlice(ctx context.Context, baseline *report.Report, req PRInheritRequest, state *statestore.State, changed []string) (*report.Report, error) {
	changedSet := make(map[string]struct{}, len(changed))
	for _, c := range changed {
		ecosystem, name, _ := strings.Cut(c, "\x00")
		changedSet[canonicalKey(ecosystem, name)] = struct{}{}
	}
	// The advisories the baseline holds a row for, by merge key and, for a migrated v1 row
	// with no source, by id (supersededByFresh's shape). Only those have a row to inherit.
	// A scan_cut_short row says nothing, so it has no claim to stand over a fresh finding.
	baselineRows := make(map[string]struct{}, len(baseline.Advisories))
	for _, f := range baseline.Advisories {
		if f.UndeterminedReason == report.ReasonScanCutShort {
			continue
		}
		baselineRows[f.Advisory.ID+"\x00"+f.Advisory.Source] = struct{}{}
	}

	// Every advisory is re-run. A failed or limit-bearing fresh finding always replaces the
	// baseline's row; any other replaces it only where that row cannot stand (below).
	reFindings := make(map[string]report.AdvisoryFinding)
	freshIDs := make(map[string]struct{})
	var notes []report.PartialityNote
	var entrypoints []plugin.ResolvedLibraryEntrypoints
	analysis := analysisOr(req.Analysis, ctx)
	cut := 0
	for _, adv := range req.Advisories {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, stopped, err := assessWithin(analysis, areq, req.AssessOptions...)
		if stopped {
			reFindings[adv.ID+"\x00"+adv.Source] = cutShortFinding(adv)
			freshIDs[adv.ID] = struct{}{}
			cut++
			continue
		}
		if err != nil {
			// A failed re-run replaces the baseline's row whatever package that row is on: the
			// head may select a different package, and the failure resolved none.
			notes = append(notes, assessFailureNote(adv, err))
			reFindings[adv.ID+"\x00"+adv.Source] = assessFailureFinding(adv, err)
			freshIDs[adv.ID] = struct{}{}
			continue
		}
		// Harvested before the skips below: a limit observed on this head commit is
		// true whether or not the re-run finding replaced the baseline's — and the
		// commonest limit (no manifest) is itself why pkg comes back nil.
		notes = append(notes, partialityNotes(st, assessmentID)...)
		entrypoints = append(entrypoints, libraryEntrypoints(st, assessmentID)...)
		advisory, pkg := advisoryFromArtifacts(st, assessmentID, areq, req.PRSBOM.Packages)
		f := withInventoryLimits(findingInBuild(st, assessmentID, advisory, pkg, goModulesOf(req.PRSBOM, req.DiffLimits)), req.DiffLimits)
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
		// An advisory new to the work set has no baseline row, so skipping its fresh finding would
		// leave it with no row at all, whatever its package. Otherwise the baseline's row stands only
		// when no package the advisory affects changed: the selected package is one of them, but
		// another affected package the PR moved, or removed, changes the verdict just as well.
		_, inherited := baselineRows[advisory.ID+"\x00"+advisory.Source]
		if !inherited {
			_, inherited = baselineRows[advisory.ID+"\x00"]
		}
		if inherited && !affectedPackageChanged(st, assessmentID, pkg, changedSet) {
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
	// The re-analyzed Report's SBOM is the PR head's — carry its relationships too, so
	// the stored head SBOM stays a whole graph and the next diff has edges to compare.
	b.SetRelationships(req.PRSBOM.Relationships)

	var rows []report.AdvisoryFinding
	for i := range baseline.Advisories {
		f := baseline.Advisories[i]
		if supersededByFresh(f, freshIDs) {
			continue
		}
		key := f.Advisory.ID + "\x00" + f.Advisory.Source
		if re, ok := reFindings[key]; ok {
			rows = append(rows, re)
			delete(reFindings, key)
			continue
		}
		rows = append(rows, withInventoryLimits(f, req.DiffLimits))
	}
	for _, re := range reFindings {
		rows = append(rows, re)
	}
	for _, f := range rows {
		b.AddFinding(f)
	}
	// Baseline limits apply to the findings inherited verbatim; the fresh notes apply
	// to the re-analyzed slice. Build de-duplicates the union.
	b.AddPartiality(withoutCutShortCount(baseline.Partiality)...)
	b.AddPartiality(notes...)
	// The head's entry points for each ecosystem this pass resolved them on, else the baseline's,
	// which the inherited refutations rest on.
	b.WithLibraryEntrypoints(entrypoints...)
	b.WithLibraryEntrypoints(baseline.LibraryEntrypoints...)
	b.AddPartiality(req.WorkSetLimits...)
	if note, ok := recountCutShort(rows, baseline.Partiality, ownStop(analysis, cut)); ok {
		b.AddPartiality(note)
	}

	b.WithProvenance(withSignals(report.Provenance{
		CommitSHA:       req.Subject.ResolvedCommit,
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  cursorOr(req.Cursor, baseline.Provenance.AdvisoryCursor),
		Timestamp:       time.Now().UTC(),
	}, req.Signals))
	b.WithBaseline(baselinePointer(baseline, state))
	rankWith(b, req.Signals, req.Advisories, pipeline.AdvisorySourceOf(req.AssessOptions...))

	rep, err := b.BuildValidated()
	if err != nil {
		return nil, err
	}
	return &rep, nil
}

// affectedPackageChanged reports whether any package the advisory affects is in the changed set:
// the package the head selected (pkg, nil when it selected none) and every package the normalized
// advisory names, its scalar primary and each affected_packages[] element. Those are named as
// advisoryFromArtifacts names the selected one, under the assessment's ecosystem; with no
// ecosystem on record a name matches in any. Names compare under canonicalKey, since the changed
// set carries the SBOM's spelling and the advisory keeps its own. An advisory whose package set
// cannot be read cannot be shown unchanged, so it counts as changed: so does one with a nameless
// affected_packages[] element, or one naming no package at all.
func affectedPackageChanged(store artifact.Store, assessmentID string, pkg *report.Package, changedSet map[string]struct{}) bool {
	if pkg != nil {
		if _, ok := changedSet[canonicalKey(pkg.Ecosystem, pkg.Name)]; ok {
			return true
		}
	}
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return true
	}
	type named struct {
		Module     string `json:"module"`
		Coordinate string `json:"coordinate"`
	}
	var adv struct {
		named
		AffectedPackages []named `json:"affected_packages"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return true
	}
	ecosystem := ""
	if pkg != nil {
		ecosystem = pkg.Ecosystem
	} else if inv, ok := inventory(store, assessmentID); ok && inv.Language != "" {
		ecosystem = ecosystemFor(inv.Language)
	}
	for _, p := range adv.AffectedPackages {
		if cmp.Or(p.Module, p.Coordinate) == "" {
			return true
		}
	}
	anyNamed := false
	for _, p := range append(adv.AffectedPackages, adv.named) {
		name := cmp.Or(p.Module, p.Coordinate)
		if name == "" {
			continue
		}
		anyNamed = true
		if ecosystem != "" {
			if _, ok := changedSet[canonicalKey(ecosystem, name)]; ok {
				return true
			}
			continue
		}
		for key := range changedSet {
			if eco, _, _ := strings.Cut(key, "\x00"); canonicalKey(eco, name) == key {
				return true
			}
		}
	}
	return !anyNamed
}

// canonicalKey is the changed-set key under the ecosystem's name-equivalence rule.
func canonicalKey(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		name = pipeline.CanonicalName("pypi", name)
	case "NuGet":
		name = pipeline.CanonicalName("nuget", name)
	}
	return ecosystem + "\x00" + name
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
	// The pass assesses the newly-relevant advisories, but it is asked about the run's whole work set:
	// both claim, and so do the prior rows it inherits.
	workSet := append([]assessment.VulnRef(nil), req.Advisories...)
	var entrypoints []plugin.ResolvedLibraryEntrypoints
	analysis := analysisOr(req.Analysis, ctx)
	cut := 0
	for _, a := range osvResult.Advisories {
		if _, ok := newSet[a.ID]; !ok {
			continue
		}
		areq := assessment.Request{
			Vulnerability: assessment.VulnRef{ID: a.ID, Source: "osv"},
			Codebase:      req.Codebase,
		}
		workSet = append(workSet, areq.Vulnerability)
		st, assessmentID, stopped, err := assessWithin(analysis, areq, req.AssessOptions...)
		if stopped {
			reFindings[a.ID+"\x00"+areq.Vulnerability.Source] = cutShortFinding(areq.Vulnerability)
			freshIDs[a.ID] = struct{}{}
			cut++
			continue
		}
		if err != nil {
			notes = append(notes, assessFailureNote(areq.Vulnerability, err))
			reFindings[a.ID+"\x00"+areq.Vulnerability.Source] = assessFailureFinding(areq.Vulnerability, err)
			freshIDs[a.ID] = struct{}{}
			continue
		}
		notes = append(notes, partialityNotes(st, assessmentID)...)
		entrypoints = append(entrypoints, libraryEntrypoints(st, assessmentID)...)
		advisory, tcPkg := advisoryFromArtifacts(st, assessmentID, areq, prior.SBOM.Packages)
		pkg := a.Package
		f := withInventoryLimits(findingInBuild(st, assessmentID, advisory, &pkg, goModulesOf(prior.SBOM, inventoryLimits(prior.Partiality))), inventoryLimits(prior.Partiality))
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
	// CVE-watch re-resolves no dependencies; the prior whole-graph SBOM (packages AND
	// relationships) is reused verbatim, so the stored inventory does not flatten
	// across scheduled watches.
	b.SetRelationships(prior.SBOM.Relationships)

	var rows []report.AdvisoryFinding
	for i := range prior.Advisories {
		f := prior.Advisories[i]
		if supersededByFresh(f, freshIDs) {
			continue
		}
		key := f.Advisory.ID + "\x00" + f.Advisory.Source
		if re, ok := reFindings[key]; ok {
			rows = append(rows, re)
			delete(reFindings, key)
			continue
		}
		rows = append(rows, f)
	}
	for _, re := range reFindings {
		rows = append(rows, re)
	}
	for _, f := range rows {
		b.AddFinding(f)
	}
	// CVE-watch re-resolves no dependencies, so the prior pass's limits still bound
	// every inherited finding; the fresh notes cover the newly-relevant advisories.
	b.AddPartiality(withoutCutShortCount(prior.Partiality)...)
	b.AddPartiality(notes...)
	b.WithLibraryEntrypoints(entrypoints...)
	b.WithLibraryEntrypoints(prior.LibraryEntrypoints...)
	if note, ok := recountCutShort(rows, prior.Partiality, ownStop(analysis, cut)); ok {
		b.AddPartiality(note)
	}
	if cut > 0 {
		// The advisories this pass did not assess must stay new, so the next run assesses them.
		newCursor = state.Cursor
	}

	b.WithProvenance(withSignals(report.Provenance{
		CommitSHA:       stateCommit(prior, req.Subject.ResolvedCommit),
		AnalyzerVersion: analyzerOr(req.AnalyzerVersion),
		AdvisoryCursor:  newCursor,
		Timestamp:       time.Now().UTC(),
	}, req.Signals))
	if prior.Baseline != nil {
		b.WithBaseline(*prior.Baseline)
	}
	rankWith(b, req.Signals, workSet, pipeline.AdvisorySourceOf(req.AssessOptions...))

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

// buildContextNotComparedNote is the standing disclosure that the PR-inherit diff does
// not compare build context (§8 checkbox 12 second clause, C6). PLAN-004's WorkspacePlan
// exists but is not persisted into report.SBOM — the object the diff compares — so a
// build-context-only change is undetectable and would inherit silently. It is an
// inherent_limit (quiet arm): a permanent methodology gap, not a failed run step, so it
// discloses without firing the headline qualifier. Class is set explicitly so the note
// stays quiet regardless of the reason classifier's default.
func buildContextNotComparedNote() report.PartialityNote {
	return report.PartialityNote{
		Reason: report.ReasonBuildContextNotCompared,
		Detail: "PR-inherit compared the dependency set; build-context changes " +
			"(project/language/target/runtime/root) were not compared (unimplemented)",
		Class: report.PartialityInherentLimit,
	}
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
