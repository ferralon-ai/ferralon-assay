package report

import (
	"sort"
	"time"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// Builder accumulates the output of an S1–S6 Assess pass into a Report. It is the
// population path the pipeline uses: add the resolved packages, record each
// advisory's deterministic verdict, set provenance, then Build.
//
// The Builder keeps the Report decoupled from pipeline internals — callers map
// their carrier types into the neutral Package / AdvisoryFinding shapes; the Report
// never embeds pipeline state. Build sorts the SBOM and findings into a stable order
// so the serialized Report is deterministic (content-addressable in the StateStore).
type Builder struct {
	subject    Subject
	packages   []Package
	advisories []AdvisoryFinding
	partiality []PartialityNote
	provenance Provenance
	baseline   *BaselineRef
}

// NewBuilder starts a Report for the given scanned subject. CommitSHA in provenance
// defaults to subject.ResolvedCommit and may be overridden via WithProvenance.
func NewBuilder(subject Subject) *Builder {
	return &Builder{
		subject:    subject,
		provenance: Provenance{CommitSHA: subject.ResolvedCommit},
	}
}

// AddPackage records one resolved dependency into the SBOM.
func (b *Builder) AddPackage(p Package) *Builder {
	b.packages = append(b.packages, p)
	return b
}

// AddPackages records several resolved dependencies into the SBOM.
func (b *Builder) AddPackages(pkgs ...Package) *Builder {
	b.packages = append(b.packages, pkgs...)
	return b
}

// AddFinding records one evaluated advisory and its deterministic verdict. The
// caller is responsible for supplying a valid Verdict; Build does not silently drop
// invalid findings — call Report.Validate (or BuildValidated) to enforce inv. 5.
func (b *Builder) AddFinding(f AdvisoryFinding) *Builder {
	b.advisories = append(b.advisories, f)
	return b
}

// Disqualified records an advisory the scan ruled out for this subject. basis carries the
// refutation grounds the disqualification stands on: verdict.BasisVersionNotAffected when the
// resolved version is outside the advisory's affected range, verdict.BasisSymbolAbsent when the
// vulnerable symbol is absent from the built artifact, and verdict.BasisNone when the advisory
// was never adjudicated on either axis — it belongs to another ecosystem, or its package is
// absent from the manifest. Those are disqualified because nothing here could be compared, not
// because a comparison cleared them, and an empty basis is how this Report says so. detail is
// the neutral one-line grounds.
func (b *Builder) Disqualified(adv Advisory, pkg *Package, basis verdict.NonExploitableBasis, detail string) *Builder {
	return b.AddFinding(AdvisoryFinding{
		Advisory: adv,
		Package:  pkg,
		Verdict:  VerdictDisqualified,
		Evidence: EvidenceSummary{Basis: basis, Detail: detail},
	})
}

// NotExploitable records a grounded-safe advisory: the vulnerable symbol is absent
// or not reachable. basis distinguishes which (verdict.BasisSymbolAbsent /
// BasisVersionNotAffected); detail is the neutral one-line grounds.
func (b *Builder) NotExploitable(adv Advisory, pkg *Package, basis verdict.NonExploitableBasis, detail string) *Builder {
	return b.AddFinding(AdvisoryFinding{
		Advisory: adv,
		Package:  pkg,
		Verdict:  VerdictNotExploitable,
		Evidence: EvidenceSummary{Basis: basis, Detail: detail},
	})
}

// Undetermined records an advisory the scan evaluated and established NOTHING about:
// no verdict, no grounds, only the machine-readable reason why. reason draws on the open
// PartialityNote.Reason vocabulary (e.g. ReasonGoToolchainNotScanned).
//
// The caller SHOULD also record the corresponding scan-level limit via AddPartiality: the
// row says which advisory, the note says what the limit was and which ecosystem it scoped.
func (b *Builder) Undetermined(adv Advisory, pkg *Package, reason string) *Builder {
	return b.AddFinding(AdvisoryFinding{
		Advisory:           adv,
		Package:            pkg,
		Verdict:            VerdictUndetermined,
		UndeterminedReason: reason,
		Evidence:           EvidenceSummary{Detail: UndeterminedDetail(reason)},
	})
}

// ReachableCandidate records a reachable path to the vulnerable symbol — a
// candidate, never a proof. path is the compact entrypoint→symbol path; detail is
// optional neutral context.
func (b *Builder) ReachableCandidate(adv Advisory, pkg *Package, path, detail string) *Builder {
	return b.AddFinding(AdvisoryFinding{
		Advisory: adv,
		Package:  pkg,
		Verdict:  VerdictReachableCandidate,
		Evidence: EvidenceSummary{ReachablePath: path, Detail: detail},
	})
}

// ReachableCandidateGraded records a reachable candidate with structured
// reachability evidence: a strength grade, the ingress at the path head, and the
// ingress→symbol call frames. The grade refines candidate strength and is NEVER a
// verdict (inv. 5) — the finding stays a reachable_candidate. path is the compact
// human-readable form (kept in sync with frames by the caller); detail is optional.
func (b *Builder) ReachableCandidateGraded(adv Advisory, pkg *Package, grade ReachabilityGrade, entry *EntryPoint, frames []CallFrame, path, detail string) *Builder {
	return b.AddFinding(AdvisoryFinding{
		Advisory: adv,
		Package:  pkg,
		Verdict:  VerdictReachableCandidate,
		Evidence: EvidenceSummary{
			ReachablePath: path,
			Detail:        detail,
			Grade:         grade,
			EntryPoint:    entry,
			CallPath:      frames,
		},
	})
}

// AddPartiality records scan-level disclosures of what the pass could not establish
// (see PartialityNote). Notes with an empty Reason are dropped — an unnamed limit
// renders as nothing and would be worse than silence. Build de-duplicates and sorts
// the accumulated set, so callers may add the same note once per advisory without
// producing a repeated disclosure.
//
// A note that names no Class is classified here, from its Reason. This is the single
// place the taxonomy is applied, which is what keeps two producers from disagreeing
// about the same reason code and splitting one disclosure into two after de-duplication.
// An explicit Class survives: a producer that knows its own limit is methodological may
// say so, and an unrecognized reason still lands in the loud arm.
func (b *Builder) AddPartiality(notes ...PartialityNote) *Builder {
	for _, n := range notes {
		if n.Reason == "" {
			continue
		}
		if n.Class == "" {
			n.Class = ClassifyPartialityReason(n.Reason)
		}
		b.partiality = append(b.partiality, n)
	}
	return b
}

// WithProvenance sets the full provenance block. CommitSHA, AnalyzerVersion, and
// AdvisoryCursor come from the run; Timestamp defaults to time.Now().UTC() in Build
// when left zero.
func (b *Builder) WithProvenance(p Provenance) *Builder {
	if p.CommitSHA == "" {
		p.CommitSHA = b.subject.ResolvedCommit
	}
	b.provenance = p
	return b
}

// WithBaseline sets the inherited-baseline pointer (PR-adjacent inherit / diff).
func (b *Builder) WithBaseline(ref BaselineRef) *Builder {
	b.baseline = &ref
	return b
}

// findingRank yields the descending actionable-ordering key for a finding:
// reachable candidates first, then undetermined, then CISA KEV-listed, then
// attacker-tainted over control-flow-only, then higher EPSS score, then percentile.
// Findings with no matched intel (nil Priority) score zero on the EPSS/KEV axes and
// sink below ranked peers; ties fall through to a stable ID/Source order in Build. The
// key is pure prioritization — it reorders attention, never asserts exploitability
// (inv. 5).
//
// Undetermined outranks every grounded-safe verdict, KEV included, because an
// unassessed advisory owes the reader an action and a refuted one does not. It is the
// ordering counterpart of "not assessed, never safe": sorted among the refutations it
// would read as a slightly weaker one.
func findingRank(f AdvisoryFinding) (candidate, undetermined, kev, grade int, epss, percentile float64) {
	if f.Verdict == VerdictReachableCandidate {
		candidate = 1
	}
	if f.Verdict == VerdictUndetermined {
		undetermined = 1
	}
	switch f.Evidence.Grade {
	case GradeAttackerTainted:
		grade = 2
	case GradeControlFlowOnly:
		grade = 1
	}
	if f.Priority != nil {
		if f.Priority.KEVListed {
			kev = 1
		}
		epss = f.Priority.EPSSScore
		percentile = f.Priority.EPSSPercentile
	}
	return
}

// sortFindings orders findings in place by the descending actionable key (findingRank),
// falling through to advisory id then source so the serialized Report is deterministic and
// content-addressable. It is shared by Build and by Upgrade, so a migrated document and a
// freshly built one order identically.
func sortFindings(adv []AdvisoryFinding) {
	sort.Slice(adv, func(i, j int) bool {
		ci, ui, ki, gi, ei, pi := findingRank(adv[i])
		cj, uj, kj, gj, ej, pj := findingRank(adv[j])
		switch {
		case ci != cj:
			return ci > cj // reachable candidates first (most actionable)
		case ui != uj:
			return ui > uj // then undetermined: not assessed, never safe
		case ki != kj:
			return ki > kj // CISA KEV-listed next
		case gi != gj:
			return gi > gj // attacker-tainted over control-flow-only
		case ei != ej:
			return ei > ej // higher EPSS score
		case pi != pj:
			return pi > pj // higher EPSS percentile
		case adv[i].Advisory.ID != adv[j].Advisory.ID:
			return adv[i].Advisory.ID < adv[j].Advisory.ID // stable tiebreak
		default:
			return adv[i].Advisory.Source < adv[j].Advisory.Source
		}
	})
}

// Build assembles the Report. It sets SchemaVersion, defaults the provenance
// timestamp to now (UTC) when unset, and sorts the SBOM and findings into a stable
// order so the serialized Report is deterministic.
func (b *Builder) Build() Report {
	prov := b.provenance
	if prov.Timestamp.IsZero() {
		prov.Timestamp = time.Now().UTC()
	}

	pkgs := append([]Package(nil), b.packages...)
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})

	adv := append([]AdvisoryFinding(nil), b.advisories...)
	sortFindings(adv)

	return Report{
		SchemaVersion: SchemaVersion,
		Subject:       b.subject,
		SBOM:          SBOM{Packages: pkgs},
		Advisories:    adv,
		Partiality:    dedupPartiality(b.partiality),
		Provenance:    prov,
		Baseline:      b.baseline,
	}
}

// dedupPartiality collapses the accumulated notes to a stable, unique set keyed on
// (Reason, Ecosystem, Detail), UNIONING the withheld advisory ids of notes that share
// a key. Callers add one note per assessment that declared a limit, so the same "no
// lockfile" disclosure arrives once per advisory and the customer must read it once —
// and a limit that withheld four advisories must read as one disclosure naming four,
// not as four near-identical rows. That collapse only holds when Detail agrees too:
// Detail carries per-failure specifics (e.g. which step of which advisory's assessment
// failed), and two notes that share a Reason and Ecosystem but differ in Detail are
// naming two different things, not the same thing twice. Keying on Detail as well as
// Reason/Ecosystem is what keeps assessFailureNote's one-note-per-failed-advisory
// disclosures distinct instead of collapsing to the first failure's Detail. Returns
// nil (not an empty slice) when there is nothing to disclose, so a clean scan omits
// the field entirely.
func dedupPartiality(notes []PartialityNote) []PartialityNote {
	if len(notes) == 0 {
		return nil
	}
	type key struct{ reason, ecosystem, detail string }
	index := make(map[key]int, len(notes))
	out := make([]PartialityNote, 0, len(notes))
	for _, n := range notes {
		k := key{n.Reason, n.Ecosystem, n.Detail}
		i, ok := index[k]
		if !ok {
			index[k] = len(out)
			merged := n
			merged.Advisories = append([]string(nil), n.Advisories...)
			out = append(out, merged)
			continue
		}
		out[i].Advisories = append(out[i].Advisories, n.Advisories...)
	}
	for i := range out {
		out[i].Advisories = sortedUnique(out[i].Advisories)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// sortedUnique returns ids sorted and de-duplicated, or nil when empty so the field is
// omitted rather than serialized as [].
func sortedUnique(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// BuildValidated builds the Report and runs Validate, returning an error if the
// result violates the Report invariants (notably inv. 5). Pipelines that want to
// fail fast on a mis-mapped verdict use this instead of Build.
func (b *Builder) BuildValidated() (Report, error) {
	r := b.Build()
	if err := r.Validate(); err != nil {
		return Report{}, err
	}
	return r, nil
}
