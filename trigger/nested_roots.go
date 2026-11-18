package trigger

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// nestedRoots assesses an advisory in the Go modules nested below the build root, each as its own
// build root, so a row the root build settles is withheld only by a nested module that was not
// analyzed or did not settle it too. The root inventory lists those modules as one
// plugin.PartialReasonNestedModule limit each; a module whose build settles the advisory stops
// limiting that advisory's row.
type nestedRoots struct {
	analysis context.Context
	codebase assessment.CodebaseRef
	opts     []pipeline.AssessOption
	dir      string
	modules  []plugin.ScopedReason
	builds   map[string]*nestedBuild
	// settle is settles, replaceable in tests.
	settle func(adv assessment.VulnRef, rel string) bool
}

// nestedBuild is one nested module's inventory, resolved once for the scan.
type nestedBuild struct {
	codebase assessment.CodebaseRef
	opts     []pipeline.AssessOption
	sbom     report.SBOM
	notes    []report.PartialityNote
	ok       bool
}

// newNestedRoots returns the nested modules of the inventory resolved at dir. It holds none, and
// so changes no limit, when the nested-module limit is also run-wide or dir is not known.
func newNestedRoots(analysis context.Context, codebase assessment.CodebaseRef, opts []pipeline.AssessOption, dir string, inv plugin.DependencyInventory) *nestedRoots {
	n := &nestedRoots{analysis: analysis, codebase: codebase, opts: opts, dir: dir, builds: map[string]*nestedBuild{}}
	n.settle = n.settles
	if dir == "" || slices.Contains(inv.Partiality.Reasons, plugin.PartialReasonNestedModule) {
		return n
	}
	for _, sr := range inv.Partiality.Scoped {
		if sr.Reason == plugin.PartialReasonNestedModule {
			n.modules = append(n.modules, sr)
		}
	}
	return n
}

// limitsFor returns limits as they apply to f: the nested-module limit names only the modules that
// could hold one of f's packages and whose own build did not settle adv, and is dropped when it
// names none. settled lists the modules whose build did settle it. A module the limit does not
// bound, or with no directory, is never assessed and stays.
func (n *nestedRoots) limitsFor(adv assessment.VulnRef, f report.AdvisoryFinding, limits []report.PartialityNote, purls []string) (out []report.PartialityNote, settled []string) {
	if len(n.modules) == 0 || !(f.Verdict == report.VerdictNotExploitable || restsOnInventory(f)) {
		return limits, nil
	}
	keys, known := rowKeys(f.Package, purls)
	if !known {
		return limits, nil
	}
	var kept []plugin.ScopedReason
	for _, m := range n.modules {
		note := report.PartialityNote{Targets: m.Targets}
		switch {
		case len(m.Targets) == 0 || m.Path == "":
			kept = append(kept, m)
		case !limitCovers(note, keys, true):
		case n.settle(adv, m.Path):
			settled = append(settled, m.Path)
		default:
			kept = append(kept, m)
		}
	}
	if len(settled) == 0 {
		return limits, nil
	}
	for _, l := range limits {
		if l.Reason != plugin.PartialReasonNestedModule {
			out = append(out, l)
			continue
		}
		if len(kept) == 0 {
			continue
		}
		var paths, targets []string
		unbounded := false
		for _, m := range kept {
			paths = append(paths, m.Path)
			targets = append(targets, m.Targets...)
			unbounded = unbounded || len(m.Targets) == 0
		}
		l.Path, l.Targets = strings.Join(paths, ", "), nil
		if !unbounded {
			l.Targets = slices.Compact(slices.Sorted(slices.Values(targets)))
		}
		out = append(out, l)
	}
	return out, settled
}

// settles reports whether the build rooted at the nested module rel rules adv out: its row there
// is not_exploitable or disqualified under that module's own inventory limits. A module whose
// inventory or assessment failed, or that the scan stopped before, settles nothing.
func (n *nestedRoots) settles(adv assessment.VulnRef, rel string) bool {
	b := n.build(rel)
	if !b.ok {
		return false
	}
	areq := assessment.Request{Vulnerability: adv, Codebase: b.codebase}
	st, id, stopped, err := assessWithin(n.analysis, areq, b.opts...)
	if stopped || err != nil {
		return false
	}
	f := nestedFinding(st, id, areq, b)
	return f.Verdict == report.VerdictNotExploitable || f.Verdict == report.VerdictDisqualified
}

func nestedFinding(st artifact.Store, id string, areq assessment.Request, b *nestedBuild) report.AdvisoryFinding {
	advisory, pkg := advisoryFromArtifacts(st, id, areq, b.sbom.Packages)
	f := findingInBuild(st, id, advisory, pkg, goModulesOf(b.sbom, b.notes))
	return withInventoryLimits(f, b.notes, pipeline.AdvisoryPackagePURLs(st, id))
}

func (n *nestedRoots) build(rel string) *nestedBuild {
	if b, ok := n.builds[rel]; ok {
		return b
	}
	b := &nestedBuild{
		codebase: assessment.CodebaseRef{
			Repo:        n.codebase.Repo,
			Revision:    n.codebase.Revision,
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: filepath.Join(n.dir, filepath.FromSlash(rel))},
		},
		opts: scanOptions(n.opts),
	}
	n.builds[rel] = b
	inv, language, dir, err := pipeline.ResolveCodebaseInventory(n.analysis, b.codebase, "", b.opts...)
	if err != nil || n.analysis.Err() != nil || dir != b.codebase.Acquisition.Path {
		return b
	}
	b.sbom, b.notes = sbomFromInventory(inv, ecosystemFor(language))
	b.ok = true
	return b
}

// withNestedRoots states on a row the nested modules whose own builds also settled its advisory.
func withNestedRoots(f report.AdvisoryFinding, settled []string) report.AdvisoryFinding {
	if len(settled) == 0 || f.Verdict == report.VerdictUndetermined {
		return f
	}
	f.Evidence.Detail += "; the modules nested below the build root that could build against the package were analyzed as their own builds and are not affected: " + strings.Join(settled, ", ")
	return f
}
