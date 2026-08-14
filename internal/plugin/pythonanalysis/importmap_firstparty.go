package pythonanalysis

import (
	"fmt"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// DeriveFirstParty produces the `declared` contributions for a first-party distribution from a
// checkout.WorkspacePlan's project roots + source-tree module layout — NOT a pyproject
// `packages` field. Our corpus declares first-party by layout: the AIRFLOW/SSRF repros carry
// `src/*.py` with no manifest naming `packages`, so the import packages a first-party
// distribution contributes are the TOP-LEVEL module names found by walking the source tree
// (discovery census §"declared").
//
// The distribution identity (dist) is supplied by the caller — checkout knows the source layout
// but not the distribution name (there is no `packages` field to read it from), so the
// first-party distribution's PEP 503 name comes from the resolved set / advisory that already
// names it (e.g. tegron-corpus-app). Import packages come from layout; the name comes from the
// known first-party identity. Each Python project root in the plan is walked; the plan holds
// exactly one project today (checkout.WorkspacePlan.Primary), but multiple are folded into one
// distribution's top-level set so the shape survives PLAN-400's monorepo enumeration.
//
// A read/scan failure surfaces as an error (inv.4) — never a silent empty declared set.
func DeriveFirstParty(dist string, plan checkout.WorkspacePlan) ([]Contribution, error) {
	norm := normalizePyCoordinate(dist)
	if norm == "" {
		return nil, fmt.Errorf("pythonanalysis: DeriveFirstParty: empty distribution name")
	}

	seen := map[string]bool{}
	var tops []string
	for _, proj := range plan.Projects {
		if proj.Language != checkout.LangPython {
			continue
		}
		paths, err := pythonFiles(proj.Root)
		if err != nil {
			return nil, fmt.Errorf("pythonanalysis: DeriveFirstParty: scan %q: %w", proj.Root, err)
		}
		for _, p := range paths {
			top := topLevelPackage(moduleOf(proj.Root, p))
			if top == "" || seen[top] {
				continue
			}
			seen[top] = true
			tops = append(tops, top)
		}
	}

	out := make([]Contribution, 0, len(tops))
	for _, top := range tops {
		out = append(out, Contribution{
			Distribution:  norm,
			ImportPackage: top,
			Provenance:    ProvenanceDeclared,
		})
	}
	return out, nil
}

// topLevelPackage returns the first dotted/slashed component of a module path — the import
// package a first-party module contributes. moduleOf returns '/'-joined module paths; the
// top-level import package is the leading component ("endpoints" for "endpoints",
// "pkg" for "pkg/sub"). An empty module (a root __init__.py) contributes nothing.
func topLevelPackage(module string) string {
	if module == "" {
		return ""
	}
	if i := strings.IndexByte(module, '/'); i >= 0 {
		return module[:i]
	}
	return module
}
