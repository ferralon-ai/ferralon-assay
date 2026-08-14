// internal/checkout/workspaceplan.go
package checkout

import "sort"

// WorkspacePlan is the deterministic enumeration of the projects detected in a checked-out
// source tree. It replaces Checkout.Fetch's singular (buildDir, language) return: a monorepo
// has many projects, each with its own root and language, and the pipeline cannot resolve a
// per-project dependency graph from one root + one language.
//
// Today the plan holds exactly ONE Project (single-root/single-language — faithful to current
// behavior); PLAN-400 enumerates true monorepos. Projects are emitted in explicit sorted order
// (by Root); no map is an iteration source on the encoding path (mirrors DependencyInventory §7).
type WorkspacePlan struct {
	Root     string    `json:"root"`     // the checkout root (absolute) — the tree the Projects live under
	Projects []Project `json:"projects"` // sorted by Root; exactly one today
}

// Project is one detected project/module within a WorkspacePlan. It carries only what checkout
// KNOWS: the project root and its own language. Membership, build target, configuration, and
// runtime are downstream concerns (BuildManifestResult, computed per project by the plugin —
// PLAN-400) and are deliberately NOT on this type, which keeps `checkout` free of a `plugin`
// import and sidesteps the DependencyMembership.Target vs BuildManifestResult.Target overload.
type Project struct {
	Root     string `json:"root"`     // absolute project/module root (a go.mod dir, or a source tree)
	Language string `json:"language"` // one of checkout.Lang* — this project's language, not a whole-tree collapse
}

// Primary returns the plan's single project. Today every plan has exactly one; it is the project
// whose (Root, Language) the inventory stage projects into the scalar build_dir/language fields
// that S3–S6 already read. It panics on an empty plan: inv.5 makes a plan with no project a
// checkout failure (Fetch/ResolveVendored error rather than return an empty plan), so an empty
// plan reaching Primary is a programming error, never a silent misleading zero.
func (p WorkspacePlan) Primary() Project {
	if len(p.Projects) == 0 {
		panic("checkout: WorkspacePlan.Primary on an empty plan (inv.5: Fetch must error, never return an empty plan)")
	}
	return p.Projects[0]
}

// singleProjectPlan wraps one detected (root, language) as a one-Project WorkspacePlan.
// The single home for "the plan is one project today" — FakeCheckout.Fetch, GitCheckout.Fetch,
// and ResolveVendored all route through it, so the git and vendored_repro paths never diverge.
// Projects is written through the same sort PLAN-400 will rely on; a one-element slice is
// trivially sorted, but the discipline (deterministic order by Root, never map iteration) is
// frozen here so the multi-project enumeration inherits it.
func singleProjectPlan(root, language string) WorkspacePlan {
	projects := []Project{{Root: root, Language: language}}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Root < projects[j].Root })
	return WorkspacePlan{Root: root, Projects: projects}
}
