package checkout

import (
	"encoding/json"
	"sort"
	"testing"
)

// TestSingleProjectPlanShape asserts the constructor produces a one-Project plan whose Root and
// single Project mirror the (root, language) it was handed — the faithful single-project instance
// PLAN-004 lands.
func TestSingleProjectPlanShape(t *testing.T) {
	plan := singleProjectPlan("/abs/root", LangGo)
	if plan.Root != "/abs/root" {
		t.Fatalf("plan.Root = %q, want %q", plan.Root, "/abs/root")
	}
	if len(plan.Projects) != 1 {
		t.Fatalf("len(Projects) = %d, want 1", len(plan.Projects))
	}
	if got := plan.Projects[0]; got.Root != "/abs/root" || got.Language != LangGo {
		t.Fatalf("Projects[0] = %+v, want {Root:/abs/root Language:go}", got)
	}
}

// TestPrimaryReturnsSingleProject confirms Primary projects the single project (the (Root,Language)
// the inventory stage collapses into the scalar build_dir/language downstream reads).
func TestPrimaryReturnsSingleProject(t *testing.T) {
	prim := singleProjectPlan("/abs/root", LangJava).Primary()
	if prim.Root != "/abs/root" || prim.Language != LangJava {
		t.Fatalf("Primary() = %+v, want {Root:/abs/root Language:java}", prim)
	}
}

// TestPrimaryEmptyPlanPanics locks inv.5: an empty plan reaching Primary is a programming error
// (Fetch/ResolveVendored must error rather than emit an empty plan), never a silent misleading zero.
func TestPrimaryEmptyPlanPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Primary() on an empty plan must panic (inv.5), not return a zero Project")
		}
	}()
	_ = WorkspacePlan{}.Primary()
}

// TestProjectsDeterministicOrder proves Projects is emitted sorted by Root. A one-element plan is
// trivially sorted; this asserts the ordering discipline PLAN-400 inherits directly against a
// multi-project literal so the invariant is guarded now, not first exercised at monorepo scale.
func TestProjectsDeterministicOrder(t *testing.T) {
	projects := []Project{
		{Root: "/z", Language: LangGo},
		{Root: "/a", Language: LangJS},
		{Root: "/m", Language: LangJava},
	}
	if sort.SliceIsSorted(projects, func(i, j int) bool { return projects[i].Root < projects[j].Root }) {
		t.Fatal("test fixture must start UNSORTED to prove the sort does work")
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Root < projects[j].Root })
	want := []string{"/a", "/m", "/z"}
	for i, w := range want {
		if projects[i].Root != w {
			t.Fatalf("Projects[%d].Root = %q, want %q (must be sorted by Root)", i, projects[i].Root, w)
		}
	}
}

// TestWorkspacePlanJSONRoundTrip guards the persisted shape: the inventory artifact carries the plan
// as the workspace_plan field, so its json tags (root/projects, root/language) must round-trip.
func TestWorkspacePlanJSONRoundTrip(t *testing.T) {
	in := singleProjectPlan("/abs/root", LangPython)
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"root":"/abs/root","projects":[{"root":"/abs/root","language":"python"}]}`
	if string(b) != want {
		t.Fatalf("json = %s, want %s", b, want)
	}
	var out WorkspacePlan
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Root != in.Root || len(out.Projects) != 1 || out.Projects[0] != in.Projects[0] {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", out, in)
	}
}
