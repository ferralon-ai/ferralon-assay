package cfamilyanalysis

import (
	"slices"
	"sort"
	"testing"
)

// TestCapabilityManifest pins the manifest: supported, sorted axes, and graph semantics that claim
// only what cgx produces. cgx makes possible-tier candidate edges at a call through a
// function-pointer parameter (fn_ptr_candidate) but none at a call through a struct member, so
// the function-pointer site is also a declared boundary.
func TestCapabilityManifest(t *testing.T) {
	m := CapabilityManifest()
	if !m.Supported || m.Language != "cfamily" || m.Version == "" {
		t.Fatalf("manifest identity = %+v", m)
	}
	for name, axis := range map[string][]string{
		"resolvers":          m.Resolvers,
		"runtimes":           m.Runtimes,
		"graph_semantics":    m.GraphSemantics,
		"dynamic_boundaries": m.DynamicBoundaries,
		"analyzers":          m.Analyzers,
	} {
		if len(axis) == 0 || !sort.StringsAreSorted(axis) {
			t.Errorf("%s = %q: want non-empty and sorted", name, axis)
		}
	}
	if !slices.Contains(m.GraphSemantics, "fn_ptr_candidate") {
		t.Errorf("graph_semantics = %q: cgx produces function-pointer candidate edges", m.GraphSemantics)
	}
	if !slices.Contains(m.DynamicBoundaries, "fn_ptr") {
		t.Errorf("dynamic_boundaries = %q: the function-pointer site must be a declared boundary", m.DynamicBoundaries)
	}
	if len(m.Frameworks) != 0 {
		t.Errorf("frameworks = %q: want empty", m.Frameworks)
	}
}
