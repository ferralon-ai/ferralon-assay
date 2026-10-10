package cfamilyanalysis

import (
	"sort"
	"testing"
)

// TestCapabilityManifest pins the C profile: supported, sorted axes, and the engine-dependent
// axes left empty until a graph engine backs them.
func TestCapabilityManifest(t *testing.T) {
	m := CapabilityManifest()
	if !m.Supported || m.Language != "cfamily" || m.Version == "" {
		t.Fatalf("manifest identity = %+v", m)
	}
	for name, axis := range map[string][]string{"resolvers": m.Resolvers, "runtimes": m.Runtimes, "analyzers": m.Analyzers} {
		if len(axis) == 0 || !sort.StringsAreSorted(axis) {
			t.Errorf("%s = %q: want non-empty and sorted", name, axis)
		}
	}
	if len(m.GraphSemantics) != 0 || len(m.DynamicBoundaries) != 0 || len(m.Frameworks) != 0 {
		t.Errorf("engine-dependent axes must stay empty: %+v", m)
	}
}
