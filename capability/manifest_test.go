package capability

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestManifestJSONRoundTrip marshals a fully-populated Manifest, unmarshals it, and asserts
// reflect.DeepEqual against the original. A field added without a JSON tag, or tagged omitempty
// where its zero value is meaningful, fails this.
func TestManifestJSONRoundTrip(t *testing.T) {
	orig := Manifest{
		Version:           "1.0.0",
		Language:          "go",
		Supported:         true,
		Resolvers:         []string{"go.mod", "go.sum"},
		Runtimes:          []string{"go1.20", "go1.21"},
		GraphSemantics:    []string{"cha", "rta", "vta"},
		Frameworks:        []string{"chi", "echo", "net/http"},
		DynamicBoundaries: []string{"cgo", "dynamic_dispatch", "reflection"},
		Analyzers:         []string{"govulncheck@1.1.0", "scip-go@0.1.0"},
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Manifest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Errorf("Manifest round-trip mismatch:\n orig = %+v\n back = %+v\n json = %s", orig, back, b)
	}
}

// TestManifestHonestAbsence documents the honest-absence marker: a Manifest with Supported:false
// is the "no manifest published yet" declaration every producer returns this cycle. The manifest
// carries no Partiality (that is package plugin's per-run concern, and embedding it here would form
// an import cycle — see doc.go / §5); absence is the capability-local Supported bool.
func TestManifestHonestAbsence(t *testing.T) {
	var absent Manifest // zero value: Supported false, all axes nil
	if absent.Supported {
		t.Fatalf("zero-value Manifest.Supported = true, want false (honest-absence marker)")
	}
}
