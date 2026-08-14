package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
)

// These tests are the C1–C5 convergence criteria for the plugin-contract rework
// (PLAN-000). They observe the frozen field contract at the type level (C1), assert the
// eight §4.3 categories are expressible and distinguishable (C2), that DependencyInventory
// round-trips losslessly (C3), that encoding is deterministic across a repeat run (C4), and
// that ResolveInventory is honest where unimplemented (C5 scaffold).

// symbolType is the canonical Symbol struct type used by the C1 reflect walk.
var symbolType = reflect.TypeOf(Symbol{})

// TestSymbolThreadedThroughGraphTypes (C1) walks the declared symbol-carrying fields of the
// graph and index types and fails if any resolves to reflect.String instead of the canonical
// Symbol struct. This is the type-level guard that a later refactor cannot silently widen a
// Symbol field back to a bare string: a grep would not catch it, the reflect observation does.
// (Per convergence Amendment 2, SymbolIndexResult.Symbols is already []Symbol — included here
// as a read-site so the guard covers it too.)
func TestSymbolThreadedThroughGraphTypes(t *testing.T) {
	cases := []struct {
		typ    reflect.Type
		fields []string
	}{
		{reflect.TypeOf(CallEdge{}), []string{"Caller", "Callee"}},
		{reflect.TypeOf(Ingress{}), []string{"Symbol"}},
		{reflect.TypeOf(ReachPath{}), []string{"Sink", "Ingress", "Trace"}},
		{reflect.TypeOf(CallGraphResult{}), []string{"Roots"}},
		{reflect.TypeOf(SymbolIndexResult{}), []string{"Symbols"}},
	}
	for _, tc := range cases {
		for _, name := range tc.fields {
			f, ok := tc.typ.FieldByName(name)
			if !ok {
				t.Fatalf("%s has no field %q", tc.typ.Name(), name)
			}
			// Drill through a slice ([]Symbol) to its element type; a plain Symbol field
			// is used directly.
			ft := f.Type
			if ft.Kind() == reflect.Slice {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.String {
				t.Errorf("%s.%s resolves to reflect.String — symbol-carrying field must be Symbol, not a bare string", tc.typ.Name(), name)
				continue
			}
			if ft != symbolType {
				t.Errorf("%s.%s is %s, want plugin.Symbol", tc.typ.Name(), name, ft)
			}
		}
	}
}

// TestSymbolCategories (C2) hand-writes one Symbol per §4.3 category (field-contract.md §6)
// and asserts (a) exactly eight categories are present and (b) all are pairwise unequal under
// the type's own == equality. Comparable-struct Symbol makes == the equality; distinctness
// comes from the identity fields, so empty DisplayName/SCIP create no collisions.
func TestSymbolCategories(t *testing.T) {
	rows := []struct {
		category string
		sym      Symbol
	}{
		{"packages/modules", Symbol{Kind: SymbolKindPackage, Package: "github.com/x/y"}},
		{"types", Symbol{Kind: SymbolKindType, Package: "github.com/x/y", Name: "T"}},
		{"functions", Symbol{Kind: SymbolKindFunction, Package: "github.com/x/y", Name: "F"}},
		{"methods", Symbol{Kind: SymbolKindMethod, Package: "github.com/x/y", Enclosing: "T", Name: "M"}},
		{"constructors", Symbol{Kind: SymbolKindConstructor, Package: "github.com/x/y", Enclosing: "T", Name: "New"}},
		{"overloads/generics", Symbol{Kind: SymbolKindMethod, Package: "github.com/x/y", Enclosing: "T", Name: "M", Descriptor: "(int)"}},
		{"nested declarations", Symbol{Kind: SymbolKindType, Package: "github.com/x/y", Enclosing: "Outer", Name: "Inner"}},
		{"generated symbols", Symbol{Kind: SymbolKindFunction, Package: "github.com/x/y", Name: "F", Generated: true}},
	}

	// (a) exactly eight distinct §4.3 categories are represented.
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		seen[r.category] = true
	}
	if len(seen) != 8 {
		t.Fatalf("category count = %d, want 8 (§4.3 has eight categories)", len(seen))
	}

	// (b) all eight Symbol values are pairwise unequal under ==.
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[i].sym == rows[j].sym {
				t.Errorf("categories %q and %q collapse to the same Symbol value: %+v", rows[i].category, rows[j].category, rows[i].sym)
			}
		}
	}
}

// fullInventory builds a fully-populated DependencyInventory fixture: every field non-zero,
// two nodes, one parent edge, and one partial node. Shared by C3 (round-trip) and C4
// (determinism).
func fullInventory() DependencyInventory {
	return DependencyInventory{
		Partiality: Partial(PartialReasonToolFailure),
		Nodes: []DependencyNode{
			{
				ID:         "n1",
				PURL:       "pkg:golang/github.com/x/y@v1.2.3",
				Version:    "v1.2.3",
				Direct:     true,
				Membership: DependencyMembership{Project: "root", Workspace: "mono", Target: "runtime"},
				Artifact:   DependencyArtifact{Identity: "y-v1.2.3.zip", Digest: "sha256:aaaa"},
				Provenance: DependencyProvenance{Manifest: "go.mod", Lockfile: "go.sum", Resolver: "go mod", Runtime: "go1.21", Target: "linux/amd64"},
				Partiality: Complete(),
			},
			{
				ID:         "n2",
				PURL:       "pkg:golang/github.com/a/b@v0.4.0",
				Version:    "v0.4.0",
				Direct:     false,
				Membership: DependencyMembership{Project: "root", Workspace: "mono", Target: "test"},
				Artifact:   DependencyArtifact{Identity: "b-v0.4.0.zip", Digest: "sha512:bbbb"},
				Provenance: DependencyProvenance{Manifest: "go.mod", Lockfile: "go.sum", Resolver: "go mod", Runtime: "go1.21", Target: "linux/arm64"},
				Partiality: Partial(PartialReasonReflection),
			},
		},
		Edges: []DependencyEdge{{Parent: "n1", Child: "n2"}},
	}
}

// TestDependencyInventoryJSONRoundTrip (C3) marshals a fully-populated DependencyInventory,
// unmarshals it, and asserts reflect.DeepEqual against the original. A field added without a
// JSON tag, or tagged omitempty where its zero value is meaningful, fails this.
func TestDependencyInventoryJSONRoundTrip(t *testing.T) {
	orig := fullInventory()

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back DependencyInventory
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Errorf("DependencyInventory round-trip mismatch:\n orig = %+v\n back = %+v\n json = %s", orig, back, b)
	}
}

// TestEncodingIsByteIdenticalAcrossRuns (C4) encodes DependencyInventory, Symbol and
// BuildManifestResult ≥50 times in-process and asserts every encoding is byte-identical (Go
// randomizes map iteration PER iteration, so an in-process loop catches any map-order emission;
// these types carry no maps by construction). It also t.Logs a sha256 of each canonical
// encoding — run the test binary as two separate processes and diff the logged digests to prove
// cross-process determinism. There is deliberately no checked-in golden.
func TestEncodingIsByteIdenticalAcrossRuns(t *testing.T) {
	fixtures := map[string]any{
		"DependencyInventory": fullInventory(),
		"Symbol":              Symbol{Kind: SymbolKindMethod, Package: "github.com/x/y", Enclosing: "Outer.Inner", Name: "M", Descriptor: "(int)", Generated: true, DisplayName: "github.com/x/y.(*Outer.Inner).M", SCIP: "scip:x#M"},
		"BuildManifestResult": BuildManifestResult{
			Partiality:    Partial(PartialReasonNoManifest),
			Runtime:       RuntimeSpec{Name: "go", Version: "1.21", Toolchain: "go1.21.3"},
			Target:        "linux/amd64",
			Configuration: "release",
			ProjectRoot:   "github.com/x/y",
			Resolver:      ResolverSpec{Name: "go", Command: "go build ./..."},
		},
	}

	const runs = 64
	for name, v := range fixtures {
		first, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: Marshal: %v", name, err)
		}
		for i := 1; i < runs; i++ {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("%s: Marshal (run %d): %v", name, i, err)
			}
			if !bytes.Equal(first, b) {
				t.Fatalf("%s: encoding not byte-identical on run %d:\n first = %s\n   got = %s", name, i, first, b)
			}
		}
		t.Logf("C4 canonical-encoding sha256 %s = %x", name, sha256.Sum256(first))
	}
}

// isHonestlyUnsupported reports whether an inventory declares honest absence: NOT Complete and
// carrying PartialReasonUnsupported. This is the exact predicate C5's full five-plugin table
// (authored once the leaf agents land the four non-Go subprocess cases) asserts over every
// constructor; the negative control below proves it does not also accept a Complete() zero-node
// inventory, which would read downstream as "this build has no dependencies".
func isHonestlyUnsupported(inv DependencyInventory) bool {
	if inv.Partiality.Complete {
		return false
	}
	for _, r := range inv.Partiality.Reasons {
		if r == PartialReasonUnsupported {
			return true
		}
	}
	return false
}

// TestResolveInventoryHonestlyUnsupported (C5, scaffold) asserts the one honest-Unsupported
// data point observable in this package today: StubPlugin.ResolveInventory returns a
// declared-partial inventory (Complete=false, PartialReasonUnsupported), never an
// empty-but-successful one. The four non-Go plugins (js/java/python/dotnet) complete the full
// C5 constructor table once their leaf agents land the subprocess ResolveInventory case; those
// rows need real subprocess binaries and so live with the leaf migrations, not here.
func TestResolveInventoryHonestlyUnsupported(t *testing.T) {
	got, err := StubPlugin{}.ResolveInventory(context.Background(), ResolveInventoryRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("ResolveInventory: unexpected error: %v", err)
	}
	if !isHonestlyUnsupported(got) {
		t.Errorf("StubPlugin.ResolveInventory = %+v, want honest Unsupported (Complete=false, reason %q)", got.Partiality, PartialReasonUnsupported)
	}

	// Negative control: a Complete() inventory with zero nodes must NOT be classified as
	// honestly-unsupported. If this predicate accepted both, the assertion above would be
	// measuring nothing.
	empty := DependencyInventory{Partiality: Complete()}
	if isHonestlyUnsupported(empty) {
		t.Errorf("empty Complete() inventory classified as honestly-unsupported — the two shapes must be distinguishable")
	}
}
