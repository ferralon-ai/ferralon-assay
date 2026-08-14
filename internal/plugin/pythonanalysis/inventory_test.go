package pythonanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolveInventory runs ResolveInventory over a testdata build dir with the declared
// environment + selection, failing the test on a hard error.
func resolveInventory(t *testing.T, dir string, env map[string]string, selection []string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{
		BuildDir:  "testdata/" + dir,
		TargetEnv: env,
		Selection: selection,
	})
	if err != nil {
		t.Fatalf("ResolveInventory(%s): %v", dir, err)
	}
	return inv
}

func nodeByPURL(inv plugin.DependencyInventory, purl string) (plugin.DependencyNode, bool) {
	for _, n := range inv.Nodes {
		if n.PURL == purl {
			return n, true
		}
	}
	return plugin.DependencyNode{}, false
}

// TestInventoryEdgesC4 asserts C4 at the ASSEMBLED-inventory level for the two edge-bearing
// formats: the two-level chain surfaces as a DependencyEdge whose Parent names jinja2 and whose
// Child is markupsafe; markupsafe is transitive (Direct=false), jinja2 is direct (Direct=true).
// Then the negative control: a flat requirements.txt — a format with no edge data — yields nodes
// that are NOT defaulted to direct and whose Partiality carries relationship_unexpressed, with no
// edges. Without the negative control a resolver hardcoding "direct" passes the positive case.
func TestInventoryEdgesC4(t *testing.T) {
	for _, tc := range []struct{ dir, lock string }{
		{dir: "pdm", lock: "pdm.lock"},
		{dir: "uv", lock: "uv.lock"},
	} {
		t.Run("positive/"+tc.dir, func(t *testing.T) {
			inv := resolveInventory(t, tc.dir, nil, nil)

			jinja, ok := nodeByPURL(inv, "pkg:pypi/jinja2@3.1.2")
			if !ok {
				t.Fatalf("%s: jinja2 node missing", tc.dir)
			}
			if !jinja.Direct {
				t.Errorf("%s: jinja2 Direct=false, want true (root of the locked closure)", tc.dir)
			}
			ms, ok := nodeByPURL(inv, "pkg:pypi/markupsafe@3.0.3")
			if !ok {
				t.Fatalf("%s: markupsafe node missing", tc.dir)
			}
			if ms.Direct {
				t.Errorf("%s: markupsafe Direct=true, want false (transitive)", tc.dir)
			}
			if hasReason(ms.Partiality, plugin.PartialReasonRelationshipUnexpressed) {
				t.Errorf("%s: a classified node must not carry relationship_unexpressed", tc.dir)
			}

			// The edge names jinja2 -> markupsafe by node ID (scope#name).
			wantParent := tc.lock + "#jinja2"
			wantChild := tc.lock + "#markupsafe"
			found := false
			for _, e := range inv.Edges {
				if e.Parent == wantParent && e.Child == wantChild {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no edge %s -> %s; edges=%+v", tc.dir, wantParent, wantChild, inv.Edges)
			}
			// The edge endpoints must reference real node IDs.
			ids := map[string]bool{}
			for _, n := range inv.Nodes {
				ids[n.ID] = true
			}
			for _, e := range inv.Edges {
				if !ids[e.Parent] || !ids[e.Child] {
					t.Errorf("%s: edge %+v references a non-existent node ID", tc.dir, e)
				}
			}
		})
	}

	t.Run("negative/flat", func(t *testing.T) {
		inv := resolveInventory(t, "flat", nil, nil)
		if len(inv.Nodes) == 0 {
			t.Fatal("flat inventory produced no nodes")
		}
		if len(inv.Edges) != 0 {
			t.Errorf("flat requirements.txt has no edge data; want 0 edges, got %d", len(inv.Edges))
		}
		for _, n := range inv.Nodes {
			if n.Direct {
				t.Errorf("%s: Direct defaulted to true in a format with no edge data (C4 violation)", n.ID)
			}
			if !hasReason(n.Partiality, plugin.PartialReasonRelationshipUnexpressed) {
				t.Errorf("%s: missing relationship_unexpressed partiality; reasons=%v", n.ID, n.Partiality.Reasons)
			}
		}
	})
}

// TestInventoryMarkersC1 asserts ResolveInventory threads req.TargetEnv into the marker
// evaluator: a marker-false requirement is absent from the selected inventory (not a node), a
// marker referencing an unbound variable is present with an env_condition_unresolved:<var>
// partiality naming the variable, and a marker-true requirement is present. The control binds
// python_version so the version-valued row resolves through the shared pep440 comparator.
func TestInventoryMarkersC1(t *testing.T) {
	env := map[string]string{
		"python_version":      "3.11",
		"python_full_version": "3.11.6",
		"sys_platform":        "linux",
		"os_name":             "posix",
		// platform_machine intentionally unbound.
	}
	inv := resolveInventory(t, "markers", env, nil)

	if _, ok := nodeByPURL(inv, "pkg:pypi/pkg-pyver@1.0.0"); !ok {
		t.Error("marker-true pkg-pyver absent from selected inventory")
	}
	if _, ok := nodeByPURL(inv, "pkg:pypi/pkg-plat@1.0.0"); ok {
		t.Error("marker-false pkg-plat present; a false marker must exclude it from the selected set")
	}
	unbound, ok := nodeByPURL(inv, "pkg:pypi/pkg-unbound@1.0.0")
	if !ok {
		t.Fatal("marker-unbound pkg-unbound absent; an unbound marker must yield a partial node, never a drop")
	}
	if !hasReason(unbound.Partiality, plugin.PartialReasonEnvConditionUnresolved+":platform_machine") {
		t.Errorf("pkg-unbound partiality = %v, want env_condition_unresolved:platform_machine", unbound.Partiality.Reasons)
	}
}

// TestInventoryExtrasC2 asserts ResolveInventory threads req.Selection into extras resolution
// and records the selection that produced a node's inclusion as membership provenance (C2 (c)).
func TestInventoryExtrasC2(t *testing.T) {
	inv := resolveInventory(t, "extras", nil, []string{"security"})
	n, ok := nodeByPURL(inv, "pkg:pypi/pkg-extras@2.0.0")
	if !ok {
		t.Fatal("pkg-extras absent from inventory")
	}
	if n.Membership.Target != "security" {
		t.Errorf("pkg-extras Membership.Target = %q, want %q (the selection that produced inclusion)", n.Membership.Target, "security")
	}
}

// TestInventoryFailOpenC1 asserts the fail-open posture survives at the inventory layer: only an
// exact ==X.Y.Z pin resolves to a Version/PURL@version; the drop fixture's unpinned sources
// (VCS/URL/editable/include) become partial nodes carrying source_unpinned with an empty
// version, never fabricated to a concrete one, and are still present (never silently dropped).
func TestInventoryFailOpenC1(t *testing.T) {
	inv := resolveInventory(t, "drop", nil, nil)
	unpinned := 0
	for _, n := range inv.Nodes {
		if hasReason(n.Partiality, plugin.PartialReasonSourceUnpinned) {
			unpinned++
			if n.Version != "" {
				t.Errorf("%s: unpinned source carries a fabricated version %q", n.ID, n.Version)
			}
			if strings.Contains(n.PURL, "@") {
				t.Errorf("%s: unpinned source PURL carries a version: %q", n.ID, n.PURL)
			}
		}
	}
	if unpinned == 0 {
		t.Error("drop fixture produced no source_unpinned nodes; unpinned lines were dropped, not recovered")
	}
}

// TestInventoryDeterminismC7 resolves each fixture many times in-process and asserts a
// byte-identical canonical encoding of the WHOLE assembled inventory every time (Go randomizes
// map iteration per range, so any map on the output path surfaces within a few iterations),
// then logs its sha256 so two separate test-process runs can be diffed. No checked-in golden.
func TestInventoryDeterminismC7(t *testing.T) {
	for _, dir := range []string{"flat", "pdm", "uv", "markers", "extras", "drop"} {
		t.Run(dir, func(t *testing.T) {
			first := canonicalInventory(t, resolveInventory(t, dir, nil, nil))
			for i := 0; i < 64; i++ {
				if got := canonicalInventory(t, resolveInventory(t, dir, nil, nil)); got != first {
					t.Fatalf("%s: non-deterministic inventory encoding at iteration %d", dir, i)
				}
			}
			t.Logf("C7 inventory %s canonical sha256=%x", dir, sha256.Sum256([]byte(first)))
		})
	}
}

func canonicalInventory(t *testing.T, inv plugin.DependencyInventory) string {
	t.Helper()
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	return string(b)
}
