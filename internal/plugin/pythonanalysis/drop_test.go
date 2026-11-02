package pythonanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// countRequirementLines counts the non-blank, non-comment lines in a requirements fixture —
// the "line count" the drop test asserts node count against.
func countRequirementLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	n := 0
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

// TestDropRecoveryC3 asserts that no requirement line is silently omitted: each one becomes
// a node, or is recorded as the include or local install it is (node count + recorded lines
// == line count). A line that names no PyPI project becomes no node. Deleting any one
// branch (or reverting it to a `continue`) drops that line and fails the count — the C3
// control.
func TestDropRecoveryC3(t *testing.T) {
	path := filepath.Join("testdata", "drop", "requirements.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rf := parseRequirementsFile(data, nil, nil)
	nodes := rf.reqs

	lineCount := countRequirementLines(t, path)
	if got := len(nodes) + len(rf.includes) + len(rf.locals); got != lineCount {
		t.Fatalf("nodes+includes+locals %d != line count %d — a dropped line is a silent omission (§3.1)", got, lineCount)
	}
	if !reflect.DeepEqual(rf.includes, []string{"other-requirements.txt"}) {
		t.Errorf("includes = %q, want [other-requirements.txt]", rf.includes)
	}
	if !reflect.DeepEqual(rf.locals, []string{"./localpkg"}) {
		t.Errorf("locals = %q, want [./localpkg]", rf.locals)
	}
	if rf.unnamed {
		t.Error("unnamed = true; every install line in the fixture names its project or is local")
	}

	// Each named shape must be present with the right kind and partiality. Keyed by Name so
	// the assertions do not depend on slice order.
	byName := make(map[string]pyReq, len(nodes))
	for _, n := range nodes {
		byName[n.Name] = n
	}

	checks := []struct {
		name         string
		wantKind     reqKind
		wantUnpinned bool // carries source_unpinned partiality
	}{
		{name: "foo", wantKind: reqVCS, wantUnpinned: true}, // #egg=foo
		{name: "bar", wantKind: reqURL, wantUnpinned: true}, // the wheel filename names bar
		{name: "baz", wantKind: reqNormal, wantUnpinned: false},
	}
	for _, c := range checks {
		r, ok := byName[c.name]
		if !ok {
			t.Errorf("%s: missing node (line was dropped)", c.name)
			continue
		}
		if r.Kind != c.wantKind {
			t.Errorf("%s: kind = %d, want %d", c.name, r.Kind, c.wantKind)
		}
		if got := containsString(r.Partial, plugin.PartialReasonSourceUnpinned); got != c.wantUnpinned {
			t.Errorf("%s: source_unpinned partiality = %v, want %v", c.name, got, c.wantUnpinned)
		}
		// A source node is still Selected (the dependency IS installed; only its version is
		// unpinned) — never silently excluded.
		if c.wantKind != reqNormal && !r.Selected {
			t.Errorf("%s: source node must be Selected (installed but unpinned)", c.name)
		}
	}

	// The --hash tokens are retained (declared order), not truncated.
	baz := byName["baz"]
	if !baz.Resolved || baz.Version != "1.0.0" {
		t.Errorf("baz: want resolved 1.0.0, got resolved=%v version=%q", baz.Resolved, baz.Version)
	}
	wantHashes := []string{
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if len(baz.Hashes) != len(wantHashes) {
		t.Fatalf("baz: hashes = %v, want %v", baz.Hashes, wantHashes)
	}
	for i, h := range wantHashes {
		if baz.Hashes[i] != h {
			t.Errorf("baz: hash[%d] = %q, want %q", i, baz.Hashes[i], h)
		}
	}
}
