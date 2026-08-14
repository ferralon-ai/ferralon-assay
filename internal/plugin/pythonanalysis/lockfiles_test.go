package pythonanalysis

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// lockParser is the selected-set parser for a captured lockfile format.
type lockParser func(data []byte, env map[string]string, selection []string) ([]pyReq, error)

var lockFormats = []struct {
	dir    string // testdata subdir
	file   string // lockfile name
	source string // expected pyReq.Source
	parse  lockParser
}{
	{dir: "pdm", file: "pdm.lock", source: "pdm.lock", parse: parsePDMLock},
	{dir: "uv", file: "uv.lock", source: "uv.lock", parse: parseUVLock},
}

func readLock(t *testing.T, dir, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, file))
	if err != nil {
		t.Fatalf("read %s/%s: %v", dir, file, err)
	}
	return data
}

func byNamePyReq(reqs []pyReq) map[string]pyReq {
	m := make(map[string]pyReq, len(reqs))
	for _, r := range reqs {
		m[r.Name] = r
	}
	return m
}

// TestLockfileFormatsC3 asserts both new formats parse into a non-empty resolved set with the
// format recorded as the node's resolver provenance, exact versions resolved, and hashes
// retained (not truncated).
func TestLockfileFormatsC3(t *testing.T) {
	for _, f := range lockFormats {
		t.Run(f.source, func(t *testing.T) {
			reqs, err := f.parse(readLock(t, f.dir, f.file), nil, nil)
			if err != nil {
				t.Fatalf("parse %s: %v", f.source, err)
			}
			if len(reqs) == 0 {
				t.Fatalf("%s: empty resolved set", f.source)
			}
			for _, r := range reqs {
				if r.Source != f.source {
					t.Errorf("%s: node %q resolver provenance = %q, want %q", f.source, r.Name, r.Source, f.source)
				}
				if !r.Resolved || r.Version == "" {
					t.Errorf("%s: node %q must carry an exact pinned version, got resolved=%v version=%q", f.source, r.Name, r.Resolved, r.Version)
				}
				if !r.Selected {
					t.Errorf("%s: locked node %q must be Selected", f.source, r.Name)
				}
			}
			// Hashes are retained from the lockfile, not discarded.
			if h := byNamePyReq(reqs)["markupsafe"].Hashes; len(h) == 0 {
				t.Errorf("%s: markupsafe hashes were dropped; want retained integrity data", f.source)
			}
		})
	}
}

// TestParentEdgesC4 asserts the positive control (a two-level chain: markupsafe's parent field
// names jinja2 and its classification is transitive; jinja2 is direct) for BOTH edge-bearing
// formats, plus the negative control: a flat requirements.txt expresses no relationship, so
// every node reads as unexpressed — never defaulted to direct.
func TestParentEdgesC4(t *testing.T) {
	for _, f := range lockFormats {
		t.Run("positive/"+f.source, func(t *testing.T) {
			reqs, err := f.parse(readLock(t, f.dir, f.file), nil, nil)
			if err != nil {
				t.Fatalf("parse %s: %v", f.source, err)
			}
			byName := byNamePyReq(reqs)

			ms, ok := byName["markupsafe"]
			if !ok {
				t.Fatalf("%s: transitive node markupsafe missing", f.source)
			}
			if ms.Relationship != relTransitive {
				t.Errorf("%s: markupsafe relationship = %s, want transitive", f.source, relKindName(ms.Relationship))
			}
			if !containsString(ms.Parents, "jinja2") {
				t.Errorf("%s: markupsafe.Parents = %v, want to name jinja2", f.source, ms.Parents)
			}
			if r := ms.relationshipReason(); r != "" {
				t.Errorf("%s: a classified node must carry no relationship_unexpressed partiality, got %q", f.source, r)
			}

			jn, ok := byName["jinja2"]
			if !ok {
				t.Fatalf("%s: direct node jinja2 missing", f.source)
			}
			if jn.Relationship != relDirect {
				t.Errorf("%s: jinja2 relationship = %s, want direct", f.source, relKindName(jn.Relationship))
			}
		})
	}

	// Negative control: a flat requirements.txt has no edge data. Every node must be
	// unexpressed (naming that in its partiality), NOT direct — otherwise a resolver that
	// hardcodes "direct" would pass the positive assertion on any flat input.
	t.Run("negative/requirements.txt", func(t *testing.T) {
		data := readLock(t, "flat", "requirements.txt")
		reqs := resolveRequirements(data, nil, nil)
		if len(reqs) == 0 {
			t.Fatalf("flat fixture produced no nodes")
		}
		for _, r := range reqs {
			if r.Relationship == relDirect {
				t.Errorf("%s: relationship defaulted to direct in a format with no edge data (C4 violation)", r.Name)
			}
			if r.Relationship != relUnexpressed {
				t.Errorf("%s: relationship = %s, want unexpressed", r.Name, relKindName(r.Relationship))
			}
			if got := r.relationshipReason(); got != plugin.PartialReasonRelationshipUnexpressed {
				t.Errorf("%s: relationshipReason = %q, want %q", r.Name, got, plugin.PartialReasonRelationshipUnexpressed)
			}
			if len(r.Parents) != 0 {
				t.Errorf("%s: flat node has parents %v, want none", r.Name, r.Parents)
			}
		}
	})
}

type expectedGroundTruth struct {
	Provenance string        `json:"provenance"`
	Resolver   string        `json:"resolver"`
	Packages   []expectedPkg `json:"packages"`
}

type expectedPkg struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Relationship string   `json:"relationship"`
	Parents      []string `json:"parents"`
}

// TestGroundTruthC6 compares the parser's selected set against the ground truth CAPTURED from
// the real resolver (testdata/<fmt>/expected.json, provenance-stamped), failing on any
// coordinate present in one and absent in the other and on any version mismatch — and, because
// the captured expectation also records the resolver's own edge classification, on any
// relationship/parent divergence.
func TestGroundTruthC6(t *testing.T) {
	for _, f := range lockFormats {
		t.Run(f.source, func(t *testing.T) {
			var exp expectedGroundTruth
			raw := readLock(t, f.dir, "expected.json")
			if err := json.Unmarshal(raw, &exp); err != nil {
				t.Fatalf("%s: parse expected.json: %v", f.source, err)
			}
			if exp.Provenance == "" {
				t.Fatalf("%s: expected.json carries no provenance line — captured ground truth must record its origin (C6)", f.source)
			}

			reqs, err := f.parse(readLock(t, f.dir, f.file), nil, nil)
			if err != nil {
				t.Fatalf("parse %s: %v", f.source, err)
			}
			got := byNamePyReq(reqs)

			// Every captured coordinate is present at the captured version + classification.
			seen := map[string]bool{}
			for _, want := range exp.Packages {
				seen[want.Name] = true
				r, ok := got[want.Name]
				if !ok {
					t.Errorf("%s: coordinate %q in ground truth but absent from resolved set", f.source, want.Name)
					continue
				}
				if r.Version != want.Version {
					t.Errorf("%s: %q version = %q, ground truth %q", f.source, want.Name, r.Version, want.Version)
				}
				if got := relKindName(r.Relationship); got != want.Relationship {
					t.Errorf("%s: %q relationship = %q, ground truth %q", f.source, want.Name, got, want.Relationship)
				}
				if !equalStrings(r.Parents, want.Parents) {
					t.Errorf("%s: %q parents = %v, ground truth %v", f.source, want.Name, r.Parents, want.Parents)
				}
			}
			// No coordinate resolved that the ground truth does not record.
			for name := range got {
				if !seen[name] {
					t.Errorf("%s: resolved coordinate %q absent from captured ground truth", f.source, name)
				}
			}
		})
	}
}

// TestLockfileDeterminismC7 resolves each lockfile many times in-process and asserts a
// byte-identical canonical encoding every time, then logs its sha256 for a cross-process diff.
// Go randomizes map iteration per range, so an unsorted parent map (or any map on the output
// path) would surface here within a few iterations.
func TestLockfileDeterminismC7(t *testing.T) {
	for _, f := range lockFormats {
		t.Run(f.source, func(t *testing.T) {
			data := readLock(t, f.dir, f.file)
			first := canonicalPyReqs(t, mustParse(t, f.parse, data))
			for i := 0; i < 64; i++ {
				if got := canonicalPyReqs(t, mustParse(t, f.parse, data)); got != first {
					t.Fatalf("%s: non-deterministic encoding at iteration %d", f.source, i)
				}
			}
			t.Logf("C7 %s canonical sha256=%x", f.source, sha256.Sum256([]byte(first)))
		})
	}
}

func mustParse(t *testing.T, parse lockParser, data []byte) []pyReq {
	t.Helper()
	reqs, err := parse(data, nil, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return reqs
}

func canonicalPyReqs(t *testing.T, reqs []pyReq) string {
	t.Helper()
	b, err := json.Marshal(reqs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestPDMEdgeMarkerReuse exercises the pdm-edge child extraction directly to prove it reuses
// the E1/E2 evaluator: a false marker deactivates the edge, an unbound marker keeps it active
// (never inferring a dependency's absence, §3.1), and extras on the requirement string do not
// derail the name extraction.
func TestPDMEdgeMarkerReuse(t *testing.T) {
	env := map[string]string{"sys_platform": "linux", "python_version": "3.11"}
	cases := []struct {
		name       string
		dep        string
		wantChild  string
		wantActive bool
	}{
		{name: "no marker", dep: "MarkupSafe>=2.0", wantChild: "markupsafe", wantActive: true},
		{name: "marker true", dep: `colorama>=0.4 ; sys_platform == "linux"`, wantChild: "colorama", wantActive: true},
		{name: "marker false", dep: `pywin32>=1 ; sys_platform == "win32"`, wantChild: "pywin32", wantActive: false},
		{name: "marker unbound stays active", dep: `foo>=1 ; platform_machine == "arm64"`, wantChild: "foo", wantActive: true},
		{name: "extras do not derail name", dep: `requests[socks]>=2.0`, wantChild: "requests", wantActive: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			child, active := pdmEdgeChild(c.dep, env, nil)
			if child != c.wantChild || active != c.wantActive {
				t.Fatalf("pdmEdgeChild(%q) = (%q, %v), want (%q, %v)", c.dep, child, active, c.wantChild, c.wantActive)
			}
		})
	}
}

// relKindName renders a relKind for assertion messages and ground-truth comparison.
func relKindName(k relKind) string {
	switch k {
	case relDirect:
		return "direct"
	case relTransitive:
		return "transitive"
	default:
		return "unexpressed"
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
