package pythonanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

// outcome is the three-valued membership state of a requirement, so the C1 test can assert
// on all three DISTINCT outcomes — a test that only checked "absent" could not tell
// "excluded because the marker said so" from "dropped because the parser choked".
type outcome int

const (
	outcomeAbsent   outcome = iota // marker evaluated false → not selected
	outcomeSelected                // marker true (or none) → selected
	outcomePartial                 // marker referenced an unbound variable → unresolved
)

func (o outcome) String() string {
	switch o {
	case outcomeSelected:
		return "selected"
	case outcomePartial:
		return "partial"
	default:
		return "absent"
	}
}

func outcomeOf(r pyReq) outcome {
	switch {
	case r.Unresolved:
		return outcomePartial
	case r.Selected:
		return outcomeSelected
	default:
		return outcomeAbsent
	}
}

func resolveFixture(t *testing.T, dir string, env map[string]string, selection []string) map[string]pyReq {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	byName := make(map[string]pyReq)
	for _, r := range resolveRequirements(data, env, selection) {
		byName[r.Name] = r
	}
	return byName
}

// TestMarkersC1 asserts all three DISTINCT marker outcomes over the fixture, then a control
// that flips one row via python_version — proving the evaluator genuinely reads the
// descriptor rather than hardcoding membership (C1).
func TestMarkersC1(t *testing.T) {
	// Descriptor A: python_version 3.11, linux/posix. platform_machine intentionally unbound.
	envA := map[string]string{
		"python_version":      "3.11",
		"python_full_version": "3.11.4",
		"sys_platform":        "linux",
		"os_name":             "posix",
		"implementation_name": "cpython",
	}

	got := resolveFixture(t, "markers", envA, nil)

	// Every fixture line must produce a node (nothing silently dropped) — including the
	// marker-false one, whose presence-as-absent is what distinguishes evaluation from a drop.
	want := map[string]outcome{
		"pkg-pyver":    outcomeSelected, // 3.11 >= 3.8
		"pkg-plat":     outcomeAbsent,   // linux != win32
		"pkg-unbound":  outcomePartial,  // platform_machine unbound
		"pkg-bool":     outcomeSelected, // (3.11>=3.8 and linux==linux) or ...
		"pkg-in":       outcomeSelected, // "linux" in "linux"
		"pkg-full":     outcomeSelected, // 3.11.4 >= 3.11.0
		"pkg-reversed": outcomeSelected, // "3.8" <= 3.11
		"pkg-nomarker": outcomeSelected, // no marker
	}
	if len(got) != len(want) {
		t.Fatalf("node count %d, want %d (a dropped line is a silent omission, §3.1)", len(got), len(want))
	}
	for name, wantOutcome := range want {
		r, ok := got[name]
		if !ok {
			t.Errorf("%s: missing node (silently dropped)", name)
			continue
		}
		if o := outcomeOf(r); o != wantOutcome {
			t.Errorf("%s: outcome = %s, want %s", name, o, wantOutcome)
		}
	}

	// Assert all THREE distinct outcomes actually occur, so the table cannot pass by
	// collapsing two of them.
	seen := map[outcome]bool{}
	for _, o := range want {
		seen[o] = true
	}
	for _, o := range []outcome{outcomeSelected, outcomeAbsent, outcomePartial} {
		if !seen[o] {
			t.Fatalf("C1 requires all three distinct outcomes; %s not exercised", o)
		}
	}

	// The unbound partial must name the specific unbound variable in its declared partiality.
	if r := got["pkg-unbound"]; len(r.Partial) != 1 || r.Partial[0] != "env_condition_unresolved:platform_machine" {
		t.Errorf("pkg-unbound partiality = %v, want [env_condition_unresolved:platform_machine]", r.Partial)
	}

	// Control: bind python_version to 3.7 and confirm pkg-pyver's membership FLIPS
	// selected → absent (the evaluator reads the descriptor, not a hardcode).
	envB := map[string]string{
		"python_version":      "3.7",
		"python_full_version": "3.11.4",
		"sys_platform":        "linux",
		"os_name":             "posix",
		"implementation_name": "cpython",
	}
	gotB := resolveFixture(t, "markers", envB, nil)
	if o := outcomeOf(gotB["pkg-pyver"]); o != outcomeAbsent {
		t.Errorf("control: pkg-pyver under python_version=3.7 = %s, want absent (membership must flip)", o)
	}
	if o := outcomeOf(got["pkg-pyver"]); o != outcomeSelected {
		t.Errorf("control precondition: pkg-pyver under python_version=3.11 = %s, want selected", o)
	}
}

// TestEvaluateMarkerUnit exercises the pure evaluator directly across the operator surface,
// independent of the file parser.
func TestEvaluateMarkerUnit(t *testing.T) {
	env := map[string]string{
		"python_version":         "3.11",
		"python_full_version":    "3.11.4",
		"implementation_version": "3.11.4",
		"sys_platform":           "linux",
		"os_name":                "posix",
		"platform_system":        "Linux",
	}
	cases := []struct {
		name       string
		marker     string
		selection  []string
		selected   bool
		unresolved bool
		unboundVar string
	}{
		{name: "ge true", marker: `python_version >= "3.8"`, selected: true},
		{name: "lt false", marker: `python_version < "3.8"`, selected: false},
		{name: "eq compat tilde", marker: `python_version ~= "3.11"`, selected: true},
		{name: "ne true", marker: `sys_platform != "win32"`, selected: true},
		{name: "in true", marker: `"inux" in sys_platform`, selected: true},
		{name: "not in true", marker: `"win" not in sys_platform`, selected: true},
		{name: "and false", marker: `python_version >= "3.8" and sys_platform == "win32"`, selected: false},
		{name: "or true", marker: `python_version < "3.8" or os_name == "posix"`, selected: true},
		{name: "paren", marker: `(python_version < "3.8" or os_name == "posix") and sys_platform == "linux"`, selected: true},
		{name: "full version", marker: `python_full_version < "3.12.0"`, selected: true},
		{name: "impl version", marker: `implementation_version == "3.11.4"`, selected: true},
		{name: "unbound", marker: `platform_machine == "arm64"`, unresolved: true, unboundVar: "platform_machine"},
		{name: "unbound in or", marker: `os_name == "posix" or platform_machine == "arm64"`, unresolved: true, unboundVar: "platform_machine"},
		{name: "extra selected", marker: `extra == "socks"`, selection: []string{"socks"}, selected: true},
		{name: "extra not selected", marker: `extra == "socks"`, selection: []string{"security"}, selected: false},
		{name: "extra unbound nil selection", marker: `extra == "socks"`, selection: nil, unresolved: true, unboundVar: "extra"},
		{name: "malformed", marker: `python_version >= `, unresolved: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evaluateMarker(c.marker, env, c.selection)
			if got.selected != c.selected || got.unresolved != c.unresolved {
				t.Fatalf("evaluateMarker(%q) = %+v, want selected=%v unresolved=%v", c.marker, got, c.selected, c.unresolved)
			}
			if c.unboundVar != "" && got.unboundVar != c.unboundVar {
				t.Errorf("evaluateMarker(%q) unboundVar = %q, want %q", c.marker, got.unboundVar, c.unboundVar)
			}
		})
	}
}
