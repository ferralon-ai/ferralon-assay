package pythonanalysis

import (
	"reflect"
	"testing"
)

func TestParseInterpreterRange(t *testing.T) {
	cases := []struct {
		spec     string
		releases []int
		newer    bool
		ok       bool
	}{
		{spec: ">=3.12", releases: []int{312, 313, 314}, newer: true, ok: true},
		{spec: "==3.8.*", releases: []int{308}, ok: true},
		{spec: ">=3.8, <3.12", releases: []int{308, 309, 310, 311}, ok: true},
		{spec: "~=3.10", releases: []int{310, 311, 312, 313, 314}, newer: true, ok: true},
		{spec: ">3.12", releases: []int{312, 313, 314}, newer: true, ok: true},
		{spec: "==3.11.4", releases: []int{311}, ok: true},
		{spec: ">=3.9,!=3.10.*", releases: []int{309, 311, 312, 313, 314}, newer: true, ok: true},
		{spec: ">=2.7,!=3.0.*,!=3.1.*,<3.4", releases: []int{207, 302, 303}, ok: true},
		{spec: ">=3.15", newer: true, ok: true},
		{spec: "3.11", releases: []int{311}, ok: true},
		{spec: "3.11.2", releases: []int{311}, ok: true},
		{spec: "==2.6.*"},
		{spec: "3.8 or newer"},
		{spec: "pypy3.10"},
		{spec: ">=3.12,<3.8"},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			r, ok := parseInterpreterRange(c.spec)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (range %+v)", ok, c.ok, r)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(r.releases, c.releases) || r.newer != c.newer {
				t.Errorf("range = %v newer=%v, want %v newer=%v", r.releases, r.newer, c.releases, c.newer)
			}
		})
	}
}

func TestInterpreterRangeShips(t *testing.T) {
	cases := []struct {
		name  string
		r     interpreterRange
		top   string
		ships bool
	}{
		{"every release ships it", anyInterpreter, "os", true},
		{"removed before a release the range admits", interpreterRange{releases: []int{311, 312}}, "asyncore", false},
		{"every admitted release ships it", interpreterRange{releases: []int{308, 309, 310, 311}}, "asyncore", true},
		{"added after a release the range admits", interpreterRange{releases: []int{308, 309}}, "graphlib", false},
		{"open-ended module on newer releases", interpreterRange{releases: []int{314}, newer: true}, "graphlib", true},
		{"removed module on newer releases only", interpreterRange{newer: true}, "asyncore", false},
		{"gap between runs", interpreterRange{releases: []int{207, 301}}, "argparse", false},
		{"both runs", interpreterRange{releases: []int{207, 302, 303}}, "argparse", true},
		{"not a standard-library module", anyInterpreter, "othermod", false},
		{"assumed interpreter ships what 3.8 on ship", assumedInterpreter, "dataclasses", true},
		{"assumed interpreter lacks what 3.8 lacks", assumedInterpreter, "tomllib", false},
		{"assumed interpreter lacks what 3.12 dropped", assumedInterpreter, "distutils", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.ships(c.top); got != c.ships {
				t.Errorf("ships(%q) = %v, want %v", c.top, got, c.ships)
			}
		})
	}
}

// TestUndeclaredImport_CuratedNameExcludedOnlyWithOneShipper: a curated name exactly one
// distribution provides is attributed on its own; a name several provide needs one of them,
// or a distribution of its own name, declared.
func TestUndeclaredImport_CuratedNameExcludedOnlyWithOneShipper(t *testing.T) {
	curated := func(dists ...string) DistImportMap {
		var cs []Contribution
		for _, d := range dists {
			cs = append(cs, Contribution{
				Distribution:  d,
				ImportPackage: "sharedpkg",
				Provenance:    ProvenanceCurated,
				Source:        "test fixture",
				Date:          "2026-10-12",
			})
		}
		return NewDistImportMap(cs...)
	}
	cases := []struct {
		name       string
		dists      []string
		declared   map[string]bool
		undeclared bool
	}{
		{"one shipper, undeclared", []string{"shared-a"}, nil, false},
		{"two shippers, neither declared", []string{"shared-a", "shared-b"}, nil, true},
		{"two shippers, top declared by name", []string{"shared-a", "shared-b"}, map[string]bool{"sharedpkg": true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := distResolver{curated: curated(c.dists...), declared: c.declared, python: assumedInterpreter}
			if got := d.undeclaredImport("sharedpkg"); got != c.undeclared {
				t.Errorf("undeclaredImport = %v, want %v", got, c.undeclared)
			}
		})
	}
}
