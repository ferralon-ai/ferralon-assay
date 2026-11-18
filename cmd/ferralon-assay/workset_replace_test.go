package main

import (
	"context"
	"slices"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

const replaceBase = "module example.com/fixture\n\ngo 1.21.0\n\nrequire (\n\texample.com/m v1.0.0\n\texample.com/other v2.0.0+incompatible\n)\n\n"

// TestGoInventory_ReplaceDecidesTheVersion pins the version the work set queries for a module go.mod
// replaces: the version the build holds, which only a same-module replacement names. A fork or a
// directory holds no release's source, so the module is admitted by name and never queried at the
// require version.
func TestGoInventory_ReplaceDecidesTheVersion(t *testing.T) {
	other := report.Package{Ecosystem: ecosystemGo, Name: "example.com/other", Version: "v2.0.0+incompatible"}
	for _, tc := range []struct {
		name         string
		replace      string
		wantResolved []report.Package // example.com/m's entry, empty when unresolved
		wantNamed    bool
	}{
		{name: "no replace", replace: "", wantResolved: []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/m", Version: "v1.0.0"}}},
		{name: "same module, any version", replace: "replace example.com/m => example.com/m v1.5.0\n",
			wantResolved: []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/m", Version: "v1.5.0"}}},
		{name: "same module, exact left version", replace: "replace example.com/m v1.0.0 => example.com/m v1.5.0\n",
			wantResolved: []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/m", Version: "v1.5.0"}}},
		{name: "exact left version beats the wildcard", replace: "replace example.com/m => example.com/m v1.9.0\nreplace example.com/m v1.0.0 => example.com/m v1.5.0\n",
			wantResolved: []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/m", Version: "v1.5.0"}}},
		{name: "replace of another version leaves the require", replace: "replace example.com/m v0.9.0 => example.com/m v1.5.0\n",
			wantResolved: []report.Package{{Ecosystem: ecosystemGo, Name: "example.com/m", Version: "v1.0.0"}}},
		{name: "fork", replace: "replace example.com/m => example.com/fork v1.5.0\n", wantNamed: true},
		{name: "directory", replace: "replace example.com/m => ../m\n", wantNamed: true},
		{name: "fork at the exact version", replace: "replace example.com/m v1.0.0 => example.com/fork v1.5.0\n", wantNamed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, replaceBase+tc.replace)
			resolved, unresolved, _ := goDependencyInventory(context.Background(), acq)
			var gotM []report.Package
			for _, p := range resolved {
				if p.Name == "example.com/m" {
					gotM = append(gotM, p)
				}
			}
			if !slices.Equal(gotM, tc.wantResolved) {
				t.Errorf("resolved example.com/m = %+v, want %+v", gotM, tc.wantResolved)
			}
			named := slices.Contains(unresolved, report.Package{Ecosystem: ecosystemGo, Name: "example.com/m"})
			if named != tc.wantNamed {
				t.Errorf("example.com/m named unresolved = %v, want %v (unresolved %+v)", named, tc.wantNamed, unresolved)
			}
			if !slices.Contains(resolved, other) {
				t.Errorf("an unreplaced require is no longer resolved at its version: %+v", resolved)
			}
		})
	}
}

// rangeOSV answers like OSV: an advisory comes back only for a queried package whose version it
// affects, and a package with no version is not asked about.
type rangeOSV struct {
	name, introduced, fixed string
	id                      string
}

func (o rangeOSV) QueryBatch(_ context.Context, pkgs []report.Package) (trigger.OSVResult, error) {
	var res trigger.OSVResult
	for _, p := range pkgs {
		if p.Name == o.name && p.Version != "" && semver.Compare(p.Version, o.introduced) >= 0 && semver.Compare(p.Version, o.fixed) < 0 {
			res.Advisories = append(res.Advisories, trigger.OSVAdvisory{ID: o.id, Package: p})
		}
	}
	return res, nil
}

type idSource map[string]bool

func (s idSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	return pipeline.AdvisoryFacts{}, s[id]
}

// TestWorkSet_ReplacedModuleIsAdmittedAtTheBuiltVersion: go.mod requires v1.0.0 and replaces it with
// v1.5.0 of the same module; an advisory affecting [1.4.0, 1.6.0) is the build's, and must be
// admitted. A fork or directory replace is admitted by name, never by the require version.
func TestWorkSet_ReplacedModuleIsAdmittedAtTheBuiltVersion(t *testing.T) {
	osv := rangeOSV{name: "example.com/m", introduced: "v1.4.0", fixed: "v1.6.0", id: "GO-TEST-0001"}
	for _, tc := range []struct {
		name        string
		replace     string
		wantAdmit   bool
		wantNamedBy bool // unversioned disclosure names the module
	}{
		{name: "same module at a version in range", replace: "replace example.com/m => example.com/m v1.5.0\n", wantAdmit: true},
		{name: "same module at a version out of range", replace: "replace example.com/m => example.com/m v1.7.0\n"},
		{name: "no replace, require out of range", replace: ""},
		{name: "fork", replace: "replace example.com/m => example.com/fork v1.5.0\n", wantNamedBy: true},
		{name: "directory", replace: "replace example.com/m => ../m\n", wantNamedBy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, replaceBase+tc.replace)
			ws := resolveWorkSet(context.Background(), acq, osv, idSource{"GO-TEST-0001": true})
			admitted := slices.ContainsFunc(ws.advisories, func(a assessment.VulnRef) bool { return a.ID == "GO-TEST-0001" })
			if admitted != tc.wantAdmit {
				t.Errorf("GO-TEST-0001 admitted = %v, want %v", admitted, tc.wantAdmit)
			}
			if named := slices.Contains(ws.unversioned, "example.com/m"); named != tc.wantNamedBy {
				t.Errorf("example.com/m disclosed unversioned = %v, want %v", named, tc.wantNamedBy)
			}
		})
	}
}
