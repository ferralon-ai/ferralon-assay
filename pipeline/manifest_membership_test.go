package pipeline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// membershipStub models a plugin's advisory-path dependency read: present lists the coordinates
// the read contains; exhaustive is what the plugin vouches about absence (true only for a
// complete lockfile such as uv.lock; false for requirements-only or declared-only trees).
type membershipStub struct {
	plugin.StubPlugin
	lang       string
	present    map[string]bool
	exhaustive bool
	err        error
}

func (s membershipStub) Language() string { return s.lang }

func (s membershipStub) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	if s.err != nil {
		return plugin.DependencyVersionResult{}, s.err
	}
	res := plugin.DependencyVersionResult{Partiality: plugin.Complete(), Exhaustive: s.exhaustive}
	if s.present[req.Coordinate] {
		res.Found = true
		res.Match = plugin.ResolvedDependency{Coordinate: req.Coordinate, Source: "uv.lock"}
	}
	return res, nil
}

func TestResolveManifestMembership(t *testing.T) {
	pypi := func(names ...string) []PackageKey {
		var ks []PackageKey
		for _, n := range names {
			ks = append(ks, PackageKey{Ecosystem: "pypi", Name: n})
		}
		return ks
	}
	tests := []struct {
		name        string
		p           plugin.LanguagePlugin
		language    string
		keys        []PackageKey
		wantNil     bool
		wantPresent bool
		wantKnown   bool
	}{
		{"uv.lock, package absent", membershipStub{lang: "python", exhaustive: true}, "python", pypi("aiohttp"), false, false, true},
		{"requirements-only, package absent", membershipStub{lang: "python"}, "python", pypi("aiohttp"), false, false, false},
		{"package present (non-exhaustive read still proves presence)", membershipStub{lang: "python", present: map[string]bool{"jinja2": true}}, "python", pypi("jinja2"), false, true, true},
		{"second affected package present", membershipStub{lang: "python", exhaustive: true, present: map[string]bool{"b": true}}, "python", pypi("a", "b"), false, true, true},
		{"npm lock, package absent", membershipStub{lang: "js", exhaustive: true}, "js", []PackageKey{{Ecosystem: "npm", Name: "left-pad"}}, false, false, true},
		{"mixed-ecosystem advisory", membershipStub{lang: "python", exhaustive: true}, "python", []PackageKey{{Ecosystem: "pypi", Name: "a"}, {Ecosystem: "npm", Name: "a"}}, true, false, false},
		{"advisory ecosystem differs from plugin", membershipStub{lang: "python", exhaustive: true}, "python", []PackageKey{{Ecosystem: "npm", Name: "left-pad"}}, true, false, false},
		{"plugin language differs from detected", membershipStub{lang: "js", exhaustive: true}, "python", pypi("aiohttp"), true, false, false},
		{"go is not a membership ecosystem", membershipStub{lang: "go", exhaustive: true}, "go", []PackageKey{{Ecosystem: "golang", Name: "x"}}, true, false, false},
		{"plugin error", membershipStub{lang: "python", exhaustive: true, err: errors.New("boom")}, "python", pypi("aiohttp"), true, false, false},
		{"no affected packages", membershipStub{lang: "python", exhaustive: true}, "python", nil, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := resolveManifestMembership(context.Background(), tt.p, "/build", tt.language, tt.keys)
			if (m == nil) != tt.wantNil {
				t.Fatalf("membership = %+v, wantNil %v", m, tt.wantNil)
			}
			if m != nil && (m.Present != tt.wantPresent || m.Known != tt.wantKnown) {
				t.Fatalf("membership = %+v, want present=%v known=%v", m, tt.wantPresent, tt.wantKnown)
			}
		})
	}
}

// End to end through codebase_inventory and disqualification_discovery: a Python codebase whose
// complete lockfile proves the advisory's package absent is disqualified no_manifest_entry; a
// requirements-only codebase fails open; a present package proceeds.
func TestIntakeRun_PyPIManifestMembership(t *testing.T) {
	tests := []struct {
		name     string
		stub     membershipStub
		wantDisq bool
	}{
		{"uv.lock without the package", membershipStub{lang: "python", exhaustive: true}, true},
		{"requirements-only (manifestKnown=false)", membershipStub{lang: "python"}, false},
		{"package present", membershipStub{lang: "python", exhaustive: true, present: map[string]bool{"aiohttp": true}}, false},
		{"plugin cannot answer", membershipStub{lang: "python", exhaustive: true, err: errors.New("boom")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import aiohttp\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			src := selectionStubSource{facts: AdvisoryFacts{Coordinate: "aiohttp", PURL: "pkg:pypi/aiohttp"}}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-pypi-membership", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "PYSEC-TEST", Source: "corpus"},
				Codebase:      assessment.CodebaseRef{Repo: "acme/py", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir}},
			}}
			if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			err := (codebaseInventory{plugin: tt.stub, src: src}).Run(context.Background(), c, store)
			if tt.stub.err != nil {
				// A plugin error on the version read already fails the stage; the oracle adds no
				// verdict of its own. Exercise the oracle's own error path directly instead.
				if resolveManifestMembership(context.Background(), tt.stub, dir, "python", []PackageKey{{Ecosystem: "pypi", Name: "aiohttp"}}) != nil {
					t.Fatal("plugin error must yield no membership fact")
				}
				return
			}
			if err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}
			res := runDisqual(t, store, c.ID)
			if tt.wantDisq {
				if !res.Disqualified || res.Reason != ReasonNoManifestEntry {
					t.Fatalf("want disqualified/%s, got %+v", ReasonNoManifestEntry, res)
				}
				return
			}
			if res.Disqualified && res.Reason == ReasonNoManifestEntry {
				t.Fatalf("must not disqualify no_manifest_entry, got %+v", res)
			}
		})
	}
}

// The recorded fact is all the intake reads: Known=false never disqualifies, and a Go module
// still goes through go.mod regardless of any recorded fact.
func TestIntakeManifestMembership_PersistedFact(t *testing.T) {
	tests := []struct {
		name       string
		membership any
		wantDisq   bool
	}{
		{"known absent", map[string]any{"ecosystem": "npm", "coordinates": []string{"left-pad"}, "present": false, "known": true}, true},
		{"unknown absent", map[string]any{"ecosystem": "npm", "coordinates": []string{"left-pad"}, "present": false, "known": false}, false},
		{"present", map[string]any{"ecosystem": "npm", "coordinates": []string{"left-pad"}, "present": true, "known": true}, false},
		{"no fact recorded", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-npm-membership"
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{"vuln_id": "GHSA-TEST", "purl": "pkg:npm/left-pad"})
			inv := map[string]any{"language": "js", "build_dir": t.TempDir()}
			if tt.membership != nil {
				inv["manifest_membership"] = tt.membership
			}
			putJSON(t, store, caseID, artifact.TypeInventory, inv)
			res := runDisqual(t, store, caseID)
			if got := res.Disqualified && res.Reason == ReasonNoManifestEntry; got != tt.wantDisq {
				t.Fatalf("disqualified no_manifest_entry = %v, want %v (%+v)", got, tt.wantDisq, res)
			}
		})
	}
}
