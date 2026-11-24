package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// upstreamDB is a three-entry v1 database: GO-1 aliased to the fixture's CVE, GO-2 listed by id, and
// GO-3 the fixture does not grade; GO-1 and GO-3 share a module.
func upstreamDB(t *testing.T) string {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"index/db.json": `{"modified":"2026-11-24T00:00:00Z"}`,
		"index/vulns.json": `[{"id":"GO-1","modified":"2026-01-02T00:00:00Z","aliases":["CVE-1","GHSA-1"]},
			{"id":"GO-2","modified":"2026-03-04T00:00:00Z"},
			{"id":"GO-3","modified":"2026-11-24T00:00:00Z","aliases":["CVE-3"]}]`,
		"index/modules.json": `[{"path":"example.com/a","vulns":[{"id":"GO-1","modified":"2026-01-02T00:00:00Z","fixed":"1.2.0"},{"id":"GO-3","modified":"2026-11-24T00:00:00Z"}]},
			{"path":"example.com/b","vulns":[{"id":"GO-2","modified":"2026-03-04T00:00:00Z"}]},
			{"path":"example.com/c","vulns":[{"id":"GO-3","modified":"2026-11-24T00:00:00Z"}]}]`,
		"ID/GO-1.json": `{"id":"GO-1","aliases":["CVE-1","GHSA-1"]}`,
		"ID/GO-2.json": `{"id":"GO-2"}`,
		"ID/GO-3.json": `{"id":"GO-3"}`,
	})
	return dir
}

// TestCutVulnDB pins the slice: exactly the entries whose id or an alias the fixture names, indexes
// covering only them, db.json dated by the latest kept entry, and no stale entry left from an earlier cut.
func TestCutVulnDB(t *testing.T) {
	src, err := newVulnDBSource(upstreamDB(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		names        []string
		wantIDs      []string
		wantModified string
		wantModules  map[string][]string
	}{
		{name: "by alias and by id", names: []string{"CVE-1", "GO-2", "CVE-unrelated"}, wantIDs: []string{"GO-1", "GO-2"},
			wantModified: "2026-03-04T00:00:00Z", wantModules: map[string][]string{"example.com/a": {"GO-1"}, "example.com/b": {"GO-2"}}},
		{name: "none graded", names: []string{"CVE-unrelated"}, wantIDs: []string{},
			wantModified: "0001-01-01T00:00:00Z", wantModules: map[string][]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			writeTree(t, out, map[string]string{"ID/GO-3.json": `{"id":"GO-3"}`}) // a previous cut's entry
			names := map[string]bool{}
			for _, n := range tt.names {
				names[n] = true
			}
			ids, err := cutVulnDB(context.Background(), src, names, out)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ids, tt.wantIDs) {
				t.Errorf("ids = %q, want %q", ids, tt.wantIDs)
			}
			ents, _ := os.ReadDir(filepath.Join(out, "ID"))
			var files []string
			for _, e := range ents {
				files = append(files, strings.TrimSuffix(e.Name(), ".json"))
			}
			if !slices.Equal(files, tt.wantIDs) && !(len(files) == 0 && len(tt.wantIDs) == 0) {
				t.Errorf("ID/ holds %q, want %q", files, tt.wantIDs)
			}
			var meta vulnDBMeta
			readJSON(t, filepath.Join(out, "index", "db.json"), &meta)
			if got := meta.Modified.Format("2006-01-02T15:04:05Z07:00"); got != tt.wantModified {
				t.Errorf("db.json modified = %s, want %s", got, tt.wantModified)
			}
			var mods []vulnDBModule
			readJSON(t, filepath.Join(out, "index", "modules.json"), &mods)
			if mods == nil {
				t.Error("modules.json is null, want a list")
			}
			got := map[string][]string{}
			for _, m := range mods {
				for _, v := range m.Vulns {
					got[m.Path] = append(got[m.Path], v.ID)
				}
			}
			if len(got) != len(tt.wantModules) {
				t.Errorf("modules = %v, want %v", got, tt.wantModules)
			}
			for p, want := range tt.wantModules {
				if !slices.Equal(got[p], want) {
					t.Errorf("module %s vulns = %q, want %q", p, got[p], want)
				}
			}
			if len(mods) > 0 && mods[0].Vulns[0].Fixed != "1.2.0" {
				t.Errorf("module vuln fixed = %q, want 1.2.0 carried over", mods[0].Vulns[0].Fixed)
			}
		})
	}
}

// TestCutVulnDBIdempotent pins that a slice cut from a slice is byte-identical, so re-cutting a
// committed slice (as a re-baseline does from a local database) moves no pin by itself.
func TestCutVulnDBIdempotent(t *testing.T) {
	names := map[string]bool{"CVE-1": true, "GO-2": true}
	first, second := t.TempDir(), t.TempDir()
	for _, c := range []struct{ from, out string }{{upstreamDB(t), first}, {first, second}} {
		src, err := newVulnDBSource(c.from)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cutVulnDB(context.Background(), src, names, c.out); err != nil {
			t.Fatal(err)
		}
	}
	a, err := treeDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := treeDigest(second); a != b {
		t.Errorf("a slice cut from a slice digests %s, the slice %s", b, a)
	}
}

func readJSON(t *testing.T, p string, v any) {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

// TestVerifyGoVulnDB pins the load-time check: a database inside the fixture, read as one by
// govulncheck, whose tree digest is the pin; and a digest that moves with any file's bytes or name.
func TestVerifyGoVulnDB(t *testing.T) {
	db := map[string]string{"index/db.json": `{}`, "index/modules.json": `[]`, "index/vulns.json": `[]`}
	fixture := t.TempDir()
	writeTree(t, fixture, map[string]string{"govulndb/index/db.json": db["index/db.json"],
		"govulndb/index/modules.json": db["index/modules.json"], "govulndb/index/vulns.json": db["index/vulns.json"],
		"nodb/index/db.json": `{}`})
	pin, err := treeDigest(filepath.Join(fixture, "govulndb"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		pf      PinnedFile
		wantErr string
	}{
		{name: "pinned", pf: PinnedFile{Path: "govulndb", SHA256: pin}},
		{name: "digest differs", pf: PinnedFile{Path: "govulndb", SHA256: strings.Repeat("0", 64)}, wantErr: "tree digest"},
		{name: "not a database", pf: PinnedFile{Path: "nodb", SHA256: pin}, wantErr: "not a govulncheck database"},
		{name: "outside the fixture", pf: PinnedFile{Path: "../x", SHA256: pin}, wantErr: "leaves its directory"},
		{name: "absent", pf: PinnedFile{Path: "missing", SHA256: pin}, wantErr: "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyGoVulnDB(fixture, tt.pf)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("verifyGoVulnDB: %v", err)
			case tt.wantErr == "" && got != filepath.Join(evalSymlinks(t, fixture), "govulndb"):
				t.Errorf("path = %s", got)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}

	other := t.TempDir()
	writeTree(t, other, map[string]string{"index/db.json": `{}`, "index/modules.json": `[]`, "index/vulns.json": `[ ]`})
	if d, _ := treeDigest(other); d == pin {
		t.Error("tree digest unchanged by a file's bytes")
	}
	renamed := t.TempDir()
	writeTree(t, renamed, map[string]string{"index/db.json": `{}`, "index/modules.json": `[]`, "index/vulns2.json": `[]`})
	if d, _ := treeDigest(renamed); d == pin {
		t.Error("tree digest unchanged by a file's name")
	}
}

func evalSymlinks(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestFixtureScanEnvGoVulnDB pins that a fixture's pinned database reaches the scan as
// ASSAY_GO_VULN_DB, and that a fixture without one sets nothing, so the scan reads vuln.go.dev.
func TestFixtureScanEnvGoVulnDB(t *testing.T) {
	base := []string{"PATH=/bin", "ASSAY_GO_VULN_DB=file:///caller"} // the caller's own is not inherited
	tests := []struct {
		name string
		path string
		want string
		set  bool
	}{
		{name: "pinned", path: "/fx/a b/govulndb", want: "file:///fx/a%20b/govulndb", set: true},
		{name: "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := fixtureScanEnv(base, Fixture{GoVulnDBPath: tt.path}, "/scanner")
			var vals []string
			for _, kv := range env {
				if v, ok := strings.CutPrefix(kv, goVulnDBEnv+"="); ok {
					vals = append(vals, v)
				}
			}
			switch {
			case tt.set && !slices.Equal(vals, []string{tt.want}):
				t.Errorf("%s = %q, want [%q]", goVulnDBEnv, vals, tt.want)
			case !tt.set && len(vals) != 0:
				t.Errorf("%s = %q, want unset", goVulnDBEnv, vals)
			}
		})
	}
}

// TestScenarioGoVulnDBLane pins that intel.govulndb is refused outside the go lane.
func TestScenarioGoVulnDBLane(t *testing.T) {
	s := Scenario{Schema: ScenarioSchema, Repo: "https://github.com/o/r", Commit: strings.Repeat("a", 40), Lang: "python",
		Intel: ScenarioIntel{Policy: "p", GoVulnDB: &PinnedFile{Path: "govulndb", SHA256: strings.Repeat("a", 64)}}}
	if err := s.validate(); err == nil || !strings.Contains(err.Error(), "go lane") {
		t.Errorf("validate = %v, want the go-lane refusal", err)
	}
}
