package jsanalysis

import (
	"path/filepath"
	"testing"
)

// TestBuildContext_ModuleMode asserts newBuildContext maps package.json's "type" field
// to the project-level module mode: "module" -> esm, absent/"commonjs" -> cjs (default).
func TestBuildContext_ModuleMode(t *testing.T) {
	cases := []struct {
		name string
		body string
		want moduleMode
	}{
		{"explicit module -> esm", `{"name":"m","type":"module"}`, moduleModeESM},
		{"explicit commonjs -> cjs", `{"name":"c","type":"commonjs"}`, moduleModeCJS},
		{"absent type -> cjs default", `{"name":"d"}`, moduleModeCJS},
		{"unknown type -> cjs default", `{"name":"u","type":"weird"}`, moduleModeCJS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePkg(t, dir, tc.body)
			bc := newBuildContext(dir)
			if bc.ModuleMode != tc.want {
				t.Errorf("ModuleMode = %q, want %q", bc.ModuleMode, tc.want)
			}
		})
	}
}

// TestBuildContext_RootsMissingPackage asserts a dir with no package.json yields the cjs
// default and the dir as the sole root — this artifact reports the resolution default,
// not partiality (BuildManifest owns declared partiality).
func TestBuildContext_RootsMissingPackage(t *testing.T) {
	dir := t.TempDir()
	bc := newBuildContext(dir)
	if bc.ModuleMode != moduleModeCJS {
		t.Errorf("ModuleMode = %q, want cjs default", bc.ModuleMode)
	}
	if len(bc.Roots) != 1 || bc.Roots[0] != dir {
		t.Errorf("Roots = %v, want [%q]", bc.Roots, dir)
	}
}

// TestBuildContext_WorkspaceRoots asserts a workspaces layout appends the declared
// member globs (joined to the build dir) to Roots, and that the extension fields
// stage 3 owns are left at their zero value.
func TestBuildContext_WorkspaceRoots(t *testing.T) {
	dir := "testdata/manifest-workspace"
	bc := newBuildContext(dir)
	wantGlob := filepath.Join(dir, "packages", "*")
	found := false
	for _, r := range bc.Roots {
		if r == wantGlob {
			found = true
		}
	}
	if bc.Roots[0] != dir {
		t.Errorf("Roots[0] = %q, want build dir %q", bc.Roots[0], dir)
	}
	if !found {
		t.Errorf("Roots = %v, want to contain declared member glob %q", bc.Roots, wantGlob)
	}
	// Stage-1 boundary: the stage-3 bundler extension fields stay zero.
	if bc.AliasMap != nil || bc.Defines != nil || bc.EntryPoints != nil || bc.ServerSideRoots != nil {
		t.Errorf("stage-3 extension fields must be zero at stage 1; got alias=%v defines=%v entry=%v server=%v",
			bc.AliasMap, bc.Defines, bc.EntryPoints, bc.ServerSideRoots)
	}
}
