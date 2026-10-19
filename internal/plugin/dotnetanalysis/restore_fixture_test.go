package dotnetanalysis

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// restoredProject, as a fixture's App.csproj, asks composeILBuildDir for a project its
// obj/project.assets.json is a current restore of: trustRestore writes both.
var restoredProject = []byte("<!-- restored project -->")

// trustRestore rewrites dir's App.csproj to declare the frameworks and runtimes its
// obj/project.assets.json restores, and records in the assets file the project spec restore
// writes for that project, so AssetsTrusted holds. The project declares no package, so the
// spec's frameworks list none.
func trustRestore(t *testing.T, dir string) {
	t.Helper()
	assetsPath := filepath.Join(dir, "obj", "project.assets.json")
	data, err := os.ReadFile(assetsPath)
	if err != nil {
		t.Fatal(err)
	}
	var assets map[string]any
	if err := json.Unmarshal(data, &assets); err != nil {
		t.Fatal(err)
	}
	targets, _ := assets["targets"].(map[string]any)
	var aliases, rids []string
	for key := range targets {
		alias, rid, hasRID := strings.Cut(key, "/")
		if !slices.Contains(aliases, alias) {
			aliases = append(aliases, alias)
		}
		if hasRID && !slices.Contains(rids, rid) {
			rids = append(rids, rid)
		}
	}
	slices.Sort(aliases)
	slices.Sort(rids)
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(projectDeclaring(aliases, rids, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	assets["project"] = projectSpec(root, "App", aliases, rids, nil)
	out, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetsPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// projectDeclaring renders an SDK project file for the target frameworks and runtime
// identifiers given, holding items.
func projectDeclaring(tfms, rids []string, items string) string {
	var props bytes.Buffer
	if len(tfms) == 1 {
		props.WriteString("<TargetFramework>" + tfms[0] + "</TargetFramework>")
	} else {
		props.WriteString("<TargetFrameworks>" + strings.Join(tfms, ";") + "</TargetFrameworks>")
	}
	if len(rids) > 0 {
		props.WriteString("<RuntimeIdentifiers>" + strings.Join(rids, ";") + "</RuntimeIdentifiers>")
	}
	return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>` + props.String() + `</PropertyGroup>` + items + `</Project>`
}

// projectSpec is the "project" object restore writes into project.assets.json for the project
// <root>/<name>.csproj restored for tfms and rids, whose direct package references are deps
// (id → recorded range).
func projectSpec(root, name string, tfms, rids []string, deps map[string]string) map[string]any {
	restoreFws := make(map[string]any)
	fws := make(map[string]any)
	for _, tfm := range tfms {
		restoreFws[tfm] = map[string]any{"targetAlias": tfm, "projectReferences": map[string]any{}}
		fw := map[string]any{"targetAlias": tfm}
		if len(deps) > 0 {
			d := make(map[string]any)
			for _, id := range slices.Sorted(maps.Keys(deps)) {
				d[id] = map[string]any{"target": "Package", "version": deps[id]}
			}
			fw["dependencies"] = d
		}
		fws[tfm] = fw
	}
	path := filepath.Join(root, name+".csproj")
	spec := map[string]any{
		"version": "1.0.0",
		"restore": map[string]any{
			"projectUniqueName":        path,
			"projectName":              name,
			"projectPath":              path,
			"outputPath":               filepath.Join(root, "obj") + string(filepath.Separator),
			"projectStyle":             "PackageReference",
			"originalTargetFrameworks": tfms,
			"frameworks":               restoreFws,
		},
		"frameworks": fws,
	}
	if len(rids) > 0 {
		runtimes := make(map[string]any)
		for _, rid := range rids {
			runtimes[rid] = map[string]any{"#import": []any{}}
		}
		spec["runtimes"] = runtimes
	}
	return spec
}
