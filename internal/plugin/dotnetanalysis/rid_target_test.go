package dotnetanalysis

// rid_target_test.go — packages restore resolves only in a runtime-specific target. A
// runtime.json can add a package to "<tfm>/<rid>" that the portable "<tfm>" target never
// lists, or resolve a different version there. A build produced for that runtime runs the
// "<tfm>/<rid>" graph, so those bytes are read, or named as a miss, never skipped.

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ridDep builds "Dep" declaring D.Sink.boom; withInit adds a module initializer calling it.
func ridDep(withInit bool) []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	var cctor []mspec
	boomRID := uint32(1)
	if withInit {
		boomRID = 2
		cctor = []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: body(ilCall(mtok(xMethodDef, boomRID)))}}
	}
	b.addType(0, "<Module>", "", 0, cctor)
	b.addType(0x1, "Sink", "D", obj, []mspec{{name: "boom", flags: 0x16, sig: sigStaticVoid, il: body()}})
	return b.bytesNamed("Dep")
}

// ridOnlyPkg builds "RidOnly", whose module initializer calls Dep's D.Sink.boom.
func ridOnlyPkg() []byte {
	b := scaffold()
	sink := b.extTypeRefScoped(b.asmRef("Dep"), "D", "Sink")
	boom := b.memberRef(sink, "boom", sigStaticVoid)
	b.addType(0, "<Module>", "", 0, []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: body(ilCall(boom))}})
	return b.bytesNamed("RidOnly")
}

var ridSinkSCIP = funcSCIP("D", []string{"Sink"}, "boom", 0)

func ridRow(pkgKey, dll, deps string) string {
	row := `"` + pkgKey + `":{"type":"package","runtime":{"` + dll + `":{}}`
	if deps != "" {
		row += `,"dependencies":{` + deps + `}`
	}
	return row + `}`
}

func TestReachability_RIDTargetOnlyPackages(t *testing.T) {
	const (
		depLib     = `"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"}`
		dep2Lib    = `"Dep/2.0.0":{"type":"package","path":"dep/2.0.0"}`
		ridOnlyLib = `"RidOnly/1.0.0":{"type":"package","path":"ridonly/1.0.0"}`
		depDLL     = "lib/net8.0/Dep.dll"
		ridOnlyDLL = "lib/net8.0/RidOnly.dll"
	)
	plainDep := ridRow("Dep/1.0.0", depDLL, "")
	ridOnly := ridRow("RidOnly/1.0.0", ridOnlyDLL, `"Dep":"1.0.0"`)
	tests := []struct {
		name      string
		targets   string // project.assets.json "targets" body
		libraries string
		pkgFiles  map[string][]byte
		buildRID  string // "" = portable deps.json
		alsoRID   string // a second runtime's copy of the build, beside buildRID's
		// wantSearched: the sink is listed as searched. wantPath: some path reaches it.
		wantSearched bool
		wantPath     bool
		wantScoped   map[string]string // purl -> reason
		wantReason   string            // a run-wide reason with no scope, "" for none
	}{
		{
			name:      "runtime-only package is read from the runtime target",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `,` + ridOnly + `}`,
			libraries: depLib + `,` + ridOnlyLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL:         ridDep(false),
				"ridonly/1.0.0/" + ridOnlyDLL: ridOnlyPkg(),
			},
			buildRID: "win-x64",
			wantPath: true,
		},
		{
			name:      "runtime-only package missing on disk is a named miss",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `,` + ridOnly + `}`,
			libraries: depLib + `,` + ridOnlyLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:     "win-x64",
			wantSearched: true,
			wantScoped:   map[string]string{"pkg:nuget/ridonly": partialReasonNoDependencyArtifact},
		},
		{
			name:      "runtime target's version shadows the portable one",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + ridRow("Dep/2.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + dep2Lib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
				"dep/2.0.0/" + depDLL: ridDep(true),
			},
			buildRID: "win-x64",
			wantPath: true,
		},
		{
			name:      "runtime unknown: a runtime-only package is a named miss",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `,` + ridOnly + `}`,
			libraries: depLib + `,` + ridOnlyLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL:         ridDep(false),
				"ridonly/1.0.0/" + ridOnlyDLL: ridOnlyPkg(),
			},
			wantSearched: true,
			wantScoped:   map[string]string{"pkg:nuget/ridonly": partialReasonRIDUnknown},
		},
		{
			name:      "runtime unknown: a shadowed package is a named miss, not the portable bytes",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + ridRow("Dep/2.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + dep2Lib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
				"dep/2.0.0/" + depDLL: ridDep(true),
			},
			wantScoped: map[string]string{"pkg:nuget/dep": partialReasonRIDUnknown},
		},
		{
			name: "runtime ambiguous: a runtime-only package is a named miss",
			targets: `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `,` + ridOnly + `},` +
				`"net8.0/linux-x64":{` + plainDep + `}`,
			libraries: depLib + `,` + ridOnlyLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL:         ridDep(false),
				"ridonly/1.0.0/" + ridOnlyDLL: ridOnlyPkg(),
			},
			buildRID:     "win-x64",
			alsoRID:      "linux-x64",
			wantSearched: true,
			wantScoped:   map[string]string{"pkg:nuget/ridonly": partialReasonRIDAmbiguous},
		},
		{
			name: "runtime unknown: a re-versioned package with no runtime assemblies keeps its portable bytes",
			targets: `"net8.0":{` + plainDep + `,` + ridOnly + `},"net8.0/win-x64":{` + plainDep +
				`,"RidOnly/2.0.0":{"type":"package","compile":{"lib/netstandard1.0/_._":{}},"dependencies":{"Dep":"1.0.0"}}}`,
			libraries: depLib + `,` + ridOnlyLib + `,"RidOnly/2.0.0":{"type":"package","path":"ridonly/2.0.0"}`,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL:         ridDep(false),
				"ridonly/1.0.0/" + ridOnlyDLL: ridOnlyPkg(),
			},
			wantPath: true,
		},
		{
			name:      "runtime known, restore wrote no runtime target",
			targets:   `"net8.0":{` + plainDep + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:   "linux-x64",
			wantReason: partialReasonRuntimeTargetAbsent,
		},
		{
			name:      "runtime known, restore wrote only another runtime's target",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:   "linux-x64",
			wantReason: partialReasonRuntimeTargetAbsent,
		},
		{
			name:      "runtime ambiguous, restore wrote no runtime target",
			targets:   `"net8.0":{` + plainDep + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:   "linux-x64",
			alsoRID:    "win-x64",
			wantReason: partialReasonRuntimeTargetAbsent,
		},
		{
			name: "runtime unknown: a runtime-only package with no assemblies is not a miss",
			targets: `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep +
				`,"RidMeta/1.0.0":{"type":"package","compile":{"lib/netstandard1.0/_._":{}}}}`,
			libraries: depLib + `,"RidMeta/1.0.0":{"type":"package","path":"ridmeta/1.0.0"}`,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			wantSearched: true,
		},
		{
			name:      "runtime target agrees with the portable one",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:     "win-x64",
			wantSearched: true,
		},
		{
			name:      "runtime unknown, runtime target agrees",
			targets:   `"net8.0":{` + plainDep + `},"net8.0/win-x64":{` + plainDep + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			wantSearched: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			assets := `{"version":3,"targets":{` + tt.targets + `},"libraries":{` + tt.libraries + `},` +
				`"packageFolders":{"` + pkgRoot + `/":{}}}`
			out := "bin/Release/net8.0/"
			if tt.buildRID != "" {
				out += tt.buildRID + "/"
			}
			files := map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(assets),
				out + "App.dll":           appMain(".NETCoreApp,Version=v8.0"),
				out + "App.deps.json":     depsJSON(tt.buildRID),
			}
			if tt.alsoRID != "" {
				also := "bin/Release/net8.0/" + tt.alsoRID + "/"
				files[also+"App.dll"] = appMain(".NETCoreApp,Version=v8.0")
				files[also+"App.deps.json"] = depsJSON(tt.alsoRID)
			}
			dir := composeILBuildDir(t, files)
			f := depFixture{buildDir: dir, pkgRoot: pkgRoot}
			for rel, data := range tt.pkgFiles {
				f.writePkgFile(t, rel, data)
			}

			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{ridSinkSCIP}})
			if err != nil {
				t.Fatal(err)
			}
			if hasILReason(res.Partiality, partialReasonRestoreUntrusted) {
				t.Fatalf("restore output untrusted, so every row below could pass for that reason: %v", res.Partiality.Reasons)
			}
			if got := slices.Contains(res.Searched, ridSinkSCIP); got != tt.wantSearched {
				t.Errorf("searched = %v, want %v (paths %d, partiality %+v)", got, tt.wantSearched, len(res.Paths), res.Partiality)
			}
			if got := len(res.Paths) > 0; got != tt.wantPath {
				t.Errorf("path = %v, want %v (partiality %+v)", got, tt.wantPath, res.Partiality)
			}
			scoped := map[string]string{}
			for _, s := range res.Partiality.Scoped {
				scoped[s.Package] = s.Reason
				if !hasILReason(res.Partiality, s.Reason) {
					t.Errorf("scoped %s (%s) has no run-wide reason: %v", s.Package, s.Reason, res.Partiality.Reasons)
				}
				if s.Targets == nil || !slices.Contains(s.Targets, s.Package) {
					t.Errorf("scoped %s targets = %v, want its bounded closure", s.Package, s.Targets)
				}
			}
			for purl, reason := range tt.wantScoped {
				if scoped[purl] != reason {
					t.Errorf("scoped[%s] = %q, want %q (all %v)", purl, scoped[purl], reason, scoped)
				}
			}
			if len(tt.wantScoped) == 0 && len(scoped) != 0 {
				t.Errorf("scoped = %v, want none", scoped)
			}
			if tt.wantReason != "" && !hasILReason(res.Partiality, tt.wantReason) {
				t.Errorf("reasons = %v, want %s", res.Partiality.Reasons, tt.wantReason)
			}
			if tt.wantReason == "" && hasILReason(res.Partiality, partialReasonRuntimeTargetAbsent) {
				t.Errorf("reasons = %v, want no %s", res.Partiality.Reasons, partialReasonRuntimeTargetAbsent)
			}
		})
	}
}

// ridDepWithoutSink builds a "Dep" whose code declares no D.Sink.boom.
func ridDepWithoutSink() []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0x1, "Other", "D", obj, []mspec{{name: "quiet", flags: 0x16, sig: sigStaticVoid, il: body()}})
	return b.bytesNamed("Dep")
}

func TestResolveDependencySymbols_RIDTarget(t *testing.T) {
	const (
		depLib  = `"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"}`
		dep2Lib = `"Dep/2.0.0":{"type":"package","path":"dep/2.0.0"}`
		depDLL  = "lib/net8.0/Dep.dll"
		other   = `"Other/1.0.0":{"type":"package","runtime":{"lib/net8.0/Other.dll":{}}}`
		otherLb = `"Other/1.0.0":{"type":"package","path":"other/1.0.0"}`
	)
	tests := []struct {
		name        string
		targets     string
		libraries   string
		pkgFiles    map[string][]byte
		buildRID    string
		alsoRID     string
		wantMatched bool
		wantScoped  string // reason scoped to pkg:nuget/dep, "" for none
	}{
		{
			name:      "runtime-only package resolves from the runtime target",
			targets:   `"net8.0":{` + other + `},"net8.0/win-x64":{` + other + `,` + ridRow("Dep/1.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + otherLb,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:    "win-x64",
			wantMatched: true,
		},
		{
			name:      "runtime-only package with the runtime unknown is a named miss",
			targets:   `"net8.0":{` + other + `},"net8.0/win-x64":{` + other + `,` + ridRow("Dep/1.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + otherLb,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			wantScoped: partialReasonRIDUnknown,
		},
		{
			name:      "runtime target's version is the one resolved",
			targets:   `"net8.0":{` + ridRow("Dep/1.0.0", depDLL, "") + `},"net8.0/win-x64":{` + ridRow("Dep/2.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + dep2Lib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDepWithoutSink(),
				"dep/2.0.0/" + depDLL: ridDep(false),
			},
			buildRID:    "win-x64",
			wantMatched: true,
		},
		{
			name:      "shadowed version with the runtime unknown is a named miss, not the portable bytes",
			targets:   `"net8.0":{` + ridRow("Dep/1.0.0", depDLL, "") + `},"net8.0/win-x64":{` + ridRow("Dep/2.0.0", depDLL, "") + `}`,
			libraries: depLib + `,` + dep2Lib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
				"dep/2.0.0/" + depDLL: ridDep(false),
			},
			wantScoped: partialReasonRIDUnknown,
		},
		{
			name:      "runtime known, restore wrote no runtime target",
			targets:   `"net8.0":{` + ridRow("Dep/1.0.0", depDLL, "") + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:    "linux-x64",
			wantMatched: true,
			wantScoped:  partialReasonRuntimeTargetAbsent,
		},
		{
			name:      "runtime known, restore wrote only another runtime's target",
			targets:   `"net8.0":{` + ridRow("Dep/1.0.0", depDLL, "") + `},"net8.0/win-x64":{` + ridRow("Dep/1.0.0", depDLL, "") + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:    "linux-x64",
			wantMatched: true,
			wantScoped:  partialReasonRuntimeTargetAbsent,
		},
		{
			name:      "runtime ambiguous, restore wrote no runtime target",
			targets:   `"net8.0":{` + ridRow("Dep/1.0.0", depDLL, "") + `}`,
			libraries: depLib,
			pkgFiles: map[string][]byte{
				"dep/1.0.0/" + depDLL: ridDep(false),
			},
			buildRID:    "linux-x64",
			alsoRID:     "win-x64",
			wantMatched: true,
			wantScoped:  partialReasonRuntimeTargetAbsent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			assets := `{"version":3,"targets":{` + tt.targets + `},"libraries":{` + tt.libraries + `},` +
				`"packageFolders":{"` + pkgRoot + `/":{}}}`
			out := "bin/Release/net8.0/"
			if tt.buildRID != "" {
				out += tt.buildRID + "/"
			}
			files := map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(assets),
				out + "App.dll":           appMain(".NETCoreApp,Version=v8.0"),
				out + "App.deps.json":     depsJSON(tt.buildRID),
			}
			if tt.alsoRID != "" {
				also := "bin/Release/net8.0/" + tt.alsoRID + "/"
				files[also+"App.dll"] = appMain(".NETCoreApp,Version=v8.0")
				files[also+"App.deps.json"] = depsJSON(tt.alsoRID)
			}
			dir := composeILBuildDir(t, files)
			f := depFixture{buildDir: dir, pkgRoot: pkgRoot}
			for rel, data := range tt.pkgFiles {
				f.writePkgFile(t, rel, data)
			}

			res, err := ResolveDependencySymbols(t.Context(), plugin.ResolveSymbolsRequest{
				BuildDir: dir, PURL: "pkg:nuget/Dep", AdvisorySymbols: []string{"D.Sink.boom"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if trusted, why := AssetsTrusted(dir, locateFirstPartyBuild(dir).assetsPath); !trusted {
				t.Fatalf("restore output untrusted (%s): the row does not model a restored project", why)
			}
			if got := len(res.Matched) == 1; got != tt.wantMatched {
				t.Errorf("matched = %v, want %v (resolved %d, partiality %+v)", res.Matched, tt.wantMatched, len(res.Resolved), res.Partiality)
			}
			if tt.wantScoped == "" {
				if !res.Partiality.Complete {
					t.Errorf("partiality = %+v, want complete", res.Partiality)
				}
				return
			}
			if !tt.wantMatched && len(res.Resolved) != 0 {
				t.Errorf("resolved %d symbols from bytes that may not run", len(res.Resolved))
			}
			var depReasons []string
			for _, s := range res.Partiality.Scoped {
				if s.Package == "pkg:nuget/dep" {
					depReasons = append(depReasons, s.Reason)
				}
			}
			if len(depReasons) != 1 || depReasons[0] != tt.wantScoped || !hasILReason(res.Partiality, tt.wantScoped) {
				t.Errorf("partiality = %+v, want only %s scoped to pkg:nuget/dep, and run-wide", res.Partiality, tt.wantScoped)
			}
		})
	}
}
