package dotnetanalysis

// Build 3c — the ecosystem-neutral BuildManifest for the .NET lane (PLAN-151).
//
// BuildManifest is invoked ONCE per BuildDir and returns ONE flat plugin.BuildManifestResult
// (5 scalar/small-struct fields — no per-project list, no property bag; PLAN-000 froze the shape).
// It reads the checkout LEXICALLY — .csproj/.fsproj/.vbproj, Directory.Build.props/.targets,
// global.json, and the PRESENCE of restore output (project.assets.json / packages.lock.json) —
// and NEVER runs dotnet/MSBuild/NuGet/restore/network. Where the flat shape cannot carry a fact
// (multi-TFM, multi-RID, multi-project, the analysis-decisive property residual, or a
// condition-gated value this pass cannot evaluate) it declares partiality naming the fact — it
// never overclaims Complete (inv.5). The deliverable-7 → frozen-type mapping and the 6-included /
// 3-excluded property set are the ratified PLAN-151 architecture deposit.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// msbuildPropsXML parses the property surface this cycle needs from a .csproj/.fsproj/.vbproj OR a
// Directory.Build.props/.targets file. It captures the 6 INCLUDED properties (analysis-decisive per
// the deposit's Deliverable 2) plus the PropertyGroup Condition attr for C4 condition-gating. The 3
// EXCLUDED candidates (Nullable, AssemblyName, RootNamespace) are deliberately ABSENT — they cannot
// change which code is compiled/analysed, so they never enter this parser.
type msbuildPropsXML struct {
	PropertyGroups []struct {
		Condition          string `xml:"Condition,attr"`
		Configuration      string `xml:"Configuration"`
		TargetFramework    string `xml:"TargetFramework"`
		TargetFrameworks   string `xml:"TargetFrameworks"`
		RuntimeIdentifier  string `xml:"RuntimeIdentifier"`
		RuntimeIdentifiers string `xml:"RuntimeIdentifiers"`
		DefineConstants    string `xml:"DefineConstants"`
		LangVersion        string `xml:"LangVersion"`
		OutputType         string `xml:"OutputType"`
	} `xml:"PropertyGroup"`
}

// propGroup is one flattened MSBuild PropertyGroup (its Condition plus the included property
// values). Emission ranges an ordered []propGroup, never a map (C3 determinism).
type propGroup struct {
	condition          string
	configuration      string
	targetFramework    string
	targetFrameworks   string
	runtimeIdentifier  string
	runtimeIdentifiers string
	defineConstants    string
	langVersion        string
	outputType         string
}

// BuildManifest derives the flat, ecosystem-neutral build manifest for one .NET BuildDir. It is
// pure lexical file reading; every unrepresentable fact becomes a declared partiality reason.
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	buildDir := req.BuildDir
	res := plugin.BuildManifestResult{
		Runtime:  plugin.RuntimeSpec{Name: "dotnet"},
		Resolver: plugin.ResolverSpec{Name: "dotnet", Command: "dotnet restore"},
	}
	var reasons []string

	// --- project / solution root identity (item 2) ---
	projPath, hasProject := findProjectFile(buildDir)
	sln, projects, isMulti := discoverWorkspace(buildDir)

	root := buildDir
	switch {
	case sln != "":
		root = filepath.Dir(sln)
	case hasProject:
		root = filepath.Dir(projPath)
	}
	res.ProjectRoot = relTo(buildDir, root)

	if !hasProject && sln == "" {
		reasons = mergeReasons(reasons, plugin.PartialReasonNoManifest)
	}

	// A real N-entry enumeration is a checkout/DetectLanguage rework (PLAN-400) and the plugin has
	// no write channel into WorkspacePlan; the flat result names the members as a declared reason.
	if isMulti && len(projects) >= 2 {
		memberRoots := make([]string, 0, len(projects))
		for _, p := range projects {
			memberRoots = append(memberRoots, relTo(buildDir, filepath.Dir(p)))
		}
		sort.Strings(memberRoots)
		detail := fmt.Sprintf("%s: %d member project(s): %s",
			reasonMultiProjectSolution, len(memberRoots), strings.Join(memberRoots, ", "))
		reasons = mergeReasons(reasons, reasonMultiProjectSolution, detail)
	}

	// --- property surface: primary project + Directory.Build.* walk-up (project overrides) ---
	var px projectXML
	var projGroups []propGroup
	if hasProject {
		if data, err := os.ReadFile(projPath); err == nil {
			_ = xml.Unmarshal(data, &px)
			var mx msbuildPropsXML
			if xml.Unmarshal(data, &mx) == nil {
				projGroups = propGroupsFrom(mx)
			}
		}
	}
	projDir := buildDir
	if hasProject {
		projDir = filepath.Dir(projPath)
	}
	dbGroups := loadDirectoryBuildProps(buildDir, projDir)
	groups := append(projGroups, dbGroups...) // project (nearest/highest) first, then walk-up.

	// --- TFM → Runtime.Version | multi-TFM partiality (item 4) ---
	tfms := projectTFMs(px)
	if len(tfms) == 0 {
		tfms = unconditionalValues(dbGroups,
			func(g propGroup) string { return g.targetFramework },
			func(g propGroup) string { return g.targetFrameworks })
	}
	tfmKnown := len(tfms) == 1
	selTFM := ""
	switch {
	case len(tfms) == 1:
		selTFM = tfms[0]
		res.Runtime.Version = tfms[0]
	case len(tfms) > 1:
		reasons = mergeReasons(reasons, reasonMultiTargetFramework)
	}

	// --- RID → Target | multi-RID partiality (item 5) ---
	rids := projectRIDs(px)
	if len(rids) == 0 {
		rids = unconditionalValues(dbGroups,
			func(g propGroup) string { return g.runtimeIdentifier },
			func(g propGroup) string { return g.runtimeIdentifiers })
	}
	switch {
	case len(rids) == 1:
		res.Target = rids[0] // a RID (e.g. linux-x64) IS the platform/architecture Target documents.
	case len(rids) > 1:
		reasons = mergeReasons(reasons, reasonNoRuntimeTarget)
	}
	// len(rids)==0 ⇒ Target empty: portable / RID-agnostic, an honest absence, not partiality.

	// --- Configuration (item 3); condition-gated ⇒ reasonUnevaluatedCondition (C4) ---
	cfg, cfgUneval := pickProperty(groups, func(g propGroup) string { return g.configuration }, selTFM, tfmKnown)
	switch {
	case cfgUneval:
		reasons = mergeReasons(reasons, reasonUnevaluatedCondition)
		res.Configuration = "Debug"
	case cfg != "":
		res.Configuration = cfg
	default:
		res.Configuration = "Debug" // MSBuild default; an honest default is not partiality.
	}

	// --- SDK toolchain pin from global.json (item 1) ---
	if v, ok := readGlobalJSONSDK(buildDir); ok && v != "" {
		res.Runtime.Toolchain = v // absent ⇒ empty via omitempty: an honest "no pin," not partiality.
	}

	// --- restore-artifact presence (item 6) ---
	_, hasAssets := findFile(buildDir, "project.assets.json", true)
	_, hasLock := findFile(buildDir, "packages.lock.json", true)
	if !hasAssets && !hasLock {
		reasons = mergeReasons(reasons, reasonNoLockfile)
	}

	// --- property residual with no frozen home (item 7): DefineConstants/LangVersion/OutputType ---
	anyUnhomed := false
	for _, sel := range []func(propGroup) string{
		func(g propGroup) string { return g.defineConstants },
		func(g propGroup) string { return g.langVersion },
		func(g propGroup) string { return g.outputType },
	} {
		v, uneval := pickProperty(groups, sel, selTFM, tfmKnown)
		if uneval {
			reasons = mergeReasons(reasons, reasonUnevaluatedCondition)
			anyUnhomed = true
		}
		if v != "" {
			anyUnhomed = true
		}
	}
	if anyUnhomed {
		reasons = mergeReasons(reasons, reasonPropertySetUnhomed)
	}

	if len(reasons) == 0 {
		res.Partiality = plugin.Complete()
	} else {
		res.Partiality = plugin.Partial(reasons...)
	}
	return res, nil
}

// pickProperty returns the winning value for one property under nearest-wins precedence, and
// whether that value is gated by a condition this cycle cannot evaluate. Groups are visited in
// precedence order (project first, then Directory.Build.* nearest→farthest): the first group that
// both sets the property and provably applies wins; if the nearest group that sets it is guarded by
// an unevaluable condition, the winning value is uncertain ⇒ (value="", unevaluated=true) — it is
// NEVER collapsed to that first match as Complete (C4).
func pickProperty(groups []propGroup, sel func(propGroup) string, tfm string, tfmKnown bool) (value string, unevaluated bool) {
	for _, g := range groups {
		v := strings.TrimSpace(sel(g))
		if v == "" {
			continue
		}
		applies, evaluable := condApplies(g.condition, tfm, tfmKnown)
		if !evaluable {
			return "", true
		}
		if applies {
			return v, false
		}
		// provably excluded for this TFM; keep looking.
	}
	return "", false
}

// condApplies evaluates the reachable-without-MSBuild subset of a Condition: an empty condition
// always applies; a TFM predicate is evaluated via the shared evalTFMCondition when the single TFM
// is known; anything else (unknown TFM, non-TFM predicate) is unevaluable.
func condApplies(cond, tfm string, tfmKnown bool) (applies, evaluable bool) {
	if strings.TrimSpace(cond) == "" {
		return true, true
	}
	if !tfmKnown {
		return true, false
	}
	return evalTFMCondition(cond, tfm)
}

// unconditionalValues collects the dedup+sorted values of a single-valued and a `;`-list property
// across only the UNCONDITIONAL groups (used for inherited TFM/RID defaults when the project sets
// none). A map dedups; the OUTPUT ranges the sorted slice (C3).
func unconditionalValues(groups []propGroup, single, multi func(propGroup) string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, g := range groups {
		if strings.TrimSpace(g.condition) != "" {
			continue
		}
		add(single(g))
		for _, v := range strings.Split(multi(g), ";") {
			add(v)
		}
	}
	sort.Strings(out)
	return out
}

// projectRIDs is the RID mirror of projectTFMs: the dedup+sorted RuntimeIdentifier(s) declared on a
// project. A map dedups; the output ranges the sorted slice (C3).
func projectRIDs(px projectXML) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, pg := range px.PropertyGroups {
		add(pg.RuntimeIdentifier)
		for _, r := range strings.Split(pg.RuntimeIdentifiers, ";") {
			add(r)
		}
	}
	sort.Strings(out)
	return out
}

func propGroupsFrom(mx msbuildPropsXML) []propGroup {
	out := make([]propGroup, 0, len(mx.PropertyGroups))
	for _, pg := range mx.PropertyGroups {
		out = append(out, propGroup{
			condition:          pg.Condition,
			configuration:      pg.Configuration,
			targetFramework:    pg.TargetFramework,
			targetFrameworks:   pg.TargetFrameworks,
			runtimeIdentifier:  pg.RuntimeIdentifier,
			runtimeIdentifiers: pg.RuntimeIdentifiers,
			defineConstants:    pg.DefineConstants,
			langVersion:        pg.LangVersion,
			outputType:         pg.OutputType,
		})
	}
	return out
}

// loadDirectoryBuildProps walks Directory.Build.props/.targets upward from projDir to (and
// including) buildDir, nearest-first, copying loadCPM's bounded walk. It reads ONLY via
// os.ReadFile/filepath and NEVER escapes buildDir (the HasPrefix guard is the bound).
func loadDirectoryBuildProps(buildDir, projDir string) []propGroup {
	var out []propGroup
	dir := projDir
	for {
		for _, name := range []string{"Directory.Build.props", "Directory.Build.targets"} {
			p := filepath.Join(dir, name)
			if data, err := os.ReadFile(p); err == nil {
				var mx msbuildPropsXML
				if xml.Unmarshal(data, &mx) == nil {
					out = append(out, propGroupsFrom(mx)...)
				}
			}
		}
		if dir == buildDir || !strings.HasPrefix(dir, buildDir) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// readGlobalJSONSDK reads the SDK version pin from global.json ({"sdk":{"version":"..."}}) if one is
// present under buildDir. A missing file is an honest "no pin" (ok=false), not partiality.
func readGlobalJSONSDK(buildDir string) (string, bool) {
	path, ok := findFile(buildDir, "global.json", false)
	if !ok {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var g struct {
		SDK struct {
			Version string `json:"version"`
		} `json:"sdk"`
	}
	if json.Unmarshal(data, &g) != nil {
		return "", false
	}
	return strings.TrimSpace(g.SDK.Version), true
}
