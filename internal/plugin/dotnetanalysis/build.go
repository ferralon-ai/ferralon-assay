package dotnetanalysis

// build.go — which first-party program a run analyzes, and which restore target its
// dependencies come from. Symbol resolution and the IL reachability tier both read through
// locateFirstPartyBuild, so they see the same assembly bound to the same target.
//
// One project and one entry assembly are supported. A build directory with more than one
// project file, or a project built for more than one target framework, is analyzed from the
// first one for candidate paths, but the run carries multiple_projects_unsupported and no
// sink is searched: the others were never traced.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// partialReasonMultipleProjects: the build holds more than one project or entry assembly, and
// only one was traced.
const partialReasonMultipleProjects = "multiple_projects_unsupported"

// partialReasonTargetUnbound: the first-party assembly could not be tied to exactly one
// restore target, so the dependency bytes read may not be the ones it runs against.
const partialReasonTargetUnbound = "reachability_undetermined:restore_target_unbound"

// firstPartyBuild is the first-party program a run analyzes.
type firstPartyBuild struct {
	project string             // project file; "" when the build has none
	fp      *assembly.Assembly // the built assembly; nil when not located or unreadable
	assets  []byte             // project.assets.json; nil when absent
	target  string             // the assets targets key fp binds to; "" when unbound or no assets
	reasons []string           // run-wide limits from the layout
}

// locateFirstPartyBuild finds the build's project, its built assembly and restore output,
// and binds the assembly to the restore target matching the framework it was compiled for.
func locateFirstPartyBuild(buildDir string) firstPartyBuild {
	var b firstPartyBuild
	projects := findProjectFiles(buildDir)
	if len(projects) == 0 {
		return b
	}
	b.project = projects[0]
	multiple := len(projects) > 1

	name := strings.TrimSuffix(filepath.Base(b.project), filepath.Ext(b.project))
	var fpTFM string
	entries := map[string]bool{}
	for _, path := range builtAssemblies(buildDir, name) {
		a, ok := assembly.ReadAssembly(path)
		if !ok || a == nil || a.Failed {
			entries["unreadable:"+path] = true
			continue
		}
		if a.IsReferenceAssembly() {
			continue // a ref/ copy of the build: a stub surface, not a program
		}
		tfm := assemblyTFM(a, path)
		entries[tfm] = true
		if b.fp == nil {
			b.fp, fpTFM = a, tfm
		}
	}
	if len(entries) > 1 {
		multiple = true
	}
	if multiple {
		b.reasons = append(b.reasons, partialReasonMultipleProjects)
	}

	data, ok := readAssetsFile(buildDir)
	if !ok {
		return b
	}
	b.assets = data
	if t, bound := bindTarget(assetsTargetKeys(data), fpTFM); bound {
		b.target = t
	} else {
		b.reasons = append(b.reasons, partialReasonTargetUnbound)
	}
	return b
}

// findProjectFiles returns every project file under buildDir, sorted.
func findProjectFiles(buildDir string) []string {
	var found []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no project; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".csproj", ".fsproj", ".vbproj":
			found = append(found, path)
		}
		return nil
	})
	sort.Strings(found)
	return found
}

// builtAssemblies returns every "<name>.dll" under buildDir/bin then buildDir/publish, each
// tree in lexical order: one per configuration, target framework and publish copy.
func builtAssemblies(buildDir, name string) []string {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return nil
	}
	want := name + ".dll"
	var out []string
	for _, sub := range []string{"bin", "publish"} {
		_ = filepath.WalkDir(filepath.Join(buildDir, sub), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable subtree yields no match; keep walking.
			}
			if !d.IsDir() && d.Name() == want {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

// assemblyTFM is the canonical framework a built assembly targets: its TargetFramework
// attribute, else the output directory's name (bin/Release/net8.0/App.dll). "" when neither
// names one.
func assemblyTFM(a *assembly.Assembly, path string) string {
	if s, ok := a.TargetFramework(); ok {
		if t, ok := canonicalTFM(s); ok {
			return t
		}
	}
	if t, ok := canonicalTFM(filepath.Base(filepath.Dir(path))); ok {
		return t
	}
	return ""
}

// assetsTargetKeys returns project.assets.json's targets keys.
func assetsTargetKeys(data []byte) []string {
	g := parseAssetsGraph(data)
	if g == nil {
		return nil
	}
	keys := make([]string, 0, len(g.targets))
	for k := range g.targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// bindTarget picks the restore target a build of framework tfm ran against. Runtime-specific
// keys ("net8.0/linux-x64") are not candidates. With tfm known, exactly one key must name the
// same framework; with tfm unknown, the restore must hold exactly one target.
func bindTarget(keys []string, tfm string) (string, bool) {
	var plain []string
	for _, k := range keys {
		if !strings.Contains(k, "/") {
			plain = append(plain, k)
		}
	}
	if tfm == "" {
		if len(plain) == 1 {
			return plain[0], true
		}
		return "", false
	}
	var match []string
	for _, k := range plain {
		if c, ok := canonicalTFM(k); ok && sameFramework(c, tfm) {
			match = append(match, k)
		}
	}
	if len(match) == 1 {
		return match[0], true
	}
	return "", false
}

// sameFramework compares canonical frameworks. A side without a platform ("netcoreapp|8.0",
// as the TargetFramework attribute spells net8.0-windows) matches any platform of the same
// framework and version; bindTarget's exactly-one rule rejects the resulting ambiguity.
func sameFramework(a, b string) bool {
	if a == b {
		return true
	}
	ab, ap, _ := strings.Cut(a, "#")
	bb, bp, _ := strings.Cut(b, "#")
	return ab == bb && (ap == "" || bp == "")
}

// canonicalTFM normalizes a target framework, in either the long form
// (".NETCoreApp,Version=v8.0") or the short folder form ("net8.0", "netcoreapp3.1",
// "netstandard2.0", "net472", "net8.0-windows"), to "identifier|version[#platform]".
func canonicalTFM(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if ident, rest, ok := strings.Cut(s, ",version="); ok {
		ident = strings.TrimPrefix(ident, ".")
		v, _, _ := strings.Cut(rest, ",")
		ver, ok := canonicalVersion(strings.TrimPrefix(v, "v"))
		if ident == "" || !ok {
			return "", false
		}
		return ident + "|" + ver, true
	}
	s, platform, _ := strings.Cut(s, "-")
	var ident, ver string
	switch {
	case strings.HasPrefix(s, "netcoreapp"):
		ident, ver = "netcoreapp", strings.TrimPrefix(s, "netcoreapp")
	case strings.HasPrefix(s, "netstandard"):
		ident, ver = "netstandard", strings.TrimPrefix(s, "netstandard")
	case strings.HasPrefix(s, "net"):
		ver = strings.TrimPrefix(s, "net")
		if major, _, dotted := strings.Cut(ver, "."); dotted {
			n, err := strconv.Atoi(major)
			if err != nil || n < 5 {
				return "", false
			}
			ident = "netcoreapp"
		} else {
			if ver == "" || strings.Trim(ver, "0123456789") != "" {
				return "", false
			}
			ident, ver = "netframework", strings.Join(strings.Split(ver, ""), ".")
		}
	default:
		return "", false
	}
	v, ok := canonicalVersion(ver)
	if !ok {
		return "", false
	}
	out := ident + "|" + v
	if platform != "" {
		out += "#" + platform
	}
	return out, true
}

// canonicalVersion renders a dotted numeric version with at least two components and no
// trailing zero components beyond them ("8" -> "8.0", "5.0.0" -> "5.0").
func canonicalVersion(v string) (string, bool) {
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
	}
	for len(parts) > 2 && strings.Trim(parts[len(parts)-1], "0") == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 1 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, "."), true
}
