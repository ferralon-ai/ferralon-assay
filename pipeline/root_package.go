package pipeline

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// RootPackage is the identity the scanned project itself publishes under: the package an advisory
// names when the repository IS the vulnerable package (an advisory against grafana scanned in the
// grafana repository). Version is set only when it is positively established as the version of the
// checked-out code (a Go module tag at HEAD, or a release version the manifest states outright in a
// declaration the reader fully models) and is "" otherwise; the advisory is still admitted on it,
// and the verdict gate reports the version as unresolved.
type RootPackage struct {
	// PURLType is the package URL type ("golang", "npm", "pypi", "maven", "nuget").
	PURLType string
	// Name is the name the ecosystem's advisories key the package by: the Go module path, the npm
	// or PyPI name, Maven groupId:artifactId, the NuGet package id.
	Name    string
	Version string
}

// ReadRootPackage reads the scanned project's own package identity from its manifest in buildDir.
// It reads only the project at buildDir; workspace members of a monorepo are not enumerated. It
// returns false when the manifest declares no publishable identity: no manifest, a private npm
// package, a Maven or Gradle project with no group.
func ReadRootPackage(ctx context.Context, buildDir, language string) (RootPackage, bool) {
	if buildDir == "" {
		return RootPackage{}, false
	}
	switch language {
	case checkout.LangGo:
		return goRootPackage(ctx, buildDir)
	case checkout.LangJS:
		return npmRootPackage(buildDir)
	case checkout.LangPython:
		return pypiRootPackage(buildDir)
	case checkout.LangJava, checkout.LangKotlin:
		if r, ok := mavenRootPackage(buildDir); ok {
			return r, true
		}
		return gradleRootPackage(buildDir)
	case checkout.LangDotNet:
		return nugetRootPackage(buildDir)
	}
	return RootPackage{}, false
}

// Matches reports whether an advisory package identity (as AffectedPackageKeys reads it) names the
// root package, and the version the root is known at for it. A Go advisory may be keyed at a package
// path inside the module; that path matches unless a nested module, a major-version suffix, or a
// module the project requires or replaces under its own path makes it a different module, and a
// path whose module the scan cannot tell apart from the root matches with no version. Every other
// ecosystem matches by normalized name, and an advisory PURL of another type never matches.
func (r RootPackage) Matches(buildDir, module, coordinate, purl string) (string, bool) {
	if typ := purlEcosystem(purl); typ != "" && typ != r.PURLType {
		return "", false
	}
	if r.PURLType == "golang" {
		switch goPathOwner(buildDir, r.Name, module) {
		case goOwnedByRoot:
			return r.Version, true
		case goOwnerAmbiguous:
			return "", true
		}
		return "", false
	}
	if coordinate != "" && normalizeRootName(r.PURLType, coordinate) == normalizeRootName(r.PURLType, r.Name) {
		return r.Version, true
	}
	return "", false
}

var goMajorSuffix = regexp.MustCompile(`^v[0-9]+$`)

type goOwner int

const (
	goOwnedElsewhere goOwner = iota
	goOwnedByRoot
	goOwnerAmbiguous
)

// goPathOwner reports which module owns the Go import path p, given that mod is the module the
// go.mod in buildDir declares. p is the root's when it is mod itself, or a path under it that no
// nested go.mod claims, whose first element is not a major-version suffix (example.com/m/v2 is a
// different module from example.com/m), and that no module go.mod requires or replaces claims. A
// longer module path go.sum records but go.mod does not name, or a go.mod that does not parse,
// leaves the owner ambiguous.
func goPathOwner(buildDir, mod, p string) goOwner {
	if p == mod {
		return goOwnedByRoot
	}
	rest, ok := strings.CutPrefix(p, mod+"/")
	if !ok || rest == "" {
		return goOwnedElsewhere
	}
	elems := strings.Split(rest, "/")
	if goMajorSuffix.MatchString(elems[0]) {
		return goOwnedElsewhere
	}
	for i := range elems {
		if _, err := os.Stat(filepath.Join(buildDir, filepath.FromSlash(path.Join(elems[:i+1]...)), "go.mod")); err == nil {
			return goOwnedElsewhere
		}
	}
	claims := func(m string) bool { return len(m) > len(mod) && (p == m || strings.HasPrefix(p, m+"/")) }
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return goOwnerAmbiguous
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return goOwnerAmbiguous
	}
	for _, r := range mf.Require {
		if claims(r.Mod.Path) {
			return goOwnedElsewhere
		}
	}
	for _, r := range mf.Replace {
		if claims(r.Old.Path) {
			return goOwnedElsewhere
		}
	}
	if sum, err := os.ReadFile(filepath.Join(buildDir, "go.sum")); err == nil {
		for _, line := range strings.Split(string(sum), "\n") {
			if f := strings.Fields(line); len(f) > 0 && claims(f[0]) {
				return goOwnerAmbiguous
			}
		}
	}
	return goOwnedByRoot
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

func normalizeRootName(purlType, name string) string {
	switch purlType {
	case "pypi":
		return pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
	case "nuget":
		return strings.ToLower(name)
	}
	return name
}

// goRootPackage reads the module path from go.mod. A Go module declares no version of its own, so
// the version is the semver tag at HEAD for this module (a nested module's tags carry its
// directory as a prefix), or "" when HEAD is not tagged.
func goRootPackage(ctx context.Context, buildDir string) (RootPackage, bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return RootPackage{}, false
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil || mf.Module == nil || mf.Module.Mod.Path == "" {
		return RootPackage{}, false
	}
	return RootPackage{PURLType: "golang", Name: mf.Module.Mod.Path, Version: goModuleTagAtHead(ctx, buildDir)}, true
}

func goModuleTagAtHead(ctx context.Context, dir string) string {
	prefix, err := gitOutput(ctx, dir, "rev-parse", "--show-prefix")
	if err != nil {
		return ""
	}
	tags, err := gitOutput(ctx, dir, "tag", "--points-at", "HEAD")
	if err != nil {
		return ""
	}
	var versions []string
	for _, t := range strings.Fields(tags) {
		if v, ok := strings.CutPrefix(t, prefix); ok && semver.IsValid(v) && semver.Build(v) == "" {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Slice(versions, func(i, j int) bool { return semver.Compare(versions[i], versions[j]) > 0 })
	return versions[0]
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

// npmRootPackage reads package.json. A private package is never published, so no advisory can be
// about it, whatever it is named.
func npmRootPackage(buildDir string) (RootPackage, bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "package.json"))
	if err != nil {
		return RootPackage{}, false
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Private bool   `json:"private"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Name == "" || pkg.Private {
		return RootPackage{}, false
	}
	return RootPackage{PURLType: "npm", Name: pkg.Name, Version: establishedVersion("npm", pkg.Version)}, true
}

var pyVersionAssign = regexp.MustCompile(`(?m)^__version__\s*(?::\s*str\s*)?=\s*['"]([^'"]+)['"]`)

// pypiRootPackage reads pyproject.toml ([project], then [tool.poetry]), falling back to setup.cfg
// [metadata]. A dynamic version is read from the file hatch's [tool.hatch.version] path names.
func pypiRootPackage(buildDir string) (RootPackage, bool) {
	var py struct {
		Project struct {
			Name    string   `toml:"name"`
			Version string   `toml:"version"`
			Dynamic []string `toml:"dynamic"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"poetry"`
			Hatch struct {
				Version struct {
					Path string `toml:"path"`
				} `toml:"version"`
			} `toml:"hatch"`
		} `toml:"tool"`
	}
	if _, err := toml.DecodeFile(filepath.Join(buildDir, "pyproject.toml"), &py); err == nil {
		if name := py.Project.Name; name != "" {
			version := py.Project.Version
			if version == "" && py.Tool.Hatch.Version.Path != "" {
				version = hatchVersion(buildDir, py.Tool.Hatch.Version.Path)
			}
			return RootPackage{PURLType: "pypi", Name: name, Version: establishedVersion("pypi", version)}, true
		}
		if name := py.Tool.Poetry.Name; name != "" {
			return RootPackage{PURLType: "pypi", Name: name, Version: establishedVersion("pypi", py.Tool.Poetry.Version)}, true
		}
	}
	return setupCfgRootPackage(buildDir)
}

func hatchVersion(buildDir, rel string) string {
	p := filepath.Join(buildDir, filepath.FromSlash(rel))
	if !strings.HasPrefix(p, filepath.Clean(buildDir)+string(filepath.Separator)) {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if m := pyVersionAssign.FindAllSubmatch(data, -1); len(m) == 1 {
		return string(m[0][1])
	}
	return ""
}

// setupCfgRootPackage reads [metadata] name/version from setup.cfg. A version given as an
// "attr:" or "file:" directive is not a literal and stays unresolved, as does any version when a
// setup.py beside it can pass setup() a different one.
func setupCfgRootPackage(buildDir string) (RootPackage, bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "setup.cfg"))
	if err != nil {
		return RootPackage{}, false
	}
	var name, version string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "metadata" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "name":
			name = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
	}
	if name == "" {
		return RootPackage{}, false
	}
	if _, err := os.Stat(filepath.Join(buildDir, "setup.py")); err == nil {
		version = ""
	}
	return RootPackage{PURLType: "pypi", Name: name, Version: establishedVersion("pypi", version)}, true
}

// mavenRootPackage reads pom.xml, inheriting groupId and version from <parent>. A version that
// holds a ${…} reference stays unresolved: CI-friendly versions (${revision}${changelist}) are set
// on the command line, and the defaults in <properties> are placeholders (999999-SNAPSHOT).
func mavenRootPackage(buildDir string) (RootPackage, bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "pom.xml"))
	if err != nil {
		return RootPackage{}, false
	}
	var pom struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Parent     struct {
			GroupID string `xml:"groupId"`
			Version string `xml:"version"`
		} `xml:"parent"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return RootPackage{}, false
	}
	group := strings.TrimSpace(firstNonEmpty(pom.GroupID, pom.Parent.GroupID))
	artifact := strings.TrimSpace(pom.ArtifactID)
	if group == "" || artifact == "" || strings.Contains(group+artifact, "${") {
		return RootPackage{}, false
	}
	version := strings.TrimSpace(firstNonEmpty(pom.Version, pom.Parent.Version))
	return RootPackage{PURLType: "maven", Name: group + ":" + artifact, Version: establishedVersion("maven", version)}, true
}

var gradleRootName = regexp.MustCompile(`(?m)^\s*rootProject\.name\s*=\s*['"]([^'"$]+)['"]`)

// gradleRootPackage reads group and version from the root build script and the project name from
// settings. A project with no literal top-level group, or no rootProject.name, publishes no
// coordinate the scan can name. The version is read only from a script nothing else in can set it:
// see gradleScript.
func gradleRootPackage(buildDir string) (RootPackage, bool) {
	script, ok := readGradleScript(readFirst(buildDir, "build.gradle.kts", "build.gradle"))
	if !ok || script.group == "" {
		return RootPackage{}, false
	}
	name := submatch(gradleRootName, readFirst(buildDir, "settings.gradle.kts", "settings.gradle"))
	if name == "" {
		return RootPackage{}, false
	}
	return RootPackage{PURLType: "maven", Name: script.group + ":" + name, Version: establishedVersion("maven", script.version)}, true
}

// gradleScript is what a root build script states outright at its top level.
type gradleScript struct {
	// group is the literal of the one top-level group assignment, or "".
	group string
	// version is the literal of the one top-level version assignment, and "" when there is none,
	// when version is named anywhere else in the script (a nested block, project.version, a plugin
	// declaration), or when the script has a plugins, allprojects, subprojects or configure block or
	// an apply: each can set the project version where this reader cannot see it.
	version string
}

var (
	gradleWord      = regexp.MustCompile(`\b(group|version|plugins|allprojects|subprojects|configure|apply)\b`)
	gradleAssignRHS = regexp.MustCompile(`^\s*=\s*(['"])`)
)

// readGradleScript reads a Groovy or Kotlin build script; ok is false when it does not lex.
func readGradleScript(src string) (gradleScript, bool) {
	code, depth, ok := maskGradle(src)
	if !ok {
		return gradleScript{}, false
	}
	var groups, versions []string
	versionNamed, opaque := 0, false
	for _, m := range gradleWord.FindAllStringIndex(code, -1) {
		word, top := code[m[0]:m[1]], depth[m[0]] == 0
		switch word {
		case "group", "version":
			if word == "version" {
				versionNamed++
			}
			lit, isLit := gradleLiteralAssign(src, code, m[0], m[1])
			if !top || !isLit {
				continue
			}
			if word == "group" {
				groups = append(groups, lit)
			} else {
				versions = append(versions, lit)
			}
		default:
			opaque = opaque || top
		}
	}
	var out gradleScript
	if len(groups) == 1 {
		out.group = groups[0]
	}
	if len(versions) == 1 && versionNamed == 1 && !opaque {
		out.version = versions[0]
	}
	return out, true
}

// gradleLiteralAssign reports whether the word at code[start:end] begins a statement assigning it
// one string literal with nothing after it, and returns the literal. An interpolating string comes
// back verbatim; establishedVersion rejects it.
func gradleLiteralAssign(src, code string, start, end int) (string, bool) {
	lineStart := strings.LastIndexAny(code[:start], "\n;") + 1
	if strings.TrimSpace(code[lineStart:start]) != "" {
		return "", false
	}
	m := gradleAssignRHS.FindStringSubmatchIndex(code[end:])
	if m == nil {
		return "", false
	}
	open := end + m[3] - 1
	closing := strings.IndexByte(code[open+1:], code[open])
	if closing < 0 {
		return "", false
	}
	closing += open + 1
	rest := code[closing+1:]
	if stop := strings.IndexAny(rest, "\n;"); stop >= 0 {
		rest = rest[:stop]
	}
	lit := src[open+1 : closing]
	if strings.TrimSpace(rest) != "" {
		return "", false
	}
	return lit, true
}

// maskGradle blanks comments and the contents of string literals in src (keeping the quotes and
// every offset), and gives the brace depth at each byte. ok is false when a comment or string does
// not close or the braces do not balance.
func maskGradle(src string) (string, []int, bool) {
	code := []byte(src)
	depth := make([]int, len(src))
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if code[k] != '\n' {
				code[k] = ' '
			}
		}
	}
	d := 0
	for i := 0; i < len(src); {
		depth[i] = d
		switch {
		case strings.HasPrefix(src[i:], "//"):
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				j = len(src) - i
			}
			blank(i, i+j)
			i += j
			continue
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				return "", nil, false
			}
			blank(i, i+2+j+2)
			i += 2 + j + 2
			continue
		case src[i] == '\'' || src[i] == '"':
			q := src[i : i+1]
			if strings.HasPrefix(src[i:], q+q+q) {
				q += q + q
			}
			j := i + len(q)
			for j < len(src) && !strings.HasPrefix(src[j:], q) {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				return "", nil, false
			}
			blank(i+len(q), j)
			for k := i; k < j+len(q); k++ {
				depth[k] = d
			}
			i = j + len(q)
			continue
		case src[i] == '{':
			d++
		case src[i] == '}':
			d--
			if d < 0 {
				return "", nil, false
			}
		}
		i++
	}
	return string(code), depth, d == 0
}

// nugetRootPackage reads the one project file at buildDir: PackageId, else AssemblyName, else the
// file name. The version is read only when the project states exactly one unconditioned Version (or,
// with none, one VersionPrefix) and no VersionSuffix, and no Directory.Build.targets beside it can
// set it after the project file is read. A directory holding several projects has no single root.
func nugetRootPackage(buildDir string) (RootPackage, bool) {
	projects, _ := filepath.Glob(filepath.Join(buildDir, "*.csproj"))
	if len(projects) != 1 {
		return RootPackage{}, false
	}
	data, err := os.ReadFile(projects[0])
	if err != nil {
		return RootPackage{}, false
	}
	type prop struct {
		Value     string `xml:",chardata"`
		Condition string `xml:"Condition,attr"`
	}
	var proj struct {
		Groups []struct {
			Condition     string `xml:"Condition,attr"`
			PackageID     string `xml:"PackageId"`
			AssemblyName  string `xml:"AssemblyName"`
			Version       []prop `xml:"Version"`
			VersionPrefix []prop `xml:"VersionPrefix"`
			VersionSuffix []prop `xml:"VersionSuffix"`
		} `xml:"PropertyGroup"`
	}
	if err := xml.Unmarshal(data, &proj); err != nil {
		return RootPackage{}, false
	}
	var id, assembly string
	var versions, prefixes []string
	conditioned, suffixed := false, false
	for _, g := range proj.Groups {
		id = firstNonEmpty(id, strings.TrimSpace(g.PackageID))
		assembly = firstNonEmpty(assembly, strings.TrimSpace(g.AssemblyName))
		for _, v := range g.Version {
			versions = append(versions, strings.TrimSpace(v.Value))
			conditioned = conditioned || g.Condition != "" || v.Condition != ""
		}
		for _, v := range g.VersionPrefix {
			prefixes = append(prefixes, strings.TrimSpace(v.Value))
			conditioned = conditioned || g.Condition != "" || v.Condition != ""
		}
		suffixed = suffixed || len(g.VersionSuffix) > 0
	}
	id = firstNonEmpty(id, assembly, strings.TrimSuffix(filepath.Base(projects[0]), ".csproj"))
	if strings.Contains(id, "$(") {
		return RootPackage{}, false
	}
	version := ""
	switch {
	case conditioned || suffixed:
	case len(versions) == 1:
		version = versions[0]
	case len(versions) == 0 && len(prefixes) == 1:
		version = prefixes[0]
	}
	if _, err := os.Stat(filepath.Join(buildDir, "Directory.Build.targets")); err == nil {
		version = ""
	}
	return RootPackage{PURLType: "nuget", Name: id, Version: establishedVersion("nuget", version)}, true
}

var (
	releaseVersion        = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)
	mavenReleaseQualifier = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+){0,3})[.-](RELEASE|Final|GA)$`)
)

// establishedVersion returns v when it is a release version a manifest can state as the version of
// the checked-out code, and "" otherwise: a snapshot, pre-release or development version, a
// placeholder a release tool rewrites (0.0.0, 999999), a reference, or anything else this does not
// model. Up to four numeric components; Maven may add a RELEASE, Final or GA qualifier.
func establishedVersion(purlType, v string) string {
	core := v
	if purlType == "maven" {
		if m := mavenReleaseQualifier.FindStringSubmatch(v); m != nil {
			core = m[1]
		}
	}
	if !releaseVersion.MatchString(core) {
		return ""
	}
	allZero := true
	for _, c := range strings.Split(core, ".") {
		if strings.Trim(c, "0") != "" {
			allZero = false
		}
		if len(c) >= 4 && strings.Trim(c, "9") == "" {
			return ""
		}
	}
	if allZero {
		return ""
	}
	return v
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func readFirst(dir string, names ...string) string {
	for _, n := range names {
		if data, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			return string(data)
		}
	}
	return ""
}

func submatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}
