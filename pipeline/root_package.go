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
// grafana repository). Version is "" when the manifest declares none the scan can read; the
// advisory is still admitted on it, and the verdict gate reports the version as unresolved.
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
// root package. A Go advisory may be keyed at a package path inside the module; that path matches
// unless a nested module or a major-version suffix makes it a different module. Every other
// ecosystem matches by normalized name, and an advisory PURL of another type never matches.
func (r RootPackage) Matches(buildDir, module, coordinate, purl string) bool {
	if typ := purlEcosystem(purl); typ != "" && typ != r.PURLType {
		return false
	}
	if r.PURLType == "golang" {
		return goPathInModule(buildDir, r.Name, module)
	}
	return coordinate != "" && CanonicalName(r.PURLType, coordinate) == CanonicalName(r.PURLType, r.Name)
}

var goMajorSuffix = regexp.MustCompile(`^v[0-9]+$`)

// goPathInModule reports whether the Go import path p belongs to module mod as checked out in
// buildDir: p is mod itself, or a path under it that no nested go.mod claims and whose first
// element is not a major-version suffix (example.com/m/v2 is a different module from example.com/m).
func goPathInModule(buildDir, mod, p string) bool {
	if p == mod {
		return true
	}
	rest, ok := strings.CutPrefix(p, mod+"/")
	if !ok || rest == "" {
		return false
	}
	elems := strings.Split(rest, "/")
	if goMajorSuffix.MatchString(elems[0]) {
		return false
	}
	for i := range elems {
		if _, err := os.Stat(filepath.Join(buildDir, filepath.FromSlash(path.Join(elems[:i+1]...)), "go.mod")); err == nil {
			return false
		}
	}
	return true
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// CanonicalName returns the form under which two names of a package of PURL type purlType name the
// same package: a PyPI name normalized per PEP 503 (lowercase, each run of '-', '_' and '.' as one
// '-'), a NuGet id lowercased, and any other name as given. The PyPI and NuGet version resolvers
// compare names the same way.
func CanonicalName(purlType, name string) string {
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
	return RootPackage{PURLType: "npm", Name: pkg.Name, Version: pkg.Version}, true
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
			return RootPackage{PURLType: "pypi", Name: name, Version: version}, true
		}
		if name := py.Tool.Poetry.Name; name != "" {
			return RootPackage{PURLType: "pypi", Name: name, Version: py.Tool.Poetry.Version}, true
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
	if m := pyVersionAssign.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// setupCfgRootPackage reads [metadata] name/version from setup.cfg. A version given as an
// "attr:" or "file:" directive is not a literal and stays unresolved.
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
	if strings.Contains(version, ":") {
		version = ""
	}
	return RootPackage{PURLType: "pypi", Name: name, Version: version}, true
}

// mavenRootPackage reads pom.xml, inheriting groupId and version from <parent>. A version that
// still holds a ${…} reference after one level of <properties> substitution stays unresolved.
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
		Properties struct {
			Entries []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return RootPackage{}, false
	}
	group := strings.TrimSpace(firstNonEmpty(pom.GroupID, pom.Parent.GroupID))
	artifact := strings.TrimSpace(pom.ArtifactID)
	if group == "" || artifact == "" || strings.Contains(group+artifact, "${") {
		return RootPackage{}, false
	}
	props := map[string]string{}
	for _, e := range pom.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	version := strings.TrimSpace(firstNonEmpty(pom.Version, pom.Parent.Version))
	version = mavenPropertyRef.ReplaceAllStringFunc(version, func(ref string) string {
		if v, ok := props[ref[2:len(ref)-1]]; ok {
			return v
		}
		return ref
	})
	if strings.Contains(version, "${") {
		version = ""
	}
	return RootPackage{PURLType: "maven", Name: group + ":" + artifact, Version: version}, true
}

var mavenPropertyRef = regexp.MustCompile(`\$\{[^}]+\}`)

var (
	gradleRootName = regexp.MustCompile(`(?m)^\s*rootProject\.name\s*=\s*['"]([^'"]+)['"]`)
	gradleGroup    = regexp.MustCompile(`(?m)^\s*group\s*=\s*['"]([^'"]+)['"]`)
	gradleVersion  = regexp.MustCompile(`(?m)^\s*version\s*=\s*['"]([^'"]+)['"]`)
)

// gradleRootPackage reads group and version from the root build script and the project name from
// settings (else the directory name). A project with no literal group publishes no coordinate the
// scan can name.
func gradleRootPackage(buildDir string) (RootPackage, bool) {
	build := readFirst(buildDir, "build.gradle.kts", "build.gradle")
	group := submatch(gradleGroup, build)
	if group == "" {
		return RootPackage{}, false
	}
	name := submatch(gradleRootName, readFirst(buildDir, "settings.gradle.kts", "settings.gradle"))
	if name == "" {
		name = filepath.Base(filepath.Clean(buildDir))
	}
	version := submatch(gradleVersion, build)
	if version == "unspecified" {
		version = ""
	}
	return RootPackage{PURLType: "maven", Name: group + ":" + name, Version: version}, true
}

// nugetRootPackage reads the one project file at buildDir: PackageId, else AssemblyName, else the
// file name, and Version or VersionPrefix. A directory holding several projects has no single root.
func nugetRootPackage(buildDir string) (RootPackage, bool) {
	projects, _ := filepath.Glob(filepath.Join(buildDir, "*.csproj"))
	if len(projects) != 1 {
		return RootPackage{}, false
	}
	data, err := os.ReadFile(projects[0])
	if err != nil {
		return RootPackage{}, false
	}
	var proj struct {
		Groups []struct {
			PackageID     string `xml:"PackageId"`
			AssemblyName  string `xml:"AssemblyName"`
			Version       string `xml:"Version"`
			VersionPrefix string `xml:"VersionPrefix"`
		} `xml:"PropertyGroup"`
	}
	if err := xml.Unmarshal(data, &proj); err != nil {
		return RootPackage{}, false
	}
	var id, assembly, version string
	for _, g := range proj.Groups {
		id = firstNonEmpty(id, strings.TrimSpace(g.PackageID))
		assembly = firstNonEmpty(assembly, strings.TrimSpace(g.AssemblyName))
		version = firstNonEmpty(version, strings.TrimSpace(g.Version), strings.TrimSpace(g.VersionPrefix))
	}
	id = firstNonEmpty(id, assembly, strings.TrimSuffix(filepath.Base(projects[0]), ".csproj"))
	if strings.Contains(id, "$(") {
		return RootPackage{}, false
	}
	if strings.Contains(version, "$(") {
		version = ""
	}
	return RootPackage{PURLType: "nuget", Name: id, Version: version}, true
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
