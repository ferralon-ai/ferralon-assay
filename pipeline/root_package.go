package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/gradlewrapper"
)

// RootPackage is the identity the scanned project itself publishes under: the package an advisory
// names when the repository IS the vulnerable package (an advisory against grafana scanned in the
// grafana repository). Version is set only when it is positively established as the version of the
// checked-out code, and is "" otherwise: the advisory is still admitted on it, and the verdict gate
// reports the version as unresolved. For Go that is the one full semver tag at HEAD whose major
// version the module path allows; elsewhere, a release version the manifest states outright where
// nothing the reader cannot see can change it.
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
		if r, ok := mavenRootPackage(ctx, buildDir); ok {
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
func (r RootPackage) Matches(buildDir string, ws GoWorkspace, module, coordinate, purl string) (string, bool) {
	if typ := purlEcosystem(purl); typ != "" && typ != r.PURLType {
		return "", false
	}
	if r.PURLType == "golang" {
		switch goPathOwner(buildDir, ws, r.Name, module) {
		case goOwnedByRoot:
			return r.Version, true
		case goOwnerAmbiguous:
			return "", true
		}
		return "", false
	}
	if coordinate != "" && CanonicalName(r.PURLType, coordinate) == CanonicalName(r.PURLType, r.Name) {
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
// go.mod in buildDir declares. p is the root's when it is mod itself, or a path under it whose
// first element is not a major-version suffix (example.com/m/v2 is a different module from
// example.com/m) and that no other module claims: none another go.mod below buildDir declares, none
// the workspace ws uses, and none go.mod requires or replaces. A longer module path
// go.sum records but go.mod does not name, or one a go.mod elsewhere in the repository declares,
// leaves the owner ambiguous, as does a go.mod or go.work that does not parse: such a module is not
// in the build, so the path may still be the root's, but it may also be the other module's at
// another version. So does one a go.work member requires or replaces, or the go.work replaces: the
// workspace build may serve the path from that module instead.
func goPathOwner(buildDir string, ws GoWorkspace, mod, p string) goOwner {
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
	others, outside, ok := goTreeModules(buildDir)
	if !ok {
		return goOwnerAmbiguous
	}
	members, ok := goWorkModules(ws)
	if !ok {
		return goOwnerAmbiguous
	}
	for _, m := range append(others, members...) {
		if claims(m) {
			return goOwnedElsewhere
		}
	}
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
	work, ok := goWorkRequires(ws)
	if !ok {
		return goOwnerAmbiguous
	}
	for _, m := range append(outside, work...) {
		if claims(m) {
			return goOwnerAmbiguous
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

// goTreeModules returns the module path every go.mod below buildDir declares, whatever directory
// it sits in, and as outside the module path every other go.mod in the git work tree holding
// buildDir declares; ok is false when the tree cannot be walked or a go.mod below buildDir declares
// no module. Like the go command, it skips testdata directories and those whose name begins with
// . or _, unless buildDir is inside one.
func goTreeModules(buildDir string) (below, outside []string, ok bool) {
	own, err := filepath.EvalSymlinks(buildDir)
	if err != nil {
		return nil, nil, false
	}
	root := own
	if top, err := gitOutput(context.Background(), own, "rev-parse", "--show-toplevel"); err == nil && top != "" {
		root = top
	}
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if goIgnoredDir(d.Name()) && !strings.HasPrefix(own+string(filepath.Separator), p+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" || filepath.Dir(p) == own {
			return nil
		}
		m := goModFileModule(p)
		if !strings.HasPrefix(p, own+string(filepath.Separator)) {
			if m != "" {
				outside = append(outside, m)
			}
			return nil
		}
		if m == "" {
			return os.ErrInvalid
		}
		below = append(below, m)
		return nil
	})
	return below, outside, err == nil
}

func goIgnoredDir(name string) bool {
	return name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// goWorkModules returns the module path of every module the workspace uses; ok is false when its
// go.work does not parse or a module it uses declares no module path.
func goWorkModules(ws GoWorkspace) ([]string, bool) {
	uses, _, ok := ws.uses()
	if !ok {
		return nil, false
	}
	var mods []string
	for _, use := range uses {
		m := goModFileModule(filepath.Join(use, "go.mod"))
		if m == "" {
			return nil, false
		}
		mods = append(mods, m)
	}
	return mods, true
}

// goWorkRequires returns the module path every go.mod of a module the workspace uses requires or
// replaces, and every one its go.work replaces; ok is false when one cannot be read.
func goWorkRequires(ws GoWorkspace) ([]string, bool) {
	uses, paths, ok := ws.uses()
	if !ok {
		return nil, false
	}
	for _, use := range uses {
		data, err := os.ReadFile(filepath.Join(use, "go.mod"))
		if err != nil {
			return nil, false
		}
		mf, err := modfile.Parse("go.mod", data, nil)
		if err != nil {
			return nil, false
		}
		for _, r := range mf.Require {
			paths = append(paths, r.Mod.Path)
		}
		for _, r := range mf.Replace {
			paths = append(paths, r.Old.Path)
		}
	}
	return paths, true
}

func goModFileModule(gomod string) string {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return ""
	}
	return modfile.ModulePath(data)
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
// the version is the full semver tag at HEAD for this module (a nested module's tags carry its
// directory as a prefix) whose major version the module path allows (v0 or v1 with no /vN suffix,
// vN with one). It is "" when HEAD carries no such tag, or more than one: the reader cannot tell
// which of them the build publishes.
func goRootPackage(ctx context.Context, buildDir string) (RootPackage, bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return RootPackage{}, false
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil || mf.Module == nil || mf.Module.Mod.Path == "" {
		return RootPackage{}, false
	}
	return RootPackage{PURLType: "golang", Name: mf.Module.Mod.Path, Version: goModuleTagAtHead(ctx, buildDir, mf.Module.Mod.Path)}, true
}

func goModuleTagAtHead(ctx context.Context, dir, mod string) string {
	_, pathMajor, ok := module.SplitPathVersion(mod)
	if !ok {
		return ""
	}
	prefix, err := gitOutput(ctx, dir, "rev-parse", "--show-prefix")
	if err != nil {
		return ""
	}
	tags, err := gitOutput(ctx, dir, "tag", "--points-at", "HEAD")
	if err != nil {
		return ""
	}
	version := ""
	for _, t := range strings.Fields(tags) {
		v, ok := strings.CutPrefix(t, prefix)
		if !ok || !semver.IsValid(v) || semver.Canonical(v) != v || module.CheckPathMajor(v, pathMajor) != nil {
			continue
		}
		if version != "" && version != v {
			return ""
		}
		version = v
	}
	return version
}

// gitRepositoryEnv names the variables that point git at a repository, work tree or config other
// than the one it would find from dir (what `git rev-parse --local-env-vars` lists), and
// GIT_CEILING_DIRECTORIES, which can stop it finding that one at all.
var gitRepositoryEnv = []string{
	"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
	"GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
	"GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
	"GIT_SHALLOW_FILE", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES",
}

// gitOutput runs git against the repository containing dir, whatever the environment says.
func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(gitRepositoryEnv, name)
	})
	out, err := cmd.Output()
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

var pyVersionPlugin = regexp.MustCompile(`(?i)version`)

var pyVersionAssign = regexp.MustCompile(`(?m)^__version__\s*(?::\s*str\s*)?=\s*['"]([^'"]+)['"]`)

// pypiRootPackage reads pyproject.toml ([project], then [tool.poetry]), falling back to setup.cfg
// [metadata]. A dynamic version is read from the file hatch's [tool.hatch.version] path names.
func pypiRootPackage(buildDir string) (RootPackage, bool) {
	var py struct {
		BuildSystem struct {
			Requires []string `toml:"requires"`
			Backend  string   `toml:"build-backend"`
		} `toml:"build-system"`
		Project struct {
			Name    string   `toml:"name"`
			Version string   `toml:"version"`
			Dynamic []string `toml:"dynamic"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Name           string         `toml:"name"`
				Version        string         `toml:"version"`
				RequirePlugins map[string]any `toml:"requires-plugins"`
			} `toml:"poetry"`
			Hatch struct {
				Version struct {
					Path    string `toml:"path"`
					Source  string `toml:"source"`
					Pattern any    `toml:"pattern"`
				} `toml:"version"`
			} `toml:"hatch"`
		} `toml:"tool"`
	}
	md, err := toml.DecodeFile(filepath.Join(buildDir, "pyproject.toml"), &py)
	if err == nil {
		// A version plugin (poetry-dynamic-versioning, or any other) rewrites the stated version
		// from VCS at build time, so what the file states is not the version built.
		plugin := len(py.Tool.Poetry.RequirePlugins) > 0 || pyVersionPlugin.MatchString(py.BuildSystem.Backend)
		for _, r := range py.BuildSystem.Requires {
			plugin = plugin || pyVersionPlugin.MatchString(r)
		}
		for _, k := range md.Keys() {
			plugin = plugin || len(k) >= 2 && k[0] == "tool" && pyVersionPlugin.MatchString(k[1])
		}
		if name := py.Project.Name; name != "" {
			version := py.Project.Version
			hv := py.Tool.Hatch.Version
			if version == "" && hv.Path != "" && (hv.Source == "" || hv.Source == "regex") && hv.Pattern == nil {
				version = hatchVersion(buildDir, hv.Path)
			}
			if plugin {
				version = ""
			}
			return RootPackage{PURLType: "pypi", Name: name, Version: establishedVersion("pypi", version)}, true
		}
		if name := py.Tool.Poetry.Name; name != "" {
			version := py.Tool.Poetry.Version
			if plugin {
				version = ""
			}
			return RootPackage{PURLType: "pypi", Name: name, Version: establishedVersion("pypi", version)}, true
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
// on the command line, and the defaults in <properties> are placeholders (999999-SNAPSHOT). Any
// version is left unknown where something this reader cannot see may set it (see
// mavenVersionWritersVisible).
func mavenRootPackage(ctx context.Context, buildDir string) (RootPackage, bool) {
	pomPath := filepath.Join(buildDir, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return RootPackage{}, false
	}
	var pom mavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return RootPackage{}, false
	}
	group, version := pom.coordinates()
	artifact := strings.TrimSpace(pom.ArtifactID)
	if group == "" || artifact == "" || strings.Contains(group+artifact, "${") {
		return RootPackage{}, false
	}
	if !mavenVersionWritersVisible(ctx, buildDir, pomPath, data, pom) {
		version = ""
	}
	return RootPackage{PURLType: "maven", Name: group + ":" + artifact, Version: establishedVersion("maven", version)}, true
}

type mavenPOM struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     *struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
}

// coordinates returns the POM's groupId and version, each inherited from <parent> when absent.
func (p mavenPOM) coordinates() (group, version string) {
	if p.Parent != nil {
		group, version = p.Parent.GroupID, p.Parent.Version
	}
	return strings.TrimSpace(firstNonEmpty(p.GroupID, group)), strings.TrimSpace(firstNonEmpty(p.Version, version))
}

// mavenVersionWritersVisible reports whether every writer of the project version is one this
// reader sees in the checkout:
//   - the .mvn directory Maven uses (the first at or above buildDir) loads no core extension:
//     no extensions.xml, and no maven.config or jvm.config naming maven.ext.class.path;
//   - every Maven wrapper at or above buildDir fetches a stock distribution from Maven Central (a
//     custom one can load core extensions from its lib/ext);
//   - no POM in the parent chain has an <extensions> element, since a build extension or a plugin
//     with extensions can set the version once projects are read;
//   - every parent resolves to a POM inside the checkout, at its relativePath (default
//     ../pom.xml), whose coordinates match the ones declared; Maven takes any other parent from a
//     repository, which can carry extensions of its own.
//
// Anything that cannot be read counts as a writer.
func mavenVersionWritersVisible(ctx context.Context, buildDir, pomPath string, data []byte, pom mavenPOM) bool {
	if mavenCoreExtensions(buildDir) || !stockMavenWrappers(buildDir) {
		return false
	}
	root := buildDir
	if top, err := gitOutput(ctx, buildDir, "rev-parse", "--show-toplevel"); err == nil && top != "" {
		root = top
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	for {
		if bytes.Contains(data, []byte("<extensions")) {
			return false
		}
		if pom.Parent == nil {
			return true
		}
		rel := "../pom.xml"
		if pom.Parent.RelativePath != nil {
			rel = strings.TrimSpace(*pom.Parent.RelativePath)
		}
		if rel == "" {
			return false
		}
		next := filepath.Join(filepath.Dir(pomPath), filepath.FromSlash(rel))
		if info, err := os.Stat(next); err == nil && info.IsDir() {
			next = filepath.Join(next, "pom.xml")
		}
		real, err := filepath.EvalSymlinks(next)
		if err != nil || seen[real] {
			return false
		}
		if r, err := filepath.Rel(root, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return false
		}
		seen[real] = true
		want := *pom.Parent
		if data, err = os.ReadFile(real); err != nil {
			return false
		}
		pom = mavenPOM{}
		if xml.Unmarshal(data, &pom) != nil {
			return false
		}
		group, version := pom.coordinates()
		if group != strings.TrimSpace(want.GroupID) || strings.TrimSpace(pom.ArtifactID) != strings.TrimSpace(want.ArtifactID) || version != strings.TrimSpace(want.Version) || strings.Contains(version, "${") {
			return false
		}
		pomPath = real
	}
}

// mavenCoreExtensions reports whether the .mvn directory Maven uses for a build at buildDir (the
// first at or above it) can load a core extension, or cannot be read.
func mavenCoreExtensions(buildDir string) bool {
	dir, err := filepath.Abs(buildDir)
	if err != nil {
		return true
	}
	for {
		mvn := filepath.Join(dir, ".mvn")
		if !absent(mvn) {
			if !absent(filepath.Join(mvn, "extensions.xml")) {
				return true
			}
			for _, name := range []string{"maven.config", "jvm.config"} {
				path := filepath.Join(mvn, name)
				data, err := os.ReadFile(path)
				if err != nil && !absent(path) || bytes.Contains(data, []byte("maven.ext.class.path")) {
					return true
				}
			}
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// stockMavenWrappers reports whether every .mvn/wrapper/maven-wrapper.properties at or above
// buildDir fetches a stock distribution, and the wrapper JAR, if it names one, from Maven Central.
// Every one is checked, not only the first, since mvnw reads the properties beside wherever it
// sits. The file must hold nothing but plain key=value lines with known keys, each printable ASCII
// ending in \n or \r\n and none ending in a backslash: the mvnw script and the wrapper JAR parse it
// differently (java.util.Properties also breaks a line at a lone \r, continues one at a trailing
// backslash, and reads \f as whitespace), and only that form reads the same to both.
func stockMavenWrappers(buildDir string) bool {
	dir, err := filepath.Abs(buildDir)
	if err != nil {
		return false
	}
	for {
		path := filepath.Join(dir, ".mvn", "wrapper", "maven-wrapper.properties")
		if data, err := os.ReadFile(path); err != nil {
			if !absent(path) {
				return false
			}
		} else if !stockMavenWrapper(data) {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
		dir = parent
	}
}

func stockMavenWrapper(data []byte) bool {
	seen := map[string]bool{}
	for raw := range strings.Lines(string(data)) {
		line, ended := strings.CutSuffix(raw, "\n")
		if ended {
			line = strings.TrimSuffix(line, "\r")
		}
		if !printableASCII(line) || strings.HasSuffix(line, "\\") {
			return false
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || seen[key] || strings.HasSuffix(value, "\\") || !mavenWrapperKey.MatchString(key) {
			return false
		}
		seen[key] = true
		switch key {
		case "distributionUrl":
			if !mavenStockDist.MatchString(value) {
				return false
			}
		case "wrapperUrl":
			if !mavenStockWrapper.MatchString(value) {
				return false
			}
		}
	}
	return seen["distributionUrl"]
}

// printableASCII reports whether every byte of s is a printable ASCII character, space included.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// gradleRootPackage reads group and version from the root build script and the project name from
// settings. A project with no literal top-level group, or no top-level rootProject.name literal,
// publishes no coordinate the scan can name. The version is read only where every statement that
// runs before publishing is one this reader can see does not set it: the root script's top-level
// statements are all on its allowlist (see gradleScript), settings holds nothing but the
// rootProject.name assignment (an include adds projects whose scripts run after the root's), there
// is no buildSrc, and the wrapper, if any, fetches a stock distribution (a custom one can carry
// init scripts).
func gradleRootPackage(buildDir string) (RootPackage, bool) {
	script, ok := readGradleScript(readFirst(buildDir, "build.gradle.kts", "build.gradle"))
	if !ok || script.group == "" {
		return RootPackage{}, false
	}
	name, settingsPlain := readGradleSettings(readFirst(buildDir, "settings.gradle.kts", "settings.gradle"))
	if name == "" {
		return RootPackage{}, false
	}
	version := script.version
	if !settingsPlain || bothExist(buildDir, "build.gradle.kts", "build.gradle") || bothExist(buildDir, "settings.gradle.kts", "settings.gradle") || !absent(filepath.Join(buildDir, "buildSrc")) || !gradlewrapper.StockGradleWrapper(buildDir) {
		version = ""
	}
	return RootPackage{PURLType: "maven", Name: script.group + ":" + name, Version: establishedVersion("maven", version)}, true
}

// gradleScript is what a root build script states outright at its top level.
type gradleScript struct {
	// group is the literal of the one top-level group assignment, or "".
	group string
	// version is the literal of the one top-level version assignment, and "" unless every other
	// top-level statement is a literal group assignment or a plain dependencies or repositories
	// block (see gradlePlainBlock): anything else can run code that sets the version.
	version string
}

var (
	gradleGroupWord     = regexp.MustCompile(`\bgroup\b`)
	gradleAssignRHS     = regexp.MustCompile(`^\s*=\s*(['"])`)
	gradleStatementWord = regexp.MustCompile(`^(group|version|dependencies|repositories)\b`)
	gradleRootNameStmt  = regexp.MustCompile(`^rootProject\.name\b`)
	gradleDependency    = regexp.MustCompile(`^(api|implementation|compileOnly|runtimeOnly|annotationProcessor|testImplementation|testCompileOnly|testRuntimeOnly|testAnnotationProcessor)\s*(\(\s*['"]\s*['"]\s*\)|['"]\s*['"])$`)
	gradleRepository    = regexp.MustCompile(`^(mavenCentral|google|gradlePluginPortal|mavenLocal)\s*\(\s*\)$`)
	mavenWrapperKey     = regexp.MustCompile(`^(distributionUrl|distributionSha256Sum|distributionType|wrapperUrl|wrapperSha256Sum|wrapperVersion)$`)
	mavenStockDist      = regexp.MustCompile(`^https://repo\.maven\.apache\.org/maven2/org/apache/maven/apache-maven/[0-9][0-9A-Za-z.-]*/apache-maven-[0-9][0-9A-Za-z.-]*-bin\.(zip|tar\.gz)$`)
	mavenStockWrapper   = regexp.MustCompile(`^https://repo\.maven\.apache\.org/maven2/org/apache/maven/wrapper/maven-wrapper/[0-9][0-9A-Za-z.-]*/maven-wrapper-[0-9][0-9A-Za-z.-]*\.jar$`)
)

// readGradleScript reads a Groovy or Kotlin build script; ok is false when it does not lex.
func readGradleScript(src string) (gradleScript, bool) {
	code, depth, ok := maskGradle(src)
	if !ok {
		return gradleScript{}, false
	}
	var groups []string
	for _, m := range gradleGroupWord.FindAllStringIndex(code, -1) {
		if lit, isLit := gradleLiteralAssign(src, code, m[0], m[1]); depth[m[0]] == 0 && isLit {
			groups = append(groups, lit)
		}
	}
	var out gradleScript
	if len(groups) == 1 {
		out.group = groups[0]
	}
	var versions []string
	for _, st := range gradleStatements(code, depth, 0, len(code), 0) {
		text := code[st[0]:st[1]]
		word := gradleStatementWord.FindString(text)
		switch word {
		case "group", "version":
			lit, isLit := gradleLiteralAssign(src, code, st[0], st[0]+len(word))
			if !isLit {
				return out, true
			}
			if word == "version" {
				versions = append(versions, lit)
			}
		case "dependencies", "repositories":
			if !gradlePlainBlock(src, code, depth, st, word) {
				return out, true
			}
		default:
			return out, true
		}
	}
	if len(versions) == 1 {
		out.version = versions[0]
	}
	return out, true
}

// readGradleSettings returns the literal of the settings file's one top-level rootProject.name
// assignment, and whether that assignment is the file's only statement. A file that does not lex
// names nothing.
func readGradleSettings(src string) (name string, plain bool) {
	code, depth, ok := maskGradle(src)
	if !ok {
		return "", false
	}
	var names []string
	plain = true
	for _, st := range gradleStatements(code, depth, 0, len(code), 0) {
		lit, isLit := "", false
		if m := gradleRootNameStmt.FindStringIndex(code[st[0]:st[1]]); m != nil {
			lit, isLit = gradleLiteralAssign(src, code, st[0], st[0]+m[1])
		}
		if !isLit || strings.Contains(lit, "$") {
			plain = false
			continue
		}
		names = append(names, lit)
	}
	if len(names) != 1 {
		return "", false
	}
	return names[0], plain
}

// gradleStatements splits code[from:to] into the statements at brace depth level: each runs from
// its first non-blank byte to the next newline or semicolon at that depth, so a block runs through
// the line its closing brace is on. Anything that spans lines otherwise splits into fragments no
// allowlist accepts.
func gradleStatements(code string, depth []int, from, to, level int) [][2]int {
	var out [][2]int
	start := -1
	for i := from; i < to; i++ {
		end := (code[i] == '\n' || code[i] == ';') && depth[i] == level
		switch {
		case end && start >= 0:
			out = append(out, [2]int{start, i})
			start = -1
		case !end && start < 0 && strings.TrimSpace(code[i:i+1]) != "":
			start = i
		}
	}
	if start >= 0 {
		out = append(out, [2]int{start, to})
	}
	for k, st := range out {
		out[k][1] = st[0] + len(strings.TrimRightFunc(code[st[0]:st[1]], unicode.IsSpace))
	}
	return out
}

// gradlePlainBlock reports whether the statement st is `word { ... }` holding only plain entries:
// a dependency on a standard configuration declared as one string literal with no interpolation,
// or a stock repository. Any other name in the block resolves against the project as well, so a
// call such as setVersion would run there.
func gradlePlainBlock(src, code string, depth []int, st [2]int, word string) bool {
	rest := strings.TrimLeftFunc(code[st[0]+len(word):st[1]], unicode.IsSpace)
	if !strings.HasPrefix(rest, "{") || !strings.HasSuffix(rest, "}") {
		return false
	}
	open := st[1] - len(rest)
	if depth[st[1]-1] != 1 {
		return false
	}
	for _, in := range gradleStatements(code, depth, open+1, st[1]-1, 1) {
		text := code[in[0]:in[1]]
		if word == "repositories" && !gradleRepository.MatchString(text) {
			return false
		}
		if word == "dependencies" && (!gradleDependency.MatchString(text) || strings.ContainsAny(src[in[0]:in[1]], "$")) {
			return false
		}
	}
	return true
}

// absent reports whether nothing exists at path; an error other than not-exist counts as present.
func absent(path string) bool {
	_, err := os.Lstat(path)
	return os.IsNotExist(err)
}

// bothExist reports whether both names exist in dir, where which one Gradle reads is not this
// reader's to decide.
func bothExist(dir, a, b string) bool {
	return !absent(filepath.Join(dir, a)) && !absent(filepath.Join(dir, b))
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
// file name. The version is never established from the checkout: a property passed on the MSBuild
// command line (dotnet pack -p:Version=...) overrides every value the project sets, and nothing in
// the checkout records it. A directory holding several projects has no single root.
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
			PackageID    string `xml:"PackageId"`
			AssemblyName string `xml:"AssemblyName"`
		} `xml:"PropertyGroup"`
	}
	if err := xml.Unmarshal(data, &proj); err != nil {
		return RootPackage{}, false
	}
	var id, assembly string
	for _, g := range proj.Groups {
		id = firstNonEmpty(id, strings.TrimSpace(g.PackageID))
		assembly = firstNonEmpty(assembly, strings.TrimSpace(g.AssemblyName))
	}
	id = firstNonEmpty(id, assembly, strings.TrimSuffix(filepath.Base(projects[0]), ".csproj"))
	if strings.Contains(id, "$(") {
		return RootPackage{}, false
	}
	return RootPackage{PURLType: "nuget", Name: id}, true
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
