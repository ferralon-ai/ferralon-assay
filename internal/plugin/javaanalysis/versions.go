package javaanalysis

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/html/charset"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the codebase's declared dependency versions from its
// pure-Go-parseable build files (pom.xml via stdlib XML; build.gradle via a line scan) and
// returns the declared version for the advisory's requested coordinate. It is the cheap
// Assess-tier input to the disqualification predicate.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. A coordinate whose version cannot be
// determined confidently — a BOM/dependencyManagement-managed dependency with no inline
// <version>, a property indirection (${...}) that does not resolve to a literal in the same
// POM, or a gradle declaration with no literal version — is returned with Resolved=false (an
// UNRESOLVED marker). The pipeline fails OPEN on UNRESOLVED, never fabricating a not-affected.
//
// All lists every declaration as read. Match is narrower (matchCoordinate): it resolves only to a
// literal POM version that every declaration agrees on, in a build whose POMs this reader models
// whole. A ${prop} version is unresolved there, since -Dprop on the command line or in
// .mvn/maven.config overrides the POM. Gradle declarations join the agreement as All states them.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir is a hard error.
//   - A build dir with NO pom.xml and NO build.gradle degrades Partiality to declared-partial
//     (no_manifest) rather than hard-failing the run: a repo that carries no Maven/Gradle
//     build file is a normal shape, not a tool failure. pom.xml / build.gradle ARE the
//     declaration, so unlike JS there is no separate declared-deps file left to seed — All is
//     legitimately empty. Soundness rests entirely on the declared partiality: the result is
//     Complete=false, so a consumer must not read the empty All as proof the dependency is
//     absent and fabricate a not-affected.
//   - An unparseable build file degrades Partiality to declared-partial (tool_failure); any
//     coordinate it would have carried becomes UNRESOLVED, not absent.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}

	poms, gradles, walkFailed := buildFiles(req.BuildDir)
	poms, unread := reactorModules(req.BuildDir, poms)

	var (
		all []plugin.ResolvedDependency
		// A subtree the walk couldn't list, or a reactor module it couldn't read, could declare
		// any coordinate at any version, as a manifest that doesn't parse could.
		parseFailed = walkFailed || unread
	)
	for _, p := range poms {
		deps, ok := parsePOM(p)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}
	for _, g := range gradles {
		deps, ok := parseGradle(g)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}

	part := plugin.Complete()
	switch {
	case len(poms) == 0 && len(gradles) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
	if want := normalizeCoordinate(req.Coordinate); want != "" {
		res.Match, res.Found = matchCoordinate(poms, all, want)
		// Presence keeps the first resolved copy, agreement or not: a malicious-package advisory
		// is affected by any copy at a listed version.
		for _, d := range all {
			if d.Resolved && normalizeCoordinate(d.Coordinate) == want {
				res.Presence = &d
				break
			}
		}
		if parseFailed {
			// A manifest that doesn't parse could declare want at any version.
			if !res.Found {
				res.Match = plugin.ResolvedDependency{Coordinate: strings.TrimSpace(req.Coordinate)}
			}
			res.Found = true
			res.Match.Version = ""
			res.Match.Resolved = false
		}
	}
	return res, nil
}

// matchCoordinate selects the Match for the normalized coordinate want across every declaration
// of it: each POM's, read again by pomDeclarations, and each Gradle entry of all as it stands. The
// Match is resolved only when every declaration is resolved (a POM one only at a literal pin,
// pinnedVersion), every POM in scope is one this reader models, and all of them name the same
// version. A declaration this reader can't vouch for, a POM that could
// declare the coordinate where this reader doesn't look, or two versions leave it unresolved: a
// build with one patched module and one affected one must not be ruled not-affected on the copy
// that happens to sit outside the range. A modeled module with dependencies but no declaration of
// want could still ship it transitively, at a version Maven picks from the graph, so it leaves the
// Match unresolved too. So does a module that doesn't declare want and inherits from a parent POM
// outside poms (inheritsOutOfTree): the parent's dependencies, which this reader never sees, are
// the module's own.
func matchCoordinate(poms []string, all []plugin.ResolvedDependency, want string) (plugin.ResolvedDependency, bool) {
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		opaque   bool
		versions = map[string]struct{}{}
	)
	add := func(d plugin.ResolvedDependency) {
		if !found {
			match, found = d, true
		}
		if !d.Resolved {
			unknown = true
			return
		}
		if len(versions) == 0 {
			match = d
		}
		versions[d.Version] = struct{}{}
	}
	inSet := make(map[string]bool, len(poms))
	for _, p := range poms {
		inSet[filepath.Clean(p)] = true
	}
	for _, p := range poms {
		decls, modeled, others := pomDeclarations(p, want)
		for _, d := range decls {
			add(d)
		}
		opaque = opaque || !modeled || (len(decls) == 0 && (others || inheritsOutOfTree(p, inSet)))
	}
	for _, d := range all {
		if d.Source == "gradle" && normalizeCoordinate(d.Coordinate) == want {
			add(d)
		}
	}
	if found && (unknown || opaque || len(versions) != 1) {
		match.Version = ""
		match.Resolved = false
	}
	return match, found
}

// pomDeclarations returns each <dependencies> declaration of want in the POM at path, resolved
// when its <version> is a literal pin, and whether this reader models the POM whole: it parses,
// every top-level element is one pomModeled knows, and no core extension loads for its build. A
// POM that isn't modeled could declare want where this reader doesn't look, so its declarations
// come back unresolved. others reports whether the POM declares a dependency other than want.
func pomDeclarations(path, want string) (decls []plugin.ResolvedDependency, modeled, others bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false, false
	}
	var proj pomProject
	if err := unmarshalPOM(data, &proj); err != nil {
		return nil, false, false
	}
	modeled = pomModeled(data) && !mavenCoreExtensions(filepath.Dir(path))
	for _, dep := range proj.Deps {
		coord := strings.TrimSpace(dep.GroupID) + ":" + strings.TrimSpace(dep.ArtifactID)
		if normalizeCoordinate(coord) != want {
			others = true
			continue
		}
		d := plugin.ResolvedDependency{Coordinate: coord, Source: "pom"}
		if v := strings.TrimSpace(dep.Version); modeled && pinnedVersion(v) {
			d.Version, d.Resolved = v, true
		}
		decls = append(decls, d)
	}
	return decls, modeled, others
}

// inheritsOutOfTree reports whether the POM at path names a <parent> that Maven takes from outside
// inSet. Maven reads the parent from the file at its relativePath (../pom.xml by default, with
// pom.xml appended to a directory) only when that file's groupId, artifactId and version are the
// parent's; otherwise, or with an empty <relativePath/>, it reads the parent from a repository.
// A POM that can't be read counts as inheriting from outside.
func inheritsOutOfTree(path string, inSet map[string]bool) bool {
	data, err := readRegular(path)
	if err != nil {
		return true
	}
	var proj pomProject
	if err := unmarshalPOM(data, &proj); err != nil {
		return true
	}
	ref := proj.Parent
	if strings.TrimSpace(ref.ArtifactID) == "" && strings.TrimSpace(ref.GroupID) == "" {
		return false
	}
	rel := "../pom.xml"
	if ref.RelativePath != nil {
		rel = strings.TrimSpace(*ref.RelativePath)
	}
	if rel == "" {
		return true
	}
	parent := filepath.Join(filepath.Dir(path), filepath.FromSlash(rel))
	if !strings.HasSuffix(strings.ToLower(rel), ".xml") {
		parent = filepath.Join(parent, "pom.xml")
	}
	if !inSet[filepath.Clean(parent)] {
		return true
	}
	data, err = readRegular(parent)
	if err != nil {
		return true
	}
	var local pomProject
	if err := unmarshalPOM(data, &local); err != nil {
		return true
	}
	g, a, v := strings.TrimSpace(local.GroupID), strings.TrimSpace(local.ArtifactID), strings.TrimSpace(local.VersionElem)
	if g == "" {
		g = strings.TrimSpace(local.Parent.GroupID)
	}
	if v == "" {
		v = strings.TrimSpace(local.Parent.Version)
	}
	return a == "" || g != strings.TrimSpace(ref.GroupID) || a != strings.TrimSpace(ref.ArtifactID) || v != strings.TrimSpace(ref.Version)
}

// pinnedVersion reports whether v is a plain release version: a digit first, then only letters,
// digits, '.', '-' and '_'. Anything else (a dynamic "5.+", "latest.release", RELEASE, LATEST, a
// range, a bracketed pin, an interpolation) does not name one version and is not a pin.
func pinnedVersion(v string) bool {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// pomInert names the top-level POM elements that can't change which version of a dependency
// the POM's own <dependencies> declares. Any other element (profiles among them) is one this
// reader doesn't model, and so is a build extension anywhere in the POM.
var pomInert = map[string]bool{
	"modelVersion": true, "parent": true, "groupId": true, "artifactId": true, "version": true,
	"packaging": true, "name": true, "description": true, "url": true, "inceptionYear": true,
	"organization": true, "licenses": true, "developers": true, "contributors": true,
	"mailingLists": true, "prerequisites": true, "modules": true, "scm": true,
	"issueManagement": true, "ciManagement": true, "distributionManagement": true,
	"properties": true, "dependencyManagement": true, "dependencies": true, "repositories": true,
	"pluginRepositories": true, "build": true, "reporting": true,
}

// pomModeled reports whether every top-level element of the POM is in pomInert and no element
// anywhere is <extensions>.
func pomModeled(data []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	depth := 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && !pomInert[t.Name.Local] || t.Name.Local == "extensions" {
				return false
			}
		case xml.EndElement:
			depth--
		}
	}
}

// mavenCoreExtensions reports whether the .mvn directory Maven uses for a build in dir (the first
// at or above it) can load a core extension, which may rewrite the model, or can't be read.
func mavenCoreExtensions(dir string) bool {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return true
	}
	for {
		mvn := filepath.Join(dir, ".mvn")
		if _, err := os.Lstat(mvn); err == nil || !os.IsNotExist(err) {
			if _, err := os.Lstat(filepath.Join(mvn, "extensions.xml")); err == nil || !os.IsNotExist(err) {
				return true
			}
			for _, name := range []string{"maven.config", "jvm.config"} {
				data, err := readRegular(filepath.Join(mvn, name))
				if err != nil && !os.IsNotExist(err) || bytes.Contains(data, []byte("maven.ext.class.path")) {
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

// buildFiles returns the pom.xml and build.gradle (incl. build.gradle.kts) files under root,
// skipping build-output/VCS trees, mirroring javaanalysis.javaFiles's source notion. failed is set
// when some part of the tree couldn't be listed or examined.
func buildFiles(root string) (poms, gradles []string, failed bool) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if !os.IsNotExist(err) {
				failed = true
			}
			return nil //nolint:nilerr // keep walking; the caller reports the subtree as unread.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "pom.xml":
			poms = append(poms, path)
		case "build.gradle", "build.gradle.kts":
			gradles = append(gradles, path)
		}
		return nil
	})
	return poms, gradles, failed
}

// reactorModules adds to poms every module POM the reactor names that the walk didn't return: a
// module in a directory the walk skips (build, out, ...) or a module file not named pom.xml. A
// module is read from the module list of every POM in the set, its profiles' included, until no
// new one turns up. unread is set when a named module POM is outside root or can't be read.
func reactorModules(root string, poms []string) (_ []string, unread bool) {
	seen := map[string]bool{}
	for _, p := range poms {
		seen[filepath.Clean(p)] = true
	}
	for i := 0; i < len(poms); i++ {
		data, err := readRegular(poms[i])
		if err != nil {
			continue
		}
		var proj pomModules
		if err := unmarshalPOM(data, &proj); err != nil {
			continue
		}
		modules := proj.Modules
		for _, prof := range proj.Profiles {
			modules = append(modules, prof.Modules...)
		}
		for _, m := range modules {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			path := filepath.Join(filepath.Dir(poms[i]), filepath.FromSlash(m))
			if !strings.HasSuffix(strings.ToLower(m), ".xml") {
				path = filepath.Join(path, "pom.xml")
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			if rel, err := filepath.Rel(root, path); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				unread = true
				continue
			}
			poms = append(poms, path)
		}
	}
	return poms, unread
}

// pomModules is the reactor module list of a POM, its profiles' included.
type pomModules struct {
	Modules  []string `xml:"modules>module"`
	Profiles []struct {
		Modules []string `xml:"modules>module"`
	} `xml:"profiles>profile"`
}

// --- pom.xml -----------------------------------------------------------------

// pomProject is the minimal subset of a Maven POM we read: the <properties> block (for
// ${name} version interpolation) and the <dependencies> list. dependencyManagement is
// intentionally NOT read for versions — a dep whose version lives only there (BOM-managed)
// is UNRESOLVED to us, the sound conservative outcome.
type pomProject struct {
	Properties  pomProperties `xml:"properties"`
	Parent      pomParent     `xml:"parent"`
	GroupID     string        `xml:"groupId"`
	ArtifactID  string        `xml:"artifactId"`
	VersionElem string        `xml:"version"`
	Deps        []pomDep      `xml:"dependencies>dependency"`
}

type pomParent struct {
	GroupID      string  `xml:"groupId"`
	ArtifactID   string  `xml:"artifactId"`
	Version      string  `xml:"version"`
	RelativePath *string `xml:"relativePath"`
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// pomProperties captures the arbitrary child elements of <properties> as name→value pairs
// for ${name} interpolation, plus the two implicit Maven properties we can resolve.
type pomProperties struct {
	Entries map[string]string
}

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	p.Entries = map[string]string{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = strings.TrimSpace(val)
		case xml.EndElement:
			return nil
		}
	}
}

// parsePOM parses one pom.xml into ResolvedDependency records. The bool is false when the XML
// is unparseable (the caller degrades partiality). Each dependency's version is resolved as:
//   - a literal <version> → Resolved
//   - a ${prop} that resolves to a literal property (incl. project.version) → Resolved
//   - missing, empty, or an unresolved ${prop} → UNRESOLVED (Resolved=false). NEVER guessed.
func parsePOM(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	var proj pomProject
	if err := unmarshalPOM(data, &proj); err != nil {
		return nil, false
	}

	props := map[string]string{}
	for k, v := range proj.Properties.Entries {
		props[k] = v
	}
	// Maven's implicit project.version / pom.version, resolvable to a literal only.
	projectVersion := proj.VersionElem
	if projectVersion == "" {
		projectVersion = proj.Parent.Version
	}
	if isLiteralVersion(projectVersion) {
		props["project.version"] = projectVersion
		props["pom.version"] = projectVersion
	}

	var out []plugin.ResolvedDependency
	for _, dep := range proj.Deps {
		coord := strings.TrimSpace(dep.GroupID) + ":" + strings.TrimSpace(dep.ArtifactID)
		ver, ok := resolvePOMVersion(strings.TrimSpace(dep.Version), props)
		out = append(out, plugin.ResolvedDependency{
			Coordinate: coord,
			Version:    ver,
			Resolved:   ok,
			Source:     "pom",
		})
	}
	return out, true
}

// resolvePOMVersion resolves a raw <version> value to a literal. A bare literal passes
// through; a single ${name} reference is looked up in props (one level, no recursion into
// another ${...}); anything else (empty, partial interpolation, unresolved property) is
// UNRESOLVED → ("", false). No guessing.
func resolvePOMVersion(raw string, props map[string]string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if isLiteralVersion(raw) {
		return raw, true
	}
	if name, ok := singlePropertyRef(raw); ok {
		if v, present := props[name]; present && isLiteralVersion(v) {
			return v, true
		}
	}
	return "", false
}

// singlePropertyRef reports whether raw is exactly one "${name}" reference and returns name.
func singlePropertyRef(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "${") || !strings.HasSuffix(raw, "}") {
		return "", false
	}
	inner := raw[2 : len(raw)-1]
	if inner == "" || strings.ContainsAny(inner, "${}") {
		return "", false
	}
	return inner, true
}

// isLiteralVersion reports whether v is a concrete version literal (no property syntax, not
// empty). This is the gate that keeps an unresolved ${...} out of the Resolved set.
func isLiteralVersion(v string) bool {
	return v != "" && !strings.Contains(v, "${")
}

// --- build.gradle ------------------------------------------------------------

// parseGradle scans a build.gradle / .kts file lexically for dependency declarations in the
// common string-notation forms and extracts {group, name, version}. The bool is false only
// when the file cannot be read. Supported forms (Groovy and Kotlin DSL):
//
//	implementation 'g:a:v'              implementation("g:a:v")
//	api "g:a:v"                         testImplementation('g:a:v')
//	implementation group: 'g', name: 'a', version: 'v'
//
// A declaration with no version segment (e.g. "g:a", BOM-aligned) or a version that is an
// interpolation ("$ver" / "${ver}") is UNRESOLVED (Resolved=false), NEVER guessed. Map-notation
// without a version: key is likewise UNRESOLVED.
func parseGradle(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	for _, line := range strings.Split(string(data), "\n") {
		line = stripGradleComment(line)
		if !gradleConfigLine(line) {
			continue
		}
		if dep, ok := gradleStringNotation(line); ok {
			out = append(out, dep)
			continue
		}
		if dep, ok := gradleMapNotation(line); ok {
			out = append(out, dep)
		}
	}
	return out, true
}

// gradleConfiguration prefixes whose argument is a dependency declaration we read.
var gradleConfigs = []string{
	"implementation", "api", "compile", "compileOnly", "runtimeOnly",
	"testImplementation", "testCompile", "testRuntimeOnly", "annotationProcessor",
}

// gradleConfigLine reports whether the trimmed line begins with a known dependency
// configuration keyword (so we ignore plugins{}, repositories{}, task bodies, etc.).
func gradleConfigLine(line string) bool {
	t := strings.TrimSpace(line)
	for _, c := range gradleConfigs {
		if strings.HasPrefix(t, c+" ") || strings.HasPrefix(t, c+"(") {
			return true
		}
	}
	return false
}

// gradleStringNotation extracts a dependency from the "g:a:v" single-string form. It pulls the
// first quoted string on the line and splits it on ':'. A 3-part split with a literal version
// is Resolved; a 2-part split (no version) or an interpolated version is UNRESOLVED.
func gradleStringNotation(line string) (plugin.ResolvedDependency, bool) {
	s, ok := firstQuoted(line)
	if !ok {
		return plugin.ResolvedDependency{}, false
	}
	if strings.Contains(s, "=") || !strings.Contains(s, ":") {
		return plugin.ResolvedDependency{}, false
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return plugin.ResolvedDependency{}, false
	}
	group, name := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if group == "" || name == "" {
		return plugin.ResolvedDependency{}, false
	}
	coord := group + ":" + name
	if len(parts) >= 3 {
		ver := strings.TrimSpace(parts[2])
		if isLiteralGradleVersion(ver) {
			return plugin.ResolvedDependency{Coordinate: coord, Version: ver, Resolved: true, Source: "gradle"}, true
		}
	}
	// 2-part (no version) or interpolated version → UNRESOLVED.
	return plugin.ResolvedDependency{Coordinate: coord, Resolved: false, Source: "gradle"}, true
}

// gradleMapNotation extracts a dependency from the "group: 'g', name: 'a', version: 'v'" form.
// A declaration with group+name but no literal version: value is UNRESOLVED.
func gradleMapNotation(line string) (plugin.ResolvedDependency, bool) {
	group, gok := gradleMapValue(line, "group")
	name, nok := gradleMapValue(line, "name")
	if !gok || !nok || group == "" || name == "" {
		return plugin.ResolvedDependency{}, false
	}
	coord := group + ":" + name
	if ver, vok := gradleMapValue(line, "version"); vok && isLiteralGradleVersion(ver) {
		return plugin.ResolvedDependency{Coordinate: coord, Version: ver, Resolved: true, Source: "gradle"}, true
	}
	return plugin.ResolvedDependency{Coordinate: coord, Resolved: false, Source: "gradle"}, true
}

// gradleMapValue returns the quoted value of "key:" in a gradle map-notation line.
func gradleMapValue(line, key string) (string, bool) {
	i := strings.Index(line, key+":")
	if i < 0 {
		// tolerate a space before the colon ("name :")
		i = strings.Index(line, key+" :")
		if i < 0 {
			return "", false
		}
	}
	rest := line[i:]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return "", false
	}
	v, ok := firstQuoted(rest[colon+1:])
	return strings.TrimSpace(v), ok
}

// isLiteralGradleVersion reports whether v is a concrete version literal, rejecting Groovy/
// Kotlin interpolations ("$ver", "${ver}") so an interpolated version is treated as UNRESOLVED.
func isLiteralGradleVersion(v string) bool {
	return v != "" && !strings.Contains(v, "$")
}

// firstQuoted returns the contents of the first single- or double-quoted string on s.
func firstQuoted(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			q := s[i]
			for j := i + 1; j < len(s); j++ {
				if s[j] == q {
					return s[i+1 : j], true
				}
			}
			return "", false
		}
	}
	return "", false
}

// stripGradleComment removes a trailing "//" line comment outside of any quoted string.
func stripGradleComment(line string) string {
	var inQuote byte
	for i := 0; i+1 < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == '/' && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}

// normalizeCoordinate trims and lowercases a "groupId:artifactId" for case/space-insensitive
// matching of the request coordinate against parsed declarations.
func normalizeCoordinate(c string) string {
	return strings.ToLower(strings.TrimSpace(c))
}
