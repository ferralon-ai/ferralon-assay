package javaanalysis

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	poms, gradles := buildFiles(req.BuildDir)

	var (
		all         []plugin.ResolvedDependency
		parseFailed bool
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
	want := normalizeCoordinate(req.Coordinate)
	if want != "" {
		for _, d := range all {
			if normalizeCoordinate(d.Coordinate) == want {
				res.Found = true
				res.Match = d
				// A resolved match wins over an UNRESOLVED one for the same coordinate.
				if d.Resolved {
					break
				}
			}
		}
	}
	return res, nil
}

// buildFiles returns the pom.xml and build.gradle (incl. build.gradle.kts) files under root,
// skipping build-output/VCS trees, mirroring javaanalysis.javaFiles's source notion.
func buildFiles(root string) (poms, gradles []string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no build files; keep walking.
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
	return poms, gradles
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
	GroupID string `xml:"groupId"`
	Version string `xml:"version"`
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
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
