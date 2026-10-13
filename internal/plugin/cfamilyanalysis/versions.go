package cfamilyanalysis

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Dependency manifests the lane reads, in authority order: a Conan lockfile pins the resolved
// graph, a conanfile.txt declares direct requirements, a vcpkg manifest declares constraints and
// exact overrides.
const (
	conanLockFile = "conan.lock"
	conanTxtFile  = "conanfile.txt"
	vcpkgFile     = "vcpkg.json"
)

// ResolveDependencyVersions reads the C/C++ codebase's declared dependency versions from the Conan
// and vcpkg manifests at the build root and returns the version for the requested coordinate (the
// package name, compared case-insensitively). An empty coordinate enumerates every declaration.
//
// SOUNDNESS (inv.5): only an exact pin resolves — a conan.lock reference, a conanfile.txt
// requirement with a literal version, or a vcpkg.json override. A Conan version range, a vcpkg
// "version>=" minimum, or a bare vcpkg dependency name is UNRESOLVED (source_unpinned), never a
// guessed version. A conanfile.py is a Python program, not a manifest; it is not executed or
// pattern-matched.
//
// A coordinate no manifest declares is NOT evidence of absence in C/C++: system packages,
// vendored sources and header-only copies never appear in a package manifest, so a miss is
// declared no_manifest rather than reading as "not a dependency". Two manifests pinning one
// package to different versions resolve to neither (lockfile_ambiguous).
//
// A missing or non-directory build dir is a hard error; an unparseable manifest degrades to
// tool_failure and the dependencies it would have carried are unknown, not absent.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("cfamilyanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("cfamilyanalysis: build dir %q is not a directory", req.BuildDir)
	}

	var (
		all         []plugin.ResolvedDependency
		read        int
		parseFailed bool
	)
	for _, m := range []struct {
		name  string
		parse func([]byte) ([]plugin.ResolvedDependency, bool)
	}{
		{conanLockFile, parseConanLock},
		{conanTxtFile, parseConanfileTxt},
		{vcpkgFile, parseVcpkgManifest},
	} {
		data, err := os.ReadFile(filepath.Join(req.BuildDir, m.name))
		if err != nil {
			if !os.IsNotExist(err) {
				parseFailed = true
			}
			continue
		}
		read++
		deps, ok := m.parse(data)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}
	reasons := newReasonSet()
	if read == 0 {
		reasons.add(plugin.PartialReasonNoManifest)
	}
	if parseFailed {
		reasons.add(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{All: all}
	want := strings.ToLower(strings.TrimSpace(req.Coordinate))
	if want == "" {
		for _, d := range all {
			if !d.Resolved {
				reasons.add(plugin.PartialReasonSourceUnpinned)
				break
			}
		}
		res.Partiality = reasons.partiality()
		return res, nil
	}

	var resolved []plugin.ResolvedDependency
	for _, d := range all {
		if strings.ToLower(d.Coordinate) != want {
			continue
		}
		if !res.Found {
			res.Found, res.Match = true, d
		}
		if d.Resolved {
			resolved = append(resolved, d)
		}
	}
	switch {
	case !res.Found:
		reasons.add(plugin.PartialReasonNoManifest)
	case len(resolved) == 0:
		reasons.add(plugin.PartialReasonSourceUnpinned)
	case !sameVersion(resolved):
		res.Match = plugin.ResolvedDependency{Coordinate: resolved[0].Coordinate}
		reasons.add(plugin.PartialReasonLockfileAmbiguous)
	default:
		res.Match = resolved[0]
	}
	res.Partiality = reasons.partiality()
	return res, nil
}

func sameVersion(deps []plugin.ResolvedDependency) bool {
	for _, d := range deps[1:] {
		if d.Version != deps[0].Version {
			return false
		}
	}
	return true
}

// parseConanLock reads a Conan 2 lockfile (format "0.5"): its "requires" are the resolved host
// graph as "name/version[@user/channel][#rrev[%timestamp]]" references, every one an exact pin.
// build_requires and python_requires are build tooling, not linked into the product, and are not
// read. Any other lockfile format version is not parsed: its shape is unverified, and reading
// zero requirements out of an unfamiliar shape would look like an empty graph.
func parseConanLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var lock struct {
		Version  string   `json:"version"`
		Requires []string `json:"requires"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || lock.Version != "0.5" {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	ok := true
	for _, ref := range lock.Requires {
		name, version, valid := splitConanRef(ref)
		if !valid || isConanRange(version) {
			ok = false
			continue
		}
		out = append(out, plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: conanLockFile})
	}
	return out, ok
}

// parseConanfileTxt reads the [requires] section of a conanfile.txt. A literal version is the exact
// requirement Conan resolves; a bracketed range ("zlib/[>=1.2 <2]") is a constraint, UNRESOLVED.
// Tool, build and test requirements are not linked into the product and are not read.
func parseConanfileTxt(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	ok := true
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.Contains(line, "/") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "requires" {
			continue
		}
		name, version, valid := splitConanRef(line)
		if !valid {
			ok = false
			continue
		}
		if isConanRange(version) {
			out = append(out, plugin.ResolvedDependency{Coordinate: name, Source: conanTxtFile})
			continue
		}
		out = append(out, plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: conanTxtFile})
	}
	if sc.Err() != nil {
		ok = false
	}
	return out, ok
}

// splitConanRef splits "name/version[@user/channel][#rev[%ts]]" into name and version.
func splitConanRef(ref string) (name, version string, ok bool) {
	ref = strings.TrimSpace(ref)
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	name, version, found := strings.Cut(ref, "/")
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if !found || name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

func isConanRange(version string) bool { return strings.HasPrefix(version, "[") }

// parseVcpkgManifest reads a vcpkg.json. An overrides[] entry pins an exact version; a
// dependencies[] entry is a name with at most a "version>=" minimum, UNRESOLVED unless an override
// pins it. builtin-baseline is a registry commit, not a per-package pin, and is not read as one.
// A port-version is vcpkg's packaging revision of the upstream version; a non-zero one stays on the
// pin in vcpkg's own "version#port-version" form, since two port-versions of one upstream version
// are different builds.
func parseVcpkgManifest(data []byte) ([]plugin.ResolvedDependency, bool) {
	var m struct {
		Dependencies []json.RawMessage `json:"dependencies"`
		Overrides    []struct {
			Name          string `json:"name"`
			Version       string `json:"version"`
			VersionSemver string `json:"version-semver"`
			VersionDate   string `json:"version-date"`
			VersionString string `json:"version-string"`
			PortVersion   int    `json:"port-version"`
		} `json:"overrides"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	ok := true
	pinned := map[string]bool{}
	var out []plugin.ResolvedDependency
	for _, o := range m.Overrides {
		v := firstNonEmpty(o.Version, o.VersionSemver, o.VersionDate, o.VersionString)
		if o.Name == "" || v == "" || o.PortVersion < 0 {
			ok = false
			continue
		}
		pinned[strings.ToLower(o.Name)] = true
		out = append(out, plugin.ResolvedDependency{Coordinate: o.Name, Version: vcpkgVersion(v, o.PortVersion), Resolved: true, Source: vcpkgFile})
	}
	for _, raw := range m.Dependencies {
		var name string
		if err := json.Unmarshal(raw, &name); err != nil {
			var obj struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil || obj.Name == "" {
				ok = false
				continue
			}
			name = obj.Name
		}
		if pinned[strings.ToLower(name)] {
			continue
		}
		out = append(out, plugin.ResolvedDependency{Coordinate: name, Source: vcpkgFile})
	}
	return out, ok
}

// vcpkgVersion renders an upstream version and its port-version the way vcpkg writes them.
func vcpkgVersion(version string, portVersion int) string {
	if portVersion == 0 {
		return version
	}
	return version + "#" + strconv.Itoa(portVersion)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
