package cfamilyanalysis

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Dependency manifests the lane reads, relative to the build root. Per package manager, a lock tier
// records the resolved graph (a Conan lockfile, vcpkg's installed-package database) and a declared
// tier records what the project asked for (a conanfile.txt, a vcpkg manifest).
const (
	conanLockFile    = "conan.lock"
	conanTxtFile     = "conanfile.txt"
	vcpkgFile        = "vcpkg.json"
	vcpkgStatusFile  = "vcpkg_installed/vcpkg/status"
	vcpkgUpdatesDir  = "vcpkg_installed/vcpkg/updates"
	purlTypeConan    = "conan"
	purlTypeVcpkg    = "vcpkg"
	vcpkgInstalledOK = "install ok installed"
)

// cdep is one dependency a manifest records. ResolveDependencyVersions and ResolveInventory both
// read these, so the two never disagree on what a manifest pins.
type cdep struct {
	name        string
	version     string // exact upstream version; empty when not pinned
	portVersion int    // vcpkg's packaging revision of version; 0 is none
	resolved    bool
	source      string // manifest path relative to the build root, slash-separated
	purlType    string
	lockTier    bool
	user        string // Conan reference namespace
	channel     string
	ref         string // the reference as the manifest spells it
	triplet     string // vcpkg triplet the package is installed for
	depends     []cdepRef
}

// cdepRef names a dependency of a cdep within the same manifest.
type cdepRef struct{ name, triplet string }

// fullVersion is the pinned version as its manager writes it: a non-zero vcpkg port-version stays
// on it ("1.3.1#2"), since two port-versions of one upstream version are different builds.
func (d cdep) fullVersion() string { return vcpkgVersion(d.version, d.portVersion) }

func (d cdep) resolvedDependency() plugin.ResolvedDependency {
	if !d.resolved {
		return plugin.ResolvedDependency{Coordinate: d.name, Source: d.source}
	}
	return plugin.ResolvedDependency{Coordinate: d.name, Version: d.fullVersion(), Resolved: true, Source: d.source}
}

// manifestSet is what readManifests found at a build root.
type manifestSet struct {
	deps        []cdep
	read        int  // manifests read
	parseFailed bool // a manifest was unreadable or did not parse
	// present holds each package manager with at least one manifest at the root, readable or not.
	present map[string]bool
	// locked holds each package manager whose lock tier parsed and pins at least one package.
	locked map[string]bool
	// declared holds, per package manager, the lower-cased names the declared tier asks for.
	declared map[string]map[string]bool
}

// readManifests reads every dependency manifest at the build root. A declared-tier entry with no
// pin is dropped when its manager's lock tier pins the same name: the lock is what that range or
// bare name resolved to. A declared pin is kept beside the lock's, so a stale declaration that
// disagrees with the lock still surfaces.
func readManifests(buildDir string) manifestSet {
	ms := manifestSet{present: map[string]bool{}, locked: map[string]bool{}, declared: map[string]map[string]bool{}}
	for _, m := range []struct {
		name     string
		purlType string
		lockTier bool
		read     func(buildDir string) ([]byte, error)
		parse    func([]byte) ([]cdep, bool)
	}{
		{conanLockFile, purlTypeConan, true, readRootFile(conanLockFile), parseConanLock},
		{conanTxtFile, purlTypeConan, false, readRootFile(conanTxtFile), parseConanfileTxt},
		{vcpkgStatusFile, purlTypeVcpkg, true, readVcpkgStatus, parseVcpkgStatus},
		{vcpkgFile, purlTypeVcpkg, false, readRootFile(vcpkgFile), parseVcpkgManifest},
	} {
		data, err := m.read(buildDir)
		if err != nil {
			if !os.IsNotExist(err) {
				ms.parseFailed = true
				ms.present[m.purlType] = true
			}
			continue
		}
		ms.read++
		ms.present[m.purlType] = true
		deps, ok := m.parse(data)
		if !ok {
			ms.parseFailed = true
		}
		for i := range deps {
			deps[i].source, deps[i].purlType, deps[i].lockTier = m.name, m.purlType, m.lockTier
			if m.lockTier && deps[i].resolved {
				ms.locked[m.purlType] = true
			}
			if !m.lockTier {
				if ms.declared[m.purlType] == nil {
					ms.declared[m.purlType] = map[string]bool{}
				}
				ms.declared[m.purlType][strings.ToLower(deps[i].name)] = true
			}
		}
		ms.deps = append(ms.deps, deps...)
	}

	lockPinned := map[string]bool{}
	for _, d := range ms.deps {
		if d.lockTier && d.resolved {
			lockPinned[d.purlType+"/"+strings.ToLower(d.name)] = true
		}
	}
	kept := ms.deps[:0]
	for _, d := range ms.deps {
		if !d.lockTier && !d.resolved && lockPinned[d.purlType+"/"+strings.ToLower(d.name)] {
			continue
		}
		kept = append(kept, d)
	}
	ms.deps = kept
	return ms
}

func readRootFile(name string) func(string) ([]byte, error) {
	return func(buildDir string) ([]byte, error) { return os.ReadFile(filepath.Join(buildDir, name)) }
}

// checkBuildDir is the hard error both dependency ops return for a build dir they cannot read.
func checkBuildDir(buildDir string) error {
	info, err := os.Stat(buildDir)
	if err != nil {
		return fmt.Errorf("cfamilyanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cfamilyanalysis: build dir %q is not a directory", buildDir)
	}
	return nil
}

// ResolveDependencyVersions reads the C/C++ codebase's declared dependency versions from the Conan
// and vcpkg manifests at the build root and returns the version for the requested coordinate (the
// package name, compared case-insensitively). An empty coordinate enumerates every declaration.
//
// SOUNDNESS (inv.5): only an exact pin resolves — a conan.lock reference, a conanfile.txt
// requirement with a literal version, a package vcpkg records as installed, or a vcpkg.json
// override. A Conan version range, a vcpkg "version>=" minimum, or a bare vcpkg dependency name is
// UNRESOLVED (source_unpinned), never a guessed version, unless the same manager's lock tier pins
// that name. A conanfile.py is a Python program, not a manifest; it is not executed or
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
	if err := checkBuildDir(req.BuildDir); err != nil {
		return plugin.DependencyVersionResult{}, err
	}
	ms := readManifests(req.BuildDir)
	all := make([]plugin.ResolvedDependency, 0, len(ms.deps))
	for _, d := range ms.deps {
		all = append(all, d.resolvedDependency())
	}
	if len(all) == 0 {
		all = nil
	}
	reasons := newReasonSet()
	if ms.read == 0 {
		reasons.add(plugin.PartialReasonNoManifest)
	}
	if ms.parseFailed {
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
func parseConanLock(data []byte) ([]cdep, bool) {
	var lock struct {
		Version  string   `json:"version"`
		Requires []string `json:"requires"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || lock.Version != "0.5" {
		return nil, false
	}
	var out []cdep
	ok := true
	for _, raw := range lock.Requires {
		ref, valid := parseConanRef(raw)
		if !valid || isConanRange(ref.version) {
			ok = false
			continue
		}
		out = append(out, cdep{name: ref.name, version: ref.version, resolved: true, user: ref.user, channel: ref.channel, ref: strings.TrimSpace(raw)})
	}
	return out, ok
}

// parseConanfileTxt reads the [requires] section of a conanfile.txt. A literal version is the exact
// requirement Conan resolves; a bracketed range ("zlib/[>=1.2 <2]") is a constraint, UNRESOLVED.
// Tool, build and test requirements are not linked into the product and are not read.
func parseConanfileTxt(data []byte) ([]cdep, bool) {
	var out []cdep
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
		ref, valid := parseConanRef(line)
		if !valid {
			ok = false
			continue
		}
		d := cdep{name: ref.name, user: ref.user, channel: ref.channel, ref: line}
		if !isConanRange(ref.version) {
			d.version, d.resolved = ref.version, true
		}
		out = append(out, d)
	}
	if sc.Err() != nil {
		ok = false
	}
	return out, ok
}

type conanRef struct{ name, version, user, channel string }

// parseConanRef splits "name/version[@user/channel][#rev[%ts]]".
func parseConanRef(raw string) (conanRef, bool) {
	ref := strings.TrimSpace(raw)
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		ref = ref[:i]
	}
	var r conanRef
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		r.user, r.channel, _ = strings.Cut(ref[i+1:], "/")
		r.user, r.channel = strings.TrimSpace(r.user), strings.TrimSpace(r.channel)
		ref = ref[:i]
	}
	name, version, found := strings.Cut(ref, "/")
	r.name, r.version = strings.TrimSpace(name), strings.TrimSpace(version)
	if !found || r.name == "" || r.version == "" {
		return conanRef{}, false
	}
	return r, true
}

func isConanRange(version string) bool { return strings.HasPrefix(version, "[") }

// readVcpkgStatus reads vcpkg's installed-package database: the status file, then each file in
// the updates directory beside it in name order. vcpkg appends one update per package it installs
// or removes and folds them into status on a later run, so status alone can lag the tree.
func readVcpkgStatus(buildDir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(buildDir, filepath.FromSlash(vcpkgStatusFile)))
	if err != nil {
		return nil, err
	}
	updatesDir := filepath.Join(buildDir, filepath.FromSlash(vcpkgUpdatesDir))
	entries, err := os.ReadDir(updatesDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		u, err := os.ReadFile(filepath.Join(updatesDir, n))
		if err != nil {
			return nil, err
		}
		data = append(append(data, "\n\n"...), u...)
	}
	return data, nil
}

// parseVcpkgStatus reads vcpkg's installed-package database, a sequence of "Field: value"
// paragraphs. A paragraph without a Feature field is a package installed for its Architecture
// (triplet), at Version and Port-Version: an exact pin. A Feature paragraph adds that feature's
// Depends to its package. A later paragraph for the same package, feature and triplet replaces an
// earlier one, as the updates vcpkg appends do. Only "install ok installed" counts; a package
// recorded as not installed is gone. Any other state, or a paragraph that names no package, does
// not parse.
func parseVcpkgStatus(data []byte) ([]cdep, bool) {
	paras, ok := controlParagraphs(data)
	type key struct{ pkg, feature, arch string }
	latest := map[key]map[string]string{}
	var order []key
	for _, p := range paras {
		k := key{strings.ToLower(p["Package"]), p["Feature"], p["Architecture"]}
		if k.pkg == "" {
			ok = false
			continue
		}
		if _, seen := latest[k]; !seen {
			order = append(order, k)
		}
		latest[k] = p
	}

	byPkg := map[cdepRef]int{}
	var out []cdep
	for _, k := range order {
		p := latest[k]
		if k.feature != "" {
			continue
		}
		switch status := p["Status"]; {
		case status == vcpkgInstalledOK:
		case strings.HasSuffix(status, " not-installed"):
			continue
		default:
			ok = false
			continue
		}
		d := cdep{name: p["Package"], triplet: k.arch, ref: p["Package"] + ":" + k.arch, version: p["Version"]}
		d.resolved = d.version != ""
		if pv := p["Port-Version"]; pv != "" {
			n, err := strconv.Atoi(pv)
			if err != nil || n < 0 {
				ok = false
				d.resolved = false
			}
			d.portVersion = n
		}
		if !d.resolved {
			d.version, d.portVersion = "", 0
		}
		d.depends = vcpkgDepends(p["Depends"], k.arch)
		byPkg[cdepRef{k.pkg, k.arch}] = len(out)
		out = append(out, d)
	}
	for _, k := range order {
		p := latest[k]
		if k.feature == "" || p["Status"] != vcpkgInstalledOK {
			continue
		}
		if i, found := byPkg[cdepRef{k.pkg, k.arch}]; found {
			out[i].depends = append(out[i].depends, vcpkgDepends(p["Depends"], k.arch)...)
		}
	}
	return out, ok
}

// vcpkgDepends splits a status Depends field ("zlib, vcpkg-cmake:x64-linux") into package
// references. An entry with no triplet is installed for the depending package's own.
func vcpkgDepends(field, arch string) []cdepRef {
	var out []cdepRef
	for _, e := range strings.Split(field, ",") {
		e = strings.TrimSpace(e)
		if i := strings.IndexAny(e, "[("); i >= 0 {
			e = strings.TrimSpace(e[:i])
		}
		if e == "" {
			continue
		}
		name, triplet, found := strings.Cut(e, ":")
		if !found || triplet == "" {
			triplet = arch
		}
		out = append(out, cdepRef{strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(triplet)})
	}
	return out
}

// controlParagraphs splits Debian-control-style text into paragraphs of fields. A line that starts
// with a space continues the previous field. The bool is false when a line is neither a field nor
// a continuation.
func controlParagraphs(data []byte) ([]map[string]string, bool) {
	var (
		out  []map[string]string
		cur  map[string]string
		last string
		ok   = true
	)
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur, last = nil, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				ok = false
				continue
			}
			cur[last] += "\n" + strings.TrimSpace(line)
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			ok = false
			continue
		}
		if cur == nil {
			cur = map[string]string{}
		}
		last = strings.TrimSpace(field)
		cur[last] = strings.TrimSpace(value)
	}
	if sc.Err() != nil {
		ok = false
	}
	flush()
	return out, ok
}

// parseVcpkgManifest reads a vcpkg.json. An overrides[] entry pins an exact version; a
// dependencies[] entry is a name with at most a "version>=" minimum, UNRESOLVED unless an override
// pins it. builtin-baseline is a registry commit, not a per-package pin, and is not read as one.
func parseVcpkgManifest(data []byte) ([]cdep, bool) {
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
	var out []cdep
	for _, o := range m.Overrides {
		v := firstNonEmpty(o.Version, o.VersionSemver, o.VersionDate, o.VersionString)
		if o.Name == "" || v == "" || o.PortVersion < 0 {
			ok = false
			continue
		}
		pinned[strings.ToLower(o.Name)] = true
		out = append(out, cdep{name: o.Name, version: v, portVersion: o.PortVersion, resolved: true, ref: o.Name})
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
		out = append(out, cdep{name: name, ref: name})
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
