package trigger

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// notExploitableGrounds is the positive-grounds gate of finding()'s default arm. Reaching that arm
// means no path was found and no step declared it did not run; this decides whether the absence
// is evidence about the admitted package. It returns the NE detail naming the grounds, or the
// undetermined reason when there are none:
//
//   - G1: the advisory was admitted on a package whose installed version resolved.
//   - G2 arm A: every advisory symbol resolved to code inside that package, and the lane searched
//     every such sink from its entry points.
//   - G2 arm B: the lane refuted that package on positive evidence (ReachabilityResult.Refutation).
//
// Both arms speak for the admitted package only, so neither grounds an advisory that also names
// another package: that package's symbols were never resolved or searched, and it may be installed
// beside the admitted one.
//
// A leaf-name hit in first-party code never counts toward arm A: its origin is not the package.
func notExploitableGrounds(store artifact.Store, assessmentID string, pkg *report.Package, mods goModules) (detail, reason string, ok bool) {
	admitted, label, ok := admittedPackage(store, assessmentID, pkg)
	if !ok {
		return "", report.ReasonPackageVersionUnresolved, false
	}
	reach, _ := reachabilityResult(store, assessmentID)
	symbols := pipeline.AdvisorySymbols(store, assessmentID)
	if namesOtherPackage(pipeline.AdvisoryPackagePURLs(store, assessmentID), admitted, mods) {
		if len(symbols) == 0 {
			return "", report.ReasonAdvisorySymbolAbsent, false
		}
		return "", report.ReasonVulnerableSymbolUnresolved, false
	}

	if len(symbols) > 0 {
		res, err := pipeline.VulnerableSymbols(store, assessmentID)
		if err == nil && searchedInPackage(symbols, res, reach.Searched, admitted) {
			return fmt.Sprintf("no path from any entry point reaches %s in %s",
				strings.Join(symbols, ", "), label), "", true
		}
	}
	if r := reach.Refutation; r != nil {
		if key, ok := purlKey(r.Package); ok && key == admitted {
			if r.Detail == "" {
				return fmt.Sprintf("%s: %s", label, r.Basis), "", true
			}
			return fmt.Sprintf("%s: %s (%s)", label, r.Detail, r.Basis), "", true
		}
	}
	if len(symbols) == 0 {
		return "", report.ReasonAdvisorySymbolAbsent, false
	}
	return "", report.ReasonVulnerableSymbolUnresolved, false
}

// namesOtherPackage reports whether the advisory names a package other than the admitted one that
// may be in the build. A package URL that does not parse cannot be shown to be the admitted
// package, so it counts as other.
func namesOtherPackage(purls []string, admitted pkgKey, mods goModules) bool {
	for _, p := range purls {
		key, ok := purlKey(p)
		if !ok || !(samePackage(key, admitted, mods) || outsideBuild(key, mods)) {
			return true
		}
	}
	return false
}

// samePackage reports whether a package the advisory names is the admitted one. A Go advisory
// also names packages by import path: golang.org/x/net/http2 beside golang.org/x/net, net/http
// beside stdlib. A standard library path is stdlib. Any other path is the admitted module only
// when that is the build's module that holds it, so a path under a nested module the build also
// selects (github.com/containerd/containerd/v2 under github.com/containerd/containerd) stays
// another package, and without a module list no path collapses.
func samePackage(key, admitted pkgKey, mods goModules) bool {
	if key == admitted {
		return true
	}
	if key.typ != "golang" || admitted.typ != "golang" {
		return false
	}
	if admitted.name == goStdlib {
		return stdlibPath(key.name)
	}
	return mods.holding(key.name) == admitted.name
}

// outsideBuild reports whether a Go module path the advisory names is held by none of the build's
// modules, so none of its code is compiled in. Only a module path qualifies: the standard library,
// the toolchain and other paths without a dotted first element are always counted.
func outsideBuild(key pkgKey, mods goModules) bool {
	if key.typ != "golang" || mods == nil {
		return false
	}
	first, _, _ := strings.Cut(key.name, "/")
	return strings.Contains(first, ".") && mods.holding(key.name) == ""
}

const goStdlib = "stdlib"

// goModules is the set of Go module paths a scan's build selects, replace targets included; nil
// when the list is unknown or incomplete.
type goModules map[string]bool

// goModulesOf returns the Go modules of a scan's SBOM, or nil unless they are the build's whole
// module list. Only the module build list `go mod graph` resolves qualifies (a vendored module
// resolves to the same list); go.mod's require block alone does not, and a go.work workspace is
// declared unsupported by the inventory, so it carries no build list. The main module counts, and
// each dependency counts under its own path and under the path of the module a replace directive
// substitutes for it.
//
// The module graph can list more than the build compiles (a module whose packages nothing imports),
// and that errs only toward "in the build", which keeps an advisory blocking. A narrower source,
// such as the packages a build actually loads, would err toward collapsing; it qualifies only if
// it is the build's complete package set.
func goModulesOf(sbom report.SBOM, limits []report.PartialityNote) goModules {
	if sbom.GoBuildList != plugin.BuildListGoModGraph || sbom.GoMainModule == "" {
		return nil
	}
	for _, n := range limits {
		if n.Ecosystem == "" || n.Ecosystem == "Go" {
			return nil
		}
	}
	mods := goModules{sbom.GoMainModule: true}
	for _, p := range sbom.Packages {
		if p.Ecosystem != "Go" {
			continue
		}
		for _, path := range []string{p.Name, p.Replace} {
			if path != "" {
				mods[path] = true
			}
		}
	}
	return mods
}

// holding returns the module that holds an import path: the longest module path that is the path
// or a prefix of it at a '/' boundary, or "" when none is.
func (m goModules) holding(path string) string {
	for p := path; ; {
		if m[p] {
			return p
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return ""
		}
		p = p[:i]
	}
}

// stdlibPath reports whether an import path is in the Go standard library: its first element is
// one of the library's top-level directories. cmd is the toolchain, not the library.
func stdlibPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return stdlibRoots[first]
}

var stdlibRoots = map[string]bool{
	"archive": true, "bufio": true, "builtin": true, "bytes": true, "cmp": true, "compress": true,
	"container": true, "context": true, "crypto": true, "database": true, "debug": true,
	"embed": true, "encoding": true, "errors": true, "expvar": true, "flag": true, "fmt": true,
	"go": true, "hash": true, "html": true, "image": true, "index": true, "internal": true,
	"io": true, "iter": true, "log": true, "maps": true, "math": true, "mime": true, "net": true,
	"os": true, "path": true, "plugin": true, "reflect": true, "regexp": true, "runtime": true,
	"slices": true, "sort": true, "strconv": true, "strings": true, "structs": true, "sync": true,
	"syscall": true, "testing": true, "text": true, "time": true, "unicode": true, "unique": true,
	"unsafe": true, "weak": true,
}

// searchedInPackage is arm A: every advisory symbol has at least one resolved symbol whose origin
// is the admitted package, and every such in-package symbol was searched.
func searchedInPackage(symbols []string, res plugin.SymbolResolutionResult, searched []string, admitted pkgKey) bool {
	done := make(map[string]bool, len(searched))
	for _, s := range searched {
		done[s] = true
	}
	for _, sym := range symbols {
		inPackage := 0
		for _, scip := range res.Matched[sym] {
			origin, ok := res.Origins[scip]
			if !ok {
				continue // first-party: matches only a root package (not admitted here yet)
			}
			if key, ok := purlKey(origin); !ok || key != admitted {
				continue
			}
			if !done[scip] {
				return false
			}
			inPackage++
		}
		if inPackage == 0 {
			return false
		}
	}
	return true
}

// admittedPackage returns the key of the package the advisory was admitted on and a name@version
// label for the detail, or false when no installed version resolved (G1).
//
// A Go toolchain subject has no SBOM package; toolchainUndetermined has already required that the
// subject's exact toolchain was scanned, so the scanned toolchain is the version.
func admittedPackage(store artifact.Store, assessmentID string, pkg *report.Package) (pkgKey, string, bool) {
	if pipeline.ToolchainSubject(store, assessmentID) {
		reach, _ := reachabilityResult(store, assessmentID)
		return pkgKey{typ: "golang", name: goStdlib}, "stdlib@" + reach.ScanToolchain, true
	}
	if pkg == nil || pkg.Version == "" || strings.HasPrefix(pkg.PartialReason, plugin.PartialReasonSourceUnpinned) {
		return pkgKey{}, "", false
	}
	for _, p := range []string{pipeline.AdvisoryPURL(store, assessmentID), pkg.PURL} {
		if key, ok := purlKey(p); ok {
			return key, pkg.Name + "@" + pkg.Version, true
		}
	}
	if typ, ok := purlTypeFor[pkg.Ecosystem]; ok && pkg.Name != "" {
		return pkgKey{typ: typ, name: normalizePackageName(typ, pkg.Name)}, pkg.Name + "@" + pkg.Version, true
	}
	return pkgKey{}, "", false
}

// pkgKey identifies a package across versions: PURL type plus the ecosystem-normalized name.
type pkgKey struct {
	typ, name string
}

var purlTypeFor = map[string]string{
	"Go":    "golang",
	"npm":   "npm",
	"PyPI":  "pypi",
	"Maven": "maven",
	"NuGet": "nuget",
}

// purlKey parses a package URL into its pkgKey, ignoring version, qualifiers and subpath.
func purlKey(purl string) (pkgKey, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return pkgKey{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return pkgKey{}, false
	}
	// The version separator is the '@' after the last '/'; an npm scope's '@' precedes it.
	if at := strings.LastIndex(path, "@"); at > strings.LastIndex(path, "/") {
		path = path[:at]
	}
	if dec, err := url.PathUnescape(path); err == nil {
		path = dec
	}
	typ = strings.ToLower(typ)
	if typ == "maven" {
		if group, artifact, ok := strings.Cut(path, "/"); ok {
			path = group + ":" + artifact
		}
	}
	name := normalizePackageName(typ, path)
	if name == "" {
		return pkgKey{}, false
	}
	return pkgKey{typ: typ, name: name}, true
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// normalizePackageName applies the ecosystem's name-equivalence rule.
func normalizePackageName(typ, name string) string {
	switch typ {
	case "pypi":
		return pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
	case "nuget":
		return strings.ToLower(name)
	default:
		return name
	}
}

// reachabilityResult reads the reachability stage's result off its artifact.
func reachabilityResult(store artifact.Store, assessmentID string) (plugin.ReachabilityResult, bool) {
	arts, err := store.Query(assessmentID, artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		return plugin.ReachabilityResult{}, false
	}
	var payload struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil {
		return plugin.ReachabilityResult{}, false
	}
	return payload.Reachability, true
}
