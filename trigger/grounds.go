package trigger

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// notExploitableGrounds is the positive-grounds gate of finding()'s default arm. Reaching that arm
// means no path was found and no step declared it did not run; this decides whether the absence
// is evidence about the admitted package. It returns the NE detail naming the grounds and the basis
// they rest on, or the undetermined reason when there are none:
//
//   - G1: the advisory was admitted on a package whose installed version resolved.
//   - G2 arm A: every advisory symbol resolved to code inside that package, and the lane searched
//     every such sink from its entry points. It grounds only on a vetted symbol set (vettedSymbols);
//     an unvetted one leaves the advisory undetermined unless arm B grounds it.
//   - G2 arm B: the lane refuted that package on positive evidence (ReachabilityResult.Refutation).
//     The refutation's assumptions come back with the detail: the verdict holds only under them.
//     Arm A carries them too, since the lane's search started from the same entry points.
//
// Arm A, and arm B on any refutation but package_not_loaded, show the code present and unreached:
// the basis is BasisSymbolUnreachable. package_not_loaded shows the package's code never loads, so
// it is BasisSymbolAbsent.
//
// Both arms speak for the admitted package only, so neither grounds an advisory that also names
// another package: that package's symbols were never resolved or searched, and it may be installed
// beside the admitted one.
//
// A leaf-name hit in first-party code never counts toward arm A: its origin is not the package.
func notExploitableGrounds(store artifact.Store, assessmentID string, pkg *report.Package, mods goModules) (detail, reason string, basis verdict.NonExploitableBasis, assumptions []string, ok bool) {
	admitted, label, ok := admittedPackage(store, assessmentID, pkg)
	if !ok {
		return "", report.ReasonPackageVersionUnresolved, "", nil, false
	}
	root := pkg != nil && pkg.Root
	reach, _ := reachabilityResult(store, assessmentID)
	symbols := pipeline.AdvisorySymbols(store, assessmentID)
	if namesOtherPackage(pipeline.AdvisoryPackagePURLs(store, assessmentID), admitted, mods) {
		if len(symbols) == 0 {
			return "", report.ReasonAdvisorySymbolAbsent, "", nil, false
		}
		return "", report.ReasonVulnerableSymbolUnresolved, "", nil, false
	}

	unvetted := false
	if len(symbols) > 0 {
		res, err := pipeline.VulnerableSymbols(store, assessmentID)
		absent := targetConditionalAbsent(symbols, pipeline.AdvisoryTargetConditionalSymbols(store, assessmentID), res)
		if err == nil && searchedInPackage(symbols, absent, res, reach.Searched, admitted, root) {
			if !vettedSymbols(store, assessmentID) {
				unvetted = true
			} else if len(absent) == 0 {
				return fmt.Sprintf("no path from any entry point reaches %s in %s",
					strings.Join(symbols, ", "), label), "", verdict.BasisSymbolUnreachable, refutationAssumptions(reach), true
			} else {
				present := slices.DeleteFunc(slices.Clone(symbols), func(s string) bool { return slices.Contains(absent, s) })
				return fmt.Sprintf("no path from any entry point reaches %s in %s, whose build target does not define %s",
					strings.Join(present, ", "), label, strings.Join(absent, ", ")), "", verdict.BasisSymbolUnreachable, refutationAssumptions(reach), true
			}
		}
	}
	// package_not_loaded speaks for one package, so it grounds only an advisory whose record lists
	// every package it affects, and never the scanned project, whose own code always loads.
	if r := reach.Refutation; r != nil && (r.Basis != plugin.RefutationPackageNotLoaded ||
		!root && pipeline.AdvisoryListsAffectedPackages(store, assessmentID)) {
		if r.Package != "" && inAdmitted(r.Package, admitted, root) {
			basis := verdict.BasisSymbolUnreachable
			if r.Basis == plugin.RefutationPackageNotLoaded {
				basis = verdict.BasisSymbolAbsent
			}
			if r.Detail == "" {
				return fmt.Sprintf("%s: %s", label, r.Basis), "", basis, r.Assumptions, true
			}
			return fmt.Sprintf("%s: %s (%s)", label, r.Detail, r.Basis), "", basis, r.Assumptions, true
		}
	}
	if unvetted {
		return "", report.ReasonAdvisorySymbolsUnvetted, "", nil, false
	}
	if len(symbols) == 0 {
		return "", report.ReasonAdvisorySymbolAbsent, "", nil, false
	}
	return "", report.ReasonVulnerableSymbolUnresolved, "", nil, false
}

// vettedSymbols reports whether the advisory's symbol set is complete enough for an absence of the
// listed symbols to ground not_exploitable: no path reaching them (arm A), or no module declaring
// them (outsideBuildGrounds). An osv-declared or curated set is; so is an untagged set the built-in
// table answered, whose marker S1 sets from where the record came from, never from the record. A
// diff-lexed set is a candidate list lexed from the fix, which can miss the vulnerable function; a
// cna-declared set's completeness has not been measured; and an untagged corpus set, or a tag this
// version does not know, says nothing about how the set was obtained. A record's own trust_tier
// does not vouch for its symbol set.
func vettedSymbols(store artifact.Store, assessmentID string) bool {
	arts, err := store.Query(assessmentID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return false
	}
	var adv struct {
		SymbolProvenance string `json:"symbol_provenance"`
		BuiltIn          bool   `json:"built_in"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return false
	}
	switch adv.SymbolProvenance {
	case "osv-declared", "curated":
		return true
	case "":
		return adv.BuiltIn
	default:
		return false
	}
}

// outsideBuildGrounds grounds an advisory on a Go package that no module of the build holds, when
// it resolved no package to assess. The advisory's code is absent from the build only if no module
// carries it under another path, as a renamed fork would, so it grounds only when the lane read the
// source of every module in the build's complete module list and found no declaration of an
// advisory symbol. A fork is found only through the listed symbols, so the set must be vetted
// (vettedSymbols). It returns the NE detail, or false when any of that is not shown: no module
// list, no symbols, an advisory naming more than one package, a module the lane could not read, or
// a module that declares a symbol. When everything else is shown but the set is unvetted, reason is
// advisory_symbols_unvetted; otherwise it is "".
func outsideBuildGrounds(store artifact.Store, assessmentID string, pkg *report.Package, mods goModules) (detail, reason string, ok bool) {
	symbols := pipeline.AdvisorySymbols(store, assessmentID)
	purls := pipeline.AdvisoryPackagePURLs(store, assessmentID)
	if pkg != nil || mods == nil || len(symbols) == 0 || len(purls) == 0 {
		return "", "", false
	}
	key, ok := purlKey(purls[0])
	if !ok || !outsideBuild(key, mods) {
		return "", "", false
	}
	for _, p := range purls[1:] {
		if k, ok := purlKey(p); !ok || k != key {
			return "", "", false
		}
	}
	res, err := pipeline.VulnerableSymbols(store, assessmentID)
	if err != nil || res.ModuleSearch == nil || len(res.ModuleSearch.Declaring) > 0 {
		return "", "", false
	}
	searched := make(map[string]bool, len(res.ModuleSearch.Searched))
	for _, m := range res.ModuleSearch.Searched {
		searched[m] = true
	}
	for m := range mods {
		if !searched[m] {
			return "", "", false
		}
	}
	if !vettedSymbols(store, assessmentID) {
		return "", report.ReasonAdvisorySymbolsUnvetted, false
	}
	return fmt.Sprintf("no module in the build holds %s, and none of the build's %d modules declares %s",
		key.name, len(mods), strings.Join(symbols, ", ")), "", true
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
// the toolchain and other paths without a dotted first element are always counted. Paths are
// compared ignoring case, so a path an advisory spells in another case than the build's module
// counts as in the build.
func outsideBuild(key pkgKey, mods goModules) bool {
	if key.typ != "golang" || mods == nil {
		return false
	}
	first, _, _ := strings.Cut(key.name, "/")
	return strings.Contains(first, ".") && !mods.holdsFold(key.name)
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

// holdsFold reports whether a module holds an import path, comparing paths ignoring case.
func (m goModules) holdsFold(path string) bool {
	for mod := range m {
		if len(path) >= len(mod) && strings.EqualFold(path[:len(mod)], mod) && (len(path) == len(mod) || path[len(mod)] == '/') {
			return true
		}
	}
	return false
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
// is the admitted package, and every such in-package symbol was searched. First-party code is the
// admitted package only when that package is the root. A symbol in absent, which
// targetConditionalAbsent established the build's target of the package does not define, is
// not required.
func searchedInPackage(symbols, absent []string, res plugin.SymbolResolutionResult, searched []string, admitted pkgKey, root bool) bool {
	done := make(map[string]bool, len(searched))
	for _, s := range searched {
		done[s] = true
	}
	for _, sym := range symbols {
		if slices.Contains(absent, sym) {
			continue
		}
		inPackage := 0
		for _, scip := range res.Matched[sym] {
			if !inAdmitted(res.Origins[scip], admitted, root) {
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

// targetConditionalAbsent returns the advisory symbols the build's target of the package does not
// define: each is one the advisory declares some target may not compile, and it matched nothing in
// a package the lane read in full. It returns nil unless every symbol that matched nothing is such
// a symbol, at least one symbol matched, and the resolution's only limit is
// advisory_symbol_unresolved: any other limit, ambiguity included, means the symbol may be in code
// the lane did not read or could not tell apart.
func targetConditionalAbsent(symbols, conditional []string, res plugin.SymbolResolutionResult) []string {
	if res.Partiality.Complete || len(res.Partiality.Scoped) > 0 {
		return nil
	}
	for _, r := range res.Partiality.Reasons {
		if r != plugin.PartialReasonAdvisorySymbolUnresolved {
			return nil
		}
	}
	var absent []string
	for _, sym := range symbols {
		if len(res.Matched[sym]) > 0 {
			continue
		}
		if !slices.Contains(conditional, sym) {
			return nil
		}
		absent = append(absent, sym)
	}
	if len(absent) == len(symbols) {
		return nil
	}
	return absent
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

// inAdmitted reports whether a package named the plugin way (a versionless PURL, "" for
// first-party) is the admitted package. First-party matches only when the admitted package is the
// scanned project itself.
func inAdmitted(p string, admitted pkgKey, root bool) bool {
	if p == "" {
		return root
	}
	key, ok := purlKey(p)
	return ok && key == admitted
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

// refutationAssumptions are the assumptions the lane's refutation rests on, none without one.
func refutationAssumptions(reach plugin.ReachabilityResult) []string {
	if reach.Refutation == nil {
		return nil
	}
	return reach.Refutation.Assumptions
}

// libraryEntrypoints reads the library entry points the lane resolved for the assessment, none when
// it resolved none.
func libraryEntrypoints(store artifact.Store, assessmentID string) []plugin.ResolvedLibraryEntrypoints {
	reach, _ := reachabilityResult(store, assessmentID)
	if reach.LibraryEntrypoints == nil {
		return nil
	}
	return []plugin.ResolvedLibraryEntrypoints{*reach.LibraryEntrypoints}
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
