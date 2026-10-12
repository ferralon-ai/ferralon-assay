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
// A leaf-name hit in first-party code never counts toward arm A: its origin is not the package.
func notExploitableGrounds(store artifact.Store, assessmentID string, pkg *report.Package) (detail, reason string, ok bool) {
	admitted, label, ok := admittedPackage(store, assessmentID, pkg)
	if !ok {
		return "", report.ReasonPackageVersionUnresolved, false
	}
	reach, _ := reachabilityResult(store, assessmentID)
	symbols := pipeline.AdvisorySymbols(store, assessmentID)

	if len(symbols) > 0 {
		res, err := pipeline.VulnerableSymbols(store, assessmentID)
		if err == nil && searchedInPackage(symbols, res, reach.Searched, admitted) {
			return fmt.Sprintf("no path from any entry point reaches %s in %s",
				strings.Join(symbols, ", "), label), "", true
		}
	}
	if r := reach.Refutation; r != nil {
		if key, ok := purlKey(r.Package); ok && key == admitted {
			grounds := r.Detail
			if grounds == "" {
				grounds = r.Basis
			}
			return fmt.Sprintf("%s: %s", label, grounds), "", true
		}
	}
	if len(symbols) == 0 {
		return "", report.ReasonAdvisorySymbolAbsent, false
	}
	return "", report.ReasonVulnerableSymbolUnresolved, false
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
		return pkgKey{typ: "golang", name: "stdlib"}, "stdlib@" + reach.ScanToolchain, true
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
