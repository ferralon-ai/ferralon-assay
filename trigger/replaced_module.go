package trigger

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// moduleReplacement returns the fork or local directory the build compiles the advisory's Go module
// from, for a row with no package: one whose version never resolved because a replace directive sends
// the module to code no release of it describes. The scanned project's own module is never one.
func moduleReplacement(store artifact.Store, assessmentID string, pkg *report.Package) (pipeline.ModuleReplacement, bool) {
	if pkg != nil || pipeline.RootSubject(store, assessmentID) {
		return pipeline.ModuleReplacement{}, false
	}
	return pipeline.Replacement(store, assessmentID)
}

// replacedGrounds judges an advisory on a Go module the build compiles from a replacement (a fork or a
// local directory) on that compiled code alone. No release of the module describes it, so the
// advisory's affected versions say nothing about it, and the replacement's own version string is
// never compared against them. It grounds only when every advisory symbol, from a vetted set
// (vettedSymbols), resolved to code of the module's packages in the build, and the lane searched every
// such sink from its entry points and reached none. A symbol the compiled code does not define is
// never taken as absent: a fork can rename or move the vulnerable code, so the row stays held. It
// never rests on the lane's package-level refutation, and an advisory that names another package that
// may be in the build stays held.
func replacedGrounds(store artifact.Store, assessmentID string, mods goModules, r pipeline.ModuleReplacement) (detail string, basis verdict.NonExploitableBasis, assumptions []string, ok bool) {
	admitted, ok := purlKey(pipeline.AdvisoryPURL(store, assessmentID))
	if !ok || admitted.typ != "golang" {
		return "", "", nil, false
	}
	symbols := pipeline.AdvisorySymbols(store, assessmentID)
	if len(symbols) == 0 || !vettedSymbols(store, assessmentID) {
		return "", "", nil, false
	}
	if namesOtherPackage(pipeline.AdvisoryPackagePURLs(store, assessmentID), admitted, mods, nil) {
		return "", "", nil, false
	}
	res, err := pipeline.VulnerableSymbols(store, assessmentID)
	if err != nil {
		return "", "", nil, false
	}
	reach, _ := reachabilityResult(store, assessmentID)
	if !searchedInPackage(symbols, nil, res, reach.Searched, admitted, false) {
		return "", "", nil, false
	}
	return fmt.Sprintf("no path from any entry point reaches %s in %s, which the build compiles from %s; that code defines each of them",
		strings.Join(symbols, ", "), admitted.name, replacementLabel(r)), verdict.BasisSymbolUnreachable, refutationAssumptions(reach, admitted, false), true
}

// replacedHeldDetail is the detail of a package_version_unresolved row whose module the build compiles
// from a replacement replacedGrounds did not ground: what the build compiles instead of a release,
// why that leaves the advisory unjudged, and what would settle it.
func replacedHeldDetail(store artifact.Store, assessmentID string, mods goModules, r pipeline.ModuleReplacement) string {
	key, keyed := purlKey(pipeline.AdvisoryPURL(store, assessmentID))
	module := key.name
	if !keyed {
		module = "the advisory's module"
	}
	head := fmt.Sprintf("The build compiles %s from %s, code no release of %s describes, so the advisory's affected versions do not place it. ",
		module, replacementLabel(r), module)
	symbols := pipeline.AdvisorySymbols(store, assessmentID)
	res, resErr := pipeline.VulnerableSymbols(store, assessmentID)
	reasons, _ := keptDidNotRunReasons(store, assessmentID, nil)
	var why string
	switch {
	case len(symbols) == 0:
		why = "The advisory names no vulnerable symbol to look for in that code."
	case !vettedSymbols(store, assessmentID):
		why = "The advisory's vulnerable symbols are not a vetted set, so their absence from every path is not evidence."
	case keyed && resErr == nil && !resolvesInto(res, key):
		why = fmt.Sprintf("The analysis does not locate the advisory's symbols inside the build's code of %s, so whether that code defines %s was not determined.",
			module, strings.Join(symbols, ", "))
	case keyed && resErr == nil && resolutionRead(res) && len(undefinedIn(symbols, res, key)) > 0:
		why = fmt.Sprintf("The build's code of %s does not define %s. A replacement can rename or move the vulnerable code, so that is not taken as a fix.",
			module, strings.Join(undefinedIn(symbols, res, key), ", "))
	case keyed && namesOtherPackage(pipeline.AdvisoryPackagePURLs(store, assessmentID), key, mods, nil):
		why = "The advisory also names a package the build may hold, so that code alone does not settle it."
	case len(reasons) > 0 || emptyGraphUncalledComplete(store, assessmentID):
		why = "Steps an analysis of that code rests on did not run, so it was not judged."
	default:
		why = fmt.Sprintf("The analysis did not search every definition of %s from the entry points.", strings.Join(symbols, ", "))
	}
	return head + why + fmt.Sprintf(" It is settled by building %s from a release the advisory's ranges place, or by finding the advisory's vulnerable functions in the replacement's code with no path reaching them.", module)
}

// resolvesInto reports whether the resolution attributed any symbol to the module key names. A lane
// that does not resolve inside a dependency's code (Go's, which indexes only the build's own packages)
// returns no origins for it, and an empty result there says nothing about what that code defines.
func resolvesInto(res plugin.SymbolResolutionResult, key pkgKey) bool {
	for _, origin := range res.Origins {
		if inAdmitted(origin, key, false) {
			return true
		}
	}
	return false
}

// resolutionRead reports whether the resolution read all the code it indexes, so that a symbol it did
// not match is undefined there rather than unread. Its only allowed shortfall is a symbol it could not
// resolve, which is that same absence.
func resolutionRead(res plugin.SymbolResolutionResult) bool {
	if res.Partiality.Complete {
		return true
	}
	if len(res.Partiality.Scoped) > 0 {
		return false
	}
	for _, r := range res.Partiality.Reasons {
		if r != plugin.PartialReasonAdvisorySymbolUnresolved {
			return false
		}
	}
	return true
}

// undefinedIn returns the symbols that resolved to no code of the module key names.
func undefinedIn(symbols []string, res plugin.SymbolResolutionResult, key pkgKey) []string {
	var out []string
	for _, sym := range symbols {
		if !slices.ContainsFunc(res.Matched[sym], func(scip string) bool { return inAdmitted(res.Origins[scip], key, false) }) {
			out = append(out, sym)
		}
	}
	return out
}

// replacementLabel names a replacement as its directive does: a module path and version, or a
// directory.
func replacementLabel(r pipeline.ModuleReplacement) string {
	switch {
	case r.Directory:
		return "the local directory " + r.Path
	case r.Version == "":
		return r.Path
	}
	return r.Path + " " + r.Version
}
