package goanalysis

import "golang.org/x/tools/go/ssa"

// Sanitizer model — minimal and membership-based.
//
// A sanitizer is a function whose result is treated as NO LONGER attacker-tainted
// for the purpose of value-flow taint: taint that flows only through a sanitizer
// to a sink yields no taint edge (a true negative that must not be reported).
//
// This model is deliberately small and conservative — membership in an explicit,
// documented allow-list, NOT symbolic/constraint reasoning (a non-goal). Each
// entry is justified below; the set is extended by adding a (pkgPath, funcName)
// key, never by inferring sanitizers heuristically. We sanitize ONLY library
// functions whose contract is to neutralize the attacker-controllable content of
// their input in a way that is universal across the sink classes this analysis
// targets (string/command/path/markup sinks):
//
//   - strconv.Atoi / ParseInt / ParseUint / ParseFloat / ParseBool — parse-to-typed:
//     the result is a number/bool, so the attacker no longer controls free-form
//     string content flowing to a string sink. (The error return is irrelevant to
//     the value-carrying result.)
//   - html.EscapeString — HTML-escapes its input; the result is markup-safe.
//   - text/template.HTMLEscapeString / JSEscapeString / URLQueryEscaper — the
//     template escapers, same contract for HTML/JS/URL contexts.
//   - net/url.QueryEscape / PathEscape — percent-encode the input for URL contexts.
//   - regexp.QuoteMeta — escapes regex metacharacters; result is a literal pattern.
//   - path.Clean / path/filepath.Clean — normalize a path, collapsing traversal
//     segments; defensible for path-traversal sinks.
//
// Anything outside this list is NOT a sanitizer: an unmodeled transform forwards
// taint (honesty over reach). To extend, add an entry with its justification.
var sanitizerFuncs = map[string]map[string]bool{
	"strconv": {
		"Atoi":       true,
		"ParseInt":   true,
		"ParseUint":  true,
		"ParseFloat": true,
		"ParseBool":  true,
	},
	"html": {
		"EscapeString": true,
	},
	"text/template": {
		"HTMLEscapeString": true,
		"JSEscapeString":   true,
		"URLQueryEscaper":  true,
	},
	"net/url": {
		"QueryEscape": true,
		"PathEscape":  true,
	},
	"regexp": {
		"QuoteMeta": true,
	},
	"path": {
		"Clean": true,
	},
	"path/filepath": {
		"Clean": true,
	},
}

// isSanitizer reports whether fn is a modeled sanitizer: a function whose result
// clears taint on the value it produces. Only statically-resolved library
// functions identified by their (package path, name) are sanitizers.
func isSanitizer(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	names, ok := sanitizerFuncs[fn.Pkg.Pkg.Path()]
	if !ok {
		return false
	}
	return names[fn.Name()]
}
