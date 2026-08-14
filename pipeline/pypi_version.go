// internal/pipeline/pypi_version.go
//
// PEP 440 version comparison and specifier matching for the Python (PyPI)
// disqualification axis. The comparator itself now lives in the shared leaf package
// internal/pep440 so the pipeline axis and the Python analyzer's PEP 508 marker
// evaluator share ONE implementation (PLAN-170 C1 — two independent PEP 440 comparators
// would diverge; pythonanalysis cannot import pipeline without an import cycle, so the
// shared logic moved down to a leaf both import). This file keeps the pipeline-facing
// entry points and thin name-preserving forwarders.
//
// Two entry points (mirroring npm_version.go):
//   - pypiVersionOutsideRange(ver, upper): the "affects < upper" disqualification bound
//     (plugin resolves the literal installed version, pipeline applies the bound).
//   - pypiVersionInRange(ver, spec): the full PEP 440 specifier set (a ","-joined AND of
//     >=, <=, >, <, ==, !=, ~=, ==prefix.*, ===) for advisories carrying a specifier.
package pipeline

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
)

// pypiVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under PEP 440 ordering. ok is false (no proof) on any input the
// comparator cannot confidently order. Provably-outside means comparePEP440(ver, upper) >= 0.
func pypiVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	a, aok := parsePEP440(ver)
	b, bok := parsePEP440(upper)
	if !aok || !bok {
		return false, false
	}
	return comparePEP440(a, b) >= 0, true
}

// pypiVersionInRange reports whether ver satisfies the PEP 440 specifier spec — a
// ","-joined conjunction (AND) of clauses, each one of >=, <=, >, <, ==, !=, ~=,
// "==X.Y.*" prefix match, or "===" arbitrary equality. PEP 440 has no "||" union.
// ok is false when ver or any clause falls outside the modelled grammar, so the
// caller fails open. A version satisfies the spec iff it satisfies EVERY clause.
func pypiVersionInRange(ver, spec string) (inRange bool, ok bool) {
	v, vok := parsePEP440(ver)
	if !vok {
		return false, false
	}
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		sat, cok := pep440.Satisfies(v, ver, clause)
		if !cok {
			return false, false
		}
		if !sat {
			return false, true
		}
	}
	return true, true
}

// parsePEP440 / comparePEP440 forward to the shared pep440 leaf package. They preserve
// the pipeline-local names the disqualification axis and its white-box tests
// (pypi_version_test.go) reference, so the extraction is behavior- and API-preserving.
func parsePEP440(s string) (pep440.Version, bool) { return pep440.Parse(s) }

func comparePEP440(a, b pep440.Version) int { return pep440.Compare(a, b) }
