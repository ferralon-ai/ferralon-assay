// partiality_class.go — the two-arm taxonomy that decides how loudly a surface
// discloses a coverage limit.
//
// Every limit reaches the Report (that is what PartialityNote is for), but not every
// limit deserves the same volume. A disclosure that fires on every scan stops carrying
// information: if "static analysis cannot see through reflection" shouts from the
// headline of every run, the headline can no longer distinguish it from "the analyzer
// for this language was not installed". Making methodology loud would blunt the
// qualifier for exactly the runs the qualifier exists to protect.
//
// The line is: *"this is how the method works"* versus *"this run did not do what it
// normally does."*
package report

import "github.com/ferralon-ai/ferralon-assay/plugin"

// PartialityClass is the arm a coverage limit is disclosed in. It governs volume only —
// no verdict, count or finding depends on it, and both arms are always present and
// readable in the Report and in every sink.
type PartialityClass string

const (
	// PartialityInherentLimit is a property of static analysis itself: it holds for
	// essentially every scan of a given language, on every codebase, forever. The
	// analysis ran and did exactly what it always does. Surfaces disclose it quietly, in
	// a methodology footer — never in the headline, never as a finding.
	PartialityInherentLimit PartialityClass = "inherent_limit"

	// PartialityDidNotRun is a step of the analysis that did not happen on THIS run: the
	// analyzer was absent, a tool failed, the manifest was unreadable, an entry point
	// could not be resolved. This is what the headline qualifier exists for, and it is
	// the DEFAULT for anything a reader does not recognize (see EffectiveClass).
	PartialityDidNotRun PartialityClass = "did_not_run"
)

// ClassifyPartialityReason sorts a canonical reason code into its arm.
//
// Only codes that name a limit of the METHOD are inherent — a limit that would be
// declared just as truthfully on a codebase where nothing at all went wrong.
// Everything else is did-not-run, including every code this build does not know:
// see EffectiveClass for why the unknown case leans that way.
//
// The Phase-1 contract stub (unsupported_phase1) is deliberately NOT inherent. It reads
// like methodology — the operation always returns a stub — but what it discloses is
// that the analysis did not run at all, which is the exact conflation this whole type
// exists to prevent. Likewise cgo: the boundary is a real property of Go static
// analysis, but it is declared only on codebases that actually cross it, so it still
// tells a reader something specific about THIS codebase's coverage.
func ClassifyPartialityReason(reason string) PartialityClass {
	switch reason {
	case plugin.PartialReasonReflection, plugin.PartialReasonDynamicDispatch:
		return PartialityInherentLimit
	default:
		return PartialityDidNotRun
	}
}

// EffectiveClass returns the arm a reader must render this note in.
//
// Anything that is not explicitly the inherent-limit arm resolves to
// PartialityDidNotRun: an unset field, a class string from a newer writer, a typo. The
// default is deliberate and one-directional. Defaulting an unrecognized limit to the
// quiet arm would let a genuine failure hide behind a taxonomy gap — a silent clean
// scan reached by a different route — so the taxonomy fails loud, never quiet.
//
// Every sink resolves the arm through this method rather than reading Class directly,
// so the default holds even for a note that never passed through Builder.AddPartiality.
func (n PartialityNote) EffectiveClass() PartialityClass {
	if n.Class == PartialityInherentLimit {
		return PartialityInherentLimit
	}
	return PartialityDidNotRun
}
