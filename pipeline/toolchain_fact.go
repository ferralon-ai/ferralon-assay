// ferralon-assay/pipeline/toolchain_fact.go
//
// The subject's Go toolchain version as ONE resolved fact. Four unconnected sources
// named a "Go version" before this file existed — the go.mod `go` directive, the go.mod `toolchain`
// directive, the CI runner's installed Go, and the scanner's own pinned toolchain — and no verdict
// path could say which of them was a statement about the SUBJECT. This resolves them into a single
// value that carries its own strength.
//
// The strength is load-bearing, and it is why the fact is a struct and not a string. Go's own
// semantics make both go.mod directives LOWER BOUNDS: `go X.Y` is a minimum language version,
// `toolchain goX.Y.Z` a minimum toolchain, and under GOTOOLCHAIN=auto the go command only ever
// switches UP from them. Nothing inside go.mod is an exact statement about the toolchain that built
// the artifact. So the two consumers of this fact can do different things with it:
//
//   - The version axis may consume a FLOOR. goToolchainVersionOutsideRange is monotone
//     non-decreasing in its version argument, so for a floor f on the true toolchain t (t >= f),
//     outside(f, u) implies outside(t, u): a floor already past the fix proves the real toolchain is
//     past the fix. The converse fails and is not needed — no disqualification is the existing
//     fail-open behavior and is correct.
//   - Reachability may NOT. Its output is a refutation by absence, and absence is only evidence
//     about the toolchain the analysis actually ran on. A floor licenses nothing there.
//
// The recorded fact drives the U7 version comparator (M3), the withhold-and-disclose predicate,
// and — via ToolchainScan below — the subject-toolchain reachability gate (M4).
package pipeline

import "fmt"

// Bound values for ToolchainFact.Bound.
const (
	// ToolchainBoundExact means the subject's toolchain IS this version — the value came from a
	// direct statement or a direct observation, not from a manifest floor.
	ToolchainBoundExact = "exact"
	// ToolchainBoundMinimum means the subject's toolchain is AT OR ABOVE this version.
	ToolchainBoundMinimum = "minimum"
	// ToolchainBoundNone means nothing was resolved; Version is empty.
	ToolchainBoundNone = "none"
)

// Source values for ToolchainFact.Source, in descending precedence. The two exact sources
// outrank both floors; among the floors the higher VERSION wins (they are both lower bounds on
// the same quantity, so their maximum is the tightest sound bound), ties going to the
// toolchain directive.
const (
	// ToolchainSourceSubjectDeclared is the subject's own statement of its build toolchain (the
	// Action's subject-go-version input). Nothing overrides a declaration.
	ToolchainSourceSubjectDeclared = "subject_declared"
	// ToolchainSourceCIObserved is `go env GOVERSION` captured on the CI runner BEFORE the Action
	// set up the scanner's own toolchain. It is a statement about the SUBJECT only if the caller
	// asserts that the Go present when the Action starts is the toolchain the subject builds with,
	// which is why this tier is OPT-IN (toolchainInputs.trustCIObserved, the Action's
	// trust-observed-go input). Untrusted, it does not participate in resolution at all.
	ToolchainSourceCIObserved = "ci_observed"
	// ToolchainSourceToolchainDirective is the go.mod `toolchain goX.Y.Z` directive: a floor.
	ToolchainSourceToolchainDirective = "toolchain_directive"
	// ToolchainSourceGoDirective is the go.mod `go X.Y` directive: a floor, normalized to goX.Y.0.
	ToolchainSourceGoDirective = "go_directive"
	// ToolchainSourceUnresolved means no source produced an orderable version.
	ToolchainSourceUnresolved = "unresolved"
)

// ToolchainFact is the subject's Go toolchain version as one resolved fact.
//
// Bound is load-bearing and a consumer that ignores it reintroduces the defect this type exists to
// close: "exact" licenses a reachability refutation, "minimum" licenses only a disqualification.
// The asymmetry is not a policy choice — goToolchainVersionOutsideRange is monotone in its version
// argument, so a floor past the fix proves the true toolchain is past the fix, whereas a floor
// below the fix proves nothing at all about a symbol's absence.
//
// An unresolved fact is recorded explicitly (Bound "none", Source "unresolved", empty Version)
// rather than omitted: "we looked and established nothing" is a disclosure, and a silently absent
// field is exactly how the version axis stayed dark.
type ToolchainFact struct {
	// Version is the normalized "go1.21.3" form (always three segments, always the "go" prefix).
	// Empty if and only if Source is ToolchainSourceUnresolved.
	Version string `json:"version,omitempty"`
	Bound   string `json:"bound"`
	Source  string `json:"source"`
	// Contradiction is set only when an EXACT claim was refuted by the subject's own go.mod floor and
	// therefore discarded (see resolveToolchainFact). It is a pointer so its absence is absence: a
	// contradiction is the abnormal case, and an always-present block of empty strings would be noise
	// rather than the disclosure an always-emitted unresolved fact is. When set, Bound is "minimum"
	// and Version/Source describe the floor that survived, not the claim that did not.
	Contradiction *ToolchainContradiction `json:"contradiction,omitempty"`
}

// ToolchainContradiction records an exact toolchain claim the subject's own manifest disproved, so the
// report surface can disclose the discarded input instead of silently ignoring a caller's declaration
// or observation. It is evidence about the INPUTS, never about exploitability.
type ToolchainContradiction struct {
	// ClaimedVersion / ClaimedSource are the refuted exact claim and the tier that made it.
	ClaimedVersion string `json:"claimed_version"`
	ClaimedSource  string `json:"claimed_source"`
	// FloorVersion / FloorSource are the directive floor that refutes it — the value that survived.
	FloorVersion string `json:"floor_version"`
	FloorSource  string `json:"floor_source"`
}

// toolchainInputs are the four candidate sources, raw and unvalidated, in the spellings their
// origins produce: a bare "1.21" from a `go` directive, a "go1.21.3" from a `toolchain` directive
// or from `go env GOVERSION`, or whatever a customer typed into subject-go-version.
type toolchainInputs struct {
	subjectDeclared string
	ciObserved      string
	// trustCIObserved is the caller's assertion that ciObserved describes the SUBJECT — that the Go
	// installed when the Action started is the toolchain the scanned repository builds with. The
	// zero value withholds that trust, which is the correct default: a scan job that never ran
	// actions/setup-go still finds the hosted runner image's preinstalled Go, and the code cannot
	// tell that case from a same-job build.
	trustCIObserved    bool
	toolchainDirective string
	goDirective        string
}

// resolveToolchainFact reduces the candidate sources to one fact: the
// highest-precedence EXACT source wins outright, and absent any exact source the resolved FLOORS
// combine by maximum. A source that does not parse as an orderable Go release version resolves
// nothing and is skipped, so junk degrades to the next source (and ultimately to unresolved)
// rather than seeding an axis with a value it cannot order.
//
// The observed tier participates only when the caller trusts it. Untrusted, it drops out ENTIRELY
// rather than being demoted to a floor: in the topology the gate exists for — a dedicated scan job
// on a hosted runner whose image happens to ship a Go — the observation bears no relation to the
// subject's toolchain, so it is not a lower bound on it either. Demoting would have been the
// tempting half-measure and it is unsound.
// The floors are resolved FIRST, before any exact source, because they are what can refute one. See
// the contradiction guard below.
func resolveToolchainFact(in toolchainInputs) ToolchainFact {
	floorFact, floorParsed, haveFloor := resolveToolchainFloor(in)

	exactSources := []struct{ raw, source string }{
		{in.subjectDeclared, ToolchainSourceSubjectDeclared},
	}
	if in.trustCIObserved {
		exactSources = append(exactSources, struct{ raw, source string }{in.ciObserved, ToolchainSourceCIObserved})
	}
	for _, exact := range exactSources {
		parsed, ok := parseGoToolchainVersion(exact.raw)
		if !ok {
			continue
		}
		// THE CONTRADICTION GUARD. An exact claim BELOW the repo's own floor is refuted by the repo:
		// `GOTOOLCHAIN=auto` switches only UP from a directive, so a subject whose go.mod requires at
		// least `floor` provably does not build with anything less. The claim is therefore false —
		// most often because the observed Go is the bootstrap toolchain that then switched up, or
		// because a declaration went stale against a directive bump.
		//
		// Why this matters now and did not before: for the version axis alone the direction is SAFE
		// (a too-low version only ever withholds disqualifications), which is why it survived review
		// as a mere imprecision. Once `Bound == exact` also licenses refutation-by-absence and an
		// actual toolchain install, an exact claim below the floor would run govulncheck over the
		// wrong stdlib and emit `not_exploitable` / OpenVEX `not_affected` off it — a safety claim
		// resting on a fact nothing established, which is the whole defect this file exists to close,
		// reappearing one layer up.
		//
		// Resolution: drop the refuted claim and resolve as the floor. Disqualification still works
		// (a floor is all it ever needed) and the exact-bound gate is denied structurally rather than
		// by a special case, because the bound is no longer exact. The contradiction is recorded so the
		// report surface can disclose it instead of silently discarding a caller's input.
		//
		// Note the asymmetry, which is why this is `<` and not `!=`: exact ABOVE the floor is not a
		// contradiction at all. Floors are minimums, and a build above its own minimum is the normal
		// case.
		if haveFloor && compareGoToolchain(parsed, floorParsed) < 0 {
			refuted := floorFact
			refuted.Contradiction = &ToolchainContradiction{
				ClaimedVersion: formatGoToolchainVersion(parsed),
				ClaimedSource:  exact.source,
				FloorVersion:   floorFact.Version,
				FloorSource:    floorFact.Source,
			}
			// Deliberately no fall-through to a lower-precedence exact source that would be
			// consistent with the floor: recovering exactness after refuting a claim is a
			// different semantic, and the floor is never wrong-direction.
			return refuted
		}
		return ToolchainFact{
			Version: formatGoToolchainVersion(parsed),
			Bound:   ToolchainBoundExact,
			Source:  exact.source,
		}
	}

	return floorFact
}

// resolveToolchainFloor reduces the two go.mod directives to the tightest sound lower bound: both are
// minimums on the same quantity, so their MAXIMUM is the strongest floor that remains true. ok is
// false when neither directive resolves, in which case the returned fact is the explicit unresolved
// one and no exact claim can be refuted.
func resolveToolchainFloor(in toolchainInputs) (ToolchainFact, goToolchainVersion, bool) {
	best := ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}
	var bestParsed goToolchainVersion
	var haveFloor bool
	for _, floor := range []struct{ raw, source string }{
		{in.toolchainDirective, ToolchainSourceToolchainDirective},
		{in.goDirective, ToolchainSourceGoDirective},
	} {
		parsed, ok := parseGoToolchainVersion(floor.raw)
		if !ok {
			continue
		}
		// Strictly-greater keeps the earlier (higher-precedence) source on a tie.
		if haveFloor && compareGoToolchain(parsed, bestParsed) <= 0 {
			continue
		}
		best = ToolchainFact{
			Version: formatGoToolchainVersion(parsed),
			Bound:   ToolchainBoundMinimum,
			Source:  floor.source,
		}
		bestParsed = parsed
		haveFloor = true
	}
	return best, bestParsed, haveFloor
}

func formatGoToolchainVersion(v goToolchainVersion) string {
	return fmt.Sprintf("go%d.%d.%d", v.major, v.minor, v.patch)
}

// ToolchainScan records which Go toolchain the reachability analysis ACTUALLY executed under.
// It is written on the reachability artifact and read back by
// SubjectToolchainScanned.
//
// It exists because the request can be declined. Asking the analyzer to run under the subject's
// toolchain is best-effort — the release may not be fetchable, or may not be able to build the
// module — and the fallback is a scan under the analyzer's own toolchain, which is exactly the state
// whose empty path set may NOT license a refutation. Recording the request and the outcome
// separately is what keeps a declined request from reading as an honored one.
type ToolchainScan struct {
	// Requested is the subject toolchain the stage asked for; empty when none was licensed (the
	// flag is off, the bound is not exact, or this is not a Go subject).
	Requested string `json:"requested,omitempty"`
	// Actual is the toolchain the analyzer reported running under. Empty means unknown.
	Actual string `json:"actual,omitempty"`
	// Subject is true only when a request was made AND honored — the one state in which an empty
	// stdlib path set is evidence about the subject rather than about the analyzer.
	Subject bool `json:"subject"`
}

// newToolchainScan pairs what was asked for with what ran. The Subject determination is a match, not
// a trust: a fallback reports the analyzer's toolchain, which can never equal a requested version it
// differed from.
func newToolchainScan(requested, actual string) ToolchainScan {
	return ToolchainScan{
		Requested: requested,
		Actual:    actual,
		Subject:   requested != "" && actual == requested,
	}
}
