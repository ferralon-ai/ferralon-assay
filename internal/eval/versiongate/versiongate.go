// Package versiongate is the Phase-1 exit gate (PLAN-190): it compares each in-scope
// lane's resolved dependency graph against the native-package-manager oracle (PLAN-120's
// versionaccuracy instrument) across the benchmark suite and grades the §6 gate criteria
// per lane, never blended.
//
// # What this package is and is NOT
//
// It RUNS the comparison and GRADES it. It fixes nothing it finds (a gate that repairs its
// own failures cannot fail) and captures no oracle (an oracle captured by the gate that
// grades against it is not independent) — oracles are committed content produced out-of-band
// (see corpus/testdata/oracles/ and the capture procedure). The resolver function is injected
// so this package stays hermetic: unit tests pass a stub, the eval_live gate passes the real
// goanalysis.ResolveInventory. This package itself executes no target build tooling.
//
// # Honest absence (§3.1/§3.6)
//
// A fixture whose oracle is absent or stale is StateUnmeasurable at the version metric, and
// at THIS gate an absent comparison is a C1 FAILURE — a lane that cannot be compared has not
// passed a gate whose condition is comparison. A named corpus slice with no fixtures is
// unmeasurable{coverage}: a coverage finding routed to fixture work, never a default pass. A
// per-axis Partiality the resolver declared (e.g. an unexpressed edge, an unpinnable version)
// is preserved as unmeasurable on that axis, never laundered into a measured miss.
package versiongate

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/versionaccuracy"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveFn resolves one fixture build directory to its dependency inventory. Injected so the
// gate stays hermetic and executes no toolchain itself; the eval_live gate supplies
// goanalysis.ResolveInventory, unit tests supply a recorded stub.
type ResolveFn func(ctx context.Context, buildDir string) (plugin.DependencyInventory, error)

// OracleSource returns a fixture's captured oracle, or nil when none is recorded (honest
// absence — Measure then reports oracle_absent, a C1 failure at this gate). It never
// synthesises an oracle.
type OracleSource func(fixtureID string) (*versionaccuracy.Oracle, error)

// FixtureOutcome is one fixture's gate outcome: the versionaccuracy Result plus the resolver's
// declared completeness (C5 evidence) and the build dir resolved against.
type FixtureOutcome struct {
	FixtureID    string                 `json:"fixture_id"`
	Category     corpus.Category        `json:"category"`
	BuildDir     string                 `json:"build_dir"`
	ResolveError string                 `json:"resolve_error,omitempty"`
	Complete     bool                   `json:"resolved_complete"` // resolver's graph-level Partiality.Complete (C5)
	Reasons      []string               `json:"resolved_reasons,omitempty"`
	Result       versionaccuracy.Result `json:"result"`
}

// versionAxisState reports whether this fixture's exact-version axis was measured, and its
// agreement Rate when so. A systematically unmeasurable version axis across a lane is a finding
// (§6 names "version ... match": an axis never measured cannot be asserted to match).
func (o FixtureOutcome) versionAxisMeasured() bool {
	return o.Result.State == versionaccuracy.StateMeasured &&
		o.Result.Scores.ExactVersion.State == versionaccuracy.StateMeasured
}

// isMiss reports whether any measured axis is a real disagreement (Num < Denom with a nonzero
// denom) — a resolver that produced a graph disagreeing with the native oracle. A zero-denom
// axis ("n/a") is honest emptiness, not a miss; an unmeasurable axis is preserved Partiality,
// not a miss.
func (o FixtureOutcome) isMiss() bool {
	if o.Result.State != versionaccuracy.StateMeasured {
		return false // an unmeasurable Result is a C1 coverage failure, handled separately, not an axis miss
	}
	for _, a := range []versionaccuracy.AxisScore{o.Result.Scores.ExactVersion, o.Result.Scores.TransitiveSet, o.Result.Scores.ParentEdge} {
		if a.State == versionaccuracy.StateMeasured && a.Rate.Denom > 0 && a.Rate.Num < a.Rate.Denom {
			return true
		}
	}
	return false
}

// GateReport is the whole run's per-fixture outcomes for one lane's declared fixture set. It is
// deterministic (outcomes sorted by fixture id) so it round-trips as a committed golden.
type GateReport struct {
	Lane     string           `json:"lane"`
	Outcomes []FixtureOutcome `json:"outcomes"`
}

// Run measures every in-scope fixture against its oracle and returns the lane GateReport. A
// resolve error is recorded on the outcome (never dropped) and the fixture still measures —
// against a nil inventory, which an oracle-present fixture reads as a total miss, honestly.
func Run(ctx context.Context, lane string, fixtures []corpus.Fixture, oracles OracleSource, resolve ResolveFn) (GateReport, error) {
	rep := GateReport{Lane: lane}
	for _, fix := range fixtures {
		buildDir := corpus.ReproPath(fix.Codebase.Acquisition.Path)
		out := FixtureOutcome{FixtureID: fix.ID, Category: fix.Category, BuildDir: buildDir}

		inv, err := resolve(ctx, buildDir)
		if err != nil {
			out.ResolveError = err.Error()
		}
		out.Complete = inv.Partiality.Complete
		out.Reasons = inv.Partiality.Reasons

		oracle, oerr := oracles(fix.ID)
		if oerr != nil {
			return GateReport{}, oerr
		}
		out.Result = versionaccuracy.Measure(oracle, inv, versionaccuracy.Observed{
			FixtureDigest: versionaccuracy.FixtureDigest(fix),
		})
		rep.Outcomes = append(rep.Outcomes, out)
	}
	sort.Slice(rep.Outcomes, func(i, j int) bool { return rep.Outcomes[i].FixtureID < rep.Outcomes[j].FixtureID })
	return rep, nil
}

// GateState is a criterion's or slice's gate outcome.
type GateState string

const (
	StatePass                 GateState = "pass"
	StateFail                 GateState = "fail"
	StateUnmeasurableCoverage GateState = "unmeasurable_coverage" // a named slice with no fixtures — routed, never a default pass
)

// C1 — the oracle comparison ran for every in-scope fixture. Returns the fixture ids whose
// Result is unmeasurable for an oracle-comparability reason (absent/stale/env mismatch); a
// non-empty list is a C1 failure at this gate. Axis-level partiality does NOT count — the
// comparison ran, some axis was honestly undetermined.
func (r GateReport) C1OracleComparisonGaps() []string {
	var gaps []string
	for _, o := range r.Outcomes {
		if o.Result.State == versionaccuracy.StateUnmeasurable {
			gaps = append(gaps, o.FixtureID+":"+o.Result.Reason)
		}
	}
	return gaps
}

// C2 — version, transitive-set and parent-edge are graded as three separate axes. True unless
// some measured outcome collapsed them (structurally impossible with the SubScores type, but
// checked so a future refactor that blends cannot pass silently).
func (r GateReport) C2Decomposed() bool {
	for _, o := range r.Outcomes {
		if o.Result.State != versionaccuracy.StateMeasured {
			continue
		}
		s := o.Result.Scores
		// three named, independently-stated axes; each must carry its own state
		if s.ExactVersion.State == "" || s.TransitiveSet.State == "" || s.ParentEdge.State == "" {
			return false
		}
	}
	return true
}

// SliceState grades one named corpus slice (category). A slice with no fixtures is
// unmeasurable_coverage (C3: a slice with nothing in it is not a slice that passed). A slice
// with a measured miss fails. Otherwise it passes (every fixture agreed or was honestly
// unmeasurable by preserved partiality).
func (r GateReport) SliceState(cat corpus.Category) GateState {
	n := 0
	for _, o := range r.Outcomes {
		if o.Category != cat {
			continue
		}
		n++
		if o.isMiss() || o.Result.State == versionaccuracy.StateUnmeasurable {
			return StateFail
		}
	}
	if n == 0 {
		return StateUnmeasurableCoverage
	}
	return StatePass
}

// C5 — partiality preserved, with a negative control. Reports whether at least one fixture
// resolved partial-with-reason AND at least one resolved complete: an assertion that accepts
// both a partial and a complete run distinguishes preservation from a resolver that always
// claims one or the other. A lane missing either side is a coverage finding, not a pass.
func (r GateReport) C5PartialityControl() (partialWithReason, completeControl bool) {
	for _, o := range r.Outcomes {
		if !o.Complete && len(o.Reasons) > 0 {
			partialWithReason = true
		}
		if o.Complete {
			completeControl = true
		}
	}
	return partialWithReason, completeControl
}

// VersionAxisCoverage reports how many measured fixtures had a MEASURED version axis versus a
// version axis left unmeasurable by preserved partiality. A lane where the version axis is
// never measured cannot claim "version results match native output" — the axis was not
// exercised — even when every graph axis agrees. This is the finding the source_unpinned
// collision produces on the Go reference lane.
func (r GateReport) VersionAxisCoverage() (measured, unmeasurable int) {
	for _, o := range r.Outcomes {
		if o.Result.State != versionaccuracy.StateMeasured {
			continue
		}
		if o.versionAxisMeasured() {
			measured++
		} else {
			unmeasurable++
		}
	}
	return measured, unmeasurable
}

// Misses returns the fixture ids with a measured axis disagreement — the resolver graphs that
// diverge from the native oracle. Empty is the expected reference-lane result.
func (r GateReport) Misses() []string {
	var out []string
	for _, o := range r.Outcomes {
		if o.isMiss() {
			out = append(out, o.FixtureID)
		}
	}
	return out
}
