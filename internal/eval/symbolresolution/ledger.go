package symbolresolution

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// LaneState is whether a lane's symbol-resolution rate was measured or is unmeasurable (C6),
// mirroring versionaccuracy.State's three-state honesty.
type LaneState string

const (
	LaneMeasured     LaneState = "measured"
	LaneUnmeasurable LaneState = "unmeasurable"
)

// ReasonLaneArtifactIndexerAbsent is the lane-granularity twin of the record-level
// ReasonArtifactNotIndexed: the lane's PLAN-2x0 dependency-artifact indexer has not landed, so
// dependency artifacts are not indexed and dependency-symbol resolution cannot run. Never 0.0,
// never an omitted row (C6).
const ReasonLaneArtifactIndexerAbsent = "lane-artifact-indexer-absent"

// measuredLanes are the lanes PLAN-221 measures this cycle: {go} is measurable NOW via
// ResolveDependencySymbols → go/packages, with no PLAN-2x0 artifact indexer required (Amendment
// A1). unmeasurableLanes are the in-program lanes whose indexer has not landed — honestly
// LaneUnmeasurable until it does. Both are frozen this cycle; a lane graduates by moving between
// the lists when its PLAN-221 {lane} lands.
var (
	measuredLanes     = []string{"go"}
	unmeasurableLanes = []string{"java", "js", "python", "dotnet"}
)

// LaneLedgerEntry is one lane's honesty-preserving ledger row (C6). Exactly one of the two
// shapes: State==LaneMeasured carries the §4 D1–D4 Denominators (and no Reason); State==
// LaneUnmeasurable carries a Reason naming the missing input (and no Denominators). A lane that
// genuinely resolved nothing is LaneMeasured with a Rate of {Num:0,Denom:N} — the State
// discriminator, not the float, is what holds "resolved nothing" apart from "could not measure".
type LaneLedgerEntry struct {
	Lane         string              `json:"lane"`
	State        LaneState           `json:"state"`
	Reason       string              `json:"reason,omitempty"`       // set iff State==LaneUnmeasurable; NAMES THE MISSING INPUT
	Denominators []DenominatorReport `json:"denominators,omitempty"` // set iff State==LaneMeasured (the §4 rates)
}

// Ledger is the metric's top-level deposit (C5): the per-lane honesty rows and the per-category
// slice of every outcome. The ByCategory "" bucket is the honest home of every unbound record
// (artifact-not-indexed / advisory-names-no-symbol / out-of-lane) — kept VISIBLE, never dropped.
type Ledger struct {
	ByLane     map[string]LaneLedgerEntry              `json:"by_lane"`
	ByCategory map[corpus.Category][]ResolutionOutcome `json:"by_category"`
}

// BuildLedger joins the two corpora and produces the full metric ledger. It classifies every
// record for each measured lane (running the resolver via run only for the buildable subset),
// computes D1–D4, slices outcomes by corpus.Category, and records each unmeasurable lane with the
// reason naming its missing input. records is the advisory corpus (pipeline.AdvisoryTable); store
// is the attribution sidecar (empty == all unreviewed, today's state); fixtures is the
// code-fixture corpus (corpus.Load()); run drives the deterministic resolver (RunCaseRunner in
// production, a fake in the hermetic suite).
func BuildLedger(ctx context.Context, records map[string]pipeline.AdvisoryFacts, store pipeline.AttributionStore, fixtures []corpus.Fixture, run CaseRunner) *Ledger {
	bound := bindFixtures(fixtures)
	total := len(records)
	led := &Ledger{
		ByLane:     map[string]LaneLedgerEntry{},
		ByCategory: map[corpus.Category][]ResolutionOutcome{},
	}
	for _, lane := range measuredLanes {
		outcomes := ClassifyLane(ctx, lane, records, bound, run)
		ctxs := buildRecordCtxs(records, store, bound, outcomes)
		led.ByLane[lane] = LaneLedgerEntry{
			Lane:         lane,
			State:        LaneMeasured,
			Denominators: buildDenominators(lane, total, ctxs),
		}
		for _, o := range outcomes {
			led.ByCategory[o.Category] = append(led.ByCategory[o.Category], o)
		}
	}
	for _, lane := range unmeasurableLanes {
		led.ByLane[lane] = LaneLedgerEntry{
			Lane:   lane,
			State:  LaneUnmeasurable,
			Reason: ReasonLaneArtifactIndexerAbsent,
		}
	}
	// Deterministic ordering of each category's outcomes (vuln_id then lane).
	for cat := range led.ByCategory {
		outs := led.ByCategory[cat]
		sort.Slice(outs, func(i, j int) bool {
			if outs[i].RecordID != outs[j].RecordID {
				return outs[i].RecordID < outs[j].RecordID
			}
			return outs[i].Lane < outs[j].Lane
		})
		led.ByCategory[cat] = outs
	}
	return led
}

// Categories returns the corpus.Category keys present in the ledger's by-category slice, sorted —
// including the "" bucket when unbound records are present (kept visible, C5).
func (l *Ledger) Categories() []corpus.Category {
	out := make([]corpus.Category, 0, len(l.ByCategory))
	for c := range l.ByCategory {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
