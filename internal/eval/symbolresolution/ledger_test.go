package symbolresolution

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// TestLedgerSlicesByLaneAndCategory is C5: the ledger reports per in-scope lane AND per
// corpus.Category, and every category present among the outcomes appears (including the "" bucket
// of unbound records — kept visible, never dropped).
func TestLedgerSlicesByLaneAndCategory(t *testing.T) {
	fixtures := loadCorpus(t)
	led := BuildLedger(context.Background(), pipeline.AdvisoryTable, pipeline.AttributionStore{}, fixtures, spreadRunner(fixtures).run)

	// Lane axis: the measured lane plus every unmeasurable lane, all present.
	for _, lane := range append(append([]string{}, measuredLanes...), unmeasurableLanes...) {
		if _, ok := led.ByLane[lane]; !ok {
			t.Errorf("lane %q absent from ByLane", lane)
		}
	}
	if len(led.ByLane) != len(measuredLanes)+len(unmeasurableLanes) {
		t.Errorf("ByLane has %d lanes, want %d", len(led.ByLane), len(measuredLanes)+len(unmeasurableLanes))
	}

	// Category axis: total outcomes across categories == records × measured lanes; every category
	// present among bound records appears, plus "" for the unbound remainder.
	total := 0
	for _, outs := range led.ByCategory {
		total += len(outs)
	}
	if want := len(pipeline.AdvisoryTable) * len(measuredLanes); total != want {
		t.Errorf("total sliced outcomes = %d, want %d", total, want)
	}
	if _, ok := led.ByCategory[corpus.Category("")]; !ok {
		t.Error(`the "" category bucket (unbound records) is missing — it must stay visible`)
	}
	// The bound golang records carry real categories; at least one non-empty category is present.
	nonEmpty := 0
	for cat := range led.ByCategory {
		if cat != "" {
			nonEmpty++
		}
	}
	if nonEmpty == 0 {
		t.Error("no non-empty category present — bound-fixture categories were dropped")
	}

	// Every outcome in every slice is well-formed.
	for cat, outs := range led.ByCategory {
		for _, o := range outs {
			if err := o.Validate(); err != nil {
				t.Errorf("category %q outcome %s: %v", cat, o.RecordID, err)
			}
		}
	}
}

// TestLaneHonestyMeasuredVsUnmeasurable is C6: {go} reports measured with denominators; the four
// non-Go lanes report unmeasurable with a reason naming the missing input and NO denominators.
func TestLaneHonestyMeasuredVsUnmeasurable(t *testing.T) {
	fixtures := loadCorpus(t)
	led := BuildLedger(context.Background(), pipeline.AdvisoryTable, pipeline.AttributionStore{}, fixtures, spreadRunner(fixtures).run)

	goEntry := led.ByLane["go"]
	if goEntry.State != LaneMeasured {
		t.Errorf("go lane state = %q, want measured", goEntry.State)
	}
	if goEntry.Reason != "" {
		t.Errorf("measured go lane carries a reason %q, want none", goEntry.Reason)
	}
	if len(goEntry.Denominators) == 0 {
		t.Error("measured go lane has no denominators")
	}

	for _, lane := range unmeasurableLanes {
		e := led.ByLane[lane]
		if e.State != LaneUnmeasurable {
			t.Errorf("lane %q state = %q, want unmeasurable", lane, e.State)
		}
		if e.Reason != ReasonLaneArtifactIndexerAbsent {
			t.Errorf("lane %q reason = %q, want %q", lane, e.Reason, ReasonLaneArtifactIndexerAbsent)
		}
		if len(e.Denominators) != 0 {
			t.Errorf("unmeasurable lane %q carries denominators", lane)
		}
	}
}

// TestMeasuredZeroVsUnmeasurableDistinguishable is the C6 negative control: a lane that genuinely
// resolved NOTHING (measured, rate 0.0 over a non-zero denominator) MUST be distinguishable from
// an unmeasurable lane. The test asserts on State — NOT on the float — because 0.0 and "could not
// measure" are the same number to a reader and opposite facts.
func TestMeasuredZeroVsUnmeasurableDistinguishable(t *testing.T) {
	fixtures := loadCorpus(t)
	// A runner that resolves nothing: every step-5 record returns "measured, no match".
	resolveNothing := &fakeRunner{dflt: noMatchResult()}
	led := BuildLedger(context.Background(), pipeline.AdvisoryTable, pipeline.AttributionStore{}, fixtures, resolveNothing.run)

	goEntry := led.ByLane["go"]
	javaEntry := led.ByLane["java"]

	// Find D4 (buildable) — the denominator with a non-zero included count and a zero numerator.
	var d4 DenominatorReport
	for _, d := range goEntry.Denominators {
		if d.Name == "buildable-in-lane" {
			d4 = d
		}
	}
	if d4.Rate.Denom == 0 {
		t.Fatal("buildable denominator is empty — cannot demonstrate a measured 0.0")
	}
	if d4.Rate.Num != 0 {
		t.Fatalf("resolve-nothing run left numerator %d, want 0", d4.Rate.Num)
	}

	// The float alone CANNOT tell them apart: measured-zero is 0.0.
	if d4.Rate.Float() != 0.0 {
		t.Fatalf("measured-zero float = %v, want 0.0", d4.Rate.Float())
	}
	// The State discriminator IS what holds them apart.
	if goEntry.State == javaEntry.State {
		t.Fatalf("measured-zero lane and unmeasurable lane share state %q — the three-state design is defeated", goEntry.State)
	}
	if goEntry.State != LaneMeasured || javaEntry.State != LaneUnmeasurable {
		t.Fatalf("states wrong: go=%q java=%q", goEntry.State, javaEntry.State)
	}
	// Measured-zero renders its denominator (0.000 (0/N)); unmeasurable has no denominators at all.
	if got := d4.Rate.String(); got == "n/a (0/0)" {
		t.Errorf("measured-zero rendered as unmeasurable %q — the denominator vanished", got)
	}
	if len(javaEntry.Denominators) != 0 {
		t.Error("unmeasurable java lane carries denominators — it must not")
	}
}
