// internal/pipeline/metrics_test.go
package pipeline

import (
	"context"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// metricsReader is a package-scoped, delta-temporality ManualReader installed as the global
// MeterProvider exactly ONCE, in TestMain, before any test runs. This must be the only
// otel.SetMeterProvider call in this test binary: go.opentelemetry.io/otel's global package
// upgrades an already-vended otel.Meter(...) instrument (scanCounter, constructed at package
// init) to a real provider only on the FIRST SetMeterProvider call in the process — a second
// call would move the global pointer for future callers but NOT re-delegate scanCounter, which
// is fixed to whichever provider won that first call. Delta temporality means each Collect
// drains only what accumulated since the previous Collect, so per-test "baseline collect, act,
// collect-and-assert" windows are robust to test execution order within this binary.
var metricsReader = sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(
	func(sdkmetric.InstrumentKind) metricdata.Temporality { return metricdata.DeltaTemporality },
))

func TestMain(m *testing.M) {
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(metricsReader))
	otel.SetMeterProvider(mp)
	os.Exit(m.Run())
}

// sumInt64 drains the delta accumulated since the previous collect and returns the summed
// value across all data points for the named counter (0 if it recorded nothing this window).
func sumInt64(t *testing.T, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricsReader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			s, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range s.DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

func TestScanCounter_IncrementsOncePerRun(t *testing.T) {
	sumInt64(t, "tegron.scan.count") // drain prior accumulation to establish a clean baseline

	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	c := newRunCase(t, cases)
	var ran []string
	orch := NewOrchestrator(cases, store, []Stage{
		fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran},
		fakeStage{name: "b", status: assessment.StatusAnalysis, ran: &ran},
	})

	if err := orch.Run(context.Background(), c.ID); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := sumInt64(t, "tegron.scan.count"); got != 1 {
		t.Fatalf("tegron.scan.count = %d, want 1", got)
	}
}

func TestScanCounter_IncrementsEvenOnStageFailure(t *testing.T) {
	sumInt64(t, "tegron.scan.count") // baseline

	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	c := newRunCase(t, cases)
	var ran []string
	orch := NewOrchestrator(cases, store, []Stage{
		fakeStage{name: "a", status: assessment.StatusInventory, fail: true, ran: &ran},
	})

	if err := orch.Run(context.Background(), c.ID); err == nil {
		t.Fatal("Run: want error")
	}
	// scan.count counts the ATTEMPT, not just a successful one —
	// a failed scan still consumed a scan's worth of compute.
	if got := sumInt64(t, "tegron.scan.count"); got != 1 {
		t.Fatalf("tegron.scan.count = %d, want 1 (counts the attempt, not just success)", got)
	}
}

func TestScanCounter_TwoRunsIncrementTwice(t *testing.T) {
	sumInt64(t, "tegron.scan.count") // baseline

	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	var ran []string
	stages := []Stage{fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran}}

	c1 := newRunCase(t, cases)
	if err := NewOrchestrator(cases, store, stages).Run(context.Background(), c1.ID); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	c2 := newRunCase(t, cases)
	if err := NewOrchestrator(cases, store, stages).Run(context.Background(), c2.ID); err != nil {
		t.Fatalf("Run 2: %v", err)
	}

	if got := sumInt64(t, "tegron.scan.count"); got != 2 {
		t.Fatalf("tegron.scan.count = %d, want 2 (one per Run call)", got)
	}
}
