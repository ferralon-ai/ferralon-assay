package telemetry

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestViewSetFlip_HigherTierStreamDroppedAtLowerLevel is the acceptance test for the tier
// knob: a stream kept at one level must be dropped at a lower level. It records to a
// standard-tier instrument and asserts the View set drops it at essential but keeps it at
// standard.
func TestViewSetFlip_HigherTierStreamDroppedAtLowerLevel(t *testing.T) {
	const stdInstrument = "tegron.stage.duration"
	if got := instrumentTier[stdInstrument]; got != LevelStandard {
		t.Fatalf("precondition: instrumentTier[%q] = %v, want standard", stdInstrument, got)
	}

	if present := collectHistogramPresent(t, LevelEssential, stdInstrument); present {
		t.Errorf("level=essential: %s was exported, want DROPPED by the essential View set", stdInstrument)
	}
	if present := collectHistogramPresent(t, LevelStandard, stdInstrument); !present {
		t.Errorf("level=standard: %s was dropped, want KEPT by the standard View set", stdInstrument)
	}
}

// collectHistogramPresent builds a MeterProvider at level over a ManualReader, records one
// value to a histogram named instrumentName, collects, and reports whether the stream
// survived the level's Views.
func collectHistogramPresent(t *testing.T, level Level, instrumentName string) bool {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithView(viewsForLevel(level)...),
	)
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	h, err := mp.Meter("test").Float64Histogram(instrumentName)
	if err != nil {
		t.Fatalf("create histogram %s: %v", instrumentName, err)
	}
	h.Record(context.Background(), 1.0)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == instrumentName {
				return true
			}
		}
	}
	return false
}

// TestTelemetryUp_Emits asserts the foundational health counter emits exactly one data point
// with value 1 and NO attributes (zero-dimension; never owner_id).
func TestTelemetryUp_Emits(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	if err := registerUp(mp); err != nil {
		t.Fatalf("registerUp: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	sum := findSumInt64(t, &rm, upInstrumentName)
	if len(sum.DataPoints) != 1 {
		t.Fatalf("%s: got %d data points, want 1", upInstrumentName, len(sum.DataPoints))
	}
	if got := sum.DataPoints[0].Value; got != 1 {
		t.Errorf("%s: value=%d, want 1", upInstrumentName, got)
	}
	if n := sum.DataPoints[0].Attributes.Len(); n != 0 {
		t.Errorf("%s: %d attributes, want 0 (zero-dimension liveness signal, never owner_id)", upInstrumentName, n)
	}
}

func findSumInt64(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.Sum[int64] {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				s, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("%s: data type %T, want Sum[int64]", name, m.Data)
				}
				return s
			}
		}
	}
	t.Fatalf("%s: not found in collected metrics", name)
	return metricdata.Sum[int64]{}
}

// TestSampler_EssentialExportsNoSpans asserts the essential sampler is AlwaysOff (zero spans
// exported) and that a span DOES export at standard (the tree lights up above essential).
func TestSampler_EssentialExportsNoSpans(t *testing.T) {
	if n := spansExported(t, LevelEssential); n != 0 {
		t.Errorf("level=essential: exported %d spans, want 0 (AlwaysOff)", n)
	}
	if n := spansExported(t, LevelStandard); n == 0 {
		t.Errorf("level=standard: exported 0 spans, want >=1")
	}
	if n := spansExported(t, LevelFull); n == 0 {
		t.Errorf("level=full: exported 0 spans, want >=1")
	}
}

func spansExported(t *testing.T, level Level) int {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(samplerForLevel(level, 1.0)),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	_, span := tp.Tracer("test").Start(context.Background(), "tegron.assess")
	span.End()
	if err := tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("force flush: %v", err)
	}
	return len(exp.GetSpans())
}

// TestDeltaTemporality_NeverCumulative asserts the exporter temporality selector returns
// delta for every instrument kind — never cumulative, so the SDK stays stateless.
func TestDeltaTemporality_NeverCumulative(t *testing.T) {
	kinds := []sdkmetric.InstrumentKind{
		sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter,
		sdkmetric.InstrumentKindObservableGauge,
	}
	for _, k := range kinds {
		if got := deltaTemporality(k); got != metricdata.DeltaTemporality {
			t.Errorf("deltaTemporality(%v) = %v, want DeltaTemporality (never cumulative)", k, got)
		}
	}
}

// TestNew_NoopWhenEndpointUnset asserts boot does not crash or block when no OTLP endpoint is
// configured: New returns a disabled provider whose Shutdown is a clean no-op.
func TestNew_NoopWhenEndpointUnset(t *testing.T) {
	t.Setenv(envOTLPEndpoint, "")
	t.Setenv(envOTLPMetricsEndpoint, "")
	t.Setenv(envOTLPTracesEndpoint, "")
	t.Setenv(EnvLevel, "essential")

	p, err := New(context.Background(), Config{
		ServiceName:    "tegron-cli",
		ServiceVersion: "0.0.0-test",
		Component:      "assess",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Enabled() {
		t.Error("expected a disabled provider when no OTLP endpoint is configured")
	}
	if p.Level() != LevelEssential {
		t.Errorf("Level()=%v, want essential", p.Level())
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on disabled provider: %v", err)
	}
}

// TestParseLevel covers the default and the unknown-value fallback.
func TestParseLevel(t *testing.T) {
	cases := []struct {
		in     string
		want   Level
		wantOK bool
	}{
		{"", LevelEssential, true},
		{"essential", LevelEssential, true},
		{"standard", LevelStandard, true},
		{"STANDARD", LevelStandard, true},
		{"  full ", LevelFull, true},
		{"bogus", LevelEssential, false},
	}
	for _, c := range cases {
		got, ok := ParseLevel(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestTierCatalogCardinality guards the catalog's 17 essential / 20 standard / 3 full split
// (plus the up counter), so a mistyped or dropped entry is caught in review.
func TestTierCatalogCardinality(t *testing.T) {
	var e, s, f int
	for _, tier := range instrumentTier {
		switch tier {
		case LevelEssential:
			e++
		case LevelStandard:
			s++
		case LevelFull:
			f++
		}
	}
	// 17 essential business/COGS instruments + the tegron.telemetry.up health counter = 18.
	if e != 18 {
		t.Errorf("essential instruments = %d, want 18 (17 business/COGS + telemetry.up)", e)
	}
	if s != 20 {
		t.Errorf("standard instruments = %d, want 20", s)
	}
	if f != 3 {
		t.Errorf("full instruments = %d, want 3", f)
	}
}

// TestEnvLevelFlipsInstalledViewSet is the end-to-end form of acceptance (a): it ties the
// TEGRON_OTEL_LEVEL *environment variable* to the installed View set. The SAME standard-tier
// stream is dropped when the env selects essential and kept when it selects standard, proving
// the env var (read once via levelFromEnv at provider construction) is the single gating lever
// — not just the Level enum the sibling test exercises directly.
func TestEnvLevelFlipsInstalledViewSet(t *testing.T) {
	const stdInstrument = "tegron.stage.duration"

	t.Setenv(EnvLevel, "essential")
	if present := collectHistogramPresent(t, levelFromEnv(), stdInstrument); present {
		t.Errorf("TEGRON_OTEL_LEVEL=essential: %s exported, want DROPPED by the essential View set", stdInstrument)
	}

	t.Setenv(EnvLevel, "standard")
	if present := collectHistogramPresent(t, levelFromEnv(), stdInstrument); !present {
		t.Errorf("TEGRON_OTEL_LEVEL=standard: %s dropped, want KEPT by the standard View set", stdInstrument)
	}
}

// TestFoundation_OnlyTelemetryUpEmits: this package is pure foundation, so the ONLY
// live emit site is registerUp. A collected foundation MeterProvider must therefore carry
// exactly one metric — tegron.telemetry.up — and NO business instrument. This guards the
// invariant that the foundation lights up the pipe without emitting a single domain metric;
// the business/COGS instruments arrive in their own later phase PRs.
func TestFoundation_OnlyTelemetryUpEmits(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	if err := registerUp(mp); err != nil {
		t.Fatalf("registerUp: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names = append(names, m.Name)
		}
	}
	if len(names) != 1 || names[0] != upInstrumentName {
		t.Errorf("foundation emitted %v, want exactly [%s] — no business instrument emits yet", names, upInstrumentName)
	}
}
