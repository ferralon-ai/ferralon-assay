package telemetry

import (
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// deltaTemporality is the temporality selector installed on the OTLP metric exporter: DELTA
// for every instrument kind, never cumulative. Delta keeps the SDK stateless — each data
// point covers only (T[n-1], Tn] and the collector owns cumulative conversion, windowing,
// and rate math — aggregation is the collector's problem, not the SDK's. Cumulative
// would force the SDK to hold high-cardinality per-tenant running state in-process, exactly
// the responsibility this convention pushes downstream.
//
// Caveat for future instrument PRs: delta on an UpDownCounter (e.g. tegron.sandbox.run.active)
// is well-defined but some backends prefer cumulative for in-flight gauges. Delta is
// uniform here on purpose — a stateless SDK is the invariant — so rely on the collector to
// convert; do not special-case a kind back to cumulative.
func deltaTemporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.DeltaTemporality
}

// viewsForLevel builds the metric View set for a coverage level. Every instrument is
// registered unconditionally by its emit site; the Views returned here DROP — by exact
// instrument name — every catalogued instrument whose tier is ABOVE the active level. Thus
// essential keeps only the essential streams, standard additionally keeps the standard
// streams, and full keeps everything. This is the single gating lever: the code that emits
// is identical at every level, and no drop-View touches an instrument at or below the level.
func viewsForLevel(level Level) []sdkmetric.View {
	views := make([]sdkmetric.View, 0)
	for name, tier := range instrumentTier {
		if tier > level {
			views = append(views, sdkmetric.NewView(
				sdkmetric.Instrument{Name: name},
				sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}},
			))
		}
	}
	return views
}

// samplerForLevel selects the TracerProvider sampler for a coverage level:
//   - essential → AlwaysOff (NeverSample): ZERO spans, zero exemplars, zero per-request
//     cardinality. Essential is metrics-only by construction.
//   - standard  → ParentBased(TraceIDRatioBased(ratio)): the basic span tree, ratio-sampled
//     (ratio env-tunable; 1.0 for low volume, lower under load), which also lights up the
//     trace-based exemplar path on cost histograms.
//   - full      → ParentBased(AlwaysSample): the full tree including per-Trial detail.
func samplerForLevel(level Level, ratio float64) sdktrace.Sampler {
	switch level {
	case LevelStandard:
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	case LevelFull:
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	default: // essential
		return sdktrace.NeverSample()
	}
}
