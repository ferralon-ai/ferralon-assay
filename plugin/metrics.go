package plugin

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// pluginMetricScope is the OTEL instrumentation scope for the language-plugin COGS instruments.
// Each analyzer subprocess exec is one
// call; the count and duration meter the callgraph/language-plugin compute cost driver — a top-5
// COGS. Instruments are obtained from the GLOBAL MeterProvider the telemetry foundation installs
// (ferralon-assay/telemetry), so they are safe no-ops until an OTLP endpoint is configured.
const pluginMetricScope = "github.com/ferralon-ai/ferralon-assay/plugin"

// tegron.* attribute keys carried on the plugin COGS instruments. The set is fixed here and
// shared by every instrument in the engine: bounded-enum keys only, never a per-request or
// per-owner identifier.
const (
	attrCostClass = "tegron.cost_class"
	attrLanguage  = "tegron.codebase.language"
	attrPluginOp  = "tegron.plugin.op"
	attrErrorType = "error.type"

	// costClassCOGS classifies a real external compute cost. The
	// analyzer subprocess exec is compute Tegron pays for; downstream routes on this, never a rate.
	costClassCOGS = "cogs"
)

// pluginMetrics holds the two language-plugin COGS instruments. Created once per client from the
// current global MeterProvider (see goPlugin.ensureMetrics), so a test that installs a MeterProvider
// before constructing the client captures the emitted data points.
type pluginMetrics struct {
	callCount    metric.Int64Counter
	callDuration metric.Float64Histogram
}

func newPluginMetrics() pluginMetrics {
	m := otel.Meter(pluginMetricScope)
	cc, _ := m.Int64Counter(
		"tegron.plugin.call.count",
		metric.WithUnit("{call}"),
		metric.WithDescription("Language-analyzer subprocess executions — one per analyzer "+
			"subprocess call, sliced by codebase.language and plugin.op (cost_class=cogs)."),
	)
	cd, _ := m.Float64Histogram(
		"tegron.plugin.call.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Language-analyzer subprocess wall time in seconds; sum is the "+
			"total plugin compute, distribution catches the slow op (cost_class=cogs)."),
	)
	return pluginMetrics{callCount: cc, callDuration: cd}
}

// ensureMetrics lazily creates the client's instruments on first use. Lazy (not constructed in
// NewGoPlugin) so it also covers clients built by struct literal, and so the instruments bind to
// whatever MeterProvider is installed at first call — which is after telemetry.New in production and
// after a test's manual provider in the hermetic suite.
func (p *goPlugin) ensureMetrics() {
	p.metricsOnce.Do(func() { p.metrics = newPluginMetrics() })
}

// errorType renders a low-cardinality error.type value — OTEL's own semantic-convention
// attribute, reused verbatim rather than renamed under a tegron.* key. The
// concrete Go error type is bounded (a handful of wrap/string types), never the error message —
// keeping it a safe metric dimension. Empty when there is no error.
func errorType(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T", err)
}
