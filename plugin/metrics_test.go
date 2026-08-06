package plugin

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// installTestMeter installs a ManualReader-backed MeterProvider as the global provider and returns
// the reader. It restores the prior global provider on cleanup so metric state never leaks between
// tests. Tests using it must not run in parallel (they share the process-global provider).
func installTestMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	prev := otel.GetMeterProvider()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		_ = mp.Shutdown(context.Background())
		otel.SetMeterProvider(prev)
	})
	return reader
}

// sumIntPoints returns the summed int64 counter value and the attribute set of the first data point
// for the named instrument, or (0, empty, false) when the instrument was not exported.
func sumIntPoints(t *testing.T, reader *sdkmetric.ManualReader, name string) (int64, attribute.Set, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: data type %T, want Sum[int64]", name, m.Data)
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			return total, sum.DataPoints[0].Attributes, true
		}
	}
	return 0, *attribute.EmptySet(), false
}

func histoCount(t *testing.T, reader *sdkmetric.ManualReader, name string) uint64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("%s: data type %T, want Histogram[float64]", name, m.Data)
			}
			var n uint64
			for _, dp := range h.DataPoints {
				n += dp.Count
			}
			return n
		}
	}
	return 0
}

func attrValue(set attribute.Set, key string) (string, bool) {
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return "", false
	}
	return v.AsString(), true
}

// TestPluginCall_MetersOncePerSubprocessWithLanguageAndOp is the acceptance for the language-plugin
// COGS group: one analyzer subprocess call emits exactly one tegron.plugin.call.count (value 1) and
// one .duration data point, carrying codebase.language=go, plugin.op, and cost_class=cogs.
func TestPluginCall_MetersOncePerSubprocessWithLanguageAndOp(t *testing.T) {
	reader := installTestMeter(t)

	p := newHelperPlugin(t, "success")
	if _, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"}); err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}

	total, attrs, ok := sumIntPoints(t, reader, "tegron.plugin.call.count")
	if !ok {
		t.Fatal("tegron.plugin.call.count not exported")
	}
	if total != 1 {
		t.Errorf("call.count = %d, want 1 (one subprocess exec)", total)
	}
	if v, _ := attrValue(attrs, attrLanguage); v != "go" {
		t.Errorf("codebase.language = %q, want go", v)
	}
	if v, _ := attrValue(attrs, attrPluginOp); v != OpIndexSymbols {
		t.Errorf("plugin.op = %q, want %q", v, OpIndexSymbols)
	}
	if v, _ := attrValue(attrs, attrCostClass); v != costClassCOGS {
		t.Errorf("cost_class = %q, want cogs", v)
	}
	if _, present := attrs.Value(attribute.Key(attrErrorType)); present {
		t.Error("error.type must be absent on a successful call")
	}
	if n := histoCount(t, reader, "tegron.plugin.call.duration"); n != 1 {
		t.Errorf("call.duration data-point count = %d, want 1", n)
	}
}

// TestPluginCall_CarriesErrorTypeOnFailure asserts a failed subprocess call still meters the campaign
// and attaches the error.type dimension, which is carried only when the call failed.
func TestPluginCall_CarriesErrorTypeOnFailure(t *testing.T) {
	reader := installTestMeter(t)

	p := newHelperPlugin(t, "error")
	if _, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"}); err == nil {
		t.Fatal("want error from the helper's canned Response.Error")
	}

	total, attrs, ok := sumIntPoints(t, reader, "tegron.plugin.call.count")
	if !ok {
		t.Fatal("tegron.plugin.call.count not exported")
	}
	if total != 1 {
		t.Errorf("call.count = %d, want 1", total)
	}
	if v, present := attrValue(attrs, attrErrorType); !present || v == "" {
		t.Errorf("error.type must be set on a failed call, got present=%v value=%q", present, v)
	}
}

// TestPluginCall_MetersEveryLanguage is the F1 regression: review found tegron.plugin.call.*
// metered ONLY goPlugin.run — dotnetPlugin/javaPlugin/jsPlugin/pythonPlugin each had their own
// self-contained, un-metered run, so 4 of 5 languages ran dark on this COGS instrument and it
// would only ever emit codebase.language=go. Every language plugin's run now funnels through the
// single shared runSubprocessCall (subprocess.go), so this proves each of the five emits exactly
// one call.count + one call.duration point carrying its OWN real language — never a constant.
func TestPluginCall_MetersEveryLanguage(t *testing.T) {
	cases := []struct {
		language string
		plugin   func(bin string) LanguagePlugin
	}{
		{"go", func(bin string) LanguagePlugin { return &goPlugin{bin: bin} }},
		{"dotnet", func(bin string) LanguagePlugin { return &dotnetPlugin{bin: bin} }},
		{"java", func(bin string) LanguagePlugin { return &javaPlugin{bin: bin} }},
		{"js", func(bin string) LanguagePlugin { return &jsPlugin{bin: bin} }},
		{"python", func(bin string) LanguagePlugin { return &pythonPlugin{bin: bin} }},
	}

	for _, tc := range cases {
		t.Run(tc.language, func(t *testing.T) {
			reader := installTestMeter(t)

			p := tc.plugin(helperCmd(t, "success"))
			if got := p.Language(); got != tc.language {
				t.Fatalf("Language() = %q, want %q", got, tc.language)
			}
			if _, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"}); err != nil {
				t.Fatalf("IndexSymbols: %v", err)
			}

			total, attrs, ok := sumIntPoints(t, reader, "tegron.plugin.call.count")
			if !ok {
				t.Fatal("tegron.plugin.call.count not exported")
			}
			if total != 1 {
				t.Errorf("call.count = %d, want 1 (one subprocess exec — no gap, no double-count)", total)
			}
			if v, _ := attrValue(attrs, attrLanguage); v != tc.language {
				t.Errorf("codebase.language = %q, want %q (must reflect the real plugin, not a hard-coded constant)", v, tc.language)
			}
			if v, _ := attrValue(attrs, attrPluginOp); v != OpIndexSymbols {
				t.Errorf("plugin.op = %q, want %q", v, OpIndexSymbols)
			}
			if n := histoCount(t, reader, "tegron.plugin.call.duration"); n != 1 {
				t.Errorf("call.duration data-point count = %d, want 1", n)
			}
		})
	}
}
