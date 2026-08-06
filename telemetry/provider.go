// Package telemetry is the shared OpenTelemetry provider for the engine. It lives
// in the ferralon-assay (lower) module because the dependency
// direction is service → ferralon-assay only: a single shared provider must therefore be an
// EXPORTED package here so both engine binaries — ferralon-assay (the OSS CLI scanner) and
// tegrond (the service daemon) — can construct it. Go internal/ visibility would block the
// cross-module import.
//
// # No API-stability promise
//
// Exported for that reason alone. Nothing outside this repository should depend on it:
// the provider bootstrap tracks whatever the two engine binaries need, and it changes
// with them. Being importable is a consequence of the module layout, not an offer of
// compatibility.
//
// New builds a MeterProvider + TracerProvider over an OTLP/gRPC exporter with a delta
// temporality selector, reading TEGRON_OTEL_LEVEL once to install one of three View sets
// (essential | standard | full). It no-ops cleanly when no OTLP endpoint is configured, so
// boot never blocks or fails on a missing collector. No business instrument emits here — the
// only live signal is the tegron.telemetry.up health counter, which proves the pipe.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Environment variables read by New. The OTLP endpoint variables are the standard OTEL
// exporter knobs (a full URL, e.g. https://collector.run.app:4317 for Cloud Run); the
// exporter itself reads the endpoint from the environment.
const (
	// EnvEnvironment sets the deployment.environment.name resource attribute. Internal-only
	// (F-6 review, same reasoning as telemetry.EnvLevel): never printed, no flag surface, not
	// part of the OSS operator-facing docs. Left literal.
	EnvEnvironment = "TEGRON_ENV"
	// EnvSampleRatio tunes the standard-tier trace sampling ratio (0.0–1.0, default 1.0).
	// Internal-only, same reasoning as EnvEnvironment above. Left literal.
	EnvSampleRatio = "TEGRON_OTEL_SAMPLE_RATIO"

	envOTLPEndpoint        = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOTLPMetricsEndpoint = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	envOTLPTracesEndpoint  = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"

	// upInstrumentName is the foundational health counter. It carries no
	// attributes — a pure liveness signal, and never an owner_id metric dimension.
	upInstrumentName = "tegron.telemetry.up"

	// scopeName is the instrumentation scope for provider-owned instruments.
	scopeName = "github.com/ferralon-ai/ferralon-assay/telemetry"

	defaultEnvironment = "development"
)

// Config carries the process identity stamped onto the OTEL Resource. The env-driven knobs
// (level, endpoint, sample ratio, environment) are read by New; a caller supplies only the
// stable identity of the binary.
type Config struct {
	// ServiceName is the reused service.name resource attribute — one of
	// tegron-cli | tegron-service | tegron-sandbox-runner.
	ServiceName string
	// ServiceVersion is the reused service.version resource attribute (build version).
	ServiceVersion string
	// Component is the minted tegron.component resource attribute distinguishing the
	// subsystem — assess | prove | sandbox-runner | callgraph | assay | model-client.
	Component string
	// Environment optionally overrides the deployment.environment.name resource attribute;
	// when empty, New reads TEGRON_ENV (default "development").
	Environment string
}

// Provider owns the constructed MeterProvider and TracerProvider and flushes them on
// Shutdown. When no OTLP endpoint is configured it is a disabled no-op whose Shutdown is a
// no-op and whose global OTEL providers stay at their default no-op implementations.
type Provider struct {
	level   Level
	enabled bool
	mp      *sdkmetric.MeterProvider
	tp      *sdktrace.TracerProvider
}

// New constructs the telemetry provider. It reads TEGRON_OTEL_LEVEL once (default essential)
// and installs the matching View set + trace sampler. When no OTLP endpoint is configured it
// returns a disabled provider without touching the network, so boot never blocks on a
// collector. A construction failure is returned to the caller, which should treat telemetry
// as best-effort (warn and continue) — telemetry must never break the boot.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	level := levelFromEnv()
	p := &Provider{level: level}

	if strings.TrimSpace(cfg.Environment) == "" {
		cfg.Environment = envOr(EnvEnvironment, defaultEnvironment)
	}

	if !otlpEndpointConfigured() {
		// Graceful no-op. The global OTEL MeterProvider/TracerProvider default to no-op
		// implementations, so downstream otel.Meter/Tracer calls remain safe; we simply do
		// not build exporters and never dial. Boot proceeds with zero telemetry cost.
		log.Printf("telemetry: %s unset — telemetry disabled (no-op); level=%s", envOTLPEndpoint, level)
		return p, nil
	}

	res := newResource(cfg)

	// Metrics: OTLP/gRPC exporter with delta temporality, periodic reader, tier Views. The
	// exporter reads the endpoint (and TLS/headers) from the standard OTEL_EXPORTER_OTLP_*
	// environment; the gRPC client dials lazily, so New does not block on the collector.
	metricExp, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithTemporalitySelector(deltaTemporality))
	if err != nil {
		return nil, fmt.Errorf("telemetry: build OTLP metric exporter: %w", err)
	}
	p.mp = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithView(viewsForLevel(level)...),
	)

	// Traces: OTLP/gRPC exporter with the level-selected sampler.
	traceExp, err := otlptracegrpc.New(ctx)
	if err != nil {
		_ = p.mp.Shutdown(ctx)
		p.mp = nil
		return nil, fmt.Errorf("telemetry: build OTLP trace exporter: %w", err)
	}
	p.tp = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithSampler(samplerForLevel(level, sampleRatioFromEnv())),
	)

	otel.SetMeterProvider(p.mp)
	otel.SetTracerProvider(p.tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	if err := registerUp(p.mp); err != nil {
		return nil, fmt.Errorf("telemetry: register %s: %w", upInstrumentName, err)
	}

	p.enabled = true
	log.Printf("telemetry: enabled (OTLP/gRPC, delta temporality); level=%s component=%s env=%s",
		level, cfg.Component, cfg.Environment)
	return p, nil
}

// Enabled reports whether telemetry is exporting (an OTLP endpoint was configured).
func (p *Provider) Enabled() bool { return p != nil && p.enabled }

// Level reports the coverage tier the provider was constructed at.
func (p *Provider) Level() Level {
	if p == nil {
		return LevelEssential
	}
	return p.level
}

// Shutdown flushes and stops the MeterProvider and TracerProvider. It is safe to call on a
// disabled (no-op) provider and on a nil receiver.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.tp != nil {
		errs = append(errs, p.tp.Shutdown(ctx))
	}
	if p.mp != nil {
		errs = append(errs, p.mp.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// newResource builds the process Resource. It is schemaless (no schema URL) to sidestep
// merge conflicts across semconv versions; the attribute KEYS are the reused semconv keys
// pinned against semconv v1.43.0 — note deployment.environment.name (the current spelling;
// the older deployment.environment was renamed), plus the minted tegron.component.
func newResource(cfg Config) *resource.Resource {
	return resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.ServiceVersion),
		attribute.String("deployment.environment.name", cfg.Environment),
		attribute.String("tegron.component", cfg.Component),
	)
}

// registerUp creates and increments the tegron.telemetry.up health counter once, proving the
// export pipe end-to-end. It carries no attributes: a zero-dimension liveness signal (and
// never an owner_id metric dimension).
func registerUp(mp metric.MeterProvider) error {
	up, err := mp.Meter(scopeName).Int64Counter(
		upInstrumentName,
		metric.WithUnit("{boot}"),
		metric.WithDescription("Heartbeat: increments once when the telemetry pipeline "+
			"initializes, proving OTLP export works (cost_class=ops)."),
	)
	if err != nil {
		return err
	}
	up.Add(context.Background(), 1)
	return nil
}

// otlpEndpointConfigured reports whether any standard OTLP endpoint variable is set. Absence
// selects the graceful no-op path.
func otlpEndpointConfigured() bool {
	for _, k := range []string{envOTLPEndpoint, envOTLPMetricsEndpoint, envOTLPTracesEndpoint} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return false
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// sampleRatioFromEnv reads TEGRON_OTEL_SAMPLE_RATIO, clamped to [0,1], default 1.0. It only
// affects the standard-tier sampler; essential is AlwaysOff and full is AlwaysSample.
func sampleRatioFromEnv() float64 {
	v := strings.TrimSpace(os.Getenv(EnvSampleRatio))
	if v == "" {
		return 1.0
	}
	r, err := strconv.ParseFloat(v, 64)
	if err != nil || r < 0 {
		return 1.0
	}
	if r > 1 {
		return 1.0
	}
	return r
}
