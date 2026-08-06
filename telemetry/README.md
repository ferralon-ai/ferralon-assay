# `telemetry` — shared OpenTelemetry provider for the tegron engine

The OpenTelemetry SDK foundation both engine binaries construct at startup. It
builds a
`MeterProvider` + `TracerProvider` over an **OTLP/gRPC** exporter with **delta**
temporality, reads `TEGRON_OTEL_LEVEL` once to install one of three View sets,
and **no-ops cleanly when no OTLP endpoint is configured** so boot never blocks
on a collector.

This is pure foundation. No business instrument emits yet — the only live signal
is the `tegron.telemetry.up` health counter, which proves the export pipe. The
cost-of-goods instruments it is built for land with their emit sites; their
coverage tiers are already fixed in `tiers.go`.

## Why it lives here (and is exported)

The dependency direction is **`service` → `ferralon-assay`, never the reverse**. A
single shared provider must therefore be an **exported** package in the lower
(`ferralon-assay`) module — Go `internal/` visibility would block the cross-module
import from `service`. Both binaries import it: `ferralon-assay` (the OSS CLI
scanner) and `tegrond` (the service daemon).

## Usage

Construct once at startup, defer `Shutdown` so the final metric batch flushes on
exit:

```go
tel, err := telemetry.New(ctx, telemetry.Config{
    ServiceName:    "tegron-cli",   // tegron-cli | tegron-service | tegron-sandbox-runner
    ServiceVersion: version,        // build version
    Component:      "assess",       // assess | prove | sandbox-runner | callgraph | assay | model-client
})
if err != nil {
    // Non-fatal: telemetry must NEVER break the boot. Warn and continue.
    log.Printf("telemetry init (continuing without telemetry): %v", err)
} else {
    defer func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        _ = tel.Shutdown(ctx)
    }()
}
```

For a short-lived CLI, split `main` so the deferred `Shutdown` actually runs —
`os.Exit` skips defers and would drop the final flush (see
`cmd/ferralon-assay/main.go`'s `run() int` split).

`New` sets the **global** `otel.MeterProvider` / `otel.TracerProvider`, so
downstream `otel.Meter(...)` / `otel.Tracer(...)` calls just work (and are safe
no-ops when telemetry is disabled).

## Configuration (environment)

| Env var | Default | Effect |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` (or the `_METRICS` / `_TRACES` variants) | *(unset)* | The collector target. **Unset → the whole provider is a graceful no-op** (no exporters built, no network dialed). |
| `TEGRON_OTEL_LEVEL` | `essential` | Coverage tier: `essential` \| `standard` \| `full`. Read **once** at construction; selects the installed View set + trace sampler. An unrecognized value falls back to `essential`. |
| `TEGRON_ENV` | `development` | The `deployment.environment.name` resource attribute (overridable via `Config.Environment`). |
| `TEGRON_OTEL_SAMPLE_RATIO` | `1.0` | Trace sampling ratio for **standard** only (clamped to `[0,1]`). `essential` is `AlwaysOff`; `full` is `AlwaysSample`. |

The exporter reads the endpoint, TLS, and headers from the standard `OTEL_*`
environment; the gRPC client dials lazily, so `New` never blocks on the collector.

## The coverage-tier knob (`TEGRON_OTEL_LEVEL`)

One knob, three **View sets** — not three code paths. Every instrument is
registered unconditionally by its emit site (registering is cheap); SDK Views
decide what actually aggregates and exports. `tiers.go` is the single source of
truth mapping each instrument to the lowest level at which its stream survives;
`viewsForLevel` drops, by exact instrument name, every stream above the active
level.

| Level | Metrics | Traces |
|---|---|---|
| `essential` (default) | Count every business action + top COGS; bounded-enum attributes only. | **`AlwaysOff` — zero spans**, zero exemplars, zero per-request cardinality. |
| `standard` | + per-run cost breakdowns, durations, stage/`cve.id`/`vuln_class`/`language` dims, aux ops. | Basic span tree, `ParentBased(TraceIDRatioBased(ratio))` — lights up exemplars. |
| `full` | + vanity, high-cardinality, `cve.id` as a metric dimension. | + per-Trial detail, `AlwaysSample`. |

The knob gates emission **volume**, never pricing: it changes which signals
export and at what cardinality; it never multiplies a unit by a rate.

## Invariants

- **Delta temporality only** — never cumulative. The SDK stays stateless; the
  collector owns rollup, windowing, and rate math.
- **No currency/rate instrument, no in-process rollup.** Raw units (`{token}`,
  `s`, `By`, counts) only; `tegron.cost_class` classifies, downstream denominates.
- **No `owner_id` metric dimension, ever.** Per-tenant identity rides on spans and
  DB columns only. A metric dimension is unbounded cardinality and outlives any
  retention policy the identity is subject to.
- **`tegron.*` launches at `development` stability** (one-way ratchet).

## The semantic convention

The `tegron.*` names — resource attributes, shared attributes, and the instrument
tiers in `tiers.go` — are pinned against OTEL semconv `v1.43.0`. Where an
upstream convention already has the attribute we need, we reuse it verbatim
rather than minting a `tegron.*` twin: `gen_ai.*`, `http.*`, `rpc.*`, and
`error.type` all appear here under their upstream names. Only concepts with no
upstream equivalent — `tegron.cost_class`, `tegron.plugin.op` — get a new key.
