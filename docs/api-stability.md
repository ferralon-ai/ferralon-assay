# API stability

This module is pre-1.0, and its exported API may change. This page says what we already hold
ourselves to, so you can judge the risk of importing it rather than guess at it.

Two things are worth knowing before you depend on `ferralon-assay` as a library: it keeps
third-party types off its exported signatures, and it has a handful of exported package-level
variables that are not safe to write concurrently.

## Third-party types are kept off the exported surface

A third-party type in an exported signature is a version pin on everyone who imports you. If a
public struct field were `[]*packages.Package`, then any program importing this module would have
to resolve `golang.org/x/tools` to a version whose `packages.Package` is assignment-compatible with
ours — a compatibility promise on a type we neither own nor version. That is an expensive accident,
so the exported surface is audited to keep it from happening.

The watched modules are `golang.org/x/tools`, `golang.org/x/vuln`, `golang.org/x/mod`, and
`go.opentelemetry.io/otel`, including all sub-paths. Together with `github.com/google/uuid` they are
this module's only non-stdlib dependencies.

**Today the importable packages expose zero third-party types.**

The audit found two, both in `plugin/goanalysis` — `LoadResult.Packages` and `LoadProgram`, each
leaking `golang.org/x/tools/go/packages.Package`. Neither had an importer outside its own package,
so instead of documenting them as accepted exceptions we removed them: the package now lives under
`internal/`, where it is not part of the public API at all. There are no remaining exceptions and
therefore no exception list.

Two cases are worth calling out because they look like they should leak and do not:

- **`telemetry`** hands the host an OpenTelemetry setup without ever naming an otel type in its
  signatures. `Provider` holds its `MeterProvider` and `TracerProvider` in unexported fields, and
  its whole exported surface is `New`, `Enabled`, `Level`, `Shutdown`, `Config`, `Level`,
  `ParseLevel`, and some string constants. It installs providers through the otel globals, so you
  reach instrumentation via `otel.Meter(...)` in your own code rather than through a value we hand
  back. That is deliberate and worth preserving — returning the concrete `*sdkmetric.MeterProvider`
  for caller convenience would create the exception this design avoids.
- **`pipeline` and `plugin`** both import otel, and `pipeline` imports `golang.org/x/mod`, but only
  in unexported declarations and function bodies. None of it reaches an exported signature.

### Checking it yourself

The exhaustive audit walked every exported package-scope object with
`golang.org/x/tools/go/packages` — parameter and result types, exported and embedded struct fields,
interface method sets, value and pointer method sets, type arguments, and through
pointer/slice/array/map/channel element types — reporting any named type defined in one of the four
watched modules. That tool was a one-shot and is not committed.

The cheap regression check catches the common case, and is worth running against a version you are
about to depend on:

```sh
cd ferralon-assay
for p in artifact assessment checkout corpus hostmatch pipeline plugin projection report \
         resultsink resultsink/github statestore telemetry trigger verdict vulnclass; do
  GOWORK=off go doc -all ./$p
done | grep -nE '(x/tools|x/vuln|x/mod|go\.opentelemetry\.io|packages|otel|metric|attribute|sdkmetric|sdktrace|modfile|semver|ssa)\.[A-Z]'
```

It is a text match, so it reports prose inside doc comments as well as real declarations. At the
time of writing the only hits are prose. Any hit that is an actual declaration is a regression.

## Exported mutable process-wide state

These are exported package-level variables and setters with no synchronization. They are not
third-party leaks, but they are the most likely surprise for a consumer, so they are listed here
rather than left to be discovered.

| Symbol | Where | Why it bites |
|---|---|---|
| `pipeline.AdvisoryTable` | `pipeline/stages.go` | An exported `map[string]AdvisoryFacts`. Maps are reference types, so a consumer can mutate the analyzer's advisory facts at runtime, from any goroutine, with no synchronization. |
| `pipeline.SetDefaultAdvisorySource` | `pipeline/advisory_source.go` | An unguarded process-wide setter. Its contract is set-before-spawn; it is not `-race`-safe. |
| `trigger.AnalyzerVersion` | `trigger/assess.go` | An exported `var`. It is writable, and its value lands in emitted reports. |
| `github.PRCommentMarker` | `resultsink/github/tier1_pr_comment.go` | The marker used to find and overwrite an existing PR comment. Changing it at runtime orphans previously-posted comments. |
| `github.IssueMarker` | `resultsink/github/tier1_issue.go` | The same hazard for the pinned dashboard issue. |
| `github.IssueTitle` | `resultsink/github/tier1_issue.go` | The same. |

Treat all six as set-once-before-use, from a single goroutine, if you set them at all. Narrowing
them is on the list; until then this page is the warning.
