# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project is pre-1.0;
see [API stability](docs/api-stability.md) for what that means for the public Go API.

## [v0.2.0] — 2026-08-06

First public release: the module source and a pinned composite GitHub Action.

- **Module source.** The full Assess pipeline (S1–S6), the `report`, `verdict`, `projection`,
  `trigger`, `pipeline`, `plugin`, `assessment`, `artifact`, `checkout`, `statestore`,
  `resultsink`, `corpus`, `vulnclass`, `hostmatch`, and `telemetry` packages — see [Using Assay as
  a Go library](README.md#using-assay-as-a-go-library) for the importable surface.
- **GitHub Action.** A composite action (`action.yml`) that fetches a pinned, checksum-verified
  scanner release, runs a `baseline` scan, and publishes to whichever of the job summary, a sticky
  PR comment, a pinned dashboard Issue, and SARIF code scanning the caller's token permits — see
  [Quickstart — GitHub Action](README.md#quickstart--github-action).
- **Five-language coverage.** Go, Java, JavaScript, Python, and .NET each complete a scan; analysis
  depth differs by language — see [Scope](README.md#scope--what-this-does-not-do).
- **Optional Ferralon console link.** The `link-to-console` input (default `false`) is the single
  switch that lets a run talk to Ferralon at all — see the disclosure in
  [Quickstart — GitHub Action](README.md#quickstart--github-action) and
  [docs/threat-model.md](docs/threat-model.md).

[v0.2.0]: https://github.com/ferralon-ai/ferralon-assay/commit/dc1b84a896aa0bdcefe6c98dd8bb7ab125152c0d
