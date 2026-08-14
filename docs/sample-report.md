# Sample report

**Illustrative, shape only.** No golden `report.json` fixture ships in this repository yet — the
excerpt below is hand-written from the `report` package's Go types
([`report/report.go`](../report/report.go)), to show the shape of the `Report` schema
(`tegron.report.v2`), not a real scan's output. Field names, nesting, and the four permitted
verdict values (`disqualified`, `not_exploitable`, `reachable_candidate`, `undetermined`) are taken
directly from the types; the identifiers, paths, and scores inside are invented for illustration
and correspond to no real advisory or codebase.

```json
{
  "schema_version": "tegron.report.v2",
  "subject": {
    "repo": "github.com/example/widget",
    "revision": "main",
    "resolved_commit": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3"
  },
  "sbom": {
    "packages": [
      {
        "ecosystem": "Go",
        "name": "golang.org/x/example",
        "version": "v0.3.7",
        "purl": "pkg:golang/golang.org/x/example@v0.3.7"
      }
    ]
  },
  "advisories": [
    {
      "advisory": {
        "id": "GO-2021-0113",
        "source": "osv",
        "aliases": ["CVE-2021-00000"]
      },
      "package": {
        "ecosystem": "Go",
        "name": "golang.org/x/example",
        "version": "v0.3.7"
      },
      "verdict": "reachable_candidate",
      "evidence": {
        "reachable_path": "net/http.HandlerFunc -> x/example.VulnFunc",
        "reachability_grade": "attacker_tainted",
        "entry_point": {
          "symbol": "main.handleRequest",
          "kind": "http_route",
          "attacker_controllable": true
        },
        "call_path": [
          { "symbol": "main.handleRequest", "file": "main.go", "line": 42 },
          { "symbol": "x/example.VulnFunc", "file": "vendor/x/example/vuln.go", "line": 17 }
        ]
      },
      "priority": {
        "epss_score": 0.12,
        "epss_percentile": 0.61,
        "kev_listed": false,
        "snapshot": "2026-08-01"
      }
    },
    {
      "advisory": { "id": "GO-2022-0322", "source": "osv" },
      "package": {
        "ecosystem": "Go",
        "name": "golang.org/x/example",
        "version": "v0.3.7"
      },
      "verdict": "disqualified",
      "evidence": {
        "basis": "version_not_in_affected_range",
        "detail": "resolved v0.3.7 is below the first affected version v0.4.0"
      }
    }
  ],
  "partiality": [],
  "provenance": {
    "commit_sha": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3",
    "analyzer_version": "v0.2.0",
    "advisory_cursor": "2026-08-01",
    "timestamp": "2026-08-01T00:00:00Z"
  }
}
```

A real report also serializes `undetermined_reason` on any finding with verdict `undetermined`, and
a non-empty `partiality` array whenever some part of the codebase could not be resolved — see
[Scope](../README.md#scope--what-this-does-not-do) for when that happens. See
[`report/report.go`](../report/report.go) for the authoritative field-by-field documentation.
