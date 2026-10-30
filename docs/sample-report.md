# Sample report

**Illustrative, shape only.** No golden `report.json` fixture ships in this repository yet — the
excerpt below is hand-written from the `report` package's Go types
([`report/report.go`](../report/report.go)), to show the shape of the `Report` schema
(`tegron.report.v3`), not a real scan's output. Field names, nesting, and the five permitted
verdict values (`disqualified`, `not_exploitable`, `reachable_candidate`, `undetermined`,
`malicious_package_present`) are taken directly from the types; the identifiers, paths, and scores
inside are invented for illustration and correspond to no real advisory or codebase.

```json
{
  "schema_version": "tegron.report.v3",
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
        "epss_as_of": "2026-07-31",
        "kev_catalog_version": "2026.07.30",
        "kev_date_released": "2026-07-30T18:00:00.000Z"
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
    "analyzer_version": "v0.5.0",
    "advisory_cursor": "2026-08-01",
    "timestamp": "2026-08-01T00:00:00Z",
    "intel": {
      "work_set_source": "builtin_language_set",
      "work_set_size": 2,
      "fact_source": "builtin_table",
      "signals_digest": "sha256:5d1e…"
    }
  }
}
```

A real report also serializes `undetermined_reason` on any finding with verdict `undetermined`
([the reasons](operator-guide.md#undetermined-reasons)), and a non-empty `partiality` array whenever
some part of the codebase could not be resolved — see [Scope](../README.md#scope) for when that
happens. See [`report/report.go`](../report/report.go) for the authoritative field-by-field
documentation.

## Optional fields not shown above

These fields appear only when the scan has something to say:

| Field | Where | Carries |
|---|---|---|
| `root` | package | `true` for the scanned project's own package, when an advisory targets it. |
| `replace` | package | The module path a Go `replace` directive substitutes for the package. |
| `go_build_list`, `go_main_module`, `go_workspace_modules` | `sbom` | The resolver output a Go SBOM was taken from, the module it was resolved for, and the go.work's other modules when it was resolved under one. |
| `advisory_bounds` | finding `evidence` | The affected ranges an advisory records, on an `advisory_range_absent` finding only. |
| `package`, `path` | `partiality` note | The package and location inside it that a limit is bounded to. |
| `priority` | finding | EPSS/KEV context, only when the run was given a signals file that has a stamped value for the advisory. Each value carries its own date: `epss_as_of` for the EPSS fields, `kev_catalog_version` and `kev_date_released` for the KEV ones. `epss_score` is present exactly when `epss_as_of` is, a score of 0 included, and `epss_percentile` whenever the signals file sourced one, a percentile of 0 included. `kev_listed` appears only when `true`; a KEV stamp without it, as above, means "not in that catalog". |
| `signals_digest` | `provenance.intel` | The `signals_digest` of the signals file the findings were ranked with. |

Partiality reasons a scan can carry include `work_set_dependency_unresolved` and the JavaScript
`relationship_unexpressed:uninspectable_package` and `relationship_unexpressed:computed_require`;
[`plugin/plugin.go`](../plugin/plugin.go) holds the full vocabulary.
