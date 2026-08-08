# Demonstration snapshot — example advisory corpus + precomputed policies

This directory is a **frozen demonstration snapshot**: a real, deduplicated advisory corpus plus a
few precomputed **policy sub-corpora**, each a directory the scanner reads directly via
`-advisory-corpus`. It exists so the tool does something interesting out of the box, without you
having to build or fetch an advisory feed first.

It is a snapshot, not a generator. Nothing here re-derives itself at scan time; the files are what
they say they are, as of the data below.

## What's here

```
demo/
  corpus/                       the full deduped union — a -advisory-corpus root
    manifest.json               8,546 records, each pinned by sha256 of its exact bytes
    records/<language>/CVE-*.json
    index.jsonl                 one provenance row per record (see below)
  policies/                     precomputed policy sub-corpora, each its own -advisory-corpus root
    last-90d-go-high-critical/  ← the policy the top-level README demonstrates
    last-90d-python-high-critical/
    last-30d-python-high-critical/
    last-7d-javascript-high-critical/
    last-24h-all-high-critical/
    last-60d-java-high-critical/
    last-60d-dotnet-high-critical/
    policies.json               machine-readable summary (record + symbol counts per policy)
```

Each `<policy>/manifest.json` + `<policy>/records/` is a self-contained corpus you can point
`-advisory-corpus` at. Each policy also carries a `NOTE.md` stating its exact filter.

## The corpus

- **8,546 advisories**, schema `ferralon.normalized_advisory.v3`, deduplicated by CVE id from three
  symbol-enrichment collection windows (30-day, 60-day, 90-day). The windows nest, so the union
  equals the 90-day set; where a CVE appeared in more than one window the **fresher** re-enrichment
  (30d > 60d > 90d) was kept. Each record's source window is recorded in `index.jsonl`.
- **825 records carry vulnerable-symbol data** (`symbols`). Those are the reachability-interesting
  ones — an advisory with symbols lets the analyzer search a call graph for them rather than
  stopping at the dependency-version axis. They are overwhelmingly Python (559) and Go (262).
- **All five supported ecosystems are present** by package URL: PyPI 4,746 · Go 1,461 · npm 1,457 ·
  Maven 697 · NuGet 185. Java and .NET advisories are here, but the enrichment pass extracted
  essentially no Java/.NET symbols (Maven 1, NuGet 0), so those languages scan on the version axis
  only — see the per-policy notes.

### `index.jsonl` — provenance and derivation

One JSON object per record, so every derived attribute is auditable back to its source:

| field | meaning |
|---|---|
| `vuln_id` | the CVE id (also the record filename) |
| `ecosystem` / `language` | package-URL ecosystem, mapped to the scanner's language tag |
| `source_window` | which collection window this copy came from (30d / 60d / 90d) |
| `osv_id`, `published`, `modified` | the backing OSV advisory and its dates |
| `cvss_vector` | the CVSS vector string when OSV carried one (else `null`) |
| `severity_tier` | `critical`/`high`/`medium`/`low` from OSV's severity label, or **`unspecified`** |
| `has_symbols` | whether the record carries vulnerable-symbol data |
| `path`, `digest` | location and content pin inside `corpus/` |

**Severity and dates are sourced, never invented.** Tiers come from the OSV
`database_specific.severity` label; ~14% of advisories have no label and are `unspecified` rather
than guessed. A severity-scoped policy therefore *excludes* `unspecified` records — it does not
assume a tier for them. Every record has an OSV `published` date (100% coverage).

## Policies

A policy selects records from the corpus by three axes: a **time window** on the advisory's OSV
`published` date, an **ecosystem/language**, and a **severity tier**. Windows are anchored to the
snapshot's latest data — **t0 = 2026-08-07T17:16:13Z** (the newest `published` date in the corpus).
A "last 90d" policy holds advisories published within 90 days of t0, and so on.

| policy | window | language | severity | records | symbol-bearing |
|---|---|---|---|--:|--:|
| **last-90d-go-high-critical** (flagship) | 90d | Go | high+critical | 314 | **45** |
| last-90d-python-high-critical | 90d | Python | high+critical | 410 | 31 |
| last-30d-python-high-critical | 30d | Python | high+critical | 103 | 17 |
| last-7d-javascript-high-critical | 7d | JavaScript | high+critical | 48 | 0 |
| last-24h-all-high-critical | 24h | all | high+critical | 3 | 0 |
| last-60d-java-high-critical | 60d | Java | high+critical | 110 | 0 |
| last-60d-dotnet-high-critical | 60d | .NET | high+critical | 43 | 0 |

**Why the freshest windows carry no symbols.** Symbol enrichment depends on an analyzed upstream
fix, which lands well after an advisory is first published — so symbol-bearing records skew
*older*-published, and a "last 24h" or "last 7d" slice legitimately has none yet. That is why the
top-level README demonstrates the **90-day Go** policy: it is the widest window scoped to the
deepest analyzer, and it provably surfaces 45 advisories with vulnerable-symbol data, so a scan
against it exercises the reachability stage instead of stopping at the version axis. The narrow
windows are included to show the recency axis honestly, symbol-sparse tail and all.

## How the manifests are pinned

Each `manifest.json` follows the `-advisory-corpus` contract read by
[`pipeline/advisory_source.go`](../pipeline/advisory_source.go):

- `records[].output_digest` is `sha256:<hex>` over the **exact bytes** of the record file, and is
  re-verified on every lookup — a tampered or drifted record is rejected (fail-open), never scanned.
- `record_count` equals `len(records)`; identifiers are unique; `record_count` mismatch or a
  duplicate fails the whole manifest at preflight.
- `corpus_digest` is `sha256` over the compact JSON of the per-record pins
  `[identifier, path, output_digest]` sorted by identifier (the outer integrity handle the run
  records; not re-verified per lookup).

## Regenerating

`build_demo.py` rebuilds this directory from the enrichment-pass records and the raw OSV export it
reads read-only. It never executes any collection tooling — it only parses inert JSON. The script is
committed for provenance; the committed output is the artifact.
