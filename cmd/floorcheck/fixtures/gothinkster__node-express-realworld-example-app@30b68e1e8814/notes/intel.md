# Advisory intel

`intel/advisories/` holds only the advisories adjudicated for this fixture, so the scan's work set is
those advisories and nothing else. Signals are not included: they rank findings and never move a verdict.

Source: release `corpus-92d72057330c` of `ferralon-ai/vulnerability-corpus`, asset `full.jsonl.gz`
(`sha256:2233ff305c007bbfdd0e88d8e121f26a7699927ce277d87092ed08caab987af0`).

Extraction: each record below is the bundle line's `bytes` written verbatim to its `path`; its sha256
equals the line's `output_digest`, which `manifest.json` pins. The manifest's `corpus_digest` is the
sha256 of the sorted `<identifier> <output_digest>` lines.

| Identifier | Path | Digest |
|---|---|---|
| CVE-2025-15284 | `2025/12/CVE-2025-15284.json` | `sha256:8a5e0e891491f7cd1a954c7586d776eacd9bd00c046854cac88c2064e49d8d56` |
| CVE-2026-2391 | `2026/02/CVE-2026-2391.json` | `sha256:6f70be62f188feed6d19b605c9804cd311d3f560dea51d7fab49b5b5a1d9eb1d` |
