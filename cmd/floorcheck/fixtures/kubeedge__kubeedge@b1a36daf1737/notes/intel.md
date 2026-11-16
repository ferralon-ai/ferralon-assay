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
| CVE-2026-85731 | `2026/09/CVE-2026-85731.json` | `sha256:a75b371c2973c8e9af2839e7a13cde726d486bf27153df788ae5ad6353fdbf72` |
| GHSA-w67g-5rqw-f597 | `2026/08/GHSA-w67g-5rqw-f597.json` | `sha256:224a76459bd6794f452a872e55650b556712a472fdf1df3ffd756d0dc2f370d7` |
