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
| CVE-2025-41249 | `2025/09/CVE-2025-41249.json` | `sha256:b59fbc1adf32dcc3c8efcf6cb8e56e5bbaa35a150e7800aafafbd77678d19806` |
| CVE-2026-19032 | `2026/09/CVE-2026-19032.json` | `sha256:adee036d9b8780b70d10dcd10acbde46d986ec905389366edca2bcfb0cb879d0` |
| CVE-2026-22747 | `2026/04/CVE-2026-22747.json` | `sha256:d75f9a647dc7bb39713c8333193762722d6e9316574d2b1a8a1014d2589fcc5f` |
