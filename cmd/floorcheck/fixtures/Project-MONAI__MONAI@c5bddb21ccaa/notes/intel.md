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
| CVE-2026-100844 | `2026/09/CVE-2026-100844.json` | `sha256:2af29e7f2efa86f94a94d4994d60f4d2927df4da153a642efca537cba1380b8c` |
| CVE-2026-100845 | `2026/09/CVE-2026-100845.json` | `sha256:8059ff0580857e1cca5a4f78844853674cde7b025c201c414a4df6013f0b4080` |
