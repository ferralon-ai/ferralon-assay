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
| CVE-2026-116591 | `2026/10/CVE-2026-116591.json` | `sha256:accbb6a99df9f6933814257318415414468cf375941fabec3743f6016df619cc` |
| CVE-2026-63209 | `2026/09/CVE-2026-63209.json` | `sha256:5c6620bf80a38b8cb413f777923dc3c4b9690bc776411849adf2e6fc18077768` |
