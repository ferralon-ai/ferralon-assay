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
| CVE-2026-84304 | `2026/09/CVE-2026-84304.json` | `sha256:1f6e8cb4f7e6ca529dd3e96806d0ec2665a823c9b020d8c1caa002a9aa7c4fd6` |
| CVE-2026-84445 | `2026/09/CVE-2026-84445.json` | `sha256:2a475f9c8a45cfbbd601b8a8a59d7fe62624ad1e50a13cc8cf0b68241458ea6a` |
