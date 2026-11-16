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
| CVE-2020-15250 | `2020/10/CVE-2020-15250.json` | `sha256:ab641a2a76a74fc91587822d5eee0eaaa67fed3ace0a59e685a54be3225debca` |
| CVE-2026-8149 | `2026/05/CVE-2026-8149.json` | `sha256:ad95a79f4704a76d9cfd2f150d91023d14312d5390a8798f1948b34677425b19` |
| GHSA-4h8f-2wvx-gg5w | `2024/05/GHSA-4h8f-2wvx-gg5w.json` | `sha256:2ac12c5a58d188ddcf15075da8a198cf56ad2046da8ef383f73f533d39c70198` |
