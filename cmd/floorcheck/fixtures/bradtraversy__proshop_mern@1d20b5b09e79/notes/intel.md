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
| CVE-2026-113872 | `2026/10/CVE-2026-113872.json` | `sha256:0de2ce13300e5080c8a9b64b2b4d0df8f8214efd0dc0adcf91e8a5f5ec081dec` |
| CVE-2026-2391 | `2026/02/CVE-2026-2391.json` | `sha256:6f70be62f188feed6d19b605c9804cd311d3f560dea51d7fab49b5b5a1d9eb1d` |
| CVE-2026-5038 | `2026/06/CVE-2026-5038.json` | `sha256:3f08dd55ff47fea437095e3ed36296bf0708b16e361b842a38f9af1cd58bbb6a` |
| CVE-2026-5079 | `2026/06/CVE-2026-5079.json` | `sha256:94236982bedd8be6df542dac694b79426088e1d4110dab0c7d69d687c6fffd8c` |
| CVE-2026-77037 | `2026/08/CVE-2026-77037.json` | `sha256:6da373ada1dfdcba5f07d268cc67248e0fedb31d1a8cd43d1ea47d4c2eb05de2` |
| CVE-2026-77078 | `2026/08/CVE-2026-77078.json` | `sha256:9c1884a224206f9aa099e84da7860010660b2e23333bf7780e077ce18982931a` |
| CVE-2026-88932 | `2026/09/CVE-2026-88932.json` | `sha256:3eef542d201af0ea8874d86519ecdae109ff367667389a68997d30ab270c2ae3` |
