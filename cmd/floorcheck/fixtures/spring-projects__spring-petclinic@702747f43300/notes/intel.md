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
| CVE-2026-41848 | `2026/06/CVE-2026-41848.json` | `sha256:e73dfd8d03587a50b505e14e0690e51f64c6b3961d7272ec3cc30a8cb81606c9` |
| CVE-2026-54512 | `2026/06/CVE-2026-54512.json` | `sha256:275a82b67511c1ba5f92fec39aa23c2422f678cedc68a0901d78281bf1ef663e` |
| CVE-2026-59889 | `2026/07/CVE-2026-59889.json` | `sha256:8496a3bcb6c91b23752b691ba5fea453e2731f126349cf98305c186ce8ef0ec7` |
| CVE-2026-68497 | `2026/09/CVE-2026-68497.json` | `sha256:5430d38fd7ec8689d83867119da1d0688662806c330bdcefaff224c289f40ad9` |
| CVE-2026-83557 | `2026/09/CVE-2026-83557.json` | `sha256:61511e68486641287e5341febf20c12926757c062ecd68eeca4af4ef683bca6b` |
| CVE-2026-89425 | `2026/09/CVE-2026-89425.json` | `sha256:cecfda14d31f57ee875efd5296d46b4059651a3d750dd58e442d885b0b40d4bc` |
| CVE-2026-91776 | `2026/09/CVE-2026-91776.json` | `sha256:0d3794afd83ccecd955edc6ccce62b94b25b495ff0ab9cf9174b724cbad8364e` |
| CVE-2026-91777 | `2026/09/CVE-2026-91777.json` | `sha256:031790ca85efb2976bbd7fd99cf6cc2badbacc989369403a1f9cf02bc33d343b` |
| GHSA-673j-qm5f-xpv8 | `2022/02/GHSA-673j-qm5f-xpv8.json` | `sha256:196026690333a0e4513eded50a78bf8c4bf674fc3d4388e2ce527186c6ef9bbe` |
