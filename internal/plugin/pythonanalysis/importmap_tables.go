package pythonanalysis

// Inline curated distribution→import-package table (PLAN-172 C5) and the synthetic PEP 420
// namespace fixture (C3, D5).
//
// The curated set is a handful of rows, so it ships INLINE and is reviewed in the engineer
// stage — it does not warrant a maintained artifact with its own review workflow. Every row
// carries a cited Source + RFC 3339 Date: a `curated` label is a CLAIM (C5), auditable row by
// row, not a coincidence the type launders into a fact. The NON-IDENTITY rows
// (apache-airflow→airflow, pyjwt→jwt, pillow→PIL, …) are what prove the map is a real lookup
// and not strings.ToLower(dist).

// curatedTableDate is the RFC 3339 (full-date) date the curated rows were taken.
const curatedTableDate = "2026-08-10"

// importBindingTableDate is the RFC 3339 (full-date) date the import-binding rows were taken.
const importBindingTableDate = "2026-10-12"

// CuratedContributions returns the inline curated rows, each with a cited Source + Date (C5).
// Distribution names are PEP 503-normalized. The result is NOT yet canonicalized; feed it
// (with the declared/unknown contributions) through NewDistImportMap.
//
// The import-binding rows (dated importBindingTableDate, each citing the wheel whose
// top-level entries were listed) cover distributions whose import name is not their
// distribution name, so a call through `import jwt` / `import yaml` names the right
// distribution — the PEP 503 fallback cannot ("jwt" never equals "pyjwt").
//
// The five identity rows (flask, jinja2, markupsafe, aiohttp, pydantic) still carry a real
// cited Source — the curated label on flask→flask is a claim that cites where the import name
// was confirmed, not an assumption the type launders into a fact (discovery, load-bearing
// finding §2).
func CuratedContributions() []Contribution {
	return []Contribution{
		{
			Distribution:  "apache-airflow",
			ImportPackage: "airflow", // NON-IDENTITY: distribution "apache-airflow" imports as "airflow"
			Provenance:    ProvenanceCurated,
			Source:        "Advisory FERRALON-PY-AIRFLOW-EXPAPI-0001 (pkg:pypi/apache-airflow); the AIRFLOW repro (corpus/testdata/repros/FERRALON-PY-AIRFLOW-EXPAPI-0001-*/src) is a faithful reduction of apache/airflow source per its file-header comments (the reduced src imports flask, not airflow); Apache Airflow PyPI project page / docs confirms the distribution imports as `airflow`",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "flask",
			ImportPackage: "flask",
			Provenance:    ProvenanceCurated,
			Source:        "Advisory FERRALON-PY-DEP-0001 (pkg:pypi/flask); `from flask import ...` in the AIRFLOW and SSRF repros; Flask PyPI project page",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "jinja2",
			ImportPackage: "jinja2",
			Provenance:    ProvenanceCurated,
			Source:        "Advisory CVE-2024-22195 (pkg:pypi/jinja2); `Jinja2==3.1.2` in the JINJA2 repro requirements.txt; PLAN-170 pdm/uv fixtures; Jinja2 PyPI project page",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "markupsafe",
			ImportPackage: "markupsafe",
			Provenance:    ProvenanceCurated,
			Source:        "PLAN-170 pdm/uv resolver fixtures (jinja2's transitive dependency); MarkupSafe PyPI project page",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "aiohttp",
			ImportPackage: "aiohttp",
			Provenance:    ProvenanceCurated,
			Source:        "Advisory pkg:pypi/aiohttp (CVE-2023-49081-class); aiohttp PyPI project page",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "pydantic",
			ImportPackage: "pydantic",
			Provenance:    ProvenanceCurated,
			Source:        "Advisory pkg:pypi/pydantic; pydantic PyPI project page",
			Date:          curatedTableDate,
		},
		{
			Distribution:  "pyjwt",
			ImportPackage: "jwt",
			Provenance:    ProvenanceCurated,
			Source:        "pyjwt-2.15.1-py3-none-any.whl from pypi.org: sole top-level package jwt/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "pyyaml",
			ImportPackage: "_yaml",
			Provenance:    ProvenanceCurated,
			Source:        "pyyaml-6.0.3-cp310-cp310-macosx_10_13_x86_64.whl from pypi.org: top-level packages _yaml/ and yaml/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "pyyaml",
			ImportPackage: "yaml",
			Provenance:    ProvenanceCurated,
			Source:        "pyyaml-6.0.3-cp310-cp310-macosx_10_13_x86_64.whl from pypi.org: top-level packages _yaml/ and yaml/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "pillow",
			ImportPackage: "PIL",
			Provenance:    ProvenanceCurated,
			Source:        "pillow-12.3.0-cp310-cp310-macosx_10_10_x86_64.whl from pypi.org: sole top-level package PIL/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "beautifulsoup4",
			ImportPackage: "bs4",
			Provenance:    ProvenanceCurated,
			Source:        "beautifulsoup4-4.15.0-py3-none-any.whl from pypi.org: sole top-level package bs4/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-dateutil",
			ImportPackage: "dateutil",
			Provenance:    ProvenanceCurated,
			Source:        "python_dateutil-2.9.0.post0-py2.py3-none-any.whl from pypi.org: sole top-level package dateutil/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-jose",
			ImportPackage: "jose",
			Provenance:    ProvenanceCurated,
			Source:        "python_jose-3.5.0-py2.py3-none-any.whl from pypi.org: sole top-level package jose/",
			Date:          importBindingTableDate,
		},
	}
}

// namespaceFixtureSource labels the synthetic pair explicitly as a fixture so the C5 reviewer
// spot-check reads it as such, not a real-world claim — while still satisfying the non-empty
// Source+Date test.
const namespaceFixtureSource = "synthetic PEP 420 fixture — no real namespace case in corpus (see 01-discovery-census.md §b)"

// NamespaceFixture returns the two synthetic curated distributions sharing one implicit PEP 420
// namespace root `acme` (D5): acme-foo→acme.foo and acme-bar→acme.bar. Neither contributes the
// bare root `acme` — it is reachable only as a dotted prefix of the leaves, which is what lets
// Reverse("acme") return both without either distribution owning the root exclusively (C3).
//
// This is a synthetic fixture (the corpus has no real namespace case); it is deliberately NOT
// part of CuratedContributions and never ships in the real curated table.
func NamespaceFixture() []Contribution {
	return []Contribution{
		{
			Distribution:  "acme-foo",
			ImportPackage: "acme.foo",
			Provenance:    ProvenanceCurated,
			Source:        namespaceFixtureSource,
			Date:          curatedTableDate,
		},
		{
			Distribution:  "acme-bar",
			ImportPackage: "acme.bar",
			Provenance:    ProvenanceCurated,
			Source:        namespaceFixtureSource,
			Date:          curatedTableDate,
		},
	}
}
