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

// pypiBindingTableDate is the RFC 3339 (full-date) date the PyPI import-binding rows were taken: one row per
// distribution whose import name is not its own, each citing the wheel (or, where none is published, the sdist or egg)
// whose top-level entries were listed. For each such name, PyPI's project list was searched by that name and two
// further kinds of shipper were added: the distribution named after the import, where its newest release really ships
// it, and three distributions named during review (graphql-core-next, taming-transformers, flash-linear-attention).
// That list is not exhaustive (forks of popular libraries also ship these names), so a name with one row here still
// decides on its own, as any single curated shipper does.
const pypiBindingTableDate = "2026-11-11"

// CuratedContributions returns the inline curated rows, each with a cited Source + Date (C5).
// Distribution names are PEP 503-normalized. The result is NOT yet canonicalized; feed it
// (with the declared/unknown contributions) through NewDistImportMap.
//
// The import-binding rows (dated importBindingTableDate, each citing the wheel whose
// top-level entries were listed) cover distributions whose import name is not their
// distribution name, so a call through `import jwt` / `import yaml` names the right
// distribution — the PEP 503 fallback cannot ("jwt" never equals "pyjwt").
//
// The identity rows (flask, jinja2, markupsafe, aiohttp, pydantic, and the same-named co-shippers
// among the PyPI binding rows, such as environ and fpdf) still carry a real cited Source —
// the curated label on flask→flask is a claim that cites where the import name was confirmed,
// not an assumption the type launders into a fact (discovery, load-bearing finding §2).
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
			Distribution:  "apache-airflow-core",
			ImportPackage: "airflow",
			Provenance:    ProvenanceCurated,
			Source:        "apache_airflow_core-3.3.2-py3-none-any.whl from pypi.org: RECORD sole top-level package airflow/ (has __init__.py, no airflow/sdk/); ships the same import package as apache-airflow 2.x, while the apache-airflow 3.3.2 wheel ships no package at all",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "apache-airflow-task-sdk",
			ImportPackage: "airflow.sdk",
			Provenance:    ProvenanceCurated,
			Source:        "apache_airflow_task_sdk-1.3.2-py3-none-any.whl from pypi.org: RECORD ships only airflow/sdk/ (has __init__.py), with no airflow/__init__.py; apache-airflow-core ships no airflow/sdk/",
			Date:          importBindingTableDate,
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
			Distribution:  "jwt",
			ImportPackage: "jwt",
			Provenance:    ProvenanceCurated,
			Source:        "jwt-1.4.0-py3-none-any.whl from pypi.org: sole top-level package jwt/ (RECORD, top_level.txt); ships the same import package as pyjwt",
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
			Distribution:  "pillow-simd",
			ImportPackage: "PIL",
			Provenance:    ProvenanceCurated,
			Source:        "pillow_simd-12.1.1.post0.tar.gz from pypi.org (the project publishes no wheels): pyproject.toml [tool.setuptools] packages = [\"PIL\"] with package-dir src, and src/PIL/__init__.py; ships the same import package as pillow",
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
			Distribution:  "py-dateutil",
			ImportPackage: "dateutil",
			Provenance:    ProvenanceCurated,
			Source:        "py-dateutil-2.2.tar.gz from pypi.org (the project publishes no wheels): setup.py packages = [\"dateutil\", \"dateutil.zoneinfo\"], egg-info top_level.txt dateutil; ships the same import package as python-dateutil",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-jose",
			ImportPackage: "jose",
			Provenance:    ProvenanceCurated,
			Source:        "python_jose-3.5.0-py2.py3-none-any.whl from pypi.org: sole top-level package jose/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-jose-cryptodome",
			ImportPackage: "jose",
			Provenance:    ProvenanceCurated,
			Source:        "python_jose_cryptodome-1.3.2-py2.py3-none-any.whl from pypi.org: RECORD sole top-level package jose/; ships the same import package as python-jose",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "jose",
			ImportPackage: "jose",
			Provenance:    ProvenanceCurated,
			Source:        "jose-1.0.0.tar.gz from pypi.org (the project publishes no wheels): setup.py py_modules=['jose'], egg-info top_level.txt jose, top-level module jose.py; ships the same import name as python-jose",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-dotenv",
			ImportPackage: "dotenv",
			Provenance:    ProvenanceCurated,
			Source:        "python_dotenv-1.2.4-py3-none-any.whl from pypi.org: sole top-level package dotenv/ (RECORD, top_level.txt)",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "python-dotenv-yaml",
			ImportPackage: "dotenv",
			Provenance:    ProvenanceCurated,
			Source:        "python_dotenv_yaml-0.17.1-py2.py3-none-any.whl from pypi.org: RECORD top-level package dotenv/ (has __init__.py); ships the same import package as python-dotenv",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "django-dotenv",
			ImportPackage: "dotenv",
			Provenance:    ProvenanceCurated,
			Source:        "django_dotenv-1.4.2-py2.py3-none-any.whl from pypi.org: RECORD top-level module dotenv.py, top_level.txt dotenv; ships the same import name as python-dotenv",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "teams-ai",
			ImportPackage: "teams",
			Provenance:    ProvenanceCurated,
			Source:        "teams_ai-1.8.2-py3-none-any.whl from pypi.org: RECORD top-level packages teams/ and tests/ (no top_level.txt); only teams/ is mapped, since tests/ is a name projects commonly use for their own code",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "teams-ai-azml-model",
			ImportPackage: "teams",
			Provenance:    ProvenanceCurated,
			Source:        "teams_ai_azml_model-1.0.2-py3-none-any.whl from pypi.org: RECORD top-level packages teams/ (has __init__.py) and tests/; only teams/ is mapped; ships the same import package as teams-ai",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "teams",
			ImportPackage: "teams",
			Provenance:    ProvenanceCurated,
			Source:        "teams-0.1.0-py3-none-any.whl from pypi.org: RECORD sole top-level package teams/ (has __init__.py); ships the same import package as teams-ai",
			Date:          importBindingTableDate,
		},
		// azure and botframework are PEP 420 namespaces shared by several distributions, so
		// each row names the package its wheel ships; distsFor takes the longest one on an
		// import path, and the bare root names none.
		{
			Distribution:  "azure-core",
			ImportPackage: "azure.core",
			Provenance:    ProvenanceCurated,
			Source:        "azure_core-1.41.0-py3-none-any.whl from pypi.org: RECORD top-level azure/ with no azure/__init__.py (namespace); package azure/core/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-core-experimental",
			ImportPackage: "azure.core.experimental",
			Provenance:    ProvenanceCurated,
			Source:        "azure_core_experimental-1.0.0b4-py3-none-any.whl from pypi.org: RECORD package azure/core/experimental/ with no azure/__init__.py or azure/core/__init__.py; azure-core ships no azure/core/experimental/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-core-tracing-opentelemetry",
			ImportPackage: "azure.core.tracing.ext.opentelemetry_span",
			Provenance:    ProvenanceCurated,
			Source:        "azure_core_tracing_opentelemetry-1.0.0b13-py3-none-any.whl from pypi.org: RECORD package azure/core/tracing/ext/opentelemetry_span/ and nothing above it; azure-core ships azure/core/tracing/ext/__init__.py but no opentelemetry_span/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-core-tracing-opencensus",
			ImportPackage: "azure.core.tracing.ext.opencensus_span",
			Provenance:    ProvenanceCurated,
			Source:        "azure_core_tracing_opencensus-1.0.0b10-py3-none-any.whl from pypi.org: RECORD package azure/core/tracing/ext/opencensus_span/ and nothing above it; azure-core ships no opencensus_span/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-identity",
			ImportPackage: "azure.identity",
			Provenance:    ProvenanceCurated,
			Source:        "azure_identity-1.26.0-py3-none-any.whl from pypi.org: RECORD top-level azure/ with no azure/__init__.py (namespace); package azure/identity/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-identity-broker",
			ImportPackage: "azure.identity.broker",
			Provenance:    ProvenanceCurated,
			Source:        "azure_identity_broker-1.3.0-py3-none-any.whl from pypi.org: RECORD package azure/identity/broker/ with no azure/identity/__init__.py; azure-identity ships no azure/identity/broker/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "azure-search-documents",
			ImportPackage: "azure.search.documents",
			Provenance:    ProvenanceCurated,
			Source:        "azure_search_documents-12.0.0-py3-none-any.whl from pypi.org: RECORD top-level azure/ with no azure/__init__.py (namespace); package azure/search/documents/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "botframework-connector",
			ImportPackage: "botframework.connector",
			Provenance:    ProvenanceCurated,
			Source:        "botframework_connector-4.17.1-py2.py3-none-any.whl from pypi.org: RECORD top-level botframework/ with no botframework/__init__.py (namespace); package botframework/connector/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "botframework-streaming",
			ImportPackage: "botframework.streaming",
			Provenance:    ProvenanceCurated,
			Source:        "botframework_streaming-4.17.1-py3-none-any.whl from pypi.org: RECORD top-level botframework/ with no botframework/__init__.py (namespace); package botframework/streaming/",
			Date:          importBindingTableDate,
		},
		{
			Distribution:  "django-allauth",
			ImportPackage: "allauth",
			Provenance:    ProvenanceCurated,
			Source:        "django_allauth-65.21.1-py3-none-any.whl from pypi.org: top_level.txt lists only allauth",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "argon2",
			ImportPackage: "argon2",
			Provenance:    ProvenanceCurated,
			Source:        "argon2-0.1.10.tar.gz from pypi.org: the sdist (no wheel published) ships top-level argon2",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "argon2-cffi",
			ImportPackage: "argon2",
			Provenance:    ProvenanceCurated,
			Source:        "argon2_cffi-25.1.0-py3-none-any.whl from pypi.org: RECORD sole top-level package argon2/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "python-bidi",
			ImportPackage: "bidi",
			Provenance:    ProvenanceCurated,
			Source:        "python_bidi-0.6.12-cp310-cp310-macosx_10_12_x86_64.whl from pypi.org: RECORD sole top-level package bidi/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "biopython",
			ImportPackage: "Bio",
			Provenance:    ProvenanceCurated,
			Source:        "biopython-1.88-cp310-cp310-macosx_11_0_arm64.whl from pypi.org: top_level.txt lists Bio, BioSQL",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-braces",
			ImportPackage: "braces",
			Provenance:    ProvenanceCurated,
			Source:        "django_braces-1.17.0-py3-none-any.whl from pypi.org: top_level.txt lists only braces",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "causal-conv1d",
			ImportPackage: "causal_conv1d_cuda",
			Provenance:    ProvenanceCurated,
			Source:        "causal_conv1d-1.7.0.tar.gz from pypi.org (no wheel published): setup.py builds causal_conv1d_cuda",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pycrypto",
			ImportPackage: "Crypto",
			Provenance:    ProvenanceCurated,
			Source:        "pycrypto-2.6.1.tar.gz from pypi.org (no wheel published): setup.py builds Crypto.Cipher._AES and 18 more Crypto.* extension modules",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pycryptodome",
			ImportPackage: "Crypto",
			Provenance:    ProvenanceCurated,
			Source:        "pycryptodome-4.4.0-cp315-cp315t-macosx_10_15_universal2.whl from pypi.org: top_level.txt lists only Crypto",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pycryptodomex",
			ImportPackage: "Cryptodome",
			Provenance:    ProvenanceCurated,
			Source:        "pycryptodomex-3.24.2-cp27-cp27m-manylinux2010_i686.whl from pypi.org: top_level.txt lists only Cryptodome",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "cupy",
			ImportPackage: "cupy",
			Provenance:    ProvenanceCurated,
			Source:        "cupy-14.2.0.tar.gz from pypi.org: the sdist (no wheel published) ships top-level cupy",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "cupy-cuda12x",
			ImportPackage: "cupy",
			Provenance:    ProvenanceCurated,
			Source:        "cupy_cuda12x-14.2.0-cp310-cp310-manylinux2014_aarch64.whl from pypi.org: top_level.txt lists cupy, cupy_backends, cupyx",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "cupy-cuda13x",
			ImportPackage: "cupy",
			Provenance:    ProvenanceCurated,
			Source:        "cupy_cuda13x-14.2.0-cp310-cp310-manylinux2014_aarch64.whl from pypi.org: top_level.txt lists cupy, cupy_backends, cupyx",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "opencv-contrib-python",
			ImportPackage: "cv2",
			Provenance:    ProvenanceCurated,
			Source:        "opencv_contrib_python-5.0.0.93-cp37-abi3-macosx_13_0_arm64.whl from pypi.org: top_level.txt lists only cv2",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "opencv-contrib-python-headless",
			ImportPackage: "cv2",
			Provenance:    ProvenanceCurated,
			Source:        "opencv_contrib_python_headless-5.0.0.93-cp37-abi3-macosx_13_0_arm64.whl from pypi.org: top_level.txt lists only cv2",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "opencv-python",
			ImportPackage: "cv2",
			Provenance:    ProvenanceCurated,
			Source:        "opencv_python-5.0.0.93-cp37-abi3-macosx_13_0_arm64.whl from pypi.org: top_level.txt lists only cv2",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "opencv-python-headless",
			ImportPackage: "cv2",
			Provenance:    ProvenanceCurated,
			Source:        "opencv_python_headless-5.0.0.93-cp37-abi3-macosx_13_0_arm64.whl from pypi.org: top_level.txt lists only cv2",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "dac",
			ImportPackage: "dac",
			Provenance:    ProvenanceCurated,
			Source:        "dac-0.4.3-py3-none-any.whl from pypi.org: top_level.txt lists only dac",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "descript-audio-codec",
			ImportPackage: "dac",
			Provenance:    ProvenanceCurated,
			Source:        "descript_audio_codec-1.0.0-py3-none-any.whl from pypi.org: top_level.txt lists dac, tests",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "dal",
			ImportPackage: "dal",
			Provenance:    ProvenanceCurated,
			Source:        "dal-0.2-py2.4.egg from pypi.org: the egg (no wheel published) ships top-level dal",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-autocomplete-light",
			ImportPackage: "dal",
			Provenance:    ProvenanceCurated,
			Source:        "django_autocomplete_light-5.0.0-py3-none-any.whl from pypi.org: top_level.txt lists dal, dal_alight, dal_alight_queryset_sequence, dal_contenttypes, dal_queryset_sequence, dal_select2, dal_select2_queryset_sequence, dal_select2_taggit",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "dbus-python",
			ImportPackage: "dbus",
			Provenance:    ProvenanceCurated,
			Source:        "dbus_python-1.5.1.tar.gz from pypi.org (no wheel published): the sdist lays out package dbus/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-filter",
			ImportPackage: "django_filters",
			Provenance:    ProvenanceCurated,
			Source:        "django_filter-26.2-py3-none-any.whl from pypi.org: RECORD sole top-level package django_filters/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-environ",
			ImportPackage: "environ",
			Provenance:    ProvenanceCurated,
			Source:        "django_environ-0.14.0-py3-none-any.whl from pypi.org: top_level.txt lists only environ",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "environ",
			ImportPackage: "environ",
			Provenance:    ProvenanceCurated,
			Source:        "environ-1.0.tar.gz from pypi.org: the sdist (no wheel published) ships top-level environ",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fairseq",
			ImportPackage: "fairseq",
			Provenance:    ProvenanceCurated,
			Source:        "fairseq-0.12.2-cp36-cp36m-macosx_10_9_x86_64.whl from pypi.org: top_level.txt lists fairseq, fairseq_cli",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fairseq-fixed",
			ImportPackage: "fairseq",
			Provenance:    ProvenanceCurated,
			Source:        "fairseq_fixed-0.12.3.1-cp312-cp312-manylinux_2_28_x86_64.whl from pypi.org: top_level.txt lists alignment_train_cpu_binding, fairseq, fairseq_cli",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fitz",
			ImportPackage: "fitz",
			Provenance:    ProvenanceCurated,
			Source:        "fitz-0.0.0.tar.gz from pypi.org: the sdist (no wheel published) ships top-level fitz",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pymupdf",
			ImportPackage: "fitz",
			Provenance:    ProvenanceCurated,
			Source:        "pymupdf-2.1-cp311-abi3-macosx_11_0_arm64.whl from pypi.org: RECORD top-level entries fitz/, pymupdf/, pymupdf4llm/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fla-core",
			ImportPackage: "fla",
			Provenance:    ProvenanceCurated,
			Source:        "fla_core-0.6.0-py3-none-any.whl from pypi.org: top_level.txt lists only fla",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "flash-linear-attention",
			ImportPackage: "fla.layers",
			Provenance:    ProvenanceCurated,
			Source:        "flash_linear_attention-0.6.0-py3-none-any.whl from pypi.org: ships fla/layers/ with no fla/__init__.py (a portion of another distribution's fla package; packages fla/layers/, fla/models/)",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "flash-linear-attention",
			ImportPackage: "fla.models",
			Provenance:    ProvenanceCurated,
			Source:        "flash_linear_attention-0.6.0-py3-none-any.whl from pypi.org: ships fla/models/ with no fla/__init__.py (a portion of another distribution's fla package; packages fla/layers/, fla/models/)",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fpdf",
			ImportPackage: "fpdf",
			Provenance:    ProvenanceCurated,
			Source:        "fpdf-1.7.2.tar.gz from pypi.org: the sdist (no wheel published) ships top-level fpdf",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "fpdf2",
			ImportPackage: "fpdf",
			Provenance:    ProvenanceCurated,
			Source:        "fpdf2-2.9.0-py3-none-any.whl from pypi.org: top_level.txt lists only fpdf",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "funcodec",
			ImportPackage: "funcodec",
			Provenance:    ProvenanceCurated,
			Source:        "funcodec-0.2.0-py3-none-any.whl from pypi.org: top_level.txt lists only funcodec",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "ms-funcodec",
			ImportPackage: "funcodec",
			Provenance:    ProvenanceCurated,
			Source:        "ms_funcodec-0.2.0-py3-none-any.whl from pypi.org: top_level.txt lists only funcodec",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pygobject",
			ImportPackage: "gi",
			Provenance:    ProvenanceCurated,
			Source:        "pygobject-3.58.1.tar.gz from pypi.org (no wheel published): the sdist lays out package gi/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "github",
			ImportPackage: "github",
			Provenance:    ProvenanceCurated,
			Source:        "github-1.2.7-py3-none-any.whl from pypi.org: top_level.txt lists only github",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pygithub",
			ImportPackage: "github",
			Provenance:    ProvenanceCurated,
			Source:        "pygithub-2.10.0-py3-none-any.whl from pypi.org: top_level.txt lists only github",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "google-api-python-client",
			ImportPackage: "googleapiclient",
			Provenance:    ProvenanceCurated,
			Source:        "google_api_python_client-2.202.0-py3-none-any.whl from pypi.org: top_level.txt lists apiclient, googleapiclient",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "graphql",
			ImportPackage: "graphql",
			Provenance:    ProvenanceCurated,
			Source:        "graphql-0.0.4.tar.gz from pypi.org: the sdist (no wheel published) ships top-level graphql",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "graphql-core",
			ImportPackage: "graphql",
			Provenance:    ProvenanceCurated,
			Source:        "graphql_core-3.3.2-py3-none-any.whl from pypi.org: RECORD sole top-level package graphql/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "graphql-core-next",
			ImportPackage: "graphql",
			Provenance:    ProvenanceCurated,
			Source:        "GraphQL_core_next-1.1.1-py3-none-any.whl from pypi.org: the wheel ships top-level graphql",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "ignite",
			ImportPackage: "ignite",
			Provenance:    ProvenanceCurated,
			Source:        "ignite-1.1.0-py2.py3-none-any.whl from pypi.org: top_level.txt lists only ignite",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pytorch-ignite",
			ImportPackage: "ignite",
			Provenance:    ProvenanceCurated,
			Source:        "pytorch_ignite-0.5.5-py3-none-any.whl from pypi.org: RECORD sole top-level package ignite/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-import-export",
			ImportPackage: "import_export",
			Provenance:    ProvenanceCurated,
			Source:        "django_import_export-4.4.5-py3-none-any.whl from pypi.org: top_level.txt lists only import_export",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "python-xmp-toolkit",
			ImportPackage: "libxmp",
			Provenance:    ProvenanceCurated,
			Source:        "python_xmp_toolkit-2.1.0-py2.py3-none-any.whl from pypi.org: RECORD sole top-level package libxmp/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "lightrag",
			ImportPackage: "lightrag",
			Provenance:    ProvenanceCurated,
			Source:        "lightrag-0.1.0b6-py3-none-any.whl from pypi.org: RECORD sole top-level package lightrag/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "lightrag-hku",
			ImportPackage: "lightrag",
			Provenance:    ProvenanceCurated,
			Source:        "lightrag_hku-1.5.7-py3-none-any.whl from pypi.org: top_level.txt lists lightrag, lightrag_webui",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "mcubes",
			ImportPackage: "mcubes",
			Provenance:    ProvenanceCurated,
			Source:        "mcubes-0.1.6-cp310-abi3-macosx_10_12_x86_64.whl from pypi.org: RECORD sole top-level package mcubes/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pymcubes",
			ImportPackage: "mcubes",
			Provenance:    ProvenanceCurated,
			Source:        "PyMCubes-0.1.6-cp310-cp310-macosx_10_9_x86_64.whl from pypi.org: top_level.txt lists only mcubes",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "mmseg",
			ImportPackage: "mmseg",
			Provenance:    ProvenanceCurated,
			Source:        "mmseg-1.3.0.tar.gz from pypi.org: the sdist (no wheel published) ships top-level mmseg",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "mmsegmentation",
			ImportPackage: "mmseg",
			Provenance:    ProvenanceCurated,
			Source:        "mmsegmentation-1.2.2-py3-none-any.whl from pypi.org: top_level.txt lists mmseg, tests",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-modeltranslation",
			ImportPackage: "modeltranslation",
			Provenance:    ProvenanceCurated,
			Source:        "django_modeltranslation-0.20.6-py3-none-any.whl from pypi.org: RECORD sole top-level package modeltranslation/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "modeltranslation",
			ImportPackage: "modeltranslation",
			Provenance:    ProvenanceCurated,
			Source:        "modeltranslation-0.25.tar.gz from pypi.org: the sdist (no wheel published) ships top-level modeltranslation",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pynrrd",
			ImportPackage: "nrrd",
			Provenance:    ProvenanceCurated,
			Source:        "pynrrd-1.1.3-py3-none-any.whl from pypi.org: top_level.txt lists docs, nrrd",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "open-clip-torch",
			ImportPackage: "open_clip",
			Provenance:    ProvenanceCurated,
			Source:        "open_clip_torch-4.2.2-py3-none-any.whl from pypi.org: RECORD top-level entries open_clip/, open_clip_train/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pdfminer",
			ImportPackage: "pdfminer",
			Provenance:    ProvenanceCurated,
			Source:        "pdfminer-20191125.tar.gz from pypi.org: the sdist (no wheel published) ships top-level pdfminer",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pdfminer-six",
			ImportPackage: "pdfminer",
			Provenance:    ProvenanceCurated,
			Source:        "pdfminer_six-20260107-py3-none-any.whl from pypi.org: top_level.txt lists only pdfminer",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "progressbar",
			ImportPackage: "progressbar",
			Provenance:    ProvenanceCurated,
			Source:        "progressbar-2.5.tar.gz from pypi.org: the sdist (no wheel published) ships top-level progressbar",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "progressbar2",
			ImportPackage: "progressbar",
			Provenance:    ProvenanceCurated,
			Source:        "progressbar2-4.7.0-py3-none-any.whl from pypi.org: top_level.txt lists only progressbar",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "progressbar33",
			ImportPackage: "progressbar",
			Provenance:    ProvenanceCurated,
			Source:        "progressbar33-2.4.tar.gz from pypi.org (no wheel published): the sdist lays out package progressbar/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "djangorestframework",
			ImportPackage: "rest_framework",
			Provenance:    ProvenanceCurated,
			Source:        "djangorestframework-3.18.3-py3-none-any.whl from pypi.org: top_level.txt lists only rest_framework",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "scikit-image",
			ImportPackage: "skimage",
			Provenance:    ProvenanceCurated,
			Source:        "scikit_image-0.26.0-cp311-cp311-macosx_10_9_x86_64.whl from pypi.org: RECORD sole top-level package skimage/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "scikit-learn",
			ImportPackage: "sklearn",
			Provenance:    ProvenanceCurated,
			Source:        "scikit_learn-1.9.1-cp311-cp311-macosx_10_9_x86_64.whl from pypi.org: RECORD sole top-level package sklearn/",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "django-suit",
			ImportPackage: "suit",
			Provenance:    ProvenanceCurated,
			Source:        "django_suit-0.2.28-py2.py3-none-any.whl from pypi.org: top_level.txt lists only suit",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "suit",
			ImportPackage: "suit",
			Provenance:    ProvenanceCurated,
			Source:        "suit-2.0.2-py2.6.egg from pypi.org: the egg (no wheel published) ships top-level suit",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "swe-rex",
			ImportPackage: "swerex",
			Provenance:    ProvenanceCurated,
			Source:        "swe_rex-1.4.0-py3-none-any.whl from pypi.org: top_level.txt lists only swerex",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "taming-transformers",
			ImportPackage: "taming",
			Provenance:    ProvenanceCurated,
			Source:        "taming_transformers-0.0.1-py3-none-any.whl from pypi.org: the wheel ships top-level taming",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "taming-transformers-rom1504",
			ImportPackage: "taming",
			Provenance:    ProvenanceCurated,
			Source:        "taming_transformers_rom1504-0.0.6-py3-none-any.whl from pypi.org: top_level.txt lists only taming",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "umap-learn",
			ImportPackage: "umap",
			Provenance:    ProvenanceCurated,
			Source:        "umap_learn-0.6.0-py3-none-any.whl from pypi.org: top_level.txt lists only umap",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "google-cloud-aiplatform",
			ImportPackage: "vertexai",
			Provenance:    ProvenanceCurated,
			Source:        "google_cloud_aiplatform-2.8.0-py2.py3-none-any.whl from pypi.org: top_level.txt lists agentplatform, google, vertex_ray, vertexai",
			Date:          pypiBindingTableDate,
		},
		{
			Distribution:  "pyzmq",
			ImportPackage: "zmq",
			Provenance:    ProvenanceCurated,
			Source:        "pyzmq-27.3.0-cp310-cp310-macosx_10_15_universal2.whl from pypi.org: RECORD sole top-level package zmq/",
			Date:          pypiBindingTableDate,
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
