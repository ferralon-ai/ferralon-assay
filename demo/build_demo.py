#!/usr/bin/env python3
"""Build the Ferralon Assay demonstration snapshot: a full deduped advisory corpus plus a
few precomputed policy sub-corpora, each a real `-advisory-corpus` root the scanner loads.

This script CONSUMES the symbol-enrichment pass output (inert JSON) and the raw OSV export
(inert JSON) as read-only inputs. It never executes any enrichment `scripts/`, tooling, or
lifecycle code — it only reads/parses records. All outputs are written under demo/.

Determinism: record files are copied byte-verbatim from their source window; every manifest
`output_digest` is sha256 over those exact bytes; `corpus_digest` is sha256 over the compact
JSON of the per-record pins {identifier,path,output_digest} sorted by identifier.
"""
import json, os, glob, hashlib, shutil, collections
from datetime import datetime, timedelta

# --- inputs (read-only) -------------------------------------------------------------------
SRC = {
    "30d": "/Users/eric/Downloads/cve-enrichment-30d/symbol-pass/corpus/records",
    "60d": "/Users/eric/Downloads/cve-enrichment-60d/symbol-corpus/records",
    "90d": "/Users/eric/Downloads/cve-enrichment-90d/symbol-corpus/records",
}
RAW = ["/Users/eric/Downloads/cve-enrichment-90d/raw",
       "/Users/eric/Downloads/cve-enrichment-60d/raw"]
OUT = os.path.dirname(os.path.abspath(__file__))          # .../demo
CORPUS = os.path.join(OUT, "corpus")
POLICIES = os.path.join(OUT, "policies")

ECO2LANG = {"pypi": "python", "golang": "go", "npm": "javascript",
            "maven": "java", "nuget": "dotnet"}
TIER = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
SCHEMA = "ferralon.normalized_advisory.v3"

def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()
def parse(s):
    try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return None

# --- 1. dedup union, priority 30 > 60 > 90 ------------------------------------------------
union = {}  # vuln_id -> {"window","src_path"}
for w in ("30d", "60d", "90d"):
    for p in sorted(glob.glob(os.path.join(SRC[w], "CVE-*.json"))):
        vid = os.path.basename(p)[:-5]
        if vid not in union:
            union[vid] = {"window": w, "src": p}
print(f"union: {len(union)} records")

# --- 2. OSV date/severity lookup (inert raw JSON) -----------------------------------------
inv = {}   # cve -> inventory row (published/modified/osv_id/source_path)
for base in RAW:
    fp = os.path.join(base, "cve_inventory.jsonl")
    if not os.path.exists(fp): continue
    for line in open(fp):
        d = json.loads(line)
        for c in d.get("cves", []):
            if c not in inv:
                inv[c] = {"published": d.get("published"), "modified": d.get("modified"),
                          "osv_id": d.get("id"), "source_path": d.get("source_path"), "base": base}
def severity(cve):
    """Return (tier, cvss_vector). HONEST-ABSENT: (unspecified, None) when no label."""
    info = inv.get(cve)
    if not info: return ("unspecified", None)
    sp, base = info.get("source_path"), info.get("base")
    for b in [base] + RAW:
        fp = os.path.join(b, sp) if sp else None
        if fp and os.path.exists(fp):
            r = json.load(open(fp))
            label = (r.get("database_specific") or {}).get("severity")
            vec = None
            for s in (r.get("severity") or []):
                if str(s.get("type", "")).startswith("CVSS"): vec = s.get("score")
            return (TIER.get(label, "unspecified"), vec)
    return ("unspecified", None)

# --- 3. materialize full corpus (byte-verbatim copy) + index ------------------------------
if os.path.exists(CORPUS): shutil.rmtree(CORPUS)
if os.path.exists(POLICIES): shutil.rmtree(POLICIES)
recdir = os.path.join(CORPUS, "records")

meta = {}  # vuln_id -> full derived metadata (for index + policy filtering)
records_pins = []
for vid in sorted(union):
    info = union[vid]
    raw_bytes = open(info["src"], "rb").read()
    doc = json.loads(raw_bytes)
    purl = doc.get("purl", "")
    eco = purl.split("/")[0].replace("pkg:", "") if purl.startswith("pkg:") else ""
    lang = ECO2LANG.get(eco, "other")
    tier, vec = severity(vid)
    ov = inv.get(vid, {})
    pub, mod = ov.get("published"), ov.get("modified")
    has_sym = bool(doc.get("symbols"))
    relpath = f"records/{lang}/{vid}.json"
    dst = os.path.join(CORPUS, relpath)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f: f.write(raw_bytes)          # verbatim → digest is stable
    digest = sha(raw_bytes)
    records_pins.append({"identifier": vid, "path": relpath, "output_digest": digest})
    meta[vid] = {"vuln_id": vid, "ecosystem": eco, "language": lang,
                 "source_window": info["window"], "osv_id": ov.get("osv_id"),
                 "published": pub, "modified": mod, "cvss_vector": vec,
                 "severity_tier": tier, "has_symbols": has_sym,
                 "symbols": doc.get("symbols") or [], "path": relpath, "digest": digest}

def write_manifest(root, pins, mver="1.0.0"):
    pins = sorted(pins, key=lambda r: r["identifier"])
    body = json.dumps([[r["identifier"], r["path"], r["output_digest"]] for r in pins],
                      separators=(",", ":"))
    man = {"manifest_version": mver, "schema_version": SCHEMA,
           "record_count": len(pins), "records": pins, "corpus_digest": sha(body.encode())}
    with open(os.path.join(root, "manifest.json"), "w") as f:
        json.dump(man, f, indent=2); f.write("\n")
    return man["corpus_digest"]

cd = write_manifest(CORPUS, records_pins)
# provenance/derivation index
with open(os.path.join(CORPUS, "index.jsonl"), "w") as f:
    for vid in sorted(meta):
        m = dict(meta[vid]); m.pop("symbols", None)   # keep index compact; symbol list lives in the record
        f.write(json.dumps(m, separators=(",", ":")) + "\n")
print(f"full corpus: {len(records_pins)} records, corpus_digest={cd[:23]}…")

# --- 4. policy sub-corpora ----------------------------------------------------------------
t0 = max(parse(m["published"]) for m in meta.values() if m["published"])
WIN = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
       "60d": timedelta(days=60), "90d": timedelta(days=90), "snapshot": None}

def select(window=None, langs=None, tiers=None):
    out = []
    cut = (t0 - WIN[window]) if window and WIN[window] else None
    for vid, m in meta.items():
        if langs and m["language"] not in langs: continue
        if tiers and m["severity_tier"] not in tiers: continue
        if cut:
            pd = parse(m["published"])
            if not pd or pd < cut: continue
        out.append(vid)
    return sorted(out)

def emit_policy(name, vids, note):
    root = os.path.join(POLICIES, name)
    pins = []
    nsym = 0
    for vid in vids:
        m = meta[vid]
        raw_bytes = open(union[vid]["src"], "rb").read()
        rel = m["path"]                                    # same lang-partitioned layout
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f: f.write(raw_bytes)
        pins.append({"identifier": vid, "path": rel, "output_digest": m["digest"]})
        nsym += 1 if m["has_symbols"] else 0
    write_manifest(root, pins)
    open(os.path.join(root, "NOTE.md"), "w").write(note.strip() + "\n")
    langs = collections.Counter(meta[v]["language"] for v in vids)
    print(f"  policy {name:34} n={len(vids):4} symbols={nsym:4} langs={dict(langs)}")
    return len(vids), nsym

print("\n=== flagship candidate matrix (choose one that surfaces symbols, demo-sized) ===")
for w in ("snapshot", "90d", "60d"):
    for lg in ("python", "go"):
        for ts in (("critical",), ("high", "critical"), ("high", "critical", "medium")):
            v = select(window=w, langs={lg}, tiers=set(ts))
            ns = sum(1 for x in v if meta[x]["has_symbols"])
            print(f"  {w:8} {lg:7} {'+'.join(ts):22} n={len(v):4} symbols={ns:4}")

print("\n=== emitting policies ===")

t0iso = t0.isoformat()
HC = {"high", "critical"}
summary = []

def note(title, window, langs, tiers, extra=""):
    win = "the full snapshot (widest window)" if window == "snapshot" else f"the last {window}"
    langtxt = ", ".join(sorted(langs)) if langs else "all languages"
    tiertxt = "/".join(sorted(tiers)) if tiers else "all severities"
    return (f"# {title}\n\n"
            f"Precomputed `-advisory-corpus` root: advisories **published within {win}** of the "
            f"snapshot's latest data (t0 = {t0iso}), ecosystem = **{langtxt}**, severity = "
            f"**{tiertxt}**.\n\n"
            f"Severity is the OSV `database_specific.severity` label; records without one are "
            f"`unspecified` and are excluded from a severity-scoped policy rather than guessed. "
            f"Windows key on the advisory's OSV **published** date.\n{extra}")

specs = [
    ("last-24h-all-high-critical",   "24h", None,          HC,
     "\nFreshest slice. Recently-published advisories are not yet symbol-enriched, so this policy "
     "is expected to carry **no** symbol-bearing records — reachability has nothing to resolve here "
     "yet, by design of the snapshot."),
    ("last-7d-javascript-high-critical", "7d", {"javascript"}, HC,
     "\nLanguage-scoped recent slice (npm advisories dominate the freshest windows)."),
    ("last-30d-python-high-critical", "30d", {"python"},    HC, ""),
    ("last-90d-go-high-critical",     "90d", {"go"},        HC,
     "\n**This is the policy the top-level README demonstrates.** Go carries the deepest analyzer, "
     "and this slice provably surfaces symbol-bearing advisories, so a scan against it exercises the "
     "reachability stage rather than stopping at the version axis."),
    ("last-90d-python-high-critical", "90d", {"python"},    HC,
     "\nPython companion to the Go flagship; also carries symbol-bearing records."),
    ("last-60d-java-high-critical",   "60d", {"java"},      HC,
     "\nJava (Maven) advisories **are** present in the corpus, but the symbol-enrichment pass "
     "extracted essentially no Java symbols — so this policy scans on the version axis only "
     "(`undetermined` rather than a reachability verdict). It is committed to show the language is "
     "covered, not omitted."),
    ("last-60d-dotnet-high-critical", "60d", {"dotnet"},    HC,
     "\n.NET (NuGet) advisories are present but symbol-less, same as Java above — committed for "
     "coverage, honest about carrying no reachability signal."),
]

flagship = None
for name, win, langs, tiers, extra in specs:
    vids = select(window=win, langs=langs, tiers=tiers)
    title = name.replace("-", " ")
    n, ns = emit_policy(name, vids, note(title, win, langs, tiers, extra))
    summary.append({"name": name, "window": win,
                    "languages": sorted(langs) if langs else "all",
                    "tiers": sorted(tiers), "records": n, "symbol_bearing": ns})
    if name == "last-90d-go-high-critical":
        flagship = summary[-1]

with open(os.path.join(POLICIES, "policies.json"), "w") as f:
    json.dump({"t0_latest_published": t0iso, "flagship": "last-90d-go-high-critical",
               "policies": summary}, f, indent=2); f.write("\n")

assert flagship and flagship["symbol_bearing"] > 0, "flagship must surface symbol-bearing records"
print(f"\nflagship {flagship['name']}: {flagship['records']} records, "
      f"{flagship['symbol_bearing']} symbol-bearing — OK")

