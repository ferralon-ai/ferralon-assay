// advisory_source_roundtrip_test.go
//
// The cross-repo contract proof. advisory_source.go declares the wire shape; this file is the
// SHARED GOLDEN FIXTURE half of that contract — it vendors a real emitted Log4Shell corpus
// verbatim, exactly as an upstream producer wrote it, and proves three things over it:
//
//  1. Roundtrip — artifactSource.Lookup over the vendored corpus returns real, correctly-shaped
//     AdvisoryFacts (not just the hand-rolled testdata in advisory_source_test.go).
//  2. Invariant — the RAW vendored JSON bytes never carry a severity/CVSS/EPSS/KEV/prioritization
//     field. Those live on a signals plane the engine deliberately does not read.
//  3. Drift alarm — the vendored bytes are hash-pinned; a silent re-vendor that changes the
//     emitter's output shape must fail this test loudly, forcing a CONSCIOUS re-vendor.
//
// The vendored corpus lives at testdata/ferralon-corpus/ and was copied byte-for-byte from the
// producer's golden fixture. Do NOT hand-edit or reformat those files — re-vendor from a fresh
// producer emit and update the digests below in the same commit.
//
// The current bytes track the producer's poc_signal object shape {available,references,source}
// (it was once a bare bool) and its narrative under `root_cause` (it was once `summary`); both
// older spellings are still decoded, which is why the union decoder in advisory_source.go exists.
//
// CVE-2023-39325 (HTTP/2 rapid reset) is the v3 fixture: a TWO-PACKAGE advisory carrying an
// `affected_packages[]` array (golang.org/x/net gomod fixed v0.17.0, the scalar primary; and the Go
// stdlib/toolchain, go-toolchain scheme, backported go1.20.10 / go1.21.3). It is the shared
// byte-pin — a conforming producer emits it byte-identically, so if both sides conform no live
// cross-repo run is needed. This reader is the source of truth for its shape.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ferralonCorpusRoot is the vendored golden corpus emitted by intel's `enrich-cve --emit-advisory`
// (contract §6). It is a real cross-repo artifact, not hand-rolled testdata.
const ferralonCorpusRoot = "testdata/ferralon-corpus"

// --- 1. Roundtrip -----------------------------------------------------------------------------

// TestArtifactSource_FerralonCorpusRoundtrip proves the seam end-to-end over REAL bytes emitted by
// intel: artifactSource.Lookup("CVE-2021-44228") against the vendored corpus must return the exact
// facts the golden document carries. Values are asserted explicitly where the golden doc pins them
// (contract §6); this is not a mere non-emptiness check.
func TestArtifactSource_FerralonCorpusRoundtrip(t *testing.T) {
	src := artifactSource{root: ferralonCorpusRoot}
	facts, ok := src.Lookup("CVE-2021-44228")
	if !ok {
		t.Fatal(`Lookup("CVE-2021-44228") ok=false, want true — vendored intel corpus must load`)
	}

	if facts.SinkKind != "code_execution" {
		t.Errorf("SinkKind = %q, want code_execution", facts.SinkKind)
	}
	if len(facts.CWEs) != 1 || facts.CWEs[0] != "CWE-502" {
		t.Errorf("CWEs = %v, want [CWE-502]", facts.CWEs)
	}
	if len(facts.AffectedRanges) == 0 {
		t.Error("AffectedRanges is empty, want non-empty (golden doc carries 3 ranges)")
	}
	if facts.Provenance.TrustTier != TrustFirstParty {
		t.Errorf("Provenance.TrustTier = %q, want first_party", facts.Provenance.TrustTier)
	}

	// Exact values from the golden document (intel fixtures/ferralon-corpus/2021/12/CVE-2021-44228.json)
	// — asserted precisely since they are known, not just "present".
	if facts.Coordinate != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("Coordinate = %q, want org.apache.logging.log4j:log4j-core", facts.Coordinate)
	}
	if facts.Module != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("Module = %q, want org.apache.logging.log4j:log4j-core", facts.Module)
	}
	if facts.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core" {
		t.Errorf("PURL = %q, want pkg:maven/org.apache.logging.log4j/log4j-core", facts.PURL)
	}
	if facts.VersionScheme != "maven" {
		t.Errorf("VersionScheme = %q, want maven", facts.VersionScheme)
	}
	if len(facts.Aliases) != 1 || facts.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("Aliases = %v, want [GHSA-jfh8-c2jp-5v3q]", facts.Aliases)
	}
	if !facts.PocSignal {
		t.Error("PocSignal = false, want true")
	}
	// Summary decodes from intel's `root_cause` key (not `summary`); the golden narrative opens with
	// the CWE-502 gloss.
	if !strings.HasPrefix(facts.Summary, "Deserialization of Untrusted Data (CWE-502)") {
		t.Errorf("Summary = %q, want the root_cause narrative (decode failed on the wrong key?)", facts.Summary)
	}
	if facts.Lineage.RefixedBy != "CVE-2021-45046" {
		t.Errorf("Lineage.RefixedBy = %q, want CVE-2021-45046", facts.Lineage.RefixedBy)
	}
	if facts.Lineage.IncompleteFixOf != "" {
		t.Errorf("Lineage.IncompleteFixOf = %q, want empty (honest-empty, not incomplete-fix lineage)", facts.Lineage.IncompleteFixOf)
	}
	if len(facts.AffectedRanges) != 3 {
		t.Fatalf("AffectedRanges has %d entries, want 3", len(facts.AffectedRanges))
	}
	wantRanges := []Range{
		{Introduced: "2.0-beta9", Fixed: "2.3.1", FixedVersion: "2.3.1"},
		{Introduced: "2.13.0", Fixed: "2.15.0", FixedVersion: "2.15.0"},
		{Introduced: "2.4", Fixed: "2.12.2", FixedVersion: "2.12.2"},
	}
	for i, want := range wantRanges {
		if facts.AffectedRanges[i] != want {
			t.Errorf("AffectedRanges[%d] = %+v, want %+v", i, facts.AffectedRanges[i], want)
		}
	}
	// Honest-empty: the golden doc is a multi-range set, so the top-level UpperExclusive/
	// FixedVersion must stay empty — never collapsed from the range set (contract §2).
	if facts.UpperExclusive != "" {
		t.Errorf("UpperExclusive = %q, want empty (multi-range set, honest-empty per contract §2)", facts.UpperExclusive)
	}
	if facts.FixedVersion != "" {
		t.Errorf("FixedVersion = %q, want empty (multi-range set, honest-empty per contract §2)", facts.FixedVersion)
	}
}

// TestArtifactSource_FerralonCorpus_MultiPackage proves the v3 multi-package fixture roundtrips:
// artifactSource.Lookup("CVE-2023-39325") over the vendored corpus carries BOTH affected packages
// through toFacts, while the scalar-lift (v2 back-compat fields) still yields the primary
// (golang.org/x/net). This is the reader half of the shared cross-repo byte-pin (contract §5/§6).
func TestArtifactSource_FerralonCorpus_MultiPackage(t *testing.T) {
	src := artifactSource{root: ferralonCorpusRoot}
	facts, ok := src.Lookup("CVE-2023-39325")
	if !ok {
		t.Fatal(`Lookup("CVE-2023-39325") ok=false, want true — the v3 multi-package fixture must load`)
	}

	// Scalar-lift (v2 back-compat) yields the primary package, golang.org/x/net.
	if facts.Module != "golang.org/x/net" {
		t.Errorf("scalar Module = %q, want golang.org/x/net (primary)", facts.Module)
	}
	if facts.VersionScheme != "gomod" {
		t.Errorf("scalar VersionScheme = %q, want gomod", facts.VersionScheme)
	}
	if facts.PURL != "pkg:golang/golang.org/x/net" {
		t.Errorf("scalar PURL = %q, want pkg:golang/golang.org/x/net", facts.PURL)
	}
	if facts.FixedVersion != "v0.17.0" {
		t.Errorf("scalar FixedVersion = %q, want v0.17.0", facts.FixedVersion)
	}
	if len(facts.AffectedRanges) != 1 || facts.AffectedRanges[0] != (Range{Fixed: "v0.17.0", FixedVersion: "v0.17.0"}) {
		t.Errorf("scalar AffectedRanges = %+v, want one {Fixed:v0.17.0}", facts.AffectedRanges)
	}

	// The v3 affected_packages[] carries BOTH packages, primary first.
	if len(facts.AffectedPackages) != 2 {
		t.Fatalf("AffectedPackages has %d entries, want 2 (x/net + stdlib)", len(facts.AffectedPackages))
	}
	xnet := facts.AffectedPackages[0]
	if xnet.Module != "golang.org/x/net" || xnet.VersionScheme != "gomod" || xnet.FixedVersion != "v0.17.0" {
		t.Errorf("AffectedPackages[0] (x/net) = %+v, want the gomod primary fixed v0.17.0", xnet)
	}
	if len(xnet.AffectedRanges) != 1 || xnet.AffectedRanges[0].Fixed != "v0.17.0" {
		t.Errorf("x/net ranges = %+v, want one {Fixed:v0.17.0}", xnet.AffectedRanges)
	}
	stdlib := facts.AffectedPackages[1]
	if stdlib.Module != "" || stdlib.VersionScheme != "go-toolchain" {
		t.Errorf("AffectedPackages[1] (stdlib) = %+v, want empty module + go-toolchain scheme", stdlib)
	}
	if len(stdlib.AffectedRanges) != 2 {
		t.Fatalf("stdlib ranges = %+v, want 2 backport ranges (go1.20.10, go1.21.3)", stdlib.AffectedRanges)
	}
	wantStdlib := []Range{
		{Fixed: "go1.20.10", FixedVersion: "go1.20.10"},
		{Introduced: "go1.21.0", Fixed: "go1.21.3", FixedVersion: "go1.21.3"},
	}
	for i, want := range wantStdlib {
		if stdlib.AffectedRanges[i] != want {
			t.Errorf("stdlib AffectedRanges[%d] = %+v, want %+v", i, stdlib.AffectedRanges[i], want)
		}
	}
}

// --- 2. Invariant -------------------------------------------------------------------------------

// prohibitedKeySubstrings and prohibitedKeysExact together enforce the wire's one non-negotiable:
// the document and manifest carry NO severity, CVSS, EPSS, KEV, or prioritization-signal field.
// Enforcement is by ABSENCE of the field, checked over the raw decoded JSON (not the Go struct,
// which would only prove the reader ignores unknown fields — this proves the WIRE BYTES never
// carried them in the first place).
var (
	prohibitedKeysExact = map[string]bool{
		"severity":              true,
		"epss":                  true,
		"kev":                   true,
		"prioritization_signal": true,
		"band":                  true,
		// v3 verdict-key bright line (B1 §4.1): the corpus must be structurally incapable of
		// originating a Tegron verdict. None of these can land on advisoryDoc — same enforcement as
		// CVSS exclusion (there is no field it could land in) — and the wire bytes must never carry
		// them either. Extends the roundtrip invariant to the v3 additive block.
		"exploitability_verdict":  true,
		"is_exploitable":          true,
		"reachability_conclusion": true,
		"severity_decision":       true,
	}
)

func hasProhibitedKey(key string) bool {
	if prohibitedKeysExact[strings.ToLower(key)] {
		return true
	}
	// "any cvss key" — catches cvss, cvss_v3, cvss_score, cvssVector, etc.
	return strings.Contains(strings.ToLower(key), "cvss")
}

// walkKeysForProhibited recursively walks a decoded-JSON value (map/slice/scalar) and fails the
// test if any object key anywhere in the tree matches a prohibited key.
func walkKeysForProhibited(t *testing.T, path string, v interface{}) {
	t.Helper()
	switch val := v.(type) {
	case map[string]interface{}:
		for k, sub := range val {
			if hasProhibitedKey(k) {
				t.Errorf("%s: prohibited key %q present in vendored corpus JSON — the wire carries no prioritization signal", path, k)
			}
			walkKeysForProhibited(t, path+"."+k, sub)
		}
	case []interface{}:
		for i, sub := range val {
			walkKeysForProhibited(t, path+"[]", sub)
			_ = i
		}
	}
}

// TestFerralonCorpusInvariant_NoProhibitedKeys asserts, over the RAW vendored JSON bytes (both the
// advisory document and the manifest), that no prohibited signals-plane key is present anywhere in
// the tree. This is wire-level enforcement — the invariant is that the field CANNOT land, not
// that the reader happens to ignore it.
func TestFerralonCorpusInvariant_NoProhibitedKeys(t *testing.T) {
	files := []string{
		filepath.Join(ferralonCorpusRoot, "manifest.json"),
		filepath.Join(ferralonCorpusRoot, "2021", "12", "CVE-2021-44228.json"),
		filepath.Join(ferralonCorpusRoot, "2023", "10", "CVE-2023-39325.json"),
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		var decoded interface{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshalling %s: %v", f, err)
		}
		walkKeysForProhibited(t, f, decoded)
	}
}

// --- 2b. v3 verdict-key non-carriability ---------------------------------------------------------

// TestV3Doc_NoVerdictKeyCarriable proves the v3 additive block cannot carry a verdict (B1 §4.1). It
// builds a v3 raw-JSON document exercising EVERY v3 enrichment field AND injecting the four banned
// verdict keys, then proves two things:
//
//  1. Structural non-carriability: the injected verdict keys survive nowhere on the decoded
//     AdvisoryFacts — re-marshalling the facts yields bytes that contain none of them, because
//     advisoryDoc has no field they could land in (they are silently dropped on Unmarshal).
//  2. Correct v3 decode: the legitimate enrichment fields (trigger/fix/poc_summary/…) DO decode,
//     so the invariant is enforced by absence-of-a-field, not by rejecting the whole document.
func TestV3Doc_NoVerdictKeyCarriable(t *testing.T) {
	const v3JSON = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-TEST-V3",
	  "module": "example.com/x",
	  "version_scheme": "gomod",
	  "sink_kind": "ssrf",
	  "cwes": ["CWE-918"],
	  "root_cause": "server-side request forgery in the fetch handler",
	  "withdrawn": false,
	  "trigger": {"ingress_kind": "http", "route": "/fetch", "param": "target", "malformed_token": "an internal-address URL"},
	  "fix": {"upstream_commit": "abc123", "guard_shape": "outbound allowlist", "failed_fix_class": "guard-keyed-away-from-sink"},
	  "poc_summary": "public PoC drives the target param at an internal address",
	  "trigger_condition": "handler reachable without auth",
	  "prerequisite": "outbound egress permitted",
	  "config_key": {"key": "allow_outbound", "unsafe_value": "true"},
	  "feature_flag": "beta_fetch",
	  "gadget_classes": ["com.example.Gadget"],
	  "guard_sufficiency": [{"symbol": "allowlist.Check", "version": "1.2.0", "for_bypass": "dns-rebind", "sufficient": false}],
	  "exploitability_verdict": "exploitable",
	  "is_exploitable": true,
	  "reachability_conclusion": "reachable",
	  "severity_decision": "critical"
	}`

	var doc advisoryDoc
	if err := json.Unmarshal([]byte(v3JSON), &doc); err != nil {
		t.Fatalf("unmarshal v3 doc: %v", err)
	}
	facts, ok := doc.toFacts("CVE-TEST-V3")
	if !ok {
		t.Fatal("toFacts(v3 doc) ok=false, want true — a valid v3 document must decode")
	}

	// (2) legitimate v3 enrichment decodes.
	if facts.SinkKind != "ssrf" {
		t.Errorf("SinkKind = %q, want ssrf", facts.SinkKind)
	}
	if facts.Trigger != (TriggerRoute{IngressKind: "http", Route: "/fetch", Param: "target", MalformedToken: "an internal-address URL", Declared: PresenceDeclaredValues}) {
		t.Errorf("Trigger = %+v, want the declared http trigger", facts.Trigger)
	}
	if facts.Fix.FailedFixClass != "guard-keyed-away-from-sink" {
		t.Errorf("Fix.FailedFixClass = %q, want guard-keyed-away-from-sink", facts.Fix.FailedFixClass)
	}
	if facts.PocSummary == "" || facts.ConfigKey.Key != "allow_outbound" || facts.FeatureFlag != "beta_fetch" {
		t.Errorf("v3 enrichment fields did not decode: %+v", facts)
	}
	if len(facts.GadgetClasses) != 1 || len(facts.GuardSufficiency) != 1 {
		t.Errorf("gadget_classes/guard_sufficiency did not decode: %+v", facts)
	}

	// (1) structural non-carriability: the decoded facts, re-marshalled, carry no verdict key.
	factBytes, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	var decoded interface{}
	if err := json.Unmarshal(factBytes, &decoded); err != nil {
		t.Fatalf("re-decode facts: %v", err)
	}
	walkKeysForProhibited(t, "AdvisoryFacts", decoded)
	// belt-and-suspenders: the verdict tokens must not appear anywhere in the fact bytes.
	for _, banned := range []string{"exploitability_verdict", "is_exploitable", "reachability_conclusion", "severity_decision"} {
		if strings.Contains(strings.ToLower(string(factBytes)), banned) {
			t.Errorf("verdict token %q leaked into AdvisoryFacts bytes — must be structurally uncarriable", banned)
		}
	}
}

// --- 3. Drift alarm -----------------------------------------------------------------------------

// ferralonCorpusDigests pins the SHA-256 of each vendored file's exact bytes, as vendored from the
// producer's golden fixture and verified byte-identical to a fresh producer emit. If the producer's
// output changes shape or the schema version bumps, THIS TEST MUST FAIL — re-vendoring the corpus
// (copying fresh bytes over these files) is a CONSCIOUS act, and updating these digests in the same
// commit is how that act is recorded. Never update a digest here without re-copying the actual file
// bytes in the same change — a digest bump with no byte change defeats the whole point of this
// test.
var ferralonCorpusDigests = map[string]string{
	filepath.Join(ferralonCorpusRoot, "manifest.json"):                     "56e0d0d509c0dec0855cd3e2faa3844b997c2f4c08dac3354d797ec8b85dd0e4",
	filepath.Join(ferralonCorpusRoot, "2021", "12", "CVE-2021-44228.json"): "ddbe69131ac9c673b89b268acf3070d5845720a927bc0f0e8fbcfe03afa79b1d",
	filepath.Join(ferralonCorpusRoot, "2023", "10", "CVE-2023-39325.json"): "d67b2b7e00fb218a81f4e26cf1f3d6f9fecd6eec0d01ea2337b56b0d1254945b",
}

func TestFerralonCorpusDriftAlarm(t *testing.T) {
	for path, want := range ferralonCorpusDigests {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != want {
			t.Errorf("%s: sha256 = %s, want %s — vendored fixture drifted from the producer's golden "+
				"emit; re-vendor CONSCIOUSLY (copy fresh bytes over these files) and update this digest "+
				"in the same commit",
				path, got, want)
		}
	}
	// The manifest's own per-record output_digest must also match the doc's actual bytes — this is
	// belt-and-suspenders with artifactSource's own digest check (already exercised by the roundtrip
	// test above), asserted here directly against the raw manifest JSON so a drift in either file
	// alone is caught without needing Lookup to succeed first.
	manifestData, err := os.ReadFile(filepath.Join(ferralonCorpusRoot, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var man advisoryManifest
	if err := json.Unmarshal(manifestData, &man); err != nil {
		t.Fatalf("unmarshalling manifest: %v", err)
	}
	docData, err := os.ReadFile(filepath.Join(ferralonCorpusRoot, "2021", "12", "CVE-2021-44228.json"))
	if err != nil {
		t.Fatalf("reading doc: %v", err)
	}
	if !digestMatches(docData, findManifestDigest(t, man, "CVE-2021-44228")) {
		t.Error("manifest output_digest does not match the vendored document's actual bytes")
	}
}

func findManifestDigest(t *testing.T, man advisoryManifest, id string) string {
	t.Helper()
	for _, r := range man.Records {
		if r.Identifier == id {
			return r.OutputDigest
		}
	}
	t.Fatalf("manifest has no record for %s", id)
	return ""
}
