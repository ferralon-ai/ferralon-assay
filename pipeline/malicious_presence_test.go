// malicious_presence_test.go
//
// Unit tests for the MAL presence-verdict pipeline stage (dispatch 10, [B2 pipeline]): the
// malicious_package marker mapping in toFacts, the carry onto the normalized-advisory artifact, and
// the maliciousPresence Assess stage. Every non-match case emits NOTHING and falls open (inv.5); the
// stage can only ever mint an affirmative, never a not-affected.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// --- toFacts: the malicious_package marker mapping -------------------------------------------

// A declared marker with a version set ⇒ Declared=true and the versions copied verbatim.
func TestToFacts_MaliciousPackage_DeclaredWithVersions(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion:    normalizedAdvisorySchemaVersionV3,
		VulnID:           "MAL-2024-1",
		MaliciousPackage: &docMaliciousPackage{AffectedVersions: []string{"1.0.0", "1.0.1", "99.9.9"}},
	}
	facts, ok := doc.toFacts("MAL-2024-1")
	if !ok {
		t.Fatal("toFacts ok=false, want true")
	}
	if !facts.MaliciousPackage.Declared {
		t.Error("Declared=false, want true for a present marker")
	}
	got := facts.MaliciousPackage.AffectedVersions
	want := []string{"1.0.0", "1.0.1", "99.9.9"}
	if len(got) != len(want) {
		t.Fatalf("AffectedVersions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AffectedVersions = %v, want %v", got, want)
		}
	}
}

// A nil marker (v2 doc or any non-MAL advisory) ⇒ Declared=false, and the rest of the decode is
// byte-identical to today's behavior. This is the fail-open zero case the whole design rests on.
func TestToFacts_MaliciousPackage_NilIsNotDeclared(t *testing.T) {
	doc := advisoryDoc{SchemaVersion: normalizedAdvisorySchemaVersion, VulnID: "CVE-2023-1", SinkKind: "ssrf"}
	facts, ok := doc.toFacts("CVE-2023-1")
	if !ok {
		t.Fatal("toFacts ok=false, want true (v2 doc must keep validating)")
	}
	if facts.MaliciousPackage.Declared {
		t.Error("Declared=true, want false for an absent marker")
	}
	if len(facts.MaliciousPackage.AffectedVersions) != 0 {
		t.Errorf("AffectedVersions = %v, want empty", facts.MaliciousPackage.AffectedVersions)
	}
	if facts.SinkKind != "ssrf" {
		t.Errorf("unrelated axis drifted: SinkKind = %q, want ssrf", facts.SinkKind)
	}
}

// A declared-but-empty marker ⇒ Declared=true with an empty set (un-decidable → OPEN both
// directions). The explicit Declared bool is what distinguishes this from "not malicious"; empty
// strings inside the set are dropped.
func TestToFacts_MaliciousPackage_DeclaredEmptySet(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion:    normalizedAdvisorySchemaVersionV3,
		VulnID:           "MAL-2024-2",
		MaliciousPackage: &docMaliciousPackage{AffectedVersions: []string{"", ""}},
	}
	facts, ok := doc.toFacts("MAL-2024-2")
	if !ok {
		t.Fatal("toFacts ok=false, want true")
	}
	if !facts.MaliciousPackage.Declared {
		t.Error("Declared=false, want true: an empty version set is still a declared marker")
	}
	if len(facts.MaliciousPackage.AffectedVersions) != 0 {
		t.Errorf("AffectedVersions = %v, want empty (empty strings dropped)", facts.MaliciousPackage.AffectedVersions)
	}
}

// --- round-trip: doc → toFacts → advisoryIntake artifact ------------------------------------

// A malicious_package advisory carried through advisoryIntake.Run lands on the normalized-advisory
// artifact as malicious_package.affected_versions — what the maliciousPresence stage reads back.
func TestAdvisoryIntake_CarriesMaliciousPackageOntoArtifact(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "a1", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "MAL-2024-1", Source: "test"},
	}}
	src := fakeMaliciousSource{versions: []string{"1.0.1"}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}

	versions, declared := extractMaliciousAffectedVersions(store, c.ID)
	if !declared {
		t.Fatal("normalized-advisory artifact does not carry the malicious_package marker")
	}
	if len(versions) != 1 || versions[0] != "1.0.1" {
		t.Fatalf("affected_versions = %v, want [1.0.1]", versions)
	}
}

// A non-malicious advisory omits the marker entirely (omitempty) — the stage then sees declared=false
// and never fires.
func TestAdvisoryIntake_NonMalicious_OmitsMarker(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "a1", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2023-1", Source: "test"},
	}}
	src := fakeMaliciousSource{} // Declared=false
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if _, declared := extractMaliciousAffectedVersions(store, c.ID); declared {
		t.Error("non-malicious advisory carried a malicious_package marker; it must be omitted")
	}
}

// --- the maliciousPresence stage ------------------------------------------------------------

// present-at-listed: a malicious package resolved to a listed version ⇒ affirmative artifact.
func TestMaliciousPresence_PresentAtListedVersion_EmitsAffirmative(t *testing.T) {
	store := artifact.NewMemStore()
	c := seedMaliciousAndInventory(t, store, []string{"1.0.0", "1.0.1"}, "1.0.1")
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	res, ok := queryMaliciousPresence(t, store, c.ID)
	if !ok {
		t.Fatal("no affirmative artifact emitted for a present-at-listed match")
	}
	if !res.Present || res.MatchedVersion != "1.0.1" {
		t.Fatalf("result = %+v, want {Present:true MatchedVersion:1.0.1}", res)
	}
}

// present-but-version-not-listed: the resolved version is not in the enumerated set ⇒ NOTHING
// (falls open to the existing reconcile path).
func TestMaliciousPresence_VersionNotListed_EmitsNothing(t *testing.T) {
	store := artifact.NewMemStore()
	c := seedMaliciousAndInventory(t, store, []string{"1.0.0", "1.0.1"}, "2.0.0")
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	if _, ok := queryMaliciousPresence(t, store, c.ID); ok {
		t.Error("an artifact was emitted for a version not in the enumerated set; must fail open")
	}
}

// version near-miss: the resolved version differs from a listed version only by semver-style
// spelling drift ("1.0.0" vs "v1.0.0") ⇒ NOTHING → OPEN. Membership is EXACT string equality, no
// comparator, so drift fails toward NO match (safe), never a fabricated clear. Regression guard for
// the ratified "spelling drift fails OPEN, never false-matches" invariant on the first decisive OSS
// affected path — distinct from the clear-miss row above (a genuinely different version).
func TestMaliciousPresence_VersionNearMissSpellingDrift_EmitsNothing(t *testing.T) {
	store := artifact.NewMemStore()
	c := seedMaliciousAndInventory(t, store, []string{"v1.0.0"}, "1.0.0")
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	if _, ok := queryMaliciousPresence(t, store, c.ID); ok {
		t.Error(`an artifact was emitted for a near-miss ("1.0.0" vs "v1.0.0"); exact-string membership must fail OPEN, never false-match`)
	}
}

// unresolvable: resolved_version == "" (absent/unpinned) ⇒ NOTHING → OPEN, never clear.
func TestMaliciousPresence_UnresolvableVersion_EmitsNothing(t *testing.T) {
	store := artifact.NewMemStore()
	c := seedMaliciousAndInventory(t, store, []string{"1.0.0"}, "")
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	if _, ok := queryMaliciousPresence(t, store, c.ID); ok {
		t.Error("an artifact was emitted for an unresolvable version; must fail open")
	}
}

// non-malicious: the advisory declared no marker ⇒ NOTHING (every existing stage runs unchanged).
func TestMaliciousPresence_NonMalicious_EmitsNothing(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "a1"}
	// normalized-advisory artifact with NO malicious_package marker + a resolved version.
	putRaw(t, store, c.ID, artifact.TypeNormalizedAdvisory, `{"vuln_id":"CVE-2023-1"}`)
	putRaw(t, store, c.ID, artifact.TypeInventory, `{"resolved_version":"1.0.1"}`)
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	if _, ok := queryMaliciousPresence(t, store, c.ID); ok {
		t.Error("an artifact was emitted for a non-malicious advisory; the marker gates the whole path")
	}
}

// declared-but-empty set: a present marker with no versions is un-decidable ⇒ NOTHING → OPEN.
func TestMaliciousPresence_EmptySet_EmitsNothing(t *testing.T) {
	store := artifact.NewMemStore()
	c := seedMaliciousAndInventory(t, store, []string{}, "1.0.1")
	if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("malicious_presence: %v", err)
	}
	if _, ok := queryMaliciousPresence(t, store, c.ID); ok {
		t.Error("an artifact was emitted for a declared-but-empty version set; must fail open")
	}
}

// --- helpers --------------------------------------------------------------------------------

// fakeMaliciousSource is a minimal AdvisorySource returning a MAL-declared fact when versions is
// non-nil, else a plain non-malicious fact.
type fakeMaliciousSource struct{ versions []string }

func (s fakeMaliciousSource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	f := AdvisoryFacts{VersionScheme: "npm", PURL: "pkg:npm/evil"}
	if s.versions != nil {
		f.MaliciousPackage = MaliciousPackageFacts{Declared: true, AffectedVersions: s.versions}
	}
	return f, true
}

// seedMaliciousAndInventory seeds the two upstream artifacts the stage reads: a normalized-advisory
// carrying a declared malicious_package marker, and an inventory carrying resolved_version.
func seedMaliciousAndInventory(t *testing.T, store *artifact.MemStore, affected []string, resolved string) *assessment.Assessment {
	t.Helper()
	c := &assessment.Assessment{ID: "a1"}
	adv, err := json.Marshal(struct {
		VulnID           string `json:"vuln_id"`
		MaliciousPackage *struct {
			AffectedVersions []string `json:"affected_versions"`
		} `json:"malicious_package"`
	}{VulnID: "MAL-2024-1", MaliciousPackage: &struct {
		AffectedVersions []string `json:"affected_versions"`
	}{AffectedVersions: affected}})
	if err != nil {
		t.Fatalf("marshal advisory: %v", err)
	}
	putRaw(t, store, c.ID, artifact.TypeNormalizedAdvisory, string(adv))
	inv, _ := json.Marshal(struct {
		ResolvedVersion string `json:"resolved_version,omitempty"`
	}{ResolvedVersion: resolved})
	putRaw(t, store, c.ID, artifact.TypeInventory, string(inv))
	return c
}

func putRaw(t *testing.T, store *artifact.MemStore, caseID string, ty artifact.Type, payload string) {
	t.Helper()
	if _, err := store.Put(&artifact.Artifact{AssessmentID: caseID, Type: ty, ProducedBy: "test", Payload: []byte(payload)}); err != nil {
		t.Fatalf("Put %s: %v", ty, err)
	}
}

func queryMaliciousPresence(t *testing.T, store *artifact.MemStore, caseID string) (MaliciousPresenceResult, bool) {
	t.Helper()
	arts, err := store.Query(caseID, artifact.TypeMaliciousPresence)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(arts) == 0 {
		return MaliciousPresenceResult{}, false
	}
	var res MaliciousPresenceResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res, true
}

// A copy of a malicious package at a listed version is present whether or not the other copies
// agree with it. The resolver withholds Match when copies disagree, which empties resolved_version;
// the affirmative must still fire off the first resolved copy, as it does for a single copy.
func TestMaliciousPresence_DisagreeingCopies_RealResolver(t *testing.T) {
	const javaCoord, nugetID = "com.example.lib:widget", "Newtonsoft.Json"
	reactor := `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>a</module><module>b</module></modules></project>`
	module := func(v string) string {
		return `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>m</artifactId><version>1.0.0</version>` +
			`<dependencies><dependency><groupId>com.example.lib</groupId><artifactId>widget</artifactId><version>` + v + `</version></dependency></dependencies></project>`
	}
	project := func(v string) string {
		return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="` + v + `" /></ItemGroup></Project>`
	}
	cases := []struct {
		name, lang, coord, purl, listed string
		files                           map[string]string
		wantResolved                    string
	}{
		{"maven modules disagree", "java", javaCoord, "pkg:maven/com.example.lib/widget", "1.0.1",
			map[string]string{"pom.xml": reactor, "a/pom.xml": module("1.0.1"), "b/pom.xml": module("1.0.2")}, ""},
		{"maven modules agree", "java", javaCoord, "pkg:maven/com.example.lib/widget", "1.0.1",
			map[string]string{"pom.xml": reactor, "a/pom.xml": module("1.0.1"), "b/pom.xml": module("1.0.1")}, "1.0.1"},
		{"nuget projects disagree", "dotnet", nugetID, "pkg:nuget/Newtonsoft.Json", "13.0.1",
			map[string]string{"A/A.csproj": project("[13.0.1]"), "B/B.csproj": project("[12.0.3]")}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTreeFixture(t, tc.files)
			src := selectionStubSource{facts: AdvisoryFacts{
				Coordinate:       tc.coord,
				PURL:             tc.purl,
				MaliciousPackage: MaliciousPackageFacts{Declared: true, AffectedVersions: []string{tc.listed}},
				Provenance:       Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
			}}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "mal-" + tc.lang, Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "MAL-2024-1", Source: "corpus"},
				Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1", Acquisition: assessment.Acquisition{Mode: "git"}},
			}}
			if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			inv := codebaseInventory{checkout: dirCheckout{dir: dir, lang: tc.lang}, plugin: realResolverPlugin{lang: tc.lang}, src: src}
			if err := inv.Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}
			if got, _ := extractResolvedVersion(store, c.ID); got != tc.wantResolved {
				t.Fatalf("resolved_version = %q, want %q", got, tc.wantResolved)
			}
			if err := (maliciousPresence{}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("malicious_presence: %v", err)
			}
			res, ok := queryMaliciousPresence(t, store, c.ID)
			if !ok || res.MatchedVersion != tc.listed {
				t.Fatalf("affirmative = %+v (emitted %v), want a match at %s", res, ok, tc.listed)
			}
		})
	}
}
