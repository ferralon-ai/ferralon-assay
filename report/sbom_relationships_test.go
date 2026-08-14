package report

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// fullyPopulatedSBOMReport builds a Report whose SBOM exercises every new field: three packages, a
// direct and a transitive one, a parent→child relationship, and a package carrying a declared-partial
// field. It is the C2 round-trip fixture.
func fullyPopulatedSBOMReport() Report {
	root := Package{Ecosystem: "Go", Name: "example.com/app", Version: "v1.0.0", PURL: "pkg:golang/example.com/app@v1.0.0", Direct: true}
	dep := Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6", PURL: "pkg:golang/golang.org/x/text@v0.3.6", Direct: true}
	transitive := Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", PURL: "pkg:golang/golang.org/x/net@v0.17.0", Direct: false}
	// A package whose integrity digest could not be acquired in a no-acquisition scan declares the
	// limit rather than emitting an empty value (§4.1 declared partiality at package scope).
	partial := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Direct: false, PartialReason: "artifact_unacquired"}

	return NewBuilder(Subject{Repo: "example.com/app", ResolvedCommit: "sha"}).
		AddPackages(root, dep, transitive, partial).
		SetRelationships([]Relationship{
			{Parent: root.Key(), Child: dep.Key()},
			{Parent: dep.Key(), Child: transitive.Key()},
		}).
		Build()
}

// TestSBOMJSONRoundTrip is C2(b): a fully populated SBOM marshals, unmarshals, and DeepEquals the
// original. A field without a JSON tag, or omitempty where the zero value is meaningful (Direct=false
// for a transitive package), would drop through this.
func TestSBOMJSONRoundTrip(t *testing.T) {
	orig := fullyPopulatedSBOMReport()

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig.SBOM, back.SBOM) {
		t.Fatalf("SBOM did not round-trip:\n orig=%+v\n back=%+v", orig.SBOM, back.SBOM)
	}
	// Direct=false must actually be present in the JSON — the transitive package proves it is not
	// omitempty'd away (which would make it indistinguishable from a direct package on decode).
	if !strings.Contains(string(b), `"direct":false`) {
		t.Fatalf("transitive package's direct:false was omitted from the wire: %s", b)
	}
}

// TestSBOMValidateRejectsDanglingRelationship is C2 referential integrity: an edge naming a package
// not in the SBOM is a structural violation, not a tolerated partial.
func TestSBOMValidateRejectsDanglingRelationship(t *testing.T) {
	r := fullyPopulatedSBOMReport()
	r.SBOM.Relationships = append(r.SBOM.Relationships, Relationship{Parent: "pkg:golang/example.com/app@v1.0.0", Child: "pkg:golang/nonexistent@v9.9.9"})
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a relationship whose child is not in the SBOM (dangling edge)")
	}
	// The valid report still passes — the guard rejects only dangling edges, not relationships as such.
	if err := fullyPopulatedSBOMReport().Validate(); err != nil {
		t.Fatalf("Validate rejected a referentially-valid SBOM: %v", err)
	}
}

// TestColdPreCycleReportStillDecodes is C2(c): a stored v2 report written BEFORE this cycle — no
// direct/partial_reason/relationships fields — still decodes and still passes Validate. This literal
// is authored as the OLD shape, not regenerated from the new code, so it genuinely predates the
// change: it proves the schema addition is backward-compatible and needs no SchemaVersion bump.
func TestColdPreCycleReportStillDecodes(t *testing.T) {
	const preCycle = `{
	  "schema_version": "tegron.report.v2",
	  "subject": {"repo": "example.com/legacy", "resolved_commit": "deadbeef"},
	  "sbom": {"packages": [
	    {"ecosystem": "Go", "name": "golang.org/x/text", "version": "v0.3.6", "purl": "pkg:golang/golang.org/x/text@v0.3.6"}
	  ]},
	  "advisories": [],
	  "provenance": {"commit_sha": "deadbeef", "analyzer_version": "v0", "timestamp": "2026-01-01T00:00:00Z"}
	}`
	var r Report
	if err := json.Unmarshal([]byte(preCycle), &r); err != nil {
		t.Fatalf("a pre-cycle v2 report failed to decode under the new schema: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("a pre-cycle v2 report failed Validate under the new schema: %v", err)
	}
	// The absent fields decode to their zero values, not to an error.
	if len(r.SBOM.Packages) != 1 || r.SBOM.Packages[0].Direct || r.SBOM.Packages[0].PartialReason != "" {
		t.Fatalf("pre-cycle package decoded wrong: %+v", r.SBOM.Packages)
	}
	if r.SBOM.Relationships != nil {
		t.Fatalf("pre-cycle SBOM should have no relationships, got %+v", r.SBOM.Relationships)
	}
}

// TestSBOMEncodingIsByteDeterministic is C4: encoding the same fully-populated SBOM many times
// in-process is byte-identical. Go randomizes map iteration PER iteration, so a map on the encoding
// path would diverge within this loop; a sorted slice never does. It also logs the canonical digest
// so a second `go test` process can diff it (the cross-process half of C4) — no checked-in golden,
// which would only prove one process's order recurred.
func TestSBOMEncodingIsByteDeterministic(t *testing.T) {
	sbom := fullyPopulatedSBOMReport().SBOM

	first, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 64; i++ {
		b, err := json.Marshal(sbom)
		if err != nil {
			t.Fatalf("marshal iter %d: %v", i, err)
		}
		if string(b) != string(first) {
			t.Fatalf("SBOM encoding diverged on iteration %d (a map on the encoding path?):\n first=%s\n got  =%s", i, first, b)
		}
	}
	t.Logf("sbom_canonical_sha256=%x", sha256.Sum256(first))
}
