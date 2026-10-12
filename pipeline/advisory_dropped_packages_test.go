package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestAdvisoryPackagePURLs_DroppedElementStaysNamed: CVE-2023-39325 names x/net and the Go
// standard library. When the stdlib element fails validation and is dropped from the
// multi-package set, the normalized advisory still names stdlib, so the not_exploitable gate
// cannot treat the advisory as x/net's alone.
func TestAdvisoryPackagePURLs_DroppedElementStaysNamed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(ferralonCorpusRoot, "2023", "10", "CVE-2023-39325.json"))
	if err != nil {
		t.Fatal(err)
	}
	const xnet, stdlib = "pkg:golang/golang.org/x/net", "pkg:golang/stdlib"
	tests := []struct {
		name        string
		mutate      func(*docAffectedPackage)
		wantDropped []string
	}{
		{"well-formed", func(*docAffectedPackage) {}, nil},
		{"unrecognized version scheme", func(p *docAffectedPackage) { p.VersionScheme = "semver-x" }, []string{stdlib}},
		{"boundless range", func(p *docAffectedPackage) { p.AffectedRanges = []docRange{{}} }, []string{stdlib}},
		{"boundless range, no package URL", func(p *docAffectedPackage) {
			p.AffectedRanges = []docRange{{}}
			p.PURL = ""
		}, []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc advisoryDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.AffectedPackages) != 2 || doc.AffectedPackages[1].PURL != stdlib {
				t.Fatalf("fixture changed: affected_packages = %+v, want [x/net, stdlib]", doc.AffectedPackages)
			}
			tt.mutate(&doc.AffectedPackages[1])
			facts, ok := doc.toFacts("CVE-2023-39325")
			if !ok {
				t.Fatal("toFacts rejected the document")
			}
			if !slices.Equal(facts.DroppedPackages, tt.wantDropped) {
				t.Errorf("DroppedPackages = %q, want %q", facts.DroppedPackages, tt.wantDropped)
			}

			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-dropped", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "CVE-2023-39325", Source: "corpus"},
			}}
			if err := AssessStages(WithAdvisorySource(selectionStubSource{facts: facts}))[0].Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake run: %v", err)
			}
			got := AdvisoryPackagePURLs(store, c.ID)
			want := []string{xnet, xnet, stdlib}
			if tt.wantDropped != nil {
				want = append([]string{xnet, xnet}, tt.wantDropped...)
			}
			if !slices.Equal(got, want) {
				t.Errorf("AdvisoryPackagePURLs = %q, want %q", got, want)
			}
		})
	}
}
