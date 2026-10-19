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

// publishedCorpusRoot holds records copied byte-for-byte from the published corpus, which lists an
// advisory's packages under affected[] rather than affected_packages[].
const publishedCorpusRoot = "testdata/published-corpus"

func lookupPublished(t *testing.T, id string) AdvisoryFacts {
	t.Helper()
	facts, ok := NewArtifactSource(publishedCorpusRoot).Lookup(id)
	if !ok {
		t.Fatalf("Lookup(%s) missed", id)
	}
	return facts
}

func affectedPURLs(pkgs []AffectedPackage) []string {
	var purls []string
	for _, p := range pkgs {
		purls = append(purls, p.PURL)
	}
	return purls
}

// TestPublishedAffected_MultiPackage: CVE-2023-39325 lists x/net, two package paths with no version
// scheme (x/net/http2, net/http) and stdlib. The ranged entries become the multi-package set, the
// unranged ones are dropped but still named, and every entry carries the advisory's symbols, since
// the published entries carry none of their own.
func TestPublishedAffected_MultiPackage(t *testing.T) {
	const (
		xnet    = "pkg:golang/golang.org/x/net"
		http2   = "pkg:golang/golang.org/x/net/http2"
		nethttp = "pkg:golang/net/http"
		stdlib  = "pkg:golang/stdlib"
	)
	facts := lookupPublished(t, "CVE-2023-39325")
	if got, want := affectedPURLs(facts.AffectedPackages), []string{xnet, stdlib}; !slices.Equal(got, want) {
		t.Fatalf("AffectedPackages = %q, want %q", got, want)
	}
	if want := []string{http2, nethttp}; !slices.Equal(facts.DroppedPackages, want) {
		t.Errorf("DroppedPackages = %q, want %q", facts.DroppedPackages, want)
	}
	if len(facts.Symbols) == 0 {
		t.Fatal("fixture has no advisory symbols")
	}
	for _, p := range facts.AffectedPackages {
		if !slices.Equal(p.Symbols, facts.Symbols) {
			t.Errorf("%s symbols = %q, want the advisory's %q", p.PURL, p.Symbols, facts.Symbols)
		}
	}
	xn, std := facts.AffectedPackages[0], facts.AffectedPackages[1]
	if want := []Range{{Fixed: "0.17.0", FixedVersion: "0.17.0"}}; !slices.Equal(xn.AffectedRanges, want) {
		t.Errorf("x/net ranges = %+v, want %+v", xn.AffectedRanges, want)
	}
	if xn.FixedVersion != "0.17.0" {
		t.Errorf("x/net fixed version = %q, want 0.17.0", xn.FixedVersion)
	}
	wantStd := []Range{
		{Fixed: "1.20.10", FixedVersion: "1.20.10"},
		{Introduced: "1.21.0-0", Fixed: "1.21.3", FixedVersion: "1.21.3"},
	}
	if !slices.Equal(std.AffectedRanges, wantStd) {
		t.Errorf("stdlib ranges = %+v, want %+v", std.AffectedRanges, wantStd)
	}
	if std.FixedVersion != "" {
		t.Errorf("stdlib fixed version = %q, want none (two fixing releases)", std.FixedVersion)
	}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-published", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2023-39325", Source: "corpus"},
	}}
	if err := (advisoryIntake{src: NewArtifactSource(publishedCorpusRoot)}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if got, want := AdvisoryPackagePURLs(store, c.ID), []string{xnet, xnet, stdlib, http2, nethttp}; !slices.Equal(got, want) {
		t.Errorf("AdvisoryPackagePURLs = %q, want %q", got, want)
	}
}

// TestPublishedAffected_SecondarySelected: CVE-2024-25621 lists containerd and containerd/v2. A
// build that requires only containerd/v2 selects that entry and resolves its version.
func TestPublishedAffected_SecondarySelected(t *testing.T) {
	const v2 = "github.com/containerd/containerd/v2"
	dir := t.TempDir()
	goMod := "module example.com/target\n\ngo 1.23\n\nrequire " + v2 + " v2.1.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	src := NewArtifactSource(publishedCorpusRoot)
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-published-select", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2024-25621", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{checkout: dirCheckout{dir: dir, lang: "go"}, src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var inv selectInventoryFields
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.SelectedModule != v2 {
		t.Errorf("selected_module = %q, want %s", inv.SelectedModule, v2)
	}
	if inv.ResolvedVersion != "v2.1.0" {
		t.Errorf("resolved_version = %q, want v2.1.0", inv.ResolvedVersion)
	}
}
