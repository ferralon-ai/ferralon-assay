package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestComputeTaint_PathPresentFromIngress(t *testing.T) {
	dir := reachFixture(t)
	fetch := methodSCIP("com.example.web", []string{"UrlFetcher"}, "fetch", 1)
	doGet := methodSCIP("com.example.web", []string{"FetchServlet"}, "doGet", 2)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: dir,
		Sinks:    []string{fetch},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if res.PrecisionNote == "" {
		t.Error("taint result must carry a precision note recording the path-presence limit")
	}
	if len(res.Paths) != 1 {
		t.Fatalf("expected one path-presence path, got %d: %+v", len(res.Paths), res.Paths)
	}
	if res.Paths[0].Ingress != doGet {
		t.Errorf("taint path ingress = %q, want %q", res.Paths[0].Ingress, doGet)
	}
	if !res.Partiality.Complete {
		t.Errorf("fully-resolved path presence should be Complete, got %+v", res.Partiality)
	}
}

func TestComputeTaint_NoPathIsNoKnownIngress(t *testing.T) {
	dir := reachFixture(t)
	orphan := methodSCIP("com.example.web", []string{"UrlFetcher"}, "orphan", 1)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: dir,
		Sinks:    []string{orphan},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Errorf("orphan sink must yield no path, got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Errorf("no path is UNKNOWN, must not be Complete (inv.5)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("no path must declare no_known_ingress, got %+v", res.Partiality)
	}
	if res.PrecisionNote == "" {
		t.Error("precision note must be set even when no path is found")
	}
}

func TestComputeTaint_MissingBuildDirIsHardError(t *testing.T) {
	_, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}
