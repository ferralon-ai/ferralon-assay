//go:build live

// This file is OPT-IN: it is excluded from the default `go test ./...` run by the
// `live` build tag. Run it with `go test -tags live ./internal/plugin/goanalysis/...`.
//
// Network / vuln-DB requirement (OQ-5): the live test drives the real govulncheck
// library against the testdata/livevulnmod fixture, whose own go.mod pins the
// vulnerable golang.org/x/text@v0.3.0. Running it requires:
//   - the Go vulnerability database (https://vuln.go.dev by default, or a local
//     offline bundle via GOVULNDB) — govulncheck always consults it; and
//   - golang.org/x/text@v0.3.0 resolvable for the load (present in the module
//     cache, the configured GOPROXY, or — if added — a vendor/ dir).
//
// The fixture is deliberately NOT vendored to keep third-party source out of the
// gofmt/test tree; the dep is resolved from the module cache/proxy. The hermetic
// suite (reach_test.go) never runs govulncheck and needs no network.

package goanalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	liveFixtureDir = "testdata/livevulnmod"
	liveVulnID     = "GO-2021-0113" // out-of-bounds read in golang.org/x/text/language
)

// TestReachability_Live exercises Reachability end-to-end with the real
// govulncheck library against a fixture that calls a known-vulnerable symbol
// (language.Parse). It asserts the library route parses a reachable trace into a
// ReachPath whose sink is the vulnerable symbol and whose trace runs through the
// fixture's Trigger entry — proving the govulncheck -> derivation -> reconciliation
// pipeline works against a real advisory.
func TestReachability_Live(t *testing.T) {
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: liveFixtureDir,
		VulnID:   liveVulnID,
	})
	if err != nil {
		t.Fatalf("Reachability (live) returned a hard error: %v", err)
	}

	if len(res.Paths) == 0 {
		t.Fatalf("expected at least one reachable path for %s; got none (partiality=%+v)",
			liveVulnID, res.Partiality)
	}

	var found bool
	for _, p := range res.Paths {
		if strings.Contains(p.Sink.SCIP, "language") && strings.Contains(p.Sink.SCIP, "Parse") {
			found = true
			if len(p.Trace) < 2 {
				t.Errorf("expected a multi-frame trace ingress->sink, got %v", p.Trace)
			}
			traceIDs := make([]string, len(p.Trace))
			for i, s := range p.Trace {
				traceIDs[i] = s.SCIP
			}
			traceJoined := strings.Join(traceIDs, "\n")
			if !strings.Contains(traceJoined, "Trigger") {
				t.Errorf("expected the trace to pass through Trigger; got %v", p.Trace)
			}
			if p.Sink != p.Trace[len(p.Trace)-1] {
				t.Errorf("sink should be the bottom trace frame: sink=%q trace=%v", p.Sink.SCIP, p.Trace)
			}
		}
	}
	if !found {
		t.Errorf("no ReachPath whose sink is language.Parse; paths=%+v", res.Paths)
	}
}

// TestReachability_Live_HostileWorkspace is the non-live-trial reproducer for the
// go.work auto-discovery blocker: when the analyzed module sits UNDER a Go
// workspace the plugin process happens to run inside (e.g. an in-repo corpus
// repro under an enclosing go.work), an ambient GOWORK pointing at that workspace
// makes govulncheck's go/packages load fail with "directory prefix . does not
// contain modules listed in go.work" — because the repro module is not a go.work
// member. The fix forces GOWORK=off LOCALLY on the scan command's Env (reach.go),
// so the load resolves the target module standalone regardless of the ambient
// workspace. This test plants a hostile go.work that does NOT `use` the fixture,
// points GOWORK at it, and asserts Reachability still resolves the trace.
func TestReachability_Live_HostileWorkspace(t *testing.T) {
	abs, err := filepath.Abs(liveFixtureDir)
	if err != nil {
		t.Fatalf("abs fixture dir: %v", err)
	}
	// A go.work in a parent dir that lists an unrelated module (NOT the fixture),
	// reproducing the monorepo-go.work-does-not-use-the-repro situation.
	hostileWork := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(hostileWork, []byte("go 1.21\n\nuse ./somewhere-else\n"), 0o644); err != nil {
		t.Fatalf("write hostile go.work: %v", err)
	}
	t.Setenv("GOWORK", hostileWork)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: abs,
		VulnID:   liveVulnID,
	})
	if err != nil {
		if strings.Contains(err.Error(), "go.work") {
			t.Fatalf("reachability leaked the ambient GOWORK into govulncheck (the blocker is back): %v", err)
		}
		t.Fatalf("Reachability (hostile workspace) returned a hard error: %v", err)
	}
	if len(res.Paths) == 0 {
		t.Fatalf("expected a reachable path under a hostile GOWORK; got none (partiality=%+v)", res.Partiality)
	}
}

// TestReachability_Live_BrokenDirIsHardError asserts that a govulncheck run over a
// nonexistent build dir surfaces as a HARD error (inv.4), never a silent empty
// result.
func TestReachability_Live_BrokenDirIsHardError(t *testing.T) {
	_, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: "testdata/does-not-exist",
		VulnID:   liveVulnID,
	})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir (inv.4)")
	}
}

// TestReachability_Live_SettledFailureReplays drives the real govulncheck over a tree whose load
// fails on a type error: the failure settles, and a later advisory gets the same hard error from
// the run cache even after the tree is fixed, which a fresh run would scan cleanly.
func TestReachability_Live_SettledFailureReplays(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() { var x int = \"s\"; _ = x }\n",
	})
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	req := plugin.ReachabilityRequest{BuildDir: dir, VulnID: liveVulnID}
	_, first := Reachability(ctx, req)
	var failed *govulncheckError
	if !errors.As(first, &failed) || !failed.settled || len(loadPackageErrors(failed.cause)) == 0 {
		t.Fatalf("first run: %v, want a settled load failure carrying package errors", first)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reachability(ctx, req); err == nil || err.Error() != first.Error() {
		t.Fatalf("second advisory: %v, want the first run's error %q", err, first)
	}
	if _, err := Reachability(WithRunCacheDir(context.Background(), t.TempDir()), req); err != nil {
		t.Fatalf("fresh run over the fixed tree: %v", err)
	}
}

// TestReachability_Live_PartialRunPastUnloadableCgo drives the real govulncheck over a tree where one
// root imports a cgo package whose header does not exist: the full load fails and settles, and the
// partial run over the other root still finds the vulnerable call, while an advisory it says nothing
// about stays unknown to the analyzer, beside a tool failure bounded to what the left-out root
// imports. Modules resolve offline; the vulnerability database is still vuln.go.dev.
func TestReachability_Live_PartialRunPastUnloadableCgo(t *testing.T) {
	sum, err := os.ReadFile(filepath.Join(liveFixtureDir, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	dir := writeTree(t, map[string]string{
		"go.mod":           "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n",
		"go.sum":           string(sum),
		"cmd/ok/main.go":   "package main\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { _, _ = language.Parse(\"en-US\") }\n",
		"cmd/bad/main.go":  "package main\n\nimport \"example.com/m/cgobad\"\n\nfunc main() { cgobad.F() }\n",
		"cgobad/cgobad.go": "package cgobad\n\n// #include \"nonexistent.h\"\nimport \"C\"\n\nfunc F() {}\n",
	})
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "1")
	ctx := WithRunCacheDir(context.Background(), t.TempDir())

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, VulnID: liveVulnID})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if !slices.ContainsFunc(res.Paths, func(p plugin.ReachPath) bool { return strings.Contains(p.Sink.SCIP, "language/Parse") }) {
		t.Errorf("no path to language.Parse from the root the partial run kept: %+v", res.Paths)
	}
	disclosed := slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
		return s.Reason == plugin.PartialReasonToolFailure && strings.Contains(s.Path, "example.com/m/cgobad") && strings.Contains(s.Path, "example.com/m/cmd/bad")
	})
	if !disclosed {
		t.Errorf("partiality %+v does not name what the partial run left out", res.Partiality)
	}

	res, err = Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, VulnID: "GO-2099-0001"})
	if err != nil {
		t.Fatalf("Reachability, an advisory the run says nothing about: %v", err)
	}
	bounded := slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
		return s.Reason == plugin.PartialReasonToolFailure && slices.Contains(s.Targets, "pkg:golang/example.com/m") &&
			!slices.Contains(s.Targets, "pkg:golang/golang.org/x/text")
	})
	if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonAdvisoryUnknownToAnalyzer) || !bounded {
		t.Errorf("silence of a partial run: refutation %+v, partiality %+v; want unknown to the analyzer, beside a tool failure bounded to the left-out root's imports", res.Refutation, res.Partiality)
	}
}

// TestReachability_Live_PartialRunReleasesOutsideHidden pins ferralon-ai/tracker#612 end to end: a
// root imports a dependency's cgo package whose header does not exist, so govulncheck runs over the
// other root only. Nothing the left-out root imports is golang.org/x/text, so the refutation of
// x/text stands, beside a tool failure whose Targets are what the left-out root imports.
func TestReachability_Live_PartialRunReleasesOutsideHidden(t *testing.T) {
	sum, err := os.ReadFile(filepath.Join(liveFixtureDir, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	depDir := writeTree(t, map[string]string{
		"go.mod":     "module example.com/dep\n\ngo 1.22\n",
		"olm/olm.go": "package olm\n\n// #include \"nonexistent.h\"\nimport \"C\"\n\nfunc F() {}\n",
	})
	dir := writeTree(t, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n\texample.com/dep v0.0.0\n)\n\nreplace example.com/dep => " + depDir + "\n",
		"go.sum": string(sum),
		// transform's own package has no left-out files, so excluded_files does not withhold.
		"cmd/ok/main.go":  "package main\n\nimport \"golang.org/x/text/transform\"\n\nvar T transform.Transformer = transform.Nop\n\nfunc main() { println(T != nil) }\n",
		"cmd/bad/main.go": "package main\n\nimport \"example.com/dep/olm\"\n\nfunc main() { olm.F() }\n",
	})
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "1")
	ctx := WithRunCacheDir(context.Background(), t.TempDir())

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, VulnID: liveVulnID})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if res.Refutation == nil || res.Refutation.Package != "pkg:golang/golang.org/x/text" || len(res.Paths) > 0 {
		t.Errorf("refutation %+v, %d paths, partiality %+v; want the refutation of x/text to stand", res.Refutation, len(res.Paths), res.Partiality)
	}
	if len(res.Partiality.Reasons) > 0 {
		t.Errorf("run-wide reasons %v; want none", res.Partiality.Reasons)
	}
	i := slices.IndexFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool { return s.Reason == plugin.PartialReasonToolFailure })
	if i < 0 {
		t.Fatalf("partiality %+v names no tool failure for the left-out root", res.Partiality)
	}
	want := []string{"", "pkg:golang/example.com/dep", "pkg:golang/example.com/m", "pkg:golang/stdlib"}
	if got := res.Partiality.Scoped[i].Targets; !slices.Equal(got, want) {
		t.Errorf("tool failure Targets = %q, want %q", got, want)
	}
}
