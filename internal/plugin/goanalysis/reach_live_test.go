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
	"os"
	"path/filepath"
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
// repro under Tegron's own go.work), an ambient GOWORK pointing at that workspace
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
