//go:build live

// This file is OPT-IN via the `live` build tag, like reach_live_test.go, because it needs both the
// Go vulnerability database and — the whole point — a real toolchain fetch from the module proxy.
//
// It is the empirical proof of the mechanism: govulncheck's
// package loading really does execute under the SUBJECT's Go toolchain, so the stdlib it resolves
// against is the subject's. Nothing else in the tree can prove that — the hermetic tests stop at the
// env construction, and a fake that echoes the requested version back would look identical to a
// mechanism that silently did nothing.
//
// Run it with:
//
//	GOWORK=off go test -tags live ./internal/plugin/goanalysis/ -run TestReachability_SubjectToolchain -v
package goanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	// A real subject toolchain inside the supported band (see loaderMinMinor), old enough that the
	// switch is a genuine fetch-and-exec rather than a no-op against the analyzer's own Go, and new
	// enough to satisfy the fixture's own `go 1.22` directive — a subject toolchain OLDER than the
	// module it is asked to build is a contradiction the go command rejects, and that rejection is a
	// fallback (covered by TestReachability_ToolchainFallbacks), not this test's subject.
	liveSubjectToolchain = "go1.22.12"
	// The corpus repro whose Dockerfile pins FROM golang:1.17.1 — BELOW the loader floor. Used to
	// prove the decline path costs no download, not to prove a scan.
	belowFloorFixtureDir = "../../../corpus/testdata/repros/GO-2021-0264-reachable"
	belowFloorToolchain  = "go1.17.1"
)

// TestReachability_SubjectToolchainExecutes is the load-bearing assertion: a scan requested under an
// older subject toolchain COMPLETES and reports having run under exactly that toolchain. The fixture
// is the existing livevulnmod (x/text@v0.3.0, GO-2021-0113), reused because it is already known to
// produce a reachable path — so a failure here is attributable to the toolchain switch and not to the
// fixture.
func TestReachability_SubjectToolchainExecutes(t *testing.T) {
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir:    liveFixtureDir,
		VulnID:      liveVulnID,
		GoToolchain: liveSubjectToolchain,
	})
	if err != nil {
		t.Fatalf("Reachability under %s returned a hard error: %v", liveSubjectToolchain, err)
	}
	if res.ScanToolchain != liveSubjectToolchain {
		t.Fatalf("ScanToolchain = %q, want %q — the switch did not take effect, so nothing here is evidence about the subject",
			res.ScanToolchain, liveSubjectToolchain)
	}
	if len(res.Paths) == 0 {
		t.Fatalf("no reachable path for %s under %s (partiality=%+v); the fixture calls the vulnerable symbol directly",
			liveVulnID, liveSubjectToolchain, res.Partiality)
	}
	for _, p := range res.Paths {
		t.Logf("path sink=%s ingress=%s frames=%d", p.Sink.SCIP, p.Ingress.SCIP, len(p.Trace))
	}
}

// TestReachability_SubjectToolchainSameAsAnalyzerIsNotAFetch pins the no-op case against a real
// toolchain: asking for the analyzer's own release must report a full-fidelity subject scan without
// pinning GOTOOLCHAIN, so the common CI shape (a runner whose Go is the scanner's Go) costs nothing.
func TestReachability_SubjectToolchainSameAsAnalyzerIsNotAFetch(t *testing.T) {
	local := goEnvVersion(context.Background(), liveFixtureDir, reachBaseEnv())
	if local == "" {
		t.Skip("cannot resolve the analyzer's own toolchain")
	}
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir:    liveFixtureDir,
		VulnID:      liveVulnID,
		GoToolchain: local,
	})
	if err != nil {
		t.Fatalf("Reachability returned a hard error: %v", err)
	}
	if res.ScanToolchain != local {
		t.Errorf("ScanToolchain = %q, want %q", res.ScanToolchain, local)
	}
	if len(res.Paths) == 0 {
		t.Errorf("no reachable path for %s under the analyzer's own %s", liveVulnID, local)
	}
}

// TestReachability_ToolchainFallbacks covers every way the request can go unhonored. All three must
// produce a completed scan whose ScanToolchain is NOT the requested version — a fallback, never an
// error, and never a silent claim that the subject was scanned.
func TestReachability_ToolchainFallbacks(t *testing.T) {
	cases := []struct {
		name     string
		buildDir string
		want     string
	}{
		{
			// Below the loader floor: the bundled go/packages emits `go list` flags (-pgo,
			// -json=<fields>) that a pre-1.20 go command rejects. No fetch is attempted.
			name:     "below the loader floor",
			buildDir: belowFloorFixtureDir,
			want:     belowFloorToolchain,
		},
		{
			// A release that will never exist: the fetch reaches the proxy and is refused.
			name:     "unfetchable release",
			buildDir: liveFixtureDir,
			want:     "go1.99.99",
		},
		{
			// The likeliest real-world decline, and the one worth naming: the fetch SUCCEEDS and
			// the toolchain then refuses the module, because livevulnmod declares `go 1.22` and a
			// go1.20 command will not build it. A subject toolchain older than its own go.mod
			// requires is a contradiction in the inputs; falling back is the only honest answer.
			name:     "subject toolchain older than the module's own go directive",
			buildDir: liveFixtureDir,
			want:     "go1.20.14",
		},
		{
			// Parses as nothing: declined before any subprocess.
			name:     "junk version",
			buildDir: liveFixtureDir,
			want:     "not-a-version",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
				BuildDir:    c.buildDir,
				GoToolchain: c.want,
			})
			if err != nil {
				t.Fatalf("an unhonored toolchain request failed the scan: %v — it must be a fallback", err)
			}
			if res.ScanToolchain == c.want {
				t.Fatalf("ScanToolchain = %q; the request was not honored and must not be reported as if it were", res.ScanToolchain)
			}
			if res.ScanToolchain == "" {
				t.Error("ScanToolchain is empty after a fallback; the run must record which toolchain it actually used")
			}
			t.Logf("requested %s, fell back to %s", c.want, res.ScanToolchain)
		})
	}
}
