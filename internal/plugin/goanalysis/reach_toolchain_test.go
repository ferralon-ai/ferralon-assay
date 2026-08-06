// reach_toolchain_test.go
//
// The govulncheck child may run under the SUBJECT's Go
// toolchain rather than the analyzer's, so an empty path set for a stdlib advisory is finally
// evidence about the subject. These are the hermetic halves — the env construction and the release
// normalizer that decides "already on it" vs "switch needed". The download itself is exercised by
// reach_toolchain_live_test.go.
//
// No test here runs govulncheck, and none needs a network: subjectToolchainEnv's only outside
// contact is `go env GOVERSION`, which resolves from the local toolchain.
package goanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseGoRelease(t *testing.T) {
	cases := []struct {
		in   string
		want goRelease
		ok   bool
	}{
		{"go1.21.3", goRelease{1, 21, 3}, true},
		// A pre-1.21 initial release reports two segments; the toolchain fact always carries
		// three. Parsing both is what stops a needless fetch of an already-installed release.
		{"go1.17", goRelease{1, 17, 0}, true},
		{"go1.17.0", goRelease{1, 17, 0}, true},
		{" go1.26.4\n", goRelease{1, 26, 4}, true},
		{"go1.100.2", goRelease{1, 100, 2}, true},
		// No release identity: never equal to a requested release, and never requested.
		{"devel go1.27-abc123 2026-07-01", goRelease{}, false},
		{"go1.22rc1", goRelease{}, false},
		{"go1.22beta1", goRelease{}, false},
		{"go1", goRelease{}, false},
		{"go1.2.3.4", goRelease{}, false},
		{"1.21.3", goRelease{}, false},
		{"go", goRelease{}, false},
		{"", goRelease{}, false},
		{"gox.y.z", goRelease{}, false},
		{"go1.-1.0", goRelease{}, false},
	}
	for _, c := range cases {
		got, ok := parseGoRelease(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseGoRelease(%q) = (%+v, %t), want (%+v, %t)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestGoRelease_ToolchainSpelling pins the release-naming wrinkle that would otherwise degrade a
// scannable subject to a fallback: there is no golang.org/toolchain version named "go1.20.0" — the
// initial release of a pre-1.21 minor is spelled "go1.20" — while from 1.21 on the ".0" IS the name.
// The toolchain fact always carries the canonical three-segment form, so the translation has to
// happen here or the pin names a release that cannot be downloaded.
func TestGoRelease_ToolchainSpelling(t *testing.T) {
	cases := []struct{ in, want string }{
		{"go1.20.0", "go1.20"},
		{"go1.20", "go1.20"},
		{"go1.20.14", "go1.20.14"},
		{"go1.17.0", "go1.17"},
		// 1.21 onward: the initial release really is "go1.21.0".
		{"go1.21.0", "go1.21.0"},
		{"go1.21.3", "go1.21.3"},
		{"go1.26.0", "go1.26.0"},
	}
	for _, c := range cases {
		r, ok := parseGoRelease(c.in)
		if !ok {
			t.Fatalf("parseGoRelease(%q) failed", c.in)
		}
		if got := r.toolchain(); got != c.want {
			t.Errorf("%q.toolchain() = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestGoRelease_Loadable pins the loader floor with the exact releases it was measured against
// (see loaderMinMinor). A subject below it gets no fetch attempt at all, because the fetch would
// succeed and the scan would then fail on a `go list` flag the older go command lacks.
func TestGoRelease_Loadable(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"go1.16.1", false},
		{"go1.17.1", false}, // the GO-2021-0264 corpus repro's pinned toolchain
		{"go1.18.10", false},
		{"go1.19", false},
		{"go1.19.13", false},
		{"go1.20", true},
		{"go1.20.9", true},
		{"go1.21.0", true},
		{"go1.26.4", true},
	}
	for _, c := range cases {
		r, ok := parseGoRelease(c.in)
		if !ok {
			t.Fatalf("parseGoRelease(%q) failed", c.in)
		}
		if got := r.loadable(); got != c.want {
			t.Errorf("%q loadable = %t, want %t", c.in, got, c.want)
		}
	}
}

func TestSameGoToolchain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"go1.17", "go1.17.0", true},
		{"go1.26.4", "go1.26.4", true},
		{"go1.26.4", "go1.26.3", false},
		{"go1.26.4", "go1.27.0", false},
		// An unparseable side is never "the same" — an unknown toolchain must not be able to
		// satisfy a request for a specific release.
		{"", "go1.26.4", false},
		{"go1.26.4", "", false},
		{"devel go1.27-abc", "go1.27.0", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := sameGoToolchain(c.a, c.b); got != c.want {
			t.Errorf("sameGoToolchain(%q, %q) = %t, want %t", c.a, c.b, got, c.want)
		}
	}
}

// goToolchainOf returns the GOTOOLCHAIN assignment present in env, or "" when env pins none.
func goToolchainOf(env []string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], "GOTOOLCHAIN="); ok {
			return v
		}
	}
	return ""
}

// scratchModule writes a minimal buildable module so `go env GOVERSION` has a real directory to
// resolve against (it is directory-sensitive under GOTOOLCHAIN=auto).
func scratchModule(t *testing.T, goDirective string) string {
	t.Helper()
	dir := t.TempDir()
	body := "module tegron.test/scratch\n\ngo " + goDirective + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	return dir
}

// TestReachBaseEnv_ForcesWorkspaceOffAndDoesNotPin asserts the untouched baseline: today's env,
// exactly. This is the environment every flag-off run and every non-exact-bound run still gets, so
// a regression here is a silent behavior change on every scan that is green today.
func TestReachBaseEnv_ForcesWorkspaceOffAndDoesNotPin(t *testing.T) {
	env := reachBaseEnv()
	if !slices.Contains(env, "GOWORK=off") {
		t.Errorf("reachBaseEnv() does not force GOWORK=off; env tail=%v", env[max(0, len(env)-3):])
	}
	if tc := goToolchainOf(env); tc != "" {
		t.Errorf("reachBaseEnv() pinned GOTOOLCHAIN=%q; the base env must never pin a toolchain", tc)
	}
	// Appending must not alias os.Environ()'s backing array — two independently derived
	// candidate environments would otherwise clobber each other's last element.
	a, b := reachBaseEnv(), reachBaseEnv()
	a = append(a, "GOTOOLCHAIN=go1.1.1")
	if slices.Contains(b, "GOTOOLCHAIN=go1.1.1") {
		t.Error("reachBaseEnv() results share a backing array: appending to one mutated the other")
	}
}

// TestSubjectToolchainEnv_SwitchDecision is the env-construction table: given the subject toolchain
// the caller wants (already gated on flag + exact bound upstream), does the run pin one, and which
// toolchain does it report having run under?
func TestSubjectToolchainEnv_SwitchDecision(t *testing.T) {
	dir := scratchModule(t, "1.21")
	base := reachBaseEnv()

	// The flag-off / floor / unresolved / non-Go arm. Asserted FIRST because it is the one that
	// must not change: it is every scan that is green today.
	t.Run("no request: today's env exactly, and no claim of a scan toolchain", func(t *testing.T) {
		env, scan, switched := subjectToolchainEnv(context.Background(), base, dir, "")
		if !slices.Equal(env, base) {
			t.Errorf("env = %v, want the base env verbatim", env[max(0, len(env)-3):])
		}
		if scan != "" {
			t.Errorf("scanToolchain = %q, want \"\": an unrequested run must not report a subject toolchain", scan)
		}
		if switched {
			t.Error("switched = true with no request")
		}
	})

	local := goEnvVersion(context.Background(), dir, base)
	if local == "" {
		t.Skip("no usable `go` on PATH to resolve the analyzer's own toolchain")
	}
	t.Logf("analyzer toolchain for %s: %s", dir, local)

	t.Run("already on the subject's toolchain: no pin, full fidelity", func(t *testing.T) {
		env, scan, switched := subjectToolchainEnv(context.Background(), base, dir, local)
		if tc := goToolchainOf(env); tc != "" {
			t.Errorf("pinned GOTOOLCHAIN=%q when the analyzer is already on %s", tc, local)
		}
		if !slices.Equal(env, base) {
			t.Errorf("env differs from the base env; want today's env exactly")
		}
		if switched {
			t.Error("switched = true; no toolchain switch is needed or wanted here")
		}
		if !sameGoToolchain(scan, local) {
			t.Errorf("scanToolchain = %q, want the analyzer's own %q", scan, local)
		}
	})

	t.Run("canonical three-segment spelling of the same release: still no pin", func(t *testing.T) {
		r, ok := parseGoRelease(local)
		if !ok {
			t.Skipf("analyzer toolchain %q has no release identity", local)
		}
		// The toolchain fact always carries the canonical three-segment form. Feed that in and
		// assert it is still recognized as the local release rather than fetched.
		canonical := fmt.Sprintf("go%d.%d.%d", r.major, r.minor, r.patch)
		env, _, switched := subjectToolchainEnv(context.Background(), base, dir, canonical)
		if tc := goToolchainOf(env); tc != "" || switched {
			t.Errorf("pinned GOTOOLCHAIN=%q (switched=%t) for %q, which is the same release as %q",
				tc, switched, canonical, local)
		}
	})

	t.Run("below the loader floor: no fetch is even attempted", func(t *testing.T) {
		// GOPROXY=off would make a fetch fail anyway; the point of this arm is that no fetch is
		// attempted at all, which is observable as the run taking the fallback with the base env.
		env, scan, switched := subjectToolchainEnv(context.Background(), base, dir, "go1.17.1")
		if tc := goToolchainOf(env); tc != "" {
			t.Errorf("pinned GOTOOLCHAIN=%q for a release the package loader cannot drive", tc)
		}
		if switched {
			t.Error("switched = true below the loader floor")
		}
		if !sameGoToolchain(scan, local) {
			t.Errorf("scanToolchain = %q, want the analyzer's own %q", scan, local)
		}
	})

	t.Run("unfetchable release: falls back, reports the analyzer's toolchain", func(t *testing.T) {
		// GOPROXY=off makes the toolchain fetch fail deterministically and OFFLINE, so this
		// exercises the fetch-failure arm — the production no-network case — without the
		// hermetic suite reaching the network to discover that go1.99.99 does not exist.
		offline := append(slices.Clone(base), "GOPROXY=off")
		env, scan, switched := subjectToolchainEnv(context.Background(), offline, dir, "go1.99.99")
		if tc := goToolchainOf(env); tc != "" {
			t.Errorf("returned an env pinned to GOTOOLCHAIN=%q after the fetch failed", tc)
		}
		if switched {
			t.Error("switched = true after a failed fetch")
		}
		if scan == "go1.99.99" {
			t.Fatal("scanToolchain claims the unfetchable toolchain ran — the fallback must never claim the subject was scanned")
		}
		if !sameGoToolchain(scan, local) {
			t.Errorf("scanToolchain = %q, want the analyzer's own %q", scan, local)
		}
	})

	t.Run("junk version: falls back", func(t *testing.T) {
		offline := append(slices.Clone(base), "GOPROXY=off")
		env, scan, switched := subjectToolchainEnv(context.Background(), offline, dir, "not-a-version")
		if goToolchainOf(env) != "" || switched {
			t.Errorf("pinned a junk toolchain (switched=%t)", switched)
		}
		if scan == "not-a-version" {
			t.Error("scanToolchain echoed the junk request")
		}
	})
}

// TestGoEnvVersion_UnknownOnFailure pins the "unknown, never a guess" contract: a directory the go
// command cannot resolve yields "", which upstream reads as "not the subject's toolchain".
func TestGoEnvVersion_UnknownOnFailure(t *testing.T) {
	dir := scratchModule(t, "1.21")
	// A cancelled context makes the probe fail deterministically without depending on a
	// filesystem or toolchain state we do not control.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := goEnvVersion(ctx, dir, reachBaseEnv()); got != "" {
		t.Errorf("goEnvVersion with a cancelled context = %q, want \"\"", got)
	}
	if got := goEnvVersion(context.Background(), filepath.Join(dir, "no-such-dir"), reachBaseEnv()); got != "" {
		t.Errorf("goEnvVersion on a missing dir = %q, want \"\"", got)
	}
}
