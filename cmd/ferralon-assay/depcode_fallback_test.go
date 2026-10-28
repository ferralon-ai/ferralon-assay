package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// inProcessJS is the real JS lane called in process, recording the dependency cache each
// call that can read dependency code was handed.
type inProcessJS struct {
	plugin.StubPlugin
	mu     sync.Mutex
	caches []string
}

func (*inProcessJS) Language() string { return "js" }

func (p *inProcessJS) saw(cache string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.caches = append(p.caches, cache)
}

func (*inProcessJS) IndexSymbols(ctx context.Context, req plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	return jsanalysis.IndexSymbols(ctx, req)
}

func (p *inProcessJS) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	p.saw(req.DependencyCache)
	return jsanalysis.ResolveDependencySymbols(ctx, req)
}

func (*inProcessJS) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return jsanalysis.ResolveDependencyVersions(ctx, req)
}

func (p *inProcessJS) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	p.saw(req.DependencyCache)
	return jsanalysis.CallGraph(ctx, req)
}

func (*inProcessJS) FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return jsanalysis.FindIngresses(ctx, req)
}

func (p *inProcessJS) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	p.saw(req.DependencyCache)
	return jsanalysis.Reachability(ctx, req)
}

func (p *inProcessJS) ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	p.saw(req.DependencyCache)
	return jsanalysis.ComputeTaint(ctx, req)
}

func (*inProcessJS) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return jsanalysis.BuildManifest(ctx, req)
}

func (*inProcessJS) ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return jsanalysis.ResolveInventory(ctx, req)
}

// leftPadTarball stands in for left-pad 1.3.0's tarball; the lock pins its SRI.
var leftPadTarball = []byte("left-pad 1.3.0 tarball")

func leftPadSRI() []byte {
	sum := sha512.Sum512(leftPadTarball)
	return sum[:]
}

// writeLeftPadApp writes a JS app that calls left-pad 1.3.0, inside FERRALON-JS-DEP-0001's range,
// with npmrc as its project .npmrc (none when npmrc is empty).
func writeLeftPadApp(t *testing.T, npmrc string) string {
	t.Helper()
	dir := t.TempDir()
	lock := `{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": {
  "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
  "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    "integrity": "sha512-` + base64.StdEncoding.EncodeToString(leftPadSRI()) + `"}}}`
	files := map[string]string{
		"package.json":      `{"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}`,
		"package-lock.json": lock,
		"index.js":          "const leftPad = require('left-pad');\nconsole.log(leftPad(process.argv[2], 5));\n",
	}
	if npmrc != "" {
		files[".npmrc"] = npmrc
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scanJS runs a baseline over dir with the -dependency-* flags given, the way runBaseline does,
// and returns the published Report, the run's exit error and the caches the lane was handed.
func scanJS(t *testing.T, dir, mode, cache, timeout string) (*report.Report, error, []string) {
	t.Helper()
	t.Setenv(envDependencyCode, "")
	t.Setenv(envDependencyCache, "")
	t.Setenv(envDependencyUncredCache, "")
	t.Setenv(envDependencyNPMRCEnv, "")
	t.Setenv(envDependencyTimeout, "")
	npmrcEnv := ""
	f := &runFlags{depCode: &mode, depCache: &cache, depUncredCache: new(string), depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
	p := &inProcessJS{}
	opts := []pipeline.AssessOption{pipeline.WithPlugin(p)}
	depOpt, err := f.dependencyCodeOption()
	if err != nil {
		t.Fatal(err)
	}
	if depOpt != nil {
		opts = append(opts, depOpt)
	}
	rep, err := trigger.RunBaseline(context.Background(), statestore.NewMemStore(), trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: "app", Revision: "main", ResolvedCommit: "abc123"},
		Codebase: assessment.CodebaseRef{Repo: "app", Revision: "main",
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir}},
		Advisories:    []assessment.VulnRef{{ID: "FERRALON-JS-DEP-0001", Source: "corpus"}},
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatal(err)
	}
	deps := f.depRun.forLanguage("js")
	deps.stamp(rep)
	rep.Provenance.Timestamp = time.Time{}
	return rep, runExit(nil, deps), p.caches
}

// withoutDependencyCode is rep's JSON with the dependency_code field and the
// dependency_code_unavailable note removed: what is left must be the off run's Report.
func withoutDependencyCode(t *testing.T, rep *report.Report) string {
	t.Helper()
	r := *rep
	r.DependencyCode = nil
	r.Partiality = nil
	for _, n := range rep.Partiality {
		if n.Reason != report.PartialReasonDependencyCodeUnavailable {
			r.Partiality = append(r.Partiality, n)
		}
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A JS scan whose fetch fails publishes the Report the same tree publishes with
// -dependency-code=off, plus the dependency_code field and the named reason, and exits as off
// does. Each failure is produced by the real fetch path with no network: a credential the
// repository's .npmrc requires and does not supply, a registry nothing listens on, and a
// deadline. The control seeds an offline cache, so the lane is handed one when nothing fails.
func TestDependencyCodeFetchFailureRunsAsOff(t *testing.T) {
	tests := []struct {
		name, npmrc, timeout, wantKind string
	}{
		{name: "credential required and unset", npmrc: "//registry.npmjs.org/:_authToken=\n", wantKind: pipeline.UnreadPolicyRefused},
		{name: "registry unreachable", npmrc: "registry=https://127.0.0.1:1/\n", wantKind: pipeline.UnreadFetchFailed},
		{name: "deadline", npmrc: "registry=https://127.0.0.1:1/\n", timeout: "1ns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeLeftPadApp(t, tt.npmrc)
			offRep, offErr, offCaches := scanJS(t, dir, "off", "", "")
			if len(offCaches) == 0 {
				t.Fatal("the lane never ran: the comparison would be vacuous")
			}
			for _, c := range offCaches {
				if c != "" {
					t.Fatalf("off run handed the lane cache %q", c)
				}
			}
			if dc := offRep.DependencyCode; dc == nil || dc.Source != report.DependencyCodeSourceOff || dc.Cause != nil {
				t.Fatalf("off dependency_code = %+v", offRep.DependencyCode)
			}

			rep, exit, caches := scanJS(t, dir, "", t.TempDir(), tt.timeout)
			if (exit != nil) != (offErr != nil) {
				t.Fatalf("exit = %v, off exit = %v", exit, offErr)
			}
			for _, c := range caches {
				if c != "" {
					t.Fatalf("lane handed cache %q after a failed fetch", c)
				}
			}
			dc := rep.DependencyCode
			if dc == nil || dc.Source != report.DependencyCodeSourceFetch || dc.Cause == nil {
				t.Fatalf("dependency_code = %+v, want source fetch with a cause", dc)
			}
			if tt.wantKind != "" && dc.Cause.Kind != tt.wantKind {
				t.Fatalf("cause = %+v, want kind %s", dc.Cause, tt.wantKind)
			}
			var note *report.PartialityNote
			for i, n := range rep.Partiality {
				if n.Reason == report.PartialReasonDependencyCodeUnavailable {
					note = &rep.Partiality[i]
				}
			}
			if note == nil || note.Ecosystem != "npm" || note.Class != report.PartialityDidNotRun || note.Detail != describeCause(dc.Cause) {
				t.Fatalf("note = %+v, want tool_failure:dependency_code_unavailable (npm, did_not_run) naming %+v", note, dc.Cause)
			}
			if got, off := withoutDependencyCode(t, rep), withoutDependencyCode(t, offRep); got != off {
				t.Fatalf("report differs from the off run beyond dependency_code:\n--- fallback\n%s\n--- off\n%s", got, off)
			}
		})
	}

	t.Run("control: a seeded cache is handed to the lane", func(t *testing.T) {
		cache := t.TempDir()
		h := hex.EncodeToString(leftPadSRI())
		if err := os.MkdirAll(filepath.Join(cache, "sha512", h[:2]), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, "sha512", h[:2], h), leftPadTarball, 0o644); err != nil {
			t.Fatal(err)
		}
		rep, exit, caches := scanJS(t, writeLeftPadApp(t, ""), "offline", cache, "")
		if exit != nil {
			t.Fatalf("exit = %v", exit)
		}
		handed := false
		for _, c := range caches {
			handed = handed || c != ""
		}
		if !handed {
			t.Fatal("the lane was never handed the seeded cache")
		}
		if dc := rep.DependencyCode; dc == nil || dc.Source != report.DependencyCodeSourceOffline || dc.Cause != nil {
			t.Fatalf("dependency_code = %+v", dc)
		}
	})
}
