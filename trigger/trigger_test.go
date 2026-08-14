package trigger

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// --- OSV client (mocked transport) -------------------------------------------

// TestParseOSVResponse_PositionalAttribution proves the positional querybatch
// response is mapped back onto the queried packages, with per-id de-duplication.
func TestParseOSVResponse_PositionalAttribution(t *testing.T) {
	pkgs := []report.Package{
		{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"},
		{Ecosystem: "Go", Name: "github.com/safe/pkg", Version: "v1.0.0"},
	}
	// Fixture modeled on the OSV.dev querybatch shape: results[] positional to queries[].
	body := []byte(`{"results":[
		{"vulns":[{"id":"GO-2021-0113"},{"id":"GHSA-dup"},{"id":"GHSA-dup"}]},
		{"vulns":[]}
	]}`)

	res, err := parseOSVResponse(body, pkgs)
	if err != nil {
		t.Fatalf("parseOSVResponse: %v", err)
	}
	ids := res.IDs()
	if len(ids) != 2 {
		t.Fatalf("want 2 de-duplicated ids, got %v", ids)
	}
	for _, a := range res.Advisories {
		if a.Package.Name != "golang.org/x/text" {
			t.Fatalf("advisory %q attributed to wrong package %q", a.ID, a.Package.Name)
		}
	}
}

// TestHTTPOSVClient_QueryBatch_CoordinateForm proves the wire request uses OSV's
// {ecosystem, name} + version coordinate form and never emits a "purl" key, even
// when the SBOM package carries a PURL. OSV rejects a query that pairs a purl with
// a name ("name specified in a PURL query", HTTP 400) — this guards that seam.
func TestHTTPOSVClient_QueryBatch_CoordinateForm(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-2021-0113"}]}]}`))
	}))
	defer srv.Close()

	client := &HTTPOSVClient{URL: srv.URL}
	pkgs := []report.Package{{
		Ecosystem: "Go",
		Name:      "golang.org/x/text",
		Version:   "v0.3.6",
		PURL:      "pkg:golang/golang.org/x/text@v0.3.6",
	}}
	res, err := client.QueryBatch(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if ids := res.IDs(); len(ids) != 1 || ids[0] != "GO-2021-0113" {
		t.Fatalf("want [GO-2021-0113], got %v", ids)
	}

	var sent struct {
		Queries []struct {
			Version string                     `json:"version"`
			Package map[string]json.RawMessage `json:"package"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("decode sent body: %v\n%s", err, gotBody)
	}
	if len(sent.Queries) != 1 {
		t.Fatalf("want 1 query, got %d", len(sent.Queries))
	}
	q := sent.Queries[0]
	if _, ok := q.Package["purl"]; ok {
		t.Fatalf("query must not carry a purl alongside name; OSV rejects it: %s", gotBody)
	}
	if string(q.Package["ecosystem"]) != `"Go"` || string(q.Package["name"]) != `"golang.org/x/text"` {
		t.Fatalf("coordinate form missing/incorrect: %s", gotBody)
	}
	if q.Version != "v0.3.6" {
		t.Fatalf("want version v0.3.6, got %q", q.Version)
	}
}

// --- Baseline: real git-ref StateStore against a temp bare repo ---------------

// TestRunBaseline_RealGitRefStore exercises the full baseline flow against the REAL
// statestore git-ref implementation (temp bare repo, mirroring H's tests): compose
// AssessStages → Report → store. It then reads the ref back and asserts the Report
// round-tripped with deterministic verdicts.
func TestRunBaseline_RealGitRefStore(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--bare", "-q")
	store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})

	req := BaselineRequest{
		Subject:  Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "abc123"},
		Codebase: assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
		Advisories: []assessment.VulnRef{
			{ID: "GO-2021-0113", Source: "osv"},
			{ID: "FERRALON-APP-SSRF-0001", Source: "osv"},
		},
		Cursor: "GO-2021-0113",
	}

	rep, err := RunBaseline(context.Background(), store, req)
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if rep == nil || len(rep.Advisories) != 2 {
		t.Fatalf("want 2 findings, got %+v", rep)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("baseline report invalid (inv. 5): %v", err)
	}

	// Read the ref back through the real store and confirm durability.
	state, err := store.Read(context.Background())
	if err != nil {
		t.Fatalf("Read after baseline: %v", err)
	}
	if state.Report == nil || len(state.Report.Advisories) != 2 {
		t.Fatalf("stored report missing findings: %+v", state.Report)
	}
	if state.Cursor != "GO-2021-0113" {
		t.Fatalf("stored cursor = %q, want GO-2021-0113", state.Cursor)
	}
	if len(state.SBOM.Packages) != len(state.Report.SBOM.Packages) {
		t.Fatalf("state SBOM and report SBOM diverged")
	}
}

// --- PR-inherit: fast-path vs re-analyze decision ----------------------------

func seedBaseline(t *testing.T) (*memStore, *report.Report) {
	t.Helper()
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		ReachableCandidate(report.Advisory{ID: "GO-2021-0113", Source: "osv"}, &pkg, "h → s", "").
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: "GO-2021-0113"}).
		Build()
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: "GO-2021-0113"}}
	return store, &baseline
}

// TestRunPRInherit_FastPath proves an unchanged dependency set inherits the baseline
// with NO re-analysis and NO write.
func TestRunPRInherit_FastPath(t *testing.T) {
	store, baseline := seedBaseline(t)

	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		PRSBOM:     baseline.SBOM, // identical deps
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("want fast-path inherit, got re-analysis (changed=%v)", res.ChangedPackages)
	}
	if store.writes != 0 {
		t.Fatalf("fast path must not write state, got %d writes", store.writes)
	}
	if res.Report.Baseline == nil {
		t.Fatalf("inherited report must carry a Baseline pointer")
	}
	if res.Report.Subject.ResolvedCommit != "pr-sha" {
		t.Fatalf("inherited report subject not re-pointed to the PR head")
	}
}

// TestRunPRInherit_ReanalyzeOnChangedDep proves a version bump triggers re-analysis
// of the affected slice and a write.
func TestRunPRInherit_ReanalyzeOnChangedDep(t *testing.T) {
	store, _ := seedBaseline(t)

	prSBOM := report.SBOM{Packages: []report.Package{
		{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.9.9"}, // bumped
	}}

	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		PRSBOM:     prSBOM,
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if res.Inherited {
		t.Fatalf("want re-analysis on changed dep, got fast-path")
	}
	if len(res.ChangedPackages) != 1 {
		t.Fatalf("want 1 changed package, got %v", res.ChangedPackages)
	}
	if store.writes != 1 {
		t.Fatalf("re-analysis must write state once, got %d", store.writes)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("re-analyzed report invalid: %v", err)
	}
}

// TestRunPRInherit_NoBaseline proves PR-inherit refuses to run without a baseline.
func TestRunPRInherit_NoBaseline(t *testing.T) {
	store := &memStore{}
	_, err := RunPRInherit(context.Background(), store, PRInheritRequest{})
	if err != ErrNoBaseline {
		t.Fatalf("want ErrNoBaseline, got %v", err)
	}
}

// --- CVE-watch: heartbeat vs scoped earnest run (OSV mocked) ------------------

// TestRunCVEWatch_NoOverlapHeartbeat proves that when OSV.dev returns only advisories
// already in the cursor, the run heartbeats: cursor-only write, no new Report.
func TestRunCVEWatch_NoOverlapHeartbeat(t *testing.T) {
	store, baseline := seedBaseline(t)
	pkg := baseline.SBOM.Packages[0]

	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
		{ID: "GO-2021-0113", Package: pkg}, // already in cursor
	}}}

	res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "sha"},
		Codebase: assessment.CodebaseRef{Repo: "r"},
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !res.Heartbeat {
		t.Fatalf("want heartbeat, got earnest run (new=%v)", res.NewAdvisories)
	}
	if res.Report != nil {
		t.Fatalf("heartbeat must not produce a new Report")
	}
	if osv.calls != 1 {
		t.Fatalf("want exactly one OSV querybatch call, got %d", osv.calls)
	}
	// Heartbeat must reuse the existing Report object, not rebuild it (cursor-only write).
	if store.lastSeen.Report != baseline {
		t.Fatalf("heartbeat must reuse the existing Report object, not rebuild it")
	}
}

// TestRunCVEWatch_OverlapEarnestRun proves a newly-relevant advisory (not in the
// cursor) forces a scoped earnest run that re-analyzes and writes a new Report.
func TestRunCVEWatch_OverlapEarnestRun(t *testing.T) {
	store, _ := seedBaseline(t)
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}

	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
		{ID: "GO-2021-0113", Package: pkg},           // already in cursor
		{ID: "FERRALON-APP-SSRF-0001", Package: pkg}, // NEW → forces earnest run
	}}}

	res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "sha"},
		Codebase: assessment.CodebaseRef{Repo: "r"},
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat {
		t.Fatalf("want earnest run on overlap, got heartbeat")
	}
	if len(res.NewAdvisories) != 1 || res.NewAdvisories[0] != "FERRALON-APP-SSRF-0001" {
		t.Fatalf("want NewAdvisories=[FERRALON-APP-SSRF-0001], got %v", res.NewAdvisories)
	}
	if res.Report == nil {
		t.Fatalf("earnest run must produce a Report")
	}
	if store.writes != 1 {
		t.Fatalf("earnest run must write once, got %d", store.writes)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("earnest report invalid: %v", err)
	}
	// The new advisory must appear in the re-analyzed Report.
	found := false
	for _, f := range res.Report.Advisories {
		if f.Advisory.ID == "FERRALON-APP-SSRF-0001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("earnest report missing the newly-relevant advisory")
	}
}

// TestRunCVEWatch_OSVError surfaces the OSV transport error (no silent swallow).
func TestRunCVEWatch_OSVError(t *testing.T) {
	store, _ := seedBaseline(t)
	osv := &fakeOSV{err: errFakeOSV}
	_, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{})
	if err == nil {
		t.Fatalf("want OSV error surfaced, got nil")
	}
}
