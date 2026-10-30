package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// leftPadOSV reports FERRALON-JAVA-DEP-0001 against left-pad on every query.
type leftPadOSV struct{}

func (leftPadOSV) QueryBatch(context.Context, []report.Package) (trigger.OSVResult, error) {
	return trigger.OSVResult{Advisories: []trigger.OSVAdvisory{{
		ID: "FERRALON-JAVA-DEP-0001", Package: report.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.4.0"},
	}}}, nil
}

// An advisory a cve-watch run assessed while its registry refused the token is never kept at the
// verdict that run reached: it comes out undetermined dependency_not_fetched, and the next
// cve-watch run assesses it again although OSV reports nothing new, restoring the verdict once the
// registry serves. The fetches are real, against a local registry standing in for
// registry.npmjs.org. The advisory is a Maven one, which a JS scan disqualifies on ecosystem
// whatever it reads, so the verdict every run that assesses it reaches is disqualified: the refused
// run's is withheld for how the run went, not for what it found.
func TestCVEWatchRefusedTokenThenServing(t *testing.T) {
	const id = "FERRALON-JAVA-DEP-0001"
	tgz := leftPad140(t)
	var refuse atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(tgz)
	}))
	t.Cleanup(srv.Close)
	backend, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, backend.Host)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // hermetic self-signed test cert
	}}
	t.Setenv("NPM_TOKEN", "test-token")
	dir := writeLeftPadApp(t, "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
	lockPath := filepath.Join(dir, "package-lock.json")
	lock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(tgz)
	pinned := strings.ReplaceAll(string(lock), "1.3.0", "1.4.0")
	pinned = strings.ReplaceAll(pinned, base64.StdEncoding.EncodeToString(leftPadSRI()), base64.StdEncoding.EncodeToString(sum[:]))
	if err := os.WriteFile(lockPath, []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store := statestore.NewMemStore()
	subject := trigger.Subject{Repo: "app", Revision: "main", ResolvedCommit: "abc123"}
	codebase := assessment.CodebaseRef{Repo: "app", Revision: "main", Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir}}
	workSet := []assessment.VulnRef{{ID: id, Source: "corpus"}}
	newRun := func() (*depCodeRun, []pipeline.AssessOption) {
		run := &depCodeRun{source: report.DependencyCodeSourceFetch}
		acq := pipeline.DependencyAcquisition{Mode: pipeline.DependencyCodeFetch, CacheDir: t.TempDir(), LookupEnv: os.LookupEnv, Client: client, Observe: run.observe}
		return run, []pipeline.AssessOption{pipeline.WithPlugin(&inProcessJS{}), pipeline.WithDependencyAcquisition(acq)}
	}
	row := func(rep *report.Report) report.AdvisoryFinding {
		t.Helper()
		for _, f := range rep.Advisories {
			if f.Advisory.ID == id {
				return f
			}
		}
		t.Fatalf("no %s row in %+v", id, rep.Advisories)
		return report.AdvisoryFinding{}
	}
	stored := func() *statestore.DepFetch {
		t.Helper()
		st, err := store.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st.DepFetch
	}
	watch := func() (*trigger.CVEWatchResult, *depCodeRun) {
		t.Helper()
		run, opts := newRun()
		res, err := trigger.RunCVEWatch(ctx, store, leftPadOSV{}, cveWatchRequest(&runConfig{
			subject: subject, codebase: codebase, assessOptions: opts, advisories: workSet, deps: run,
		}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return res, run
	}

	run, opts := newRun()
	base, err := trigger.RunBaseline(ctx, store, trigger.BaselineRequest{
		Subject: subject, Codebase: codebase, Advisories: workSet, AssessOptions: opts, DependencyFetch: run.fetchUpdate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if f := row(base); f.Verdict != report.VerdictDisqualified || run.err() != nil {
		t.Fatalf("baseline: %s %s, exit %v", f.Verdict, f.UndeterminedReason, run.err())
	}

	refuse.Store(true)
	res, run := watch()
	var de *depFetchError
	if res.Heartbeat || !errors.As(run.err(), &de) || de.Kind != kindCredentialRejected {
		t.Fatalf("refused run: heartbeat %v, exit %v", res.Heartbeat, run.err())
	}
	if f := row(res.Report); f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonDependencyNotFetched {
		t.Fatalf("refused run kept %s %s, want undetermined %s", f.Verdict, f.UndeterminedReason, report.ReasonDependencyNotFetched)
	}
	if dep := stored(); dep == nil || !slices.Contains(dep.Reassess, id) {
		t.Fatalf("refused run left reassess %+v", dep)
	}
	summary := tier0Summary(t, res.Report, run)
	for _, want := range []string{"registry.npmjs.org", "refused the token this run sent", "curation proxy", "last assessed on a run that did not read all the npm dependency code"} {
		if !strings.Contains(summary, want) {
			t.Errorf("refused run's job summary lacks %q", want)
		}
	}
	t.Logf("refused run's job summary:\n%s", summary)

	refuse.Store(false)
	res, run = watch()
	if res.Heartbeat || len(res.NewAdvisories) != 0 || !slices.Equal(res.Reassessed, []string{id}) || run.err() != nil {
		t.Fatalf("serving run: heartbeat %v, new %v, reassessed %v, exit %v", res.Heartbeat, res.NewAdvisories, res.Reassessed, run.err())
	}
	if f := row(res.Report); f.Verdict != report.VerdictDisqualified {
		t.Fatalf("serving run: %s %s, want disqualified", f.Verdict, f.UndeterminedReason)
	}
	if dep := stored(); dep != nil && slices.Contains(dep.Reassess, id) {
		t.Fatalf("serving run left %s on reassess", id)
	}
	if res, _ = watch(); !res.Heartbeat {
		t.Fatalf("third run is earnest: new %v, reassessed %v", res.NewAdvisories, res.Reassessed)
	}
}

// tier0Summary is the job summary run's Report publishes, with its dependency fetch notes.
func tier0Summary(t *testing.T, rep *report.Report, run *depCodeRun) string {
	t.Helper()
	run.stamp(rep)
	res, err := buildResult(rep)
	if err != nil {
		t.Fatal(err)
	}
	res.DependencyFetch = run.fetchNotes()
	path := filepath.Join(t.TempDir(), "summary.md")
	if err := (&ghsink.Tier0Summary{SummaryPath: path}).Publish(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftPad140 is an npm tarball of a left-pad 1.4.0 stand-in.
func leftPad140(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"package/package.json": `{"name": "left-pad", "version": "1.4.0", "main": "index.js"}`,
		"package/index.js":     "module.exports = function leftPad(s, n) { return s; };\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newAdvisoryOSV reports one advisory, new to any cursor that does not hold it.
type newAdvisoryOSV struct{ id string }

func (o newAdvisoryOSV) QueryBatch(context.Context, []report.Package) (trigger.OSVResult, error) {
	return trigger.OSVResult{Advisories: []trigger.OSVAdvisory{{
		ID: o.id, Package: report.Package{Ecosystem: "Go", Name: "example.com/m", Version: "v1.0.0"},
	}}}, nil
}

// On a state ref a JS scan shares with a scan of another language, only a JS run ever clears the
// reassess list, so every row of a listed advisory that the other language's runs write stays
// withheld for good. A JS cve-watch run that had one package refused lists only the advisory on
// that package, so the other language's next write withholds that advisory's row and keeps the
// verdict of the advisory on a package the JS run read.
func TestSharedRefNonJSWriteWithholdsOnlyTheMissedPackage(t *testing.T) {
	const npmjs, corp = "https://registry.npmjs.org/", "https://npm.corp.example/"
	ctx := context.Background()
	readPkg := report.Package{Ecosystem: "npm", Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"}
	missedPkg := report.Package{Ecosystem: "npm", Name: "@corp/b", Version: "1.0.0", PURL: "pkg:npm/%40corp/b@1.0.0"}

	js := &depCodeRun{source: report.DependencyCodeSourceFetch}
	js.observe(pipeline.DependencyAcquisitionResult{Mode: "fetch", Outcomes: []pipeline.DependencyOutcome{
		{PURL: "pkg:npm/a@1.0.0", Registry: npmjs, Outcome: pipeline.OutcomeReadNetwork},
		{PURL: "pkg:npm/@corp/b@1.0.0", Registry: corp, Outcome: pipeline.UnreadPolicyRefused},
	}})
	rec := js.fetchUpdate()(nil, trigger.DependencyFetchRun{
		Assessed: []report.Advisory{{ID: "GHSA-read"}, {ID: "GHSA-missed"}},
		Packages: map[string][]string{"GHSA-read": {readPkg.PURL, "pkg:npm/a"}, "GHSA-missed": {missedPkg.PURL, "pkg:npm/%40corp/b"}},
	})
	if rec == nil {
		t.Fatal("the JS run left no record")
	}
	if !slices.Equal(rec.Reassess, []string{"GHSA-missed"}) {
		t.Errorf("the JS run listed %q, want [GHSA-missed]", rec.Reassess)
	}

	rep := report.NewBuilder(report.Subject{Repo: "app", ResolvedCommit: "abc123"}).
		AddPackage(readPkg).
		AddPackage(missedPkg).
		Disqualified(report.Advisory{ID: "GHSA-read", Source: "corpus"}, &readPkg, verdict.BasisVersionNotAffected, "1.0.0 is outside the range").
		Disqualified(report.Advisory{ID: "GHSA-missed", Source: "corpus"}, &missedPkg, verdict.BasisVersionNotAffected, "1.0.0 is outside the range").
		WithProvenance(report.Provenance{CommitSHA: "abc123"}).
		Build()
	store := statestore.NewMemStore()
	if _, err := store.Write(ctx, &statestore.State{Report: &rep, SBOM: rep.SBOM, DepFetch: rec}); err != nil {
		t.Fatal(err)
	}

	other := &runConfig{
		subject:  trigger.Subject{Repo: "app", Revision: "main", ResolvedCommit: "abc123"},
		codebase: assessment.CodebaseRef{Repo: "app", Revision: "main", Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: t.TempDir()}},
	}
	req := cveWatchRequest(other, nil)
	if req.DependencyFetch != nil {
		t.Fatal("the other language's run has a dependency-fetch hook")
	}
	res, err := trigger.RunCVEWatch(ctx, store, newAdvisoryOSV{id: "GO-2026-0001"}, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Heartbeat {
		t.Fatal("the other language's run wrote nothing")
	}
	st, err := store.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.DepFetch == nil || !slices.Equal(st.DepFetch.Reassess, rec.Reassess) {
		t.Fatalf("the other language's run changed the record to %+v", st.DepFetch)
	}
	for id, want := range map[string]report.Verdict{"GHSA-read": report.VerdictDisqualified, "GHSA-missed": report.VerdictUndetermined} {
		var rows int
		for _, f := range st.Report.Advisories {
			if f.Advisory.ID != id {
				continue
			}
			rows++
			if f.Verdict != want {
				t.Errorf("%s row %s/%q, want %s", id, f.Verdict, f.UndeterminedReason, want)
			}
			if want == report.VerdictUndetermined && f.UndeterminedReason != report.ReasonDependencyNotFetched {
				t.Errorf("%s row withheld as %q, want %s", id, f.UndeterminedReason, report.ReasonDependencyNotFetched)
			}
		}
		if rows == 0 {
			t.Errorf("no %s row in the stored report", id)
		}
	}
}
