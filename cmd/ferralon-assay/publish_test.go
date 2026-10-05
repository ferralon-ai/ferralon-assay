package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestPublishAllSurfaceFailuresAreBestEffort drives the real Tier 1 Issue and PR-comment
// sinks against a fake GitHub that refuses or fails their writes, and checks that only a
// load-bearing sink decides publishAll's error, while every surface failure lands as a
// ::warning:: and a job-summary note.
func TestPublishAllSurfaceFailuresAreBestEffort(t *testing.T) {
	tests := []struct {
		name          string
		issueStatus   int // POST /issues
		commentStatus int // POST /issues/7/comments
		localFails    bool
		wantErr       bool
		wantSummary   []string // substrings; nil means the summary file must not be written
		wantWarnings  int
	}{
		{
			name:          "every write succeeds",
			issueStatus:   http.StatusCreated,
			commentStatus: http.StatusCreated,
		},
		{
			name:          "Issues disabled: create returns 410",
			issueStatus:   http.StatusGone,
			commentStatus: http.StatusCreated,
			wantSummary:   []string{"Surfaces not updated", "dashboard Issue write (HTTP 410)", "Issues may be disabled", "`issue: false`"},
			wantWarnings:  1,
		},
		{
			name:          "Issues disabled: create returns 404",
			issueStatus:   http.StatusNotFound,
			commentStatus: http.StatusCreated,
			wantSummary:   []string{"dashboard Issue write (HTTP 404)", "`issue: false`"},
			wantWarnings:  1,
		},
		{
			name:          "PR comment forbidden: create returns 403",
			issueStatus:   http.StatusCreated,
			commentStatus: http.StatusForbidden,
			wantSummary:   []string{"pull request comment write (HTTP 403)", "`pull-requests: write`", "`pr-comment: false`"},
			wantWarnings:  1,
		},
		{
			name:          "both surfaces refused",
			issueStatus:   http.StatusGone,
			commentStatus: http.StatusForbidden,
			wantSummary:   []string{"dashboard Issue write (HTTP 410)", "pull request comment write (HTTP 403)"},
			wantWarnings:  2,
		},
		{
			name:          "GitHub server error on the Issue",
			issueStatus:   http.StatusBadGateway,
			commentStatus: http.StatusCreated,
			wantSummary:   []string{"could not take the dashboard Issue write (HTTP 502)", "next run tries again"},
			wantWarnings:  1,
		},
		{
			name:          "Local output fails: still an error",
			issueStatus:   http.StatusCreated,
			commentStatus: http.StatusCreated,
			localFails:    true,
			wantErr:       true,
		},
		{
			name:          "Local output fails alongside a refused Issue: error is Local's alone",
			issueStatus:   http.StatusGone,
			commentStatus: http.StatusCreated,
			localFails:    true,
			wantErr:       true,
			wantSummary:   []string{"dashboard Issue write (HTTP 410)"},
			wantWarnings:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet:
					_, _ = w.Write([]byte("[]"))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repos/o/r/issues"):
					w.WriteHeader(tc.issueStatus)
					_, _ = w.Write([]byte(`{"number":1}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repos/o/r/issues/7/comments"):
					w.WriteHeader(tc.commentStatus)
					_, _ = w.Write([]byte(`{"id":1}`))
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusTeapot)
				}
			}))
			defer srv.Close()

			dir := t.TempDir()
			outDir := filepath.Join(dir, "out")
			if tc.localFails {
				// A regular file where the output directory should be: Local cannot create it.
				if err := os.WriteFile(outDir, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			summary := filepath.Join(dir, "summary.md")
			env := github.Env{InActions: true, Repository: "o/r", Token: "tok", ServerURL: srv.URL, PRNumber: 7}
			sinks := []resultsink.ResultSink{
				resultsink.NewLocal(outDir),
				github.NewTier1PRComment(env, srv.Client()),
				github.NewTier1Issue(env, srv.Client()),
			}

			var warn bytes.Buffer
			err := publishAll(context.Background(), sinks, resultsink.Result{}, summary, &warn)

			if (err != nil) != tc.wantErr {
				t.Fatalf("publishAll error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "unexpected status") {
				t.Fatalf("a surface failure leaked into the run's error: %v", err)
			}
			if got := strings.Count(warn.String(), "::warning "); got != tc.wantWarnings {
				t.Fatalf("%d ::warning:: lines, want %d:\n%s", got, tc.wantWarnings, warn.String())
			}

			b, readErr := os.ReadFile(summary)
			if tc.wantSummary == nil {
				if !os.IsNotExist(readErr) {
					t.Fatalf("job summary written when no surface failed: %q (err %v)", b, readErr)
				}
				return
			}
			if readErr != nil {
				t.Fatalf("read job summary: %v", readErr)
			}
			for _, want := range tc.wantSummary {
				if !strings.Contains(string(b), want) {
					t.Errorf("job summary missing %q:\n%s", want, b)
				}
			}
		})
	}
}

// TestPublishAllTransportFailureIsBestEffort covers a surface that never reached GitHub:
// the run still succeeds and the note says the next run tries again.
func TestPublishAllTransportFailureIsBestEffort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // every request now fails to connect

	summary := filepath.Join(t.TempDir(), "summary.md")
	env := github.Env{InActions: true, Repository: "o/r", Token: "tok", ServerURL: url}
	var warn bytes.Buffer
	err := publishAll(context.Background(), []resultsink.ResultSink{github.NewTier1Issue(env, nil)}, resultsink.Result{}, summary, &warn)
	if err != nil {
		t.Fatalf("publishAll error = %v, want nil", err)
	}
	b, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read job summary: %v", err)
	}
	if !strings.Contains(string(b), "The dashboard Issue could not be updated; the next run tries again.") {
		t.Fatalf("job summary missing the transport note:\n%s", b)
	}
}

// TestPublishAllWithoutSummaryPath checks a surface failure outside a summary-capable run
// still warns and still does not fail.
func TestPublishAllWithoutSummaryPath(t *testing.T) {
	failing := github.NewTier1Issue(github.Env{Repository: "o/r", Token: "tok", ServerURL: "http://127.0.0.1:1"}, nil)
	var warn bytes.Buffer
	if err := publishAll(context.Background(), []resultsink.ResultSink{failing}, resultsink.Result{}, "", &warn); err != nil {
		t.Fatalf("publishAll error = %v, want nil", err)
	}
	if !strings.Contains(warn.String(), "::warning ") {
		t.Fatalf("no ::warning:: emitted:\n%s", warn.String())
	}
}
