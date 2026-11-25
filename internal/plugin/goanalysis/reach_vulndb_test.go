package goanalysis

import (
	"context"
	"slices"
	"testing"
)

// TestGovulncheckArgsVulnDB pins the database flag: ASSAY_GO_VULN_DB becomes govulncheck's -db only
// when the run's env sets it non-empty, and an unset one leaves the command line as it always was, so
// govulncheck reads its default database.
func TestGovulncheckArgsVulnDB(t *testing.T) {
	base := []string{"-C", "/src", "-json", "-mode=source", "-scan=symbol"}
	tests := []struct {
		name string
		env  []string
		want []string
	}{
		{name: "unset", env: []string{"GOWORK=off"}, want: append(slices.Clone(base), "./...")},
		{name: "empty", env: []string{"ASSAY_GO_VULN_DB="}, want: append(slices.Clone(base), "./...")},
		{name: "longer name is another variable", env: []string{"ASSAY_GO_VULN_DBX=file:///x"}, want: append(slices.Clone(base), "./...")},
		{name: "set", env: []string{"GOWORK=off", "ASSAY_GO_VULN_DB=file:///floor/govulndb"},
			want: append(slices.Clone(base), "-db", "file:///floor/govulndb", "./...")},
		{name: "last setting wins", env: []string{"ASSAY_GO_VULN_DB=file:///a", "ASSAY_GO_VULN_DB=file:///b"},
			want: append(slices.Clone(base), "-db", "file:///b", "./...")},
		{name: "last setting empty", env: []string{"ASSAY_GO_VULN_DB=file:///a", "ASSAY_GO_VULN_DB="}, want: append(slices.Clone(base), "./...")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := govulncheckArgs("/src", tt.env, []string{"./..."}); !slices.Equal(got, tt.want) {
				t.Errorf("govulncheckArgs = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGovulncheckCachedSeparatesVulnDB pins that the run cache keys a stream by the database it was
// read from: a run against another database, or against the default one, never gets a stream
// another database produced.
func TestGovulncheckCachedSeparatesVulnDB(t *testing.T) {
	const buildDir = "/src"
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	runs := map[string]int{}
	call := func(env []string) string {
		t.Helper()
		db := envValue(env, goVulnDBEnv)
		out, err := govulncheckCached(ctx, buildDir, env, true, func() ([]byte, error) {
			runs[db]++
			return []byte(`{"db":"` + db + `"}` + "\n"), nil
		})
		if err != nil {
			t.Fatalf("govulncheckCached(%q): %v", env, err)
		}
		return string(out)
	}
	unset := []string{"GOWORK=off"}
	a := []string{"GOWORK=off", "ASSAY_GO_VULN_DB=file:///a"}
	b := []string{"GOWORK=off", "ASSAY_GO_VULN_DB=file:///b"}
	for range 2 {
		for _, tc := range []struct {
			env  []string
			want string
		}{
			{unset, `{"db":""}` + "\n"},
			{a, `{"db":"file:///a"}` + "\n"},
			{b, `{"db":"file:///b"}` + "\n"},
		} {
			if got := call(tc.env); got != tc.want {
				t.Errorf("stream under %q = %q, want %q", tc.env, got, tc.want)
			}
		}
	}
	for _, db := range []string{"", "file:///a", "file:///b"} {
		if runs[db] != 1 {
			t.Errorf("database %q streamed %d times, want 1 (cached once per database)", db, runs[db])
		}
	}
}
