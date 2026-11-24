package goanalysis

import (
	"strings"
	"testing"
)

// TestMatchOnlyResult: a MatchOnly answer is AnalyzerMatched when govulncheck reported the advisory
// at any level over the whole build. An osv entry alone is only an advisory govulncheck considered,
// and a partial run matches nothing and says so.
func TestMatchOnlyResult(t *testing.T) {
	const (
		osv        = `{"osv":{"id":"GO-2099-0001","aliases":["GHSA-xxxx-yyyy-zzzz"]}}`
		moduleOnly = `{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","version":"v1.0.0"}]}}`
		symbol     = `{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","package":"example.com/vuln","function":"Sink"}]}}`
		other      = `{"finding":{"osv":"GO-2099-0002","trace":[{"module":"example.com/vuln","version":"v1.0.0"}]}}`
	)
	for _, tc := range []struct {
		name    string
		stream  []string
		vulnID  string
		partial bool
		want    bool
	}{
		{"osv entry only", []string{osv}, "GO-2099-0001", false, false},
		{"module-level finding", []string{osv, moduleOnly}, "GO-2099-0001", false, true},
		{"symbol finding", []string{osv, symbol}, "GO-2099-0001", false, true},
		{"another advisory's finding", []string{osv, other}, "GO-2099-0001", false, false},
		{"partial run", []string{osv, symbol}, "GO-2099-0001", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanned, err := parseFindings([]byte(strings.Join(tc.stream, "\n")), tc.vulnID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.partial {
				scanned.partial = &partialRun{}
			}
			res := matchOnlyResult(scanned, "go1.24.0")
			if res.AnalyzerMatched != tc.want {
				t.Fatalf("AnalyzerMatched = %v, want %v", res.AnalyzerMatched, tc.want)
			}
			if res.Partiality.Complete == tc.partial {
				t.Fatalf("Partiality = %+v, want complete=%v", res.Partiality, !tc.partial)
			}
		})
	}
}
