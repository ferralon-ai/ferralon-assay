package goanalysis

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestParseFindings_ResolvesAliasThroughOSVEntries(t *testing.T) {
	const stream = `{"osv":{"id":"GO-2024-3321","aliases":["CVE-2024-45337","GHSA-v778-237x-gjrc"]}}
{"osv":{"id":"GO-2023-0001","aliases":["CVE-2023-0001"]}}
{"finding":{"osv":"GO-2024-3321","trace":[{"module":"golang.org/x/crypto","version":"v0.30.0"}]}}
{"finding":{"osv":"GO-2023-0001","trace":[{"module":"golang.org/x/net","version":"v0.1.0"}]}}
`
	cases := []struct {
		vulnID string
		want   []string
	}{
		{"GO-2024-3321", []string{"GO-2024-3321"}},
		{"CVE-2024-45337", []string{"GO-2024-3321"}},
		{"GHSA-v778-237x-gjrc", []string{"GO-2024-3321"}},
		{"CVE-2099-0000", nil},
		{"", []string{"GO-2024-3321", "GO-2023-0001"}},
	}
	for _, tc := range cases {
		t.Run(tc.vulnID, func(t *testing.T) {
			scanned, err := parseFindings([]byte(stream), tc.vulnID)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range scanned.findings {
				got = append(got, f.OSV)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseFindings(%q) = %v, want %v", tc.vulnID, got, tc.want)
			}
		})
	}
}

// TestVulnerablePackages: an advisory's vulnerable packages in a module are those its OSV entries
// list for the module, plus those a package-level finding names; another advisory's do not count.
func TestVulnerablePackages(t *testing.T) {
	const stream = `{"osv":{"id":"GO-2025-0001","aliases":["CVE-2025-0001"],"affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"net/http"},{"path":"net/textproto"}]}},{"package":{"name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2"}]}}]}}
{"osv":{"id":"GO-2025-0002","affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"crypto/tls"}]}}]}}
{"finding":{"osv":"GO-2025-0001","trace":[{"module":"stdlib","version":"v1.22.0","package":"net/http/internal"}]}}
{"finding":{"osv":"GO-2025-0001","trace":[{"module":"stdlib","version":"v1.22.0"}]}}
`
	cases := []struct {
		vulnID, module string
		want           []string
	}{
		{"GO-2025-0001", "stdlib", []string{"net/http", "net/http/internal", "net/textproto"}},
		{"CVE-2025-0001", "stdlib", []string{"net/http", "net/http/internal", "net/textproto"}},
		{"GO-2025-0001", "golang.org/x/net", []string{"golang.org/x/net/http2"}},
		{"GO-2025-0002", "stdlib", []string{"crypto/tls"}},
		{"GO-2099-0000", "stdlib", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.vulnID+"/"+tc.module, func(t *testing.T) {
			scanned, err := parseFindings([]byte(stream), tc.vulnID)
			if err != nil {
				t.Fatal(err)
			}
			if got := scanned.vulnerablePackages(tc.module); !slices.Equal(got, tc.want) {
				t.Errorf("vulnerablePackages(%q) = %q, want %q", tc.module, got, tc.want)
			}
		})
	}
}

func TestEvidenceResult(t *testing.T) {
	moduleOnly := vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: "golang.org/x/net", Version: "v0.1.0"}}}
	packageOnly := vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: "golang.org/x/net", Version: "v0.1.0", Package: "golang.org/x/net/html"}}}
	symbol := vulnFinding{OSV: "GO-1", Trace: []vulnFrame{
		{Module: "golang.org/x/net", Version: "v0.1.0", Package: "golang.org/x/net/html", Function: "Parse"},
		{Module: "example.com/app", Package: "example.com/app", Function: "main"},
	}}
	unmoduled := vulnFinding{OSV: "GO-1"}
	complete := plugin.CallGraphResult{Partiality: plugin.Complete()}
	cgo := plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonCgo)}
	env := []string{"GOOS=linux", "GOARCH=arm64"}

	cases := []struct {
		name         string
		findings     []vulnFinding
		cg           plugin.CallGraphResult
		wantReasons  []string
		wantRefuted  string // Refutation.Package; "" = no refutation
		wantImported bool
		wantPaths    bool
	}{
		{name: "no finding: analyzer does not know the advisory",
			cg: complete, wantReasons: []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer}},
		{name: "no finding keeps call graph limits",
			cg: cgo, wantReasons: []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer, plugin.PartialReasonCgo}},
		{name: "module finding only: refutes the module",
			findings: []vulnFinding{moduleOnly}, cg: complete, wantRefuted: "pkg:golang/golang.org/x/net"},
		{name: "package finding, no symbol: refutes the module, package imported",
			findings: []vulnFinding{moduleOnly, packageOnly}, cg: complete,
			wantRefuted: "pkg:golang/golang.org/x/net", wantImported: true},
		{name: "refutation carries call graph limits for the gate to weigh",
			findings: []vulnFinding{moduleOnly}, cg: cgo,
			wantReasons: []string{plugin.PartialReasonCgo}, wantRefuted: "pkg:golang/golang.org/x/net"},
		{name: "symbol finding: path, no refutation",
			findings: []vulnFinding{moduleOnly, packageOnly, symbol}, cg: complete,
			wantReasons: []string{plugin.PartialReasonReachabilityUndetermined}, wantPaths: true},
		{name: "finding without a module: no refutation",
			findings: []vulnFinding{unmoduled}, cg: complete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evidenceResult(tc.findings, tc.cg, env)
			if got := res.Partiality.Reasons; !reflect.DeepEqual(got, tc.wantReasons) {
				t.Errorf("reasons = %v, want %v", got, tc.wantReasons)
			}
			if res.Partiality.Complete != (len(tc.wantReasons) == 0) {
				t.Errorf("complete = %v with reasons %v", res.Partiality.Complete, tc.wantReasons)
			}
			if (len(res.Paths) > 0) != tc.wantPaths {
				t.Errorf("paths = %d, want paths %v", len(res.Paths), tc.wantPaths)
			}
			if tc.wantRefuted == "" {
				if res.Refutation != nil {
					t.Errorf("unexpected refutation %+v", res.Refutation)
				}
				return
			}
			r := res.Refutation
			if r == nil {
				t.Fatal("want a refutation, got none")
			}
			if r.Basis != plugin.RefutationAnalyzerSymbolNotReached || r.Package != tc.wantRefuted {
				t.Errorf("refutation = %+v, want %s on %s", r, plugin.RefutationAnalyzerSymbolNotReached, tc.wantRefuted)
			}
			for _, want := range []string{"golang.org/x/net v0.1.0", "GOOS=linux GOARCH=arm64"} {
				if !strings.Contains(r.Detail, want) {
					t.Errorf("detail %q does not name %q", r.Detail, want)
				}
			}
			if imported := strings.Contains(r.Detail, "package is imported"); imported != tc.wantImported {
				t.Errorf("detail %q: imported = %v, want %v", r.Detail, imported, tc.wantImported)
			}
		})
	}
}

// TestModuleRefutation_NamesBuildTags: the refutation holds for the tags govulncheck built with,
// which GOFLAGS can set.
func TestModuleRefutation_NamesBuildTags(t *testing.T) {
	findings := []vulnFinding{{Trace: []vulnFrame{{Module: "golang.org/x/net", Version: "v0.1.0"}}}}
	for _, tc := range []struct{ goflags, want string }{
		{"", "default build tags"},
		{"-tags=prod,netgo", "build tags from GOFLAGS: prod,netgo"},
	} {
		r := moduleRefutation(findings, []string{"GOFLAGS=" + tc.goflags})
		if r == nil || !strings.Contains(r.Detail, tc.want) {
			t.Errorf("GOFLAGS=%q: refutation %+v, want detail naming %q", tc.goflags, r, tc.want)
		}
	}
}

func TestModuleRefutation_PicksFirstModuleInPathOrder(t *testing.T) {
	r := moduleRefutation([]vulnFinding{
		{Trace: []vulnFrame{{Module: "golang.org/x/text", Version: "v0.3.0"}}},
		{Trace: []vulnFrame{{Module: "golang.org/x/net", Version: "v0.1.0"}}},
	}, nil)
	if r == nil || r.Package != "pkg:golang/golang.org/x/net" {
		t.Fatalf("refutation = %+v, want golang.org/x/net", r)
	}
}
