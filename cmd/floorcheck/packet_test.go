package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestSplitHop(t *testing.T) {
	for _, tc := range []struct {
		hop                 string
		pkg, recv, function string
	}{
		{"image.Decode", "image", "", "Decode"},
		{"golang.org/x/net/html.Parse", "golang.org/x/net/html", "", "Parse"},
		{"github.com/a/b/zstd.Encoder.Write", "github.com/a/b/zstd", "Encoder", "Write"},
		{"gopkg.in/yaml.v3.Marshal", "gopkg.in/yaml.v3", "", "Marshal"},
		{"github.com/go-redis/redis/v9.baseClient._process", "github.com/go-redis/redis/v9", "baseClient", "_process"},
	} {
		n, ok := splitHop(tc.hop, nil)
		if !ok || n.Pkg != tc.pkg || n.Recv != tc.recv || n.Func != tc.function {
			t.Errorf("splitHop(%q) = %+v, %v; want %s %s %s", tc.hop, n, ok, tc.pkg, tc.recv, tc.function)
		}
	}
	if _, ok := splitHop("nodots", nil); ok {
		t.Error("a hop with no function splits")
	}
}

func TestSourceLinks(t *testing.T) {
	for _, tc := range []struct {
		name, mod, version, file, want string
	}{
		{"github module", "github.com/golang-jwt/jwt/v5", "v5.2.1", "parser.go", "https://github.com/golang-jwt/jwt/blob/v5.2.1/parser.go#L7"},
		{"github submodule", "github.com/a/b/c/v2", "v2.1.0", "x.go", "https://github.com/a/b/blob/c/v2.1.0/c/x.go#L7"},
		{"pseudo-version", "github.com/k/compress", "v1.17.11-0.20241004063537-dbd6c381492a", "zstd/e.go", "https://github.com/k/compress/blob/dbd6c381492a/zstd/e.go#L7"},
		{"x module", "golang.org/x/net", "v0.34.0", "html/parse.go", "https://github.com/golang/net/blob/v0.34.0/html/parse.go#L7"},
		{"unknown host", "go.etcd.io/bbolt", "v1.3.11", "db.go", ""},
	} {
		if got := depLink(tc.mod, tc.version, tc.file, 7).URL; got != tc.want {
			t.Errorf("%s: depLink = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := stdlibLink("1.23.12", "image/format.go", 87).URL; got != "https://github.com/golang/go/blob/go1.23.12/src/image/format.go#L87" {
		t.Errorf("stdlibLink = %q", got)
	}
}

func TestDeclaresAt(t *testing.T) {
	src := []byte("package p\n\nfunc (e *Encoder[T]) Write(b []byte) {}\nfunc Parse() {}\n")
	for _, tc := range []struct {
		line int
		n    hopName
		want bool
	}{
		{3, hopName{Recv: "Encoder", Func: "Write"}, true},
		{4, hopName{Func: "Parse"}, true},
		{4, hopName{Func: "Pars"}, false},
		{3, hopName{Func: "Write"}, false},
		{3, hopName{Recv: "Other", Func: "Write"}, false},
		{99, hopName{Func: "Parse"}, false},
	} {
		if got := declaresAt(src, tc.line, tc.n); got != tc.want {
			t.Errorf("declaresAt(line %d, %+v) = %v, want %v", tc.line, tc.n, got, tc.want)
		}
	}
}

func write(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// packetFixture is a target checkout and a module cache holding one dependency, and the ledger row whose
// path crosses them.
func packetFixture(t *testing.T) packetInput {
	repo, mc := t.TempDir(), t.TempDir()
	write(t, repo, "go.mod", "module example.com/app\n\ngo 1.23\n\nrequire (\n\texample.org/dep/v2 v2.0.1\n\texample.org/dep v1.0.0\n)\n")
	write(t, repo, "h/h.go", "package h\n\nfunc Handle() {}\n")
	write(t, repo, "h/dup_linux.go", "package h\n\nfunc Twice() {}\n")
	write(t, repo, "h/dup_other.go", "//go:build linux\n\npackage h\n\nfunc Twice() {}\n")
	write(t, repo, "h/skip_windows.go", "package h\n\nfunc OnlyWindows() {}\n")
	write(t, mc, "example.org/dep/v2@v2.0.1/p/p.go", "package p\n\ntype Parser struct{}\n\nfunc (p *Parser) Parse() {}\n")
	path := []string{"example.com/app/h.Handle", "example.org/dep/v2/p.Parser.Parse"}
	row := LedgerRow{Advisory: []string{"CVE-1", "GO-1"}, Package: "example.org/dep@v1.0.0", Target: "app",
		EngineExpected: Engine{Verdict: report.VerdictReachableCandidate}, PathReview: newPathReview(path, testBound)}
	l := Ledger{Header: LedgerHeader{Target: "app", Repo: "o/app", UpstreamSHA: strings.Repeat("a", 40), GOOS: "linux", GOARCH: "amd64",
		GoVersion: "1.23.12", CorpusRelease: "corpus-0123456789ab", MainModule: "example.com/app",
		Comparator: Comparator{Name: "govulncheck", Version: "v1.9.0"}}, Rows: []LedgerRow{row}}
	ev := &Evidence{Comparator: EvidenceConfig{Command: "govulncheck ./..."}, Findings: []EvidenceFinder{
		{OSV: "GO-1", Module: "example.org/dep", Version: "v1.0.0", Level: "package"},
		{OSV: "GO-1", Module: "example.org/dep/v2", Version: "v2.0.1", Level: "symbol"},
		{OSV: "GO-1", Module: "example.org/other", Version: "v1.0.0", Level: "symbol"},
		{OSV: "GO-9", Module: "example.org/dep", Version: "v1.0.0", Level: "symbol"}}}
	return packetInput{Ledger: l, Row: row, Showcase: &Showcase{Policy: "full"}, Evidence: ev,
		GoMod: readFileOrEmpty(filepath.Join(repo, "go.mod")), Src: &sources{Repo: repo, Modcache: mc}}
}

func TestPacketAssembly(t *testing.T) {
	in := packetFixture(t)
	p, err := buildPacket(in)
	if err != nil {
		t.Fatal(err)
	}
	h0, h1 := p.Hops[0], p.Hops[1]
	if h0.Kind != pkgTarget || h0.File != "h/h.go" || h0.Line != 3 ||
		h0.Permalink != "https://github.com/o/app/blob/"+in.Ledger.Header.UpstreamSHA+"/h/h.go#L3" {
		t.Errorf("target hop = %+v", h0)
	}
	if h1.Kind != pkgDependency || h1.Module != "example.org/dep/v2" || h1.Version != "v2.0.1" || h1.File != "p/p.go" || h1.Line != 5 {
		t.Errorf("dependency hop = %+v", h1)
	}
	if h1.Permalink != "" {
		t.Errorf("a module at an unknown host got a permalink: %q", h1.Permalink)
	}
	if !strings.Contains(h1.Unresolved, "no stable line link") {
		t.Errorf("dependency hop unresolved = %q", h1.Unresolved)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "ATTRIBUTION MISMATCH") {
		t.Errorf("a path ending in dep/v2 for a dep v1 row: notes = %q", p.Notes)
	}
	// comparator entries: the row's instance and the module the path ends in, for this advisory only
	if len(p.Govulncheck) != 2 || p.Govulncheck[0].Version != "v1.0.0" || p.Govulncheck[1].Module != "example.org/dep/v2" {
		t.Errorf("govulncheck entries = %+v", p.Govulncheck)
	}
	md := p.markdown()
	for _, want := range []string{"## Call path", "h/h.go:3", "unresolved:", "## Analysis inputs", "## Assay's finding", "Not included", "## Rerun it", "corpus-0123456789ab"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	// a stub fetch stands in for the network
	verifyLinks(p.Hops, func(url string) ([]byte, error) {
		if !strings.Contains(url, "raw.githubusercontent.com/o/app/") {
			return nil, errors.New("404")
		}
		return []byte("package h\n\nfunc Handle() {}\n"), nil
	})
	if !strings.HasPrefix(p.Hops[0].LinkCheck, "verified") {
		t.Errorf("link check = %q", p.Hops[0].LinkCheck)
	}
}

func TestLocateBuildAndAmbiguity(t *testing.T) {
	in := packetFixture(t)
	s := in.Src
	s.MainModule, s.Context = "example.com/app", pinnedContext(in.Ledger.Header)
	mods := moduleSet{}
	for _, tc := range []struct {
		name, why string
	}{
		{"Handle", ""},
		{"Twice", "declared 2 times"},
		{"OnlyWindows", "no declaration"},
		{"Missing", "no declaration"},
	} {
		_, why := s.locate(hopName{Pkg: "example.com/app/h", Func: tc.name}, mods)
		if !strings.Contains(why, tc.why) || (tc.why == "" && why != "") {
			t.Errorf("locate %s: reason %q, want %q", tc.name, why, tc.why)
		}
	}
	if _, why := s.locate(hopName{Pkg: "example.net/none", Func: "F"}, mods); why != "source not available here" {
		t.Errorf("a package with no module: %q", why)
	}
}

func TestSelectRows(t *testing.T) {
	reach := LedgerRow{Advisory: []string{"CVE-1"}, Package: "m@v1", Target: "t", EngineExpected: Engine{Verdict: report.VerdictReachableCandidate}}
	reach2 := reach
	reach2.Package = "m@v2"
	other := LedgerRow{Advisory: []string{"CVE-2"}, Package: "m@v1", Target: "t", EngineExpected: Engine{Verdict: report.VerdictUndetermined}}
	l := Ledger{Rows: []LedgerRow{reach, reach2, other}}
	for _, tc := range []struct {
		sel, want string // want is an error substring, empty for one row
	}{
		{reach.Key(), ""},
		{"CVE-1", "names 2 reachable rows"},
		{"CVE-2", "none with a reachable_candidate"},
		{"CVE-3", "no ledger row"},
	} {
		rows, err := selectRows(l, tc.sel)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) || (err == nil && len(rows) != 1) {
			t.Errorf("selectRows(%q) = %d rows, %v; want %q", tc.sel, len(rows), err, tc.want)
		}
	}
}
