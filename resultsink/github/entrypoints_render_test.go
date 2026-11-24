package github_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const entrypointsLabel = "**Entry points.**"

func entrypointsReport(sets ...plugin.ResolvedLibraryEntrypoints) report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"})
	b.AddFinding(report.AdvisoryFinding{
		Advisory: report.Advisory{ID: "GO-2099-0001", Source: "osv"},
		Package:  &pkg,
		Verdict:  report.VerdictReachableCandidate,
	})
	b.WithLibraryEntrypoints(sets...)
	return b.Build()
}

// Both surfaces show the entry points each lane analysed, whether inferred or declared, before the
// counts; a scan whose lanes reported no set shows no block.
func TestBothSurfaces_Entrypoints(t *testing.T) {
	many := []string{"example.com/m/a", "example.com/m/b", "example.com/m/c", "example.com/m/d", "example.com/m/e", "example.com/m/f", "example.com/m/g"}
	tests := []struct {
		name string
		sets []plugin.ResolvedLibraryEntrypoints
		want []string
		none bool
	}{
		{name: "inferred", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/m/lib"}}},
			want: []string{"go: inferred, nothing declared; library packages callable from outside the build (1): `example.com/m/lib`."}},
		{name: "inferred set is capped and counted", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: many}},
			want: []string{"library packages callable from outside the build (7): `example.com/m/a`, `example.com/m/b`, `example.com/m/c`, `example.com/m/d`, `example.com/m/e` and 2 more."}},
		{name: "declared none", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}},
			want: []string{"go: declared, resolved as `none`; library packages callable from outside the build: none."}},
		{name: "declared with an unmatched exclude", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "example.com/m/lib,!example.com/m/gone", Packages: []string{"example.com/m/lib"}, Unmatched: []string{"!example.com/m/gone"}}},
			want: []string{"go: declared, resolved as `example.com/m/lib,!example.com/m/gone`; library packages callable from outside the build (1): `example.com/m/lib`; excluded nothing: `!example.com/m/gone`."}},
		{name: "declared with an unmatched include", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "example.com/m/lib,example.com/m/gone,!example.com/m/old", Packages: []string{"example.com/m/lib"}, Unmatched: []string{"example.com/m/gone", "!example.com/m/old"}}},
			want: []string{"; matched nothing, so verdicts resting on it are withheld: `example.com/m/gone`; excluded nothing: `!example.com/m/old`."}},
		{name: "metacharacters stay literal", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "[x](https://example.invalid) a`b", Packages: []string{"<img src=x>"}}},
			want: []string{"``[x](https://example.invalid) a`b``", "`<img src=x>`"}},
		{name: "no lane reported a set", none: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for surface, s := range bothSurfaces(t, entrypointsReport(tc.sets...)) {
				i := strings.Index(s, entrypointsLabel)
				if tc.none {
					if i >= 0 {
						t.Errorf("%s: entry-point block with no set reported\n---\n%s", surface, s)
					}
					continue
				}
				if i < 0 {
					t.Fatalf("%s: no entry-point block\n---\n%s", surface, s)
				}
				if j := strings.Index(s, "| Verdict"); j >= 0 && j < i {
					t.Errorf("%s: the entry-point block must precede the counts table\n---\n%s", surface, s)
				}
				for _, w := range tc.want {
					if !strings.Contains(s, w) {
						t.Errorf("%s: missing %q\n---\n%s", surface, w, s)
					}
				}
			}
		})
	}
}

// A lane or kind name outside the bare lowercase vocabulary renders inside a code span, never as markup.
func TestBothSurfaces_EntrypointsOddNames(t *testing.T) {
	r := entrypointsReport()
	r.Entrypoints = []plugin.EntryRootRecord{{Lane: "Go*x", Source: plugin.LibraryEntrypointsSourceAuto, Effective: map[string][]string{"K!nd": {"a"}}}}
	for surface, s := range bothSurfaces(t, r) {
		for _, w := range []string{"`Go*x`: inferred", "`K!nd` (1): `a`"} {
			if !strings.Contains(s, w) {
				t.Errorf("%s: missing %q\n---\n%s", surface, w, s)
			}
		}
	}
}
