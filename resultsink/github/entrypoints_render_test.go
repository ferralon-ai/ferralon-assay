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
		{name: "an application read from its mains", sets: []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceMains, Input: "auto", Packages: []string{}}},
			want: []string{"go: treated as an application, nothing declared: its main packages are the entry points; library packages callable from outside the build: none; library mode: `go:library=.`."}},
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

// Under an override the line shows what the lane inferred (only the kinds the override changed) and
// the "!" selectors that removed something; with no override the line is as it always was, and a js
// record that listed nothing because no dependency code was read says so instead of "none".
func TestBothSurfaces_EntrypointsOverride(t *testing.T) {
	goLib := plugin.EntryKindLibrary
	tests := []struct {
		name string
		rec  plugin.EntryRootRecord
		want string // the whole rendered line
	}{
		{name: "no override is unchanged", rec: plugin.EntryRootRecord{
			Lane: "go", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto",
			Effective: map[string][]string{goLib: {"example.com/m/lib"}},
			Inferred:  map[string][]string{goLib: {"example.com/m/lib", "example.com/m/other"}},
			Denied:    []string{"!example.com/m/other"},
		}, want: "go: inferred, nothing declared; library packages callable from outside the build (1): `example.com/m/lib`."},
		{name: "go library override removes a path", rec: plugin.EntryRootRecord{
			Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "go:library=!example.com/m/lib/internal",
			Effective: map[string][]string{goLib: {"example.com/m/lib"}},
			Inferred: map[string][]string{goLib: {"example.com/m/lib", "example.com/m/lib/internal"},
				plugin.EntryKindMain: {"example.com/m/cmd/app"}},
			Denied: []string{"!example.com/m/lib/internal"},
		}, want: "go: declared, resolved as `go:library=!example.com/m/lib/internal`; library packages callable from outside the build (1): `example.com/m/lib`; " +
			"inferred before the override: library packages callable from outside the build (2): `example.com/m/lib`, `example.com/m/lib/internal`; " +
			"removed by: `!example.com/m/lib/internal`."},
		{name: "js bin removal lists only the changed kind", rec: plugin.EntryRootRecord{
			Lane: "js", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=bin:storybook",
			Effective: map[string][]string{"bin": {"bin:build"}, "script": {"script:test"}},
			Inferred:  map[string][]string{"bin": {"bin:build", "bin:storybook"}, "script": {"script:test"}},
			Denied:    []string{"!js:bin=bin:storybook"},
		}, want: "js: declared, resolved as `!js:bin=bin:storybook`; bin (1): `bin:build`; script (1): `script:test`; " +
			"inferred before the override: bin (2): `bin:build`, `bin:storybook`; removed by: `!js:bin=bin:storybook`."},
		{name: "an application read from its mains", rec: plugin.EntryRootRecord{
			Lane: "go", Source: plugin.LibraryEntrypointsSourceMains, Input: "auto",
			Effective: map[string][]string{goLib: {}},
			Inferred: map[string][]string{goLib: {"example.com/m/lib"},
				plugin.EntryKindMain: {"example.com/m/cmd/app"}},
		}, want: "go: treated as an application, nothing declared: its main packages are the entry points; " +
			"library packages callable from outside the build: none; library mode: `go:library=.`."},
		{name: "unlisted record, nothing declared", rec: plugin.EntryRootRecord{
			Lane: "js", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto",
			Effective: map[string][]string{"bin": {}, "script": {}},
		}, want: "js: nothing declared; entry points not listed because dependency code was not read."},
		{name: "unlisted record, declared", rec: plugin.EntryRootRecord{
			Lane: "js", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=bin:x",
			Effective: map[string][]string{"bin": {}, "script": {}},
		}, want: "js: declared, resolved as `!js:bin=bin:x`; entry points not listed because dependency code was not read."},
		{name: "override that changes nothing falls through to unmatched", rec: plugin.EntryRootRecord{
			Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "example.com/m/lib,!example.com/m/gone",
			Effective: map[string][]string{goLib: {"example.com/m/lib"}},
			Inferred:  map[string][]string{goLib: {"example.com/m/lib"}},
			Unmatched: []string{"!example.com/m/gone"},
		}, want: "go: declared, resolved as `example.com/m/lib,!example.com/m/gone`; library packages callable from outside the build (1): `example.com/m/lib`; excluded nothing: `!example.com/m/gone`."},
		{name: "more than five inferred roots are capped", rec: plugin.EntryRootRecord{
			Lane: "go", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none",
			Effective: map[string][]string{goLib: {}},
			Inferred:  map[string][]string{goLib: {"m/a", "m/b", "m/c", "m/d", "m/e", "m/f", "m/g"}, plugin.EntryKindMain: {"m/cmd/app"}},
		}, want: "go: declared, resolved as `none`; library packages callable from outside the build: none; " +
			"inferred before the override: library packages callable from outside the build (7): `m/a`, `m/b`, `m/c`, `m/d`, `m/e` and 2 more."},
		{name: "repository names stay in code spans", rec: plugin.EntryRootRecord{
			Lane: "js", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=x",
			Effective: map[string][]string{"bin": {}},
			Inferred:  map[string][]string{"bin": {"[x](https://example.invalid)"}},
			Denied:    []string{"!js:bin=<img src=x>"},
		}, want: "js: declared, resolved as `!js:bin=x`; bin: none; inferred before the override: bin (1): `[x](https://example.invalid)`; removed by: `!js:bin=<img src=x>`."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := entrypointsReport()
			r.Entrypoints = []plugin.EntryRootRecord{tc.rec}
			for surface, s := range bothSurfaces(t, r) {
				if !strings.Contains(s, "- "+tc.want+"\n") {
					t.Errorf("%s: missing line\n%s\n---\n%s", surface, tc.want, s)
				}
			}
		})
	}
}
