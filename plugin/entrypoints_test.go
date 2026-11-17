package plugin

import (
	"reflect"
	"strings"
	"testing"
)

// parseLane parses in and returns the override for lane, the zero (auto) override when in does not
// mention it.
func parseLane(t *testing.T, in, lane string) EntryOverride {
	t.Helper()
	m, err := ParseEntryOverrides(in)
	if err != nil {
		t.Fatalf("parse %q: %v", in, err)
	}
	return m[lane]
}

func TestParseEntryOverrides(t *testing.T) {
	ko := func(mode string, inc, exc []string) KindOverride {
		return KindOverride{Mode: mode, Include: inc, Exclude: exc}
	}
	cases := []struct {
		name    string
		in      string
		want    map[string]EntryOverride
		wantErr string
	}{
		{name: "empty is auto", in: "", want: map[string]EntryOverride{}},
		{name: "list replaces auto", in: "go:pkg/api, go:./pkg/client/...", want: map[string]EntryOverride{"go": {Lane: "go", Input: "go:pkg/api,go:./pkg/client/...", KindOverride: ko("paths", []string{"pkg/api", "pkg/client"}, nil)}}},
		{name: "deny-only keeps auto", in: "!go:internal/tools\n!go:cmd", want: map[string]EntryOverride{"go": {Lane: "go", Input: "!go:internal/tools,!go:cmd", KindOverride: ko("auto", nil, []string{"cmd", "internal/tools"})}}},
		{name: "auto plus allow", in: "go:auto,go:cmd/x", want: map[string]EntryOverride{"go": {Lane: "go", Input: "go:auto,go:cmd/x", KindOverride: ko("auto", []string{"cmd/x"}, nil)}}},
		{name: "duplicates compact", in: "js:pkg js:pkg !js:pkg/x !js:pkg/x", want: map[string]EntryOverride{"js": {Lane: "js", Input: "js:pkg,js:pkg,!js:pkg/x,!js:pkg/x", KindOverride: ko("paths", []string{"pkg"}, []string{"pkg/x"})}}},
		{name: "lane none", in: "js:none", want: map[string]EntryOverride{"js": {Lane: "js", Input: "js:none", KindOverride: ko("none", nil, nil)}}},
		{name: "lane auto", in: "go:auto", want: map[string]EntryOverride{"go": {Lane: "go", Input: "go:auto", KindOverride: ko("auto", nil, nil)}}},
		{name: "lane deny keeps auto", in: "!js:npm:nodemon", want: map[string]EntryOverride{"js": {Lane: "js", Input: "!js:npm:nodemon", KindOverride: ko("auto", nil, []string{"npm:nodemon"})}}},
		{name: "kind none", in: "go:library=none", want: map[string]EntryOverride{"go": {Lane: "go", Input: "go:library=none", KindOverride: ko("auto", nil, nil), Kinds: map[string]KindOverride{"library": ko("none", nil, nil)}}}},
		{name: "kind deny of bin name", in: "!js:bin=bin:storybook", want: map[string]EntryOverride{"js": {Lane: "js", Input: "!js:bin=bin:storybook", KindOverride: ko("auto", nil, nil), Kinds: map[string]KindOverride{"bin": ko("", nil, []string{"bin:storybook"})}}}},
		{
			name: "two kinds",
			in:   "go:main=cmd/traefik, go:library=none",
			want: map[string]EntryOverride{"go": {Lane: "go", Input: "go:main=cmd/traefik,go:library=none", KindOverride: ko("auto", nil, nil), Kinds: map[string]KindOverride{
				"main": ko("paths", []string{"cmd/traefik"}, nil), "library": ko("none", nil, nil),
			}}},
		},
		{name: "class selector", in: "java:main=class:com.acme.Main", want: map[string]EntryOverride{"java": {Lane: "java", Input: "java:main=class:com.acme.Main", KindOverride: ko("auto", nil, nil), Kinds: map[string]KindOverride{"main": ko("paths", []string{"class:com.acme.Main"}, nil)}}}},
		{name: "npm selector cleans repeated slashes", in: "!js:npm:nodemon//", want: map[string]EntryOverride{"js": {Lane: "js", Input: "!js:npm:nodemon//", KindOverride: ko("auto", nil, []string{"npm:nodemon"})}}},
		{name: "npm selector cleans dot segments", in: "!js:npm:nodemon/./bin", want: map[string]EntryOverride{"js": {Lane: "js", Input: "!js:npm:nodemon/./bin", KindOverride: ko("auto", nil, []string{"npm:nodemon/bin"})}}},
		{name: "bin selector cleans repeated slashes", in: "!js:bin:a//b", want: map[string]EntryOverride{"js": {Lane: "js", Input: "!js:bin:a//b", KindOverride: ko("auto", nil, []string{"bin:a/b"})}}},
		{name: "npm selector trims slash", in: "js:npm:nodemon/", want: map[string]EntryOverride{"js": {Lane: "js", Input: "js:npm:nodemon/", KindOverride: ko("paths", []string{"npm:nodemon"}, nil)}}},
		{name: "lane none beside kind clause", in: "js:none js:bin=bin:x", want: map[string]EntryOverride{"js": {Lane: "js", Input: "js:none,js:bin=bin:x", KindOverride: ko("none", nil, nil), Kinds: map[string]KindOverride{"bin": ko("paths", []string{"bin:x"}, nil)}}}},
		{
			name: "several lanes, each with its own input",
			in:   "go:library=none, !js:npm:nodemon, go:main=cmd/app",
			want: map[string]EntryOverride{
				"go": {Lane: "go", Input: "go:library=none,go:main=cmd/app", KindOverride: ko("auto", nil, nil), Kinds: map[string]KindOverride{
					"library": ko("none", nil, nil), "main": ko("paths", []string{"cmd/app"}, nil)}},
				"js": {Lane: "js", Input: "!js:npm:nodemon", KindOverride: ko("auto", nil, []string{"npm:nodemon"})},
			},
		},
		{
			name: "bare none addresses every lane",
			in:   " none ",
			want: map[string]EntryOverride{
				"go": {Lane: "go", Input: "none", KindOverride: ko("none", nil, nil)}, "java": {Lane: "java", Input: "none", KindOverride: ko("none", nil, nil)},
				"kotlin": {Lane: "kotlin", Input: "none", KindOverride: ko("none", nil, nil)}, "js": {Lane: "js", Input: "none", KindOverride: ko("none", nil, nil)},
				"python": {Lane: "python", Input: "none", KindOverride: ko("none", nil, nil)}, "dotnet": {Lane: "dotnet", Input: "none", KindOverride: ko("none", nil, nil)},
			},
		},
		{name: "bare auto addresses every lane", in: "auto", want: map[string]EntryOverride{
			"go": {Lane: "go", Input: "auto", KindOverride: ko("auto", nil, nil)}, "java": {Lane: "java", Input: "auto", KindOverride: ko("auto", nil, nil)},
			"kotlin": {Lane: "kotlin", Input: "auto", KindOverride: ko("auto", nil, nil)}, "js": {Lane: "js", Input: "auto", KindOverride: ko("auto", nil, nil)},
			"python": {Lane: "python", Input: "auto", KindOverride: ko("auto", nil, nil)}, "dotnet": {Lane: "dotnet", Input: "auto", KindOverride: ko("auto", nil, nil)},
		}},

		{name: "bare selector", in: "pkg/api", wantErr: "must name its lane; write it as <lane>:pkg/api, for example js:pkg/api"},
		{name: "bare deny", in: "!internal/tools", wantErr: "must name its lane; write it as <lane>:internal/tools"},
		{name: "bare npm selector", in: "npm:nodemon", wantErr: "must name its lane"},
		{name: "bare none beside selector", in: "none,go:pkg", wantErr: "stands alone"},
		{name: "bare none beside bare selector", in: "pkg,none", wantErr: "must name its lane"},
		{name: "bare auto beside lane clause", in: "auto js:module=none", wantErr: "stands alone"},
		{name: "bare none beside lane clause", in: "none js:module=pkg", wantErr: "stands alone"},
		{name: "bare auto and none", in: "auto,none", wantErr: "stands alone"},
		{name: "auto and none in one scope", in: "js:auto,js:none", wantErr: "none stands alone"},
		{name: "lane none beside allow", in: "js:none js:pkg", wantErr: "none stands alone"},
		{name: "kind none beside deny", in: "go:library=none !go:library=pkg", wantErr: "none stands alone"},
		{name: "deny on bare auto", in: "!auto", wantErr: "! applies to a selector"},
		{name: "deny on lane none", in: "!js:none", wantErr: "! applies to a selector"},
		{name: "deny on kind auto", in: "!js:bin=auto", wantErr: "! applies to a selector"},
		{name: "allow and deny same selector", in: "go:pkg,!go:pkg", wantErr: "both allowed and denied"},
		{name: "allow in lane scope, deny in kind scope", in: "js:src/a.js, !js:module=src/a.js", wantErr: "both allowed and denied"},
		{name: "deny in lane scope, allow in kind scope", in: "!js:src/a.js js:module=src/a.js", wantErr: "both allowed and denied"},
		{name: "allow and deny same selector in kind", in: "js:bin=bin:x !js:bin=bin:x", wantErr: "both allowed and denied"},
		{name: "unknown lane", in: "ruby:main=x", wantErr: `unknown lane "ruby"`},
		{name: "unknown kind", in: "go:widget=x", wantErr: `unknown kind "widget"`},
		{name: "kind the lane does not infer", in: "java:script=x", wantErr: `does not infer kind "script"`},
		{name: "declared is not writable", in: "go:declared=x", wantErr: `unknown kind "declared"`},
		{name: "empty target", in: "js:", wantErr: "empty target"},
		{name: "empty kind target", in: "js:bin=", wantErr: "empty target"},
		{name: "lone bang", in: "!", wantErr: "empty clause"},
		{name: "dotdot", in: "go:../x", wantErr: "leaves the repository root"},
		{name: "dotdot inside", in: "go:pkg/../../x", wantErr: "leaves the repository root"},
		{name: "absolute", in: "go:/abs", wantErr: "relative to the repository root"},
		{name: "absolute in kind", in: "go:library=/abs", wantErr: "relative to the repository root"},
		{name: "backslash", in: `go:pkg\x`, wantErr: "use /"},
		{name: "class selector leaving by dotdot", in: "java:main=class:a/../b", wantErr: "leaves the package"},
		{name: "npm escape", in: "js:npm:pkg/../x", wantErr: "leaves the package"},
		{name: "empty npm", in: "js:npm:", wantErr: "needs a name"},
		{name: "colon after a kind", in: "go:library:none", wantErr: "write go:library=none"},
		{name: "deny, colon after a kind", in: "!go:library:pkg/api", wantErr: "write go:library=pkg/api"},
		{name: "colon after a kind the lane lacks", in: "js:library:none", wantErr: `does not infer kind "library"`},
		{name: "unknown selector prefix", in: "js:C:/x", wantErr: "unknown selector form"},
		{name: "none in upper case", in: "go:NONE", wantErr: "write none in lower case"},
		{name: "auto in mixed case", in: "go:library=Auto", wantErr: "write auto in lower case"},
		{name: "bare none in upper case", in: "NONE", wantErr: "write none in lower case"},
		{name: "empty bin", in: "!js:bin:", wantErr: "needs a name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEntryOverrides(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parse = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// library-entrypoints stands for the clauses "go:library=<token>", vector for vector: the override built
// from the parsed input equals the one the entrypoints grammar yields for those clauses.
func TestEntryOverrideForLibraryEntrypoints(t *testing.T) {
	for _, in := range []string{
		"", "auto", " none ", "pkg/api, ./pkg/client/...", "!internal/tools\n!cmd", "auto,cmd/x",
		"pkg,!pkg/x,pkg", "./...", "none,pkg", "none,!pkg", "auto,none", "../x", "pkg/../../x", "/abs", `pkg\x`, "!",
	} {
		t.Run(in, func(t *testing.T) {
			lib, libErr := ParseLibraryEntrypoints(in)
			tokens := strings.FieldsFunc(in, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
			if len(tokens) == 0 {
				tokens = []string{"auto"}
			}
			var clauses []string
			for _, tok := range tokens {
				sel, denied := strings.CutPrefix(tok, "!")
				c := "go:library=" + sel
				if denied {
					c = "!" + c
				}
				clauses = append(clauses, c)
			}
			m, err := ParseEntryOverrides(strings.Join(clauses, ","))
			if (err != nil) != (libErr != nil) {
				t.Fatalf("err = %v, library-entrypoints err = %v", err, libErr)
			}
			if err != nil {
				return
			}
			got := EntryOverrideForLibraryEntrypoints(lib)
			want := m["go"]
			// Input is the clauses as written there, and as rendered from the parsed statement here.
			got.Input, want.Input = "", ""
			if len(m) != 1 || !reflect.DeepEqual(got, want) {
				t.Errorf("override = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMatchesEntryRoot(t *testing.T) {
	jsFile := EntryRoot{Lane: "js", Kind: "module", Selector: "packages/cli/bin/run.js", Name: "mytool"}
	npmRoot := EntryRoot{Lane: "js", Kind: "bin", Selector: "npm:nodemon/bin/nodemon.js", Name: "nodemon"}
	cases := []struct {
		name string
		sel  string
		root EntryRoot
		want bool
	}{
		{"equal", "packages/cli/bin/run.js", jsFile, true},
		{"directory prefix", "packages/cli", jsFile, true},
		{"deeper directory", "packages/cli/bin", jsFile, true},
		{"sibling with shared name prefix", "packages/cl", jsFile, false},
		{"pkg/api is not pkg/apiv2", "pkg/api", EntryRoot{Selector: "pkg/apiv2/x.go"}, false},
		{"pkg/api is pkg/api/x.go", "pkg/api", EntryRoot{Selector: "pkg/api/x.go"}, true},
		{"pkg/api is pkg/api", "pkg/api", EntryRoot{Selector: "pkg/api"}, true},
		{"longer selector than root", "packages/cli/bin/run.js/x", jsFile, false},
		{"dot is every path", ".", jsFile, true},
		{"dot is not an installed package", ".", npmRoot, false},
		{"npm package prefix", "npm:nodemon", npmRoot, true},
		{"npm package and path", "npm:nodemon/bin", npmRoot, true},
		{"npm exact", "npm:nodemon/bin/nodemon.js", npmRoot, true},
		{"npm package is not a name prefix", "npm:node", npmRoot, false},
		{"npm other package", "npm:nodemon2", npmRoot, false},
		{"path never selects an npm root", "nodemon", npmRoot, false},
		{"bin by name", "bin:nodemon", npmRoot, true},
		{"bin by name on a file root", "bin:mytool", jsFile, true},
		{"bin other name", "bin:mytool2", jsFile, false},
		{"bin is not a name prefix", "bin:my", jsFile, false},
		{"class exact", "class:com.acme.Main", EntryRoot{Selector: "class:com.acme.Main"}, true},
		{"class is not a prefix", "class:com.acme", EntryRoot{Selector: "class:com.acme.Main"}, false},
		{"asm exact", "asm:Acme.Telemetry", EntryRoot{Selector: "asm:Acme.Telemetry"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesEntryRoot(tc.sel, tc.root); got != tc.want {
				t.Errorf("matchesEntryRoot(%q, %+v) = %v, want %v", tc.sel, tc.root, got, tc.want)
			}
		})
	}
}

func TestApplyEntryOverride(t *testing.T) {
	js := func(kind, sel, name, origin string) EntryRoot {
		return EntryRoot{Lane: "js", Kind: kind, Selector: sel, Name: name, Origin: origin}
	}
	goRoot := func(kind, sel string) EntryRoot { return EntryRoot{Lane: "go", Kind: kind, Selector: sel} }
	declared := func(lane, sel string) EntryRoot {
		return EntryRoot{Lane: lane, Kind: "declared", Selector: sel, Origin: EntryOriginDeclared}
	}

	jsRoots := []EntryRoot{
		js("module", "src/a.js", "", ""),
		js("module", "src/b.js", "", ""),
		js("bin", "npm:storybook/bin.js", "storybook", "package.json#scripts.storybook"),
		js("script", "npm:dotenv/config.js", "", "package.json#scripts.start"),
		js("bin", "npm:nodemon/bin/nodemon.js", "nodemon", "package.json#scripts.dev"),
	}
	goRoots := []EntryRoot{
		goRoot("main", "cmd/app/main.go"),
		goRoot("main", "cmd/debugtool/main.go"),
		goRoot("library", "pkg/api/api.go"),
		goRoot("library", "pkg/apiv2/api.go"),
	}

	cases := []struct {
		name      string
		in        string
		inferred  []EntryRoot
		effective []EntryRoot
		denied    []EntryRoot
		added     []EntryRoot
		unmatched []string
	}{
		{
			name: "zero override is auto", in: "", inferred: jsRoots,
			effective: jsRoots,
		},
		{
			name: "auto keeps everything", in: "auto", inferred: jsRoots,
			effective: jsRoots,
		},
		{
			name: "none drops everything and reports it denied", in: "none", inferred: jsRoots,
			denied: jsRoots,
		},
		{
			name: "list nominates a directory", in: "js:src", inferred: jsRoots,
			effective: jsRoots[:2],
			denied:    jsRoots[2:],
		},
		{
			name: "deny by bin name keeps auto for the rest", in: "!js:bin:storybook", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[0], jsRoots[1], jsRoots[3], jsRoots[4]},
			denied:    []EntryRoot{jsRoots[2]},
		},
		{
			name: "deny an installed package", in: "!js:npm:nodemon", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[0], jsRoots[1], jsRoots[2], jsRoots[3]},
			denied:    []EntryRoot{jsRoots[4]},
		},
		{
			name: "two denies from the lane", in: "!js:bin=bin:storybook, !js:script=npm:dotenv", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[0], jsRoots[1], jsRoots[4]},
			denied:    []EntryRoot{jsRoots[2], jsRoots[3]},
		},
		{
			name: "kind none leaves the other kinds alone", in: "js:module=none", inferred: jsRoots,
			effective: jsRoots[2:],
			denied:    jsRoots[:2],
		},
		{
			name: "kind scope overrides the lane scope for its kind", in: "js:module=none !js:npm:nodemon", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[2], jsRoots[3]},
			denied:    []EntryRoot{jsRoots[0], jsRoots[1], jsRoots[4]},
		},
		{
			name: "allow beside auto matching an inferred root adds nothing", in: "js:auto,js:npm:nodemon", inferred: jsRoots,
			effective: jsRoots,
		},
		{
			name: "declared root takes the override's lane", in: "js:auto js:scripts/run.js", inferred: jsRoots,
			effective: append(append([]EntryRoot{}, jsRoots...), declared("js", "scripts/run.js")),
			added:     []EntryRoot{declared("js", "scripts/run.js")},
		},
		{
			name: "list with no inferred match replaces auto with the declared root", in: "js:scripts/run.js", inferred: jsRoots,
			effective: []EntryRoot{declared("js", "scripts/run.js")},
			denied:    jsRoots,
			added:     []EntryRoot{declared("js", "scripts/run.js")},
		},
		{
			name: "deny matching no root is unmatched", in: "!js:src/gone.js", inferred: jsRoots,
			effective: jsRoots,
			unmatched: []string{"!src/gone.js"},
		},
		{
			name: "deny beats an allow that selects the same root", in: "js:src, !js:src/a.js", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[1]},
			denied:    []EntryRoot{jsRoots[0], jsRoots[2], jsRoots[3], jsRoots[4]},
		},
		{
			name: "deny covering an allow wins over a declared root", in: "js:auto js:scripts/run.js !js:scripts", inferred: jsRoots,
			effective: jsRoots,
			unmatched: []string{"!scripts", "scripts/run.js"},
		},
		{
			name: "other lanes stand untouched", in: "js:none", inferred: append(append([]EntryRoot{}, goRoots...), jsRoots...),
			effective: goRoots,
			denied:    jsRoots,
		},
		{
			name: "go library none leaves mains", in: "go:library=none", inferred: goRoots,
			effective: goRoots[:2],
			denied:    goRoots[2:],
		},
		{
			name: "pkg/api does not select pkg/apiv2", in: "go:library=pkg/api", inferred: goRoots,
			effective: []EntryRoot{goRoots[0], goRoots[1], goRoots[2]},
			denied:    []EntryRoot{goRoots[3]},
		},
		{
			name: "deny pkg/api keeps pkg/apiv2", in: "!go:library=pkg/api", inferred: goRoots,
			effective: []EntryRoot{goRoots[0], goRoots[1], goRoots[3]},
			denied:    []EntryRoot{goRoots[2]},
		},
		{
			name: "main list names a subtree", in: "go:main=cmd/app", inferred: goRoots,
			effective: []EntryRoot{goRoots[0], goRoots[2], goRoots[3]},
			denied:    []EntryRoot{goRoots[1]},
		},
		{
			name: "dot allows the whole tree", in: "js:.", inferred: jsRoots,
			effective: []EntryRoot{jsRoots[0], jsRoots[1]},
			denied:    jsRoots[2:],
		},
		{
			name: "no inferred roots", in: "js:none", inferred: nil,
		},
		{
			name: "no inferred roots, allow declares", in: "js:cli", inferred: nil,
			effective: []EntryRoot{declared("js", "cli")},
			added:     []EntryRoot{declared("js", "cli")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseEntryOverrides(tc.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			o := m["js"]
			if len(m) == 1 {
				for _, v := range m {
					o = v
				}
			}
			eff, den, add, unm := ApplyEntryOverride(tc.inferred, o)
			check := func(what string, got, want []EntryRoot) {
				t.Helper()
				sorted := append([]EntryRoot{}, want...)
				sortEntryRoots(sorted)
				if len(got) == 0 && len(sorted) == 0 {
					return
				}
				if !reflect.DeepEqual(got, sorted) {
					t.Errorf("%s = %+v, want %+v", what, got, sorted)
				}
			}
			check("effective", eff, tc.effective)
			check("denied", den, tc.denied)
			check("added", add, tc.added)
			if len(unm) != 0 || len(tc.unmatched) != 0 {
				if !reflect.DeepEqual(unm, tc.unmatched) {
					t.Errorf("unmatched = %q, want %q", unm, tc.unmatched)
				}
			}
		})
	}
}

// Every inferred root is either effective or denied, and no root is both.
func TestApplyEntryOverridePartitionsInferred(t *testing.T) {
	inferred := []EntryRoot{
		{Lane: "go", Kind: "main", Selector: "cmd/a/main.go"},
		{Lane: "go", Kind: "library", Selector: "pkg/a/a.go"},
		{Lane: "go", Kind: "library", Selector: "pkg/b/b.go"},
		{Lane: "go", Kind: "handler", Selector: "pkg/h/h.go"},
	}
	for _, in := range []string{"", "none", "go:library=none", "!go:main=cmd", "go:library=pkg/a", "go:library=pkg/a !go:library=pkg/a/x go:main=none"} {
		t.Run(in, func(t *testing.T) {
			o := parseLane(t, in, "go")
			eff, den, _, _ := ApplyEntryOverride(inferred, o)
			seen := map[string]int{}
			for _, r := range eff {
				if r.Kind != "declared" {
					seen[r.Selector]++
				}
			}
			for _, r := range den {
				seen[r.Selector]++
			}
			for _, r := range inferred {
				if seen[r.Selector] != 1 {
					t.Errorf("%s in effective+denied %d times, want 1", r.Selector, seen[r.Selector])
				}
			}
		})
	}
}

func TestApplyEntryOverrideOrderAndInputs(t *testing.T) {
	inferred := []EntryRoot{
		{Lane: "js", Kind: "bin", Selector: "npm:b/x.js", Origin: "z/package.json#scripts.b"},
		{Lane: "js", Kind: "bin", Selector: "npm:b/x.js", Origin: "a/package.json#scripts.b"},
		{Lane: "js", Kind: "module", Selector: "src/z.js"},
		{Lane: "js", Kind: "module", Selector: "src/a.js"},
	}
	snapshot := append([]EntryRoot{}, inferred...)
	o := parseLane(t, "js:module=none js:auto js:scripts/b.js js:scripts/a.js", "js")
	oSnap := o
	oSnap.Kinds = map[string]KindOverride{}
	for k, v := range o.Kinds {
		oSnap.Kinds[k] = v
	}

	eff, den, add, unm := ApplyEntryOverride(inferred, o)
	if !reflect.DeepEqual(inferred, snapshot) {
		t.Errorf("inferred modified: %+v", inferred)
	}
	if !reflect.DeepEqual(o, oSnap) {
		t.Errorf("override modified: %+v", o)
	}
	wantSel := func(rs []EntryRoot) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Selector+"|"+r.Origin)
		}
		return out
	}
	if got, want := wantSel(eff), []string{"npm:b/x.js|a/package.json#scripts.b", "npm:b/x.js|z/package.json#scripts.b", "scripts/a.js|entrypoints", "scripts/b.js|entrypoints"}; !reflect.DeepEqual(got, want) {
		t.Errorf("effective order = %q, want %q", got, want)
	}
	if got, want := wantSel(den), []string{"src/a.js|", "src/z.js|"}; !reflect.DeepEqual(got, want) {
		t.Errorf("denied order = %q, want %q", got, want)
	}
	if got, want := wantSel(add), []string{"scripts/a.js|entrypoints", "scripts/b.js|entrypoints"}; !reflect.DeepEqual(got, want) {
		t.Errorf("added order = %q, want %q", got, want)
	}
	if len(unm) != 0 {
		t.Errorf("unmatched = %q, want none: an allow that created a declared root is reported in added", unm)
	}

	// Input order does not change the result.
	rev := []EntryRoot{inferred[3], inferred[2], inferred[1], inferred[0]}
	eff2, den2, add2, unm2 := ApplyEntryOverride(rev, o)
	if !reflect.DeepEqual(eff, eff2) || !reflect.DeepEqual(den, den2) || !reflect.DeepEqual(add, add2) || !reflect.DeepEqual(unm, unm2) {
		t.Errorf("result depends on input order")
	}
}

func TestSummarizeEntryRoots(t *testing.T) {
	inferred := []EntryRoot{
		{Lane: "js", Kind: "module", Selector: "src/a.js"},
		{Lane: "js", Kind: "module", Selector: "src/b.js"},
		{Lane: "js", Kind: "module", Selector: "src/c.js"},
		{Lane: "js", Kind: "script", Selector: "npm:dotenv/config.js", Origin: "package.json#scripts.start"},
		{Lane: "js", Kind: "bin", Selector: "npm:nodemon/bin/nodemon.js", Name: "nodemon"},
	}
	denied := []EntryRoot{inferred[2], inferred[3]}
	added := []EntryRoot{{Lane: "js", Kind: "declared", Selector: "scripts/run.js", Origin: EntryOriginDeclared}}
	snapshot := append([]EntryRoot{}, inferred...)

	got := SummarizeEntryRoots(inferred, denied, added, []string{"!gone", "a"})
	want := EntryRootSummary{
		Counts:    map[string]int{"module": 3, "script": 1, "bin": 1},
		Inferred:  []EntryRoot{inferred[3], inferred[4]},
		Denied:    []EntryRoot{inferred[3], inferred[2]}, // a denied module root is listed
		Added:     added,
		Unmatched: []string{"!gone", "a"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(inferred, snapshot) {
		t.Errorf("inferred modified")
	}

	empty := SummarizeEntryRoots(nil, nil, nil, nil)
	if len(empty.Counts) != 0 || empty.Inferred != nil || empty.Denied != nil || empty.Added != nil || empty.Unmatched != nil {
		t.Errorf("empty summary = %+v", empty)
	}
}

// Each lane's override is applied to its own roots, so unmatched names the lane that must withhold.
func TestApplyEntryOverrideUnmatchedIsPerLane(t *testing.T) {
	inferred := []EntryRoot{
		{Lane: "go", Kind: "library", Selector: "pkg/api/api.go"},
		{Lane: "js", Kind: "module", Selector: "src/a.js"},
	}
	m, err := ParseEntryOverrides("!go:library=pkg/api, !js:src/gone.js")
	if err != nil {
		t.Fatal(err)
	}
	for lane, want := range map[string][]string{"go": nil, "js": {"!src/gone.js"}} {
		_, _, _, unmatched := ApplyEntryOverride(inferred, m[lane])
		if !reflect.DeepEqual(unmatched, want) {
			t.Errorf("%s unmatched = %q, want %q", lane, unmatched, want)
		}
	}
}

// An error names the same clause on every parse: no map order decides which of several faults is
// reported.
func TestParseEntryOverridesErrorIsDeterministic(t *testing.T) {
	in := "go:pkg,!go:pkg js:x,!js:x java:none java:auto"
	_, first := ParseEntryOverrides(in)
	if first == nil {
		t.Fatal("want an error")
	}
	for i := 0; i < 200; i++ {
		if _, err := ParseEntryOverrides(in); err == nil || err.Error() != first.Error() {
			t.Fatalf("parse %d: err = %v, want %v", i, err, first)
		}
	}
}

// Unqualified lane clauses and kind= clauses combine under one rule: a deny always applies, none is
// reported unmatched while it takes effect, and a kind scope that only denies leaves its roots' base to
// the lane scope.
func TestApplyEntryOverrideLaneAndKindClauses(t *testing.T) {
	goMains := []EntryRoot{
		{Lane: "go", Kind: "main", Selector: "cmd/app/main.go"},
		{Lane: "go", Kind: "main", Selector: "cmd/debugtool/main.go"},
	}
	goLib := EntryRoot{Lane: "go", Kind: "library", Selector: "pkg/api/api.go"}
	bins := []EntryRoot{
		{Lane: "js", Kind: "bin", Selector: "npm:nodemon/bin/nodemon.js", Name: "nodemon"},
		{Lane: "js", Kind: "bin", Selector: "npm:storybook/bin.js", Name: "storybook"},
	}
	mod := EntryRoot{Lane: "js", Kind: "module", Selector: "src/a.js"}
	cases := []struct {
		name, in, lane    string
		inferred          []EntryRoot
		effective, denied []EntryRoot
		unmatched         []string
	}{
		{
			// review r01 S1, input 1: the lane deny is applied to the mains and is not unmatched.
			name: "lane deny beside a kind list", in: "go:main=cmd/app, !go:cmd/debugtool", lane: "go",
			inferred:  append(append([]EntryRoot{}, goMains...), goLib),
			effective: []EntryRoot{goMains[0], goLib},
			denied:    []EntryRoot{goMains[1]},
		},
		{
			// input 2: the lane deny reaches the bins under an explicit kind auto.
			name: "lane deny beside kind auto", in: "js:bin=auto, !js:npm:storybook", lane: "js",
			inferred:  append(append([]EntryRoot{}, bins...), mod),
			effective: []EntryRoot{bins[0], mod},
			denied:    []EntryRoot{bins[1]},
		},
		{
			// input 3: a kind scope that only denies keeps the lane's none, so no bin comes back.
			name: "kind deny beside lane none", in: "js:none, !js:bin=bin:storybook", lane: "js",
			inferred: append(append([]EntryRoot{}, bins...), mod),
			denied:   append(append([]EntryRoot{}, bins...), mod),
		},
		{
			name: "kind deny keeps a lane list", in: "js:src, !js:bin=bin:storybook", lane: "js",
			inferred:  append(append([]EntryRoot{}, bins...), mod),
			effective: []EntryRoot{mod},
			denied:    bins,
		},
		{
			name: "lane allow reaches every kind", in: "js:module=none, js:npm:nodemon", lane: "js",
			inferred:  append(append([]EntryRoot{}, bins...), mod),
			effective: []EntryRoot{bins[0]},
			denied:    []EntryRoot{bins[1], mod},
		},
		{
			name: "a deny matching no root of its kind is unmatched", in: "js:bin=auto, !js:bin=bin:gone, !js:npm:storybook", lane: "js",
			inferred:  append(append([]EntryRoot{}, bins...), mod),
			effective: []EntryRoot{bins[0], mod},
			denied:    []EntryRoot{bins[1]},
			unmatched: []string{"!bin:gone"},
		},
		{
			name: "a lane deny matching nothing in the lane is unmatched", in: "js:module=none, !js:src/gone.js", lane: "js",
			inferred:  append(append([]EntryRoot{}, bins...), mod),
			effective: bins,
			denied:    []EntryRoot{mod},
			unmatched: []string{"!src/gone.js"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := parseLane(t, tc.in, tc.lane)
			eff, den, add, unm := ApplyEntryOverride(tc.inferred, o)
			norm := func(rs []EntryRoot) []EntryRoot {
				out := append([]EntryRoot{}, rs...)
				sortEntryRoots(out)
				return out
			}
			if !reflect.DeepEqual(norm(eff), norm(tc.effective)) && (len(eff) != 0 || len(tc.effective) != 0) {
				t.Errorf("effective = %+v, want %+v", eff, norm(tc.effective))
			}
			if !reflect.DeepEqual(norm(den), norm(tc.denied)) && (len(den) != 0 || len(tc.denied) != 0) {
				t.Errorf("denied = %+v, want %+v", den, norm(tc.denied))
			}
			if len(add) != 0 {
				t.Errorf("added = %+v, want none", add)
			}
			if !reflect.DeepEqual(unm, tc.unmatched) && (len(unm) != 0 || len(tc.unmatched) != 0) {
				t.Errorf("unmatched = %q, want %q", unm, tc.unmatched)
			}
		})
	}
}

// An allow that selects no inferred root creates a declared root and is not unmatched; the declared
// root keeps the kind the caller declared it for. A deny that covers the declared root leaves the allow
// unmatched.
func TestApplyEntryOverrideDeclaredRoots(t *testing.T) {
	o := parseLane(t, "java:main=class:com.acme.Main, java:handler=class:com.acme.Main, java:class:com.acme.Other", "java")
	eff, _, added, unmatched := ApplyEntryOverride(nil, o)
	want := []EntryRoot{
		{Lane: "java", Kind: "declared", Selector: "class:com.acme.Main", Origin: "entrypoints:handler"},
		{Lane: "java", Kind: "declared", Selector: "class:com.acme.Main", Origin: "entrypoints:main"},
		{Lane: "java", Kind: "declared", Selector: "class:com.acme.Other", Origin: "entrypoints"},
	}
	if !reflect.DeepEqual(added, want) || !reflect.DeepEqual(eff, want) {
		t.Errorf("added = %+v, effective = %+v, want both %+v", added, eff, want)
	}
	if len(unmatched) != 0 {
		t.Errorf("unmatched = %q, want none", unmatched)
	}

	o = parseLane(t, "js:auto, js:scripts/run.js, !js:scripts", "js")
	_, _, added, unmatched = ApplyEntryOverride(nil, o)
	if len(added) != 0 || !reflect.DeepEqual(unmatched, []string{"!scripts", "scripts/run.js"}) {
		t.Errorf("added = %+v, unmatched = %q, want none and [!scripts scripts/run.js]", added, unmatched)
	}
}

// The alias applies the legacy tokens the new grammar rejects; only their Input fails to re-parse.
func TestEntryOverrideForLibraryEntrypointsLegacyTokens(t *testing.T) {
	for _, tok := range []string{"NONE", "Auto", "a:b", "library:x"} {
		lib, err := ParseLibraryEntrypoints(tok)
		if err != nil {
			t.Fatalf("legacy parser rejects %q: %v", tok, err)
		}
		o := EntryOverrideForLibraryEntrypoints(lib)
		if _, err := ParseEntryOverrides(o.Input); err == nil {
			t.Errorf("Input %q of legacy token %q re-parses; the alias doc says it does not", o.Input, tok)
		}
	}
}

// The alias renders the clauses it stands for.
func TestEntryOverrideForLibraryEntrypointsInput(t *testing.T) {
	for in, want := range map[string]string{
		"":               "go:library=auto",
		"none":           "go:library=none",
		"pkg/api,!cmd/x": "go:library=pkg/api,!go:library=cmd/x",
		"!cmd/x":         "!go:library=cmd/x",
	} {
		lib, err := ParseLibraryEntrypoints(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := EntryOverrideForLibraryEntrypoints(lib).Input; got != want {
			t.Errorf("Input(%q) = %q, want %q", in, got, want)
		}
	}
}
