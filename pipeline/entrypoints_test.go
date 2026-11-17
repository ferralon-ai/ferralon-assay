package pipeline

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func mustOverrides(t *testing.T, in string) map[string]plugin.EntryOverride {
	t.Helper()
	m, err := plugin.ParseEntryOverrides(in)
	if err != nil {
		t.Fatalf("ParseEntryOverrides(%q): %v", in, err)
	}
	return m
}

// TestRouteEntrypoints: the go lane's library clauses become its library-entrypoints statement, and
// every other clause fails closed, whatever lane the scan runs.
func TestRouteEntrypoints(t *testing.T) {
	const refusal = "does not accept entry-point overrides yet"
	cases := []struct {
		name     string
		in       string
		scanLane string
		want     *plugin.LibraryEntrypoints
		wantErr  string
	}{
		{name: "nothing stated", in: "", scanLane: "go"},
		{name: "bare auto, go scan", in: "auto", scanLane: "go"},
		{name: "bare auto, java scan", in: "auto", scanLane: "java"},
		{name: "bare auto, no lane", in: "auto", scanLane: ""},
		{name: "go library none", in: "go:library=none", scanLane: "go", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}},
		{name: "go library list and deny", in: "go:library=pkg/api, !go:library=pkg/api/internal", scanLane: "go",
			want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg/api"}, Exclude: []string{"pkg/api/internal"}}},
		{name: "go library deny alone keeps auto", in: "!go:library=cmd/x", scanLane: "go",
			want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto, Exclude: []string{"cmd/x"}}},
		{name: "go library auto", in: "go:library=auto", scanLane: "go", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}},
		{name: "go library clause on a java scan still routes", in: "go:library=none", scanLane: "java", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}},
		{name: "go lane auto states nothing", in: "go:auto", scanLane: "go"},
		{name: "go main", in: "go:main=none", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "go handler deny", in: "!go:handler=internal/x", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "go lane-wide selector", in: "go:pkg/api", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "go lane-wide none", in: "go:none", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "go main auto", in: "go:main=auto", scanLane: "go"},
		{name: "go handler auto", in: "go:handler=auto", scanLane: "go"},
		{name: "go main auto beside a library clause", in: "go:main=auto go:library=none", scanLane: "go", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}},
		{name: "go main auto beside a main deny", in: "go:main=auto !go:main=cmd/x", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "go library npm selector", in: "go:library=npm:x", scanLane: "go", wantErr: "package paths"},
		{name: "go library class selector", in: "go:library=class:Foo", scanLane: "go", wantErr: "package paths"},
		{name: "go library bin selector", in: "go:library=bin:x", scanLane: "go", wantErr: "package paths"},
		{name: "go library deny of a bin selector", in: "!go:library=bin:x", scanLane: "go", wantErr: "package paths"},
		{name: "go library beside go main", in: "go:library=none go:main=cmd/x", scanLane: "go", wantErr: "lane go " + refusal},
		{name: "java", in: "java:main=class:com.acme.Main", scanLane: "java", wantErr: "lane java " + refusal},
		{name: "kotlin", in: "!kotlin:handler=src/A.kt", scanLane: "kotlin", wantErr: "lane kotlin " + refusal},
		{name: "js", in: "!js:bin=bin:storybook", scanLane: "js", wantErr: "lane js " + refusal},
		{name: "python", in: "python:none", scanLane: "python", wantErr: "lane python " + refusal},
		{name: "dotnet", in: "dotnet:main=none", scanLane: "dotnet", wantErr: "lane dotnet " + refusal},
		{name: "a clause for a lane the scan does not run", in: "js:none", scanLane: "go", wantErr: "lane js " + refusal},
		{name: "python lane auto states the default", in: "python:auto", scanLane: "python"},
		{name: "js lane auto", in: "js:auto", scanLane: "js"},
		{name: "js lane auto, scan elsewhere", in: "js:auto", scanLane: "go"},
		{name: "java kind auto", in: "java:main=auto", scanLane: "java"},
		{name: "js auto with a deny", in: "js:auto !js:x", scanLane: "js", wantErr: "lane js " + refusal},
		{name: "js auto with a path", in: "js:auto js:x", scanLane: "js", wantErr: "lane js " + refusal},
		{name: "java kind auto beside a kind deny", in: "java:main=auto !java:handler=x", scanLane: "java", wantErr: "lane java " + refusal},
		{name: "every lane auto", in: "go:auto java:auto kotlin:auto js:auto python:auto dotnet:auto", scanLane: "java"},
		{name: "bare none, go scan", in: "none", scanLane: "go", wantErr: "write go:library=none"},
		{name: "bare none, java scan", in: "none", scanLane: "java", wantErr: "lane java " + refusal},
		{name: "bare none, kotlin scan", in: "none", scanLane: "kotlin", wantErr: "lane kotlin " + refusal},
		{name: "bare none, js scan", in: "none", scanLane: "js", wantErr: "lane js " + refusal},
		{name: "bare none, python scan", in: "none", scanLane: "python", wantErr: "lane python " + refusal},
		{name: "bare none, dotnet scan", in: "none", scanLane: "dotnet", wantErr: "lane dotnet " + refusal},
		{name: "bare none, a scan no lane runs", in: "none", scanLane: "cfamily"},
		{name: "bare none, no language", in: "none", scanLane: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, perr := plugin.ParseEntryOverrides(tc.in)
			if perr != nil {
				t.Fatalf("parse %q: %v", tc.in, perr)
			}
			got, err := RouteEntrypoints(m, tc.scanLane)
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
				t.Errorf("routed = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRouteEntrypoints_KindAutoEveryLane: "<lane>:<kind>=auto" on its own states the default and is
// accepted the same way for every lane and every kind the lane infers, on a scan of that lane and of
// any other; a clause that asks for something beside it is refused for every one of them (the go
// library kind is the only one a lane reads).
func TestRouteEntrypoints_KindAutoEveryLane(t *testing.T) {
	kinds := map[string][]string{
		"go":     {"main", "library", "handler"},
		"java":   {"main", "handler"},
		"kotlin": {"main", "handler"},
		"js":     {"module", "bin", "script"},
		"python": {"handler", "main"},
		"dotnet": {"main", "runtime", "handler"},
	}
	for lane, ks := range kinds {
		for _, kind := range ks {
			for _, scan := range []string{lane, "go", ""} {
				auto := lane + ":" + kind + "=auto"
				m, err := plugin.ParseEntryOverrides(auto)
				if err != nil {
					t.Fatalf("parse %q: %v", auto, err)
				}
				got, err := RouteEntrypoints(m, scan)
				if err != nil || (got != nil && lane != "go") {
					t.Errorf("%q on a %q scan: routed %+v, err %v; want accepted", auto, scan, got, err)
				}

				deny := auto + " !" + lane + ":" + kind + "=x/y"
				if lane == "go" && kind == "library" {
					continue // the one clause a lane reads
				}
				m, err = plugin.ParseEntryOverrides(deny)
				if err != nil {
					t.Fatalf("parse %q: %v", deny, err)
				}
				if _, err := RouteEntrypoints(m, scan); err == nil {
					t.Errorf("%q on a %q scan: accepted, want refused", deny, scan)
				}
			}
		}
	}
}

// TestRouteEntrypoints_EqualsLibraryEntrypoints: for every library-entrypoints value, the same
// statement written as go:library clauses routes to the identical LibraryEntrypoints.
func TestRouteEntrypoints_EqualsLibraryEntrypoints(t *testing.T) {
	for _, in := range []string{
		"auto", "none", " none ", "pkg/api, ./pkg/client/...", "!internal/tools\n!cmd", "auto,cmd/x",
		"pkg,!pkg/x,pkg", "./...", "!pkg,!pkg", "pkg/b,pkg/a", "auto,!pkg/x",
	} {
		t.Run(in, func(t *testing.T) {
			want, err := plugin.ParseLibraryEntrypoints(in)
			if err != nil {
				t.Fatalf("legacy parse: %v", err)
			}
			got, err := RouteEntrypoints(mustOverrides(t, plugin.EntryOverrideForLibraryEntrypoints(want).Input), "go")
			if err != nil {
				t.Fatalf("route: %v", err)
			}
			if got == nil || !reflect.DeepEqual(*got, want) {
				t.Errorf("routed = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSameLibraryStatement(t *testing.T) {
	le := func(mode string, inc, exc []string) plugin.LibraryEntrypoints {
		return plugin.LibraryEntrypoints{Mode: mode, Include: inc, Exclude: exc}
	}
	for _, tc := range []struct {
		name string
		a, b plugin.LibraryEntrypoints
		want bool
	}{
		{"unset mode reads as auto", le("", nil, nil), le(plugin.LibraryEntrypointsAuto, nil, nil), true},
		{"paths in another order", le(plugin.LibraryEntrypointsPaths, []string{"b", "a"}, nil), le(plugin.LibraryEntrypointsPaths, []string{"a", "b"}, nil), true},
		{"different mode", le(plugin.LibraryEntrypointsNone, nil, nil), le(plugin.LibraryEntrypointsAuto, nil, nil), false},
		{"different include", le(plugin.LibraryEntrypointsPaths, []string{"a"}, nil), le(plugin.LibraryEntrypointsPaths, []string{"b"}, nil), false},
		{"include against exclude", le(plugin.LibraryEntrypointsAuto, []string{"a"}, nil), le(plugin.LibraryEntrypointsAuto, nil, []string{"a"}), false},
	} {
		if got := SameLibraryStatement(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// reachRequest runs symbol_mapping and reachability_ingress under opts, and returns the request the
// lane saw and the stage's error.
func reachRequest(t *testing.T, opts ...AssessOption) (plugin.ReachabilityRequest, error) {
	t.Helper()
	var seen plugin.ReachabilityRequest
	p := multiSinkPlugin{seen: &seen}
	var reach Stage
	for _, s := range AssessStages(append([]AssessOption{WithPlugin(p)}, opts...)...) {
		if s.Name() == "reachability_ingress" {
			reach = s
		}
	}
	if reach == nil {
		t.Fatal("no reachability_ingress stage")
	}
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-entry"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}
	putJSON(t, store, c.ID, artifact.TypeInventory, map[string]any{"build_dir": "/checkout/svc", "checkout_root": "/checkout"})
	if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	return seen, reach.Run(context.Background(), c, store)
}

// TestReachability_EntrypointsRouteToLibraryEntrypoints: the go lane's request is the same whether
// the statement came as library-entrypoints or as the equivalent entrypoints clauses; an input no
// lane honours fails the stage before the lane is called.
func TestReachability_EntrypointsRouteToLibraryEntrypoints(t *testing.T) {
	for _, in := range []string{"none", "pkg/api,!pkg/api/x", "!cmd/x", "auto"} {
		t.Run("equivalent to "+in, func(t *testing.T) {
			le, err := plugin.ParseLibraryEntrypoints(in)
			if err != nil {
				t.Fatal(err)
			}
			viaAlias, err := reachRequest(t, WithLibraryEntrypoints(le))
			if err != nil {
				t.Fatal(err)
			}
			viaClauses, err := reachRequest(t, WithEntrypoints(mustOverrides(t, plugin.EntryOverrideForLibraryEntrypoints(le).Input)))
			if err != nil {
				t.Fatal(err)
			}
			if viaAlias.LibraryEntrypoints == nil || !reflect.DeepEqual(viaClauses, viaAlias) {
				t.Errorf("request via entrypoints = %+v, via library-entrypoints = %+v", viaClauses, viaAlias)
			}
		})
	}
	t.Run("the statement given as library-entrypoints wins", func(t *testing.T) {
		none := plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}
		got, err := reachRequest(t, WithLibraryEntrypoints(none), WithEntrypoints(mustOverrides(t, "go:library=pkg/api")))
		if err != nil || got.LibraryEntrypoints == nil || got.LibraryEntrypoints.Mode != plugin.LibraryEntrypointsNone {
			t.Errorf("request = %+v, err = %v, want the none statement", got.LibraryEntrypoints, err)
		}
	})
	t.Run("a clause no lane honours fails the stage", func(t *testing.T) {
		got, err := reachRequest(t, WithEntrypoints(mustOverrides(t, "js:none")))
		if err == nil || !strings.Contains(err.Error(), "lane js does not accept entry-point overrides yet") {
			t.Fatalf("err = %v, want the lane refusal", err)
		}
		if got.VulnID != "" {
			t.Errorf("the lane was called (%+v) after the refusal", got)
		}
	})
	t.Run("nothing stated", func(t *testing.T) {
		got, err := reachRequest(t, WithEntrypoints(nil))
		if err != nil || got.LibraryEntrypoints != nil {
			t.Errorf("request = %+v, err = %v, want nil statement", got.LibraryEntrypoints, err)
		}
	})
}
