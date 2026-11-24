package jsanalysis

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func jsOverride(t *testing.T, in string) *plugin.EntryOverride {
	t.Helper()
	m, err := plugin.ParseEntryOverrides(in)
	if err != nil {
		t.Fatalf("parse %q: %v", in, err)
	}
	o, ok := m[plugin.EntryLaneJS]
	if !ok {
		t.Fatalf("%q states nothing for js", in)
	}
	return &o
}

// entryFixture is a build whose only route to idle@1.0.0 is the bin of tool, run by a package.json
// script. Removing that bin removes the one load.
func entryFixture(t *testing.T) (*depFixture, string) {
	f := newDepFixture(t, map[string]string{
		"index.js":     "const used = require('used');\nused.make().go();\n",
		"package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"tool --serve"}}`,
	},
		closurePkg("used", map[string]string{"index.js": "exports.make = function make() { return { go() {} }; };\n"}),
		closurePkg("idle", map[string]string{"index.js": "exports.bad = function bad() {};\n"}),
		closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}`, "bin/tool.js": "require('idle');\n"}),
	)
	return f, f.diskCache(t)
}

// TestReachability_EntryOverride: removing an inferred bin takes what only it loads out of the
// closure, the clear that follows carries the override as an assumption, and the record shows what was
// inferred and what stands.
func TestReachability_EntryOverride(t *testing.T) {
	const sink = "npm:idle@1.0.0#bad"
	cases := []struct {
		name          string
		override      string
		wantRefuted   bool
		wantAssumed   string
		wantDenied    []string
		wantUnmatched []string
		wantBins      []string
	}{
		{name: "no override", override: "", wantBins: []string{"npm:tool/bin/tool.js"}},
		{name: "deny the bin", override: "!js:bin=bin:tool", wantRefuted: true, wantAssumed: "bin:tool", wantDenied: []string{"!bin:tool"}, wantBins: []string{}},
		{name: "deny the bin by selector", override: "!js:bin=npm:tool/bin/tool.js", wantRefuted: true, wantAssumed: "npm:tool/bin/tool.js", wantDenied: []string{"!npm:tool/bin/tool.js"}, wantBins: []string{}},
		{name: "unmatched deny", override: "!js:bin=bin:nothing", wantUnmatched: []string{"!bin:nothing"}, wantBins: []string{"npm:tool/bin/tool.js"}},
		{name: "deny of another kind leaves the bin", override: "!js:script=npm:tool/index.js", wantDenied: []string{"!npm:tool/index.js"}, wantBins: []string{"npm:tool/bin/tool.js"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, cache := entryFixture(t)
			req := plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, Package: "pkg:npm/idle@1.0.0", DependencyCache: cache}
			if tc.override != "" {
				req.EntryOverride = jsOverride(t, tc.override)
			}
			res, err := Reachability(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Refutation != nil; got != tc.wantRefuted {
				t.Fatalf("refuted = %v, want %v (%+v)", got, tc.wantRefuted, res.Refutation)
			}
			if tc.wantRefuted {
				last := res.Refutation.Assumptions[len(res.Refutation.Assumptions)-1]
				if !strings.Contains(last, tc.wantAssumed) || !strings.Contains(last, tc.override) {
					t.Errorf("last assumption %q does not name %q", last, tc.wantAssumed)
				}
			}
			rec := res.EntryRoots
			if rec == nil {
				t.Fatal("no entry_roots record")
			}
			if !slices.Equal(rec.Denied, tc.wantDenied) || !slices.Equal(rec.Unmatched, tc.wantUnmatched) {
				t.Errorf("denied %q unmatched %q, want %q and %q", rec.Denied, rec.Unmatched, tc.wantDenied, tc.wantUnmatched)
			}
			if !slices.Contains(rec.Inferred[plugin.EntryKindBin], "npm:tool/bin/tool.js") {
				t.Errorf("inferred bins %q omit the bin that was removed", rec.Inferred[plugin.EntryKindBin])
			}
			if !slices.Equal(rec.Effective[plugin.EntryKindBin], tc.wantBins) {
				t.Errorf("effective bins %q, want %q", rec.Effective[plugin.EntryKindBin], tc.wantBins)
			}
		})
	}
}

// TestReachability_NoOverrideUnchanged: stating no override leaves the assessment as it was: the same
// partiality, paths and refutation with the field absent and with an override that removes nothing.
func TestReachability_NoOverrideUnchanged(t *testing.T) {
	f, cache := entryFixture(t)
	req := plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{"npm:idle@1.0.0#bad"}, Package: "pkg:npm/idle@1.0.0", DependencyCache: cache}
	base, err := Reachability(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.EntryOverride = jsOverride(t, "!js:bin=bin:nothing")
	unmatched, err := Reachability(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*plugin.ReachabilityResult{&base, &unmatched} {
		r.EntryRoots = nil
	}
	a, _ := json.Marshal(base)
	b, _ := json.Marshal(unmatched)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("an override that removes nothing changed the result:\n%s\n%s", a, b)
	}
	if base.Refutation != nil {
		t.Errorf("the bin loads idle; refuted %+v", base.Refutation)
	}
}

// TestReachability_EntryOverrideRefused: the lane refuses what it cannot honour instead of ignoring it.
func TestReachability_EntryOverrideRefused(t *testing.T) {
	for _, in := range []string{"js:bin=bin:x", "!js:module=src/a.js", "js:none"} {
		f, cache := entryFixture(t)
		_, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{"npm:idle@1.0.0#bad"}, DependencyCache: cache, EntryOverride: jsOverride(t, in)})
		if err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

// TestReachability_EntryOverrideDropsItsOwnVeto: a bin that names no file withholds every clear
// until the caller removes it; the removal drops that veto, and the record names the bin by its
// binary name, the one handle it has.
func TestReachability_EntryOverrideDropsItsOwnVeto(t *testing.T) {
	f := newDepFixture(t, map[string]string{
		"index.js":     "const used = require('used');\nused.make().go();\n",
		"package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"tool --serve"}}`,
	},
		closurePkg("used", map[string]string{"index.js": "exports.make = function make() { return { go() {} }; };\n"}),
		closurePkg("idle", map[string]string{"index.js": "exports.bad = function bad() {};\n"}),
		closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","main":"index.js","bin":{"tool":""}}`}),
	)
	cache := f.diskCache(t)
	for _, tc := range []struct {
		override    string
		wantRefuted bool
	}{{"", false}, {"!js:bin=bin:tool", true}} {
		req := plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{"npm:idle@1.0.0#bad"}, Package: "pkg:npm/idle@1.0.0", DependencyCache: cache}
		if tc.override != "" {
			req.EntryOverride = jsOverride(t, tc.override)
		}
		res, err := Reachability(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Refutation != nil; got != tc.wantRefuted {
			t.Errorf("override %q: refuted = %v, want %v", tc.override, got, tc.wantRefuted)
		}
		if tc.override != "" && !slices.Equal(res.EntryRoots.Denied, []string{"!bin:tool"}) {
			t.Errorf("denied = %q", res.EntryRoots.Denied)
		}
	}
}
