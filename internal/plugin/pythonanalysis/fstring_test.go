package pythonanalysis

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_FStringCallSites: a call inside an f-string or t-string substitution is a
// call site of the def around it, with an edge when it resolves and an Unresolved entry when
// it does not. The literal's text, conversion and format spec hold no sites.
func TestCallGraph_FStringCallSites(t *testing.T) {
	helper := "def helper(x):\n    return x\n\n"
	cases := []struct {
		name   string
		files  map[string]string
		want   []string // the first-party edges from app.run
		listed bool     // a site of app.run is in Unresolved
	}{
		{
			name:  "a resolved call",
			files: map[string]string{"app.py": helper + "def run():\n    return f\"{helper(1)}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:   "an unresolved call is listed",
			files:  map[string]string{"app.py": "def run():\n    return f\"{unknown(1)}\"\n"},
			listed: true,
		},
		{
			name:  "a t-string",
			files: map[string]string{"app.py": helper + "def run():\n    return t\"{helper(1)}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "a triple-quoted f-string's later line stays in the def",
			files: map[string]string{"app.py": helper + "def other():\n    return 0\n\ndef run():\n    s = f\"\"\"\nhead\n{helper(1)}\n\"\"\"\n    return other()\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1), funcSCIP("app", nil, "other", 0)},
		},
		{
			name:  "a substitution nested in a format spec",
			files: map[string]string{"app.py": "def width():\n    return 4\n\ndef run(x):\n    return f\"{x:>{width()}}\"\n"},
			want:  []string{funcSCIP("app", nil, "width", 0)},
		},
		{
			name:  "a conversion and a debug specifier",
			files: map[string]string{"app.py": helper + "def run():\n    return f\"{helper(1)!r} {helper(2)=}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1), funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "a format spec holds no call",
			files: map[string]string{"app.py": "def d():\n    return 0\n\ndef run(x):\n    return f\"{x:%Y-%m-%d()}\"\n"},
		},
		{
			name:  "a substitution's commas are not the outer call's arguments",
			files: map[string]string{"app.py": "def one(a):\n    return a\n\ndef run(x, y):\n    return one(f\"{x, y}\")\n"},
			want:  []string{funcSCIP("app", nil, "one", 1)},
		},
		{
			name:  "adjacent substitutions are not a call",
			files: map[string]string{"app.py": "def a():\n    return 0\n\ndef run(b):\n    return f\"{a}{(b)}\"\n"},
		},
		{
			name:   "a literal inside a substitution",
			files:  map[string]string{"app.py": "def parts():\n    return []\n\ndef run():\n    return f\"{':'.join(parts())}\"\n"},
			want:   []string{funcSCIP("app", nil, "parts", 0)},
			listed: true, // str.join is a method call the lane lists
		},
		{
			name:  "an f-string nested in a substitution",
			files: map[string]string{"app.py": helper + "def run():\n    return f\"{f'{helper(1)}'}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "a dict inside a substitution",
			files: map[string]string{"app.py": helper + "def run():\n    return f\"{ {'k': helper(1)}['k'] }\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "an inequality is not a conversion",
			files: map[string]string{"app.py": helper + "def run(a):\n    return f\"{a != helper(1)}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "a quote or bracket in a format spec is text",
			files: map[string]string{"app.py": helper + "def run(x):\n    return f\"{x:'>10}{x:(^4}{helper(1)}\"\n"},
			want:  []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "doubled braces are text",
			files: map[string]string{"app.py": helper + "def run():\n    return f\"{{helper(1)}}\"\n"},
		},
		{
			name:  "a plain string is text",
			files: map[string]string{"app.py": helper + "def run():\n    return \"{helper(1)}\"\n"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, tc.files)
			var got []string
			for _, e := range res.Edges {
				if isRun(e.Caller.SCIP) && !strings.HasPrefix(e.Callee.SCIP, "pypi:") {
					got = append(got, e.Callee.SCIP)
				}
			}
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(slices.Compact(got), slices.Compact(want)) {
				t.Errorf("edges from caller = %v, want %v", got, want)
			}
			listed := slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool { return isRun(u.Caller.SCIP) })
			if listed != tc.listed {
				t.Errorf("site listed = %v, want %v; unresolved %+v", listed, tc.listed, res.Unresolved)
			}
			if hasReason(res.Partiality, plugin.PartialReasonUnlistedSites) {
				t.Errorf("every site is listed; got %v", res.Partiality.Reasons)
			}
		})
	}
}

func isRun(scip string) bool { return strings.Contains(scip, "app/run(") }
