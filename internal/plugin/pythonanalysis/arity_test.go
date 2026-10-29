package pythonanalysis

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestParamShapeOf(t *testing.T) {
	cases := []struct {
		params string
		want   paramShape
	}{
		{"()", paramShape{}},
		{"(a, b)", paramShape{required: 2, max: 2}},
		{"(a, b=1, c=2)", paramShape{required: 1, max: 3}},
		{"(self, x=None)", paramShape{required: 1, max: 2}},
		{"(a, b,)", paramShape{required: 2, max: 2}},
		{"(a: int = 1, b: dict[str, int] = {})", paramShape{max: 2}},
		{"(f: Callable[[int, str], int], g=max)", paramShape{required: 1, max: 2}},
		{"(a, /, b, *, c, d=1)", paramShape{required: 3, max: 4}},
		{"(a, *args, **kwargs)", paramShape{required: 1, max: 1, variadic: true}},
		{"(**kw)", paramShape{variadic: true}},
		{"(\n    a,\n    b=(1, 2),\n)", paramShape{required: 1, max: 2}},
	}
	for _, tc := range cases {
		if got := paramShapeOf(tc.params); got != tc.want {
			t.Errorf("paramShapeOf(%q) = %+v, want %+v", tc.params, got, tc.want)
		}
	}
}

// TestCallGraph_DefaultedArity: a call that leaves defaulted parameters out, or passes more
// arguments to *args or **kwargs, names the def; one that passes more arguments than any
// parameter takes does not, and two defs that both accept the call stay ambiguous.
func TestCallGraph_DefaultedArity(t *testing.T) {
	caller := funcSCIP("app", nil, "run", 0)
	cases := []struct {
		name   string
		files  map[string]string
		want   string // the one first-party edge from caller, "" for none
		listed bool   // the site is in Unresolved
	}{
		{
			name:  "defaults left out",
			files: map[string]string{"app.py": "def f(a, b=1, c=2):\n    return a\n\ndef run():\n    return f(1)\n"},
			want:  funcSCIP("app", nil, "f", 3),
		},
		{
			name:  "every parameter passed",
			files: map[string]string{"app.py": "def f(a, b=1, c=2):\n    return a\n\ndef run():\n    return f(1, 2, 3)\n"},
			want:  funcSCIP("app", nil, "f", 3),
		},
		{
			name:  "annotated defaults",
			files: map[string]string{"app.py": "def f(a: int = 1, b: dict[str, int] = {}):\n    return a\n\ndef run():\n    return f()\n"},
			want:  funcSCIP("app", nil, "f", 2),
		},
		{
			name:  "extra arguments to *args",
			files: map[string]string{"app.py": "def f(a, *rest):\n    return a\n\ndef run():\n    return f(1, 2, 3, 4)\n"},
			want:  funcSCIP("app", nil, "f", 2),
		},
		{
			name:  "keyword arguments to **kwargs",
			files: map[string]string{"app.py": "def f(a, **kw):\n    return a\n\ndef run():\n    return f(1, x=2, y=3)\n"},
			want:  funcSCIP("app", nil, "f", 2),
		},
		{
			name:   "more arguments than the parameters take",
			files:  map[string]string{"app.py": "def f(a, b=1):\n    return a\n\ndef run():\n    return f(1, 2, 3, 4)\n"},
			listed: true,
		},
		{
			name:   "too few for the required parameters",
			files:  map[string]string{"app.py": "def f(a, b, c, d=1):\n    return a\n\ndef run():\n    return f(1)\n"},
			listed: true,
		},
		{
			name:   "two defs that both accept the call",
			files:  map[string]string{"m.py": "def f(a):\n    return a\n", "n.py": "def f(a, b=1, c=2):\n    return a\n", "app.py": "def run():\n    return f(1)\n"},
			listed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, tc.files)
			var got []string
			for _, e := range res.Edges {
				if e.Caller.SCIP == caller && !strings.HasPrefix(e.Callee.SCIP, "pypi:") {
					got = append(got, e.Callee.SCIP)
				}
			}
			if tc.want != "" && !slices.Equal(got, []string{tc.want}) {
				t.Errorf("edges from caller = %v, want exactly %s", got, tc.want)
			}
			if tc.want == "" && len(got) > 0 {
				t.Errorf("edges from caller = %v, want none", got)
			}
			listed := slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool { return u.Caller.SCIP == caller })
			if listed != tc.listed {
				t.Errorf("site listed = %v, want %v; unresolved %+v", listed, tc.listed, res.Unresolved)
			}
		})
	}
}
