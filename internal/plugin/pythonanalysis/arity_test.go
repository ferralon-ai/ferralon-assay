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
		{"(a, key=lambda x, *ys: 0)", paramShape{required: 1, max: 2}},
		{"(a, key=lambda **kw: 0, b=1)", paramShape{required: 1, max: 3}},
		{"(a, f=lambda x, y: lambda z, w: 0)", paramShape{required: 1, max: 2}},
		{"(a: Annotated[int, Field(default=1)])", paramShape{required: 1, max: 1}},
		{"(lambda_, b)", paramShape{required: 2, max: 2}},
		{"(a, key=lambda x=lambda: 1, *ys: 0)", paramShape{required: 1, max: 2}},
		{"(a, key=lambda x=lambda: 1, y=2: 0, b=3)", paramShape{required: 1, max: 3}},
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
			name:   "a lambda default's star parameter is not the def's",
			files:  map[string]string{"app.py": "def f(a, key=lambda x, *ys: 0):\n    return a\n\ndef run():\n    return f(1, 2, 3, 4, 5)\n"},
			listed: true,
		},
		{
			name:   "a nested lambda default's star parameter is not the def's",
			files:  map[string]string{"app.py": "def f(a, key=lambda x=lambda: 1, *ys: 0):\n    return a\n\ndef run():\n    return f(1, 2, 3, 4, 5)\n"},
			listed: true,
		},
		{
			name:  "a lone def takes star-expanded arguments",
			files: map[string]string{"app.py": "def f(a, b, c):\n    return a\n\ndef run():\n    return f(*XS)\n"},
			want:  funcSCIP("app", nil, "f", 3),
		},
		{
			name:  "star-expanded arguments only one def can take",
			files: map[string]string{"m.py": "def f(a, b, c, d):\n    return a\n", "n.py": "def f():\n    return 0\n", "app.py": "def run():\n    return f(1, *REST)\n"},
			want:  funcSCIP("m", nil, "f", 4),
		},
		{
			name:   "star-expanded keyword arguments two defs can take",
			files:  map[string]string{"m.py": "def f(a, b, c):\n    return a\n", "n.py": "def f(x):\n    return x\n", "app.py": "def run():\n    return f(**OPTS)\n"},
			listed: true,
		},
		{
			name:   "star-expanded arguments a def with fewer parameters can take",
			files:  map[string]string{"m.py": "def f(a, b):\n    return a\n", "n.py": "def f():\n    return 0\n", "app.py": "def run():\n    return f(*A)\n"},
			listed: true,
		},
		{
			name:   "star-expanded arguments a variadic def can take",
			files:  map[string]string{"m.py": "def f(*args):\n    return 0\n", "n.py": "def f(a, b, c):\n    return a\n", "app.py": "def run():\n    return f(1, 2, *A)\n"},
			listed: true,
		},
		{
			name:   "a product argument is no star expansion",
			files:  map[string]string{"app.py": "def f(a, b, c):\n    return a\n\ndef run():\n    return f(X * Y)\n"},
			listed: true,
		},
		{
			name:   "an argument that is only a bracketed literal counts",
			files:  map[string]string{"m.py": "def f():\n    return 0\n", "n.py": "def f(a, b, c):\n    return a\n", "app.py": "def run():\n    return f([X])\n"},
			listed: true,
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
