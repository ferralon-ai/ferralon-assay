package pythonanalysis

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func resolveOne(t *testing.T, dir, advisorySymbol string) []plugin.Symbol {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		AdvisorySymbols: []string{advisorySymbol},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols(%q): %v", advisorySymbol, err)
	}
	return res.Resolved
}

// Each of the four target CVEs names its sink in a different idiom; all must resolve to
// exactly the declared symbol (scope doc §T5).
func TestResolveDependencySymbols_TargetSinks(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"local_python_executor.py": "def evaluate_python_code(code, static_tools, custom_tools):\n    return eval(code)\n",
		"ace_nodes.py":             "class ACE_ExpressionEval:\n    def evaluate(self, expression):\n        return eval(expression)\n",
		"deepdiff/delta.py":        "class Delta:\n    def __init__(self, diff):\n        self.diff = diff\n    def apply(self, obj):\n        return obj\n",
		"PIL/JpegImagePlugin.py":   "def _save(im, fp, filename):\n    pass\n",
	})

	cases := []struct {
		advisory string
		wantDisp string
	}{
		{"local_python_executor.evaluate_python_code", "evaluate_python_code(3)"}, // module-qualified func
		{"evaluate_python_code", "evaluate_python_code(3)"},                       // bare
		{"ACE_ExpressionEval", "ACE_ExpressionEval"},                              // node class
		{"deepdiff.delta.Delta", "Delta"},                                         // dotted import path
		{"deepdiff.delta.Delta.apply", "Delta.apply(2)"},                          // dotted method
		{"JpegImagePlugin._save", "_save(3)"},                                     // module-leaf-qualified
	}
	for _, c := range cases {
		got := resolveOne(t, dir, c.advisory)
		var found bool
		for _, s := range got {
			if s.DisplayName == c.wantDisp {
				found = true
			}
		}
		if !found {
			var names []string
			for _, s := range got {
				names = append(names, s.DisplayName)
			}
			t.Errorf("resolve %q: want display %q, got %v", c.advisory, c.wantDisp, names)
		}
	}
}

// An advisory symbol absent from the tree resolves to nothing — an empty result, not an
// error (the disqualification path reads absence as symbol-absent).
func TestResolveDependencySymbols_Absent(t *testing.T) {
	dir := writeTree(t, map[string]string{"m.py": "def present():\n    pass\n"})
	got := resolveOne(t, dir, "totally.absent.symbol")
	if len(got) != 0 {
		t.Fatalf("absent symbol must resolve to nothing, got %v", got)
	}
}

// TestResolveDependencySymbols_DependencyBoundary: for a dependency package, an advisory
// symbol resolves only onto a boundary node of that distribution present in the call
// graph, by full dotted path, with Origins naming the distribution the import binding
// resolved to. First-party code that shares the name never resolves.
func TestResolveDependencySymbols_DependencyBoundary(t *testing.T) {
	callsEncode := "import jwt\n\ndef issue(c):\n    return jwt.encode(c)\n"
	cases := []struct {
		name     string
		files    map[string]string
		purl     string
		advisory string
		want     []string // resolved SCIPs, in order
		matched  map[string][]string
	}{
		{
			name:     "boundary node resolves with origin",
			files:    map[string]string{"app.py": callsEncode},
			purl:     "pkg:pypi/pyjwt@2.8.0",
			advisory: "jwt.encode",
			want:     []string{"pypi:pyjwt#jwt.encode"},
			matched:  map[string][]string{"jwt.encode": {"pypi:pyjwt#jwt.encode"}},
		},
		{
			name: "first-party def encode never resolves as jwt.encode",
			files: map[string]string{
				"myapp/jwt.py":  "def encode(payload):\n    return payload\n",
				"myapp/auth.py": "def encode(c):\n    return c\n",
			},
			purl:     "pkg:pypi/PyJWT@2.8.0",
			advisory: "jwt.encode",
		},
		{
			name: "first-party masquerade dropped, boundary kept",
			files: map[string]string{
				"myapp/jwt.py": "def encode(payload):\n    return payload\n",
				"myapp/app.py": callsEncode,
			},
			purl:     "pkg:pypi/pyjwt",
			advisory: "jwt.encode",
			want:     []string{"pypi:pyjwt#jwt.encode"},
			matched:  map[string][]string{"jwt.encode": {"pypi:pyjwt#jwt.encode"}},
		},
		{
			name:     "re-export form is not equated with the internal path",
			files:    map[string]string{"app.py": callsEncode},
			purl:     "pkg:pypi/pyjwt",
			advisory: "jwt.api_jwt.encode",
		},
		{
			name:     "boundary node of another distribution does not resolve",
			files:    map[string]string{"app.py": callsEncode},
			purl:     "pkg:pypi/python-jose",
			advisory: "jwt.encode",
		},
		{
			name:     "advisory on the project itself keeps first-party resolution",
			files:    map[string]string{"deepdiff/delta.py": "class Delta:\n    def apply(self, obj):\n        return obj\n"},
			purl:     "pkg:pypi/deepdiff",
			advisory: "deepdiff.delta.Delta.apply",
			want:     []string{scipSymbol("deepdiff/delta", []string{"Delta"}, functionDescriptor("apply", 2))},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir:        writeTree(t, c.files),
				PURL:            c.purl,
				AdvisorySymbols: []string{c.advisory},
			})
			if err != nil {
				t.Fatalf("ResolveDependencySymbols: %v", err)
			}
			var got []string
			for _, s := range res.Resolved {
				got = append(got, s.SCIP)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("resolved = %v, want %v", got, c.want)
			}
			if len(res.Matched) != 0 || len(c.matched) != 0 {
				if !reflect.DeepEqual(res.Matched, c.matched) {
					t.Errorf("matched = %v, want %v", res.Matched, c.matched)
				}
			}
			for _, id := range got {
				if _, _, boundary := parseBoundarySCIP(id); boundary {
					if res.Origins[id] != "pkg:pypi/pyjwt" {
						t.Errorf("Origins[%s] = %q, want pkg:pypi/pyjwt", id, res.Origins[id])
					}
				} else if _, ok := res.Origins[id]; ok {
					t.Errorf("first-party symbol %s must have no origin, got %q", id, res.Origins[id])
				}
			}
		})
	}
}
