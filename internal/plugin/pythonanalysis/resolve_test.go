package pythonanalysis

import (
	"context"
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
