package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeTree writes a map of relative-path → content under a fresh temp dir and returns
// the dir. Parent directories are created as needed.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func indexOf(t *testing.T, dir string) plugin.SymbolIndexResult {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	return res
}

func hasDisplay(res plugin.SymbolIndexResult, display string) bool {
	for _, s := range res.Symbols {
		if s.DisplayName == display {
			return true
		}
	}
	return false
}

// The four target sink shapes must all resolve to declared symbols (scope doc §T4):
// a module-level function, a top-level node class, a dotted-module class, and a method
// on a class inside a module.
func TestIndexSymbols_TargetSinkShapes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		// smolagents: module-level function sink
		"local_python_executor.py": `
def evaluate_python_code(code, static_tools, custom_tools):
    """Run restricted python."""
    return eval(code)
`,
		// ComfyUI-Ace-Nodes: node-class sink with an eval() method
		"ace_nodes.py": `
class ACE_ExpressionEval:
    CATEGORY = "ACE"

    def evaluate(self, expression):
        return eval(expression)
`,
		// DeepDiff: dotted-module class with __init__ and apply methods
		"deepdiff/delta.py": `
class Delta:
    def __init__(self, diff, **kwargs):
        self.diff = diff

    def apply(self, obj):
        return obj
`,
		// Pillow: module-level _save "method-shaped" sink under a nested package
		"PIL/JpegImagePlugin.py": `
def _save(im, fp, filename):
    import subprocess
    subprocess.call("convert " + filename, shell=True)
`,
	})

	res := indexOf(t, dir)

	// module-level function
	if !hasDisplay(res, "evaluate_python_code()") && !hasDisplay(res, "evaluate_python_code(3)") {
		t.Errorf("missing smolagents sink evaluate_python_code; got %v", displays(res))
	}
	// node class
	if !hasDisplay(res, "ACE_ExpressionEval") {
		t.Errorf("missing ComfyUI node class ACE_ExpressionEval; got %v", displays(res))
	}
	// dotted-module class + method
	if !hasDisplay(res, "Delta") {
		t.Errorf("missing DeepDiff class Delta; got %v", displays(res))
	}
	if !hasDisplay(res, "Delta.__init__(3)") {
		t.Errorf("missing Delta.__init__ method; got %v", displays(res))
	}
	if !hasDisplay(res, "Delta.apply(2)") {
		t.Errorf("missing Delta.apply method; got %v", displays(res))
	}
	// Pillow _save
	if !hasDisplay(res, "_save(3)") {
		t.Errorf("missing Pillow _save; got %v", displays(res))
	}
}

func displays(res plugin.SymbolIndexResult) []string {
	var out []string
	for _, s := range res.Symbols {
		out = append(out, s.DisplayName)
	}
	return out
}

// A DeepDiff class symbol must carry a well-formed dotted module package so the resolver
// can present the "deepdiff.delta.Delta" advisory form.
func TestIndexSymbols_ModulePackage(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"deepdiff/delta.py": "class Delta:\n    pass\n",
	})
	res := indexOf(t, dir)
	var found bool
	for _, s := range res.Symbols {
		if s.DisplayName == "Delta" {
			found = true
			if s.Package != "deepdiff/delta" {
				t.Errorf("Delta package = %q, want deepdiff/delta", s.Package)
			}
		}
	}
	if !found {
		t.Fatalf("Delta not indexed; got %v", displays(res))
	}
}

// __init__.py folds to the package directory as the module path.
func TestModuleOf_InitFoldsToPackage(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pkg/__init__.py": "def top():\n    pass\n",
	})
	res := indexOf(t, dir)
	for _, s := range res.Symbols {
		if s.DisplayName == "top()" && s.Package != "pkg" {
			t.Errorf("__init__ module = %q, want pkg", s.Package)
		}
	}
}

// A build dir with no Python sources is a hard error (inv.4), never a silent empty index.
func TestIndexSymbols_NoSources_HardError(t *testing.T) {
	dir := t.TempDir()
	if _, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir}); err == nil {
		t.Fatal("empty build dir must be a hard error")
	}
}

// Multi-line signatures, decorators, docstrings, and nested defs must not derail the
// indentation-based scanner.
func TestParse_MultilineAndDecorators(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"svc.py": `
import os

@app.route("/x")
def handler(
    a,
    b,
):
    """A handler.

    Multi-line docstring with a fake def inside:
    def not_a_real_def(): pass
    """
    def inner():
        return 1
    return inner()

class Svc:
    @staticmethod
    def do(self, x):
        return x
`,
	})
	res := indexOf(t, dir)
	if !hasDisplay(res, "handler(2)") {
		t.Errorf("multi-line def handler(2) not parsed; got %v", displays(res))
	}
	if hasDisplay(res, "not_a_real_def()") {
		t.Errorf("docstring content was mis-parsed as a def")
	}
	if !hasDisplay(res, "Svc") || !hasDisplay(res, "Svc.do(2)") {
		t.Errorf("class method Svc.do not parsed; got %v", displays(res))
	}
	if !hasDisplay(res, "inner()") {
		t.Errorf("nested def inner not parsed; got %v", displays(res))
	}
}
