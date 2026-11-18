package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGenerateHarness_ResolvesUnderTheBuildsWorkspace: a sink in a workspace member the module
// does not require loads only under the build's go.work, so the skeleton calls it when the request
// names that workspace and names it in a skip when it does not.
func TestGenerateHarness_ResolvesUnderTheBuildsWorkspace(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.work":      "go 1.21\n\nuse (\n\t./app\n\t./lib\n)\n",
		"app/go.mod":   "module example.com/app\n\ngo 1.21\n",
		"app/main.go":  "package main\n\nimport \"example.com/lib\"\n\nfunc main() { lib.Parse(\"\") }\n",
		"lib/go.mod":   "module example.com/lib\n\ngo 1.21\n",
		"lib/parse.go": "package lib\n\nfunc Parse(s string) int { return len(s) }\n",
	}
	for name, src := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const call = "sink.Parse(in)"
	tests := []struct {
		name     string
		goWork   string
		resolved bool
	}{
		{name: "workspace named", goWork: filepath.Join(root, "go.work"), resolved: true},
		{name: "no workspace", goWork: "", resolved: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{
				Sink:     "scip-go gomod example.com/lib . example.com/lib/Parse().",
				Kind:     "fuzz",
				BuildDir: filepath.Join(root, "app"),
				GoWork:   tc.goWork,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(res.Source, call); got != tc.resolved {
				t.Errorf("skeleton calls the sink = %v, want %v:\n%s", got, tc.resolved, res.Source)
			}
		})
	}
}
