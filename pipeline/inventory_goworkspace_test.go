package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// goWorkRecorder records the GOWORK each ResolveInventory request names.
type goWorkRecorder struct {
	plugin.StubPlugin
	calls *[]string
}

func (goWorkRecorder) Language() string { return "go" }
func (p goWorkRecorder) ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	*p.calls = append(*p.calls, req.GoWork)
	return plugin.DependencyInventory{Partiality: plugin.Complete()}, nil
}

// The codebase inventory resolves a Go module's graph under the go.work its build runs under, the
// one codebase_inventory resolves; a declared go.work that cannot be established resolves nothing.
func TestResolveCodebaseInventory_GoWorkspace(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.work":  "go 1.22\n\nuse (\n\t.\n\t./b\n)\n",
		"go.mod":   "module example.com/mono\n\ngo 1.22\n",
		"main.go":  "package main\n\nfunc main() {}\n",
		"b/go.mod": "module example.com/mono/b\n\ngo 1.22\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file, err := filepath.EvalSymlinks(filepath.Join(root, "go.work"))
	if err != nil {
		t.Fatal(err)
	}
	codebase := assessment.CodebaseRef{Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: root}}

	for _, tc := range []struct {
		name, declared string
		want           []string
		toolFailure    bool
	}{
		{name: "found", declared: "", want: []string{file}},
		{name: "declared", declared: "go.work", want: []string{file}},
		{name: "off", declared: "off", want: []string{""}},
		{name: "missing", declared: "ci/missing.work", toolFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			inv, _, _, err := ResolveCodebaseInventory(context.Background(), codebase, "",
				WithPlugin(goWorkRecorder{calls: &calls}), WithSubjectGoWork(tc.declared))
			if err != nil {
				t.Fatalf("ResolveCodebaseInventory: %v", err)
			}
			if len(calls) != len(tc.want) || len(calls) == 1 && calls[0] != tc.want[0] {
				t.Errorf("GOWORK requests = %q, want %q", calls, tc.want)
			}
			if got := !inv.Partiality.Complete && len(inv.Partiality.Reasons) == 1 && inv.Partiality.Reasons[0] == plugin.PartialReasonToolFailure; got != tc.toolFailure {
				t.Errorf("partiality = %+v, tool_failure %v", inv.Partiality, tc.toolFailure)
			}
		})
	}
}
