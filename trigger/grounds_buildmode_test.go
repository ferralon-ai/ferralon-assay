package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGoModulesOf_BuildModes runs the Go inventory through the SBOM projection to the module list
// the not_exploitable gate reads, per build mode. A vendored build reads the same list as the
// module build; a go.work workspace yields none, so no path collapses.
func TestGoModulesOf_BuildModes(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")
	module := map[string]string{
		"go.mod":   "module example.test/app\n\ngo 1.21\n\nrequire example.test/x v0.0.0\n\nreplace example.test/x => ./x\n",
		"main.go":  "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
		"x/go.mod": "module example.test/x\n\ngo 1.21\n",
		"x/lib.go": "package x\n",
	}
	vendored := map[string]string{
		"vendor/modules.txt":           "# example.test/x v0.0.0 => ./x\n## explicit; go 1.21\nexample.test/x\n",
		"vendor/example.test/x/lib.go": "package x\n",
	}
	workspace := map[string]string{"go.work": "go 1.21\n\nuse .\n"}
	want := goModules{"example.test/app": true, "example.test/x": true}
	tests := []struct {
		name  string
		files []map[string]string
		want  goModules
	}{
		{"module build", []map[string]string{module}, want},
		{"vendored build", []map[string]string{module, vendored}, want},
		{"go.work workspace", []map[string]string{module, workspace}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, files := range tt.files {
				for name, body := range files {
					path := filepath.Join(dir, name)
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			inv, err := goanalysis.ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("ResolveInventory: %v", err)
			}
			sbom, notes := sbomFromInventory(inv, "Go")
			got := goModulesOf(sbom, notes)
			if (got == nil) != (tt.want == nil) || len(got) != len(tt.want) {
				t.Fatalf("goModulesOf = %v, want %v (inventory partiality %+v)", got, tt.want, inv.Partiality)
			}
			for m := range tt.want {
				if !got[m] {
					t.Errorf("goModulesOf = %v, missing %s", got, m)
				}
			}
		})
	}
}
