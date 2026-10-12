package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeModule lays out a single-package module from name → contents.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.22\n"
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestLoadProgram_CgoDisabledBuildDeclaresDroppedCgo: with cgo off, a cgo file vanishes from the
// build with no runtime/cgo left to trip the call-graph detector, so the load itself must say so.
func TestLoadProgram_CgoDisabledBuildDeclaresDroppedCgo(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	const pure = "//go:build !cgo\n\npackage m\n\nfunc Run() {}\n"
	const cgo = "//go:build cgo\n\npackage m\n\n// void run(void) {}\nimport \"C\"\n\nfunc Run() { C.run() }\n"
	const ignored = "//go:build ignore\n\npackage m\n\nimport \"C\"\n"
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"cgo variant dropped", map[string]string{"run.go": pure, "run_cgo.go": cgo}, true},
		{"cgo file excluded by a tag, not by cgo", map[string]string{"run.go": pure, "gen.go": ignored}, false},
		{"no cgo at all", map[string]string{"run.go": pure}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := LoadProgram(context.Background(), writeModule(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonCgo); got != tc.want {
				t.Errorf("cgo declared = %v, want %v (partiality %+v)", got, tc.want, res.Partiality)
			}
		})
	}
}
