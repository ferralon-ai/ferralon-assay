package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestModuleReplacementInBuild pins which replace directives codebase_inventory records as the code a
// build compiles a module from: a fork or a local directory, never a replacement that pins the
// module to one of its own releases, and nothing for a module the build does not require.
func TestModuleReplacementInBuild(t *testing.T) {
	const require = "module example.com/app\n\ngo 1.22\n\nrequire k8s.io/kubernetes v1.32.10\n"
	tests := []struct {
		name, gomod, module string
		want                *ModuleReplacement
	}{
		{"fork", require + "replace k8s.io/kubernetes => github.com/kubeedge/kubernetes v1.32.10-kubeedge1\n", "k8s.io/kubernetes",
			&ModuleReplacement{Path: "github.com/kubeedge/kubernetes", Version: "v1.32.10-kubeedge1"}},
		{"versioned replace of a fork", require + "replace k8s.io/kubernetes v1.32.10 => github.com/kubeedge/kubernetes v1.32.10-kubeedge1\n", "k8s.io/kubernetes",
			&ModuleReplacement{Path: "github.com/kubeedge/kubernetes", Version: "v1.32.10-kubeedge1"}},
		{"local directory", require + "replace k8s.io/kubernetes => ./staging/kubernetes\n", "k8s.io/kubernetes",
			&ModuleReplacement{Path: "./staging/kubernetes", Directory: true}},
		{"pinned to one of its own releases", require + "replace k8s.io/kubernetes => k8s.io/kubernetes v1.32.11\n", "k8s.io/kubernetes", nil},
		{"no replace", require, "k8s.io/kubernetes", nil},
		{"replace of another module", require + "replace k8s.io/api => github.com/kubeedge/api v0.1.0\n", "k8s.io/kubernetes", nil},
		{"module not required", require + "replace k8s.io/api => github.com/kubeedge/api v0.1.0\n", "k8s.io/api", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tt.gomod), 0o644); err != nil {
				t.Fatal(err)
			}
			got := moduleReplacementInBuild(context.Background(), dir, GoWorkspace{}, tt.module)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	t.Run("no go.mod", func(t *testing.T) {
		if got := moduleReplacementInBuild(context.Background(), t.TempDir(), GoWorkspace{}, "k8s.io/kubernetes"); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})
}
