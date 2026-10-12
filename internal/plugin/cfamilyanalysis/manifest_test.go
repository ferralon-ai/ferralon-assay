package cfamilyanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestBuildManifest(t *testing.T) {
	tests := []struct {
		name          string
		files         map[string]string
		wantRuntimes  []plugin.RuntimeSpec
		wantResolvers []plugin.ResolverSpec
		wantPart      plugin.Partiality
	}{
		{
			name:  "compile DB with C and C++ TUs",
			files: map[string]string{"CMakeLists.txt": "", "build/compile_commands.json": cmakeDB},
			wantRuntimes: []plugin.RuntimeSpec{
				{Name: "cc", Toolchain: "/usr/bin/cc", Source: plugin.RuntimeSourceCompileDB, Target: "arm64-apple-darwin", Lang: "c", StdLevel: "gnu17"},
				{Name: "c++", Toolchain: "/usr/bin/c++", Source: plugin.RuntimeSourceCompileDB, Target: "arm64-apple-darwin", Lang: "c++", StdLevel: "gnu++20"},
			},
			wantResolvers: []plugin.ResolverSpec{{Name: "cmake", Command: "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON", Source: plugin.RuntimeSourceDeclared}},
			wantPart:      plugin.Complete(),
		},
		{
			name:  "ambient compiler only",
			files: map[string]string{"build/CMakeCache.txt": "CMAKE_C_COMPILER:FILEPATH=/usr/bin/gcc-13\n"},
			wantRuntimes: []plugin.RuntimeSpec{
				{Name: "gcc", Toolchain: "/usr/bin/gcc-13", Source: plugin.RuntimeSourceAmbient, Lang: "c"},
			},
			wantPart: plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:     "no compile DB, no generator",
			files:    map[string]string{"a.c": ""},
			wantPart: plugin.Partial(plugin.PartialReasonNoManifest),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				p := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Runtimes, tt.wantRuntimes) {
				t.Errorf("Runtimes = %+v, want %+v", got.Runtimes, tt.wantRuntimes)
			}
			if !reflect.DeepEqual(got.Resolvers, tt.wantResolvers) {
				t.Errorf("Resolvers = %+v, want %+v", got.Resolvers, tt.wantResolvers)
			}
			if !reflect.DeepEqual(got.Partiality, tt.wantPart) {
				t.Errorf("Partiality = %+v, want %+v", got.Partiality, tt.wantPart)
			}
		})
	}
}
