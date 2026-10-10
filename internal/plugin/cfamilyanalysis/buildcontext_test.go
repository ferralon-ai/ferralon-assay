package cfamilyanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// cmakeDB is the shape CMake writes with CMAKE_EXPORT_COMPILE_COMMANDS=ON (macOS, CMake 4.x),
// plus a header entry, which is not a TU.
const cmakeDB = `[
{"directory":"/w/build","command":"/usr/bin/cc   -std=gnu17 -arch arm64 -o a.o -c /w/a.c","file":"/w/a.c"},
{"directory":"/w/build","command":"/usr/bin/c++   -std=gnu++20 -arch arm64 -o b.o -c /w/b.cpp","file":"/w/b.cpp"},
{"directory":"/w/build","command":"/usr/bin/cc   -std=gnu17 -arch arm64 -o c.o -c /w/c.c","file":"/w/c.c"},
{"directory":"/w/build","command":"/usr/bin/cc -c /w/a.h","file":"/w/a.h"}
]`

func ccRuntime(lang, std, driver string) toolchain {
	return toolchain{Name: filepath.Base(driver), Toolchain: driver, Source: sourceCompileDB, Lang: lang, StdLevel: std}
}

func darwinRuntime(lang, std, driver string) toolchain {
	tc := ccRuntime(lang, std, driver)
	tc.Target = "arm64-apple-darwin"
	return tc
}

func TestDeriveBuildContext(t *testing.T) {
	tests := []struct {
		name          string
		files         map[string]string
		wantRuntimes  []toolchain
		wantResolvers []generator
		wantPart      plugin.Partiality
		wantDB        bool
	}{
		{
			name:     "nothing to read",
			files:    map[string]string{"main.c": "int main(void){return 0;}"},
			wantPart: plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:  "cmake tree with C and C++ TUs",
			files: map[string]string{"CMakeLists.txt": "project(p C CXX)", "build/compile_commands.json": cmakeDB},
			wantRuntimes: []toolchain{
				darwinRuntime("c", "gnu17", "/usr/bin/cc"),
				darwinRuntime("c++", "gnu++20", "/usr/bin/c++"),
			},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Complete(),
			wantDB:        true,
		},
		{
			name: "one runtime per distinct target, lang, std and compiler",
			files: map[string]string{"Makefile": "all:", "compile_commands.json": `[
				{"directory":"/w","arguments":["clang","--target=aarch64-linux-gnu","-std=c11","-c","a.c"],"file":"a.c"},
				{"directory":"/w","arguments":["clang","--target=aarch64-linux-gnu","-std=c11","-c","b.c"],"file":"b.c"},
				{"directory":"/w","arguments":["clang","--target=x86_64-linux-gnu","-std=c11","-c","a.c"],"file":"a.c"},
				{"directory":"/w","arguments":["clang","--target=x86_64-linux-gnu","-std=c17","-c","a.c"],"file":"a.c"},
				{"directory":"/w","arguments":["gcc","--target=x86_64-linux-gnu","-std=c17","-c","a.c"],"file":"a.c"}
			]`},
			wantRuntimes: []toolchain{
				{Name: "clang", Toolchain: "clang", Source: sourceCompileDB, Target: "aarch64-linux-gnu", Lang: "c", StdLevel: "c11"},
				{Name: "clang", Toolchain: "clang", Source: sourceCompileDB, Target: "x86_64-linux-gnu", Lang: "c", StdLevel: "c11"},
				{Name: "clang", Toolchain: "clang", Source: sourceCompileDB, Target: "x86_64-linux-gnu", Lang: "c", StdLevel: "c17"},
				{Name: "gcc", Toolchain: "gcc", Source: sourceCompileDB, Target: "x86_64-linux-gnu", Lang: "c", StdLevel: "c17"},
			},
			wantResolvers: []generator{{"make", "make"}},
			wantPart:      plugin.Complete(),
			wantDB:        true,
		},
		{
			name:  "C++-only database is carried, not dropped",
			files: map[string]string{"meson.build": "project('p','cpp')", "builddir/compile_commands.json": `[{"directory":"/w","arguments":["g++","-std=c++17","-c","x.cc"],"file":"x.cc"}]`},
			wantRuntimes: []toolchain{
				{Name: "gcc", Toolchain: "g++", Source: sourceCompileDB, Lang: "c++", StdLevel: "c++17"},
			},
			wantResolvers: []generator{{"meson", "meson setup build"}},
			wantPart:      plugin.Complete(),
			wantDB:        true,
		},
		{
			name:         "database with no generator",
			files:        map[string]string{"compile_commands.json": `[{"directory":"/w","arguments":["cc","-c","a.c"],"file":"a.c"}]`},
			wantRuntimes: []toolchain{ccRuntime("c", "", "cc")},
			wantPart:     plugin.Partial(plugin.PartialReasonNoManifest),
			wantDB:       true,
		},
		{
			name: "cmake cache only: ambient compilers",
			files: map[string]string{
				"CMakeLists.txt":       "project(p C CXX)",
				"build/CMakeCache.txt": "//Path\nCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/c++\nCMAKE_C_COMPILER:FILEPATH=/usr/bin/cc\nCMAKE_C_COMPILER-ADVANCED:INTERNAL=1\nCMAKE_ASM_COMPILER:FILEPATH=CMAKE_ASM_COMPILER-NOTFOUND\n",
			},
			wantRuntimes: []toolchain{
				{Name: "cc", Toolchain: "/usr/bin/cc", Source: sourceAmbient, Lang: "c"},
				{Name: "c++", Toolchain: "/usr/bin/c++", Source: sourceAmbient, Lang: "c++"},
			},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:          "empty database",
			files:         map[string]string{"CMakeLists.txt": "", "compile_commands.json": `[]`},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Partial(reasonCompileDBEmpty),
			wantDB:        true,
		},
		{
			name:          "headers only is an empty TU set",
			files:         map[string]string{"CMakeLists.txt": "", "compile_commands.json": `[{"directory":"/w","arguments":["cc","a.h"],"file":"a.h"}]`},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Partial(reasonCompileDBEmpty),
			wantDB:        true,
		},
		{
			name:          "unparseable database",
			files:         map[string]string{"CMakeLists.txt": "", "compile_commands.json": `[{"directory":`},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Partial(reasonCompileDBUnreadable),
		},
		{
			name: "several build configurations",
			files: map[string]string{
				"CMakeLists.txt":                      "",
				"build-debug/compile_commands.json":   `[{"directory":"/w","arguments":["cc","-std=c99","-c","a.c"],"file":"a.c"}]`,
				"build-release/compile_commands.json": `[{"directory":"/w","arguments":["cc","-std=c11","-c","a.c"],"file":"a.c"}]`,
			},
			wantRuntimes:  []toolchain{ccRuntime("c", "c99", "cc")},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart:      plugin.Partial(reasonBuildConfig),
			wantDB:        true,
		},
		{
			name: "invocations not read in full are declared",
			files: map[string]string{"CMakeLists.txt": "", "compile_commands.json": `[
				{"directory":"/w","arguments":["clang","@args.rsp","-c","a.c"],"file":"a.c"},
				{"directory":"/w","arguments":["cl.exe","/c","b.cpp"],"file":"b.cpp"},
				{"directory":"/w","arguments":["cc","-c","start.S"],"file":"start.S"},
				{"directory":"/w","file":"d.c"}
			]`},
			wantRuntimes: []toolchain{
				{Name: "clang", Toolchain: "clang", Source: sourceCompileDB, Lang: "c"},
				{Name: "msvc", Toolchain: "cl.exe", Source: sourceCompileDB, Lang: "c++"},
			},
			wantResolvers: []generator{{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}},
			wantPart: plugin.Partial(
				reasonCompileDBEntry,
				reasonUnhandled("msvc_driver"),
				reasonUnhandled("response_file"),
				reasonTULang,
			),
			wantDB: true,
		},
		{
			name:         "several generators",
			files:        map[string]string{"CMakeLists.txt": "", "Makefile": "", "MODULE.bazel": "", "compile_commands.json": `[{"directory":"/w","arguments":["cc","-c","a.c"],"file":"a.c"}]`},
			wantRuntimes: []toolchain{ccRuntime("c", "", "cc")},
			wantResolvers: []generator{
				{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"},
				{"bazel", "bazel build //..."},
				{"make", "make"},
			},
			wantPart: plugin.Complete(),
			wantDB:   true,
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
			bc, err := deriveBuildContext(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(bc.Runtimes, tt.wantRuntimes) {
				t.Errorf("Runtimes =\n  %+v\nwant\n  %+v", bc.Runtimes, tt.wantRuntimes)
			}
			if !reflect.DeepEqual(bc.Resolvers, tt.wantResolvers) {
				t.Errorf("Resolvers = %+v, want %+v", bc.Resolvers, tt.wantResolvers)
			}
			if !reflect.DeepEqual(bc.Partiality, tt.wantPart) {
				t.Errorf("Partiality = %+v, want %+v", bc.Partiality, tt.wantPart)
			}
			if (bc.DB != nil) != tt.wantDB {
				t.Errorf("DB present = %v, want %v", bc.DB != nil, tt.wantDB)
			}
		})
	}
}

func TestDeriveBuildContextKeepsRawDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compile_commands.json"), []byte(cmakeDB), 0o644); err != nil {
		t.Fatal(err)
	}
	bc, err := deriveBuildContext(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bc.DB == nil || string(bc.DB.Raw) != cmakeDB {
		t.Fatal("the database bytes are not kept for engine hand-off")
	}
	if len(bc.DB.TUs) != 3 {
		t.Fatalf("TUs = %d, want 3 (the header entry is not a TU)", len(bc.DB.TUs))
	}
}

func TestDeriveBuildContextBadBuildDir(t *testing.T) {
	if _, err := deriveBuildContext(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing build dir: want a hard error")
	}
}
