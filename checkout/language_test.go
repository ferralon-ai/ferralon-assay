// internal/checkout/language_test.go
package checkout

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree materializes a set of relative file paths (each created empty, with parent
// dirs) under a fresh temp dir and returns the dir. It is the minimal fixture builder for
// exercising DetectLanguage's dominance walk.
func writeTree(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("// fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDetectLanguageDominance(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{
			// The airflow regression: thousands of .py plus a few frontend .js must detect
			// as Python (dominant), not JS (which old first-match precedence returned).
			name: "python-dominant with a few js -> python",
			files: []string{
				"airflow/models.py", "airflow/dag.py", "airflow/api/app.py",
				"airflow/utils/dates.py", "airflow/www/views.py",
				"airflow/www/static/main.js", "airflow/www/static/graph.js",
			},
			want: LangPython,
		},
		{
			name: "js-dominant with a few py -> js",
			files: []string{
				"src/index.js", "src/app.js", "src/router.js", "src/store.js",
				"scripts/build.py", "scripts/deploy.py",
			},
			want: LangJS,
		},
		{
			// go.mod short-circuit is load-bearing: a Go module is Go regardless of stray
			// scripts (which would otherwise dominate by count).
			name: "go.mod root with stray py and js -> go",
			files: []string{
				"go.mod", "main.go",
				"tools/a.py", "tools/b.py", "tools/c.py", "web/x.js",
			},
			want: LangGo,
		},
		{
			// Deterministic tie-break: equal java/js/python counts fall back to precedence
			// order java > js > python > dotnet, so java wins.
			name: "tie java/js/python -> java by precedence",
			files: []string{
				"A.java", "B.java",
				"a.js", "b.js",
				"a.py", "b.py",
			},
			want: LangJava,
		},
		{
			// Tie without java present: js beats python by precedence.
			name: "tie js/python -> js by precedence",
			files: []string{
				"a.js", "b.js",
				"a.py", "b.py",
			},
			want: LangJS,
		},
		// Existing single-language shapes must be unchanged under dominance.
		{name: "single-language go via go.mod", files: []string{"go.mod"}, want: LangGo},
		{name: "single-language java", files: []string{"src/com/example/App.java"}, want: LangJava},
		{name: "single-language js", files: []string{"src/app.js", "package.json"}, want: LangJS},
		{name: "single-language python", files: []string{"pkg/app.py", "requirements.txt"}, want: LangPython},
		{name: "single-language dotnet via .cs", files: []string{"Controllers/FetchController.cs"}, want: LangDotNet},
		{name: "single-language dotnet via .csproj", files: []string{"App.csproj"}, want: LangDotNet},
		{
			// .d.ts declaration files are not JS sources; a lone .d.ts among .py is Python.
			name: "d.ts excluded from js count",
			files: []string{
				"types/index.d.ts",
				"app.py", "util.py",
			},
			want: LangPython,
		},
		{
			// skipSourceDir prune: vendored deps under node_modules / .venv must not flip
			// dominance. Real source is 2 .py; the pruned trees hold many .js/.java.
			name: "vendored trees pruned from counts",
			files: []string{
				"app.py", "worker.py",
				"node_modules/left-pad/index.js", "node_modules/lodash/lodash.js",
				"node_modules/react/react.js", "node_modules/vue/vue.js",
				".venv/lib/site.py",
			},
			want: LangPython,
		},
		{name: "no source -> unknown", files: []string{"README.md", "LICENSE"}, want: LangUnknown},
		{name: "empty tree -> unknown", files: nil, want: LangUnknown},
		// Kotlin+Java interop rule (K1): Kotlin wins when its .kt/.kts count is >= the
		// .java count; Java wins only when strictly dominant.
		{
			name:  "pure-kotlin",
			files: []string{"src/main/kotlin/App.kt", "src/main/kotlin/Util.kt", "build.gradle.kts"},
			want:  LangKotlin,
		},
		{
			// Equal counts: Kotlin+Java interop tie goes to Kotlin, not the historical
			// java-first precedence used for the other language pairs.
			name: "mixed kotlin+java equal counts -> kotlin",
			files: []string{
				"src/main/kotlin/App.kt", "src/main/kotlin/Util.kt",
				"src/main/java/Legacy.java", "src/main/java/Bridge.java",
			},
			want: LangKotlin,
		},
		{
			name: "kotlin-dominant with java -> kotlin",
			files: []string{
				"src/main/kotlin/App.kt", "src/main/kotlin/Util.kt", "src/main/kotlin/Model.kt",
				"src/main/java/Legacy.java",
			},
			want: LangKotlin,
		},
		{
			name: "java-dominant with kotlin -> java",
			files: []string{
				"src/main/java/App.java", "src/main/java/Util.java", "src/main/java/Model.java",
				"src/main/kotlin/Extensions.kt",
			},
			want: LangJava,
		},
		{
			name:  ".kts build script alone counts as kotlin",
			files: []string{"settings.gradle.kts", "src/main/kotlin/App.kt"},
			want:  LangKotlin,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files...)
			if got := DetectLanguage(dir); got != tc.want {
				t.Fatalf("DetectLanguage = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCountSourcesTally locks the per-language tally the dominance decision reads, incl. the
// .d.ts exclusion, the .NET marker set, and the skipSourceDir prune.
func TestCountSourcesTally(t *testing.T) {
	dir := writeTree(t,
		"A.java", "B.java", "C.java",
		"X.kt", "Y.kt", "Z.kts",
		"a.js", "b.jsx", "c.ts", "d.tsx", "e.mjs", "f.cjs",
		"decl.d.ts", // excluded from js
		"x.py", "y.py",
		"P.cs", "P.csproj", "S.sln", "F.fsproj", "V.vbproj",
		"node_modules/pkg/z.js", // pruned
		"build/gen/G.java",      // pruned
	)
	c := countSources(dir)
	if c.java != 3 {
		t.Errorf("java = %d, want 3", c.java)
	}
	if c.kotlin != 3 {
		t.Errorf("kotlin = %d, want 3", c.kotlin)
	}
	if c.js != 6 {
		t.Errorf("js = %d, want 6 (.d.ts excluded, node_modules pruned)", c.js)
	}
	if c.python != 2 {
		t.Errorf("python = %d, want 2", c.python)
	}
	if c.dotnet != 5 {
		t.Errorf("dotnet = %d, want 5", c.dotnet)
	}
}
