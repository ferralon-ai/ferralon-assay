package gomodtree

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestNested: every go.mod below the root that the root's module graph does not include
// (through its go.work, or a required filesystem replace) is named, relative and sorted, at any
// depth; the go command's own skips (testdata, vendor, dot and underscore directories) are not
// module source.
func TestNested(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		limit int
		want  []string
	}{
		{"root only", map[string]string{"go.mod": "module r\n"}, 0, nil},
		{"stub root above nested modules", map[string]string{
			"go.mod":                      "module r\n",
			"receiver/a/go.mod":           "module r/receiver/a\n",
			"exporter/b/go.mod":           "module r/exporter/b\n",
			"internal/x/y/z/deep/go.mod":  "module r/deep\n",
			"receiver/a/internal/main.go": "package internal\n",
		}, 0, []string{"exporter/b", "internal/x/y/z/deep", "receiver/a"}},
		{"limit stops early", map[string]string{
			"go.mod": "module r\n", "a/go.mod": "module a\n", "b/go.mod": "module b\n",
		}, 1, []string{"a"}},
		{"go command skips", map[string]string{
			"go.mod":                "module r\n",
			"testdata/m/go.mod":     "module t\n",
			"vendor/v/go.mod":       "module v\n",
			".github/m/go.mod":      "module g\n",
			"_examples/go.mod":      "module e\n",
			"pkg/testdata/go.mod":   "module t2\n",
			"tools/go.mod":          "module tools\n",
			"tools/vendor/w/go.mod": "module w\n",
		}, 0, []string{"tools"}},
		{"go.work members are resolved with the root", map[string]string{
			"go.mod":   "module r\n",
			"go.work":  "go 1.21\n\nuse (\n\t.\n\t./a\n)\n",
			"a/go.mod": "module a\n",
			"b/go.mod": "module b\n",
		}, 0, []string{"b"}},
		{"a required filesystem replace is resolved with the root", map[string]string{
			"go.mod":   "module r\n\nrequire example.test/a v0.0.0\n\nreplace example.test/a => ./a\n",
			"a/go.mod": "module example.test/a\n",
			"b/go.mod": "module example.test/b\n",
		}, 0, []string{"b"}},
		{"a replace nothing requires is not", map[string]string{
			"go.mod": "module r\n\nreplace example.test/a => ./a\n", "a/go.mod": "module example.test/a\n",
		}, 0, []string{"a"}},
		{"unparseable go.work lists nothing", map[string]string{
			"go.mod": "module r\n", "go.work": "not a go.work\n", "a/go.mod": "module a\n",
		}, 0, []string{"a"}},
		{"a directory named go.mod is not a module", map[string]string{
			"go.mod": "module r\n", "a/go.mod/keep": "x\n",
		}, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range tc.files {
				p := filepath.Join(root, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := Nested(root, tc.limit); !slices.Equal(got, tc.want) {
				t.Fatalf("Nested = %q, want %q", got, tc.want)
			}
		})
	}
}
