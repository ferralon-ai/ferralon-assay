package pipeline

import (
	"context"
	"testing"
)

// go-test-bench's shape, trimmed: go 1.16, so go.mod omits indirect modules. go.sum carries
// x/crypto's module-zip hash (built) and only x/text's /go.mod hash (never built).
const (
	goBenchSum = "golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f h1:aZp0e2=\n" +
		"golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f/go.mod h1:jdWPYTVW=\n" +
		"golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU=\n" +
		"github.com/labstack/echo/v4 v4.1.17 h1:abc=\n"
	goWorkUse = "go 1.22\n\nuse (\n\t.\n\t./lib\n)\n"
)

// workspace is a go.work using the root module m and ./lib at the given go versions; the root and
// lib each get an empty go.sum, lib's replaced by libSum and go.work.sum written when non-empty.
func workspace(rootGo, libGo, workSum, libSum string) map[string]string {
	files := map[string]string{
		"go.work":    goWorkUse,
		"go.mod":     "module m\n\ngo " + rootGo + "\n",
		"go.sum":     "",
		"lib/go.mod": "module example.com/lib\n\ngo " + libGo + "\n",
		"lib/go.sum": libSum,
	}
	if workSum != "" {
		files["go.work.sum"] = workSum
	}
	return files
}

func TestGoModRequires_GoVersions(t *testing.T) {
	sum116 := map[string]string{"go.mod": "module m\n\ngo 1.16\n\nrequire github.com/labstack/echo/v4 v4.1.17\n", "go.sum": goBenchSum}
	tests := []struct {
		name        string
		files       map[string]string
		module      string
		wantPresent bool
		wantKnown   bool
	}{
		{"1.16 direct require is present", sum116, "github.com/labstack/echo/v4", true, true},
		{"1.17 missing require is proof, go.sum ignored", map[string]string{"go.mod": "module m\n\ngo 1.17\n", "go.sum": goBenchSum}, "golang.org/x/crypto", false, true},
		{"1.21 missing require is proof without go.sum", map[string]string{"go.mod": "module m\n\ngo 1.21\n"}, "golang.org/x/crypto", false, true},
		{"1.21 require is present", map[string]string{"go.mod": "module m\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.1.0\n"}, "golang.org/x/crypto", true, true},
		{"go.work at 1.17 throughout: missing require is proof", workspace("1.21", "1.17", "", goBenchSum), "golang.org/x/crypto", false, true},
		{"unparseable go.mod fails open", map[string]string{"go.mod": "module"}, "golang.org/x/crypto", false, false},
		{"no go.mod fails open", map[string]string{}, "golang.org/x/crypto", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			present, known := goModRequires(context.Background(), dir, workspaceFor(t, dir), tc.module, noNestedModules)
			if present != tc.wantPresent || known != tc.wantKnown {
				t.Fatalf("goModRequires(%q) = (%v, %v), want (%v, %v)", tc.module, present, known, tc.wantPresent, tc.wantKnown)
			}
		})
	}
}
