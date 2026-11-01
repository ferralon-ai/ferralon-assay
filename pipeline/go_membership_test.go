package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// go-test-bench's shape, trimmed: go 1.16, so go.mod omits indirect modules. go.sum carries
// x/crypto's module-zip hash (built) and only x/text's /go.mod hash (never built).
const (
	goBenchSum = "golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f h1:aZp0e2=\n" +
		"golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f/go.mod h1:jdWPYTVW=\n" +
		"golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU=\n" +
		"github.com/labstack/echo/v4 v4.1.17 h1:abc=\n"
)

func TestGoModRequires(t *testing.T) {
	sum116 := map[string]string{"go.mod": "module m\n\ngo 1.16\n\nrequire github.com/labstack/echo/v4 v4.1.17\n", "go.sum": goBenchSum}
	tests := []struct {
		name        string
		files       map[string]string
		module      string
		wantPresent bool
		wantKnown   bool
	}{
		{"1.16 indirect module with h1 in go.sum is present", sum116, "golang.org/x/crypto", true, true},
		{"1.16 package path inside a built module is present", sum116, "golang.org/x/crypto/ssh", true, true},
		{"1.16 module with only /go.mod hash is provably absent", sum116, "golang.org/x/text", false, true},
		{"1.16 direct require is present", sum116, "github.com/labstack/echo/v4", true, true},
		{"1.16 no go.sum fails open", map[string]string{"go.mod": "module m\n\ngo 1.16\n"}, "golang.org/x/crypto", false, false},
		{"1.16 unparseable go.sum fails open", map[string]string{"go.mod": "module m\n\ngo 1.16\n", "go.sum": "garbage line\n"}, "golang.org/x/crypto", false, false},
		{"1.16 empty go.sum is provably absent", map[string]string{"go.mod": "module m\n\ngo 1.16\n", "go.sum": ""}, "golang.org/x/crypto", false, true},
		{"no go directive reads go.sum", map[string]string{"go.mod": "module m\n", "go.sum": goBenchSum}, "golang.org/x/crypto", true, true},
		{"no go directive, no go.sum fails open", map[string]string{"go.mod": "module m\n"}, "golang.org/x/crypto", false, false},
		{"1.16 replaced module is present", map[string]string{"go.mod": "module m\n\ngo 1.16\n\nreplace golang.org/x/text => ./text\n", "go.sum": goBenchSum}, "golang.org/x/text", true, true},
		{"1.17 missing require is proof, go.sum ignored", map[string]string{"go.mod": "module m\n\ngo 1.17\n", "go.sum": goBenchSum}, "golang.org/x/crypto", false, true},
		{"1.21 missing require is proof without go.sum", map[string]string{"go.mod": "module m\n\ngo 1.21\n"}, "golang.org/x/crypto", false, true},
		{"1.21 require is present", map[string]string{"go.mod": "module m\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.1.0\n"}, "golang.org/x/crypto", true, true},
		{"unparseable go.mod fails open", map[string]string{"go.mod": "module"}, "golang.org/x/crypto", false, false},
		{"no go.mod fails open", map[string]string{}, "golang.org/x/crypto", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, c := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			present, known := goModRequires(dir, tc.module)
			if present != tc.wantPresent || known != tc.wantKnown {
				t.Fatalf("goModRequires(%q) = (%v, %v), want (%v, %v)", tc.module, present, known, tc.wantPresent, tc.wantKnown)
			}
		})
	}
}

// The wiring: the go.mod/go.sum answer feeds the intake guard, so x/crypto proceeds and x/text
// is disqualified no_manifest_entry.
func TestGoModRequiresFeedsIntakeGuard(t *testing.T) {
	dir := t.TempDir()
	for n, c := range map[string]string{"go.mod": "module m\n\ngo 1.16\n", "go.sum": goBenchSum} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for mod, wantDisq := range map[string]bool{"golang.org/x/crypto": false, "golang.org/x/text": true} {
		has, known := goModRequires(dir, mod)
		disq, reason := intakeDisqualify("go", "go", mod, has, known)
		if disq != wantDisq || (disq && reason != ReasonNoManifestEntry) {
			t.Errorf("%s: intakeDisqualify = (%v, %q), want disqualified=%v", mod, disq, reason, wantDisq)
		}
	}
}
