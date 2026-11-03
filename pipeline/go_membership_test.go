package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/checkout/gomodtree"
)

// go-test-bench's shape, trimmed: go 1.16, so go.mod omits indirect modules. go.sum carries
// x/crypto's module-zip hash (built) and only x/text's /go.mod hash (never built).
const (
	goBenchSum = "golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f h1:aZp0e2=\n" +
		"golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f/go.mod h1:jdWPYTVW=\n" +
		"golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU=\n" +
		"github.com/labstack/echo/v4 v4.1.17 h1:abc=\n"
	// A pre-1.17 vendor/modules.txt: x/text is vendored though go.sum holds only its /go.mod hash.
	vendorTxt = "# golang.org/x/text v0.3.0\ngolang.org/x/text/unicode/norm\n" +
		"# golang.org/x/net v0.0.0-20201021035429-f5854403a974 => golang.org/x/net v0.0.0-20210226172049-e18ecbb05110\n" +
		"## explicit\ngolang.org/x/net/http2\n"
	goWorkUse = "go 1.22\n\nuse (\n\t.\n\t./lib\n)\n"
)

// vendored is a go 1.16 module with the given go.sum (none when "") and vendor/modules.txt.
func vendored(sum, modulesTxt string) map[string]string {
	files := map[string]string{"go.mod": "module m\n\ngo 1.16\n", "vendor/modules.txt": modulesTxt}
	if sum != "" {
		files["go.sum"] = sum
	}
	return files
}

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
		{"1.17 replaced module without a require is present", map[string]string{"go.mod": "module m\n\ngo 1.17\n\nreplace golang.org/x/text => ./text\n"}, "golang.org/x/text", true, true},
		{"1.16 module in vendor/modules.txt but not go.sum is present", vendored(goBenchSum, vendorTxt), "golang.org/x/text", true, true},
		{"1.16 package path under a vendored module is present", vendored("", vendorTxt), "golang.org/x/net/http2", true, true},
		{"1.16 module in neither vendor/modules.txt nor go.sum is provably absent", vendored(goBenchSum, vendorTxt), "golang.org/x/sys", false, true},
		{"1.16 malformed vendor/modules.txt fails open", vendored(goBenchSum, "#\n"), "golang.org/x/sys", false, false},
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

// A pre-1.17 absence proven by go.sum still gives way to a nested module that may require it.
func TestGoModRequires_NestedGuardBelow117(t *testing.T) {
	dir := writeTree(t, map[string]string{"go.mod": "module m\n\ngo 1.16\n", "go.sum": goBenchSum})
	nested := func() gomodtree.Tree {
		return gomodtree.Tree{Complete: true, Modules: []gomodtree.Module{{Path: "example.com/tool", Bounded: true, Requires: []string{"golang.org/x/text"}}}}
	}
	if present, known := goModRequires(context.Background(), dir, workspaceFor(t, dir), "golang.org/x/text", nested); present || known {
		t.Fatalf("goModRequires = (%v, %v), want (false, false)", present, known)
	}
}

// The wiring: the go.mod/go.sum answer feeds the intake guard through intakeManifestMembership,
// so x/crypto proceeds and x/text is disqualified no_manifest_entry.
func TestGoModRequiresFeedsIntakeGuard(t *testing.T) {
	ctx := context.Background()
	dir := writeTree(t, map[string]string{"go.mod": "module m\n\ngo 1.16\n", "go.sum": goBenchSum})
	for mod, wantDisq := range map[string]bool{"golang.org/x/crypto": false, "golang.org/x/text": true} {
		coord, has, known := intakeManifestMembership(ctx, artifact.NewMemStore(), "", dir, workspaceFor(t, dir), mod)
		disq, reason := intakeDisqualify("go", "go", coord, has, known)
		if disq != wantDisq || (disq && reason != ReasonNoManifestEntry) {
			t.Errorf("%s: intakeDisqualify = (%v, %q), want disqualified=%v", mod, disq, reason, wantDisq)
		}
	}
}
