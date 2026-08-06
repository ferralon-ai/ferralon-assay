// stateref_literal_test.go — the general case of the re-inlined-literal defect, checked at the
// source level rather than at the surface.
//
// HERMETIC and always on: it parses Go source, builds nothing, executes nothing, touches no
// network. It belongs in the default `go test ./...` run because it is the cheapest possible
// version of the check and because it catches the defect at the moment it is written, not at the
// moment a release is cut.
//
// # What it enforces
//
// internal/brand's doc comment states the rule:
//
//	No consumer may re-inline one of these strings as a literal. A literal is a site a downstream
//	rebrand silently misses.
//
// Nothing enforced it. The state ref is the highest-consequence instance: statestore.DefaultRef is
// derived from brand.RefNamespace, while the CLI help text and the self-cleanup PR body — text the
// tool writes into the CUSTOMER'S repository — spell a different namespace as a literal. Following
// our own documented uninstall therefore deletes a ref that does not exist and leaves the real
// state behind.
//
// The test walks every non-test .go file in the module, looks at STRING LITERALS ONLY (via go/ast,
// so comments and identifiers are out of scope — prose that describes history is not a defect), and
// fails any refs/<namespace>/state whose namespace is not brand.RefNamespace's.
//
// # Scope, and why it is drawn here
//
//   - Non-test files only. A _test.go file may legitimately use a foreign ref as INPUT DATA — a
//     fixture asserting that an operator-supplied ref overrides the default, say — and flagging
//     that would be a false positive on a correct test.
//   - String literals only. `// DeleteStateRef removes refs/tegron/state.` in a doc comment is
//     stale prose, worth fixing, but it is not a value the tool emits.
//   - Whole module, including statestore itself. statestore builds its ref from brand.RefNamespace
//     and so has no literal to find; if one ever appears there it is exactly as wrong.
//
// This subsumes any per-surface divergence check for one particular copy string: a new surface that
// re-inlines the ref fails here without anyone remembering to add a case for it.
package selfdesc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// moduleRoot is the ferralon-assay module root, relative to this package's test working directory.
// Declared here rather than in the `live`-tagged file so the hermetic test does not depend on a
// build tag being set.
const moduleRoot = "../.."

// stateRefLiteral matches any refs/<namespace>/state spelling inside a string literal. It matches
// the WRONG namespaces as readily as the right one — that is the point; a pattern anchored on the
// correct spelling would make drift invisible.
var stateRefLiteral = regexp.MustCompile(`refs/([A-Za-z0-9._-]+)/state`)

// TestStateRefLiteralsMatchStateStore fails any re-inlined state-ref namespace in the tree.
func TestStateRefLiteralsMatchStateStore(t *testing.T) {
	// Computed, never snapshotted: the expectation is whatever statestore writes today.
	want := statestore.DefaultRef

	// Sanity anchor. If this ever fails, the derivation itself moved and every finding below is
	// measured against the wrong yardstick.
	if want != "refs/"+brand.RefNamespace+"/state" {
		t.Fatalf("statestore.DefaultRef = %q, which is no longer refs/<brand.RefNamespace>/state (%q) — "+
			"this test's premise moved and its scrape pattern needs rethinking", want, brand.RefNamespace)
	}

	root := moduleRoot
	fset := token.NewFileSet()
	var checked int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			// testdata holds vendored corpus JSON and fixture trees, not this module's code;
			// dot-directories hold tooling config.
			switch {
			case d.Name() == "testdata", d.Name() == "vendor", strings.HasPrefix(d.Name(), "."):
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parsing %s: %v", path, perr)
			return nil
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			// Unquote so an interpreted literal's escapes are resolved; a raw string round-trips
			// unchanged. A literal that will not unquote is not one we can reason about.
			val, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			for _, loc := range stateRefLiteral.FindAllStringIndex(val, -1) {
				m := val[loc[0]:loc[1]]
				if m == want {
					continue
				}
				// Report the line the SPELLING is on, not the line the literal opens on: a
				// multi-line raw string (the CLI usage banners) would otherwise send the reader
				// dozens of lines away from the text to fix.
				line := fset.Position(lit.Pos()).Line + strings.Count(val[:loc[0]], "\n")
				t.Errorf("%s:%d re-inlines the state ref as the literal %q; statestore.DefaultRef is %q\n"+
					"  derive it (statestore.DefaultRef) instead of spelling it — brand.RefNamespace is the\n"+
					"  single source of truth, and this literal is a site a rebrand silently misses",
					rel, line, m, want)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if checked == 0 {
		t.Fatalf("parsed no Go files under %s — the walk is broken, not the tree", root)
	}
	t.Logf("checked %d non-test Go files against statestore.DefaultRef = %q", checked, want)
}
