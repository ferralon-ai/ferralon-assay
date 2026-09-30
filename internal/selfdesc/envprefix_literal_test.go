// envprefix_literal_test.go — the same source-level defect as stateref_literal_test.go (a
// re-inlined literal where a derivation belongs), applied to the tool's own env-var prefix.
//
// # What it enforces
//
// brand.EnvPrefix is the single source of truth for the tool's env-var namespace (see
// internal/brand/brand_identity.go). A literal that spells the CURRENT prefix as a bare
// "<PREFIX>_..." string — instead of deriving it via brand.EnvPrefix+"_X", the pattern
// cmd/ferralon-assay/run.go's envAdvisoryCorpusDir and its three siblings follow — is a site a
// downstream rebrand silently misses, exactly the failure stateref_literal_test.go guards
// against for the state ref.
//
// internal/brand already carries a wider gate for this shape
// (brand_envliteral_gate_test.go, TestNoHardcodedBrandEnvLiteral), which also flags the
// NUCLEON_/TEGRON_ prefixes and carries an allowlist for genuinely internal knobs. This test does
// not attempt to replace that: it is deliberately narrower (it flags ONLY the current prefix and
// has no allowlist) and deliberately more paranoid about one specific thing — it derives its own
// matcher from brand.EnvPrefix at test-RUN time, never a hardcoded prefix string in its own
// source, so it keeps working unattended across a future rebrand.
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
)

// TestNoCurrentEnvPrefixLiteral fails any non-test .go file in the module that spells
// brand.EnvPrefix's current value as a bare env-var-shaped string literal instead of deriving
// it.
func TestNoCurrentEnvPrefixLiteral(t *testing.T) {
	// Anchored, and built from brand.EnvPrefix at run time — never a hardcoded prefix string —
	// so this check keeps matching the CURRENT prefix even after a rebrand changes it.
	envPrefixLiteral := regexp.MustCompile(`^` + regexp.QuoteMeta(brand.EnvPrefix) + `_[A-Z0-9]+(?:_[A-Z0-9]+)*$`)

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
			val, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if !envPrefixLiteral.MatchString(val) {
				return true
			}
			line := fset.Position(lit.Pos()).Line
			t.Errorf("%s:%d spells the current env-var prefix as the bare literal %q; derive it "+
				"as brand.EnvPrefix+\"_X\" instead — see run.go's envAdvisoryCorpusDir for the "+
				"pattern. brand.EnvPrefix (%q) is the single source of truth and this literal is "+
				"a site a rebrand silently misses", rel, line, val, brand.EnvPrefix)
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
	t.Logf("checked %d non-test Go files for a bare %q-prefixed env-var literal", checked, brand.EnvPrefix)
}
