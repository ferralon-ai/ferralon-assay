package brand

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// platformEnv is every environment variable this module reads that is not its own
// configuration: names a runtime platform or a standard tool defines. A key ending in "_" is a
// prefix. Each entry lists the package directories allowed to read it; "cmd" covers every
// entry point under cmd/. Adding an entry is a deliberate act: name the platform that defines
// the variable and why the package cannot take the value from its caller.
var platformEnv = map[string]struct {
	dirs []string
	why  string
}{
	"GITHUB_": {
		dirs: []string{"cmd", "resultsink/github"},
		why:  "GitHub Actions runtime context; the GitHub result sink detects the Actions run it is writing to",
	},
	"ACTIONS_ID_TOKEN_REQUEST_": {
		dirs: []string{"cmd"},
		why:  "GitHub Actions OIDC token endpoint",
	},
	"FERRALON_": {
		dirs: []string{"cmd"},
		why:  "the Action's console-link and self-cleanup wiring, read only by the CLI",
	},
	"OTEL_EXPORTER_OTLP_": {
		dirs: []string{"telemetry"},
		why:  "standard OpenTelemetry exporter endpoints, which the OTLP exporters also read themselves",
	},
	"NUGET_PACKAGES": {
		dirs: []string{"internal/plugin/dotnetanalysis/assembly"},
		why:  "the .NET SDK's global-packages folder override, which the restored assemblies live under",
	},
	"PATH": {
		dirs: []string{"artifactcache/artifactcachetest"},
		why:  "the conformance kit swaps PATH for a spawn-detecting shim and restores it",
	},
}

// dynamicEnvReads is every read site whose key is not a constant the gate can resolve, by file.
var dynamicEnvReads = map[string]string{
	"telemetry/provider.go": "loops over the three OTEL_EXPORTER_OTLP_ endpoint constants",
}

// TestNoHardcodedBrandEnvLiteral fails on a string literal that spells out a complete
// "<EnvPrefix>_X" name. Every such name is declared as EnvPrefix+"_X", so the brand package stays
// the single place a rebrand edits. It does not match the bare prefix or a "_X" suffix fragment.
//
// Demonstrated failure: declaring `const envTrustObservedGo = "ASSAY_TRUST_OBSERVED_GO"` in
// cmd/ferralon-assay/run.go makes this test fail with that file:line.
func TestNoHardcodedBrandEnvLiteral(t *testing.T) {
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(EnvPrefix) + `_[A-Z0-9]+(?:_[A-Z0-9]+)*$`)
	var violations []string
	walkSources(t, func(rel string, fset *token.FileSet, file *ast.File, _ map[string]string) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && re.MatchString(v) {
				violations = append(violations, fmt.Sprintf("%s:%d: hardcoded %q; declare it as brand.EnvPrefix+%q",
					rel, fset.Position(lit.Pos()).Line, v, strings.TrimPrefix(v, EnvPrefix)))
			}
			return true
		})
	})
	report(t, violations)
}

// TestEnvReadsStayAtEntryPoints is the gate that keeps configuration explicit: a library package
// takes its settings from its caller and never reads the process environment on an embedder's
// behalf. Every os.Getenv / os.LookupEnv call in non-test source must resolve to a constant key
// that is either this tool's own EnvPrefix_ name, read only by an entry point under cmd/, or a
// platformEnv name, read only by a package listed for it. A read whose key cannot be resolved must
// be listed in dynamicEnvReads.
//
// Scope: the whole module, non-test .go files, skipping testdata directories (fixture programs
// read their own environment, not this module's).
func TestEnvReadsStayAtEntryPoints(t *testing.T) {
	var violations []string
	walkSources(t, func(rel string, fset *token.FileSet, file *ast.File, consts map[string]string) {
		dir := filepath.ToSlash(filepath.Dir(rel))
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
				return true
			}
			at := fmt.Sprintf("%s:%d", rel, fset.Position(call.Pos()).Line)
			key, ok := evalString(call.Args[0], consts)
			if !ok {
				if dynamicEnvReads[filepath.ToSlash(rel)] == "" {
					violations = append(violations, at+": env key is not a resolvable constant; list the site in dynamicEnvReads")
				}
				return true
			}
			if msg := checkEnvRead(dir, key); msg != "" {
				violations = append(violations, fmt.Sprintf("%s: reads %s: %s", at, key, msg))
			}
			return true
		})
	})
	report(t, violations)
}

// checkEnvRead returns why package dir may not read key, or "" when it may.
func checkEnvRead(dir, key string) string {
	entry := dir == "cmd" || strings.HasPrefix(dir, "cmd/")
	if strings.HasPrefix(key, EnvPrefix+"_") {
		if entry {
			return ""
		}
		return "a library package takes this setting as an option; only an entry point under cmd/ reads it"
	}
	for name, p := range platformEnv {
		if key != name && !(strings.HasSuffix(name, "_") && strings.HasPrefix(key, name)) {
			continue
		}
		for _, d := range p.dirs {
			if d == dir || (d == "cmd" && entry) {
				return ""
			}
		}
		return "this package is not listed for the variable in platformEnv"
	}
	return "neither an EnvPrefix_ name nor a platformEnv name"
}

// walkSources parses every non-test .go file outside testdata and hands each to visit with the
// string constants declared in its package directory.
func walkSources(t *testing.T, visit func(rel string, fset *token.FileSet, file *ast.File, consts map[string]string)) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's own location via runtime.Caller")
	}
	// thisFile is <module>/internal/brand/<this file>, so the module root is three levels up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	fset := token.NewFileSet()
	files := map[string][]*ast.File{} // by package directory
	rels := map[*ast.File]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files[filepath.Dir(rel)] = append(files[filepath.Dir(rel)], f)
		rels[f] = rel
		return nil
	})
	if err != nil {
		t.Fatalf("walk module tree: %v", err)
	}
	for _, pkgFiles := range files {
		consts := packageConsts(pkgFiles)
		for _, f := range pkgFiles {
			visit(rels[f], fset, f, consts)
		}
	}
}

// packageConsts resolves the package-level string constants of one package, iterating so a
// constant defined in terms of another resolves regardless of declaration order.
func packageConsts(files []*ast.File) map[string]string {
	consts := map[string]string{}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if _, done := consts[name.Name]; done {
							continue
						}
						if v, ok := evalString(vs.Values[i], consts); ok {
							consts[name.Name] = v
							changed = true
						}
					}
				}
			}
		}
	}
	return consts
}

// evalString folds a string constant expression built from literals, same-package constants,
// brand.EnvPrefix and +.
func evalString(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(x.Value)
		return v, err == nil
	case *ast.Ident:
		if x.Name == "EnvPrefix" { // inside package brand itself
			return EnvPrefix, true
		}
		v, ok := consts[x.Name]
		return v, ok
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "brand" && x.Sel.Name == "EnvPrefix" {
			return EnvPrefix, true
		}
	case *ast.ParenExpr:
		return evalString(x.X, consts)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, lok := evalString(x.X, consts)
		r, rok := evalString(x.Y, consts)
		return l + r, lok && rok
	}
	return "", false
}

func report(t *testing.T, violations []string) {
	t.Helper()
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("%d violation(s):\n%s", len(violations), strings.Join(violations, "\n"))
	}
}
