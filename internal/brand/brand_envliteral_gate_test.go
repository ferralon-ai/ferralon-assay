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

// brandEnvLiteralRe matches a fully-formed environment-variable literal under the current ASSAY_
// prefix or the NUCLEON_ / TEGRON_ prefixes, which are never this module's to read — e.g.
// "TEGRON_ADVISORY_CORPUS_DIR". It deliberately does NOT match a bare prefix ("ASSAY", the
// value of EnvPrefix in brand_identity.go) or a suffix fragment like "_ADVISORY_CORPUS_DIR"
// (the string-literal half of brand.EnvPrefix+"_ADVISORY_CORPUS_DIR") — only a complete,
// self-contained "<PREFIX>_..." string is the leak this gate exists to catch.
var brandEnvLiteralRe = regexp.MustCompile(`^(?:ASSAY|NUCLEON|TEGRON)_[A-Z0-9]+(?:_[A-Z0-9]+)*$`)

// allowedInternalEnvIdents is the explicit, commented allowlist of const/var identifiers that
// are permitted to hold a bare prefixed env-var literal. Every entry here is a deliberate,
// reviewed exception, and adding one must be a deliberate act: name the identifier, name the
// file, and state WHY it can never be read on behalf of an embedding host or reach a customer
// surface (action.yml env mapping, --help, a CLI flag, or any operator-facing doc). The fix for
// almost every violation is not an entry here but brand.EnvPrefix+"_X", read only by an entry
// point under cmd/ and passed into the library as an explicit option.
var allowedInternalEnvIdents = map[string]string{
	"scipAnalyzerImageEnv": "internal/plugin/javaanalysis/scipjava.go — gates the Prove-only Java/SCIP " +
		"container image. Build/CI knob only: not wired into action.yml, --help, or any operator doc " +
		"(Java packaging is a known separate blocker, task 01 inventory).",
	"scipDockerBinEnv": "internal/plugin/javaanalysis/scipjava.go — docker binary override for the same " +
		"internal container gate as scipAnalyzerImageEnv above.",
	"EnvEnvironment": "telemetry/provider.go — OTEL deployment.environment.name override. " +
		"Internal-only per its own F-6 review doc comment: never printed, no flag surface, not part " +
		"of any OSS operator-facing doc.",
	"EnvSampleRatio": "telemetry/provider.go — OTEL trace sample-ratio override. Internal-only, " +
		"same F-6 review basis as EnvEnvironment above.",
	"EnvLevel": "telemetry/level.go — OTEL coverage-tier selector. Internal-only per its own doc " +
		"comment (F-6 review), same basis as the other telemetry/ entries.",
	"credEnvVar": "checkout/git.go — names the env key used to hand a GitHub installation token " +
		"to a child git process for one clone/fetch. The token lives in that child process's " +
		"environment only (never at rest, never in argv); ferralon-assay never reads this var itself, " +
		"and no customer ever sets it.",
}

// TestNoHardcodedBrandEnvLiteral is the tree-wide regression gate against a prefixed
// environment-variable name hardcoded as a bare "<PREFIX>_..." string literal. Two failures follow
// from that shape. A hardcoded ASSAY_X is a site a downstream rebrand silently misses, so the brand
// package stops being the single edit point it exists to be. A hardcoded NUCLEON_X or TEGRON_X is a
// library reading, under an embedding host's name, configuration that host should pass in
// explicitly — the host then configures this module through an ambient side channel it cannot see
// in any signature.
//
// It is a plain Go test, not a go/analysis vet-style analyzer, on purpose: it needs zero extra
// CI wiring (no -vettool= flag, no separate lint step to keep configured) — it runs wherever
// `go test ./...` already runs, which is every PR. An AST walk over source files is exactly as
// precise here as a vet analyzer would be; nothing about this check needs vet's package-loading
// or type-checking machinery, since it operates on syntax (string-literal shape), not types.
//
// Scope: the whole module, non-test .go files, excluding corpus/testdata/repros/** (those are
// intentionally-realistic vulnerable-repro fixtures whose env vars are read by the SUBJECT
// programs under test, not by this module — TEGRON_OOB_URL there names the detonation
// harness's callback channel, unrelated to brand identity). action.yml and other non-.go files are
// out of scope structurally — the AST parser only reads *.go — which is correct: the Action's YAML
// env mapping is a consumer of these names, not a definition site, and must not trip this gate.
//
// Demonstrated failure: declaring `const envTrustObservedGo = "ASSAY_TRUST_OBSERVED_GO"` in
// cmd/ferralon-assay/run.go instead of deriving it from brand.EnvPrefix makes this test fail with
// that file:line.
func TestNoHardcodedBrandEnvLiteral(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's own location via runtime.Caller")
	}
	// thisFile is <module>/internal/brand/brand_envliteral_gate_test.go, so the module root —
	// the scan root — is three levels up.
	moduleRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	excludedPrefix := filepath.Join("corpus", "testdata", "repros")

	fset := token.NewFileSet()

	type site struct {
		ident string // "" when the literal isn't bound to a named const/var
		pos   token.Pos
		lit   string
	}
	sitesByPos := map[token.Pos]site{}

	walkErr := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(moduleRoot, path)
			if rel == excludedPrefix || strings.HasPrefix(rel, excludedPrefix+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", path, rerr)
		}
		file, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if i >= len(node.Values) {
						continue
					}
					lit, ok := node.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, uerr := strconv.Unquote(lit.Value)
					if uerr != nil || !brandEnvLiteralRe.MatchString(v) {
						continue
					}
					sitesByPos[lit.Pos()] = site{ident: name.Name, pos: lit.Pos(), lit: v}
				}
			case *ast.BasicLit:
				// Catches a literal NOT bound to any name (e.g. os.Getenv("TEGRON_X") inlined
				// directly). If the ValueSpec case above already recorded this exact node
				// (same Pos, visited as a parent before this generic case sees the same
				// literal as a child), don't clobber the ident it carries.
				if node.Kind != token.STRING {
					return true
				}
				if _, already := sitesByPos[node.Pos()]; already {
					return true
				}
				v, uerr := strconv.Unquote(node.Value)
				if uerr == nil && brandEnvLiteralRe.MatchString(v) {
					sitesByPos[node.Pos()] = site{ident: "", pos: node.Pos(), lit: v}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk module tree: %v", walkErr)
	}

	var violations []string
	for _, s := range sitesByPos {
		if s.ident != "" && allowedInternalEnvIdents[s.ident] != "" {
			continue
		}
		pos := fset.Position(s.pos)
		rel, _ := filepath.Rel(moduleRoot, pos.Filename)
		violations = append(violations, fmt.Sprintf(
			"%s:%d: hardcoded env-var literal %q. Fix: an ASSAY_ name is declared as "+
				"brand.EnvPrefix+\"_X\" (see cmd/ferralon-assay/run.go's envAdvisoryCorpusDir); a "+
				"setting a library needs is read by an entry point under cmd/ and passed in as an "+
				"explicit option, never read from the environment by the library itself. Only a knob "+
				"that can never be read on behalf of an embedding host belongs in "+
				"allowedInternalEnvIdents, with a one-line justification.",
			rel, pos.Line, s.lit))
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("found %d hardcoded prefixed env-var literal(s):\n\n%s",
			len(violations), strings.Join(violations, "\n\n"))
	}
}
