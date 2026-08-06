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

// brandEnvLiteralRe matches a fully-formed environment-variable literal under any prefix the
// tool has shipped under — the current ASSAY_ and the retired NUCLEON_ / TEGRON_ — e.g.
// "TEGRON_ADVISORY_CORPUS_DIR". It deliberately does NOT match a bare prefix ("ASSAY", the
// value of EnvPrefix in brand_identity.go) or a suffix fragment like "_ADVISORY_CORPUS_DIR"
// (the string-literal half of brand.EnvPrefix+"_ADVISORY_CORPUS_DIR") — only a complete,
// self-contained "<PREFIX>_..." string is the leak this gate exists to catch.
var brandEnvLiteralRe = regexp.MustCompile(`^(?:ASSAY|NUCLEON|TEGRON)_[A-Z0-9]+(?:_[A-Z0-9]+)*$`)

// allowedInternalEnvIdents is the explicit, commented allowlist of const/var identifiers that
// are permitted to hold a bare brand-prefixed literal WITHOUT routing through brand.EnvOrLegacy.
// Every entry here is a deliberate, reviewed exception — a genuinely internal knob (build/CI
// gate, process-scoped credential handoff, or telemetry-internal setting) that is never
// surfaced on a customer-facing surface (action.yml env mapping, --help, a CLI flag, or any
// operator-facing doc). Adding an entry must be a deliberate act: name the identifier, name the
// file, and state WHY it never reaches a customer. Do not add an entry to silence this gate for
// a var that might reach a customer — route it through brand.EnvOrLegacy instead (see run.go /
// storage.go for the pattern: brand.EnvPrefix+"_X" as the derived name, with the retired
// "NUCLEON_X" and "TEGRON_X" names passed as EnvOrLegacy's trailing legacy arguments).
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

// TestNoHardcodedBrandEnvLiteral is the tree-wide regression gate for the incident this gate
// was written for: a customer-facing environment-variable name hardcoded as a bare
// "<PREFIX>_..." string literal, bypassing brand.EnvOrLegacy. Two failures follow from that
// shape. A hardcoded CURRENT name (ASSAY_X) is a site a downstream rebrand silently misses, so
// the brand package stops being the single edit point it exists to be. A hardcoded RETIRED name
// (NUCLEON_X, TEGRON_X) read directly means the current name is never consulted at all, so the
// value an operator sets under the documented name is silently dropped.
//
// It is a plain Go test, not a go/analysis vet-style analyzer, on purpose: it needs zero extra
// CI wiring (no -vettool= flag, no separate lint step to keep configured) — it runs wherever
// `go test ./...` already runs, which is every PR. An AST walk over source files is exactly as
// precise here as a vet analyzer would be; nothing about this check needs vet's package-loading
// or type-checking machinery, since it operates on syntax (string-literal shape), not types.
//
// Scope: ferralon-assay/ only, non-test .go files, excluding corpus/testdata/repros/** (those are
// intentionally-realistic vulnerable-repro fixtures whose env vars are read by the SUBJECT
// programs under test, not by ferralon-assay itself — TEGRON_OOB_URL there names the detonation
// harness's callback channel, unrelated to brand identity). service/ is out of scope: it is the
// proprietary module, never a customer-editable surface, so its TEGRON_ literals are not a brand
// leak. action.yml and other non-.go files are out of scope structurally — the AST parser only
// reads *.go — which is correct: the Action's YAML env mapping is a consumer of these names, not
// a definition site, and must not trip this gate.
//
// Demonstrated failure (see cycle execution note 07-brand-gate.md): reverting
// cmd/ferralon-assay/run.go's envTrustObservedGo/legacyEnvTrustObservedGo pair to the single bare
// `const envTrustObservedGo = "TEGRON_TRUST_OBSERVED_GO"` read via direct os.Getenv — the exact
// shape #229 landed on main — makes this test fail with that file:line.
func TestNoHardcodedBrandEnvLiteral(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's own location via runtime.Caller")
	}
	// thisFile is .../ferralon-assay/brand/brand_envliteral_gate_test.go; its grandparent dir is
	// the ferralon-assay module root, which is also the intended scan root.
	openTegronRoot := filepath.Dir(filepath.Dir(thisFile))
	excludedPrefix := filepath.Join("corpus", "testdata", "repros")

	fset := token.NewFileSet()

	// legacySanctioned{Idents,Literals}: identifiers or inline literals observed in a TRAILING
	// (legacyNames...) argument position of a real brand.EnvOrLegacy(...) call anywhere in the
	// scanned tree — the sanctioned fallback position. EnvOrLegacy is variadic, so every argument
	// from index 1 onward counts; only argument 0 (the brand-derived name) does not. A const
	// following the legacyEnvX naming convention is exempted only if it is ACTUALLY consumed this
	// way, not merely because of its name: naming something "legacyEnvFoo" and reading it via a
	// bare os.Getenv instead still trips the gate.
	legacySanctionedIdents := map[string]bool{}
	legacySanctionedLiterals := map[string]bool{}

	type site struct {
		ident string // "" when the literal isn't bound to a named const/var
		pos   token.Pos
		lit   string
	}
	sitesByPos := map[token.Pos]site{}

	walkErr := filepath.WalkDir(openTegronRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(openTegronRoot, path)
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
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "EnvOrLegacy" {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "brand" || len(node.Args) < 2 {
					return true
				}
				for _, rawArg := range node.Args[1:] {
					switch arg := rawArg.(type) {
					case *ast.Ident:
						legacySanctionedIdents[arg.Name] = true
					case *ast.BasicLit:
						if arg.Kind == token.STRING {
							if v, uerr := strconv.Unquote(arg.Value); uerr == nil {
								legacySanctionedLiterals[v] = true
							}
						}
					}
				}
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
		t.Fatalf("walk ferralon-assay tree: %v", walkErr)
	}

	var violations []string
	for _, s := range sitesByPos {
		if legacySanctionedLiterals[s.lit] {
			continue
		}
		if s.ident != "" && (legacySanctionedIdents[s.ident] || allowedInternalEnvIdents[s.ident] != "") {
			continue
		}
		pos := fset.Position(s.pos)
		rel, _ := filepath.Rel(openTegronRoot, pos.Filename)
		violations = append(violations, fmt.Sprintf(
			"ferralon-assay/%s:%d: hardcoded literal %q — a customer-facing TEGRON_* env var must "+
				"never be a bare string literal read outside brand.EnvOrLegacy, because a stealth "+
				"build's public surfaces (action.yml env mapping, --help, CI config) must carry no "+
				"\"TEGRON\" engine identifier. Fix: declare a brand.EnvPrefix+\"_X\" derived name and "+
				"a %q legacy fallback const, then read both via brand.EnvOrLegacy(derived, legacy) — "+
				"see cmd/ferralon-assay/run.go's envAdvisoryCorpusDir/legacyEnvAdvisoryCorpusDir for the "+
				"pattern. If this really is internal-only and can never reach a customer surface, add "+
				"it to allowedInternalEnvIdents in this file with a one-line justification — that is "+
				"a deliberate, reviewed act, not a default.",
			rel, pos.Line, s.lit, s.lit))
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("found %d hardcoded TEGRON_* env-var literal(s) outside brand.EnvOrLegacy:\n\n%s",
			len(violations), strings.Join(violations, "\n\n"))
	}
}
