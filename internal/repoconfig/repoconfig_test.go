package repoconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, root, body string) {
	t.Helper()
	dir := filepath.Join(root, ".github")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ferralon.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Absent file is the default-preserving path: zero Config, nothing to say, no error.
func TestLoad_AbsentFileIsZero(t *testing.T) {
	cfg, warns, err := Load(t.TempDir())
	if err != nil || len(warns) != 0 || cfg != (Config{}) {
		t.Fatalf("absent file must be a silent zero config, got cfg=%+v warns=%v err=%v", cfg, warns, err)
	}
}

func TestLoad_V1WithRef(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "# scan the branch the source lives on\nversion: 1\nanalyze:\n  ref: baseline\n")
	cfg, warns, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("a clean v1 file must not warn, got %v", warns)
	}
	if cfg.Version != 1 || cfg.Analyze.Ref != "baseline" {
		t.Fatalf("got %+v", cfg)
	}
}

// Present file WITHOUT analyze.ref selects nothing.
func TestParse_NoRefSelectsNothing(t *testing.T) {
	for name, body := range map[string]string{
		"version only":  "version: 1\n",
		"empty analyze": "version: 1\nanalyze:\n",
		"null ref":      "version: 1\nanalyze:\n  ref: ~\n",
		"empty file":    "",
		"comments only": "# nothing configured yet\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := Parse([]byte(body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.Analyze.Ref != "" {
				t.Fatalf("no ref configured, got %q", cfg.Analyze.Ref)
			}
		})
	}
}

// AC3: malformed YAML fails closed with an error that names the file — never a silent skip.
func TestParse_MalformedFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"unclosed flow":       "version: 1\nanalyze: {ref: baseline\n",
		"bad indentation":     "version: 1\nanalyze:\n  ref: a\n ref2: b\n",
		"tab indentation":     "version: 1\nanalyze:\n\tref: baseline\n",
		"top-level list":      "- version: 1\n",
		"top-level scalar":    "baseline\n",
		"analyze not map":     "version: 1\nanalyze: baseline\n",
		"ref is a list":       "version: 1\nanalyze:\n  ref: [a, b]\n",
		"ref is a bool":       "version: 1\nanalyze:\n  ref: true\n",
		"duplicate key":       "version: 1\nanalyze:\n  ref: a\n  ref: b\n",
		"two documents":       "version: 1\n---\nversion: 1\n",
		"alias":               "x: &b baseline\nversion: 1\nanalyze:\n  ref: *b\n",
		"version is string":   "version: one\n",
		"unsupported version": "version: 2\nanalyze:\n  ref: baseline\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := Parse([]byte(body))
			if err == nil {
				t.Fatalf("must fail closed, got cfg=%+v", cfg)
			}
			if !strings.Contains(err.Error(), ".github/ferralon.yml") {
				t.Fatalf("error must name the file, got %v", err)
			}
			if cfg != (Config{}) {
				t.Fatalf("a failed parse must not leak a partial config, got %+v", cfg)
			}
		})
	}
}

// AC3: unknown keys WARN and the read proceeds, at the top level and inside analyze.
func TestParse_UnknownKeysWarnAndProceed(t *testing.T) {
	body := "version: 1\nnotifications: off\nanalyze:\n  ref: baseline\n  path: services/api\n"
	cfg, warns, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("unknown keys must not fail the parse: %v", err)
	}
	if cfg.Analyze.Ref != "baseline" {
		t.Fatalf("known keys must still be honored, got %+v", cfg)
	}
	joined := strings.Join(warns, "\n")
	for _, k := range []string{`"notifications"`, `"analyze.path"`} {
		if !strings.Contains(joined, k) {
			t.Fatalf("expected a warning naming %s, got %v", k, warns)
		}
	}
}

func TestParse_VersionRecognized(t *testing.T) {
	cfg, warns, err := Parse([]byte("version: 1\n"))
	if err != nil || cfg.Version != 1 || len(warns) != 0 {
		t.Fatalf("version: 1 must be recognized silently, got cfg=%+v warns=%v err=%v", cfg, warns, err)
	}
	cfg, warns, err = Parse([]byte("analyze:\n  ref: baseline\n"))
	if err != nil || cfg.Version != 1 || cfg.Analyze.Ref != "baseline" {
		t.Fatalf("omitted version must assume 1, got cfg=%+v err=%v", cfg, err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "no version") {
		t.Fatalf("omitted version must warn, got %v", warns)
	}
}

// An all-digit abbreviated SHA is typed !!int by YAML; the literal text must survive.
func TestParse_NumericLookingRefKeepsLiteralText(t *testing.T) {
	cfg, _, err := Parse([]byte("version: 1\nanalyze:\n  ref: 0123456\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Analyze.Ref != "0123456" {
		t.Fatalf("ref must keep its source text, got %q", cfg.Analyze.Ref)
	}
}

// AC3: injection-looking values are inert data. They are refused by validation (so they never
// reach git at all) and nothing in them is evaluated — the sentinel file the payloads would
// create never appears.
func TestParse_InjectionLookingRefIsInert(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "pwned")
	payloads := []string{
		`"$(touch ` + sentinel + `)"`,
		`"main; touch ` + sentinel + `"`,
		"\"`touch " + sentinel + "`\"",
		`"main && touch ` + sentinel + `"`,
		`"--upload-pack=touch ` + sentinel + `"`,
		`"-oProxyCommand=touch"`,
		`"main:refs/heads/main"`,
		`"+main"`,
		`"${{ github.token }}"`,
		`"main\nfoo"`,
		`"../../etc/passwd"`,
		`"HEAD@{1}"`,
	}
	for _, p := range payloads {
		t.Run(p, func(t *testing.T) {
			cfg, _, err := Parse([]byte("version: 1\nanalyze:\n  ref: " + p + "\n"))
			if err == nil {
				t.Fatalf("injection-looking ref must be refused, got %+v", cfg)
			}
			if !strings.Contains(err.Error(), "analyze.ref") {
				t.Fatalf("error must name analyze.ref, got %v", err)
			}
		})
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("a ref payload was executed")
	}
}

func TestValidateRef_AcceptsRealRefs(t *testing.T) {
	for _, ref := range []string{
		"main", "baseline", "release/v1.2", "v1.2.3", "feature/foo-bar_baz",
		"0123abc", "9f2c1e5d3b4a69788766554433221100ffeeddcc",
	} {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want nil", ref, err)
		}
	}
}

// A hostile repo must not be able to point the reader at another file on the runner.
func TestLoad_RefusesSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.yml")
	if err := os.WriteFile(outside, []byte("version: 1\nanalyze:\n  ref: baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".github", "ferralon.yml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, _, err := Load(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked config must be refused, got %v", err)
	}
}

func TestLoad_RefusesOversizedFile(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "version: 1\n# "+strings.Repeat("x", maxBytes)+"\n")
	if _, _, err := Load(root); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized config must be refused, got %v", err)
	}
}
