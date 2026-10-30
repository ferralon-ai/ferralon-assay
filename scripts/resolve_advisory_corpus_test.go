// Hermetic self-test for resolve-advisory-corpus.sh, the Action's advisory-corpus resolver, and for
// action.yml's wiring of its outputs into the fetch and scan steps. No network.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	publisherIdentity = "ferralon-intel-publisher@ferralon.iam.gserviceaccount.com"
	publisherIssuer   = "https://accounts.google.com"
	publisherCorpus   = "ferralon-ai/vulnerability-corpus"
)

// resolvedCorpus is the script's output, keyed as action.yml reads it.
type resolvedCorpus map[string]string

// runResolveCorpus runs the script with only the given IN_* inputs set, and returns its outputs, or
// ok=false and the combined output when it exits non-zero.
func runResolveCorpus(t *testing.T, env map[string]string) (resolvedCorpus, bool, string) {
	t.Helper()
	script, err := filepath.Abs("resolve-advisory-corpus.sh")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "github_output")
	cmd := exec.Command("bash", script)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "IN_") && !strings.HasPrefix(kv, "GITHUB_OUTPUT=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "GITHUB_OUTPUT="+out)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	log, err := cmd.CombinedOutput()
	if err != nil {
		return nil, false, string(log)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := resolvedCorpus{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		if _, dup := got[k]; dup {
			t.Fatalf("output %q written twice:\n%s", k, raw)
		}
		got[k] = v
	}
	return got, true, string(log)
}

func TestResolveAdvisoryCorpus(t *testing.T) {
	publisherFull := resolvedCorpus{
		"repo": publisherCorpus, "policy": "full",
		"signer-identity": publisherIdentity, "signer-issuer": publisherIssuer, "required": "1", "require-bundle": "1",
	}
	cases := []struct {
		name    string
		env     map[string]string
		want    resolvedCorpus // nil when the script must fail
		failMsg string         // substring of the failure, when it fails
	}{
		{
			name: "default: the public corpus, full, publisher signer",
			env:  map[string]string{},
			want: publisherFull,
		},
		{
			name: "explicit false is the default",
			env:  map[string]string{"IN_BUILTIN_ONLY": "false"},
			want: publisherFull,
		},
		{
			name: "opt-out: built-in test advisories only, nothing required",
			env:  map[string]string{"IN_BUILTIN_ONLY": "true"},
			want: resolvedCorpus{
				"repo": "", "policy": "", "signer-identity": "", "signer-issuer": "",
				"required": "0", "require-bundle": "0",
			},
		},
		{
			name: "explicit policy on the default corpus keeps the publisher signer and the git fallback",
			env:  map[string]string{"IN_CORPUS_POLICY": "published-7d"},
			want: resolvedCorpus{
				"repo": publisherCorpus, "policy": "published-7d",
				"signer-identity": publisherIdentity, "signer-issuer": publisherIssuer, "required": "1", "require-bundle": "0",
			},
		},
		{
			name: "the old Quickstart: default corpus named, no policy, takes full",
			env:  map[string]string{"IN_CORPUS_REPO": publisherCorpus},
			want: publisherFull,
		},
		{
			name: "explicit signer on the default corpus wins",
			env:  map[string]string{"IN_SIGNER_IDENTITY": "someone@example.com", "IN_SIGNER_ISSUER": "https://issuer.example"},
			want: resolvedCorpus{
				"repo": publisherCorpus, "policy": "full",
				"signer-identity": "someone@example.com", "signer-issuer": "https://issuer.example", "required": "1",
				"require-bundle": "1",
			},
		},
		{
			name: "a third-party corpus takes no default policy or signer",
			env:  map[string]string{"IN_CORPUS_REPO": "acme/corpus"},
			want: resolvedCorpus{
				"repo": "acme/corpus", "policy": "", "signer-identity": "", "signer-issuer": "",
				"required": "1", "require-bundle": "0",
			},
		},
		{
			name: "a third-party corpus with its own policy and signer",
			env: map[string]string{
				"IN_CORPUS_REPO": "acme/corpus", "IN_CORPUS_POLICY": "full",
				"IN_SIGNER_IDENTITY": "acme@example.com", "IN_SIGNER_ISSUER": "https://issuer.example",
			},
			want: resolvedCorpus{
				"repo": "acme/corpus", "policy": "full",
				"signer-identity": "acme@example.com", "signer-issuer": "https://issuer.example", "required": "1",
				"require-bundle": "0",
			},
		},
		{
			name: "a checked-out directory fetches nothing and is required",
			env:  map[string]string{"IN_CORPUS_DIR": "/work/corpus", "IN_CORPUS_POLICY": "full"},
			want: resolvedCorpus{
				"repo": "", "policy": "", "signer-identity": "", "signer-issuer": "",
				"required": "1", "require-bundle": "0",
			},
		},
		{
			name:    "opt-out with a corpus input is a contradiction",
			env:     map[string]string{"IN_BUILTIN_ONLY": "true", "IN_CORPUS_POLICY": "full"},
			failMsg: "builtin-test-advisories-only is 'true', but an advisory-corpus input is also set",
		},
		{
			name:    "opt-out must be a boolean",
			env:     map[string]string{"IN_BUILTIN_ONLY": "yes"},
			failMsg: "builtin-test-advisories-only is 'yes'",
		},
		{
			name:    "repo must be owner/repo",
			env:     map[string]string{"IN_CORPUS_REPO": "acme/../corpus"},
			failMsg: "is not an owner/repo",
		},
		{
			name:    "a line break cannot forge an output",
			env:     map[string]string{"IN_CORPUS_POLICY": "full\nrequired=0"},
			failMsg: "contains a line break",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, log := runResolveCorpus(t, tc.env)
			if tc.want == nil {
				if ok {
					t.Fatalf("resolved %v, want a failure containing %q", got, tc.failMsg)
				}
				if !strings.Contains(log, tc.failMsg) {
					t.Fatalf("failure %q does not contain %q", log, tc.failMsg)
				}
				return
			}
			if !ok {
				t.Fatalf("script failed:\n%s", log)
			}
			if len(got) != len(tc.want) {
				t.Errorf("outputs %v, want exactly %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestActionReadsResolvedCorpus: every step that fetches a corpus or declares one to the scanner
// reads the resolve step's outputs, never the raw inputs, so the defaults reach all of them. The
// requirement reads '1' when the output is missing, so a resolve that never ran fails closed.
func TestActionReadsResolvedCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string            `yaml:"name"`
				ID   string            `yaml:"id"`
				If   string            `yaml:"if"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	type want struct{ step, key, value string }
	cases := []want{
		{"corpus-bundle", "if", "steps.corpus.outputs.repo != '' && steps.corpus.outputs.policy != ''"},
		{"corpus-bundle", "CORPUS_REPO", "${{ steps.corpus.outputs.repo }}"},
		{"corpus-bundle", "CORPUS_POLICY", "${{ steps.corpus.outputs.policy }}"},
		{"corpus-bundle", "CORPUS_SIGNER_IDENTITY", "${{ steps.corpus.outputs.signer-identity }}"},
		{"corpus-bundle", "CORPUS_SIGNER_ISSUER", "${{ steps.corpus.outputs.signer-issuer }}"},
		{"corpus-bundle", "CORPUS_REQUIRE_BUNDLE", "${{ steps.corpus.outputs.require-bundle }}"},
		{"Fetch the advisory corpus (unauthenticated, shallow + sparse)", "if", "steps.corpus.outputs.repo != '' && steps.corpus-bundle.outputs.route != 'bundle'"},
		{"Fetch the advisory corpus (unauthenticated, shallow + sparse)", "CORPUS_REPO", "${{ steps.corpus.outputs.repo }}"},
		{"Fetch the advisory corpus (unauthenticated, shallow + sparse)", "CORPUS_POLICY", "${{ steps.corpus.outputs.policy }}"},
		{"run", "IN_ADVISORY_CORPUS_REPO", "${{ steps.corpus.outputs.repo }}"},
		{"run", "IN_ADVISORY_CORPUS_POLICY", "${{ steps.corpus.outputs.policy }}"},
		{"run", "ASSAY_ADVISORY_CORPUS_POLICY", "${{ steps.corpus.outputs.policy }}"},
		{"run", "ASSAY_ADVISORY_CORPUS_REQUIRED", "${{ steps.corpus.outputs.required || '1' }}"},
	}
	order := map[string]int{}
	for i, s := range action.Runs.Steps {
		if s.ID != "" {
			order[s.ID] = i
		}
		order[s.Name] = i
	}
	for _, c := range cases {
		i, found := order[c.step]
		if !found {
			t.Errorf("action.yml has no step %q", c.step)
			continue
		}
		s := action.Runs.Steps[i]
		got := s.Env[c.key]
		if c.key == "if" {
			got = s.If
		}
		if got != c.value {
			t.Errorf("step %q %s = %q, want %q", c.step, c.key, got, c.value)
		}
	}
	if order["corpus"] >= order["corpus-bundle"] {
		t.Error("the resolve step must run before the corpus fetch")
	}
}
