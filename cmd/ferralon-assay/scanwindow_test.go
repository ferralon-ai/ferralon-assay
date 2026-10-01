package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func writeRepoConfig(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if body == "" {
		return root
	}
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "ferralon.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// The repository config overrides the workflow's policy input; with neither, no window is selected.
func TestRunScanWindow(t *testing.T) {
	for _, tc := range []struct {
		name, config, policy string
		want                 string
		wantErr              string
	}{
		{name: "no config, no input", want: "window=\npolicy=\nsource=none\n"},
		{name: "config without a window, no input", config: "version: 1\nanalyze:\n  ref: main\n", want: "window=\npolicy=\nsource=none\n"},
		{name: "input only", policy: "published-7d", want: "window=7d\npolicy=published-7d\nsource=policy_input\n"},
		{name: "input outside the four windows", policy: "kev", want: "window=\npolicy=kev\nsource=policy_input\n"},
		{name: "repo config beats input", config: "version: 2\nscan:\n  window: 30d\n", policy: "published-24h", want: "window=30d\npolicy=published-30d\nsource=repo_config\n"},
		{name: "repo config, no input", config: "version: 2\nscan:\n  window: full\n", want: "window=full\npolicy=full\nsource=repo_config\n"},
		{name: "config without a window", config: "version: 1\nanalyze:\n  ref: main\n", policy: "published-7d", want: "window=7d\npolicy=published-7d\nsource=policy_input\n"},
		{name: "invalid window fails closed", config: "version: 2\nscan:\n  window: 90d\n", policy: "published-7d", wantErr: "not a scan window"},
		{name: "window on v1 fails closed", config: "version: 1\nscan:\n  window: 7d\n", wantErr: "needs version: 2"},
		{name: "malformed input fails closed", policy: "../full", wantErr: "not a policy id"},
		{name: "input with a newline fails closed", policy: "full\nsource=repo_config", wantErr: "not a policy id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeRepoConfig(t, tc.config)
			var out, log bytes.Buffer
			err := runScanWindow([]string{"-target", root, "-advisory-corpus-policy", tc.policy}, &out, &log)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				if out.Len() != 0 {
					t.Fatalf("a failed resolution must print no outputs, got %q", out.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("runScanWindow: %v", err)
			}
			if out.String() != tc.want {
				t.Fatalf("outputs = %q, want %q", out.String(), tc.want)
			}
			if !strings.Contains(log.String(), "scan window: ") {
				t.Fatalf("the run log must name the window, got %q", log.String())
			}
		})
	}
}

func TestScanTimeWindow(t *testing.T) {
	sw := func(window, policy, via string) *report.ScanWindow {
		return &report.ScanWindow{Window: window, Policy: policy, ResolvedVia: via, Source: report.ScanWindowSource{Kind: via}}
	}
	for _, tc := range []struct {
		name    string
		repo    repoconfig.Window
		policy  string
		hint    string
		api     string
		want    *report.ScanWindow
		wantErr string
	}{
		{name: "nothing declared", want: nil},
		{name: "declared policy, no hint", policy: "published-7d", want: sw("7d", "published-7d", "policy_input")},
		{name: "declared policy, input hint", policy: "full", hint: "policy_input", want: sw("full", "full", "policy_input")},
		{name: "repo window matches", repo: repoconfig.Window30d, policy: "published-30d", hint: "policy_input", want: sw("30d", "published-30d", "repo_config")},
		{name: "repo window, other policy", repo: repoconfig.Window30d, policy: "published-24h", wantErr: "selected by policy published-24h"},
		{name: "repo window, no policy", repo: repoconfig.Window7d, wantErr: "declares no advisory corpus policy"},
		{name: "none hint with nothing declared", hint: "none", want: nil},
		{name: "none hint, but a policy declared", policy: "published-7d", hint: "none", wantErr: "does not name a source"},
		{name: "repo hint is never trusted", policy: "published-7d", hint: "repo_config", wantErr: "does not name a source"},
		{name: "unknown hint", policy: "published-7d", hint: "console", wantErr: "does not name a source"},
		{name: "api hint, ancestor", policy: "published-30d", hint: "api", api: `{"kind":"ancestor","customer_id":"cus_2f9","distance":2}`,
			want: &report.ScanWindow{Window: "30d", Policy: "published-30d", ResolvedVia: "api", Source: report.ScanWindowSource{Kind: "ancestor", CustomerID: "cus_2f9", Distance: intPtr(2)}}},
		{name: "api hint, default", policy: "published-24h", hint: "api", api: `{"kind":"default"}`,
			want: &report.ScanWindow{Window: "24h", Policy: "published-24h", ResolvedVia: "api", Source: report.ScanWindowSource{Kind: "default"}}},
		{name: "repo window beats an api hint", repo: repoconfig.Window7d, policy: "published-7d", hint: "api", api: `{"kind":"default"}`, want: sw("7d", "published-7d", "repo_config")},
		{name: "api hint without a record", policy: "published-7d", hint: "api", wantErr: "not a source record"},
		{name: "api hint, tampered record", policy: "published-7d", hint: "api", api: `{"kind":"customer","customer_id":"x y","distance":0}`, wantErr: "customer_id"},
		{name: "api hint, extra field", policy: "published-7d", hint: "api", api: `{"kind":"default","name":"Acme"}`, wantErr: "not a source record"},
		{name: "api hint, non-window policy", policy: "kev", hint: "api", api: `{"kind":"default"}`, wantErr: "not a scan window policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanTimeWindow(tc.repo, tc.policy, tc.hint, tc.api)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v (%+v)", tc.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("scanTimeWindow: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A source inserted between two others is consulted in its place, and an error stops resolution.
func TestResolveScanWindow_Order(t *testing.T) {
	inserted := func() (report.ScanWindow, bool, error) {
		return newScanWindow("published-7d", "inserted"), true, nil
	}
	got, ok, err := resolveScanWindow(repoConfigWindow(""), inserted, policyInputWindow("full"))
	if err != nil || !ok || got.ResolvedVia != "inserted" || got.Policy != "published-7d" {
		t.Fatalf("got %+v, %v, %v", got, ok, err)
	}
	got, ok, err = resolveScanWindow(repoConfigWindow(repoconfig.WindowFull), inserted)
	if err != nil || !ok || got.ResolvedVia != report.ScanWindowViaRepoConfig {
		t.Fatalf("the repository config must win, got %+v, %v, %v", got, ok, err)
	}
	if _, ok, err = resolveScanWindow(repoConfigWindow(""), policyInputWindow("")); ok || err != nil {
		t.Fatalf("with no source set, nothing is selected; got ok=%v err=%v", ok, err)
	}
}

// The resolved window reaches the Report's intel block, and a repository window the declared
// policy does not match fails the run before any corpus is read.
func TestAdvisoryCorpusOption_RecordsScanWindow(t *testing.T) {
	bundle := writePolicyBundle(t, []corpusEntry{{doc: goRecord("TEST-MATCH-CRYPTO", "golang.org/x/crypto")}})

	for _, tc := range []struct {
		name    string
		repo    repoconfig.Window
		policy  string
		source  string
		want    *report.ScanWindow
		wantErr string
	}{
		{name: "no policy, no window", want: nil},
		{name: "action reports none", source: "none", want: nil},
		{name: "policy input", policy: "published-24h", source: "policy_input",
			want: &report.ScanWindow{Window: "24h", Policy: "published-24h", ResolvedVia: "policy_input", Source: report.ScanWindowSource{Kind: "policy_input"}}},
		{name: "repo window", repo: repoconfig.Window7d, policy: "published-7d", source: "policy_input",
			want: &report.ScanWindow{Window: "7d", Policy: "published-7d", ResolvedVia: "repo_config", Source: report.ScanWindowSource{Kind: "repo_config"}}},
		{name: "repo window, mismatched corpus", repo: repoconfig.Window7d, policy: "full", wantErr: "did not choose"},
		{name: "repo window, corpus without a policy", repo: repoconfig.WindowFull, wantErr: "declares no advisory corpus policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, tc.policy)
			t.Setenv(envScanWindowSource, tc.source)
			f := runFlagsFor(t, "-advisory-corpus", bundle)
			f.repoWindow = tc.repo

			_, err := f.advisoryCorpusOption()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			got := f.intelProvenance(floorWorkSet(nil)).ScanWindow
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Report scan_window = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The Action resolves the window before any corpus step, and every corpus and scan input reads the
// resolved policy rather than the raw advisory-corpus-policy input.
func TestActionConsumesResolvedScanWindow(t *testing.T) {
	data, err := os.ReadFile(actionYMLPath)
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				ID   string            `yaml:"id"`
				If   string            `yaml:"if"`
				Name string            `yaml:"name"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	const policy, source = "${{ steps.scan-window.outputs.policy }}", "${{ steps.scan-window.outputs.source }}"
	pos := map[string]int{}
	for i, st := range action.Runs.Steps {
		key := st.ID
		if key == "" {
			key = st.Name
		}
		pos[key] = i
		for k, v := range st.Env {
			if st.ID != "scan-window" && strings.Contains(v, "inputs.advisory-corpus-policy") {
				t.Errorf("step %q env %s reads the raw advisory-corpus-policy input: %s", key, k, v)
			}
		}
	}
	window, ok := pos["scan-window"]
	if !ok {
		t.Fatal("action.yml has no scan-window step")
	}
	for _, tc := range []struct{ step, env, want string }{
		{"corpus-bundle", "CORPUS_POLICY", policy},
		{"Fetch the advisory corpus (unauthenticated, shallow + sparse)", "CORPUS_POLICY", policy},
		{"run", "IN_ADVISORY_CORPUS_POLICY", policy},
		{"run", "ASSAY_ADVISORY_CORPUS_POLICY", policy},
		{"run", "ASSAY_SCAN_WINDOW_SOURCE", source},
		{"run", "ASSAY_SCAN_WINDOW_API_SOURCE", "${{ steps.scan-window.outputs.api-source }}"},
		{"scan-window", "FERRALON_LINK_TO_CONSOLE", "${{ inputs.link-to-console }}"},
		{"scan-window", "FERRALON_RUNS_URL", "${{ inputs.runs-url }}"},
	} {
		i, ok := pos[tc.step]
		if !ok {
			t.Errorf("action.yml has no step %q", tc.step)
			continue
		}
		if i < window {
			t.Errorf("step %q runs before the scan window is resolved", tc.step)
		}
		if got := action.Runs.Steps[i].Env[tc.env]; got != tc.want {
			t.Errorf("step %q env %s = %q, want %q", tc.step, tc.env, got, tc.want)
		}
	}
	if bundle := action.Runs.Steps[pos["corpus-bundle"]].If; !strings.Contains(bundle, "steps.scan-window.outputs.policy") {
		t.Errorf("the bundle step must be gated on the resolved policy, got if: %s", bundle)
	}
}

func intPtr(i int) *int { return &i }
