package trigger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// failingReachabilityPlugin is the wiring plugin with a reachability pass that errors, so every
// assessment of GO-2021-0113 fails. The error carries a newline and URL credentials, which the
// row must not.
type failingReachabilityPlugin struct{ refutingGoPlugin }

func (failingReachabilityPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{}, errors.New("fetch https://user:s3cret@proxy.example/x failed\nexit status 1")
}

func failingOptions(t *testing.T) []pipeline.AssessOption {
	t.Helper()
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(failingReachabilityPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
	}
}

// migratedBaseline holds the row report.Upgrade makes from a v1 document: undetermined, and with
// no source, so it cannot match a fresh row on the (id, source) key.
func migratedBaseline() *memStore {
	store := emptyBaseline()
	store.state.Report.Advisories = append(store.state.Report.Advisories, report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: wiringAdvisory.ID},
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonUnspecifiedLimit,
	})
	return store
}

// emptyBaseline is a stored baseline that holds the wiring package and no row for any advisory.
func emptyBaseline() *memStore {
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: wiringAdvisory.ID}).
		Build()
	return &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: wiringAdvisory.ID}}
}

func runFailingPR(t *testing.T, store *memStore, head []report.Package) *report.Report {
	t.Helper()
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: head},
		Advisories:    []assessment.VulnRef{wiringAdvisory},
		AssessOptions: failingOptions(t),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	return res.Report
}

func runFailingCVEWatch(t *testing.T, store *memStore) *report.Report {
	t.Helper()
	store.state.Cursor = ""
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
	res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: failingOptions(t),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("CVE-watch ran no earnest pass")
	}
	return res.Report
}

// TestAssessFailure_EveryRunMode: an advisory whose assessment fails gets exactly one row in every
// run mode, and that row is undetermined / analysis_did_not_run, replacing any verdict the baseline
// held for it.
func TestAssessFailure_EveryRunMode(t *testing.T) {
	changedHead := []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}
	cases := []struct {
		name string
		run  func(t *testing.T) *report.Report
	}{
		{"baseline", func(t *testing.T) *report.Report {
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: failingOptions(t),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			return rep
		}},
		{"PR re-analysis, package changed, replaces the baseline's not_exploitable", func(t *testing.T) *report.Report {
			store, _ := groundedBaseline()
			return runFailingPR(t, store, changedHead)
		}},
		{"PR re-analysis, no baseline row", func(t *testing.T) *report.Report {
			return runFailingPR(t, emptyBaseline(), changedHead)
		}},
		{"PR re-analysis, replaces a migrated v1 row", func(t *testing.T) *report.Report {
			return runFailingPR(t, migratedBaseline(), changedHead)
		}},
		{"PR re-analysis, package unchanged, replaces the baseline's not_exploitable", func(t *testing.T) *report.Report {
			store, baseline := groundedBaseline()
			head := append([]report.Package{{Ecosystem: "Go", Name: "example.org/other", Version: "v1.0.0"}}, baseline.SBOM.Packages...)
			return runFailingPR(t, store, head)
		}},
		// The advisory affects golang.org/x/net and golang.org/x/text; the baseline grounded it on
		// x/text, and the PR adds x/net, which a successful re-run could select instead.
		{"PR re-analysis, the PR adds another affected package, replaces the baseline's not_exploitable", func(t *testing.T) *report.Report {
			store, baseline := groundedBaseline()
			head := append([]report.Package{{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}}, baseline.SBOM.Packages...)
			return runFailingPR(t, store, head)
		}},
		{"CVE-watch, replaces the prior reachable_candidate", func(t *testing.T) *report.Report {
			store, _ := seedBaseline(t)
			return runFailingCVEWatch(t, store)
		}},
		{"CVE-watch, no prior row", func(t *testing.T) *report.Report {
			return runFailingCVEWatch(t, emptyBaseline())
		}},
		{"CVE-watch, replaces a migrated v1 row", func(t *testing.T) *report.Report {
			return runFailingCVEWatch(t, migratedBaseline())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := tc.run(t)
			var rows []report.AdvisoryFinding
			for _, f := range rep.Advisories {
				if f.Advisory.ID == wiringAdvisory.ID {
					rows = append(rows, f)
				}
			}
			if len(rows) != 1 {
				t.Fatalf("%d rows for %s, want exactly one: %+v", len(rows), wiringAdvisory.ID, rows)
			}
			f := rows[0]
			if f.Verdict != report.VerdictUndetermined {
				t.Fatalf("verdict = %q, want %q", f.Verdict, report.VerdictUndetermined)
			}
			if f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
				t.Errorf("undetermined_reason = %q, want %q", f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
			}
			if f.Package != nil {
				t.Errorf("Package = %+v, want none: the failed assessment resolved no package", f.Package)
			}
			if f.Evidence.Detail != "the reachability_ingress step failed (fetch https://REDACTED@proxy.example/x failed exit status 1), so no verdict was established" {
				t.Errorf("Evidence.Detail = %q, want the failed step and the sanitized error", f.Evidence.Detail)
			}
			var noted bool
			for _, n := range rep.Partiality {
				noted = noted || (n.Reason == plugin.PartialReasonToolFailure && strings.Contains(n.Detail, wiringAdvisory.ID))
			}
			if !noted {
				t.Errorf("Partiality = %+v, want the tool_failure note naming %s", rep.Partiality, wiringAdvisory.ID)
			}
		})
	}
}

func TestAssessErrorText(t *testing.T) {
	long := strings.Repeat("é", assessErrorLimit+10)
	cases := []struct {
		name string
		err  string
		want string
	}{
		{"plain", "boom", "boom"},
		{"control characters fold to one line", "a\r\nb\tc\x00d", "a b c d"},
		{"URL credentials are redacted", "GET https://x-access-token:ghs_abc@github.com/o/r: 403", "GET https://REDACTED@github.com/o/r: 403"},
		{"a URL without credentials is kept", "GET https://github.com/o/r@v1: 404", "GET https://github.com/o/r@v1: 404"},
		{"a password holding '@' is redacted whole", "fetch https://user:p@ss@host/x failed", "fetch https://REDACTED@host/x failed"},
		{"a URL token without a password is redacted", "clone https://ghp_abc@github.com/o/r failed", "clone https://REDACTED@github.com/o/r failed"},
		{"scheme-relative URL credentials are redacted", "fetch //u:pw@h/x failed", "fetch //REDACTED@h/x failed"},
		{"a scheme-relative URL token is redacted", "fetch //ghp_abc@h/x failed", "fetch //REDACTED@h/x failed"},
		{"scheme-less proxy credentials are redacted", "proxyconnect tcp: dial u:p@w@proxy:3128: refused", "proxyconnect tcp: dial REDACTED@proxy:3128: refused"},
		{"query-string values are redacted", "GET https://h/x?access_token=abc&ref=main 401", "GET https://h/x?access_token=REDACTED&ref=REDACTED 401"},
		{"an Authorization header is redacted", "sent Authorization: Bearer abc.def, got 401", "sent Authorization: REDACTED, got 401"},
		{"a bearer token is redacted", "token Bearer abc.def rejected", "token Bearer REDACTED rejected"},
		{"a module version is kept", "go: golang.org/x/text@v0.3.6: missing go.sum entry", "go: golang.org/x/text@v0.3.6: missing go.sum entry"},
		{"an ssh user without a password is kept", "git@github.com: Permission denied", "git@github.com: Permission denied"},
		{"bounded in runes", long, strings.Repeat("é", assessErrorLimit-1) + "…"},
		{"at the bound is kept", long[:2*assessErrorLimit], long[:2*assessErrorLimit]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assessErrorText(errors.New(tc.err)); got != tc.want {
				t.Errorf("assessErrorText(%q) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestAssessErrorText_BareTokenForms covers the credential forms that carry no URL, query string
// or Authorization header (tracker #312): each form is redacted with the text around it kept, and
// a near miss for each is left alone. Token bodies are runs of zeros of the real length.
func TestAssessErrorText_BareTokenForms(t *testing.T) {
	zeros := func(n int) string { return strings.Repeat("0", n) }
	cases := []struct {
		name string
		err  string
		want string
	}{
		{"a bare ghp_ token is redacted", "push rejected: ghp_" + zeros(36) + " is revoked", "push rejected: ghp_REDACTED is revoked"},
		{"a bare gho_ token is redacted", "oauth gho_" + zeros(36) + ": expired", "oauth gho_REDACTED: expired"},
		{"a bare ghs_ token is redacted", "install token ghs_" + zeros(36) + " lacks scope", "install token ghs_REDACTED lacks scope"},
		{"a bare ghu_ token is redacted", "user ghu_" + zeros(36) + " denied", "user ghu_REDACTED denied"},
		{"a bare ghr_ token is redacted", "refresh ghr_" + zeros(76) + " invalid", "refresh ghr_REDACTED invalid"},
		{"a ghp_ prefix without a body is kept", "a ghp_ token was expected", "a ghp_ token was expected"},
		{"a short ghp_ string is kept", "unknown flag ghp_0000", "unknown flag ghp_0000"},
		{"a GHSA id is kept", "GHSA-jfh8-c2jp-5v3q withdrawn", "GHSA-jfh8-c2jp-5v3q withdrawn"},

		{"a bare github_pat_ token is redacted", "clone with github_pat_" + zeros(22) + "_" + zeros(59) + " failed", "clone with github_pat_REDACTED failed"},
		{"a github_pat_ prefix without a body is kept", "github_pat_ tokens are fine-grained", "github_pat_ tokens are fine-grained"},

		{"a bare glpat- token is redacted", "gitlab: glpat-" + zeros(20) + " revoked", "gitlab: glpat-REDACTED revoked"},
		{"a routable glpat- token is redacted whole", "gitlab: glpat-" + zeros(27) + ".01." + zeros(9) + " revoked", "gitlab: glpat-REDACTED revoked"},
		{"a short glpat- string is kept", "glpat-short is not a token", "glpat-short is not a token"},

		{"a bare npm_ token is redacted", "npm ERR! npm_" + zeros(36) + " is invalid", "npm ERR! npm_REDACTED is invalid"},
		{"npm_modules is kept", "cannot read npm_modules/x/package.json", "cannot read npm_modules/x/package.json"},
		{"an npm_ config variable is kept", "npm_config_cache=/tmp/npm npm_package_version=1.2.3", "npm_config_cache=/tmp/npm npm_package_version=1.2.3"},

		{"token= outside a query string is redacted", "auth failed: token=abc123; retry", "auth failed: token=REDACTED; retry"},
		{"a NAME_TOKEN= setting is redacted", "env GITHUB_TOKEN=abc123 go mod download: 401", "env GITHUB_TOKEN=REDACTED go mod download: 401"},
		{"tokenizer= is kept", "tokenizer=bpe max_tokens=5 rejected", "tokenizer=bpe max_tokens=5 rejected"},
		{"an unexpected token = is kept", "syntax error: unexpected token = in expression", "syntax error: unexpected token = in expression"},
		{"a token.go path is kept", "open /src/tokenizer/token.go: no such file", "open /src/tokenizer/token.go: no such file"},

		{"a .netrc password is redacted", "bad .netrc: machine github.com login u password hunter2 extra", "bad .netrc: machine github.com login u password REDACTED extra"},
		{"a multi-line .netrc password is redacted", "machine h\n\tlogin u\n\tpassword p4ss\n", "machine h login u password REDACTED"},
		{"a .netrc default entry's password is redacted", "default login anonymous password p4ss", "default login anonymous password REDACTED"},
		{"password-reset is kept", "password-reset endpoint returned 404", "password-reset endpoint returned 404"},
		{"a password authentication error is kept", "pq: password authentication failed for user u", "pq: password authentication failed for user u"},
		{"a login failure naming the password is kept", "login failed: password incorrect", "login failed: password incorrect"},
		{"a default password phrase is kept", "default password policy rejected it", "default password policy rejected it"},
		{"a .netrc machine without a password is kept", "machine github.com not found in .netrc", "machine github.com not found in .netrc"},

		{"an npm _authToken= is redacted", "npm ERR! //registry.npmjs.org/:_authToken=abc123 invalid", "npm ERR! //registry.npmjs.org/:_authToken=REDACTED invalid"},
		{"an npm _authToken = with spaces is redacted", ".npmrc: _authToken = abc123", ".npmrc: _authToken=REDACTED"},
		{"an _authToken mention without a value is kept", "the _authToken option is missing", "the _authToken option is missing"},

		{"a PRIVATE-TOKEN header is redacted", "> PRIVATE-TOKEN: abc123\n< HTTP/1.1 401", "> PRIVATE-TOKEN: REDACTED < HTTP/1.1 401"},
		{"a private-token= setting is redacted", "private-token=abc123 rejected", "private-token: REDACTED rejected"},
		{"a PRIVATE-TOKEN mention without a value is kept", "PRIVATE-TOKEN header missing", "PRIVATE-TOKEN header missing"},

		{"a CVE id is kept", "CVE-2024-24790 affects net/netip", "CVE-2024-24790 affects net/netip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assessErrorText(errors.New(tc.err)); got != tc.want {
				t.Errorf("assessErrorText(%q) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
