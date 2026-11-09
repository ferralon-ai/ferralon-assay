// workset_empty_gate_test.go
//
// The no-work gate, and above all its ORDERING against the OSV work-set widening.
//
// The scanner carries no advisories of its own: a scan's work set is the opted-in house canaries
// plus whatever a corpus policy or the OSV widening chooses against the repository's dependencies.
// A run given none of those inputs must halt with an error naming every one of them, rather than
// publish a findings-free Report that reads as an assessed all-clear. A run that WAS given one, and
// whose input chose nothing for this repository, has an assessed answer and publishes it.
//
// The gate sits after the widening (scanWorkSet), never at acquisition: -osv-work-set widens the set
// in resolveWorkSet, taking the acquired target as INPUT. TestEmptyWorkSet_WideningRunsBeforeTheGate
// and TestEmptyWorkSet_WideningPopulatesAnEmptyFloor pin that ordering.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// treeFor writes a one-file source tree of the given language and acquires it, so these tests run
// the real acquisition path rather than a hand-built *acquired. The plugin binary path is a fake:
// selectPlugin only records it, and nothing here executes an analyzer.
func treeFor(t *testing.T, language string, canaries bool) *acquired {
	t.Helper()
	file, content := languageFixture(t, language)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	acq, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", canaries, graphRequest{mode: buildGraphOff})
	if err != nil {
		t.Fatalf("acquireTarget(%s, canaries=%v): %v", language, canaries, err)
	}
	t.Cleanup(acq.cleanup)
	if acq.language != language {
		t.Fatalf("detected language = %q, want %q", acq.language, language)
	}
	return acq
}

func languageFixture(t *testing.T, language string) (file, content string) {
	t.Helper()
	switch language {
	case checkout.LangGo:
		return "go.mod", fixtureGoMod
	case checkout.LangJava:
		return "App.java", "class App {}\n"
	case checkout.LangKotlin:
		return "App.kt", "class App\n"
	case checkout.LangJS:
		return "app.js", "module.exports = {}\n"
	case checkout.LangPython:
		return "app.py", "x = 1\n"
	case checkout.LangDotNet:
		return "App.cs", "class App {}\n"
	case checkout.LangCFamily:
		return "main.c", "int main(void) { return 0; }\n"
	}
	t.Fatalf("no fixture for language %q", language)
	return "", ""
}

// emptyFloorFor acquires a real tree of the given language and then empties its advisory floor.
// With the canaries off the floor is already empty; with them on, emptying it models a run whose
// opted-in canaries name nothing in this ecosystem, so the gate is shown to key on the resolved set
// and never on the flag.
func emptyFloorFor(t *testing.T, language string, canaries bool) *acquired {
	t.Helper()
	acq := treeFor(t, language, canaries)
	acq.advisories = nil
	return acq
}

// emptyWorkSetInputs is every input the halt message must name: the corpus flag and its Action
// inputs, the OSV widening, and the house-canary opt-in.
var emptyWorkSetInputs = []string{
	"-advisory-corpus", "-advisory-corpus-policy", envAdvisoryCorpusDir,
	"advisory-corpus-repo", "advisory-corpus-policy",
	"-osv-work-set", "-include-house-canaries",
}

// TestEmptyWorkSet_DefaultScanHalts runs the gate through acquisition: a scan with no corpus, no
// OSV widening and no canaries resolves nothing in any supported language, and halts.
func TestEmptyWorkSet_DefaultScanHalts(t *testing.T) {
	for _, language := range []string{checkout.LangGo, checkout.LangJava, checkout.LangKotlin, checkout.LangJS, checkout.LangPython, checkout.LangDotNet} {
		t.Run(language, func(t *testing.T) {
			trapEgress(t)
			f := runFlagsFor(t)
			if _, err := f.advisoryCorpusOption(); err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			acq := treeFor(t, language, false)
			if len(acq.advisories) != 0 {
				t.Fatalf("a default %s acquisition carries advisories %v; the scanner carries none of its own", language, ids(acq.advisories))
			}
			if _, err := f.scanWorkSet(context.Background(), acq); err == nil {
				t.Fatal("a default scan with no work-set input did not halt")
			}
		})
	}
}

// TestCVEWatch_NoFactSourceHalts: a cve-watch heartbeat with no advisory corpus has nothing to
// resolve OSV-reported advisories against, so it halts naming the corpus inputs before reading the
// stored state or querying OSV. The house canaries are a fact source only for their own demo ids,
// so opting them in does not let the heartbeat assess OSV's ids with no facts.
func TestCVEWatch_NoFactSourceHalts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"no corpus", nil},
		{"house canaries, no corpus", []string{"-include-house-canaries"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trap := trapEgress(t)
			target := t.TempDir()
			if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte(fixtureGoMod), 0o600); err != nil {
				t.Fatal(err)
			}
			stateDir := t.TempDir()
			if err := gitInitBare(stateDir); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"-target", target, "-plugin-go", "/fake/bin", "-build-graph", "off", "-git-dir", stateDir}, tc.extra...)
			err := runCVEWatch(args)
			if err == nil {
				t.Fatal("cve-watch with no advisory corpus did not halt")
			}
			for _, want := range []string{"no advisory fact source", "-advisory-corpus", envAdvisoryCorpusDir, "advisory-corpus-repo"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q: %v", want, err)
				}
			}
			if len(trap.hosts) != 0 {
				t.Errorf("cve-watch queried %v before halting", trap.hosts)
			}
		})
	}
}

// TestEmptyWorkSet_SuppliedInputMatchingNothingPublishes is the other side of the gate: a run given
// a work-set input that chose nothing for this repository was given real work, and its empty set is
// an assessed answer the run publishes, not an error. A corpus with no policy chooses nothing and
// still halts.
func TestEmptyWorkSet_SuppliedInputMatchingNothingPublishes(t *testing.T) {
	wireCorpus := filepath.Join("..", "..", "pipeline", "testdata", "advisory_source")
	policyBundle := writePolicyBundle(t, []corpusEntry{{doc: goRecord("TEST-NOT-A-DEPENDENCY", "example.com/not-a-dependency")}})

	for _, tc := range []struct {
		name       string
		args       []string
		java       bool // a Java tree with a one-coordinate inventory, for the OSV widening to query
		cfamily    bool // a C-family tree, whose language has no advisory ecosystem
		osv        []string
		wantSource string
		wantHalt   string // the halt message's distinguishing text, or "" when the run publishes
		wantNote   bool
	}{
		{name: "policy matches no dependency", args: []string{"-advisory-corpus", policyBundle, "-advisory-corpus-policy", "full"},
			wantSource: report.WorkSetPolicy},
		// The reported id has no facts in the corpus, which the run discloses rather than assesses.
		{name: "OSV reports nothing the corpus holds", args: []string{"-osv-work-set=true", "-advisory-corpus", wireCorpus},
			java: true, osv: []string{"GHSA-not-in-the-corpus"}, wantSource: report.WorkSetOSVQuery, wantNote: true},
		{name: "OSV unreachable", args: []string{"-osv-work-set=true", "-advisory-corpus", wireCorpus},
			java: true, wantSource: report.WorkSetNone, wantNote: true},
		{name: "corpus without a policy", args: []string{"-advisory-corpus", wireCorpus}, wantHalt: "no work"},
		// Nothing could match a language with no advisory ecosystem, so the input is no work.
		{name: "policy on a language with no advisory ecosystem", args: []string{"-advisory-corpus", policyBundle, "-advisory-corpus-policy", "full"},
			cfamily: true, wantHalt: "no advisory ecosystem"},
		{name: "OSV on a language with no advisory ecosystem", args: []string{"-osv-work-set=true", "-advisory-corpus", wireCorpus},
			cfamily: true, wantHalt: "no advisory ecosystem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, "")
			t.Setenv(envOSVWorkSet, "")
			if tc.osv != nil {
				stubOSV(t, tc.osv...)
			} else {
				trapEgress(t)
			}
			f := runFlagsFor(t, tc.args...)
			if _, err := f.advisoryCorpusOption(); err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			var acq *acquired
			switch {
			case tc.java:
				acq = treeFor(t, checkout.LangJava, false)
				acq.plugin = mavenInventoryPlugin{}
			case tc.cfamily:
				acq = treeFor(t, checkout.LangCFamily, false)
			default:
				acq = goFixture(t, fixtureGoMod)
				acq.advisories = nil
			}

			ws, err := f.scanWorkSet(context.Background(), acq)
			if tc.wantHalt != "" {
				if err == nil || !strings.Contains(err.Error(), "no work") || !strings.Contains(err.Error(), tc.wantHalt) {
					t.Fatalf("the input chooses nothing; want the %q halt, got %v", tc.wantHalt, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a supplied work-set input that matched nothing halted the run: %v", err)
			}
			if len(ws.advisories) != 0 {
				t.Fatalf("work set = %v, want empty", ids(ws.advisories))
			}
			if ws.source != tc.wantSource {
				t.Errorf("work set source = %q, want %q", ws.source, tc.wantSource)
			}
			if got := len(ws.partiality) != 0; got != tc.wantNote {
				t.Errorf("partiality = %+v, want a degraded-selection note: %v", ws.partiality, tc.wantNote)
			}
		})
	}
}

// TestEmptyWorkSet_HaltsTheRun is the firing half: a run given no input that chooses advisories must
// fail loudly, naming every input that would populate its work set, rather than publish a
// findings-free Report that reads as an assessed all-clear. Nothing falls back to fixture advisories.
//
// Every supported language is covered in BOTH flag directions: -include-house-canaries is set on
// half these cases, and canaries that name nothing in the ecosystem exempt none of them.
func TestEmptyWorkSet_HaltsTheRun(t *testing.T) {
	cases := []struct {
		name     string
		language string
		canaries bool
	}{
		{"go, canaries off", checkout.LangGo, false},
		{"go, canaries on", checkout.LangGo, true},
		{"java, canaries off", checkout.LangJava, false},
		{"java, canaries on", checkout.LangJava, true},
		{"kotlin, canaries off", checkout.LangKotlin, false},
		{"js, canaries off", checkout.LangJS, false},
		{"js, canaries on", checkout.LangJS, true},
		{"python, canaries off", checkout.LangPython, false},
		{"python, canaries on", checkout.LangPython, true},
		{"dotnet, canaries off", checkout.LangDotNet, false},
		{"dotnet, canaries on", checkout.LangDotNet, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trapEgress(t)
			f := runFlagsFor(t)
			acq := emptyFloorFor(t, tc.language, tc.canaries)

			ws, err := f.scanWorkSet(context.Background(), acq)
			if err == nil {
				t.Fatalf("an empty resolved work set did not halt the run; it resolved %v", ids(ws.advisories))
			}
			for _, want := range append([]string{tc.language, "no work"}, emptyWorkSetInputs...) {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// TestEmptyWorkSet_MessageDoesNotBranch pins the ruling that the error stays ONE flat string: it
// states the fact and names the inputs that populate a work set, and it does not grow a remedy
// decision tree keyed on which input was supplied. Replacing it should cost one string rewrite
// rather than an unpicking job.
//
// Two runs whose ONLY difference is an input flag must therefore produce the same sentence.
func TestEmptyWorkSet_MessageDoesNotBranch(t *testing.T) {
	// One language per ecosystem, so a message that grew a per-ecosystem remedy branch fails here
	// too and not only a per-flag one.
	for _, language := range []string{checkout.LangGo, checkout.LangJava, checkout.LangJS, checkout.LangPython, checkout.LangDotNet} {
		t.Run(language, func(t *testing.T) {
			trapEgress(t)

			// The floor is emptied on both sides (see emptyFloorFor), so the two runs differ ONLY in
			// the flag the message must not read. The flag is genuinely set on the second runFlags —
			// what is pinned is that errEmptyWorkSet does not consult it.
			off := runFlagsFor(t)
			_, errOff := off.scanWorkSet(context.Background(), emptyFloorFor(t, language, false))
			on := runFlagsFor(t, "-include-house-canaries")
			_, errOn := on.scanWorkSet(context.Background(), emptyFloorFor(t, language, true))

			if errOff == nil || errOn == nil {
				t.Fatalf("expected both %s runs to halt; got %v / %v", language, errOff, errOn)
			}
			if errOff.Error() != errOn.Error() {
				t.Fatalf("the message branches on -include-house-canaries:\n off: %s\n  on: %s", errOff, errOn)
			}
		})
	}
}

// TestEmptyWorkSet_DormantOnANonEmptySet is the dormant half. Without it the firing assertions above
// would still pass if the gate were unconditional, so these are the cases that prove it is keyed on
// the SET rather than on the language: the moment anything populates an ecosystem's work set the
// halt stops firing, with no code change and nothing to remove.
func TestEmptyWorkSet_DormantOnANonEmptySet(t *testing.T) {
	// Every language with house canaries, opted in: the canaries alone populate the set.
	for _, language := range []string{checkout.LangGo, checkout.LangJava, checkout.LangKotlin, checkout.LangJS, checkout.LangPython, checkout.LangDotNet} {
		t.Run(language, func(t *testing.T) {
			trapEgress(t)
			f := runFlagsFor(t, "-include-house-canaries")
			acq := treeFor(t, language, true)

			ws, err := f.scanWorkSet(context.Background(), acq)
			if err != nil {
				t.Fatalf("gate fired on a non-empty work set: %v", err)
			}
			if len(ws.advisories) == 0 {
				t.Fatal("scanWorkSet returned an empty work set without erroring")
			}
		})
	}
}

// TestEmptyWorkSet_WideningRunsBeforeTheGate pins the gate's ordering.
//
// A Java run with -osv-work-set set and the house canaries off has an EMPTY floor. It must acquire,
// query OSV, and only then be judged on what the work set resolved to.
//
// No corpus is configured, so the widening has no facts to admit an OSV-reported id against and the
// run was given no work: it halts. What the test pins is that the OSV query HAPPENED first: that
// outbound request is the observable proof the gate does not pre-empt the widening.
func TestEmptyWorkSet_WideningRunsBeforeTheGate(t *testing.T) {
	trap := trapEgress(t)
	f := runFlagsFor(t, "-osv-work-set=true")

	// Acquisition itself must survive an empty floor.
	acq := emptyFloorFor(t, checkout.LangJava, false)
	// A dependency inventory is what the widening has to ask OSV ABOUT; the acquired Java plugin
	// points at a fake binary and can produce none, which would make the absent request ambiguous
	// between "the gate pre-empted it" and "there was nothing to query".
	acq.plugin = mavenInventoryPlugin{}

	_, err := f.scanWorkSet(context.Background(), acq)

	if len(trap.hosts) == 0 {
		t.Fatal("a java run with -osv-work-set made no outbound request: the empty-floor gate " +
			"pre-empted the widening again, which is the defect this test exists for")
	}
	for _, h := range trap.hosts {
		if h != "api.osv.dev" {
			t.Errorf("the widening contacted %q, want api.osv.dev only", h)
		}
	}
	if err == nil {
		t.Fatal("an -osv-work-set run with no corpus was given no work and did not halt")
	}
}

// TestEmptyWorkSet_WideningPopulatesAnEmptyFloor is the payoff half: OSV answers, the answer resolves
// to facts the configured corpus holds, and a Java scan whose floor is empty runs on the widened set
// instead of halting.
func TestEmptyWorkSet_WideningPopulatesAnEmptyFloor(t *testing.T) {
	// FERRALON-TEST-0001 is a record of the wire-format test corpus, so admitting it is a widening
	// against the configured fact source and nothing else.
	const admitted = "FERRALON-TEST-0001"
	stubOSV(t, admitted)

	f := runFlagsFor(t, "-osv-work-set=true", "-advisory-corpus", filepath.Join("..", "..", "pipeline", "testdata", "advisory_source"))
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption: %v", err)
	}
	acq := treeFor(t, checkout.LangJava, false)
	acq.plugin = mavenInventoryPlugin{}

	ws, err := f.scanWorkSet(context.Background(), acq)
	if err != nil {
		t.Fatalf("the widening populated the work set and the gate still fired: %v", err)
	}
	if !hasID(ws.advisories, admitted) {
		t.Fatalf("work set = %v, want the OSV-admitted %q", ids(ws.advisories), admitted)
	}
}

// mavenInventoryPlugin supplies the one dependency coordinate the widening needs to have something
// to ask OSV about. The embedded nil interface satisfies the rest of the method set at compile time;
// resolveWorkSet calls nothing else on the plugin, and a call that arrives here panics loudly rather
// than passing silently.
type mavenInventoryPlugin struct {
	plugin.LanguagePlugin
}

func (mavenInventoryPlugin) ResolveDependencyVersions(context.Context, plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	widget := plugin.ResolvedDependency{Coordinate: "com.example.lib:widget", Version: "1.0.0", Resolved: true}
	return plugin.DependencyVersionResult{Found: true, Match: widget, All: []plugin.ResolvedDependency{widget}}, nil
}

// stubOSV installs an http.DefaultTransport that answers OSV.dev's querybatch with the given
// advisory ids, one result per query so the positional response mapping stays valid. It stands in
// for the network because scanWorkSet constructs its own trigger.HTTPOSVClient; faking the transport
// leaves the production wiring — including which endpoint it dials — under test.
func stubOSV(t *testing.T, ids ...string) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = osvStubTransport{ids: ids, t: t}
	t.Cleanup(func() { http.DefaultTransport = prev })
}

type osvStubTransport struct {
	ids []string
	t   *testing.T
}

func (s osvStubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.osv.dev" {
		s.t.Errorf("the widening dialed %q, want api.osv.dev", req.URL.Host)
	}
	var in struct {
		Queries []json.RawMessage `json:"queries"`
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}

	type vuln struct {
		ID string `json:"id"`
	}
	type result struct {
		Vulns []vuln `json:"vulns"`
	}
	out := struct {
		Results []result `json:"results"`
	}{Results: make([]result, len(in.Queries))}
	for i := range out.Results {
		for _, id := range s.ids {
			out.Results[i].Vulns = append(out.Results[i].Vulns, vuln{ID: id})
		}
	}
	enc, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(enc)),
		Request:    req,
	}, nil
}
