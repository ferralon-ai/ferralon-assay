// workset_empty_gate_test.go
//
// The halt-on-empty gate, and above all its ORDERING against the OSV work-set widening.
//
// The scanner carries no advisories of its own: a scan's work set is the opted-in house canaries
// plus whatever a corpus policy or the OSV widening chooses against the repository's dependencies.
// With none of those the set is empty, and the run must halt with an error naming every input that
// populates it, rather than publish a findings-free Report that reads as an assessed all-clear.
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
// stored state or querying OSV.
func TestCVEWatch_NoFactSourceHalts(t *testing.T) {
	trapEgress(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte(fixtureGoMod), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if err := gitInitBare(stateDir); err != nil {
		t.Fatal(err)
	}
	err := runCVEWatch([]string{"-target", target, "-plugin-go", "/fake/bin", "-build-graph", "off", "-git-dir", stateDir})
	if err == nil {
		t.Fatal("cve-watch with no advisory corpus did not halt")
	}
	for _, want := range []string{"-advisory-corpus", envAdvisoryCorpusDir, "advisory-corpus-repo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
}

// TestEmptyWorkSet_HaltsTheRun is the firing half: a work set that resolves to nothing must fail the
// run loudly, naming every input that would populate it, rather than publish a findings-free Report
// that reads as an assessed all-clear. Nothing falls back to fixture advisories.
//
// Every supported language is covered in BOTH flag directions, which is what proves the condition is
// the resolved set and not the flag: -include-house-canaries is set on half these cases and exempts
// none of them.
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
			for _, want := range append([]string{tc.language, "0 advisories"}, emptyWorkSetInputs...) {
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
// The egress trap refuses the request, so this run does still halt — the widening it asked for could
// not run, and nothing else populated the set. What the test pins is that the OSV query HAPPENED
// first: that outbound request is the observable proof the gate no longer pre-empts the widening.
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
	// The widening was refused by the trap, so the set is still empty and the gate is right to fire.
	if err == nil {
		t.Fatal("the work set resolved empty after an unreachable OSV and the run did not halt")
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
