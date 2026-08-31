// workset_empty_gate_test.go
//
// The halt-on-empty gate, and above all its ORDERING against the OSV work-set widening.
//
// The gate used to sit in acquireTarget, where it measured the compiled-in language floor. That is
// not the set a pass evaluates: -osv-work-set widens the set afterwards, in resolveWorkSet, taking
// the acquired target as INPUT. Java/JS/Python floors were house canaries in their entirety at the
// time, so with the canary gate on they resolved to zero and every such scan that asked for the
// widening died at acquisition — before OSV was ever queried — telling the user to add advisories to
// the corpus or pass -include-house-canaries, neither of which is what they had asked for.
//
// Those floors now carry real advisories (acquire.go), so the empty floor these tests turn on is
// constructed rather than borrowed from an ecosystem — see emptyFloorFor.
//
// TestEmptyWorkSet_WideningRunsBeforeTheGate and TestEmptyWorkSet_WideningPopulatesAnEmptyFloor are
// the regression pair for that ordering: both are unreachable under the old placement, because the
// run never got as far as the work set.
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
	acq, err := acquireTarget(context.Background(), dir, "", "", "/fake/bin", canaries)
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
//
// THERE IS NO LONGER A LANGUAGE WHOSE FLOOR IS NATURALLY EMPTY, and that is the point of the change
// that made this helper necessary. These tests used to use .NET as their empty-in-both-directions
// specimen; .NET now carries three real NuGet advisories by default, as do Java, JS and Python, so
// every supported language resolves a non-empty work set. That property is what makes a default
// scan of those repositories complete, and language_support_test.go holds it in place.
//
// LangUnknown is not an alternative: an unrecognized tree does not reach scanWorkSet at all. It
// fails two stages earlier, in checkout.ResolveVendored ("is not a recognized source tree"), before
// selectPlugin is ever consulted — verified by running it, 2026-08-05.
//
// So the empty set is constructed rather than found. That is a FAITHFUL model of the state the gate
// exists for, not a weaker one: the gate's condition is strictly "the resolved set is empty", never
// a language and never a flag, and a floor that resolved to nothing is exactly what it must catch.
// It is also the same manoeuvre the widening tests below already use on acq.plugin, and it is
// durable — an empty specimen sourced from a real ecosystem is a fixture that breaks every time
// coverage improves, which is precisely how these tests broke.
func emptyFloorFor(t *testing.T, language string, canaries bool) *acquired {
	t.Helper()
	acq := treeFor(t, language, canaries)
	if len(acq.advisories) == 0 {
		t.Fatalf("%s floor (canaries=%v) is already empty — the default floor for every supported "+
			"language must be non-empty, or a default scan of it cannot complete", language, canaries)
	}
	acq.advisories = nil
	return acq
}

// TestEmptyWorkSet_HaltsTheRun is the firing half: a work set that resolves to nothing must fail the
// run loudly rather than publish a findings-free Report that reads as an assessed all-clear.
//
// Every supported language is covered in BOTH flag directions, which is what proves the condition is
// the resolved set and not the flag: -include-house-canaries is set on half these cases and exempts
// none of them. The canaries-on rows carry the property the old .NET specimen carried alone.
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

			_, err := f.scanWorkSet(context.Background(), acq)
			if err == nil {
				t.Fatal("an empty resolved work set did not halt the run")
			}
			for _, want := range []string{tc.language, "0 advisories"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// TestEmptyWorkSet_MessageDoesNotBranch pins the ruling that the error stays ONE flat string: it
// states the fact and names the inputs that populate a work set, and it does not grow a remedy
// decision tree keyed on which input was supplied. The compiled-in advisory table is scaffolding on
// its way out in favour of a policy manifest; when that lands the honest sentence is a different
// one, and replacing it should cost one string rewrite rather than an unpicking job.
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
	cases := []struct {
		name     string
		language string
		canaries bool
	}{
		// EVERY supported language's default floor carries real advisories, so the gate must never
		// fire on any of them in either flag direction. This is the halt-side mirror of
		// language_support_test.go: the same property, asserted through the gate rather than
		// through the corpus.
		{"go, canaries off", checkout.LangGo, false},
		{"go, canaries on", checkout.LangGo, true},
		{"java, canaries off", checkout.LangJava, false},
		{"java, canaries on", checkout.LangJava, true},
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
			acq := treeFor(t, tc.language, tc.canaries)

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

// TestEmptyWorkSet_WideningRunsBeforeTheGate is the regression test for the defect.
//
// A Java run with -osv-work-set set and the house canaries off has an EMPTY compiled-in floor. Under
// the old placement it died inside acquireTarget and never reached the widening at all. It must now
// acquire, query OSV, and only then be judged on what the work set resolved to.
//
// The egress trap refuses the request, so this run does still halt — the widening it asked for could
// not run, and nothing else populated the set. What the test pins is that the OSV query HAPPENED
// first: that outbound request is the observable proof the gate no longer pre-empts the widening.
func TestEmptyWorkSet_WideningRunsBeforeTheGate(t *testing.T) {
	trap := trapEgress(t)
	f := runFlagsFor(t, "-osv-work-set=true")

	// Acquisition itself must survive an empty floor. This is the exact call that used to fail.
	// The floor is emptied explicitly because no language has a naturally empty one any more — see
	// emptyFloorFor for why that is the durable form of this fixture.
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

// TestEmptyWorkSet_WideningPopulatesAnEmptyFloor is the payoff half, and the case the user in the
// bug report was actually asking for: OSV answers, the answer resolves to facts we hold, and a Java
// scan whose compiled-in floor is empty runs on the widened set instead of halting.
//
// Unreachable under the old placement for the same reason as the test above.
func TestEmptyWorkSet_WideningPopulatesAnEmptyFloor(t *testing.T) {
	// TEGRON-JAVA-DEP-0001 is a Maven advisory the built-in table holds facts for and that the
	// canaries-off floor does NOT carry, so admitting it is a real widening rather than a floor hit.
	const admitted = "TEGRON-JAVA-DEP-0001"
	stubOSV(t, admitted)

	f := runFlagsFor(t, "-osv-work-set=true")
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
	return plugin.DependencyVersionResult{
		All: []plugin.ResolvedDependency{
			{Coordinate: "com.example.lib:widget", Version: "1.0.0", Resolved: true},
		},
	}, nil
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
