// workset_offline_default_test.go
//
// B-3: the workflow this tool ships into a customer's repository enumerates the endpoints a run
// contacts and says "and nothing else". Nothing in the repo previously connected that sentence to
// the binary's behaviour — the consistency test that exists checks the PR body against the
// workflow, not either against what the scanner does.
//
// These tests are that missing link, and they assert it at the TRANSPORT, not at the flag. A test
// that only reads osvWorkSetEnabled() would keep passing if someone wired a second OSV caller into
// the scan path; this one fails, because it counts outbound HTTP requests.
package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// egressTrap is an http.RoundTripper that records every request and refuses to make any. Installed
// as http.DefaultTransport it intercepts trigger.HTTPOSVClient, whose zero value builds an
// http.Client with a nil Transport and therefore dials through the default.
type egressTrap struct {
	hosts []string
}

func (e *egressTrap) RoundTrip(req *http.Request) (*http.Response, error) {
	e.hosts = append(e.hosts, req.URL.Host)
	return nil, fmt.Errorf("egressTrap: refusing outbound request to %s", req.URL)
}

// trapEgress installs an egressTrap for the duration of the test and returns it.
func trapEgress(t *testing.T) *egressTrap {
	t.Helper()
	trap := &egressTrap{}
	prev := http.DefaultTransport
	http.DefaultTransport = trap
	t.Cleanup(func() { http.DefaultTransport = prev })
	return trap
}

// TestShippedDefaults_ScanPathContactsNobody is the acceptance test for the customer-facing OUTBOUND
// claim. runFlagsFor(t) with NO arguments is exactly the flag state an Action invocation produces:
// the scaffolded workflow never sets `mode`, so it runs baseline, and it passes no OSV flag because
// action.yml exposes no input that maps to one.
//
// If this test fails, the workflow committed into every customer repository is making a claim the
// binary does not honour. Fix the binary or get the copy re-ruled; do not relax the test.
func TestShippedDefaults_ScanPathContactsNobody(t *testing.T) {
	if osvWorkSetDefault {
		t.Fatal("osvWorkSetDefault is true: the shipped scanner now contacts a third party, and the " +
			"scaffolded workflow's OUTBOUND paragraph plus the bootstrap PR body must be rewritten " +
			"to name api.osv.dev before this may land")
	}

	trap := trapEgress(t)
	f := runFlagsFor(t)
	acq := goFixture(t, fixtureGoMod)

	ws, err := f.scanWorkSet(context.Background(), acq)
	if err != nil {
		t.Fatalf("scanWorkSet err = %v", err)
	}
	if len(trap.hosts) != 0 {
		t.Fatalf("a shipped-default scan contacted %v; the workflow it ships with says the run "+
			"contacts the two endpoints in its `with:` block and nothing else", trap.hosts)
	}
	if ws.source != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q", ws.source, report.WorkSetBuiltinLanguageSet)
	}
	if len(ws.partiality) != 0 {
		t.Errorf("the DEFAULT configuration disclosed partiality %+v; not asking to widen is not a "+
			"gap between what was asked for and what happened", ws.partiality)
	}
}

// TestOSVWorkSet_OptInStillReachesOSV is the anti-vacuity twin of the test above, and it is the more
// important of the two. Without it, deleting the OSV call entirely would turn the offline test
// green — so it would stop proving anything about the default and start proving nothing at all.
//
// It also pins the second acceptance property: the capability is dormant, not removed. One flag
// reaches the same endpoint.
func TestOSVWorkSet_OptInStillReachesOSV(t *testing.T) {
	trap := trapEgress(t)
	f := runFlagsFor(t, "-osv-work-set=true")
	acq := goFixture(t, fixtureGoMod)

	ws, err := f.scanWorkSet(context.Background(), acq)
	if err != nil {
		t.Fatalf("scanWorkSet err = %v", err)
	}
	if len(trap.hosts) == 0 {
		t.Fatal("-osv-work-set=true made no outbound request: either the widening was removed, or " +
			"this trap no longer intercepts it and the offline test above is now vacuous")
	}
	for _, h := range trap.hosts {
		if h != "api.osv.dev" {
			t.Errorf("the widening contacted %q; the only counterparty this capability may have is "+
				"api.osv.dev, and adding another re-opens the whole disclosure question", h)
		}
	}
	// The trap refuses the request, so this is also the OSV-unreachable path: it must degrade to
	// the floor WITH disclosure, never fail the run and never render as a complete scan.
	if !hasNote(ws.partiality, reasonWorkSetNotWidened) {
		t.Errorf("an unreachable OSV produced no %q note; notes = %+v", reasonWorkSetNotWidened, ws.partiality)
	}
	if len(ws.advisories) != len(acq.advisories) {
		t.Errorf("work set = %d, want the floor's %d", len(ws.advisories), len(acq.advisories))
	}
}

// TestOSVWorkSet_EnvOptInReachesOSV proves the env channel is a real second switch after the
// default flip. Before it, TEGRON_OSV_WORK_SET could only ever turn the widening OFF, so nothing
// covered it as a way to turn it on — which is now its primary use.
func TestOSVWorkSet_EnvOptInReachesOSV(t *testing.T) {
	t.Setenv(envOSVWorkSet, "1")
	trap := trapEgress(t)
	f := runFlagsFor(t)
	acq := goFixture(t, fixtureGoMod)

	if _, err := f.scanWorkSet(context.Background(), acq); err != nil {
		t.Fatalf("scanWorkSet err = %v", err)
	}
	if len(trap.hosts) == 0 {
		t.Fatalf("%s=1 did not enable the widening — the flag's own default beat the env var", envOSVWorkSet)
	}
}
