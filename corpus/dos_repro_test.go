// internal/corpus/dos_repro_test.go
//
// Hermetic guard for the FERRALON-APP-DOS-0001 repro's OBSERVABILITY contract (GAP-2). The fault the
// fault-crash engine observes is the repro's defer/recover beacon — reached ONLY when the unbounded
// allocation faults with a RECOVERABLE panic. The live false-negative (fired=0/3) was NOT a missing
// vuln: the repro is sound, but the trigger drove a "merely large" count that the runtime fatal-OOMs
// (unrecoverable, no recover, no beacon) or simply allocates (no fault). The real fix lives in the
// pipeline's DoS framing trigger value; these source-level assertions keep the repro's recover→beacon
// wiring intact so a future edit cannot silently re-break observability. The end-to-end recover→beacon
// firing is proven by the live trial (Docker) and was confirmed manually by driving the binary.
package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoSRepro_VulnerableKeepsRecoverBeaconWiring(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "repros", "FERRALON-APP-DOS-0001-vulnerable", "main.go"))
	if err != nil {
		t.Fatalf("read DoS vulnerable repro: %v", err)
	}
	s := string(src)
	// The observable fault path: a recover block that calls the seed-exfil beacon. Without this, the
	// fault-crash engine has nothing to observe.
	for _, want := range []string{"recover()", "beaconFault()", "TEGRON_OOB_URL", "make([]byte, n)"} {
		if !strings.Contains(s, want) {
			t.Errorf("DoS vulnerable repro lost its observability wiring: missing %q", want)
		}
	}
	// The patched negative control must bound the count before the allocation so it never faults
	// (stays dark) — the soundness counterpart that makes a fired beacon attributable.
	psrc, err := os.ReadFile(filepath.Join("testdata", "repros", "FERRALON-APP-DOS-0001-patched", "main.go"))
	if err != nil {
		t.Fatalf("read DoS patched repro: %v", err)
	}
	ps := string(psrc)
	if !strings.Contains(ps, "maxCount") || !strings.Contains(ps, "RequestEntityTooLarge") {
		t.Error("DoS patched repro must bound count before allocation (the dark negative control)")
	}
}
