package kotlinanalysis

import (
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program.go — the shared first-party load every op funnels through, plus the Kotlin
// lane's localized partiality reason codes. Loading is done ONCE per op from the compiled
// build output; the resulting classes feed IndexSymbols, CallGraph, and (via depreach)
// Reachability alike.

// partialReasonNoBuildOutput localizes the shared tool_failure base for the Kotlin
// tool-unavailable frontier: no compiled build output was present under the checkout, so
// the analyzer could not see the first-party code at all. It is honest-absent (§3.6) — an
// absent artifact, never a confident-empty result.
const partialReasonNoBuildOutput = plugin.PartialReasonToolFailure + ":no_build_output"

// program is the loaded first-party bytecode plus the partiality its loading incurred.
type program struct {
	classes []classfile.Class
	// reasons is the accumulated declared-partiality reason set (deduplicated).
	reasons map[string]bool
	// noBuildOutput is true when no build-output root existed — the caller decides
	// whether that is a hard error (index) or a fail-open partiality (reachability).
	noBuildOutput bool
}

// loadProgram stats the build dir, loads the first-party compiled classes, and folds
// build-output-absent and per-class parse hazards into declared partiality. A missing or
// non-directory build dir is a HARD error (inv.4) — the request is malformed, distinct
// from a present-but-uncompiled tree (which is declared partiality).
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("kotlinanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("kotlinanalysis: build dir %q is not a directory", buildDir)
	}

	classes, found, failed := firstPartyLoad(buildDir)
	p := &program{classes: classes, reasons: map[string]bool{}}
	if !found {
		p.noBuildOutput = true
		p.reasons[partialReasonNoBuildOutput] = true
	}
	if len(failed) > 0 {
		p.reasons[plugin.PartialReasonToolFailure] = true
	}
	return p, nil
}

// partiality collapses the accumulated reason set into a Partiality: Complete when empty,
// else Partial with reasons sorted for a stable payload (determinism: no map is an
// iteration source on the encoding path).
func (p *program) partiality() plugin.Partiality {
	if len(p.reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(p.reasons)...)
}

// sortedKeys returns a set's keys in sorted order, for deterministic reason lists.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
