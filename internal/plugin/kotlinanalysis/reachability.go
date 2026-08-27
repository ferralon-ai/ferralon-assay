package kotlinanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Reachability derives, for each resolved sink in req.Symbols, whether a static call path
// connects a discoverable program ingress (`main`) to that sink in the compiled build
// output. It runs the SHARED depreach engine (CHA + two-trace proof-of-non-exploitability)
// over the Kotlin bytecode unchanged — the substrate reuse A4/K3 mandate.
//
// Honest-absent / fail-open (inv.5) is enforced by depreach itself and folded into the
// declared partiality here:
//   - depreach returns ReachableCandidate only from a search that ran and found a path;
//     the ordered path is emitted.
//   - Undetermined (a completeness hazard — invokedynamic, reflection, an out-of-classpath
//     receiver, a native frontier — lay on the searched frontier) is declared
//     reachability_undetermined: absence of a found path is NEVER rendered as "safe".
//   - NotExploitable (a real, hazard-free empty search) contributes no path and no reason —
//     the one arm where absence is a sound negative.
//
// A sink string that cannot be parsed to a JVM method reference, or a request with no
// discoverable ingress, is declared partial (never silently dropped). Dependency classes
// absent from the first-party classpath are out-of-classpath leaves depreach treats as
// hazards — so a sink inside an unloaded dependency fails open to undetermined, not to a
// false not-reachable.
func Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}

	engine := depreach.NewEngine(prog.classes)
	ingresses := mainMethodRefs(prog.classes)

	var paths []plugin.ReachPath
	for _, s := range req.Symbols {
		if s == "" {
			continue
		}
		sink, ok := parseMethodRef(s)
		if !ok {
			prog.reasons[plugin.PartialReasonToolFailure] = true
			continue
		}
		if len(ingresses) == 0 {
			// No entry point to start a search from: reachability is undetermined
			// (fail-open), and no attacker-facing ingress was found.
			prog.reasons[plugin.PartialReasonNoIngress] = true
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		}

		if path, found, undetermined := reachFromAny(engine, ingresses, sink); found {
			paths = append(paths, path)
		} else if undetermined {
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
		}
	}

	return plugin.ReachabilityResult{
		Partiality: prog.partiality(),
		Paths:      paths,
	}, nil
}

// reachFromAny runs the two-trace query from every ingress toward sink. It returns the
// first ReachableCandidate path found (found=true); otherwise undetermined reports whether
// any ingress's search abstained on a completeness hazard (vs. every search being a sound
// hazard-free empty). This is the fail-open discriminator the caller declares.
func reachFromAny(engine *depreach.Engine, ingresses []classfile.MethodRef, sink classfile.MethodRef) (path plugin.ReachPath, found, undetermined bool) {
	for _, ingress := range ingresses {
		res := engine.Reach(ingress, sink)
		switch res.Verdict {
		case depreach.ReachableCandidate:
			return reachPathFromTrace(res.Path), true, false
		case depreach.Undetermined:
			undetermined = true
		}
	}
	return plugin.ReachPath{}, false, undetermined
}

// reachPathFromTrace maps a depreach ingress→sink MethodRef path to a plugin.ReachPath of
// canonical symbols. The first element is the ingress, the last the sink.
func reachPathFromTrace(trace []classfile.MethodRef) plugin.ReachPath {
	syms := make([]plugin.Symbol, len(trace))
	for i, ref := range trace {
		syms[i] = SymbolFromMethodRef(ref)
	}
	var p plugin.ReachPath
	p.Trace = syms
	if len(syms) > 0 {
		p.Ingress = syms[0]
		p.Sink = syms[len(syms)-1]
	}
	return p
}

// parseMethodRef parses a sink string in classfile.MethodRef.String() form —
// "<owner>.<name><descriptor>", e.g. "com/example/UrlKt.fetch(Ljava/lang/String;)V" — back
// into a MethodRef. The descriptor begins at the first '('; the name is the segment after
// the last '.' before it; the owner is everything prior (internal slash form). ok is false
// for any string not in this shape — the caller declares that a partiality, never a guess.
func parseMethodRef(s string) (classfile.MethodRef, bool) {
	paren := strings.IndexByte(s, '(')
	if paren < 0 {
		return classfile.MethodRef{}, false
	}
	head, descriptor := s[:paren], s[paren:]
	dot := strings.LastIndexByte(head, '.')
	if dot <= 0 || dot == len(head)-1 {
		return classfile.MethodRef{}, false
	}
	return classfile.MethodRef{
		Owner:      head[:dot],
		Name:       head[dot+1:],
		Descriptor: descriptor,
	}, true
}
