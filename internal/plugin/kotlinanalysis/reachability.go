package kotlinanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// partialReasonNoWholeProgramRoot is declared when the build output has no `main`: framework
// ingress roots alone cannot bound what runs (the container or framework may invoke code the
// recognisers do not know), so no sink can be cleared. did_not_run by the classifier.
const partialReasonNoWholeProgramRoot = "no_whole_program_root"

// Reachability derives, for each resolved sink in req.Symbols, whether a static call path
// connects a program ingress to that sink. It runs the SHARED depreach engine (CHA) over the
// first-party build output PLUS the build's resolved dependency closure (depclosure.go), so a
// trace follows calls into the exact dependency bytecode the build resolved.
//
// Roots and what each may license:
//   - `main` (every mainMethodRefs entry, plus each main owner's companion initializers) is the
//     whole-program root and the ONLY root that licenses a cleared sink. A sink is listed in
//     Searched only when at least one main exists, the sink is a concrete method in loaded
//     bytecode, and every root's search (main and framework) was a hazard-free empty search.
//     Every first-party class root and build/libs JAR must also have been listed and read in
//     full (program.loadFailed): code that was not read may call any sink.
//   - framework ingress roots (frameworkIngressRefs) add a candidate path or undetermined,
//     never a cleared sink on their own.
//   - no main → no_whole_program_root + reachability_undetermined for any sink not found;
//     a candidate path from a framework root is still reported.
//
// Only the build root is traced. A build with further projects (modules.go) declares
// multiple_projects_unsupported and clears no sink: an untraced project could call it.
//
// Every hazard met is declared: reachability_undetermined (did_not_run) always, plus
// `reflection` / `dynamic_dispatch` when those were the kinds met. A dependency JAR that could
// not be opened is a Scoped reason bounded by its closure (javaanalysis.BlindSpotTargets) and is
// not repeated in Reasons: the verdict gate counts it only against an advisory whose package the
// hidden code could reach.
func Reachability(_ context.Context, req plugin.ReachabilityRequest, opts ...javaanalysis.Option) (plugin.ReachabilityResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}
	multiProject := len(otherProjects(req.BuildDir)) > 0
	if multiProject {
		prog.reasons[partialReasonMultipleProjects] = true
	}

	var sinks []string
	for _, s := range req.Symbols {
		if s != "" {
			sinks = append(sinks, s)
		}
	}
	if len(sinks) == 0 {
		return plugin.ReachabilityResult{Partiality: prog.partiality()}, nil
	}

	firstParty := make(map[string]bool, len(prog.classes))
	for _, c := range prog.classes {
		firstParty[c.Name] = true
	}
	deps := loadDependencyClosure(req.BuildDir, firstParty, opts...)
	for _, r := range deps.reasons {
		prog.reasons[r] = true
	}
	all := make([]classfile.Class, 0, len(prog.classes)+len(deps.classes))
	all = append(all, prog.classes...)
	all = append(all, deps.classes...)
	// What the build says starts the program licenses an empty search; it says nothing about a
	// path the search found.
	entryReasons := launchEntryReasons(req.BuildDir, prog, deps, all)
	cp := prog.cp
	cp.Merge(deps.cp)
	engine := depreach.NewEngineOn(all, cp)
	concrete := concreteMethods(all, cp.JDK)

	// Roots are first-party mains. A `main` inside a dependency JAR is not this program's entry
	// point; a build that launches one leaves its launch entry unmapped (launchEntryReasons).
	mains := mainMethodRefs(prog.classes)
	mains = append(mains, companionInitRoots(all, mains)...)
	frameworks := frameworkIngressRefs(prog.classes)

	var paths []plugin.ReachPath
	var searched []string
	for _, s := range sinks {
		sink, ok := parseMethodRef(s)
		if !ok {
			prog.reasons[plugin.PartialReasonToolFailure] = true
			continue
		}
		if len(mains)+len(frameworks) == 0 {
			prog.reasons[partialReasonNoWholeProgramRoot] = true
			prog.reasons[plugin.PartialReasonNoIngress] = true
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
			continue
		}

		out := searchSink(engine, mains, frameworks, sink)
		switch {
		case out.found:
			paths = append(paths, out.path)
		case len(mains) == 0:
			prog.reasons[partialReasonNoWholeProgramRoot] = true
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
		case out.undetermined || !concrete[sink.String()] || multiProject || len(deps.reasons) > 0 || prog.loadFailed:
			// An abstract sink is never an engine target (dispatch lands on overrides), so
			// an empty search for it says nothing.
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
		case len(entryReasons) > 0:
			prog.reasons[plugin.PartialReasonReachabilityUndetermined] = true
			for _, r := range entryReasons {
				prog.reasons[r] = true
			}
		default:
			searched = append(searched, s)
		}
		for _, k := range out.hazardKinds {
			switch k {
			case depreach.HazardKindReflection:
				prog.reasons[plugin.PartialReasonReflection] = true
			case depreach.HazardKindInvokedynamic:
				prog.reasons[plugin.PartialReasonDynamicDispatch] = true
			}
		}
	}

	part := prog.partiality()
	if len(deps.scoped) > 0 {
		part.Complete = false
		part.Scoped = deps.scoped
	}
	return plugin.ReachabilityResult{
		Partiality: part,
		Paths:      paths,
		Searched:   searched,
	}, nil
}

// companionInitRoots returns the initializers of each main owner's companion object: its
// declared <clinit> and every <init>. The JVM initializes the launch class before main runs
// (the engine enqueues that closure), and Kotlin builds a class's companion from the class's
// static initializer, so a companion's init block or property initializer runs before main.
// Rooting them directly keeps that true when the outer <clinit> is absent from loaded code.
func companionInitRoots(classes []classfile.Class, mains []classfile.MethodRef) []classfile.MethodRef {
	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}
	seen := map[string]bool{}
	var out []classfile.MethodRef
	for _, m := range mains {
		c := byName[m.Owner+"$Companion"]
		if c == nil || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		for _, meth := range c.Methods {
			if meth.Ref.Name == "<clinit>" || meth.Ref.Name == "<init>" {
				out = append(out, meth.Ref)
			}
		}
	}
	return out
}

// sinkSearch is the combined outcome of searching one sink from every root.
type sinkSearch struct {
	path         plugin.ReachPath
	found        bool
	undetermined bool
	hazardKinds  []string
}

// searchSink runs the engine from every main root, then every framework root. The first
// candidate path wins. Otherwise undetermined reports whether any root's search abstained on
// a hazard; hazardKinds collects every kind met, for the declared reasons.
func searchSink(engine *depreach.Engine, mains, frameworks []classfile.MethodRef, sink classfile.MethodRef) sinkSearch {
	var out sinkSearch
	kinds := map[string]bool{}
	roots := make([]classfile.MethodRef, 0, len(mains)+len(frameworks))
	roots = append(roots, mains...)
	roots = append(roots, frameworks...)
	for _, root := range roots {
		res := engine.Reach(root, sink)
		for _, k := range res.HazardKinds {
			kinds[k] = true
		}
		switch res.Verdict {
		case depreach.ReachableCandidate:
			out.path, out.found = reachPathFromTrace(res.Path), true
			out.hazardKinds = sortedKeys(kinds)
			return out
		case depreach.Undetermined:
			out.undetermined = true
		}
	}
	out.hazardKinds = sortedKeys(kinds)
	return out
}

// concreteMethods returns the set of method refs (MethodRef.String()) that have a body in the
// loaded bytecode: not abstract, not native, and not on a copy of a class the JVM may load from
// the JDK instead on feature release jdk.
func concreteMethods(classes []classfile.Class, jdk int) map[string]bool {
	out := map[string]bool{}
	for _, c := range classes {
		if depreach.BootOnly(c.Name, jdk) {
			continue
		}
		for _, m := range c.Methods {
			if !m.Abstract && !m.Native {
				out[m.Ref.String()] = true
			}
		}
	}
	return out
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
