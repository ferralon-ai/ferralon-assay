package javaanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reachability_bytecode.go — whole-program reachability for dependency sinks ("jvmref"
// symbols from ResolveDependencySymbols), searched over the build's compiled classes plus
// the dependency closure (reachclosure.go) with the depreach engine.
//
// Roots are traced in two roles:
//   - a main method (public static void main(String[])) is a whole-program root: when every
//     main's search comes back empty with no hazard, the sink is listed in Searched;
//   - an ingress the lexical recognisers found (a Spring route, a servlet method), mapped to
//     its compiled method, can yield a candidate path or block Searched, but never licenses
//     it: a framework host runs code no main reaches.
//
// A sink is Searched only when the class output covers the sources, there is at least one
// main, every mapped root's search is empty and hazard-free, every ingress mapped to
// compiled code, and the sink has a concrete body in loaded code. Otherwise a sink with no
// path carries no_known_ingress + reachability_undetermined, plus no_whole_program_root when
// there is no main.
//
// Every scoped reason is also listed run-wide in Reasons until the gate reads Scoped.

const reasonNoWholeProgramRoot = "no_whole_program_root"

// mainDescriptor is the JVM descriptor of public static void main(String[]).
const mainDescriptor = "([Ljava/lang/String;)V"

// bytecodeRoot is one traced root: the compiled method, and for an ingress the lexical
// symbol the ingress listing names it by.
type bytecodeRoot struct {
	ref     classfile.MethodRef
	ingress string // lexical ingress SCIP; "" for a main
}

// bytecodeReachability searches each sink from every main and mapped ingress.
func bytecodeReachability(ctx context.Context, buildDir string, prog *program, fp *firstPartyBytecode, sinks []string, opts ...Option) ([]plugin.ReachPath, []string, map[string]bool, []plugin.ScopedReason, error) {
	reasons := map[string]bool{}
	var scoped []plugin.ScopedReason

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: buildDir}, opts...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}

	rc, err := loadReachClosure(ctx, buildDir, fp.classes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	scoped = append(scoped, rc.Scoped...)
	if !fp.complete() {
		scoped = append(scoped, fp.scoped()...)
	}

	mains := mainRoots(fp.classes)
	ingresses, unmapped := ingressRoots(prog, fp.classes)
	if len(mains) == 0 {
		reasons[reasonNoWholeProgramRoot] = true
	}
	roots := append(append([]bytecodeRoot{}, mains...), ingresses...)

	var paths []plugin.ReachPath
	var searched []string
	for _, id := range sinks {
		sink, _ := parseDepEdgeSymbol(id)
		clean := true
		var found *plugin.ReachPath
		for _, root := range roots {
			res := rc.Engine.Reach(root.ref, sink)
			if res.Verdict == depreach.ReachableCandidate {
				p := reachPathFromBytecode(id, root, res.Path)
				found = &p
				break
			}
			if res.Verdict != depreach.NotExploitable {
				clean = false
				if r := hazardReason(res.HazardWhy); r != "" {
					reasons[r] = true
				}
			}
		}
		switch {
		case found != nil:
			if found.Ingress.SCIP == "" {
				reasons[plugin.PartialReasonNoIngress] = true // reached from a main, not an attacker-facing ingress
			}
			paths = append(paths, *found)
		case clean && len(mains) > 0 && fp.complete() && !unmapped && rc.concrete(sink):
			searched = append(searched, id)
		default:
			reasons[plugin.PartialReasonNoIngress] = true
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
		}
	}
	if unmapped {
		reasons[plugin.PartialReasonReachabilityUndetermined] = true
	}
	return paths, searched, reasons, scoped, nil
}

// mainRoots returns every concrete main(String[]) in the compiled classes, sorted.
func mainRoots(classes []classfile.Class) []bytecodeRoot {
	var out []bytecodeRoot
	for _, c := range classes {
		for _, m := range c.Methods {
			if m.Ref.Name == "main" && m.Ref.Descriptor == mainDescriptor && !m.Abstract && !m.Native {
				out = append(out, bytecodeRoot{ref: m.Ref})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ref.String() < out[j].ref.String() })
	return out
}

// ingressRoots maps each lexical ingress marker to the compiled methods it names: same
// binary class (package path + '$'-joined enclosing chain), same name, same parameter
// count. unmapped is true when some marker has no compiled counterpart, so a framework
// entry exists that the search cannot start from.
func ingressRoots(prog *program, classes []classfile.Class) (roots []bytecodeRoot, unmapped bool) {
	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}
	seen := map[string]bool{}
	for _, f := range prog.files {
		pkgPath := strings.ReplaceAll(f.pkg, ".", "/")
		for _, in := range f.ingresses {
			owner := strings.Join(in.enclosing, "$")
			if pkgPath != "" {
				owner = pkgPath + "/" + owner
			}
			c := byName[owner]
			hit := false
			if c != nil {
				for _, m := range c.Methods {
					if m.Ref.Name != in.name || descriptorParamCount(m.Ref.Descriptor) != in.arity || m.Abstract {
						continue
					}
					hit = true
					if !seen[m.Ref.String()] {
						seen[m.Ref.String()] = true
						roots = append(roots, bytecodeRoot{ref: m.Ref, ingress: methodSCIP(f.pkg, in.enclosing, in.name, in.arity)})
					}
				}
			}
			if !hit {
				unmapped = true
			}
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].ref.String() < roots[j].ref.String() })
	return roots, unmapped
}

// descriptorParamCount counts the parameters in a JVM method descriptor; -1 if malformed.
func descriptorParamCount(desc string) int {
	if !strings.HasPrefix(desc, "(") {
		return -1
	}
	n := 0
	for i := 1; i < len(desc); {
		switch desc[i] {
		case ')':
			return n
		case '[':
			i++
			continue
		case 'L':
			end := strings.IndexByte(desc[i:], ';')
			if end < 0 {
				return -1
			}
			i += end + 1
		case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
			i++
		default:
			return -1
		}
		n++
	}
	return -1
}

// hazardReason names the partiality a depreach hazard maps to, "" when none applies
// beyond reachability_undetermined.
func hazardReason(why string) string {
	switch {
	case strings.HasPrefix(why, "reflection"):
		return plugin.PartialReasonReflection
	case strings.HasPrefix(why, "invokedynamic"):
		return plugin.PartialReasonDynamicDispatch
	}
	return ""
}

// reachPathFromBytecode renders a depreach path as a ReachPath: the trace in dependency
// call-graph ids, the ingress by its lexical id when the root was an ingress.
func reachPathFromBytecode(sinkID string, root bytecodeRoot, path []classfile.MethodRef) plugin.ReachPath {
	trace := make([]plugin.Symbol, len(path))
	for i, m := range path {
		trace[i] = sym(depEdgeSymbol(m))
	}
	return plugin.ReachPath{Sink: sym(sinkID), Ingress: sym(root.ingress), Trace: trace}
}
