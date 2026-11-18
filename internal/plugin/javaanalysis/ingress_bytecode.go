package javaanalysis

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jvmingress"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ingress_bytecode.go — entry points read off the compiled first-party classes, with the
// annotations a method inherits from the interface or superclass method it overrides
// (jvmingress.Compiled). The lexical recogniser binds an annotation to the method in the same
// type body, so a controller whose routes are declared on a generated or shared interface, or
// a generated controller class under target/generated-sources, has none. These are unioned
// with the lexical ingresses; nothing here removes one.

// reasonInheritedRoute withholds Searched when a first-party class has a supertype nothing
// loaded defines: the route it declares for the class's methods is unreadable.
const reasonInheritedRoute = plugin.PartialReasonRelationshipUnexpressed + ":inherited_route"

// compiledIngressRoots returns the compiled entry points not already in have, as search roots
// carrying the ingress id the listing names them by. lookup resolves supertypes.
func compiledIngressRoots(classes []classfile.Class, lookup func(string) (*classfile.Class, bool), have []bytecodeRoot) []bytecodeRoot {
	seen := map[string]bool{}
	for _, r := range have {
		seen[r.ref.String()] = true
	}
	var out []bytecodeRoot
	for _, e := range jvmingress.Compiled(classes, lookup) {
		if seen[e.Ref.String()] {
			continue
		}
		seen[e.Ref.String()] = true
		out = append(out, bytecodeRoot{ref: e.Ref, ingress: refSCIP(e.Ref)})
	}
	return out
}

// compiledIngresses lists the compiled entry points as ingresses, skipping any whose (kind,
// symbol) the lexical listing already holds.
func compiledIngresses(classes []classfile.Class, have []plugin.Ingress) []plugin.Ingress {
	byName := make(map[string]*classfile.Class, len(classes))
	for i := range classes {
		byName[classes[i].Name] = &classes[i]
	}
	seen := map[string]bool{}
	for _, in := range have {
		seen[in.Kind+"\x00"+in.Symbol.SCIP] = true
	}
	var out []plugin.Ingress
	for _, e := range jvmingress.Compiled(classes, func(n string) (*classfile.Class, bool) { c, ok := byName[n]; return c, ok }) {
		id := refSCIP(e.Ref)
		if seen[e.Kind+"\x00"+id] {
			continue
		}
		seen[e.Kind+"\x00"+id] = true
		out = append(out, plugin.Ingress{Kind: e.Kind, Symbol: sym(id), Selector: e.Selector})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Symbol.SCIP < out[j].Symbol.SCIP })
	return out
}

// refSCIP is the lexical id of a compiled method: package from the binary name's path,
// enclosing chain from its '$' segments.
func refSCIP(ref classfile.MethodRef) string {
	pkg, name := "", ref.Owner
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		pkg, name = strings.ReplaceAll(name[:i], "/", "."), name[i+1:]
	}
	return methodSCIP(pkg, strings.Split(name, "$"), ref.Name, ref.ParamCount())
}
