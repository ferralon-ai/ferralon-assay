package dotnetanalysis

// ingress_il.go — ASP.NET Core request entry points as IL search roots.
//
// ASP.NET Core calls application code no call edge from Main shows: it discovers
// controllers and Razor Pages by reflection over the application's assemblies and invokes
// the delegates handed to its endpoint, middleware and builder APIs. Main hands control to
// the host, an out-of-set hazard, so Main alone leaves such a program undetermined. These
// roots add what the host can run:
//
//   - controller actions, by ASP.NET Core's own discovery rule (ControllerFeatureProvider
//     and the default action convention): a public, non-abstract, non-generic top-level
//     class that is not [NonController] and either ends in "Controller" or carries
//     [Controller] on itself or a base (ControllerBase carries it); its actions are the
//     public instance methods, declared on it or a loaded base, that are not special names
//     and not [NonAction];
//   - Razor Pages handlers: the public instance On* methods of a PageModel or Page
//     subclass, and the ExecuteAsync body of a compiled page or view;
//   - delegates handed to ASP.NET Core: the target of an ldftn/ldvirtftn whose delegate
//     is passed to the next call, when that call is a member of Microsoft.AspNetCore.*
//     (MapGet and the other Map* endpoint APIs, Use/Run middleware, builder callbacks).
//
// The roots apply only when the program's entry assembly references ASP.NET Core, and are
// collected across the whole loaded set: ASP.NET Core also discovers controllers in the
// dependencies that reference MVC.
//
// They over-approximate what the host runs, so they never license not_exploitable: a
// path from one is a candidate, and a hit or hazard from one keeps the sink out of
// Searched. NE stays licensed by Main plus the runtime roots alone.

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/depreach"
)

const (
	aspNetCoreNS = "Microsoft.AspNetCore"
	aspNetMvcNS  = "Microsoft.AspNetCore.Mvc"

	tblTypeDefTable    = 0x02
	tblMethodSpecTable = 0x2B

	// ECMA-335 TypeAttributes (§II.23.1.15).
	typeAttrVisibilityMask = 0x07
	typeAttrPublic         = 0x01
	typeAttrInterface      = 0x20
	typeAttrAbstract       = 0x80

	// ECMA-335 MethodAttributes (§II.23.1.10).
	methodAttrAccessMask = 0x0007
	methodAttrPublic     = 0x0006
	methodAttrAbstract   = 0x0400
)

// controllerBases are the MVC base types that carry [Controller].
var controllerBases = map[string]bool{
	"Microsoft.AspNetCore.Mvc.ControllerBase": true,
	"Microsoft.AspNetCore.Mvc.Controller":     true,
}

// handlerBases are the Razor Pages types whose subclasses' On* methods are handlers.
var handlerBases = map[string]bool{
	"Microsoft.AspNetCore.Mvc.RazorPages.PageModel": true,
	"Microsoft.AspNetCore.Mvc.RazorPages.Page":      true,
}

// viewBases are the compiled page and view base types whose ExecuteAsync renders a request.
var viewBases = map[string]bool{
	"Microsoft.AspNetCore.Mvc.RazorPages.Page":   true,
	"Microsoft.AspNetCore.Mvc.Razor.RazorPage":   true,
	"Microsoft.AspNetCore.Mvc.Razor.RazorPage`1": true,
}

type ilType struct {
	asm *assembly.Assembly
	td  *assembly.TypeDef
}

// ingressRootKeys returns the ASP.NET Core entry points of the loaded set, sorted and
// de-duplicated, or nil when the entry assembly does not reference ASP.NET Core.
func ingressRootKeys(fp *assembly.Assembly, asms []*assembly.Assembly) []depreach.MethodKey {
	if fp == nil || !fp.ReferencesNamespace(aspNetCoreNS) {
		return nil
	}
	byName := map[string][]ilType{}
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			byName[a.QualifiedName(td)] = append(byName[a.QualifiedName(td)], ilType{a, td})
		}
	}
	seen := map[depreach.MethodKey]bool{}
	var roots []depreach.MethodKey
	add := func(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef) {
		k, _ := methodIdentity(a, td, m)
		if !seen[k] {
			seen[k] = true
			roots = append(roots, k)
		}
	}
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		mvc := a.ReferencesNamespace(aspNetMvcNS)
		for i := range a.Types {
			t := ilType{a, &a.Types[i]}
			if mvc {
				typeRoots(t, byName, add)
			}
		}
		if a.ReferencesNamespace(aspNetCoreNS) {
			delegateRoots(a, add)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].String() < roots[j].String() })
	return roots
}

// typeRoots adds t's controller actions, page handlers and view bodies.
func typeRoots(t ilType, byName map[string][]ilType, add func(*assembly.Assembly, *assembly.TypeDef, *assembly.MethodDef)) {
	td := t.td
	if td.Flags&typeAttrInterface != 0 || td.Flags&typeAttrAbstract != 0 {
		return
	}
	chain, ext := baseChain(t, byName)
	switch {
	case isController(t, chain, ext):
		for _, an := range chain {
			for _, m := range an.td.Methods {
				if isPublicInstanceMethod(m) && !an.asm.HasAttribute(m.Token, "NonActionAttribute") {
					add(an.asm, an.td, m)
				}
			}
		}
	case handlerBases[ext] || viewBases[ext]:
		for _, an := range chain {
			for _, m := range an.td.Methods {
				if m == nil {
					continue
				}
				handler := handlerBases[ext] && isPublicInstanceMethod(m) && strings.HasPrefix(m.Name, "On")
				view := viewBases[ext] && m.Name == "ExecuteAsync" && m.Flags&methodAttrStatic == 0
				if handler || view {
					add(an.asm, an.td, m)
				}
			}
		}
	}
}

// isController applies ASP.NET Core's controller discovery rule to t, whose loaded base
// chain (t first) is chain and whose first base outside the loaded set is ext.
func isController(t ilType, chain []ilType, ext string) bool {
	td := t.td
	if td.Flags&typeAttrVisibilityMask != typeAttrPublic || strings.Contains(td.Name, "`") {
		return false
	}
	if ext == "System.ValueType" || ext == "System.Enum" {
		return false
	}
	for _, an := range chain {
		if an.asm.HasAttribute(an.td.Token, "NonControllerAttribute") {
			return false
		}
	}
	if len(td.Name) >= len("Controller") && strings.EqualFold(td.Name[len(td.Name)-len("Controller"):], "Controller") {
		return true
	}
	for _, an := range chain {
		if an.asm.HasAttribute(an.td.Token, "ControllerAttribute", "ApiControllerAttribute") {
			return true
		}
	}
	return controllerBases[ext]
}

// isPublicInstanceMethod is the action and handler shape: public, instance, with a body
// the type supplies (not abstract), and not a special name (constructors, accessors,
// operators).
func isPublicInstanceMethod(m *assembly.MethodDef) bool {
	return m != nil &&
		m.Flags&methodAttrAccessMask == methodAttrPublic &&
		m.Flags&(methodAttrStatic|methodAttrAbstract|methodAttrSpecialName) == 0
}

// baseChain walks t's base types through the loaded set, returning the loaded types (t
// first) and the qualified name of the first base outside it ("" when the chain ends
// inside the set). A base named by more than one loaded type follows the first.
func baseChain(t ilType, byName map[string][]ilType) ([]ilType, string) {
	chain := []ilType{t}
	seen := map[*assembly.TypeDef]bool{t.td: true}
	cur := t
	for {
		tr := cur.td.Extends
		if tr.Def != nil {
			tr = *tr.Def
		}
		if tr.Token.IsNull() {
			return chain, ""
		}
		var next ilType
		if tr.Token.Table() == tblTypeDefTable {
			rid := tr.Token.RID()
			if rid == 0 || int(rid) > len(cur.asm.Types) {
				return chain, ""
			}
			next = ilType{cur.asm, &cur.asm.Types[rid-1]}
		} else {
			name := tr.Qualified()
			cands := byName[name]
			if len(cands) == 0 {
				return chain, name
			}
			next = cands[0]
		}
		if seen[next.td] {
			return chain, ""
		}
		seen[next.td] = true
		chain = append(chain, next)
		cur = next
	}
}

// delegateRoots adds the target of every ldftn/ldvirtftn in a whose delegate is handed to
// an ASP.NET Core member: the next call after the capture, past the delegate's
// construction and any further captures for the same call.
func delegateRoots(a *assembly.Assembly, add func(*assembly.Assembly, *assembly.TypeDef, *assembly.MethodDef)) {
	for i := range a.Types {
		for _, m := range a.Types[i].Methods {
			if m == nil || m.RVA == 0 {
				continue
			}
			body, err := a.MethodBody(m)
			if err != nil || body == nil {
				continue
			}
			for j, e := range body.Edges {
				if e.Kind != assembly.EdgeLdftn && e.Kind != assembly.EdgeLdvirtftn {
					continue
				}
				if !handedToASPNetCore(a, body.Edges[j+1:]) {
					continue
				}
				if tm, ttd, ok := assemblyMethod(a, methodDefOf(a, e.Token)); ok {
					add(a, ttd, tm)
				}
			}
		}
	}
}

// handedToASPNetCore reports whether the first call in rest, skipping delegate
// construction and further captures, is a member of a Microsoft.AspNetCore type.
func handedToASPNetCore(a *assembly.Assembly, rest []assembly.Edge) bool {
	for _, e := range rest {
		switch e.Kind {
		case assembly.EdgeNewobj, assembly.EdgeLdftn, assembly.EdgeLdvirtftn:
			continue
		case assembly.EdgeCall, assembly.EdgeCallvirt:
			owner := calleeOwner(a, e.Token)
			return owner == aspNetCoreNS || strings.HasPrefix(owner, aspNetCoreNS+".")
		default:
			return false
		}
	}
	return false
}

// methodDefOf resolves a MethodSpec to the method it instantiates; other tokens pass
// through.
func methodDefOf(a *assembly.Assembly, tok assembly.Token) assembly.Token {
	if tok.Table() == tblMethodSpecTable {
		if rid := int(tok.RID()); rid > 0 && rid < len(a.MethodSpecs) {
			return a.MethodSpecs[rid].Method
		}
	}
	return tok
}

// calleeOwner is the qualified name of the type declaring the method a call token names,
// or "" when it does not resolve to a type outside a.
func calleeOwner(a *assembly.Assembly, tok assembly.Token) string {
	tok = methodDefOf(a, tok)
	if tok.Table() != tblMemberRefTable {
		return ""
	}
	mr := a.MemberRef(tok.RID())
	if mr == nil {
		return ""
	}
	if mr.Type != "" {
		return mr.Type
	}
	return a.TypeRefFor(mr.ParentToken).Qualified()
}
