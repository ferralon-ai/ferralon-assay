package dotnetanalysis

// ingress_il_test.go — ASP.NET Core request entry points as IL search roots. A path from a
// controller action, a Razor Pages handler or a delegate handed to ASP.NET Core is a
// candidate; such a root never makes a sink searched. Rows whose shape is NOT an entry
// point use a hazard-free Main, so the sink coming out searched is what shows the shape
// was not rooted.

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

var sigFuncCtor = []byte{0x20, 0x02, 0x01, 0x1C, 0x18} // instance void .ctor(object, native int)

const (
	tPublic         = 0x0001
	tPublicAbstract = 0x0081
	mPublic         = 0x0086 // public hidebysig instance
	mPrivate        = 0x0081 // private hidebysig instance
	mPublicStatic   = 0x0096 // public hidebysig static
)

func hcaTypeDef(rid uint32) uint32   { return rid<<5 | 3 }
func hcaMethodDef(rid uint32) uint32 { return rid << 5 }

// attr records a parameterless custom attribute ns.name on the element parentCoded (a
// HasCustomAttribute coded index).
func (b *peb) attr(parentCoded uint32, ns, name string) {
	ctor := b.memberRef(b.extTypeRef(ns, name), ".ctor", sigInstVoid)
	b.row(xCustomAttribute, parentCoded, (ctor&0xFFFFFF)<<3|3, b.blob([]byte{0x01, 0x00, 0x00, 0x00}))
}

// nextMethodRID is the RID the next method addType declares will get.
func (b *peb) nextMethodRID() uint32 { return uint32(len(b.tables[xMethodDef])) + 1 }

// nextTypeRID is the RID the next addType will get.
func (b *peb) nextTypeRID() uint32 { return uint32(len(b.tables[xTypeDef])) + 1 }

type aspCtx struct {
	obj            uint32 // System.Object, as a TypeDefOrRef coded index
	controllerBase uint32 // Microsoft.AspNetCore.Mvc.ControllerBase (0 without ASP.NET refs)
	pageModel      uint32 // Microsoft.AspNetCore.Mvc.RazorPages.PageModel
	boom           uint32 // MemberRef: D.Sink.boom(int) in Dep.dll
	hazard         uint32 // MemberRef: System.Activator.CreateInstance
}

// aspApp builds App.dll. main is "hosted" (Main hands control to the ASP.NET Core host, an
// out-of-set call), "console" (Main calls nothing) or "none" (no entry point). aspRefs adds
// the MVC base types to the image; add declares the shape under test.
func aspApp(main string, aspRefs bool, add func(b *peb, x aspCtx)) []byte {
	b := scaffold()
	x := aspCtx{obj: cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))}
	x.boom = b.memberRef(b.extTypeRefScoped(b.asmRef("Dep"), "D", "Sink"), "boom", sigStaticIntVoid)
	x.hazard = b.memberRef(b.extTypeRef("System", "Activator"), "CreateInstance", sigStaticVoid)
	if aspRefs {
		x.controllerBase = cTypeDefOrRef(xTypeRef, b.extTypeRefScoped(b.asmRef("Microsoft.AspNetCore.Mvc.Core"), "Microsoft.AspNetCore.Mvc", "ControllerBase"))
		x.pageModel = cTypeDefOrRef(xTypeRef, b.extTypeRefScoped(b.asmRef("Microsoft.AspNetCore.Mvc.RazorPages"), "Microsoft.AspNetCore.Mvc.RazorPages", "PageModel"))
	}
	mainIL := body()
	if main == "hosted" {
		host := b.extTypeRefScoped(b.asmRef("Microsoft.AspNetCore"), "Microsoft.AspNetCore.Builder", "WebApplication")
		mainIL = body(ilCall(b.memberRef(host, "Run", sigStaticVoid)))
	}
	b.addType(0, "<Module>", "", 0, nil)
	_, pm := b.addType(tPublic, "Program", "App", x.obj, []mspec{{name: "Main", flags: mPublicStatic, sig: sigStaticVoid, il: mainIL}})
	if main != "none" {
		b.entry = mtok(xMethodDef, pm[0])
	}
	add(b, x)
	return b.bytesNamed("App")
}

// controller declares a type name : extends with one method of the given flags whose body
// is il.
func controller(name string, typeFlags uint32, extends func(aspCtx) uint32, method string, mflags uint32, il func(aspCtx) []byte) func(*peb, aspCtx) {
	return func(b *peb, x aspCtx) {
		b.addType(typeFlags, name, "App.Controllers", extends(x), []mspec{{name: method, flags: mflags, sig: sigInstVoid, il: il(x)}})
	}
}

func baseCB(x aspCtx) uint32  { return x.controllerBase }
func baseObj(x aspCtx) uint32 { return x.obj }
func callsBoom(x aspCtx) []byte {
	return body(ilCall(x.boom))
}
func callsNothing(aspCtx) []byte { return body() }

// mapLambda declares App.Startup.Configure, which hands a delegate over its lambda
// <Configure>b__0_0 (whose body calls boom) to owner::method, and nothing else.
func mapLambda(asmName, ns, owner, method string) func(*peb, aspCtx) {
	return func(b *peb, x aspCtx) {
		funcCtor := b.memberRef(b.extTypeRef("System", "Func`1"), ".ctor", sigFuncCtor)
		target := b.memberRef(b.extTypeRefScoped(b.asmRef(asmName), ns, owner), method, sigStaticVoid)
		lambda := b.nextMethodRID() + 1
		b.addType(tPublic, "Startup", "App", x.obj, []mspec{
			{name: "Configure", flags: mPublic, sig: sigInstVoid, il: body(ilLdftn(mtok(xMethodDef, lambda)), ilNewobjOp(funcCtor), ilCall(target))},
			{name: "<Configure>b__0_0", flags: mPrivate, sig: sigInstVoid, il: callsBoom(x)},
		})
	}
}

// depWithController is Dep.dll with D.Sink.boom(int) and an MVC controller whose action
// calls it: a dependency ASP.NET Core would serve, if the program hosted it.
func depWithController() []byte {
	db := scaffold()
	cb := cTypeDefOrRef(xTypeRef, db.extTypeRefScoped(db.asmRef("Microsoft.AspNetCore.Mvc.Core"), "Microsoft.AspNetCore.Mvc", "ControllerBase"))
	obj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	sink := db.nextMethodRID()
	db.addType(tPublic, "Sink", "D", obj, []mspec{
		{name: "boom", flags: 0x16, sig: sigStaticIntVoid, il: body()},
		{name: "boom", flags: 0x16, sig: sigStaticStringVoid, il: body()},
	})
	db.addType(tPublic, "PluginController", "D", cb, []mspec{{name: "Run", flags: mPublic, sig: sigInstVoid, il: body(ilCall(mtok(xMethodDef, sink)))}})
	return db.bytesNamed("Dep")
}

func TestReachability_ASPNetIngressRoots(t *testing.T) {
	cases := []struct {
		name         string
		app          []byte
		dep          []byte // nil = depWithBoomOverloads(false)
		wantIngress  string // first trace node of the expected path; "" = no path
		wantSearched bool
	}{
		{
			name:        "controller action reaches the sink under a hosted Main",
			app:         aspApp("hosted", true, controller("PackagesController", tPublic, baseCB, "Search", mPublic, callsBoom)),
			wantIngress: "Search",
		},
		{
			name: "endpoint removed under a hosted Main stays undetermined",
			app:  aspApp("hosted", true, controller("PackagesController", tPublic, baseCB, "Search", mPublic, callsNothing)),
		},
		{
			name:        "controller path blocks a clean Main",
			app:         aspApp("console", true, controller("PackagesController", tPublic, baseCB, "Search", mPublic, callsBoom)),
			wantIngress: "Search",
		},
		{
			name:        "controller in a program with no Main",
			app:         aspApp("none", true, controller("PackagesController", tPublic, baseCB, "Search", mPublic, callsBoom)),
			wantIngress: "Search",
		},
		{
			name:        "controller by base type without the name suffix",
			app:         aspApp("console", true, controller("Packages", tPublic, baseCB, "Search", mPublic, callsBoom)),
			wantIngress: "Search",
		},
		{
			name:        "POCO controller by name suffix",
			app:         aspApp("console", true, controller("HomeController", tPublic, baseObj, "Index", mPublic, callsBoom)),
			wantIngress: "Index",
		},
		{
			name: "controller by [ApiController]",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				b.attr(hcaTypeDef(b.nextTypeRID()), "Microsoft.AspNetCore.Mvc", "ApiControllerAttribute")
				controller("Packages", tPublic, baseObj, "Search", mPublic, callsBoom)(b, x)
			}),
			wantIngress: "Search",
		},
		{
			name: "[NonController] is not a controller",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				b.attr(hcaTypeDef(b.nextTypeRID()), "Microsoft.AspNetCore.Mvc", "NonControllerAttribute")
				controller("HomeController", tPublic, baseCB, "Index", mPublic, callsBoom)(b, x)
			}),
			wantSearched: true,
		},
		{
			name: "[NonAction] is not an action",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				b.attr(hcaMethodDef(b.nextMethodRID()), "Microsoft.AspNetCore.Mvc", "NonActionAttribute")
				controller("HomeController", tPublic, baseCB, "Index", mPublic, callsBoom)(b, x)
			}),
			wantSearched: true,
		},
		{
			name:         "private method is not an action",
			app:          aspApp("console", true, controller("HomeController", tPublic, baseCB, "Index", mPrivate, callsBoom)),
			wantSearched: true,
		},
		{
			name:         "static method is not an action",
			app:          aspApp("console", true, controller("HomeController", tPublic, baseCB, "Index", mPublicStatic, callsBoom)),
			wantSearched: true,
		},
		{
			name:         "non-public type is not a controller",
			app:          aspApp("console", true, controller("HomeController", 0, baseCB, "Index", mPublic, callsBoom)),
			wantSearched: true,
		},
		{
			name:         "abstract controller with no concrete subclass",
			app:          aspApp("console", true, controller("BaseController", tPublicAbstract, baseCB, "Index", mPublic, callsBoom)),
			wantSearched: true,
		},
		{
			name: "action inherited from an abstract first-party base",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				baseRID := b.nextTypeRID()
				b.addType(tPublicAbstract, "ApiBase", "App.Controllers", x.controllerBase, []mspec{{name: "Search", flags: mPublic, sig: sigInstVoid, il: callsBoom(x)}})
				b.addType(tPublic, "Packages", "App.Controllers", cTypeDefOrRef(xTypeDef, baseRID), nil)
			}),
			wantIngress: "Search",
		},
		{
			name:        "Razor Pages handler",
			app:         aspApp("console", true, controller("IndexModel", tPublic, func(x aspCtx) uint32 { return x.pageModel }, "OnGet", mPublic, callsBoom)),
			wantIngress: "OnGet",
		},
		{
			name:         "PageModel method that is not a handler",
			app:          aspApp("console", true, controller("IndexModel", tPublic, func(x aspCtx) uint32 { return x.pageModel }, "Helper", mPublic, callsBoom)),
			wantSearched: true,
		},
		{
			name: "compiled view body",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				view := cTypeDefOrRef(xTypeRef, b.extTypeRefScoped(b.asmRef("Microsoft.AspNetCore.Mvc.Razor"), "Microsoft.AspNetCore.Mvc.Razor", "RazorPage"))
				b.addType(tPublic, "Views_Home_Index", "AspNetCore", view, []mspec{{name: "ExecuteAsync", flags: mPublic | 0x0040, sig: sigInstVoid, il: callsBoom(x)}})
			}),
			wantIngress: "ExecuteAsync",
		},
		{
			name:        "delegate handed to MapGet",
			app:         aspApp("console", true, mapLambda("Microsoft.AspNetCore.Routing", "Microsoft.AspNetCore.Builder", "EndpointRouteBuilderExtensions", "MapGet")),
			wantIngress: "Configure", // the lambda, projected to the method that declares it
		},
		{
			name:         "delegate handed to a non-ASP.NET method",
			app:          aspApp("console", true, mapLambda("System.Runtime", "System.Threading.Tasks", "Task", "Run")),
			wantSearched: true,
		},
		{
			name:         "no ASP.NET Core references: a Controller-named class is not rooted",
			app:          aspApp("console", false, controller("HomeController", tPublic, baseObj, "Index", mPublic, callsBoom)),
			wantSearched: true,
		},
		{
			name: "only a later entry point reaches the sink",
			app: aspApp("console", true, func(b *peb, x aspCtx) {
				controller("AController", tPublic, baseCB, "Index", mPublic, callsNothing)(b, x)
				controller("ZController", tPublic, baseCB, "Search", mPublic, callsBoom)(b, x)
			}),
			wantIngress: "Search",
		},
		{
			name:         "a dependency's controller in a program that does not host ASP.NET Core",
			app:          aspApp("console", false, func(*peb, aspCtx) {}),
			dep:          depWithController(),
			wantSearched: true,
		},
		{
			name:        "a dependency's controller in an ASP.NET Core program",
			app:         aspApp("hosted", false, func(*peb, aspCtx) {}),
			dep:         depWithController(),
			wantIngress: "Run",
		},
		{
			name: "ingress hazard blocks a clean Main",
			app: aspApp("console", true, controller("PackagesController", tPublic, baseCB, "Search", mPublic, func(x aspCtx) []byte {
				return body(ilCall(x.hazard))
			})),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dep := c.dep
			if dep == nil {
				dep = depWithBoomOverloads(false)
			}
			res := runReachSet(t, c.app, dep, boomSCIP)
			searched := slices.Contains(res.Searched, boomSCIP)
			if searched != c.wantSearched {
				t.Fatalf("searched = %v, want %v (paths=%d, partiality=%+v)", searched, c.wantSearched, len(res.Paths), res.Partiality)
			}
			if c.wantIngress == "" {
				if len(res.Paths) != 0 {
					t.Fatalf("paths = %+v, want none", res.Paths)
				}
			} else {
				if len(res.Paths) != 1 {
					t.Fatalf("paths = %d, want 1 (partiality=%+v)", len(res.Paths), res.Partiality)
				}
				tr := res.Paths[0].Trace
				if len(tr) < 2 || tr[0].Name != c.wantIngress || tr[len(tr)-1].Name != "boom" {
					t.Fatalf("trace = %+v, want %s .. boom", tr, c.wantIngress)
				}
			}
			if !c.wantSearched && !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
				t.Fatalf("unsearched sink without %s: %+v", plugin.PartialReasonReachabilityUndetermined, res.Partiality)
			}
		})
	}
}
