package javaanalysis

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// rmethod is an emitted method with one optional runtime-visible annotation.
type rmethod struct {
	xmethod
	anno string // annotation type descriptor, "" for none
	path string // its "value" element, "" for none
}

const (
	springGet   = "Lorg/springframework/web/bind/annotation/GetMapping;"
	springPut   = "Lorg/springframework/web/bind/annotation/PutMapping;"
	springBase  = "Lorg/springframework/web/bind/annotation/RequestMapping;"
	accBridge   = 0x1041
	accIface    = 0x0601
	accAbstract = 0x0421
)

// emitClassR is emitClassA with method annotations and a class-level annotation path.
func emitClassR(b *cpb, owner, super string, ifaces []string, flags uint16, methods []rmethod, classAnno, classPath string) []byte {
	thisIdx := b.class(owner)
	superIdx := b.class(super)
	ifaceIdx := make([]uint16, len(ifaces))
	for i, n := range ifaces {
		ifaceIdx[i] = b.class(n)
	}
	codeAttr := b.utf8("Code")
	rvaName := b.utf8("RuntimeVisibleAnnotations")
	rva := func(typ, path string) []byte {
		var w bytes.Buffer
		w.Write(be2(1))
		w.Write(be2(b.utf8(typ)))
		if path == "" {
			w.Write(be2(0))
			return w.Bytes()
		}
		w.Write(be2(1))
		w.Write(be2(b.utf8("value")))
		w.WriteByte('s')
		w.Write(be2(b.utf8(path)))
		return w.Bytes()
	}
	type built struct {
		name, desc uint16
		anno       []byte
	}
	bm := make([]built, len(methods))
	for i, m := range methods {
		bm[i] = built{name: b.utf8(m.name), desc: b.utf8(m.desc)}
		if m.anno != "" {
			bm[i].anno = rva(m.anno, m.path)
		}
	}
	var classRVA []byte
	if classAnno != "" {
		classRVA = rva(classAnno, classPath)
	}
	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))
	buf.Write(be2(52))
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(flags))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(uint16(len(ifaceIdx))))
	for _, i := range ifaceIdx {
		buf.Write(be2(i))
	}
	buf.Write(be2(0))
	buf.Write(be2(uint16(len(methods))))
	for i, m := range methods {
		buf.Write(be2(m.flags))
		buf.Write(be2(bm[i].name))
		buf.Write(be2(bm[i].desc))
		n := 0
		if m.code != nil {
			n++
		}
		if bm[i].anno != nil {
			n++
		}
		buf.Write(be2(uint16(n)))
		if m.code != nil {
			var code bytes.Buffer
			code.Write(be2(8))
			code.Write(be2(8))
			code.Write(be4(uint32(len(m.code))))
			code.Write(m.code)
			code.Write(be2(0))
			code.Write(be2(0))
			buf.Write(be2(codeAttr))
			buf.Write(be4(uint32(code.Len())))
			buf.Write(code.Bytes())
		}
		if bm[i].anno != nil {
			buf.Write(be2(rvaName))
			buf.Write(be4(uint32(len(bm[i].anno))))
			buf.Write(bm[i].anno)
		}
	}
	if classRVA == nil {
		buf.Write(be2(0))
		return buf.Bytes()
	}
	buf.Write(be2(1))
	buf.Write(be2(rvaName))
	buf.Write(be4(uint32(len(classRVA))))
	buf.Write(classRVA)
	return buf.Bytes()
}

// routed writes a first-party class with annotated methods under target/classes.
func (a *appFixture) routed(owner, super string, ifaces []string, flags uint16, classAnno, classPath string, methods func(b *cpb) []rmethod) {
	a.t.Helper()
	a.routedIn("target/classes", owner, super, ifaces, flags, classAnno, classPath, methods)
}

// routedIn is routed under a chosen class output directory.
func (a *appFixture) routedIn(outDir, owner, super string, ifaces []string, flags uint16, classAnno, classPath string, methods func(b *cpb) []rmethod) {
	a.t.Helper()
	b := &cpb{}
	data := emitClassR(b, owner, super, ifaces, flags, methods(b), classAnno, classPath)
	p := filepath.Join(a.build, filepath.FromSlash(outDir), filepath.FromSlash(owner)+".class")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		a.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		a.t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		a.t.Fatal(err)
	}
}

// route is a no-argument instance method with an optional mapping, running code.
func route(name, anno, path string, code func(*cpb) []byte, flags uint16) func(b *cpb) rmethod {
	return func(b *cpb) rmethod {
		m := rmethod{xmethod: xmethod{name, "()V", flags, nil}, anno: anno, path: path}
		if code != nil {
			m.code = code(b)
		}
		return m
	}
}

func methodsOf(fs ...func(b *cpb) rmethod) func(b *cpb) []rmethod {
	return func(b *cpb) []rmethod {
		out := make([]rmethod, len(fs))
		for i, f := range fs {
			out[i] = f(b)
		}
		return out
	}
}

const objectClass = "java/lang/Object"

// A handler that carries no mapping of its own, whose route an interface or superclass
// declares, is rooted: Spring and JAX-RS read the overridden method's annotations.
func TestBytecodeReach_InheritedRoutes(t *testing.T) {
	apiGet := methodsOf(route("list", springGet, "/pets", nil, accPublicAbstract))
	impl := methodsOf(route("list", "", "", callFetch, accPublic))
	tests := []struct {
		name  string
		build func(a *appFixture)
		want  string // the ingress SCIP the one path starts at, "" for none
	}{
		{"own method", func(a *appFixture) {
			a.routed("com/acme/Ctl", objectClass, nil, 0x0021, "", "", methodsOf(route("list", springGet, "/pets", callFetch, accPublic)))
		}, methodSCIP("com.acme", []string{"Ctl"}, "list", 0)},
		{"interface inherited", func(a *appFixture) {
			a.routed("com/acme/Api", objectClass, nil, accIface, "", "", apiGet)
			a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", impl)
		}, methodSCIP("com.acme", []string{"Impl"}, "list", 0)},
		{"abstract superclass inherited", func(a *appFixture) {
			a.routed("com/acme/Base", objectClass, nil, accAbstract, "", "", apiGet)
			a.routed("com/acme/Impl", "com/acme/Base", nil, 0x0021, "", "", impl)
		}, methodSCIP("com.acme", []string{"Impl"}, "list", 0)},
		{"transitive interface", func(a *appFixture) {
			a.routed("com/acme/Root", objectClass, nil, accIface, "", "", apiGet)
			a.routed("com/acme/Mid", objectClass, []string{"com/acme/Root"}, accIface, "", "", methodsOf())
			a.routed("com/acme/Base", objectClass, []string{"com/acme/Mid"}, accAbstract, "", "", methodsOf())
			a.routed("com/acme/Impl", "com/acme/Base", nil, 0x0021, "", "", impl)
		}, methodSCIP("com.acme", []string{"Impl"}, "list", 0)},
		{"interface default not overridden", func(a *appFixture) {
			a.routed("com/acme/Api", objectClass, nil, accIface, "", "", methodsOf(route("list", springGet, "/pets", callFetch, accPublic)))
			a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", methodsOf())
		}, methodSCIP("com.acme", []string{"Api"}, "list", 0)},
		{"generic interface with bridge", func(a *appFixture) {
			a.routed("com/acme/Api", objectClass, nil, accIface, "", "", methodsOf(func(*cpb) rmethod {
				return rmethod{xmethod: xmethod{"put", "(Ljava/lang/Object;)V", accPublicAbstract, nil}, anno: springPut, path: "/pets"}
			}))
			a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", methodsOf(
				func(b *cpb) rmethod {
					return rmethod{xmethod: xmethod{"put", "(Lcom/acme/Pet;)V", accPublic, callFetch(b)}}
				},
				func(b *cpb) rmethod { return rmethod{xmethod: xmethod{"put", "(Ljava/lang/Object;)V", accBridge, ret}} },
			))
		}, methodSCIP("com.acme", []string{"Impl"}, "put", 1)},
		{"class-level base path", func(a *appFixture) {
			a.routed("com/acme/Api", objectClass, nil, accIface, springBase, "/v1", apiGet)
			a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", impl)
		}, methodSCIP("com.acme", []string{"Impl"}, "list", 0)},
		{"delegate pattern generated controller", func(a *appFixture) {
			a.routed("com/acme/gen/PetsApi", objectClass, nil, 0x0021, springBase, "/api", methodsOf(route("list", springGet, "/pets", callFetch, accPublic)))
		}, methodSCIP("com.acme.gen", []string{"PetsApi"}, "list", 0)},
		{"non-entry annotation not rooted", func(a *appFixture) {
			a.routed("com/acme/Api", objectClass, nil, accIface, "", "", methodsOf(route("list", "Lorg/springframework/beans/factory/annotation/Autowired;", "", nil, accPublicAbstract)))
			a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", impl)
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			tt.build(a)
			res := a.reach(netkitSinkID)
			if tt.want == "" {
				if len(res.Paths) != 0 {
					t.Fatalf("want no path, got %+v", res.Paths)
				}
				return
			}
			if len(res.Paths) != 1 {
				t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
			}
			if got := res.Paths[0].Ingress.SCIP; got != tt.want {
				t.Errorf("ingress = %q, want %q", got, tt.want)
			}
		})
	}
}

// A first-party class whose supertype is not loaded may inherit a route the search cannot
// see: Searched is withheld under a named reason.
func TestBytecodeReach_UnloadedSupertypeFailsClosed(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.routed("com/acme/Impl", objectClass, []string{"com/gen/Api"}, 0x0021, "", "", methodsOf(route("list", "", "", justReturn, accPublic)))

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("Searched despite an unloaded supertype: %v", res.Searched)
	}
	if !hasReason(res.Partiality, reasonInheritedRoute) {
		t.Errorf("missing %s: %+v", reasonInheritedRoute, res.Partiality)
	}
}

// The same class set with its supertype loaded and no route anywhere is searched clean.
func TestBytecodeReach_LoadedSupertypeStaysSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.routed("com/acme/Api", objectClass, nil, accIface, "", "", methodsOf(route("list", "", "", nil, accPublicAbstract)))
	a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", methodsOf(route("list", "", "", justReturn, accPublic)))

	res := a.reach(netkitSinkID)
	if hasReason(res.Partiality, reasonInheritedRoute) {
		t.Errorf("loaded supertype raised %s: %+v", reasonInheritedRoute, res.Partiality)
	}
}

// The ingress listing names the inherited entry points, on the ungated track.
func TestFindIngresses_ListsInheritedRoutes(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.routed("com/acme/Api", objectClass, nil, accIface, springBase, "/v1", methodsOf(route("list", springGet, "/pets", nil, accPublicAbstract)))
	a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", methodsOf(route("list", "", "", justReturn, accPublic)))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: a.build})
	if err != nil {
		t.Fatal(err)
	}
	want := methodSCIP("com.acme", []string{"Impl"}, "list", 0)
	for _, in := range res.Ingresses {
		if in.Symbol.SCIP == want {
			if in.Kind != "http_route" || in.Selector != "GET /v1/pets" {
				t.Errorf("ingress = %+v", in)
			}
			return
		}
	}
	t.Errorf("no ingress %q in %+v", want, res.Ingresses)
}

// fakeAnalyzer is a docker stand-in that answers the analyzer's run with the recorded
// scip-java index, so a Prove-gated run completes without a container runtime.
func fakeAnalyzer(t *testing.T) []Option {
	t.Helper()
	index, err := filepath.Abs(springIndexFixture)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "docker")
	body := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in *:/work) cp '" + index + "' \"${a%:/work}/index.scip\" ;; esac; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return []Option{WithAnalyzerImage("assay-java-analyzer@sha256:deadbeef"), WithAnalyzerDocker(script)}
}

// The Prove-gated track merges the container-resolved ingresses into the lexical listing;
// the inherited entries are in that listing, and the bytecode search roots them with the
// gate open as it does with it closed.
func TestInheritedRoutes_SCIPGatedTrack(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.routed("com/acme/Api", objectClass, nil, accIface, "", "", methodsOf(route("list", springGet, "/pets", nil, accPublicAbstract)))
	a.routed("com/acme/Impl", objectClass, []string{"com/acme/Api"}, 0x0021, "", "", methodsOf(route("list", "", "", callFetch, accPublic)))
	gate := fakeAnalyzer(t)
	want := methodSCIP("com.acme", []string{"Impl"}, "list", 0)

	ing, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: a.build}, gate...)
	if err != nil {
		t.Fatal(err)
	}
	if hasReason(ing.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("the gated run did not complete: %+v", ing.Partiality)
	}
	listed, resolved := false, false
	for _, in := range ing.Ingresses {
		listed = listed || in.Symbol.SCIP == want
		resolved = resolved || in.Kind == "http_route" && in.Symbol.SCIP != want
	}
	if !listed {
		t.Errorf("gated listing lacks %q: %+v", want, ing.Ingresses)
	}
	if !resolved {
		t.Errorf("gated listing holds no container-resolved ingress, so the gate did not merge: %+v", ing.Ingresses)
	}

	graph := graphOption(t, a.tool, testModule(t, ".", "app", a.deps...))
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: a.build, Symbols: []string{netkitSinkID}}, append([]Option{graph}, gate...)...)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 1 || res.Paths[0].Ingress.SCIP != want {
		t.Fatalf("gated search: want one path from %q, got %+v (partiality %+v)", want, res.Paths, res.Partiality)
	}
}

// A reactor unit roots a route its own handler inherits from an interface in a sibling module:
// each unit's search runs over the unit's classes with its siblings'.
func TestInheritedRoutes_ReactorUnit(t *testing.T) {
	a := newApp(t, "", false)
	a.reactorRoot()
	a.appModule("one", "one", justReturn)
	a.appModule("two", "two", justReturn)
	a.libModule("lib", justReturn)
	a.routedIn("lib/target/classes", "com/acme/lib/Api", objectClass, nil, accIface, "", "",
		methodsOf(route("list", springGet, "/pets", nil, accPublicAbstract)))
	a.routedIn("one/target/classes", "com/acme/one/Impl", objectClass, []string{"com/acme/lib/Api"}, 0x0021, "", "",
		methodsOf(route("list", "", "", callFetch, accPublic)))

	lib := testModule(t, "lib", "lib", netkitDep(a.build))
	one := sibling(testModule(t, "one", "one", netkitDep(a.build)), lib, "compile")
	two := sibling(testModule(t, "two", "two"), lib, "compile")
	a.graph = listedGraph(t, testModule(t, ".", "parent"), one, two, lib)

	res := a.reach(netkitSinkID)
	want := methodSCIP("com.acme.one", []string{"Impl"}, "list", 0)
	if len(res.Paths) != 1 || res.Paths[0].Ingress.SCIP != want {
		t.Fatalf("want one path from %q, got %+v (partiality %+v)", want, res.Paths, res.Partiality)
	}
}

// A route declared on a concrete method of a dependency superclass, or on a default method of a
// dependency interface, that the first-party class does not override is the class's handler.
// The class file names no such method, so the search roots it on the dependency's method, and
// the listing, which resolves supertypes through the same closure, names it.
func TestInheritedRoutes_NotOverriddenFromDependency(t *testing.T) {
	tests := []struct {
		name  string
		libFl uint16 // the dependency type's access flags
		super string // the first-party class's superclass
		ifc   []string
	}{
		{"superclass concrete method", 0x0021, "com/lib/Base", nil},
		{"interface default method", accIface, objectClass, []string{"com/lib/Base"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			b := &cpb{}
			lib := emitClassR(b, "com/lib/Base", objectClass, nil, tt.libFl,
				methodsOf(route("list", springGet, "/pets", callFetch, accPublic))(b), "", "")
			jar := filepath.Join(a.build, ".m2", "repository", "com", "lib", "routes", "1.0.0", "routes-1.0.0.jar")
			writeJar(t, jar, "com/lib/Base.class", lib)
			writeFileT(t, filepath.Join(a.build, ".m2", "repository", "com", "lib", "routes", "1.0.0", "routes-1.0.0.pom"),
				`<project><modelVersion>4.0.0</modelVersion><groupId>com.lib</groupId><artifactId>routes</artifactId><version>1.0.0</version></project>`)
			a.dep(graphDep{group: "com.lib", artifact: "routes", version: "1.0.0", jar: jar})
			a.routed("com/acme/Impl", tt.super, tt.ifc, 0x0021, "", "", methodsOf())

			want := methodSCIP("com.lib", []string{"Base"}, "list", 0)
			res := a.reach(netkitSinkID)
			if len(res.Paths) != 1 || res.Paths[0].Ingress.SCIP != want {
				t.Fatalf("want one path from %q, got %+v (partiality %+v)", want, res.Paths, res.Partiality)
			}

			graph := graphOption(t, a.tool, testModule(t, ".", "app", a.deps...))
			ing, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: a.build}, graph)
			if err != nil {
				t.Fatal(err)
			}
			for _, in := range ing.Ingresses {
				if in.Symbol.SCIP == want {
					if in.Selector != "GET /pets" {
						t.Errorf("selector = %q, want GET /pets", in.Selector)
					}
					return
				}
			}
			t.Errorf("listing lacks %q: %+v", want, ing.Ingresses)
		})
	}
}
