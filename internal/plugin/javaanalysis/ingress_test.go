package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func ingressFor(ings []plugin.Ingress, symbol string) (plugin.Ingress, bool) {
	for _, in := range ings {
		if in.Symbol == symbol {
			return in, true
		}
	}
	return plugin.Ingress{}, false
}

func TestFindIngresses_ServletDoGetDetected(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"web/FetchServlet.java": servletChain,
		"web/UrlFetcher.java":   utilFetcher,
	})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	doGet := methodSCIP("com.example.web", []string{"FetchServlet"}, "doGet", 2)
	in, ok := ingressFor(res.Ingresses, doGet)
	if !ok {
		t.Fatalf("servlet doGet not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "servlet" {
		t.Errorf("servlet ingress kind = %q, want servlet", in.Kind)
	}
}

func TestFindIngresses_NonServletDoGetNotIngress(t *testing.T) {
	// A doGet on a class that does NOT extend HttpServlet is not a servlet ingress.
	src := `
package p;
public class NotAServlet {
    public void doGet(Object req, Object resp) {}
}
`
	dir := writeProgram(t, map[string]string{"NotAServlet.java": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("non-servlet doGet must not be an ingress; got %+v", res.Ingresses)
	}
}

func TestFindIngresses_AnnotationRoutesDetected(t *testing.T) {
	src := `
package com.example.api;
public class Controller {
    @GetMapping("/users")
    public String list() { return ""; }

    @PostMapping
    public String create(String body) { return ""; }

    @RequestMapping("/all")
    public String all() { return ""; }

    public String notAnIngress() { return ""; }
}
`
	dir := writeProgram(t, map[string]string{"Controller.java": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	for _, want := range []struct {
		name  string
		arity int
	}{{"list", 0}, {"create", 1}, {"all", 0}} {
		sym := methodSCIP("com.example.api", []string{"Controller"}, want.name, want.arity)
		in, ok := ingressFor(res.Ingresses, sym)
		if !ok {
			t.Errorf("annotated method %s not found as ingress; got %+v", want.name, res.Ingresses)
			continue
		}
		if in.Kind != "http_route" {
			t.Errorf("%s ingress kind = %q, want http_route", want.name, in.Kind)
		}
	}
	// The un-annotated method must NOT be an ingress.
	plain := methodSCIP("com.example.api", []string{"Controller"}, "notAnIngress", 0)
	if _, ok := ingressFor(res.Ingresses, plain); ok {
		t.Errorf("un-annotated method was reported as an ingress")
	}
}

func TestFindIngresses_JaxRsPathAndVerbs(t *testing.T) {
	src := `
package com.example.jaxrs;
@Path("/res")
public class Resource {
    @GET
    public String read() { return ""; }
    @POST
    public String write(String b) { return ""; }
}
`
	dir := writeProgram(t, map[string]string{"Resource.java": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	read := methodSCIP("com.example.jaxrs", []string{"Resource"}, "read", 0)
	write := methodSCIP("com.example.jaxrs", []string{"Resource"}, "write", 1)
	if _, ok := ingressFor(res.Ingresses, read); !ok {
		t.Errorf("@GET method read not found; got %+v", res.Ingresses)
	}
	if _, ok := ingressFor(res.Ingresses, write); !ok {
		t.Errorf("@POST method write not found; got %+v", res.Ingresses)
	}
}

func TestResolveDependencySymbols_ResolvesJavaSinkForms(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"web/FetchServlet.java": servletChain,
		"web/UrlFetcher.java":   utilFetcher,
	})
	want := methodSCIP("com.example.web", []string{"UrlFetcher"}, "fetch", 1)
	// Each advisory form must resolve to the same UrlFetcher.fetch SCIP.
	for _, sym := range []string{
		"com.example.web.UrlFetcher.fetch",
		"UrlFetcher.fetch",
		"fetch",
		"UrlFetcher.fetch(1)",
	} {
		res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
			BuildDir:        dir,
			AdvisorySymbols: []string{sym},
		})
		if err != nil {
			t.Fatalf("ResolveDependencySymbols(%q): %v", sym, err)
		}
		found := false
		for _, r := range res.Resolved {
			if r.SCIP == want {
				found = true
			}
		}
		if !found {
			t.Errorf("advisory form %q did not resolve to UrlFetcher.fetch; resolved=%+v", sym, res.Resolved)
		}
	}
}
