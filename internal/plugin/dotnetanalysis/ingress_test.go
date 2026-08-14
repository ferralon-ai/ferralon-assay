package dotnetanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func ingressFor(ings []plugin.Ingress, symbol string) (plugin.Ingress, bool) {
	for _, in := range ings {
		if in.Symbol.SCIP == symbol {
			return in, true
		}
	}
	return plugin.Ingress{}, false
}

// A controller action carrying an [HttpGet] attribute is an ingress whose handler is the
// method itself (its SCIP id is known at the declaration site).
func TestFindIngresses_ControllerHttpGetDetected(t *testing.T) {
	dir := writeTree(t, map[string]string{"FetchController.cs": controllerApp})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	handle := funcSCIP("Acme.Web", []string{"FetchController"}, "Handle", 1)
	in, ok := ingressFor(res.Ingresses, handle)
	if !ok {
		t.Fatalf("[HttpGet] controller action Handle not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "http_route" {
		t.Errorf("controller ingress kind = %q, want http_route", in.Kind)
	}
	if in.Selector != "HttpGet" {
		t.Errorf("controller ingress selector = %q, want HttpGet", in.Selector)
	}
	// A cleanly-parsed source declares ingress discovery Complete (distinct from the
	// always-Partial call graph).
	if !res.Partiality.Complete {
		t.Errorf("clean parse must declare ingress discovery Complete; got %+v", res.Partiality)
	}
}

// A minimal-API app.MapGet("/x", Handler) registration whose handler is a named method group
// is an ingress; the handler REFERENCE re-resolves to its declared method by name. The
// handlers here are methods of the Startup class the registrations live in (referenced by
// bare name), the form the lexical scanner can soundly re-resolve.
func TestFindIngresses_MinimalAPIMapGetDetected(t *testing.T) {
	src := `
namespace Acme.Web
{
    public class Startup
    {
        public void Configure(WebApplication app)
        {
            app.MapGet("/users", GetUsers);
            app.MapPost("/users", CreateUser);
            app.MapGet("/inline", () => "anonymous");
        }

        private string GetUsers()
        {
            return Load();
        }

        private string CreateUser(string payload)
        {
            return payload;
        }

        private string Load()
        {
            return "";
        }
    }
}
`
	dir := writeTree(t, map[string]string{"Startup.cs": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	getUsers := funcSCIP("Acme.Web", []string{"Startup"}, "GetUsers", 0)
	in, ok := ingressFor(res.Ingresses, getUsers)
	if !ok {
		t.Fatalf("minimal-API MapGet handler GetUsers not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "http_route" || in.Selector != "MapGet" {
		t.Errorf("minimal-API ingress kind/selector = %q/%q, want http_route/MapGet", in.Kind, in.Selector)
	}
	createUser := funcSCIP("Acme.Web", []string{"Startup"}, "CreateUser", 1)
	if _, ok := ingressFor(res.Ingresses, createUser); !ok {
		t.Errorf("minimal-API MapPost handler CreateUser not found as ingress; got %+v", res.Ingresses)
	}
}

// An inline-lambda minimal-API handler names no method group, so it records NO ingress
// (honest absence, never a fabricated node).
func TestFindIngresses_MinimalAPIAnonymousHandlerIsNotIngress(t *testing.T) {
	src := `
namespace Acme.Web
{
    public class Startup
    {
        public void Configure(WebApplication app)
        {
            app.MapGet("/inline", () => "anonymous");
            app.MapPost("/inline2", (string body) => body);
        }
    }
}
`
	dir := writeTree(t, map[string]string{"Startup.cs": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("anonymous-lambda minimal-API handlers must not be ingresses; got %+v", res.Ingresses)
	}
}

// A [Route]-only action is still an ingress; a method with no HTTP attribute is not.
func TestFindIngresses_RouteAttributeAndNonAction(t *testing.T) {
	src := `
namespace Acme.Web
{
    public class HomeController
    {
        [Route("home/index")]
        public string Index() { return ""; }

        public string Helper() { return ""; }
    }
}
`
	dir := writeTree(t, map[string]string{"HomeController.cs": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	index := funcSCIP("Acme.Web", []string{"HomeController"}, "Index", 0)
	if _, ok := ingressFor(res.Ingresses, index); !ok {
		t.Errorf("[Route] action Index not found as ingress; got %+v", res.Ingresses)
	}
	helper := funcSCIP("Acme.Web", []string{"HomeController"}, "Helper", 0)
	if _, ok := ingressFor(res.Ingresses, helper); ok {
		t.Errorf("a non-attributed method must not be an ingress: %s", helper)
	}
}

func TestFindIngresses_MissingBuildDirIsHardError(t *testing.T) {
	_, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}
