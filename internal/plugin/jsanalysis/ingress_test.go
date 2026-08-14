package jsanalysis

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

func TestFindIngresses_ExpressRouteDetected(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"app.js":     expressApp,
		"fetcher.js": fetcherModule,
	})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handleFetch", 2)
	in, ok := ingressFor(res.Ingresses, handleFetch)
	if !ok {
		t.Fatalf("express route handler handleFetch not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "http_route" {
		t.Errorf("express route ingress kind = %q, want http_route", in.Kind)
	}
}

func TestFindIngresses_InlineArrowHandlerIsNotIngress(t *testing.T) {
	// An anonymous inline-arrow handler is NOT a named call-graph node, so it must not
	// be recorded as an ingress (honest absence, never a fabricated entry).
	src := `
const express = require('express');
const app = express();
app.get('/x', (req, res) => { res.send('ok'); });
`
	dir := writeProgram(t, map[string]string{"app.js": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("inline-arrow handler must not be an ingress; got %+v", res.Ingresses)
	}
}

func TestFindIngresses_KoaRouterDetected(t *testing.T) {
	src := `
const Router = require('koa-router');
const router = new Router();

function listUsers(ctx) {
    ctx.body = read();
}

function read() { return ''; }

router.get('/users', listUsers);
`
	dir := writeProgram(t, map[string]string{"routes.js": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	listUsers := funcSCIP("routes", nil, "listUsers", 1)
	in, ok := ingressFor(res.Ingresses, listUsers)
	if !ok {
		t.Fatalf("koa router handler listUsers not found; got %+v", res.Ingresses)
	}
	if in.Kind != "http_route" {
		t.Errorf("koa route ingress kind = %q, want http_route", in.Kind)
	}
}

func TestFindIngresses_NodeHttpServerDetected(t *testing.T) {
	src := `
const http = require('http');

function requestHandler(req, res) {
    route(req.url);
    res.end();
}

function route(url) { return url; }

const server = http.createServer(requestHandler);
server.listen(8080);
`
	dir := writeProgram(t, map[string]string{"server.js": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	handler := funcSCIP("server", nil, "requestHandler", 2)
	in, ok := ingressFor(res.Ingresses, handler)
	if !ok {
		t.Fatalf("http.createServer handler not found; got %+v", res.Ingresses)
	}
	if in.Kind != "http_server" {
		t.Errorf("http server ingress kind = %q, want http_server", in.Kind)
	}
}

func TestFindIngresses_NextDefaultExportHandler(t *testing.T) {
	// Next.js API route: a default-export request handler (req,res).
	src := `
export default function handler(req, res) {
    const r = doWork(req.query.id);
    res.status(200).json(r);
}

function doWork(id) { return id; }
`
	dir := writeProgram(t, map[string]string{"api/route.ts": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	handler := funcSCIP("api/route", nil, "handler", 2)
	in, ok := ingressFor(res.Ingresses, handler)
	if !ok {
		t.Fatalf("next.js default-export handler not found; got %+v", res.Ingresses)
	}
	if in.Kind != "handler" {
		t.Errorf("next handler ingress kind = %q, want handler", in.Kind)
	}
}

func TestResolveDependencySymbols_ResolvesJSSinkForms(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"app.js":     expressApp,
		"fetcher.js": fetcherModule,
	})
	want := funcSCIP("fetcher", nil, "fetchUrl", 1)
	// Each advisory form must resolve to the same fetcher.fetchUrl SCIP.
	for _, sym := range []string{
		"fetcher.fetchUrl",
		"fetchUrl",
		"fetchUrl(1)",
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
			t.Errorf("advisory form %q did not resolve to fetcher.fetchUrl; resolved=%+v", sym, res.Resolved)
		}
	}
}

// TestFindIngresses_TSClassMethodChain confirms the scanner handles a TypeScript
// class with a method that calls a sink (a different declaration shape than the
// module-function chain), and that a default-export handler reaching the method is
// an ingress.
func TestFindIngresses_TSClassMethodChain(t *testing.T) {
	src := `
class Fetcher {
    fetch(target: string): number {
        return this.open(target);
    }
    open(url: string): number {
        return 0;
    }
}

const svc = new Fetcher();

export default function handler(req, res) {
    svc.fetch(req.query.target);
    res.end();
}
`
	dir := writeProgram(t, map[string]string{"svc.ts": src})
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handler := funcSCIP("svc", nil, "handler", 2)
	fetch := funcSCIP("svc", []string{"Fetcher"}, "fetch", 1)
	open := funcSCIP("svc", []string{"Fetcher"}, "open", 1)
	if !hasEdge(cg.Edges, handler, fetch) {
		t.Errorf("expected handler -> Fetcher.fetch edge; edges=%+v", cg.Edges)
	}
	if !hasEdge(cg.Edges, fetch, open) {
		t.Errorf("expected Fetcher.fetch -> Fetcher.open edge; edges=%+v", cg.Edges)
	}
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if _, ok := ingressFor(res.Ingresses, handler); !ok {
		t.Errorf("default-export handler not found as ingress; got %+v", res.Ingresses)
	}
}
