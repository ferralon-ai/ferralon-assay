package pythonanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the Python module at
// req.BuildDir: Flask (@app.route) and FastAPI/Starlette (@app.get/@router.post/
// @app.websocket/…) route handlers. Each ingress symbol is the HANDLER def's SCIP id —
// the SAME id the call graph and symbol resolver emit for that function — so the
// pipeline's firstPartyReachPaths BFS can connect an ingress to a reachable sink. A
// missing build dir is a hard error (inv.4).
//
// Unlike JS route handlers (which name a handler by REFERENCE in a registration call),
// Python route decorators sit directly above the def, so the handler def — and thus its
// exact SCIP id — is known at the decorator site; no reference re-resolution is needed.
//
// FOLLOW-ON (not wired for M1): Django URLconf (urlpatterns / path() / re_path()
// registration tables), Celery @task workers, and raw WSGI/ASGI application callables.
// These are registration-table / callable shapes rather than def decorators and need a
// distinct scanner. They are named in the Python skill's ingress list.
func FindIngresses(_ context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	seen := map[string]bool{}
	var ingresses []plugin.Ingress
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			scip := funcSCIP(f.module, in.enclosing, in.name, in.arity)
			key := in.kind + "\x00" + scip + "\x00" + in.selector
			if seen[key] {
				continue
			}
			seen[key] = true
			ingresses = append(ingresses, plugin.Ingress{
				Kind:     in.kind,
				Symbol:   sym(scip),
				Selector: in.selector,
			})
		}
	}

	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Kind != ingresses[j].Kind {
			return ingresses[i].Kind < ingresses[j].Kind
		}
		if ingresses[i].Symbol.SCIP != ingresses[j].Symbol.SCIP {
			return ingresses[i].Symbol.SCIP < ingresses[j].Symbol.SCIP
		}
		return ingresses[i].Selector < ingresses[j].Selector
	})

	return plugin.IngressResult{Partiality: ingressPartiality(prog), Ingresses: ingresses}, nil
}

// ingressPartiality declares completeness of ingress discovery. Unlike the call graph
// (always partial), ingress discovery over a cleanly parsed source IS complete for the
// decorator idioms the scanner models: the ingresses found are exactly the Flask/FastAPI
// route handlers present. A read failure or a skipped construct degrades to partial with
// the matching machine-readable reason.
func ingressPartiality(prog *program) plugin.Partiality {
	var reasons []string
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}
