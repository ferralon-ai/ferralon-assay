package pythonanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the Python module at
// req.BuildDir: Flask (@app.route) and FastAPI/Starlette (@app.get/@router.post/
// @app.websocket/…) route handlers, Celery task functions (@app.task, @shared_task), WSGI
// and ASGI application callables, Django URL-pattern views and application settings, and
// the console and GUI scripts a manifest declares (launchers.go). Each ingress symbol is
// the HANDLER def's SCIP id — the SAME id the call graph and symbol resolver emit for that
// function — so the pipeline's firstPartyReachPaths BFS can connect an ingress to a
// reachable sink. A missing build dir is a hard error (inv.4).
//
// A decorated handler is known at its def. A launcher names its function by dotted path,
// resolved against the build's modules; one that names a dependency's function is no
// first-party ingress.
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

	for _, t := range prog.launchTargets() {
		if t.kind == "" {
			continue
		}
		decls, _, _, _ := prog.launchDecls(t)
		for _, fd := range decls {
			scip := fd.scip()
			key := t.kind + "\x00" + scip + "\x00" + t.selector
			if seen[key] {
				continue
			}
			seen[key] = true
			ingresses = append(ingresses, plugin.Ingress{Kind: t.kind, Symbol: sym(scip), Selector: t.selector})
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
// idioms the scanner models. A read failure or a skipped construct degrades to partial with
// the matching machine-readable reason, as does a launcher whose first-party module
// declares no function by the name it gives (an instance, a class, an attribute set at run
// time): its entry point is there but not as a function the lane can name.
func ingressPartiality(prog *program) plugin.Partiality {
	var reasons []string
	if prog.readFailed || prog.launchersUnread {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped || prog.launchersUnsupported || prog.launcherUnresolved() {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}

// launcherUnresolved reports whether a launcher that must name a first-party function
// names none.
func (prog *program) launcherUnresolved() bool {
	for _, t := range prog.launchTargets() {
		if prog.unresolved(t) {
			return true
		}
	}
	return false
}
