package dotnetanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses identifies framework-idiomatic entry points in the C# module at
// req.BuildDir: ASP.NET Core controller actions carrying an HTTP action attribute
// ([HttpGet]/[HttpPost]/[HttpPut]/[HttpDelete]/[HttpPatch]/[HttpHead]/[HttpOptions]/[Route])
// and minimal-API endpoint registrations (app.MapGet/MapPost/… "/x", Handler) whose handler
// argument is a named method group. Each ingress symbol is the HANDLER method's SCIP id —
// the SAME id the call graph and symbol resolver emit for that method — so the pipeline's
// firstPartyReachPaths BFS can connect an ingress to a reachable sink. A controller action's
// handler id is known at the declaration site; a minimal-API handler REFERENCE is re-resolved
// against the program's declared methods by name (resolving iff exactly one method declares
// the name). An anonymous (inline-lambda) minimal-API handler records no ingress (honest
// absence, never a fabricated entry). A missing build dir is a hard error (inv.4).
//
// MVP scope is the ASP.NET Core controller + minimal-API family — the dominant modern .NET
// web surface. Blazor component routes (@page), gRPC service methods, and SignalR hubs are
// distinct registration shapes recognized as FOLLOW-ON (named in the .NET skill's ingress
// list); they need a distinct scanner and are not wired here.
func FindIngresses(_ context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	seen := map[string]bool{}
	var ingresses []plugin.Ingress
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			symID := prog.resolveIngressSymbol(in)
			if symID == "" {
				continue
			}
			key := in.kind + "\x00" + symID + "\x00" + in.selector
			if seen[key] {
				continue
			}
			seen[key] = true
			ingresses = append(ingresses, plugin.Ingress{
				Kind:     in.kind,
				Symbol:   sym(symID),
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
// idioms the scanner models: the ingresses found are exactly the ASP.NET controller actions
// and minimal-API registrations present. A read failure or a skipped construct degrades to
// partial with the matching machine-readable reason. find_ingresses is the one op that can
// be Complete (it reports what it found).
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
