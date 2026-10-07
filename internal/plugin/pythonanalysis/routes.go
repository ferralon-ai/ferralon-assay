package pythonanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// RouteHandler is one decorator-registered route handler found by FindIngresses' scan, named
// in Python's own dotted qualified-name syntax (module import path, every enclosing class and
// function, def name: "pkg.views.Api.get", "pkg.app.create_app.serve") rather than this
// package's SCIP id. It exists so an analyzer
// with a different symbol space can resolve the same handler with its own resolver instead
// of parsing a SCIP string.
type RouteHandler struct {
	Kind          string // "http_route"
	Selector      string // the decorator's call leaf ("route", "get", ...), as Ingress.Selector
	QualifiedName string
}

// RouteHandlers returns the route handlers FindIngresses reports, deduplicated and sorted by
// (Kind, QualifiedName, Selector), with the same partiality. A missing build dir is a hard
// error (inv.4).
func RouteHandlers(_ context.Context, buildDir string) ([]RouteHandler, plugin.Partiality, error) {
	prog, err := loadProgram(buildDir)
	if err != nil {
		return nil, plugin.Partiality{}, err
	}

	seen := map[RouteHandler]bool{}
	var out []RouteHandler
	for _, f := range prog.files {
		for _, in := range f.ingresses {
			h := RouteHandler{Kind: in.kind, Selector: in.selector, QualifiedName: dottedName(f.module, in.scope, in.name)}
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].QualifiedName != out[j].QualifiedName {
			return out[i].QualifiedName < out[j].QualifiedName
		}
		return out[i].Selector < out[j].Selector
	})
	return out, ingressPartiality(prog), nil
}

// dottedName joins a '/'-separated module path, its enclosing scope chain and a name into the
// dotted form Python imports use — the same conversion pySymbolForms applies to Package.
func dottedName(module string, enclosing []string, name string) string {
	parts := make([]string, 0, len(enclosing)+2)
	if module != "" {
		parts = append(parts, strings.ReplaceAll(module, "/", "."))
	}
	parts = append(parts, enclosing...)
	parts = append(parts, name)
	return strings.Join(parts, ".")
}
