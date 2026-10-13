package jsanalysis

import "strings"

// receiverModel types the parameters of request handlers registered on a framework's router
// values, so a method call on a typed parameter (res.redirect) is an edge into the
// framework's package (npm:express#response.redirect). One row per framework.
type receiverModel struct {
	pkg string
	// routers are the boundary member chains of values whose route methods (routeMethods)
	// register handlers.
	routers []string
	// params are the handler parameter types by position; errorParams replace them for an
	// error handler, which the framework recognizes by errorArity.
	params      []string
	errorParams []string
	errorArity  int
	// aliases maps an advisory-symbol spelling of a parameter type to its canonical name.
	aliases map[string]string
}

var receiverModels = []receiverModel{
	{
		// express() returns an application; express.Router() (or new Router()) a router. Both
		// call a handler as (req, res, next), or as (err, req, res, next) when the handler
		// declares four parameters (Express checks fn.length). req and res are express.request /
		// express.response, the objects lib/request.js and lib/response.js export.
		pkg:         "express",
		routers:     []string{callBoundary, "Router." + callBoundary, "Router"},
		params:      []string{"request", "response"},
		errorParams: []string{"", "request", "response"},
		errorArity:  4,
		aliases:     map[string]string{"req": "request", "res": "response"},
	},
}

// paramType is the boundary member naming the type of a handler's parameter idx, or "" when
// the model does not type it (next, err, or a position past the typed ones).
func (m *receiverModel) paramType(arity, idx int) string {
	params := m.params
	if arity == m.errorArity {
		params = m.errorParams
	}
	if idx < 0 || idx >= len(params) {
		return ""
	}
	return params[idx]
}

// modelFor returns the receiver model for an npm package name, or nil.
func modelFor(pkg string) *receiverModel {
	for i := range receiverModels {
		if receiverModels[i].pkg == pkg {
			return &receiverModels[i]
		}
	}
	return nil
}

// routerModel returns the model whose router values include ref, or nil. A router imported
// through a subpath ("express/lib/router") is not one of the modelled values.
func routerModel(ref boundaryRef) *receiverModel {
	m := modelFor(ref.spec)
	if m == nil {
		return nil
	}
	chain := strings.Join(ref.members, ".")
	for _, r := range m.routers {
		if r == chain {
			return m
		}
	}
	return nil
}
