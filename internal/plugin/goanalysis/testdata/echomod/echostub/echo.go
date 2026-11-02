// Package echo is a minimal local stand-in for github.com/labstack/echo/v4, just
// enough for the ingress detector to recognize the route-registrar shapes
// hermetically (no network fetch of the real module). The package PATH is what the
// detector matches (github.com/labstack/echo/v4), supplied via a go.mod module
// directive + a replace in the fixture. The shapes mirror the real echo ones: the
// registrars are declared on both *Echo and *Group and take (path, HandlerFunc,
// ...MiddlewareFunc), Add and Match take the method(s) first, Group returns a *Group,
// a handler is func(Context) error where Context is an INTERFACE, and
// WrapHandler/WrapMiddleware adapt net/http handlers and middleware.
package echo

import http "tegron.test/nethttp"

// Context is echo's request context: an interface, so its accessors are invoke calls.
type Context interface {
	Request() *http.Request
	Param(name string) string
	QueryParam(name string) string
	QueryParams() http.Values
	FormValue(name string) string
	FormParams() (http.Values, error)
	Cookie(name string) (*http.Cookie, error)
	Bind(i interface{}) error
	// Path is the registered route path: no request data.
	Path() string
	String(code int, s string) error
}

// HandlerFunc is an echo handler.
type HandlerFunc func(c Context) error

// MiddlewareFunc is echo middleware.
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

// Route is a registered route.
type Route struct{ Method, Path, Name string }

// Echo stands in for the echo router.
type Echo struct{}

// New returns an echo router.
func New() *Echo { return &Echo{} }

// Pre attaches middleware run before routing.
func (e *Echo) Pre(middleware ...MiddlewareFunc) {}

// Use attaches middleware run after routing.
func (e *Echo) Use(middleware ...MiddlewareFunc) {}

func (e *Echo) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route { return nil }
func (e *Echo) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route  { return nil }
func (e *Echo) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route     { return nil }
func (e *Echo) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route    { return nil }
func (e *Echo) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route { return nil }
func (e *Echo) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route   { return nil }
func (e *Echo) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route    { return nil }
func (e *Echo) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route     { return nil }
func (e *Echo) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route   { return nil }

func (e *Echo) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	return nil
}

func (e *Echo) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	return nil
}

func (e *Echo) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return nil
}

// Group returns a route group under prefix.
func (e *Echo) Group(prefix string, m ...MiddlewareFunc) *Group {
	return &Group{prefix: prefix, echo: e}
}

// ServeHTTP conforms to http.Handler.
func (e *Echo) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

// Group stands in for echo's route group.
type Group struct {
	prefix string
	echo   *Echo
}

// Use attaches group middleware.
func (g *Group) Use(middleware ...MiddlewareFunc) {}

func (g *Group) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route { return nil }
func (g *Group) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route  { return nil }
func (g *Group) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route     { return nil }
func (g *Group) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route    { return nil }
func (g *Group) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route { return nil }
func (g *Group) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route   { return nil }
func (g *Group) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route    { return nil }
func (g *Group) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route     { return nil }
func (g *Group) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route   { return nil }

func (g *Group) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	return nil
}

func (g *Group) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	return nil
}

func (g *Group) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return nil
}

// Group returns a nested route group under g's prefix + prefix.
func (g *Group) Group(prefix string, m ...MiddlewareFunc) *Group {
	return &Group{prefix: g.prefix + prefix, echo: g.echo}
}

// WrapHandler wraps a net/http Handler as an echo handler.
func WrapHandler(h http.Handler) HandlerFunc {
	return func(c Context) error {
		h.ServeHTTP(nil, c.Request())
		return nil
	}
}

// WrapMiddleware wraps net/http middleware as echo middleware.
func WrapMiddleware(m func(http.Handler) http.Handler) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) error { return next(c) }
	}
}
