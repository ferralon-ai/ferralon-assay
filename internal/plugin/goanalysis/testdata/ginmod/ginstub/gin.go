// Package gin is a minimal local stand-in for github.com/gin-gonic/gin, just enough
// for the ingress detector to recognize the route-registrar shapes hermetically (no
// network fetch of the real module). The package PATH is what the detector matches
// (github.com/gin-gonic/gin), supplied via a go.mod module directive + a replace in
// the fixture. The shapes mirror the real gin ones: the registrars are declared on
// *RouterGroup, which *Engine embeds, and on the IRoutes interface; handlers are
// ...HandlerFunc (func(*Context)); Group returns a *RouterGroup; and WrapF/WrapH
// adapt a net/http handler into a HandlerFunc.
package gin

import http "tegron.test/nethttp"

// HandlerFunc is a gin handler.
type HandlerFunc func(*Context)

// Context carries the request; its accessors read attacker-controlled request data.
type Context struct {
	Request *http.Request
	Writer  http.ResponseWriter
}

// Param returns a path parameter.
func (c *Context) Param(key string) string { return c.Request.URL.Path }

// Query returns a query parameter.
func (c *Context) Query(key string) string { return c.Request.URL.RawQuery }

// PostForm returns a form value.
func (c *Context) PostForm(key string) string { return c.Request.URL.RawQuery }

// IRoutes is gin's route-registration interface.
type IRoutes interface {
	Use(...HandlerFunc) IRoutes

	Handle(string, string, ...HandlerFunc) IRoutes
	Any(string, ...HandlerFunc) IRoutes
	GET(string, ...HandlerFunc) IRoutes
	POST(string, ...HandlerFunc) IRoutes
	DELETE(string, ...HandlerFunc) IRoutes
	PATCH(string, ...HandlerFunc) IRoutes
	PUT(string, ...HandlerFunc) IRoutes
	OPTIONS(string, ...HandlerFunc) IRoutes
	HEAD(string, ...HandlerFunc) IRoutes
	Match([]string, string, ...HandlerFunc) IRoutes
}

// IRouter is IRoutes plus Group.
type IRouter interface {
	IRoutes
	Group(string, ...HandlerFunc) *RouterGroup
}

// RouterGroup stands in for gin's route group.
type RouterGroup struct{ handlers []HandlerFunc }

func (group *RouterGroup) Use(middleware ...HandlerFunc) IRoutes { return group }

func (group *RouterGroup) Group(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	return &RouterGroup{handlers: handlers}
}

func (group *RouterGroup) Handle(httpMethod, relativePath string, handlers ...HandlerFunc) IRoutes {
	return group
}

func (group *RouterGroup) Match(methods []string, relativePath string, handlers ...HandlerFunc) IRoutes {
	return group
}

func (group *RouterGroup) Any(relativePath string, handlers ...HandlerFunc) IRoutes     { return group }
func (group *RouterGroup) GET(relativePath string, handlers ...HandlerFunc) IRoutes     { return group }
func (group *RouterGroup) POST(relativePath string, handlers ...HandlerFunc) IRoutes    { return group }
func (group *RouterGroup) DELETE(relativePath string, handlers ...HandlerFunc) IRoutes  { return group }
func (group *RouterGroup) PATCH(relativePath string, handlers ...HandlerFunc) IRoutes   { return group }
func (group *RouterGroup) PUT(relativePath string, handlers ...HandlerFunc) IRoutes     { return group }
func (group *RouterGroup) OPTIONS(relativePath string, handlers ...HandlerFunc) IRoutes { return group }
func (group *RouterGroup) HEAD(relativePath string, handlers ...HandlerFunc) IRoutes    { return group }

// Engine stands in for the gin router; it embeds RouterGroup as the real one does.
type Engine struct {
	RouterGroup
}

// New returns an engine.
func New() *Engine { return &Engine{} }

// Default returns an engine.
func Default() *Engine { return &Engine{} }

// Use attaches global middleware.
func (engine *Engine) Use(middleware ...HandlerFunc) IRoutes { return engine }

// ServeHTTP conforms to http.Handler.
func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {}

// WrapF wraps a net/http HandlerFunc as a gin handler.
func WrapF(f http.HandlerFunc) HandlerFunc {
	return func(c *Context) { f(c.Writer, c.Request) }
}

// WrapH wraps a net/http Handler as a gin handler.
func WrapH(h http.Handler) HandlerFunc {
	return func(c *Context) { h.ServeHTTP(c.Writer, c.Request) }
}
