// Package restful mirrors the registration surface of go-restful: the names,
// receivers and parameter shapes of the real package, with no routing behind them.
package restful

import http "tegron.test/nethttp"

// Request mirrors restful.Request.
type Request struct {
	Request *http.Request
	params  map[string]string
}

// PathParameter mirrors (*Request).PathParameter.
func (r *Request) PathParameter(name string) string { return r.params[name] }

// Response mirrors restful.Response.
type Response struct{}

// FilterChain mirrors restful.FilterChain.
type FilterChain struct{}

type RouteFunction func(*Request, *Response)
type FilterFunction func(*Request, *Response, *FilterChain)

// RouteBuilder mirrors restful.RouteBuilder.
type RouteBuilder struct{}

func (b *RouteBuilder) To(function RouteFunction) *RouteBuilder    { return b }
func (b *RouteBuilder) Method(method string) *RouteBuilder         { return b }
func (b *RouteBuilder) Path(subPath string) *RouteBuilder          { return b }
func (b *RouteBuilder) Doc(documentation string) *RouteBuilder     { return b }
func (b *RouteBuilder) Filter(filter FilterFunction) *RouteBuilder { return b }

// WebService mirrors restful.WebService.
type WebService struct{}

func (w *WebService) Path(root string) *WebService             { return w }
func (w *WebService) Route(builder *RouteBuilder) *WebService  { return w }
func (w *WebService) Method(httpMethod string) *RouteBuilder   { return &RouteBuilder{} }
func (w *WebService) Filter(filter FilterFunction) *WebService { return w }
func (w *WebService) GET(subPath string) *RouteBuilder         { return &RouteBuilder{} }
func (w *WebService) POST(subPath string) *RouteBuilder        { return &RouteBuilder{} }

// Container mirrors restful.Container.
type Container struct{}

func NewContainer() *Container                                   { return &Container{} }
func (c *Container) Add(service *WebService) *Container          { return c }
func (c *Container) Handle(pattern string, handler http.Handler) {}
func (c *Container) Filter(filter FilterFunction)                {}
