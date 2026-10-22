// Package http is a minimal local stand-in for the net/http types the chi API
// surface uses (ResponseWriter, Request, Handler, HandlerFunc), so the chi stubs and
// the fixture read exactly as they would against net/http, with only the import path
// changed.
//
// Why not net/http itself: the goanalysis loader type-checks every dependency from
// source, and net/http's import graph alone costs ~300ms per load, more than the
// 250ms a test may take. The chi detector never looks at these types: it keys on the
// import path of the chi package declaring the called registrar, and the taint
// sources are the ingress function's parameters whatever their type — the same path
// a net/http handler takes.
package http

// ResponseWriter mirrors net/http.ResponseWriter.
type ResponseWriter interface {
	Write([]byte) (int, error)
}

// URL mirrors the net/url.URL fields the fixture reads.
type URL struct {
	Path     string
	RawQuery string
}

// Request mirrors net/http.Request.
type Request struct {
	Method string
	URL    *URL
}

// Handler mirrors net/http.Handler.
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

// HandlerFunc mirrors net/http.HandlerFunc.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) { f(w, r) }
