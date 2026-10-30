// Package http is a minimal local stand-in for the net/http types the chi API
// surface uses (ResponseWriter, Request, Handler, HandlerFunc), so the chi stubs and
// the fixture read exactly as they would against net/http, with only the import path
// changed. taintflowmod also calls the request read methods (Header.Get,
// URL.Query().Get, FormValue, Context): as a dependency, this package gets no SSA
// bodies, so those calls are body-less exactly as real net/http's are.
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

// Query mirrors (*net/url.URL).Query.
func (u *URL) Query() Values { return Values{} }

// Values mirrors net/url.Values.
type Values map[string][]string

// Get mirrors (net/url.Values).Get.
func (v Values) Get(key string) string {
	if vs := v[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Header mirrors net/http.Header.
type Header map[string][]string

// Get mirrors (net/http.Header).Get.
func (h Header) Get(key string) string {
	if vs := h[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Request mirrors net/http.Request.
type Request struct {
	Method string
	URL    *URL
	Header Header
	Form   Values
}

// FormValue mirrors (*net/http.Request).FormValue.
func (r *Request) FormValue(key string) string { return r.Form.Get(key) }

// Context mirrors (*net/http.Request).Context.
func (r *Request) Context() Context { return nil }

// Context stands in for context.Context, here so the stub needs no import: taint
// treats a context like any other value and never keys on its package.
type Context interface {
	Value(key any) any
}

// Handler mirrors net/http.Handler.
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

// HandlerFunc mirrors net/http.HandlerFunc.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) { f(w, r) }
