// Package chi is a minimal local stand-in for github.com/go-chi/chi (the pre-v5
// module path), just enough for the ingress detector to recognize a route registered
// on it hermetically (no network fetch of the real module). The package PATH is what
// the detector matches, supplied via a go.mod module directive + a replace in the
// fixture; the method signatures mirror the real chi ones.
package chi

import http "tegron.test/nethttp"

// Mux stands in for the chi router.
type Mux struct{}

// NewRouter returns a router.
func NewRouter() *Mux { return &Mux{} }

// ServeHTTP makes the router an http.Handler, as in real chi.
func (mx *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

// Get registers handlerFn for GET on pattern.
func (mx *Mux) Get(pattern string, handlerFn http.HandlerFunc) {}
