// Package macaron is a minimal local stand-in for gopkg.in/macaron.v1, just enough
// for the ingress detector to recognize the route-registrar shape hermetically (no
// network fetch of the real module). The package PATH is what the detector matches
// (gopkg.in/macaron.v1), supplied via a go.mod module directive + a replace in the
// fixture. Handler is the variadic interface{} the verb methods accept, matching the
// real macaron ...Handler signature the detector unwraps from the variadic slice.
package macaron

// Handler is an arbitrary boxed handler value, as in real macaron.
type Handler interface{}

// Macaron stands in for the macaron router.
type Macaron struct{}

// New returns a router.
func New() *Macaron { return &Macaron{} }

// Get registers a handler for GET on pattern.
func (m *Macaron) Get(pattern string, h ...Handler) {}

// Post registers a handler for POST on pattern.
func (m *Macaron) Post(pattern string, h ...Handler) {}
