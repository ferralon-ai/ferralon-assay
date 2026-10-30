// Package gin is a LOOK-ALIKE router: same package name, type names and method
// names as gin, but declared under this fixture's own import path
// (tegron.test/ginmod/lookalike), not github.com/gin-gonic/gin. A handler registered
// on it, or wrapped by its WrapF and registered on the real gin, must NOT become an
// ingress — the detector keys on gin's import path, never on a type or method name
// alone.
package gin

import (
	realgin "github.com/gin-gonic/gin"
	http "tegron.test/nethttp"
)

// HandlerFunc mirrors gin's handler type.
type HandlerFunc func(*realgin.Context)

// RouterGroup mirrors gin's route group.
type RouterGroup struct{}

func (group *RouterGroup) Group(relativePath string, handlers ...HandlerFunc) *RouterGroup {
	return &RouterGroup{}
}

func (group *RouterGroup) Handle(httpMethod, relativePath string, handlers ...HandlerFunc) {}

func (group *RouterGroup) Match(methods []string, relativePath string, handlers ...HandlerFunc) {}

func (group *RouterGroup) GET(relativePath string, handlers ...HandlerFunc)  {}
func (group *RouterGroup) POST(relativePath string, handlers ...HandlerFunc) {}

// Engine mirrors gin's router type.
type Engine struct {
	RouterGroup
}

// New returns an engine.
func New() *Engine { return &Engine{} }

// WrapF mirrors gin.WrapF, returning a real gin handler.
func WrapF(f http.HandlerFunc) realgin.HandlerFunc {
	return func(c *realgin.Context) { f(c.Writer, c.Request) }
}
