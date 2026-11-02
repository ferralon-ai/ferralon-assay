// Package echo is a LOOK-ALIKE router: same package name, type names and method
// names as echo, but declared under this fixture's own import path
// (tegron.test/echomod/lookalike), not github.com/labstack/echo/v4. A handler
// registered on it, or wrapped by its WrapHandler and registered on the real echo,
// must NOT become an ingress — the detector keys on echo's import path, never on a
// type or method name alone.
package echo

import (
	realecho "github.com/labstack/echo/v4"
	http "tegron.test/nethttp"
)

// Echo mirrors echo's router type.
type Echo struct{}

// New returns a router.
func New() *Echo { return &Echo{} }

func (e *Echo) GET(path string, h realecho.HandlerFunc, m ...realecho.MiddlewareFunc)  {}
func (e *Echo) POST(path string, h realecho.HandlerFunc, m ...realecho.MiddlewareFunc) {}
func (e *Echo) Add(method, path string, h realecho.HandlerFunc, m ...realecho.MiddlewareFunc) {
}
func (e *Echo) Group(prefix string, m ...realecho.MiddlewareFunc) *Group { return &Group{} }

// Group mirrors echo's route group.
type Group struct{}

func (g *Group) GET(path string, h realecho.HandlerFunc, m ...realecho.MiddlewareFunc) {}

// WrapHandler mirrors echo.WrapHandler, returning a real echo handler.
func WrapHandler(h http.Handler) realecho.HandlerFunc {
	return func(c realecho.Context) error { return nil }
}
