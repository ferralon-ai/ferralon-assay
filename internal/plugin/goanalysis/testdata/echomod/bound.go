package main

import "github.com/labstack/echo/v4"

// The handlers in this file reach their registrar bound first: loaded from a package
// var, from a struct field, or returned by a first-party factory. Each registered one
// hands request data to its own sink; the negatives (a var stored twice, a field
// holding two handlers, a factory returning its parameter) resolve to no one handler
// and register no ingress, so their sinks get no path.

func sinkVar(v any)     { sunk = append(sunk, v) }
func sinkField(v any)   { sunk = append(sunk, v) }
func sinkFactory(v any) { sunk = append(sunk, v) }
func sinkUnbound(v any) { sunk = append(sunk, v) }

// varHandler is a handler bound to a package var by its declaration (init$1).
var varHandler = func(c echo.Context) error { sinkVar(c.Param("id")); return nil }

// boundRoutes holds its handler in a struct field.
type boundRoutes struct{ h echo.HandlerFunc }

func fieldForm(c echo.Context) error { sinkField(c.QueryParam("q")); return nil }

func (b *boundRoutes) register(e *echo.Echo) { e.GET("/field", b.h) }

// makeHandler is a first-party factory: the closure it returns is the handler.
func makeHandler(name string) echo.HandlerFunc {
	if name == "" {
		return nil
	}
	return func(c echo.Context) error { sinkFactory(c.Param(name)); return nil }
}

// reboundHandler is stored twice, so a load of it is no one handler.
var reboundHandler echo.HandlerFunc = reboundA

func reboundA(c echo.Context) error { sinkUnbound(c.Param("a")); return nil }
func reboundB(c echo.Context) error { sinkUnbound(c.Param("b")); return nil }

func rebind() { reboundHandler = reboundB }

// twoRoutes' field holds two different handlers, so a load of it is no one handler.
type twoRoutes struct{ h echo.HandlerFunc }

func twoA(c echo.Context) error { sinkUnbound(c.Param("a")); return nil }
func twoB(c echo.Context) error { sinkUnbound(c.Param("b")); return nil }

// passThrough returns its parameter, which no caller is followed into.
func passThrough(h echo.HandlerFunc) echo.HandlerFunc { return h }

func paramHandler(c echo.Context) error { sinkUnbound(c.Param("p")); return nil }

func registerBound(e *echo.Echo) {
	e.GET("/var/:id", varHandler)
	(&boundRoutes{h: fieldForm}).register(e)
	e.GET("/factory/:id", makeHandler("id"))

	rebind()
	e.GET("/rebound", reboundHandler)
	pair := []twoRoutes{{h: twoA}, {h: twoB}}
	for _, p := range pair {
		e.GET("/two", p.h)
	}
	e.GET("/param", passThrough(paramHandler))
}
