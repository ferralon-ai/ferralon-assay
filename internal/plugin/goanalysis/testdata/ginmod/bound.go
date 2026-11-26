package main

import "github.com/gin-gonic/gin"

// The handlers in this file reach their registrar bound first: loaded from a package
// var, from a struct field, or returned by a first-party factory. Each registered one
// hands request data to its own sink; the negatives (a var stored twice, a field
// holding two handlers, a factory returning its parameter) resolve to no one handler
// and register no ingress, so their sinks get no path.

func sinkVar(v string)     { sunk = append(sunk, v) }
func sinkField(v string)   { sunk = append(sunk, v) }
func sinkFactory(v string) { sunk = append(sunk, v) }
func sinkUnbound(v string) { sunk = append(sunk, v) }

// varHandler is a handler bound to a package var by its declaration (init$1).
var varHandler = func(c *gin.Context) { sinkVar(c.Param("id")) }

// boundRoutes holds its handler in a struct field.
type boundRoutes struct{ h gin.HandlerFunc }

func fieldForm(c *gin.Context) { sinkField(c.Query("q")) }

func (b *boundRoutes) register(r *gin.Engine) { r.GET("/field", b.h) }

// makeHandler is a first-party factory: the closure it returns is the handler.
func makeHandler(name string) gin.HandlerFunc {
	if name == "" {
		return nil
	}
	return func(c *gin.Context) { sinkFactory(c.Param(name)) }
}

// reboundHandler is stored twice, so a load of it is no one handler.
var reboundHandler gin.HandlerFunc = reboundA

func reboundA(c *gin.Context) { sinkUnbound(c.Param("a")) }
func reboundB(c *gin.Context) { sinkUnbound(c.Param("b")) }

func rebind() { reboundHandler = reboundB }

// twoRoutes' field holds two different handlers, so a load of it is no one handler.
type twoRoutes struct{ h gin.HandlerFunc }

func twoA(c *gin.Context) { sinkUnbound(c.Param("a")) }
func twoB(c *gin.Context) { sinkUnbound(c.Param("b")) }

// passThrough returns its parameter, which no caller is followed into.
func passThrough(h gin.HandlerFunc) gin.HandlerFunc { return h }

func paramHandler(c *gin.Context) { sinkUnbound(c.Param("p")) }

func registerBound(r *gin.Engine) {
	r.GET("/var/:id", varHandler)
	(&boundRoutes{h: fieldForm}).register(r)
	r.GET("/factory/:id", makeHandler("id"))

	rebind()
	r.GET("/rebound", reboundHandler)
	pair := []twoRoutes{{h: twoA}, {h: twoB}}
	for _, p := range pair {
		r.GET("/two", p.h)
	}
	r.GET("/param", passThrough(paramHandler))
}
