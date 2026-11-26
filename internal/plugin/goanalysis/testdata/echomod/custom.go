package main

import "github.com/labstack/echo/v4"

// customContext is the application's own echo context: it embeds echo.Context, so
// every accessor it does not override is promoted, and a handler reads request data
// through it with no echo.Context in sight.
type customContext struct {
	echo.Context
}

// sinkCustomParam and sinkCustomRealIP are reached from customForm through the
// custom context's promoted accessors.
func sinkCustomParam(v any)  { sunk = append(sunk, v) }
func sinkCustomRealIP(v any) { sunk = append(sunk, v) }

func sinkCustomAsserted(v any) { sunk = append(sunk, v) }
func sinkCustomMethod(v any)   { sunk = append(sunk, v) }

// UserID is a method of the custom context that returns request data read through the
// embedded echo.Context.
func (c *customContext) UserID() string { return c.QueryParam("user") }

// customForm reads request data through a customContext the handler builds around
// its echo.Context parameter.
func (s *server) customForm(c echo.Context) error {
	cc := &customContext{c}
	sinkCustomParam(cc.Param("id"))
	sinkCustomRealIP(cc.RealIP())
	return nil
}

// customAssertedForm is the usual middleware pattern: a middleware wraps the context
// in a customContext, and the handler asserts it back out of the echo.Context it is
// given.
func (s *server) customAssertedForm(c echo.Context) error {
	cc := c.(*customContext)
	sinkCustomAsserted(cc.Param("id"))
	sinkCustomMethod(cc.UserID())
	return nil
}
