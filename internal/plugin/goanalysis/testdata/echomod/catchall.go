package main

// Catch-all registrations: echo's RouteNotFound (on the Echo and on a Group) and the
// handlers assigned to the package-level NotFoundHandler and MethodNotAllowedHandler
// and to Echo.HTTPErrorHandler (by assignment and in a composite literal). Each
// registers under the catch-all selector "*", whatever path RouteNotFound names. The
// look-alike router's own forms are no ingress, nor are echo's own defaults.

import (
	"github.com/labstack/echo/v4"

	lookalike "tegron.test/echomod/lookalike"
)

func sinkRouteNotFound(v any)      { sunk = append(sunk, v) }
func sinkGroupRouteNotFound(v any) { sunk = append(sunk, v) }
func sinkNotFoundHandler(v any)    { sunk = append(sunk, v) }
func sinkMethodNotAllowed(v any)   { sunk = append(sunk, v) }
func sinkHTTPError(v any)          { sunk = append(sunk, v) }
func sinkHTTPErrorLiteral(v any)   { sunk = append(sunk, v) }

func (s *server) routeNotFoundForm(c echo.Context) error {
	sinkRouteNotFound(c.QueryParam("q"))
	return nil
}
func (s *server) groupRouteNotFoundForm(c echo.Context) error {
	sinkGroupRouteNotFound(c.QueryParam("q"))
	return nil
}
func (s *server) notFoundHandlerForm(c echo.Context) error {
	sinkNotFoundHandler(c.QueryParam("q"))
	return nil
}
func (s *server) methodNotAllowedForm(c echo.Context) error {
	sinkMethodNotAllowed(c.QueryParam("q"))
	return nil
}
func (s *server) httpErrorForm(err error, c echo.Context) { sinkHTTPError(c.QueryParam("q")) }
func (s *server) httpErrorLiteralForm(err error, c echo.Context) {
	sinkHTTPErrorLiteral(c.QueryParam("q"))
}
func (s *server) lookalikeNotFound(c echo.Context) error {
	sinkLookalike(c.QueryParam("q"))
	return nil
}
func (s *server) lookalikeNotFoundVar(c echo.Context) error {
	sinkLookalike(c.QueryParam("q"))
	return nil
}
func (s *server) lookalikeErrorForm(err error, c echo.Context) { sinkLookalike(c.QueryParam("q")) }

func registerCatchAll(e *echo.Echo, api *echo.Group, s *server) {
	e.RouteNotFound("/*", s.routeNotFoundForm)
	api.RouteNotFound("/*", s.groupRouteNotFoundForm)
	echo.NotFoundHandler = s.notFoundHandlerForm
	echo.MethodNotAllowedHandler = s.methodNotAllowedForm
	e.HTTPErrorHandler = s.httpErrorForm
	_ = &echo.Echo{HTTPErrorHandler: s.httpErrorLiteralForm}

	fake := lookalike.New()
	fake.RouteNotFound("/*", s.lookalikeNotFound)
	lookalike.NotFoundHandler = s.lookalikeNotFoundVar
	_ = &lookalike.Router{HTTPErrorHandler: s.lookalikeErrorForm}
}
