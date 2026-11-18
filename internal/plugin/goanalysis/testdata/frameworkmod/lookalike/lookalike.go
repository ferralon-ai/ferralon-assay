// Package lookalike carries the framework registrars' names, receivers and parameter
// shapes under an import path that is none of theirs.
package lookalike

import http "tegron.test/nethttp"

type Context struct{ Value string }

type ControllerInterface interface{ Get() }

func Router(rootpath string, c ControllerInterface, mappingMethods ...string) {}
func InsertFilter(pattern string, pos int, filter func(*Context))             {}

type Request struct{ Value string }
type Response struct{}
type RouteBuilder struct{}
type WebService struct{}

func (w *WebService) GET(subPath string) *RouteBuilder                      { return &RouteBuilder{} }
func (b *RouteBuilder) To(function func(*Request, *Response)) *RouteBuilder { return b }

type Conn struct{}
type Upgrader struct{}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, h http.Header) (*Conn, error) {
	return &Conn{}, nil
}

// Registrar is a look-alike of grpc.ServiceRegistrar.
type Registrar interface{ RegisterService(impl any) }

type ThingServer interface{ Do(v string) }

func RegisterThingServer(s Registrar, srv ThingServer) {}
