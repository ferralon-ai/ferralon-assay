// Package web mirrors the registration surface of beego's server/web: the names,
// receivers and parameter shapes of the real package, with no routing behind them.
package web

import (
	http "tegron.test/nethttp"

	"github.com/beego/beego/v2/server/web/context"
)

// ControllerInterface mirrors beego's ControllerInterface.
type ControllerInterface interface {
	Init(ctx *context.Context)
	Get()
	Post()
	Delete()
	Put()
	Head()
	Patch()
	Options()
	Trace()
}

// Controller mirrors beego's base Controller, which every controller embeds.
type Controller struct {
	Ctx *context.Context
}

func (c *Controller) Init(ctx *context.Context) { c.Ctx = ctx }
func (c *Controller) Get()                      {}
func (c *Controller) Post()                     {}
func (c *Controller) Delete()                   {}
func (c *Controller) Put()                      {}
func (c *Controller) Head()                     {}
func (c *Controller) Patch()                    {}
func (c *Controller) Options()                  {}
func (c *Controller) Trace()                    {}

// ServeJSON mirrors an exported helper every controller inherits.
func (c *Controller) ServeJSON() {}

// HandleFunc mirrors beego's HandleFunc; FilterFunc is the same type.
type HandleFunc func(ctx *context.Context)
type FilterFunc = HandleFunc

// FilterOpt mirrors beego's filter option.
type FilterOpt func()

// BeforeRouter mirrors the filter position constant.
const BeforeRouter = 1

// HttpServer mirrors beego's HttpServer.
type HttpServer struct{ Handlers *ControllerRegister }

// ControllerRegister mirrors beego's ControllerRegister.
type ControllerRegister struct{}

// BeeApp mirrors the package's default server.
var BeeApp = &HttpServer{Handlers: &ControllerRegister{}}

func Router(rootpath string, c ControllerInterface, mappingMethods ...string) *HttpServer {
	return BeeApp.Router(rootpath, c, mappingMethods...)
}
func Include(cList ...ControllerInterface) *HttpServer { return BeeApp }
func AutoRouter(c ControllerInterface) *HttpServer     { return BeeApp }
func Get(rootpath string, f HandleFunc) *HttpServer    { return BeeApp }
func Post(rootpath string, f HandleFunc) *HttpServer   { return BeeApp }
func Any(rootpath string, f HandleFunc) *HttpServer    { return BeeApp }
func CtrlGet(rootpath string, f interface{})           {}
func Handler(rootpath string, h http.Handler, options ...interface{}) *HttpServer {
	return BeeApp
}
func InsertFilter(pattern string, pos int, filter FilterFunc, opts ...FilterOpt) *HttpServer {
	return BeeApp
}

func (app *HttpServer) Router(rootPath string, c ControllerInterface, mappingMethods ...string) *HttpServer {
	return app
}

func (p *ControllerRegister) Add(pattern string, c ControllerInterface, opts ...ControllerOption) {}
func (p *ControllerRegister) AddMethod(method, pattern string, f HandleFunc)                      {}

// ControllerOption mirrors beego's route option.
type ControllerOption func()

func WithRouterSessionOn(sessionOn bool) ControllerOption { return func() {} }

// Namespace mirrors beego's Namespace.
type Namespace struct{}

// LinkNamespace mirrors beego's namespace builder function.
type LinkNamespace func(*Namespace)

func NewNamespace(prefix string, params ...LinkNamespace) *Namespace { return &Namespace{} }
func AddNamespace(nl ...*Namespace)                                  {}
func NSNamespace(prefix string, params ...LinkNamespace) LinkNamespace {
	return func(*Namespace) {}
}
func NSInclude(cList ...ControllerInterface) LinkNamespace { return func(*Namespace) {} }
func NSRouter(rootpath string, c ControllerInterface, mappingMethods ...string) LinkNamespace {
	return func(*Namespace) {}
}
func NSGet(rootpath string, f HandleFunc) LinkNamespace { return func(*Namespace) {} }
func NSBefore(filterList ...FilterFunc) LinkNamespace   { return func(*Namespace) {} }

func (n *Namespace) Router(rootpath string, c ControllerInterface, mappingMethods ...string) *Namespace {
	return n
}
