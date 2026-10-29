// Command taintflowmod exercises the value-flow shapes taint must survive between a
// request and a sink: library calls with no SSA body (the net/http read methods,
// chi.URLParam, strings.TrimSpace), a modeled sanitizer (strconv.Atoi), a store into
// a struct field, a type assertion and a map lookup, and the shapes built through an
// element or nested field address: a variadic call (fmt.Sprintf, and a sink that is
// itself variadic, as exec.Command is), a slice literal, a store into one nested
// field read back through its sibling, a store through a pointer field, and a store
// through a slice view of an array; the append and copy builtins; and the spread of
// the request's context to the result of a first-party call that takes it. One
// chi-registered handler hands each shape to its OWN sink, so a test can read each
// shape's result off its sink.
//
// The controls sit beside them: field reads and a first-party call, which were always
// tainted, and a library call, an append and a copy over values never derived from
// the request, and a context passed to an interface method, which must stay
// untainted. Apart from them sit the places taint stops: a store through a global
// pointer, through a package-level struct value, and through a pointer a closure
// captures, each read back afterwards, and a pointer a call writes through, library
// (json.Unmarshal) or first-party, read back after the call. Those reads do receive
// the request at run time, so they are known misses, not clean controls, pinned so a
// change to them is deliberate. (The http types are tegron.test/nethttp's stand-ins;
// see ../chimod/nethttpstub/http.go.)
package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	http "tegron.test/nethttp"

	"github.com/go-chi/chi/v5"
)

// sunk keeps the sinks' arguments live.
var sunk []any

// One sink per shape.
func sinkHeaderGet(v string)  { sunk = append(sunk, v) }
func sinkQueryGet(v string)   { sunk = append(sunk, v) }
func sinkFormValue(v string)  { sunk = append(sunk, v) }
func sinkURLParam(v string)   { sunk = append(sunk, v) }
func sinkTrimSpace(v string)  { sunk = append(sunk, v) }
func sinkAtoi(v int)          { sunk = append(sunk, v) }
func sinkFieldStore(v string) { sunk = append(sunk, v) }
func sinkTypeAssert(v string) { sunk = append(sunk, v) }
func sinkLookup(v []string)   { sunk = append(sunk, v) }
func sinkPath(v string)       { sunk = append(sunk, v) }
func sinkRawQuery(v string)   { sunk = append(sunk, v) }
func sinkOwnID(v string)      { sunk = append(sunk, v) }
func sinkUntainted(v string)  { sunk = append(sunk, v) }

func sinkSprintf(v string)          { sunk = append(sunk, v) }
func sinkVariadic(v ...string)      { sunk = append(sunk, v) }
func sinkSliceLit(v []string)       { sunk = append(sunk, v) }
func sinkNestedSibling(v string)    { sunk = append(sunk, v) }
func sinkVariadicConst(v ...string) { sunk = append(sunk, v) }

func sinkAppend(v []string)      { sunk = append(sunk, v) }
func sinkCopy(v string)          { sunk = append(sunk, v) }
func sinkAppendConst(v []string) { sunk = append(sunk, v) }
func sinkCopyConst(v string)     { sunk = append(sunk, v) }
func sinkPointerField(v string)  { sunk = append(sunk, v) }
func sinkSliceView(v string)     { sunk = append(sunk, v) }

func sinkGlobalPointer(v string)  { sunk = append(sunk, v) }
func sinkClosureCapture(v string) { sunk = append(sunk, v) }
func sinkPackageStruct(v string)  { sunk = append(sunk, v) }
func sinkOutArgLibrary(v string)  { sunk = append(sunk, v) }
func sinkOutArgOwn(v string)      { sunk = append(sunk, v) }

func sinkCtxOwn(v string)   { sunk = append(sunk, v) }
func sinkCtxIface(v string) { sunk = append(sunk, v) }

// greeting is never derived from the request.
var greeting = " hello "

// wrap holds the request in a field.
type wrap struct{ req *http.Request }

// outer holds a struct in a field, so o.in.a is a field address of a field address.
type outer struct{ in struct{ a, b string } }

// holder holds a pointer in a field, so h.in.a stores through a load of &h.in.
type holder struct{ in *struct{ a string } }

// gp is a global pointer: gp.a = x stores through a load of gp, where the chain of
// bases stops.
var gp = &struct{ a string }{}

// cfg is a package-level struct value: cfg.p.a = x takes the address of cfg.p straight
// off the global, so the chain of bases reaches cfg itself.
var cfg = struct{ p *struct{ a string } }{p: &struct{ a string }{}}

// ownID is a first-party transform: its body is built, so taint flows through it.
func ownID(s string) string { return "id-" + s }

// lookup is a first-party call that takes a context and returns a value that does not
// depend on it.
func lookup(ctx http.Context, key string) string { return "v-" + key }

// store is called through an interface, so a call to Get has no static callee.
type store interface {
	Get(ctx http.Context, key string) string
}

type memStore struct{}

func (memStore) Get(ctx http.Context, key string) string { return "v-" + key }

// named is the struct a call writes a request value into through a pointer.
type named struct{ Name string }

// fill is a first-party call that writes through the pointer it is passed.
func fill(dst *named, s string) { dst.Name = s }

func flows(w http.ResponseWriter, r *http.Request) {
	sinkHeaderGet(r.Header.Get("X-A"))
	sinkQueryGet(r.URL.Query().Get("q"))
	sinkFormValue(r.FormValue("f"))
	sinkURLParam(chi.URLParam(r, "id"))
	sinkTrimSpace(strings.TrimSpace(r.Method))
	n, _ := strconv.Atoi(r.Method)
	sinkAtoi(n)

	wr := &wrap{req: r}
	sinkFieldStore(wr.req.URL.Path)

	var x any = r
	sinkTypeAssert(x.(*http.Request).URL.Path)

	sinkLookup(r.Header["X-A"])

	sinkPath(r.URL.Path)
	sinkRawQuery(r.URL.RawQuery)
	sinkOwnID(ownID(r.Method))
	sinkUntainted(strings.TrimSpace(greeting))

	// Built through an element or nested field address.
	sinkSprintf(fmt.Sprintf("%s", r.Method))
	sinkVariadic("sh", "-c", r.Method)
	sinkSliceLit([]string{"a", r.Method})
	var o outer
	o.in.a = r.Method
	sinkNestedSibling(o.in.b)
	// Control: a variadic call whose elements never came from the request.
	sinkVariadicConst("sh", "-c", greeting)

	// The append and copy builtins, and their controls.
	args := []string{"a"}
	args = append(args, r.Method)
	sinkAppend(args)
	dst := make([]string, 1)
	copy(dst, []string{r.Method})
	sinkCopy(dst[0])
	cargs := append([]string{"a"}, greeting)
	sinkAppendConst(cargs)
	cdst := make([]string, 1)
	copy(cdst, []string{greeting})
	sinkCopyConst(cdst[0])

	// A store through a pointer field, read straight back, and a store through a
	// slice view, read through the array under it.
	h := &holder{in: &struct{ a string }{}}
	h.in.a = r.Method
	sinkPointerField(h.in.a)
	var arr [2]string
	view := arr[:]
	view[0] = r.Method
	sinkSliceView(arr[1])

	// Where taint stops. A store through a global pointer taints only the load of gp it
	// stores through, which a later read of gp.a, a fresh load of gp, does not observe.
	// A store through a package-level struct value reaches cfg itself, but no read of a
	// global observes a seed on it. And a store a closure makes through a pointer it
	// captures is not seen by the enclosing function's later read of that pointer.
	gp.a = r.Method
	sinkGlobalPointer(gp.a)
	cfg.p.a = r.Method
	sinkPackageStruct(cfg.p.a)
	cp := &struct{ a string }{}
	set := func(s string) { cp.a = s }
	set(r.Method)
	sinkClosureCapture(cp.a)
	// A call never taints a pointer it writes through: json.Unmarshal's result is
	// tainted, but the struct it decodes into is not, and fill's store taints its own
	// parameter, which does not flow back to the caller's struct.
	var req named
	_ = json.Unmarshal([]byte(r.Method), &req)
	sinkOutArgLibrary(req.Name)
	var own named
	fill(&own, r.Method)
	sinkOutArgOwn(own.Name)

	// The request's context taints the result of a first-party call that takes it,
	// whether or not the result depends on it; through an interface method it does not.
	ctx := r.Context()
	sinkCtxOwn(lookup(ctx, "const"))
	var st store = memStore{}
	sinkCtxIface(st.Get(ctx, "const"))
}

func main() {
	r := chi.NewRouter()
	r.Get("/flows/{id}", flows)
}
