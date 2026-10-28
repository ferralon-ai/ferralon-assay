// Command taintflowmod exercises the value-flow shapes taint must survive between a
// request and a sink: library calls with no SSA body (the net/http read methods,
// chi.URLParam, strings.TrimSpace), a modeled sanitizer (strconv.Atoi), a store into
// a struct field, a type assertion and a map lookup, and the shapes built through an
// element or nested field address: a variadic call (fmt.Sprintf, and a sink that is
// itself variadic, as exec.Command is), a slice literal, a store into one nested
// field read back through its sibling, a store through a pointer field, and a store
// through a slice view of an array; and the append and copy builtins. One
// chi-registered handler hands each shape to its OWN sink, so a test can read each
// shape's result off its sink.
//
// The controls sit beside them: field reads and a first-party call, which were always
// tainted, and a library call, an append and a copy over values never derived from
// the request, which must stay untainted. (The http types are tegron.test/nethttp's
// stand-ins; see ../chimod/nethttpstub/http.go.)
package main

import (
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

// greeting is never derived from the request.
var greeting = " hello "

// wrap holds the request in a field.
type wrap struct{ req *http.Request }

// outer holds a struct in a field, so o.in.a is a field address of a field address.
type outer struct{ in struct{ a, b string } }

// holder holds a pointer in a field, so h.in.a stores through a load of &h.in.
type holder struct{ in *struct{ a string } }

// ownID is a first-party transform: its body is built, so taint flows through it.
func ownID(s string) string { return "id-" + s }

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
}

func main() {
	r := chi.NewRouter()
	r.Get("/flows/{id}", flows)
}
