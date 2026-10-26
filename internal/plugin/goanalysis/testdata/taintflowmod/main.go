// Command taintflowmod exercises the value-flow shapes taint must survive between a
// request and a sink: library calls with no SSA body (the net/http read methods,
// chi.URLParam, strings.TrimSpace), a modeled sanitizer (strconv.Atoi), a store into
// a struct field, a type assertion and a map lookup. One chi-registered handler hands
// each shape to its OWN sink, so a test can read each shape's result off its sink.
//
// The controls sit beside them: field reads and a first-party call, which were always
// tainted, and a library call on a value never derived from the request, which must
// stay untainted. (The http types are tegron.test/nethttp's stand-ins; see
// ../chimod/nethttpstub/http.go.)
package main

import (
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

// greeting is never derived from the request.
var greeting = " hello "

// wrap holds the request in a field.
type wrap struct{ req *http.Request }

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
}

func main() {
	r := chi.NewRouter()
	r.Get("/flows/{id}", flows)
}
