// Command taintflowmod is a stdlib-only fixture where each sink is reached by one sanitized flow
// and one raw flow from the attacker-controlled request method. The raw flow takes a shape the
// taint pass must carry: a dependency call whose body it does not hold, an append read back by
// index, a copy, a field written in a callee, a concatenation, and a conditional that sanitizes on one
// branch only. Every sink must come back with a taint path.
package main

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// Upper is reached raw through strings.ToUpper, whose body the analysis does not hold.
func Upper(s string) { fmt.Println(s) }

// Appended is reached raw through an append read back by index.
func Appended(s string) { fmt.Println(s) }

// Copied is reached raw through a copy into another slice.
func Copied(s string) { fmt.Println(s) }

// Field is reached raw through a struct field a callee writes.
func Field(s string) { fmt.Println(s) }

// Concat is reached through a concatenation of a sanitized and a raw value.
func Concat(s string) { fmt.Println(s) }

// Branch is reached through a value sanitized on one branch only.
func Branch(s string) { fmt.Println(s) }

type holder struct{ f string }

func set(h *holder, v string) { h.f = v }

// UpperHandler hands Upper a sanitized and a dependency-transformed raw method.
func UpperHandler(w http.ResponseWriter, r *http.Request) {
	Upper(html.EscapeString(r.Method))
	Upper(strings.ToUpper(r.Method))
}

// AppendHandler hands Appended a sanitized method and one read back out of a slice.
func AppendHandler(w http.ResponseWriter, r *http.Request) {
	Appended(html.EscapeString(r.Method))
	var xs []string
	xs = append(xs, r.Method)
	Appended(xs[0])
}

// CopyHandler hands Copied a sanitized method and one copied into a fresh slice.
func CopyHandler(w http.ResponseWriter, r *http.Request) {
	Copied(html.EscapeString(r.Method))
	buf := make([]string, 1)
	copy(buf, []string{r.Method})
	Copied(buf[0])
}

// FieldHandler hands Field a sanitized method and one a callee stored in a field.
func FieldHandler(w http.ResponseWriter, r *http.Request) {
	Field(html.EscapeString(r.Method))
	h := &holder{}
	set(h, r.Method)
	Field(h.f)
}

// ConcatHandler hands Concat a sanitized method joined to a raw one.
func ConcatHandler(w http.ResponseWriter, r *http.Request) {
	Concat(html.EscapeString(r.Method) + r.Method)
}

// BranchHandler sanitizes the method only when it is long.
func BranchHandler(w http.ResponseWriter, r *http.Request) {
	x := r.Method
	if len(x) > 3 {
		x = html.EscapeString(x)
	}
	Branch(x)
}

func main() {
	http.HandleFunc("/upper", UpperHandler)
	http.HandleFunc("/append", AppendHandler)
	http.HandleFunc("/copy", CopyHandler)
	http.HandleFunc("/field", FieldHandler)
	http.HandleFunc("/concat", ConcatHandler)
	http.HandleFunc("/branch", BranchHandler)
}
