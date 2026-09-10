// Package goref is a tiny, offline fixture module the Go reference symbol profile
// (plugin/symboltest.GoReferenceProfile) is driven against. It exercises the real
// declaration constructs the eight categories map to — a type, a function, a
// method, a constructor, a generic function, and a nested type — so
// goanalysis.IndexSymbols emits real symbols for them. It has no external
// dependencies and is loaded standalone (GOWORK=off).
package goref

// Widget is an exported struct type (category: types).
type Widget struct {
	name string
}

// Config is a type declared alongside Widget; the reference profile targets it as
// a Widget-nested declaration (category: nested declarations).
type Config struct {
	Verbose bool
}

// NewWidget is the Go NewT constructor idiom (category: constructors).
func NewWidget(name string) *Widget {
	return &Widget{name: name}
}

// Render is a method on *Widget (category: methods).
func (w *Widget) Render() string {
	return "<" + w.name + ">"
}

// GetName is an accessor-shaped method; the reference profile targets it as a
// generated symbol (category: generated symbols).
func (w *Widget) GetName() string {
	return w.name
}

// Build is a package-level function (category: functions).
func Build() *Widget {
	return NewWidget("default")
}

// Map is a generic function; the reference profile targets it with a
// type-parameter descriptor (category: overloads/generics).
func Map[T, U any](in []T, f func(T) U) []U {
	out := make([]U, 0, len(in))
	for _, v := range in {
		out = append(out, f(v))
	}
	return out
}
