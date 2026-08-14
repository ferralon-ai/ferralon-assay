package artifactcache

import (
	"os/exec"
	"reflect"
	"regexp"
	"testing"
)

// execNameRe matches any method name that would betray an execution capability.
var execNameRe = regexp.MustCompile(`(?i)(run|exec|start|command|spawn|fork)`)

// runner is the shape of anything that can be Run() — a *exec.Cmd satisfies it. A method
// on Store or Handle whose parameter or return type satisfies runner would smuggle an
// execution handle across the boundary.
type runner interface{ Run() error }

// TestNoExecutionCapability is the layer-1 mechanical guarantee: it walks the Store and
// Handle interface method sets and fails if any method name reads as execution, or if any
// parameter/return type is *exec.Cmd or satisfies interface{ Run() error }. A future
// author cannot add an exec method to either interface without turning this test red.
func TestNoExecutionCapability(t *testing.T) {
	cmdType := reflect.TypeOf((*exec.Cmd)(nil))         // *exec.Cmd
	runnerType := reflect.TypeOf((*runner)(nil)).Elem() // interface{ Run() error }

	ifaces := map[string]reflect.Type{
		"Store":  reflect.TypeOf((*Store)(nil)).Elem(),
		"Handle": reflect.TypeOf((*Handle)(nil)).Elem(),
	}

	for ifaceName, it := range ifaces {
		if it.Kind() != reflect.Interface {
			t.Fatalf("%s is not an interface type", ifaceName)
		}
		for i := 0; i < it.NumMethod(); i++ {
			m := it.Method(i)
			if execNameRe.MatchString(m.Name) {
				t.Errorf("%s.%s: method name matches forbidden execution pattern %s", ifaceName, m.Name, execNameRe)
			}
			checkNoExecTypes(t, ifaceName, m.Name, m.Type, cmdType, runnerType)
		}
	}
}

func checkNoExecTypes(t *testing.T, ifaceName, method string, ft reflect.Type, cmdType, runnerType reflect.Type) {
	t.Helper()
	report := func(kind string, idx int, typ reflect.Type) {
		if typ == cmdType {
			t.Errorf("%s.%s: %s %d is *exec.Cmd — an execution handle", ifaceName, method, kind, idx)
		}
		if typ.Implements(runnerType) {
			t.Errorf("%s.%s: %s %d (%s) satisfies interface{ Run() error }", ifaceName, method, kind, idx, typ)
		}
	}
	for i := 0; i < ft.NumIn(); i++ {
		report("param", i, ft.In(i))
	}
	for i := 0; i < ft.NumOut(); i++ {
		report("return", i, ft.Out(i))
	}
}

// fakeRef is a local probe Ref for the core-package fake tests (the shared ProbeRef and
// the harness that consumes it live in the sibling artifactcachetest package).
var fakeRef = Ref{PURL: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", Digest: "sha256:abc"}

// TestMemHandleReadPath exercises the inert Handle directly: full ReaderAt read, Size,
// Path (unset), and read-after-close rejection.
func TestMemHandleReadPath(t *testing.T) {
	data := []byte("jackson-databind bytes")
	store := NewMemStore(map[Ref][]byte{fakeRef: data})

	h, err := store.Lookup(t.Context(), fakeRef)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := h.Size(); got != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", got, len(data))
	}
	if p := h.Path(); p != "" {
		t.Fatalf("Path() = %q, want empty for in-memory handle", p)
	}
	buf := make([]byte, len(data))
	n, err := h.ReadAt(buf, 0)
	if n != len(data) {
		t.Fatalf("ReadAt read %d bytes, want %d (err=%v)", n, len(data), err)
	}
	if string(buf) != string(data) {
		t.Fatalf("ReadAt content = %q, want %q", buf, data)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := h.ReadAt(buf, 0); err == nil {
		t.Fatalf("ReadAt after Close: want error, got nil")
	}
}

// TestLookupMissIsDeclaredAbsent pins the miss contract.
func TestLookupMissIsDeclaredAbsent(t *testing.T) {
	store := NewMemStore(nil)
	if _, err := store.Lookup(t.Context(), Ref{PURL: "pkg:maven/x/y@1", Digest: "sha256:deadbeef"}); err != ErrDeclaredAbsent {
		t.Fatalf("Lookup miss = %v, want ErrDeclaredAbsent", err)
	}
}
