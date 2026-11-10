package depreach

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// An engine seeded with another engine's exported searches answers every (ingress, sink) pair
// as a fresh engine does.
func TestClosure_ExportImportMatchesFresh(t *testing.T) {
	classes := c7Classes()
	var refs []classfile.MethodRef
	for _, c := range classes {
		for _, m := range c.Methods {
			refs = append(refs, m.Ref)
		}
	}
	for _, linked := range []bool{false, true} {
		src := NewEngineOn(classes, Classpath{})
		src.SetLinked(linked)
		dst := NewEngineOn(classes, Classpath{})
		dst.SetLinked(linked)
		for _, in := range refs {
			src.Reach(in, refs[0])
			bits, miss, ok := src.Closure(in)
			if !ok {
				t.Fatalf("linked=%v: no closure to export for %s", linked, in)
			}
			if !dst.SetClosure(in, bits, miss) {
				t.Fatalf("linked=%v: SetClosure refused %s's own export", linked, in)
			}
		}
		for _, in := range refs {
			for _, sink := range refs {
				fresh := NewEngineOn(classes, Classpath{})
				fresh.SetLinked(linked)
				if got, want := dst.Reach(in, sink), fresh.Reach(in, sink); !reflect.DeepEqual(got, want) {
					t.Fatalf("linked=%v Reach(%s, %s) from an imported search = %+v, fresh = %+v", linked, in, sink, got, want)
				}
			}
		}
	}
}

func TestClosure_SetClosureRefuses(t *testing.T) {
	in := mref("com/acme/app/App", "reachable", "()V")
	src := NewEngineOn(c7Classes(), Classpath{})
	src.Reach(in, in)
	bits, miss, ok := src.Closure(in)
	if !ok || len(bits) == 0 {
		t.Fatal("no closure to export")
	}
	n := src.tableSize
	trailing := append([]uint64(nil), bits...)
	if n%64 != 0 {
		trailing[len(trailing)-1] |= 1 << 63
	}
	found := miss
	found.Verdict = ReachableCandidate
	withPath := miss
	withPath.Path = []classfile.MethodRef{in}
	clearedHazard := Result{Verdict: NotExploitable, SinkPresent: true, HazardOnFrontier: true, HazardWhy: "reflection: x"}
	quietUndetermined := Result{Verdict: Undetermined, SinkPresent: true}
	noVerdict := Result{SinkPresent: true}
	tests := []struct {
		name string
		bits []uint64
		miss Result
	}{
		{"short", bits[:len(bits)-1], miss},
		{"long", append(append([]uint64(nil), bits...), 0), miss},
		{"bit past the table", trailing, miss},
		{"found path as the miss", bits, found},
		{"path on the miss", bits, withPath},
		{"refutation its hazard contradicts", bits, clearedHazard},
		{"undetermined with no hazard", bits, quietUndetermined},
		{"no verdict", bits, noVerdict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "bit past the table" && n%64 == 0 {
				t.Skip("table fills its last word")
			}
			dst := NewEngineOn(c7Classes(), Classpath{})
			if dst.SetClosure(in, tc.bits, tc.miss) {
				t.Error("SetClosure accepted it")
			}
			if dst.HasClosure(in) {
				t.Error("a refused closure was installed")
			}
		})
	}
}

// A search that met a method outside the loaded table numbers it as no other engine would, so
// it is never exported.
func TestClosure_BeyondTableNotExported(t *testing.T) {
	in := mref("com/acme/app/App", "reachable", "()V")
	t.Run("marked beyond", func(t *testing.T) {
		e := NewEngineOn(c7Classes(), Classpath{})
		e.closures[in] = &closure{beyond: true}
		if _, _, ok := e.Closure(in); ok {
			t.Error("exported a search beyond the table")
		}
	})
	// A later class of the same binary name replaces the earlier in the table, but the earlier's
	// constructor stays declared, so the search enqueues a method the table has no bit for.
	t.Run("duplicated class name", func(t *testing.T) {
		shadow := classfile.Class{Name: "com/evil/netkit/ServiceImpl", Super: "java/lang/Object", Interfaces: []string{"com/evil/netkit/Service"}, Methods: []classfile.Method{
			{Ref: mref("com/evil/netkit/ServiceImpl", "run", "()V")},
		}}
		e := NewEngineOn(append(c7Classes(), shadow), Classpath{})
		e.Reach(in, in)
		if !e.HasClosure(in) {
			t.Fatal("no search to export")
		}
		if _, _, ok := e.Closure(in); ok {
			t.Error("exported a search that enqueued a method outside the table")
		}
	})
}

// The subtype and dispatch memos are per linked bit: a flip forgets what the other bit
// resolved.
func TestMemos_ResetOnLink(t *testing.T) {
	e := NewEngineOn(c7Classes(), Classpath{})
	e.SetLinked(false)
	e.subtypeClosure("java/lang/Object")
	e.dispatched[dispatchKey{}] = dispatch{}
	if len(e.closed) == 0 {
		t.Fatal("subtypeClosure kept nothing")
	}
	e.SetLinked(true)
	if len(e.closed) != 0 || len(e.dispatched) != 0 {
		t.Errorf("SetLinked kept %d subtype closures and %d dispatches from the other bit", len(e.closed), len(e.dispatched))
	}
}
