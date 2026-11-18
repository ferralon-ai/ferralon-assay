package depreach

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// An engine seeded with another engine's exported searches answers every (ingress, sink) pair
// as a fresh engine does.
func TestClosure_ExportImportMatchesFresh(t *testing.T) {
	// A later class of the same binary name replaces the earlier, but the earlier's constructor
	// stays declared, so a search still enqueues it.
	shadow := classfile.Class{Name: "com/evil/netkit/ServiceImpl", Super: "java/lang/Object", Interfaces: []string{"com/evil/netkit/Service"}, Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/ServiceImpl", "run", "()V")},
	}}
	tests := []struct {
		name    string
		classes []classfile.Class
	}{
		{"loaded classes", c7Classes()},
		{"duplicated class name", append(c7Classes(), shadow)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var refs []classfile.MethodRef
			for _, c := range tc.classes {
				for _, m := range c.Methods {
					refs = append(refs, m.Ref)
				}
			}
			for _, linked := range []bool{false, true} {
				src := NewEngineOn(tc.classes, Classpath{})
				src.SetLinked(linked)
				dst := NewEngineOn(tc.classes, Classpath{})
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
						fresh := NewEngineOn(tc.classes, Classpath{})
						fresh.SetLinked(linked)
						if got, want := dst.Reach(in, sink), fresh.Reach(in, sink); !reflect.DeepEqual(got, want) {
							t.Fatalf("linked=%v Reach(%s, %s) from an imported search = %+v, fresh = %+v", linked, in, sink, got, want)
						}
					}
				}
			}
		})
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
	e := NewEngineOn(c7Classes(), Classpath{})
	e.closures[in] = &closure{beyond: true}
	if _, _, ok := e.Closure(in); ok {
		t.Error("exported a search beyond the table")
	}
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

// The path read from a whole search is the path a search for the sink returns, whether the
// engine ran that whole search or was handed another engine's.
func TestClosurePath_MatchesSearch(t *testing.T) {
	shadow := classfile.Class{Name: "com/evil/netkit/ServiceImpl", Super: "java/lang/Object", Interfaces: []string{"com/evil/netkit/Service"}, Methods: []classfile.Method{
		{Ref: mref("com/evil/netkit/ServiceImpl", "run", "()V")},
	}}
	tests := []struct {
		name    string
		classes []classfile.Class
	}{
		{"loaded classes", c7Classes()},
		{"duplicated class name", append(c7Classes(), shadow)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var refs []classfile.MethodRef
			for _, c := range tc.classes {
				for _, m := range c.Methods {
					refs = append(refs, m.Ref)
				}
			}
			for _, linked := range []bool{false, true} {
				searched := NewEngineOn(tc.classes, Classpath{})
				searched.SetLinked(linked)
				imported := NewEngineOn(tc.classes, Classpath{})
				imported.SetLinked(linked)
				read := 0
				for _, in := range refs {
					searched.ReachNone(in)
					bits, miss, ok := searched.Closure(in)
					from, treeOK := searched.ClosureTree(in)
					if !ok || !treeOK || !imported.SetClosure(in, bits, miss) || !imported.SetClosureTree(in, from) {
						t.Fatalf("linked=%v: %s's search did not move between engines", linked, in)
					}
					for _, sink := range refs {
						fresh := NewEngineOn(tc.classes, Classpath{})
						fresh.SetLinked(linked)
						want := fresh.search(in, sink, nil)
						for name, e := range map[string]*Engine{"searched": searched, "imported": imported} {
							got, ok := e.ClosurePath(in, sink)
							switch {
							case ok && !reflect.DeepEqual(got, want.Path):
								t.Fatalf("linked=%v %s ClosurePath(%s, %s) = %v, search = %v", linked, name, in, sink, got, want.Path)
							case !ok && want.Verdict == ReachableCandidate && sink != in:
								t.Fatalf("linked=%v %s ClosurePath(%s, %s) read no path, search = %v", linked, name, in, sink, want.Path)
							case ok:
								read++
							}
						}
					}
				}
				if read == 0 {
					t.Fatalf("linked=%v: no path was read from a whole search", linked)
				}
			}
		})
	}
}

func TestClosure_SetClosureTreeRefuses(t *testing.T) {
	in := mref("com/acme/app/App", "reachable", "()V")
	src := NewEngineOn(c7Classes(), Classpath{})
	src.ReachNone(in)
	bits, miss, _ := src.Closure(in)
	from, ok := src.ClosureTree(in)
	if !ok {
		t.Fatal("no predecessors to export")
	}
	reached, unreached := -1, -1
	for id, f := range from {
		if f != 0 {
			reached = id
		} else if bits[id/64]&(1<<(id%64)) == 0 {
			unreached = id
		}
	}
	if reached < 0 || unreached < 0 {
		t.Fatalf("fixture needs a reached and an unreached method: %v", from)
	}
	with := func(id int, f uint32) []uint32 {
		out := append([]uint32(nil), from...)
		out[id] = f
		return out
	}
	tests := []struct {
		name    string
		from    []uint32
		install bool // SetClosure first
		ok      bool
	}{
		{"its own export", from, true, true},
		{"no search installed", from, false, false},
		{"short", from[:len(from)-1], true, false},
		{"long", append(append([]uint32(nil), from...), 0), true, false},
		{"predecessor outside the table", with(reached, uint32(len(from))+1), true, false},
		{"predecessor of a method the search never enqueued", with(unreached, 1), true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := NewEngineOn(c7Classes(), Classpath{})
			if tc.install && !dst.SetClosure(in, bits, miss) {
				t.Fatal("SetClosure refused the export")
			}
			if got := dst.SetClosureTree(in, tc.from); got != tc.ok {
				t.Fatalf("SetClosureTree = %v, want %v", got, tc.ok)
			}
			if !tc.ok && dst.HasClosure(in) {
				if _, read := dst.ClosurePath(in, refOf(dst, reached)); read {
					t.Error("a refused tree was read")
				}
			}
		})
	}
}

func refOf(e *Engine, id int) classfile.MethodRef { return e.methodRefs()[id] }
