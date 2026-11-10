package depreach

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// assertMemoMatchesFresh asks one engine every (ingress, sink) pair over the fixture's
// methods, so each ingress's closure is filled by the first sink and answers the rest,
// and requires each answer to equal a fresh engine's.
func assertMemoMatchesFresh(t *testing.T, classes []classfile.Class, cp Classpath, linked bool) {
	t.Helper()
	var refs []classfile.MethodRef
	for _, c := range classes {
		for _, m := range c.Methods {
			refs = append(refs, m.Ref)
		}
	}
	shared := NewEngineOn(classes, cp)
	shared.SetLinked(linked)
	for _, in := range refs {
		for _, sink := range refs {
			fresh := NewEngineOn(classes, cp)
			fresh.SetLinked(linked)
			want := fresh.Reach(in, sink)
			if got := shared.Reach(in, sink); !reflect.DeepEqual(got, want) {
				t.Fatalf("Reach(%s, %s) after earlier sinks = %+v, fresh engine = %+v", in, sink, got, want)
			}
		}
	}
}

// TestReach_ClosureMemo: rows the hole tables don't hold. Each runs every (ingress, sink)
// pair on one engine against a fresh engine, then checks the closure the row names.
func TestReach_ClosureMemo(t *testing.T) {
	unknown := mref("com/acme/Nowhere", "go", "()V")
	for _, tc := range []struct {
		name    string
		classes []classfile.Class
		ingress classfile.MethodRef
		sinks   []classfile.MethodRef // asked in order on one engine
		want    []Verdict
	}{
		{
			name:    "C7: a reflection hazard, then the sink the closure met, then a decoy it did not",
			classes: c7Classes(),
			ingress: mref("com/acme/app/App", "reachable", "()V"),
			sinks: []classfile.MethodRef{
				mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc),
				mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
				mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc),
			},
			want: []Verdict{NotExploitable, ReachableCandidate, NotExploitable},
		},
		{
			name:    "C7: the closure's hazard answers every sink it did not meet",
			classes: c7Classes(),
			ingress: mref("com/acme/app/App", "dynamic", "()V"),
			sinks: []classfile.MethodRef{
				mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
				mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc),
			},
			want: []Verdict{Undetermined, Undetermined},
		},
		{
			name:    "the ingress itself as the sink: not enqueued, so not reached",
			classes: c7Classes(),
			ingress: mref("com/acme/app/App", "unreachable", "()V"),
			sinks: []classfile.MethodRef{
				mref("com/acme/app/App", "unreachable", "()V"),
				mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc),
			},
			want: []Verdict{NotExploitable, ReachableCandidate},
		},
		{
			name:    "an unknown ingress stays Undetermined with the sink present",
			classes: c7Classes(),
			ingress: unknown,
			sinks: []classfile.MethodRef{
				mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc),
				mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc),
			},
			want: []Verdict{Undetermined, Undetermined},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngineOn(tc.classes, Classpath{})
			for i, sink := range tc.sinks {
				r := e.Reach(tc.ingress, sink)
				if r.Verdict != tc.want[i] {
					t.Errorf("sink %d %s: verdict = %s, want %s (hazard=%q)", i, sink, r.Verdict, tc.want[i], r.HazardWhy)
				}
				if !r.SinkPresent {
					t.Errorf("sink %d %s: SinkPresent = false", i, sink)
				}
			}
			assertMemoMatchesFresh(t, tc.classes, Classpath{}, false)
		})
	}
}

// TestReach_ClosureMemoHazardKindsOwned: a caller that edits one answer's HazardKinds
// does not edit the closure's.
func TestReach_ClosureMemoHazardKindsOwned(t *testing.T) {
	e := NewEngineOn(c7Classes(), Classpath{})
	in := mref("com/acme/app/App", "dynamic", "()V")
	first := e.Reach(in, mref("com/evil/netkit/UrlFetcher", "fetch", sinkDesc))
	if len(first.HazardKinds) == 0 {
		t.Fatal("no hazard kinds to edit")
	}
	first.HazardKinds[0] = "edited"
	if again := e.Reach(in, mref("com/evil/netkit/UrlFetcher", "fetch", decoyDesc)); again.HazardKinds[0] == "edited" {
		t.Fatalf("closure hazard kinds shared with a caller: %v", again.HazardKinds)
	}
}
