package javaanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

var testRoot = classfile.MethodRef{Owner: "com/acme/App", Name: "main", Descriptor: mainDescriptor}

func TestDecodeClosure(t *testing.T) {
	key := closureKey([]string{"k"})
	miss := depreach.Result{Verdict: depreach.Undetermined, SinkPresent: true, HazardOnFrontier: true, HazardWhy: "reflection: x", HazardKinds: []string{"reflection"}, Reached: 7}
	bits := []uint64{5, 1 << 63}
	good, err := encodeClosure(key, testRoot, bits, miss)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(good)
		b[i] ^= 1
		return b
	}
	other := testRoot
	other.Name = "run"
	foreignRoot, _ := encodeClosure(key, other, bits, miss)
	foreignKey, _ := encodeClosure(closureKey([]string{"j"}), testRoot, bits, miss)
	tests := []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"whole entry", good, true},
		{"empty", nil, false},
		{"truncated", good[:len(good)-1], false},
		{"no checksum", good[:len(good)-32], false},
		{"header byte altered", flip(10), false},
		{"bitset byte altered", flip(len(good) - 40), false},
		{"checksum altered", flip(len(good) - 1), false},
		{"another root's entry", foreignRoot, false},
		{"another key's entry", foreignKey, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBits, gotMiss, err := decodeClosure(tc.b, key, testRoot)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
			if tc.ok && (!reflect.DeepEqual(gotBits, bits) || !reflect.DeepEqual(gotMiss, miss)) {
				t.Errorf("round trip: %v %+v", gotBits, gotMiss)
			}
		})
	}
}

// Every input a search reads keys the store: changing any one moves every entry.
func TestClosureStoreForKey(t *testing.T) {
	dir := t.TempDir()
	graph := filepath.Join(dir, "graph.json")
	writeFileT(t, graph, `{"a":1}`)
	ctx := WithRunCacheDir(context.Background(), dir)
	type in struct {
		key     string
		classes []classfile.Class
		graph   string
		mains   []string
		reasons []string
		linked  bool
	}
	base := in{key: "k", classes: []classfile.Class{{Name: "com/acme/App"}}, graph: `{"a":1}`, mains: []string{"com/acme/App"}, linked: true}
	keyOf := func(v in) string {
		t.Helper()
		writeFileT(t, graph, v.graph)
		s := closureStoreFor(ctx, &reachClosure{key: v.key}, &firstPartyBytecode{classes: v.classes}, launchEntry{mains: v.mains, reasons: v.reasons}, v.linked, WithBuildGraph(graph))
		if s == nil {
			t.Fatal("no store under a run cache")
		}
		return s.path(testRoot)
	}
	want := keyOf(base)
	if keyOf(base) != want {
		t.Fatal("key is not stable")
	}
	tests := []struct {
		name string
		mod  func(*in)
	}{
		{"engine inputs", func(v *in) { v.key = "k2" }},
		{"first-party class", func(v *in) { v.classes = []classfile.Class{{Name: "com/acme/App", Abstract: true}} }},
		{"build graph", func(v *in) { v.graph = `{"a":2}` }},
		{"launch mains", func(v *in) { v.mains = []string{"com/acme/Other"} }},
		{"launch reasons", func(v *in) { v.reasons = []string{"r"} }},
		{"linked bit", func(v *in) { v.linked = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			tc.mod(&v)
			if keyOf(v) == want {
				t.Errorf("changing %s keeps the key", tc.name)
			}
		})
	}
	t.Run("root", func(t *testing.T) {
		s := closureStoreFor(ctx, &reachClosure{key: "k"}, &firstPartyBytecode{}, launchEntry{}, true)
		other := testRoot
		other.Descriptor = "()V"
		if s.path(testRoot) == s.path(other) {
			t.Error("two roots share an entry")
		}
	})
	t.Run("build id", func(t *testing.T) {
		s1 := newClosureStore(ctx, "p")
		prev := pluginBuildID
		pluginBuildID = func() string { return "another build" }
		defer func() { pluginBuildID = prev }()
		if s2 := newClosureStore(ctx, "p"); s1.path(testRoot) == s2.path(testRoot) {
			t.Error("another plugin build reads this one's entries")
		}
		pluginBuildID = func() string { return "" }
		if newClosureStore(ctx, "p") != nil {
			t.Error("no build id must turn the cache off")
		}
	})
	t.Run("off without a dir", func(t *testing.T) {
		if closureStoreFor(context.Background(), &reachClosure{}, &firstPartyBytecode{}, launchEntry{}, true) != nil {
			t.Error("a store without a run cache")
		}
	})
}

// A run that reads the searches an earlier process stored answers exactly as one that searched.
func TestBytecodeReach_RunCacheMatchesFresh(t *testing.T) {
	tests := []struct {
		name string
		call func(*cpb) []byte
	}{
		{"path to the sink", callFetch},
		{"empty search", justReturn},
		{"hazard", callUnloaded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(tc.call))
			resetClosureCache()
			fresh := a.reach(netkitSinkID)

			dir := t.TempDir()
			ctx := WithRunCacheDir(context.Background(), dir)
			resetClosureCache()
			first := a.reachCtx(ctx, netkitSinkID)
			entries, _ := filepath.Glob(filepath.Join(dir, "java-closure-*"))
			if len(entries) == 0 {
				t.Fatal("the first process stored no search")
			}
			resetClosureCache() // a later advisory's process
			second := a.reachCtx(ctx, netkitSinkID)
			if !reflect.DeepEqual(first, fresh) || !reflect.DeepEqual(second, fresh) {
				t.Errorf("cached runs differ from a fresh one:\nfresh  %+v\nfirst  %+v\nsecond %+v", fresh, first, second)
			}
		})
	}
}

// A corrupt entry is a miss: the run searches again rather than reading it.
func TestBytecodeReach_CorruptRunCacheEntryIsAMiss(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callUnloaded))
	resetClosureCache()
	fresh := a.reach(netkitSinkID)

	dir := t.TempDir()
	ctx := WithRunCacheDir(context.Background(), dir)
	resetClosureCache()
	a.reachCtx(ctx, netkitSinkID)
	entries, _ := filepath.Glob(filepath.Join(dir, "java-closure-*"))
	if len(entries) == 0 {
		t.Fatal("no entry stored")
	}
	for _, e := range entries {
		b, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		// Clear the stored hazard: read as written, it would let the sink be Searched.
		b = bytes.Replace(b, []byte(`"HazardOnFrontier":true`), []byte(`"HazardOnFrontier":false`), 1)
		if !strings.Contains(string(b), `"HazardOnFrontier":false`) {
			t.Fatalf("entry holds no hazard to clear: %s", b)
		}
		if err := os.WriteFile(e, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resetClosureCache()
	if got := a.reachCtx(ctx, netkitSinkID); !reflect.DeepEqual(got, fresh) {
		t.Errorf("corrupt entry was read:\nfresh %+v\ngot   %+v", fresh, got)
	}
}

// A whole, well-keyed entry is read: a later process answers from it rather than searching.
func TestBytecodeReach_RunCacheEntryIsRead(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callUnloaded))
	dir := t.TempDir()
	ctx := WithRunCacheDir(context.Background(), dir)
	resetClosureCache()
	fresh := a.reachCtx(ctx, netkitSinkID)
	entries, _ := filepath.Glob(filepath.Join(dir, "java-closure-*"))
	if len(entries) == 0 {
		t.Fatal("no entry stored")
	}
	for _, e := range entries {
		b, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		body := b[:len(b)-sha256.Size]
		nl := bytes.IndexByte(body, '\n')
		var hdr closureHeader
		if err := json.Unmarshal(body[:nl], &hdr); err != nil {
			t.Fatal(err)
		}
		hdr.Miss = depreach.Result{Verdict: depreach.NotExploitable}
		h, err := json.Marshal(hdr)
		if err != nil {
			t.Fatal(err)
		}
		body = append(append(h, '\n'), body[nl+1:]...)
		sum := sha256.Sum256(body)
		if err := os.WriteFile(e, append(body, sum[:]...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resetClosureCache()
	if got := a.reachCtx(ctx, netkitSinkID); reflect.DeepEqual(got, fresh) {
		t.Errorf("a rewritten entry was not read: got the searched answer %+v", got)
	}
}

func resetClosureCache() {
	closureCache.Lock()
	closureCache.m = map[string]closureEntry{}
	closureCache.Unlock()
}

// reachCtx is reach under ctx, as the plugin main hands Reachability its run cache.
func (a *appFixture) reachCtx(ctx context.Context, symbols ...string) plugin.ReachabilityResult {
	a.t.Helper()
	graph := a.graph
	if graph == nil {
		graph = graphOption(a.t, a.tool, testModule(a.t, ".", "app", a.deps...))
	}
	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: a.build, Symbols: symbols}, graph)
	if err != nil {
		a.t.Fatalf("Reachability: %v", err)
	}
	return res
}
