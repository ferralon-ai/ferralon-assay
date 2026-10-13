package kotlinanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// enginehole_test.go: the six probes under which the dependency engine searched
// hazard-free and Reachability listed the sink Searched although the JDK can run it.
// D lives in the cached dependency org.d:d:1.0; main never calls the sink directly.

const (
	opNew           = 0xBB
	opDup           = 0x59
	opInvokeSpecial = 0xB7
	holeD           = "org/d/D"
)

// newInstance encodes `new owner; dup; invokespecial owner.<init>()V`.
func (b *kclassBuilder) newInstance(owner string) []byte {
	code := append([]byte{opNew}, be2(b.class(owner))...)
	code = append(code, opDup, opInvokeSpecial)
	return append(code, be2(b.methodref(owner, "<init>", "()V"))...)
}

// buildWithInterfaces is build plus an interfaces table, spliced after super_class.
func (b *kclassBuilder) buildWithInterfaces(this, super string, ifaces ...string) []byte {
	idx := make([]uint16, len(ifaces))
	for i, n := range ifaces {
		idx[i] = b.class(n)
	}
	raw := b.build(this, super)
	off := 10
	for _, e := range b.entries {
		off += len(e)
	}
	off += 6 // access_flags, this_class, super_class
	table := be2(uint16(len(ifaces)))
	for _, i := range idx {
		table = append(table, be2(i)...)
	}
	out := append([]byte{}, raw[:off]...)
	out = append(out, table...)
	return append(out, raw[off+2:]...)
}

// holeDClass emits org/d/D with an empty <init>, an empty finalize unless the row
// overrides it, and method name+desc calling the jackson sink.
func holeDClass(super, name, desc string, ifaces ...string) []byte {
	b := newKClassBuilder()
	b.addMethod("<init>", "()V", []byte{opReturn})
	if name != "finalize" {
		b.addMethod("finalize", "()V", []byte{opReturn})
	}
	b.addMethod(name, desc, append(b.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn))
	return b.buildWithInterfaces(holeD, super, ifaces...)
}

func TestReachability_EngineHolesNeverSearched(t *testing.T) {
	tests := []struct {
		name       string
		d          []byte // nil: no org.d dependency class
		main       func(b *kclassBuilder) []byte
		wantPath   bool
		wantReason string
	}{
		{
			name: "1 DriverManager.getConnection runs the driver's connect",
			d:    holeDClass("java/lang/Object", "connect", "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;", "java/sql/Driver"),
			main: func(b *kclassBuilder) []byte {
				return b.invokeStatic("java/sql/DriverManager", "getConnection", "(Ljava/lang/String;)Ljava/sql/Connection;")
			},
			wantPath: true,
		},
		{
			name: "2 ServiceLoader.loadInstalled",
			main: func(b *kclassBuilder) []byte {
				return b.invokeStatic("java/util/ServiceLoader", "loadInstalled", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;")
			},
			wantReason: plugin.PartialReasonReflection,
		},
		{
			name:     "3 new D() runs D.finalize",
			d:        holeDClass("java/lang/Object", "finalize", "()V"),
			main:     func(b *kclassBuilder) []byte { return b.newInstance(holeD) },
			wantPath: true,
		},
		{
			name: "4 TimerTask subclass handed to runAsync(Runnable)",
			d:    holeDClass("java/util/TimerTask", "run", "()V"),
			main: func(b *kclassBuilder) []byte {
				code := b.newInstance(holeD)
				return append(code, b.invokeStatic("java/util/concurrent/CompletableFuture", "runAsync",
					"(Ljava/lang/Runnable;)Ljava/util/concurrent/CompletableFuture;")...)
			},
			wantReason: plugin.PartialReasonReachabilityUndetermined,
		},
		{
			name: "5 java.beans.Beans.instantiate",
			main: func(b *kclassBuilder) []byte {
				return b.invokeStatic("java/beans/Beans", "instantiate", "(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Object;")
			},
			wantReason: plugin.PartialReasonReflection,
		},
		{
			name: "6 java.rmi.Naming.lookup deserializes D",
			d:    holeDClass("java/lang/Object", "readObject", "(Ljava/io/ObjectInputStream;)V", "java/io/Serializable"),
			main: func(b *kclassBuilder) []byte {
				return b.invokeStatic("java/rmi/Naming", "lookup", "(Ljava/lang/String;)Ljava/rmi/Remote;")
			},
			wantReason: plugin.PartialReasonReflection,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := gradleJacksonBuild(t, `    implementation("org.d:d:1.0")`)
			d := tt.d
			if d == nil {
				d = holeDClass("java/lang/Object", "unused", "()V")
			}
			writeGradleCacheJar(t, dir, "org.d", "d", "1.0", map[string][]byte{holeD: d})
			writeMain(t, dir, tt.main)
			res := reach(t, dir, readValueSink)
			if contains(res.Searched, readValueSink) {
				t.Fatalf("sink listed Searched (paths %+v, partiality %+v)", res.Paths, res.Partiality)
			}
			if got := len(res.Paths) == 1; got != tt.wantPath {
				t.Errorf("path found = %v, want %v (partiality %+v)", got, tt.wantPath, res.Partiality)
			}
			if tt.wantReason != "" && !hasReason(res.Partiality, tt.wantReason) {
				t.Errorf("reasons %v missing %q", res.Partiality.Reasons, tt.wantReason)
			}
		})
	}
}
