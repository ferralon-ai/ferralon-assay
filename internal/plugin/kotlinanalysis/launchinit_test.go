package kotlinanalysis

import (
	"reflect"
	"testing"
)

// TestReachability_LaunchClassInitialization: the JVM initializes the launch class before main
// runs (JVMS §5.5), so a sink called from the launch class's static initializer, a superclass's,
// or the companion object's is reachable even when main is empty. Kotlin puts a top-level
// property initializer in the file facade's <clinit> (MainKt), and a companion's init block or
// property initializer in the companion's construction from the outer class's <clinit>.
func TestReachability_LaunchClassInitialization(t *testing.T) {
	emptyMain := func(b *kclassBuilder) { b.addMethod("main", mainStringsDesc, []byte{opReturn}) }
	sinkIn := func(b *kclassBuilder, method string) {
		b.addMethod(method, "()V", append(callsReadValue(b), opReturn))
	}
	tests := []struct {
		name     string
		classes  func(t *testing.T, dir string)
		searched bool
	}{
		{"empty main, no initializer calls the sink: searched", func(t *testing.T, dir string) {
			b := newKClassBuilder()
			emptyMain(b)
			writeClassFixture(t, dir, "com/example/MainKt", b.build("com/example/MainKt", "java/lang/Object"))
			nameLaunchEntry(t, dir, "com.example.MainKt")
		}, true},
		{"top-level property initializer in the MainKt facade's <clinit>", func(t *testing.T, dir string) {
			b := newKClassBuilder()
			emptyMain(b)
			sinkIn(b, "<clinit>")
			writeClassFixture(t, dir, "com/example/MainKt", b.build("com/example/MainKt", "java/lang/Object"))
		}, false},
		{"superclass <clinit>: MainKt extends Base", func(t *testing.T, dir string) {
			base := newKClassBuilder()
			sinkIn(base, "<clinit>")
			writeClassFixture(t, dir, "com/example/Base", base.build("com/example/Base", "java/lang/Object"))
			b := newKClassBuilder()
			emptyMain(b)
			writeClassFixture(t, dir, "com/example/MainKt", b.build("com/example/MainKt", "com/example/Base"))
		}, false},
		{"companion init block: App$Companion.<init>", func(t *testing.T, dir string) {
			b := newKClassBuilder()
			emptyMain(b)
			writeClassFixture(t, dir, "com/example/App", b.build("com/example/App", "java/lang/Object"))
			c := newKClassBuilder()
			sinkIn(c, "<init>")
			writeClassFixture(t, dir, "com/example/App$Companion", c.build("com/example/App$Companion", "java/lang/Object"))
		}, false},
		{"companion static initializer: App$Companion.<clinit>", func(t *testing.T, dir string) {
			b := newKClassBuilder()
			emptyMain(b)
			writeClassFixture(t, dir, "com/example/App", b.build("com/example/App", "java/lang/Object"))
			c := newKClassBuilder()
			sinkIn(c, "<clinit>")
			writeClassFixture(t, dir, "com/example/App$Companion", c.build("com/example/App$Companion", "java/lang/Object"))
		}, false},
		{"companion of a class with no main is not a root: searched", func(t *testing.T, dir string) {
			b := newKClassBuilder()
			emptyMain(b)
			writeClassFixture(t, dir, "com/example/App", b.build("com/example/App", "java/lang/Object"))
			c := newKClassBuilder()
			sinkIn(c, "<init>")
			writeClassFixture(t, dir, "com/example/Other$Companion", c.build("com/example/Other$Companion", "java/lang/Object"))
			nameLaunchEntry(t, dir, "com.example.App")
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := gradleJacksonBuild(t, "")
			tt.classes(t, dir)
			res := reach(t, dir, readValueSink)
			if tt.searched {
				if !reflect.DeepEqual(res.Searched, []string{readValueSink}) || len(res.Paths) > 0 {
					t.Fatalf("Searched = %v, paths %v, want the sink searched (%+v)", res.Searched, res.Paths, res.Partiality)
				}
				return
			}
			if len(res.Searched) > 0 {
				t.Errorf("Searched = %v: an initializer that runs before main calls the sink", res.Searched)
			}
			if len(res.Paths) != 1 {
				t.Errorf("want one candidate path from the initializer, got %v (%+v)", res.Paths, res.Partiality)
			}
		})
	}
}
