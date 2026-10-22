package depreach

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestPlatformMethods_Pinned pins the generated table: the sha256 of its sorted entries
// (one "type supers methods" line each), its size, and entries the rule depends on.
func TestPlatformMethods_Pinned(t *testing.T) {
	if n := len(platformMethods); n != 1100 {
		t.Errorf("len(platformMethods) = %d, want 1100", n)
	}
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(platformMethods)) {
		b.WriteString(k + "\t" + platformMethods[k].supers + "\t" + platformMethods[k].methods + "\n")
	}
	const want = "b00ea5af7c40fab58e6471932884811a93b81951e4ddeea54a5e4a325fb1665a"
	sum := sha256.Sum256([]byte(b.String()))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("sha256 of the sorted entries = %s, want %s: regenerate as the header describes", got, want)
	}
	if _, ok := platformMethods[objectClass]; ok {
		t.Errorf("platformMethods lists %s; objectOverridable covers it", objectClass)
	}
	for typ, sig := range map[string]string{
		"java/util/concurrent/CopyOnWriteArrayList": "iterator()",
		"java/util/Hashtable":                       "get(Ljava/lang/Object;)",
		"java/util/List":                            "get(I)",
		"java/lang/Thread$UncaughtExceptionHandler": "uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)",
		"java/nio/charset/spi/CharsetProvider":      "charsetForName(Ljava/lang/String;)",
	} {
		if !platformSigs()[typ][sig] {
			t.Errorf("platformMethods[%s] lacks %s", typ, sig)
		}
	}
	for _, sig := range []string{"getClass()", "notify()", "wait()"} {
		for typ, sigs := range platformSigs() {
			if sigs[sig] {
				t.Errorf("platformMethods[%s] lists final Object method %s", typ, sig)
			}
		}
	}
}
