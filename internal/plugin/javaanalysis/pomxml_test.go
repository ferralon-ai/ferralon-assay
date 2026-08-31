package javaanalysis

import (
	"path/filepath"
	"testing"
)

// TestMaven_CharsetDecodedNonLeafPOMRecoversSubtree proves the CharsetReader wiring lets a
// non-UTF-8 non-leaf POM decode and expand its transitive subtree, instead of failing the XML
// decode and degrading to maven_uncached_subtree residue. Each case plants a non-leaf `top` POM
// (declaring an encoding, carrying a non-ASCII byte in <description>, and naming a transitive
// child `leaf`) into the fixture m2 cache. The latin1 case fails if unmarshalPOM's CharsetReader
// is reverted to stdlib xml.Unmarshal (which rejects the ISO-8859-1 é byte).
func TestMaven_CharsetDecodedNonLeafPOMRecoversSubtree(t *testing.T) {
	cases := []struct {
		name   string
		topPOM string // raw bytes of the non-leaf `top` POM, in its declared encoding
	}{
		{
			name: "latin1_non_leaf",
			// ISO-8859-1: the 0xe9 bytes are 'é'. stdlib xml.Unmarshal errors on these.
			topPOM: "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" +
				"<project>\n" +
				"<groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>\n" +
				"<description>caf\xe9 \xe9dition</description>\n" +
				"<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></dependency></dependencies></project>",
		},
		{
			name: "utf8_control",
			topPOM: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
				"<project>\n" +
				"<groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version>\n" +
				"<description>café édition</description>\n" +
				"<dependencies><dependency><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></dependency></dependencies></project>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			m2 := t.TempDir()
			writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.top</groupId><artifactId>top</artifactId><version>1.0</version></dependency></dependencies></project>`)
			writeCachePOM(t, m2, "org.top", "top", "1.0", tc.topPOM)
			writeCachePOM(t, m2, "org.leaf", "leaf", "2.0",
				`<project><groupId>org.leaf</groupId><artifactId>leaf</artifactId><version>2.0</version></project>`)

			inv := toJSON(t, resolveMaven(dir, findPOMs(dir), newMavenCacheAt(m2), nil))
			top := findNode(t, inv, "pkg:maven/org.top/top@1.0")
			leaf := findNode(t, inv, "pkg:maven/org.leaf/leaf@2.0")
			if top == nil || leaf == nil {
				t.Fatalf("expected top+leaf nodes recovered from the %s POM; got %+v", tc.name, inv.Nodes)
			}
			// The non-leaf POM's transitive edge must be recovered — the subtree expanded, not residue.
			found := false
			for _, e := range inv.Edges {
				if e.Parent == top.ID && e.Child == leaf.ID {
					found = true
				}
			}
			if !found {
				t.Errorf("expected transitive edge top→leaf from decoded POM; got %+v", inv.Edges)
			}
			// The false residue trigger is gone: top's subtree is determined, so no uncached residue.
			if hasStr(top.Partiality.Reasons, reasonMavenUncachedSubtree) {
				t.Errorf("decoded non-leaf POM must not emit maven_uncached_subtree residue; got %+v", top.Partiality)
			}
			if !inv.Partiality.Complete {
				t.Errorf("fully-decoded, fully-cached graph should be Complete; got %+v", inv.Partiality)
			}
		})
	}
}
