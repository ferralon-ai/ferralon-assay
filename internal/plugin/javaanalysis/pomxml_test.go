package javaanalysis

import "testing"

// unmarshalPOM honours the POM's declared encoding: the launch-entry reader decodes a non-UTF-8
// POM instead of failing on it. The latin1 case fails if the CharsetReader is reverted to stdlib
// xml.Unmarshal, which rejects the ISO-8859-1 é byte.
func TestUnmarshalPOM_DeclaredCharset(t *testing.T) {
	for _, tc := range []struct {
		name string
		pom  string // raw bytes, in the declared encoding
	}{
		{"latin1", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<project><artifactId>top</artifactId><description>caf\xe9</description></project>"},
		{"utf8 control", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project><artifactId>top</artifactId><description>café</description></project>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p struct {
				ArtifactID  string `xml:"artifactId"`
				Description string `xml:"description"`
			}
			if err := unmarshalPOM([]byte(tc.pom), &p); err != nil {
				t.Fatalf("unmarshalPOM: %v", err)
			}
			if p.ArtifactID != "top" || p.Description != "café" {
				t.Errorf("decoded %+v, want artifactId top and description café", p)
			}
		})
	}
}
