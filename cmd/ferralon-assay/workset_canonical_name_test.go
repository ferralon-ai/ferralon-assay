package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

type factsByID map[string]pipeline.AdvisoryFacts

func (f factsByID) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	facts, ok := f[id]
	return facts, ok
}

// An advisory and a manifest can spell one PyPI or NuGet package differently; admission compares the
// names the way that ecosystem's version resolver does, so the advisory is admitted and its version
// resolves. Other ecosystems compare names exactly.
func TestAdmitByInventory_CanonicalNames(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		purlType  string
		advisory  string
		dep       string
		want      bool
	}{
		{"PyPI underscore against hyphen", ecosystemPyPI, "pypi", "python-multipart", "python_multipart", true},
		{"PyPI case", ecosystemPyPI, "pypi", "pyjwt", "PyJWT", true},
		{"PyPI dot and separator runs", ecosystemPyPI, "pypi", "zope.interface", "Zope__Interface", true},
		{"PyPI different package", ecosystemPyPI, "pypi", "python-multipart", "multipart", false},
		{"NuGet case", ecosystemNuGet, "nuget", "Newtonsoft.Json", "newtonsoft.json", true},
		{"NuGet separators are significant", ecosystemNuGet, "nuget", "Microsoft.Data.SqlClient", "Microsoft-Data-SqlClient", false},
		{"npm case is significant", ecosystemNPM, "npm", "JSONStream", "jsonstream", false},
		{"npm exact", ecosystemNPM, "npm", "lodash", "lodash", true},
		{"Maven case is significant", ecosystemMaven, "maven", "org.yaml:snakeyaml", "org.yaml:SnakeYAML", false},
		{"Go case is significant", ecosystemGo, "golang", "github.com/BurntSushi/toml", "github.com/burntsushi/toml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corpus := factsByID{"ADV-1": {
				Coordinate: tt.advisory,
				PURL:       "pkg:" + tt.purlType + "/" + tt.advisory,
			}}
			if tt.purlType == "golang" {
				corpus["ADV-1"] = pipeline.AdvisoryFacts{Module: tt.advisory, PURL: "pkg:golang/" + tt.advisory}
			}
			pkgs := []report.Package{{Ecosystem: tt.ecosystem, Name: tt.dep, Version: "1.0.0"}}
			got, noCoords, unresolvable := admitByInventory([]string{"ADV-1"}, nil, corpus, tt.ecosystem, pkgs, nil)
			if len(noCoords) != 0 || len(unresolvable) != 0 {
				t.Fatalf("noCoordinates %q, unresolvable %q; want neither", noCoords, unresolvable)
			}
			if admitted := len(got) == 1; admitted != tt.want {
				t.Errorf("advisory naming %q against dependency %q: admitted = %v, want %v", tt.advisory, tt.dep, admitted, tt.want)
			}
		})
	}
}
