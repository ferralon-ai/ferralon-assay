package pythonanalysis

import "testing"

// A parenthesized specifier written with no space after the name keys on the name alone, on
// every reader: the scanner shared by requirements files, the advisory record, and the
// version-resolution entry.
func TestParenthesizedSpecifierName(t *testing.T) {
	for _, tt := range []struct {
		spec, version string
		resolved      bool
	}{
		{"PyJWT(<2)", "", false},
		{"PyJWT(==2.8.0)", "2.8.0", true},
		{"PyJWT[crypto](>=2,<3)", "", false},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			if name, _, _, _ := parseRequirementSpec(tt.spec); name != "PyJWT" {
				t.Fatalf("parseRequirementSpec name = %q, want PyJWT", name)
			}
			d, ok := declaredDependency(tt.spec, "pyproject.toml")
			if !ok || d.Coordinate != "PyJWT" || d.Version != tt.version || d.Resolved != tt.resolved {
				t.Fatalf("declaredDependency = %+v ok %v, want PyJWT %q resolved %v", d, ok, tt.version, tt.resolved)
			}
			e, _, keep, entryOK := pep508Entry(tt.spec, ".")
			if !keep || !entryOK || e.Coordinate != "PyJWT" || e.Version != tt.version || e.Resolved != tt.resolved {
				t.Fatalf("pep508Entry = %+v keep %v ok %v, want PyJWT %q resolved %v", e, keep, entryOK, tt.version, tt.resolved)
			}
		})
	}
}

// specifierPin resolves only an exact first-clause "==X": an arbitrary-equality "===", a
// prefix match, a range, and an empty specifier all leave the version unresolved.
func TestSpecifierPin(t *testing.T) {
	for _, tt := range []struct {
		specifier, version string
		resolved           bool
	}{
		{"==2.8.0", "2.8.0", true},
		{"==2.8.0,<3", "2.8.0", true},
		{"===2.8.0", "", false},
		{"==2.*", "", false},
		{">=2", "", false},
		{"<3,==2.8.0", "", false},
		{"==", "", false},
		{"", "", false},
	} {
		if v, ok := specifierPin(tt.specifier); v != tt.version || ok != tt.resolved {
			t.Errorf("specifierPin(%q) = %q, %v; want %q, %v", tt.specifier, v, ok, tt.version, tt.resolved)
		}
	}
}

// parsePEP508 drops one leading "v" or "V" on a version, as PEP 440 normalization does.
// Arbitrary equality keeps its version as written. A doubled "v", a "v" with no version, and
// an empty marker after ';' stay malformed, as pip's parser rejects them.
func TestParsePEP508_NormalizableSpellings(t *testing.T) {
	for _, tt := range []struct {
		spec, specifier, marker string
		ok                      bool
	}{
		{"pyjwt>=V2.0", ">=2.0", "", true},
		{"pyjwt>=v2.0", ">=2.0", "", true},
		{"pyjwt==V2.8.0", "==2.8.0", "", true},
		{"pyjwt>=V2,!=v2.1.*", ">=2,!=2.1.*", "", true},
		{"pyjwt===V2.0", "===V2.0", "", true},
		{"pyjwt>=1;", "", "", false},
		{"pyjwt>=1 ;  ", "", "", false},
		{"pyjwt;", "", "", false},
		{"pyjwt @ https://example.com/pyjwt-2.8.0.tar.gz ;", "", "", false},
		{"pyjwt>=1; python_version >= '3.9'", ">=1", "python_version >= '3.9'", true},
		{"pyjwt>=V", "", "", false},
		{"pyjwt>=Vx", "", "", false},
		{"pyjwt>=vv2", "", "", false},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			r, ok := parsePEP508(tt.spec)
			if ok != tt.ok || r.Specifier != tt.specifier || r.Marker != tt.marker {
				t.Fatalf("parsePEP508 = %+v ok %v, want specifier %q marker %q ok %v", r, ok, tt.specifier, tt.marker, tt.ok)
			}
		})
	}
	if d, ok := declaredDependency("pyjwt==V2.8.0", "pyproject.toml"); !ok || d.Version != "2.8.0" || !d.Resolved {
		t.Fatalf("declaredDependency = %+v ok %v, want pyjwt 2.8.0 resolved", d, ok)
	}
}
