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

// A requirement's specifier set takes one trailing comma, as packaging's Requirement does; any
// other empty clause is invalid. Each row's expectation is packaging 26.3's result.
func TestParsePEP508SpecifierCommas(t *testing.T) {
	for _, tt := range []struct {
		req, spec string
		ok        bool
	}{
		{"foo>=1.0,", ">=1.0", true},
		{"foo >= 1.0 ,", ">=1.0", true},
		{"foo>=1.0,<2,", ">=1.0,<2", true},
		{"foo (>=1.0,)", ">=1.0", true},
		{`foo>=1.0,;python_version>"3"`, ">=1.0", true},
		{"foo[x]>=1,", ">=1", true},
		{"foo>=1,\t", ">=1", true},
		{"foo (,)", "", false},
		{"foo>=1.0,,", "", false},
		{"foo>=1.0, ,", "", false},
		{"foo>=1.0,,<2", "", false},
		{"foo>=1.0, ,<2", "", false},
		{"foo,>=1.0", "", false},
		{"foo,", "", false},
	} {
		r, ok := parsePEP508(tt.req)
		if ok != tt.ok || ok && r.Specifier != tt.spec {
			t.Errorf("parsePEP508(%q) = %q, %v; want %q, %v", tt.req, r.Specifier, ok, tt.spec, tt.ok)
		}
	}
	// The trailing-comma drop needs a clause before it: an empty set is not a specifier.
	if norm, ok := normalizeSpecifier(" "); ok {
		t.Errorf(`normalizeSpecifier(" ") = %q, true; want false`, norm)
	}
	if d, ok := declaredDependency("foo==2.8.0,", "requirements.txt"); !ok || d.Version != "2.8.0" || !d.Resolved {
		t.Errorf(`declaredDependency("foo==2.8.0,") = %+v, %v; want 2.8.0 resolved`, d, ok)
	}
}

// A requirement line ending in a trailing comma reads as a requirement file, so a file of
// such lines is a manifest candidate.
func TestPyCandidateTrailingCommaLine(t *testing.T) {
	if _, ok := pyCandidate("svc/deps", []byte("foo >= 1.0,\n")); !ok {
		t.Error(`pyCandidate("svc/deps", "foo >= 1.0,") is not a candidate; pip installs from it`)
	}
}
