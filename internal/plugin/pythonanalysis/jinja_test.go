package pythonanalysis

import (
	"strings"
	"testing"
)

// airflowRequirements is the verbatim tests/config_templates/requirements.txt from
// ferralon-demo/airflow-experimental-api-rce@baseline — a requirements file rendered
// through Jinja at build time. Read literally (finding F9) its "{% if/else/endif %}"
// control lines became packages named "{%" with empty versions.
const airflowRequirements = `# comments are not ---

pyparsing==2.4.7

# --- considered as packages

{% if params and params.environ and params.environ == 'templated_unit_test' %}
    funcsigs==1.0.2
{% else %}
    funcsigs==0.4
{% endif %}

python-dateutil==2.8.1    # including inline comments
pytz==2020.1
`

// TestParseRequirementSpec_Jinja pins the per-line contract: a Jinja control
// statement or a template-named requirement yields no name (the caller skips it),
// a template-VALUED version leaves the real name UNRESOLVED, and a normal pinned
// requirement that merely sits inside a template block still parses.
func TestParseRequirementSpec_Jinja(t *testing.T) {
	tests := []struct {
		name         string
		spec         string
		wantName     string
		wantVersion  string
		wantResolved bool
	}{
		{"if-statement", "{% if params and params.environ == 'templated_unit_test' %}", "", "", false},
		{"else-statement", "{% else %}", "", "", false},
		{"endif-statement", "{% endif %}", "", "", false},
		{"dangling-close-stmt", "%}", "", "", false},
		{"dangling-close-expr", "}}", "", "", false},
		{"templated-name-bare", "{{ package }}", "", "", false},
		{"templated-name-pinned", "{{ package }}==1.2.3", "", "", false},
		{"templated-version", "somepkg=={{ version }}", "somepkg", "", false},
		{"pinned-inside-block", "funcsigs==1.0.2", "funcsigs", "1.0.2", true},
		{"normal-pin", "pyparsing==2.4.7", "pyparsing", "2.4.7", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, resolved, _ := parseRequirementSpec(strings.TrimSpace(tt.spec))
			if name != tt.wantName || version != tt.wantVersion || resolved != tt.wantResolved {
				t.Fatalf("parseRequirementSpec(%q) = (%q, %q, %v); want (%q, %q, %v)",
					tt.spec, name, version, resolved, tt.wantName, tt.wantVersion, tt.wantResolved)
			}
		})
	}
}

// junkName reports whether a parsed node name is SBOM garbage: empty, or carrying a
// Jinja delimiter. This is the F9 defect signature the fix must eliminate.
func junkName(name string) bool {
	return name == "" || strings.ContainsAny(name, "{}%")
}

// TestResolveRequirements_AirflowJinja runs the real airflow templated file through
// the selected-set parser and asserts zero junk nodes while every genuine pinned
// requirement — including both funcsigs branches (an over-approximation we do NOT
// prune, since evaluating the Jinja condition is out of scope) — survives.
func TestResolveRequirements_AirflowJinja(t *testing.T) {
	reqs := resolveRequirements([]byte(airflowRequirements), nil, nil)

	for _, r := range reqs {
		if junkName(r.Name) {
			t.Errorf("junk SBOM node from Jinja line: name=%q version=%q kind=%v", r.Name, r.Version, r.Kind)
		}
	}

	got := map[string][]string{}
	for _, r := range reqs {
		got[r.Name] = append(got[r.Name], r.Version)
	}
	wantResolved := map[string]string{
		"pyparsing":       "2.4.7",
		"python-dateutil": "2.8.1",
		"pytz":            "2020.1",
	}
	for name, ver := range wantResolved {
		vs, ok := got[name]
		if !ok {
			t.Errorf("legitimate requirement %q was dropped", name)
			continue
		}
		if len(vs) != 1 || vs[0] != ver {
			t.Errorf("%q: got versions %v; want [%q]", name, vs, ver)
		}
	}
	// Both template branches of funcsigs are retained (sound over-approximation).
	if vs := got["funcsigs"]; len(vs) != 2 {
		t.Errorf("funcsigs: got %v; want both branch pins 1.0.2 and 0.4", vs)
	}
}

// TestParseRequirementsTxt_AirflowJinja asserts the advisory (environment-blind)
// path is Jinja-aware too — both parsers share parseRequirementSpec, so the fix
// must clear junk from resolvers as well.
func TestParseRequirementsTxt_AirflowJinja(t *testing.T) {
	deps, ok := parseRequirementsTxt([]byte(airflowRequirements))
	if !ok {
		t.Fatalf("parseRequirementsTxt returned not-ok")
	}
	for _, d := range deps {
		if junkName(d.Coordinate) {
			t.Errorf("junk SBOM coordinate from Jinja line: %q (version %q)", d.Coordinate, d.Version)
		}
	}
	if len(deps) == 0 {
		t.Fatalf("expected the real pinned requirements to survive; got none")
	}
}
