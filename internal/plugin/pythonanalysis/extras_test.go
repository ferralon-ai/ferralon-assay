package pythonanalysis

import (
	"reflect"
	"testing"
)

// TestExtrasC2 asserts that a requirement's extras group is resolved against the declared
// Selection: the selected extra's subtree enters the selected set, the unselected one does
// not, and the selection that produced the inclusion is recorded as provenance (C2). The
// provenance assertion (c) is not optional — (a) and (b) alone would also pass a resolver
// that ignored the selection and included every extra.
func TestExtrasC2(t *testing.T) {
	// Selection selects only "security", not "socks".
	got := resolveFixture(t, "extras", nil, []string{"security"})

	r, ok := got["pkg-extras"]
	if !ok {
		t.Fatalf("pkg-extras: missing node")
	}

	// The requirement declares both extras.
	if want := []string{"security", "socks"}; !reflect.DeepEqual(r.Extras, want) {
		t.Errorf("Extras = %v, want %v", r.Extras, want)
	}

	// (a) selected extra present, (b) unselected absent, (c) provenance = the selection that
	// produced it — exactly ["security"], NOT ["security","socks"].
	if want := []string{"security"}; !reflect.DeepEqual(r.SelectedExtras, want) {
		t.Errorf("SelectedExtras = %v, want %v (selected present, unselected absent, provenance recorded)", r.SelectedExtras, want)
	}
	if containsString(r.SelectedExtras, "socks") {
		t.Errorf("unselected extra 'socks' entered the selected set: %v", r.SelectedExtras)
	}

	// Control: flip the selection to "socks" and confirm the selected subtree flips — proving
	// the resolver reads the declared selection rather than hardcoding membership.
	flip := resolveFixture(t, "extras", nil, []string{"socks"})
	if want := []string{"socks"}; !reflect.DeepEqual(flip["pkg-extras"].SelectedExtras, want) {
		t.Errorf("control: SelectedExtras under selection=[socks] = %v, want %v", flip["pkg-extras"].SelectedExtras, want)
	}

	// No selection declared → no extra enters the selected set (but the base requirement does).
	none := resolveFixture(t, "extras", nil, nil)
	if none["pkg-extras"].SelectedExtras != nil {
		t.Errorf("no selection: SelectedExtras = %v, want nil", none["pkg-extras"].SelectedExtras)
	}
	if !none["pkg-extras"].Selected {
		t.Errorf("no selection: base requirement must still be Selected")
	}
}

// TestSelectExtrasUnit exercises the pure selector, including PEP 503 normalization of both
// extra names and selection entries.
func TestSelectExtrasUnit(t *testing.T) {
	cases := []struct {
		name      string
		extras    []string
		selection []string
		want      []string
	}{
		{name: "one of two", extras: []string{"security", "socks"}, selection: []string{"security"}, want: []string{"security"}},
		{name: "declared order preserved", extras: []string{"socks", "security"}, selection: []string{"security", "socks"}, want: []string{"socks", "security"}},
		{name: "normalization", extras: []string{"use_scm"}, selection: []string{"Use-SCM"}, want: []string{"use-scm"}},
		{name: "no match", extras: []string{"a", "b"}, selection: []string{"c"}, want: nil},
		{name: "no selection", extras: []string{"a"}, selection: nil, want: nil},
		{name: "no extras", extras: nil, selection: []string{"a"}, want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := selectExtras(c.extras, c.selection); !reflect.DeepEqual(got, c.want) {
				t.Errorf("selectExtras(%v, %v) = %v, want %v", c.extras, c.selection, got, c.want)
			}
		})
	}
}
