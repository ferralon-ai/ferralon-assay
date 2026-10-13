package goanalysis

import (
	"reflect"
	"strings"
	"testing"
)

// TestFindingsToStacksIgnoresStreamOrder pins that the stacks, and so the path the report cites
// (Paths[0]), depend only on the set of findings govulncheck reports, never on the order it streams
// them in: every permutation of one advisory's findings yields the same stacks, shortest first.
//
// The findings cover the cases a weaker key would let swap: two traces of equal length, two equal
// length traces that differ only in a middle frame, a trace that differs only in whether its top
// frame is a recognized entry, and a module-level finding with no symbol trace.
func TestFindingsToStacksIgnoresStreamOrder(t *testing.T) {
	lines := []string{
		`{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","package":"example.com/vuln","function":"Sink"},{"module":"example.com/app","package":"example.com/app/b","function":"Handle"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}`,
		`{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","package":"example.com/vuln","function":"Sink"},{"module":"example.com/app","package":"example.com/app/a","function":"Handle"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}`,
		`{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","package":"example.com/vuln","function":"Sink"},{"module":"example.com/app","package":"example.com/app","function":"Serve"}]}}`,
		`{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","package":"example.com/vuln","function":"Sink"},{"module":"example.com/app","package":"example.com/app","function":"Serve"},{"module":"example.com/app","package":"example.com/app/c","function":""}]}}`,
		`{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vuln","version":"v1.0.0"}]}}`,
	}

	var want []CallStack
	for _, order := range permutations(len(lines)) {
		stream := make([]string, len(order))
		for i, j := range order {
			stream[i] = lines[j]
		}
		scanned, err := parseFindings([]byte(strings.Join(stream, "\n")), "GO-2099-0001")
		if err != nil {
			t.Fatalf("order %v: parseFindings: %v", order, err)
		}
		got := findingsToStacks(scanned.findings)
		if want == nil {
			want = got
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("order %v: stacks = %+v, want %+v", order, got, want)
		}
		if p, w := stacksToReachPaths(got)[0], stacksToReachPaths(want)[0]; !reflect.DeepEqual(p, w) {
			t.Fatalf("order %v: Paths[0] = %+v, want %+v", order, p, w)
		}
	}

	if len(want) != 4 {
		t.Fatalf("got %d stacks, want 4 (the module-level finding has no symbol trace): %+v", len(want), want)
	}
	for i := 1; i < len(want); i++ {
		if len(want[i].Frames) < len(want[i-1].Frames) {
			t.Errorf("stack %d is shorter than stack %d: %+v", i, i-1, want)
		}
	}
	if first := want[0].Frames; len(first) != 2 || !first[0].IsEntry {
		t.Errorf("first stack = %+v, want the two-frame trace entered at Serve", first)
	}
}

// permutations returns every ordering of 0..n-1.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			q := make([]int, 0, n)
			q = append(q, p[:i]...)
			q = append(q, n-1)
			q = append(q, p[i:]...)
			out = append(out, q)
		}
	}
	return out
}
