package main

import (
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// qualified reports whether a verdict is a positive finding.
func qualified(v report.Verdict) bool {
	return v == report.VerdictReachableCandidate || v == report.VerdictMaliciousPresent
}

// qualifiedSets groups the qualified findings into alias sets, where two findings sharing any id or
// alias are one set, and returns each set's ids, sorted and joined, in sorted order.
func qualifiedSets(fs []report.AdvisoryFinding) []string {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	for _, f := range fs {
		if !qualified(f.Verdict) || f.Advisory.ID == "" {
			continue
		}
		ids := append([]string{f.Advisory.ID}, f.Advisory.Aliases...)
		for _, id := range ids {
			if _, ok := parent[id]; !ok {
				parent[id] = id
			}
		}
		for _, id := range ids[1:] {
			parent[find(id)] = find(ids[0])
		}
	}
	sets := map[string][]string{}
	for id := range parent {
		root := find(id)
		sets[root] = append(sets[root], id)
	}
	out := make([]string, 0, len(sets))
	for _, ids := range sets {
		slices.Sort(ids)
		out = append(out, strings.Join(ids, " / "))
	}
	slices.Sort(out)
	return out
}
