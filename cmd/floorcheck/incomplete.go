package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// inventoryTolerance is how many of the ledger's distinct component instances the scan's package
// inventory may lack before the scan counts as incomplete. The ledger also names instances the
// comparator saw and the inventory may list under another version, so a few is not a short scan.
const inventoryTolerance = 3

// ledgerInstances is the distinct resolved package instances (module@version) the ledger's rows name,
// without the standard library and toolchain, which no package inventory lists.
func ledgerInstances(l Ledger) []string {
	var out []string
	for _, r := range l.Rows {
		if module, _ := moduleOf(r.Package); r.Package == "-" || slices.Contains(toolchainModules, module) {
			continue
		}
		out = append(out, r.Package)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// incompleteScan is the failures of a showcase scan whose report shows it did not see the whole
// build, one line each: an empty package inventory or one short of the ledger's instances by more than
// inventoryTolerance, a wrapped tool that failed, and fewer ledger rows answered (matched) than the
// ledger holds. A scan cut short at its time limit is the scan_truncated failure, raised for every
// scan. A clean-looking report from a broken toolchain is the case these exist for: it has no
// findings to differ from, only a ledger to fall short of.
func incompleteScan(r report.Report, l Ledger, matched int) []Failure {
	var out []Failure
	add := func(detail string, findings ...string) {
		out = append(out, Failure{Kind: KindIncompleteScan, Detail: detail, Findings: findings})
	}
	inv := map[string]bool{}
	for _, p := range r.SBOM.Packages {
		inv[p.Name+"@"+p.Version] = true
	}
	want := ledgerInstances(l)
	switch short := slices.DeleteFunc(slices.Clone(want), func(p string) bool { return inv[p] }); {
	case len(r.SBOM.Packages) == 0:
		add("the scan's package inventory is empty: it resolved no dependencies, so its rows say nothing about this build")
	case len(short) > inventoryTolerance:
		add(fmt.Sprintf("the scan's package inventory (%d packages) lacks %d of the ledger's %d component instances, more than the tolerance of %d",
			len(r.SBOM.Packages), len(short), len(want), inventoryTolerance), short...)
	}
	for _, n := range r.Partiality {
		if n.Reason == plugin.PartialReasonToolFailure || strings.HasPrefix(n.Reason, plugin.PartialReasonToolFailure+":") {
			detail := "a tool or toolchain failure occurred during the scan: " + n.Reason
			if n.Detail != "" {
				detail += ": " + n.Detail
			}
			add(detail)
		}
	}
	if matched < len(l.Rows) {
		add(fmt.Sprintf("the scan answers %d of the ledger's %d rows", matched, len(l.Rows)))
	}
	return out
}
