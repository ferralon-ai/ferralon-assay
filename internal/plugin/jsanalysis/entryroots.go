package jsanalysis

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// entryOverrideOf is the override the closure is built under, nil for none. It refuses what the lane
// cannot honour, as the host's routing does: the request crosses a process boundary, and a lane that
// ignored a statement it cannot read would analyse another set of entry points than the caller
// declared.
func entryOverrideOf(o *plugin.EntryOverride) (*plugin.EntryOverride, error) {
	if o == nil {
		return nil, nil
	}
	if o.Lane != "" && o.Lane != plugin.EntryLaneJS {
		return nil, fmt.Errorf("jsanalysis: entry override addresses lane %q, not js", o.Lane)
	}
	if why := plugin.RemovalOnlyRefusal(*o, plugin.JSRemovableKinds, plugin.JSRemovableSelectors...); why != "" {
		return nil, fmt.Errorf("jsanalysis: entry override: %s", why)
	}
	removes := len(o.Exclude) > 0
	for _, ko := range o.Kinds {
		removes = removes || len(ko.Exclude) > 0
	}
	if !removes {
		return nil, nil
	}
	c := *o
	c.Lane = plugin.EntryLaneJS
	return &c, nil
}

// entryTrack follows the entry points the launch texts infer through inferScriptRoots: every root
// the lane would nominate, and which of them the override removes. Every root passes one choke point
// (deny), so the closure, the record and the assumption read one decision.
type entryTrack struct {
	override *plugin.EntryOverride
	inferred map[plugin.EntryRoot]bool
	removed  map[plugin.EntryRoot]bool
}

func newEntryTrack(o *plugin.EntryOverride) *entryTrack {
	return &entryTrack{override: o, inferred: map[plugin.EntryRoot]bool{}, removed: map[plugin.EntryRoot]bool{}}
}

// deny records r as inferred and reports whether the override removes it from the entry points. A
// root with no kind is no entry point a selector can name and is never removed.
func (t *entryTrack) deny(r plugin.EntryRoot) bool {
	if t == nil || r.Kind == "" {
		return false
	}
	t.inferred[r] = true
	if t.override == nil {
		return false
	}
	effective, _, _, _ := plugin.ApplyEntryOverride([]plugin.EntryRoot{r}, *t.override)
	if len(effective) > 0 {
		return false
	}
	t.removed[r] = true
	return true
}

// rootName is how a record names a root: its selector, else "bin:<name>" for a binary whose package
// names no file, which only that selector can address.
func rootName(r plugin.EntryRoot) string {
	switch {
	case r.Selector != "":
		return r.Selector
	case r.Name != "":
		return "bin:" + r.Name
	}
	return r.Origin
}

// byKind lists the names of roots under each overridable kind, sorted, every kind present.
func byKind(roots []plugin.EntryRoot) map[string][]string {
	out := map[string][]string{}
	for _, k := range plugin.JSRemovableKinds {
		out[k] = []string{}
	}
	for _, r := range roots {
		if _, ok := out[r.Kind]; ok {
			out[r.Kind] = append(out[r.Kind], rootName(r))
		}
	}
	for k := range out {
		slices.Sort(out[k])
		out[k] = slices.Compact(out[k])
	}
	return out
}

func sortedRoots(set map[plugin.EntryRoot]bool) []plugin.EntryRoot {
	roots := make([]plugin.EntryRoot, 0, len(set))
	for r := range set {
		roots = append(roots, r)
	}
	slices.SortFunc(roots, func(a, b plugin.EntryRoot) int {
		return strings.Compare(rootName(a)+"\x00"+a.Kind+"\x00"+a.Origin, rootName(b)+"\x00"+b.Kind+"\x00"+b.Origin)
	})
	return roots
}

// record is what the lane tells the report of its entry points: the roots it inferred, those that
// stand, the "!" selectors that removed one, and the ones that matched none. Module roots are not
// listed: every first-party source file is one.
func (t *entryTrack) record() *plugin.EntryRootRecord {
	inferred := sortedRoots(t.inferred)
	effective := inferred
	rec := &plugin.EntryRootRecord{Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceAuto, Input: plugin.LibraryEntrypointsAuto}
	if t.override != nil {
		var unmatched []string
		effective, _, _, unmatched = plugin.ApplyEntryOverride(inferred, *t.override)
		rec.Source, rec.Input, rec.Unmatched = plugin.LibraryEntrypointsSourceDeclared, t.override.Input, unmatched
		rec.Denied = deniedSelectors(*t.override, unmatched)
	}
	rec.Effective = byKind(effective)
	rec.Inferred = byKind(inferred)
	return rec
}

// deniedSelectors are the "!" selectors of o, "!" kept, that took a root out: every one that
// selected a root it addresses.
func deniedSelectors(o plugin.EntryOverride, unmatched []string) []string {
	var out []string
	for _, ko := range append([]plugin.KindOverride{o.KindOverride}, kindOverrides(o)...) {
		for _, sel := range ko.Exclude {
			if !slices.Contains(unmatched, "!"+sel) {
				out = append(out, "!"+sel)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func kindOverrides(o plugin.EntryOverride) []plugin.KindOverride {
	var out []plugin.KindOverride
	for _, k := range slices.Sorted(maps.Keys(o.Kinds)) {
		out = append(out, o.Kinds[k])
	}
	return out
}

// unlistedRecord is the record of a run with no closure to apply its statement to (no dependency
// code was read, or the read ran out); a nil override is the default statement. Nothing was
// inferred and no "!" selector was evaluated, so the record leaves out Unmatched, which says a
// selector matched nothing the lane holds, and Denied, which would tell the customer a selector was
// wrong when it was never tried. Inferred stays absent: the lane reported no guess. The statement
// is recorded all the same, so a later run reads it.
func unlistedRecord(o *plugin.EntryOverride) *plugin.EntryRootRecord {
	rec := newEntryTrack(o).record()
	rec.Unmatched, rec.Denied, rec.Inferred = nil, nil, nil
	return rec
}

// removedNames are the names of the roots the override removed, sorted.
func (t *entryTrack) removedNames() []string {
	var names []string
	for _, r := range sortedRoots(t.removed) {
		names = append(names, rootName(r))
	}
	return slices.Compact(names)
}

// overrideKey is the part of a run-cache key the override contributes: nothing for none.
func overrideKey(o *plugin.EntryOverride) []string {
	if o == nil {
		return nil
	}
	b, err := json.Marshal(o)
	if err != nil {
		return []string{"entry-override", fmt.Sprint(o.Input)}
	}
	return []string{"entry-override", string(b)}
}

// overrideAssumption states the override a package_not_loaded refutation rests on: the removed
// roots are taken to start nothing, so what only they load is taken not to run.
func overrideAssumption(input string, removed []string) string {
	names := removed
	if len(names) > 5 {
		names = append(slices.Clone(names[:5]), fmt.Sprintf("%d more", len(removed)-5))
	}
	return fmt.Sprintf("entrypoints %q: js root(s) %s are not entry points, so nothing they load is taken to run", input, strings.Join(names, ", "))
}
