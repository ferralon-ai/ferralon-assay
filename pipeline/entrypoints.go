package pipeline

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// RouteEntrypoints decides what the lanes do with the caller's entrypoints input, parsed by
// plugin.ParseEntryOverrides. scanLane is the lane the scan runs, the detected language of the
// checkout ("" or a language without an entry-point lane runs none of them).
//
// The go lane takes the clauses its library_entrypoints request field can express, the
// "go:library=" clauses, and the result is that field's value: exactly the statement the same
// clauses written as library-entrypoints make. It is nil when the input states nothing for the go
// library scope. Every other clause fails closed, because no other lane reads an override yet: the
// error says so, and a run that were to proceed would analyse a different set of entry points than
// the caller declared. A clause that asks for something is refused whatever lane the scan runs; a "js:none" clause on a
// Go scan fails the run too.
//
// The js lane takes removal of an inferred script binary or script root: "!js:bin=bin:<name>",
// "!js:npm:<package>/<file>" and the like, handed to the lane by JSEntryOverride, not through the
// library statement. Its module kind is not overridable (first-party modules stay entry points), and
// an allow or a "none" is refused until the lane can resolve what the caller adds.
//
// A bare "auto" changes nothing and is accepted everywhere; so is an explicit "<lane>:auto" or
// "<lane>:<kind>=auto" with no other clause for that lane, which states the default. A bare "none" names all six lanes, so it
// binds the lane the scan runs and no other: that lane must be able to honour it, and the go lane
// cannot, since a lane-wide "none" also drops the go lane's mains and handlers and its request
// field holds library roots only (the error says to write go:library=none). A lane the scan does
// not run is not scanned, so "none" has nothing to bind there.
func RouteEntrypoints(overrides map[string]plugin.EntryOverride, scanLane string) (*plugin.LibraryEntrypoints, error) {
	lanes := make([]string, 0, len(overrides))
	for lane := range overrides {
		lanes = append(lanes, lane)
	}
	slices.Sort(lanes)
	var routed *plugin.LibraryEntrypoints
	for _, lane := range lanes {
		o := overrides[lane]
		switch o.Input {
		case plugin.LibraryEntrypointsAuto:
			continue
		case plugin.LibraryEntrypointsNone:
			if lane != scanLane {
				continue
			}
			why := ""
			switch lane {
			case plugin.EntryLaneGo:
				why = `bare "none" drops every root of the lane and the go lane can drop library roots only; write go:library=none`
			case plugin.EntryLaneJS:
				why = plugin.RemovalOnlyRefusal(o, plugin.JSRemovableKinds, plugin.JSRemovableSelectors...)
			}
			return nil, laneRefusal(lane, why, o.Input)
		}
		if lane == plugin.EntryLaneJS {
			if statesDefault(o) {
				continue
			}
			if ko, ok := o.Kinds[plugin.EntryKindModule]; ok && !statesDefault(plugin.EntryOverride{KindOverride: ko}) {
				return nil, fmt.Errorf("entrypoints: js:module cannot be overridden: first-party modules always stay entry points, and only bin and script roots can be removed (%q)", o.Input)
			}
			if why := plugin.RemovalOnlyRefusal(o, plugin.JSRemovableKinds, plugin.JSRemovableSelectors...); why != "" {
				return nil, laneRefusal(lane, why, o.Input)
			}
			continue
		}
		if lane != plugin.EntryLaneGo {
			if statesDefault(o) {
				continue
			}
			return nil, laneRefusal(lane, "", o.Input)
		}
		le, why := libraryStatement(o)
		if why != "" {
			return nil, laneRefusal(lane, why, o.Input)
		}
		routed = le
	}
	return routed, nil
}

// JSEntryOverride is the js lane's override of overrides, the one reachability_ingress hands the lane,
// or nil when the input states the default for it. RouteEntrypoints has already refused what the
// lane cannot honour.
func JSEntryOverride(overrides map[string]plugin.EntryOverride) *plugin.EntryOverride {
	o, ok := overrides[plugin.EntryLaneJS]
	if !ok || o.Input == plugin.LibraryEntrypointsAuto || statesDefault(o) {
		return nil
	}
	return &o
}

// SameEntryOverride reports whether two statements of one lane's override say the same thing: the
// same scopes, kinds and selectors. Input is the caller's spelling and does not count, so the same
// denies in another order are one statement; a nil override and one that states the default are one.
func SameEntryOverride(a, b *plugin.EntryOverride) bool {
	norm := func(o *plugin.EntryOverride) string {
		if o == nil || statesDefault(*o) {
			return ""
		}
		c := *o
		c.Input = ""
		out, err := json.Marshal(c)
		if err != nil {
			return "\x00" + c.Lane
		}
		return string(out)
	}
	return norm(a) == norm(b)
}

// statesDefault reports whether an override asks for nothing: auto at the lane scope and at every
// kind scope, with no path selected or denied.
func statesDefault(o plugin.EntryOverride) bool {
	plain := func(k plugin.KindOverride) bool {
		return (k.Mode == "" || k.Mode == plugin.LibraryEntrypointsAuto) && len(k.Include) == 0 && len(k.Exclude) == 0
	}
	if !plain(o.KindOverride) {
		return false
	}
	for _, k := range o.Kinds {
		if !plain(k) {
			return false
		}
	}
	return true
}

func laneRefusal(lane, why, input string) error {
	msg := fmt.Sprintf("entrypoints: lane %s does not accept entry-point overrides yet", lane)
	if lane == plugin.EntryLaneJS {
		msg = "entrypoints: lane js cannot honour this clause"
	}
	if why != "" {
		msg += ": " + why
	}
	return fmt.Errorf("%s (%q)", msg, input)
}

// libraryStatement reads a go-lane override as a library-entrypoints statement. The reason is
// non-empty when the override says anything the statement cannot: a lane-wide selector or mode, a
// kind other than library that asks for something, or a library selector that is not a package
// path. A scope that states the default (plain auto) asks for nothing and is skipped, as it is for
// every other lane. The statement is nil for an override that holds no clause for the library scope,
// which reads as auto.
func libraryStatement(o plugin.EntryOverride) (le *plugin.LibraryEntrypoints, why string) {
	const onlyLibrary = "only go:library clauses are accepted"
	if o.Mode != plugin.LibraryEntrypointsAuto || len(o.Include) > 0 || len(o.Exclude) > 0 {
		return nil, onlyLibrary
	}
	for kind, ko := range o.Kinds {
		if kind != plugin.EntryKindLibrary && !statesDefault(plugin.EntryOverride{KindOverride: ko}) {
			return nil, onlyLibrary
		}
	}
	ko, ok := o.Kinds[plugin.EntryKindLibrary]
	if !ok {
		return nil, ""
	}
	for _, sel := range slices.Concat(ko.Include, ko.Exclude) {
		if strings.Contains(sel, ":") {
			return nil, fmt.Sprintf("go:library takes package paths relative to the repository root, not %q", sel)
		}
	}
	st := plugin.LibraryEntrypoints{Mode: ko.Mode, Include: ko.Include, Exclude: ko.Exclude}
	if st.Mode == "" {
		st.Mode = plugin.LibraryEntrypointsAuto
	}
	return &st, ""
}

// LibraryStatementOf is the go library entry-point statement a run assessed with opts makes: the
// WithLibraryEntrypoints one, else the one its entrypoints input routes to the go lane, else auto.
// A scan of another language states none, since no lane but go reads it. It is the statement
// reachability_ingress hands the lane, without the checkout root.
func LibraryStatementOf(opts ...AssessOption) plugin.LibraryEntrypoints {
	var cfg AssessConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.Plugin != nil && cfg.Plugin.Language() != "go" {
		return plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}
	}
	declared := cfg.LibraryEntrypoints
	if declared == nil && len(cfg.Entrypoints) > 0 {
		declared, _ = RouteEntrypoints(cfg.Entrypoints, "")
	}
	if declared == nil {
		return plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}
	}
	return *declared
}

// JSStatementOf is the js lane's entry-point override a run assessed with opts makes: the one its
// entrypoints input states for the lane, nil when it states none. A scan of another language states
// none, since no lane but js reads it. It is the override reachability_ingress hands the lane.
func JSStatementOf(opts ...AssessOption) *plugin.EntryOverride {
	var cfg AssessConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.Plugin != nil && cfg.Plugin.Language() != plugin.EntryLaneJS {
		return nil
	}
	return JSEntryOverride(cfg.Entrypoints)
}

// SameLibraryStatement reports whether two library-entrypoints statements say the same thing: the
// same mode, with the same paths in any order. An unset mode reads as auto.
func SameLibraryStatement(a, b plugin.LibraryEntrypoints) bool {
	norm := func(e plugin.LibraryEntrypoints) string {
		mode := e.Mode
		if mode == "" {
			mode = plugin.LibraryEntrypointsAuto
		}
		inc, exc := slices.Clone(e.Include), slices.Clone(e.Exclude)
		slices.Sort(inc)
		slices.Sort(exc)
		return mode + "|" + strings.Join(slices.Compact(inc), ",") + "|" + strings.Join(slices.Compact(exc), ",")
	}
	return norm(a) == norm(b)
}
