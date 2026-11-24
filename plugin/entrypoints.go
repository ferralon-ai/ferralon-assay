package plugin

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Entry-point lanes an override clause can name.
const (
	EntryLaneGo     = "go"
	EntryLaneJava   = "java"
	EntryLaneKotlin = "kotlin"
	EntryLaneJS     = "js"
	EntryLanePython = "python"
	EntryLaneDotnet = "dotnet"
)

// Entry-root kinds. A lane reports the kinds it infers; EntryKindDeclared is the kind of a root
// the caller added that no inference produced, and is never written in an override.
const (
	EntryKindModule   = "module"
	EntryKindBin      = "bin"
	EntryKindScript   = "script"
	EntryKindMain     = "main"
	EntryKindLibrary  = "library"
	EntryKindTest     = "test"
	EntryKindHandler  = "handler"
	EntryKindRuntime  = "runtime"
	EntryKindDeclared = "declared"
)

// EntryOriginDeclared is the Origin of a root added by an override's lane scope; a root added by a
// kind scope has the Origin "entrypoints:<kind>", which keeps the kind the caller declared it for.
const EntryOriginDeclared = "entrypoints"

// entryLaneKinds lists the kinds each lane infers, and so the kinds an override clause may qualify.
var entryLaneKinds = map[string][]string{
	EntryLaneGo:     {EntryKindMain, EntryKindLibrary, EntryKindHandler},
	EntryLaneJava:   {EntryKindMain, EntryKindHandler},
	EntryLaneKotlin: {EntryKindMain, EntryKindHandler},
	EntryLaneJS:     {EntryKindModule, EntryKindBin, EntryKindScript},
	EntryLanePython: {EntryKindHandler, EntryKindMain},
	EntryLaneDotnet: {EntryKindMain, EntryKindRuntime, EntryKindHandler},
}

// entrySelectorPrefixes are the non-path selector forms. A selector carrying one is matched as an
// opaque name, not a repository path.
var entrySelectorPrefixes = []string{"npm:", "bin:", "class:", "type:", "asm:"}

// EntryRoot is one entry point of a lane's analysis: a place execution can begin.
type EntryRoot struct {
	// Lane is the analysis lane that infers the root ("js").
	Lane string `json:"lane"`
	// Kind is one of the EntryKind* constants.
	Kind string `json:"kind"`
	// Selector is what a caller writes to allow or deny the root: the repo-relative,
	// slash-separated path of the root file, never absolute; "npm:<package>/<path>" for a root
	// inside an installed package; "class:<FQN>", "type:<FQN>" or "asm:<Assembly>" for a root known
	// only from bytecode or IL.
	Selector string `json:"selector"`
	// Name is an optional human label, such as a bin's name; "bin:<Name>" also selects the root.
	Name string `json:"name,omitempty"`
	// Origin is where the root was inferred from, such as "<dir>/package.json#scripts.<name>".
	Origin string `json:"origin,omitempty"`
}

// KindOverride is one scope of an override: the whole lane, or the roots of one kind.
type KindOverride struct {
	// Mode is LibraryEntrypointsAuto, LibraryEntrypointsNone or LibraryEntrypointsPaths. Empty reads
	// as auto in the lane scope and, in a Kinds entry, as the lane scope's mode: a kind scope that
	// only denies leaves the base of its roots as the lane scope sets it.
	Mode string `json:"mode,omitempty"`
	// Include allows selectors; Exclude denies them. Both hold normalised selectors.
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// EntryOverride is the caller's statement of which entry points one lane analyses. It is
// configuration handed to the lane, never read from the tree. The zero value is auto: every
// inferred root stands.
//
// The embedded KindOverride is the lane scope, addressing every root of the lane. Kinds holds a scope
// for each kind the caller qualified with "kind=", addressing the roots of that kind. A root is
// governed by both: its base is its kind scope's Mode when that scope names one and the lane scope's
// Mode otherwise, its allows are the selectors of both scopes, and its denies are the selectors of
// both scopes. So a deny always applies, whichever scope holds it, and a kind scope that only denies
// never turns auto back on.
//
// An allow that matches no inferred root becomes a declared root (see ApplyEntryOverride). The
// matcher cannot tell a root the caller declared from a typo, so the lane owns that check: it MUST
// resolve every added root against the scanned tree and treat one it cannot resolve as an unmatched
// selector, reported and withholding that lane's clears. Under a nominated list a typo also denies
// the inferred roots it was meant to keep, which is why an unresolved added root cannot stand.
type EntryOverride struct {
	// Lane is the lane the override addresses; ApplyEntryOverride leaves the roots of other lanes
	// untouched. Empty addresses every lane.
	Lane string `json:"lane,omitempty"`
	KindOverride
	Kinds map[string]KindOverride `json:"kinds,omitempty"`
	// Input is the lane's clauses as the caller wrote them, joined by commas.
	Input string `json:"input,omitempty"`
}

// ParseEntryOverrides reads the entrypoints input and returns one override per lane it addresses. A
// lane the input does not mention is absent from the result and reads as auto.
//
// The grammar is library-entrypoints' own (ParseLibraryEntrypoints has the base rules) with a
// required "lane:" on every selector and an optional "kind=" after it: "js:none", "!go:cmd/debugtool",
// "js:module=none", "go:main=cmd/traefik". Tokens are separated by commas or whitespace.
//
// Within one scope (a lane, or one kind of it), "auto" keeps the inferred roots, "none" drops them, a
// selector allows a root, and "!selector" denies one. Naming a selector without "auto" nominates the
// roots outright, and denies alone keep auto. A selector is a repository-relative path ("./pkg/..."
// reads as "pkg"), "npm:<package>[/<path>]", "bin:<Name>", "class:<FQN>", "type:<FQN>" or
// "asm:<Assembly>".
//
// A bare "auto" or "none", with no lane, addresses every lane and must be the only token. Empty
// input is auto and returns an empty map. The input is rejected when a selector names no lane, a lane
// or kind is unknown, a lane does not infer the kind, "none" stands beside another clause of its
// scope, "!" is applied to auto or none, a selector is both allowed and denied, within one scope or
// between the lane scope and a kind scope, or a path is absolute, leaves the repository root, or contains a backslash.
func ParseEntryOverrides(s string) (map[string]EntryOverride, error) {
	tokens := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	type laneState struct {
		scopes map[string]*entryScope
		input  []string
	}
	lanes := map[string]*laneState{}
	global := ""
	for _, t := range tokens {
		body, denied := strings.CutPrefix(t, "!")
		lane, kind, target, err := splitEntryClause(body)
		if err != nil {
			return nil, fmt.Errorf("entrypoints: %q: %w", t, err)
		}
		if low := strings.ToLower(target); low != target && (low == LibraryEntrypointsAuto || low == LibraryEntrypointsNone) {
			return nil, fmt.Errorf("entrypoints: %q: write %s in lower case", t, low)
		}
		if lane == "" {
			switch {
			case target != LibraryEntrypointsAuto && target != LibraryEntrypointsNone:
				return nil, fmt.Errorf("entrypoints: %q: a selector must name its lane; write it as <lane>:%s, for example js:%s (lanes: %s)",
					t, strings.TrimPrefix(body, "!"), strings.TrimPrefix(body, "!"), strings.Join(sortedKeys(entryLaneKinds), ", "))
			case denied:
				return nil, fmt.Errorf("entrypoints: %q: ! applies to a selector, not %s", t, target)
			case len(tokens) > 1:
				return nil, fmt.Errorf("entrypoints: %q: bare %s addresses every lane and stands alone; write <lane>:%s to address one lane", t, target, target)
			}
			global = target
			continue
		}
		st := lanes[lane]
		if st == nil {
			st = &laneState{scopes: map[string]*entryScope{}}
			lanes[lane] = st
		}
		st.input = append(st.input, t)
		sc := st.scopes[kind]
		if sc == nil {
			sc = &entryScope{}
			st.scopes[kind] = sc
		}
		switch target {
		case LibraryEntrypointsAuto, LibraryEntrypointsNone:
			if denied {
				return nil, fmt.Errorf("entrypoints: %q: ! applies to a selector, not %s", t, target)
			}
			if target == LibraryEntrypointsAuto {
				sc.auto = true
			} else {
				sc.none = true
			}
			continue
		}
		sel, err := cleanEntrySelector(target)
		if err != nil {
			return nil, fmt.Errorf("entrypoints: %q: %w", t, err)
		}
		if denied {
			sc.exclude = append(sc.exclude, sel)
		} else {
			sc.include = append(sc.include, sel)
		}
	}

	out := map[string]EntryOverride{}
	if global != "" {
		for _, lane := range sortedKeys(entryLaneKinds) {
			out[lane] = EntryOverride{Lane: lane, KindOverride: KindOverride{Mode: global}, Input: global}
		}
		return out, nil
	}
	for _, lane := range sortedKeys(lanes) {
		st := lanes[lane]
		o := EntryOverride{Lane: lane, Input: strings.Join(st.input, ","), KindOverride: KindOverride{Mode: LibraryEntrypointsAuto}}
		for _, kind := range sortedKeys(st.scopes) {
			sc := st.scopes[kind]
			name := lane
			if kind != "" {
				name = lane + ":" + kind
			}
			ko, err := sc.resolve(name, kind != "")
			if err != nil {
				return nil, fmt.Errorf("entrypoints: %w", err)
			}
			if kind == "" {
				o.KindOverride = ko
				continue
			}
			if o.Kinds == nil {
				o.Kinds = map[string]KindOverride{}
			}
			o.Kinds[kind] = ko
			if both := append(intersectSorted(o.Include, ko.Exclude), intersectSorted(o.Exclude, ko.Include)...); len(both) > 0 {
				return nil, fmt.Errorf("entrypoints: %s: %q is both allowed and denied", name, both[0])
			}
		}
		out[lane] = o
	}
	return out, nil
}

// EntryOverrideForLibraryEntrypoints is the override the library-entrypoints input stands for: its
// parsed statement applied to the library roots of the go lane, as the clauses
// "go:library=<token>" for each token of the input, for every token ParseEntryOverrides accepts.
// The legacy parser also accepts tokens the new grammar rejects: "NONE" and "Auto" (case) and
// tokens whose first path segment holds a colon ("a:b", "library:x"). The override applies them as
// the legacy parser does; only Input does not re-parse, so a caller that re-parses Input must treat
// a parse error there as the legacy token being invalid. Input holds the clauses rendered from the
// parsed statement.
func EntryOverrideForLibraryEntrypoints(le LibraryEntrypoints) EntryOverride {
	ko := KindOverride{Mode: le.Mode, Include: slices.Clone(le.Include), Exclude: slices.Clone(le.Exclude)}
	switch {
	case ko.Mode == "":
		ko.Mode = LibraryEntrypointsAuto
	case ko.Mode == LibraryEntrypointsAuto && len(ko.Include) == 0 && len(ko.Exclude) > 0:
		// Denies alone leave the base to the lane scope, which is auto.
		ko.Mode = ""
	}
	var clauses []string
	for _, t := range strings.Split(le.String(), ",") {
		sel, denied := strings.CutPrefix(t, "!")
		c := EntryLaneGo + ":" + EntryKindLibrary + "=" + sel
		if denied {
			c = "!" + c
		}
		clauses = append(clauses, c)
	}
	return EntryOverride{
		Lane:         EntryLaneGo,
		KindOverride: KindOverride{Mode: LibraryEntrypointsAuto},
		Kinds:        map[string]KindOverride{EntryKindLibrary: ko},
		Input:        strings.Join(clauses, ","),
	}
}

// RemovalOnlyRefusal reports why a lane that accepts removal of entry points only cannot honour o,
// or "" when it can. overridable are the kinds the lane lets the caller remove; a clause of another
// kind that asks for anything is refused, and one that states the default (plain auto) is not. An
// allow, a "none" and a nominated list are refused at every scope: the lane would have to resolve
// what the caller adds, and it does not yet. The reason is for the caller, not for the lane.
func RemovalOnlyRefusal(o EntryOverride, overridable ...string) string {
	plain := func(k KindOverride) bool {
		return (k.Mode == "" || k.Mode == LibraryEntrypointsAuto) && len(k.Include) == 0 && len(k.Exclude) == 0
	}
	removalOnly := func(k KindOverride) bool {
		return (k.Mode == "" || k.Mode == LibraryEntrypointsAuto) && len(k.Include) == 0
	}
	for _, kind := range sortedKeys(o.Kinds) {
		if ko := o.Kinds[kind]; !slices.Contains(overridable, kind) && !plain(ko) {
			return fmt.Sprintf("%s:%s cannot be overridden: only %s entry points can be removed", o.Lane, kind, strings.Join(overridable, " and "))
		}
	}
	for _, kind := range sortedKeys(o.Kinds) {
		if !removalOnly(o.Kinds[kind]) {
			return notAcceptedYet(o.Lane)
		}
	}
	if !removalOnly(o.KindOverride) {
		return notAcceptedYet(o.Lane)
	}
	return ""
}

func notAcceptedYet(lane string) string {
	return fmt.Sprintf("allow and none clauses are not accepted yet for %s, which accepts removal only: write !<selector>, for example !%s:bin=bin:<name>", lane, lane)
}

// entryScope accumulates the tokens of one scope while parsing.
type entryScope struct {
	auto, none       bool
	include, exclude []string
}

func (sc *entryScope) resolve(name string, kindScope bool) (KindOverride, error) {
	slices.Sort(sc.include)
	sc.include = slices.Compact(sc.include)
	slices.Sort(sc.exclude)
	sc.exclude = slices.Compact(sc.exclude)
	if both := intersectSorted(sc.include, sc.exclude); len(both) > 0 {
		return KindOverride{}, fmt.Errorf("%s: %q is both allowed and denied", name, both[0])
	}
	ko := KindOverride{Include: sc.include, Exclude: sc.exclude}
	switch {
	case sc.none && (sc.auto || len(sc.include) > 0 || len(sc.exclude) > 0):
		return KindOverride{}, fmt.Errorf("%s: none stands alone", name)
	case sc.none:
		ko.Mode = LibraryEntrypointsNone
	case sc.auto:
		ko.Mode = LibraryEntrypointsAuto
	case len(sc.include) == 0:
		if !kindScope {
			ko.Mode = LibraryEntrypointsAuto
		}
	default:
		ko.Mode = LibraryEntrypointsPaths
	}
	return ko, nil
}

func intersectSorted(a, b []string) []string {
	var out []string
	for _, s := range a {
		if _, ok := slices.BinarySearch(b, s); ok {
			out = append(out, s)
		}
	}
	return out
}

// splitEntryClause splits a token, "!" already removed, into its optional lane, optional kind and
// target.
func splitEntryClause(body string) (lane, kind, target string, err error) {
	if body == "" {
		return "", "", "", fmt.Errorf("empty clause")
	}
	prefix, rest, ok := strings.Cut(body, ":")
	if !ok || strings.Contains(prefix, "/") {
		return "", "", body, nil
	}
	if slices.Contains(entrySelectorPrefixes, prefix+":") {
		return "", "", body, nil
	}
	kinds, known := entryLaneKinds[prefix]
	if !known {
		return "", "", "", fmt.Errorf("unknown lane %q", prefix)
	}
	lane, target = prefix, rest
	if k, t, ok := strings.Cut(rest, "="); ok {
		if !slices.Contains(kinds, k) {
			if isEntryKind(k) {
				return "", "", "", fmt.Errorf("lane %s does not infer kind %q", lane, k)
			}
			return "", "", "", fmt.Errorf("unknown kind %q", k)
		}
		kind, target = k, t
	} else if k, t, ok := strings.Cut(rest, ":"); ok && isEntryKind(k) && !slices.Contains(entrySelectorPrefixes, k+":") {
		if slices.Contains(kinds, k) {
			return "", "", "", fmt.Errorf("a kind is followed by =, not :; write %s:%s=%s", lane, k, t)
		}
		return "", "", "", fmt.Errorf("lane %s does not infer kind %q", lane, k)
	}
	if target == "" {
		return "", "", "", fmt.Errorf("empty target")
	}
	return lane, kind, target, nil
}

func isEntryKind(k string) bool {
	switch k {
	case EntryKindModule, EntryKindBin, EntryKindScript, EntryKindMain, EntryKindLibrary,
		EntryKindTest, EntryKindHandler, EntryKindRuntime:
		return true
	}
	return false
}

// cleanEntrySelector canonicalizes one selector, rejecting one that is not repository-relative.
func cleanEntrySelector(sel string) (string, error) {
	for _, p := range entrySelectorPrefixes {
		name, ok := strings.CutPrefix(sel, p)
		if !ok {
			continue
		}
		if name == "" || strings.Contains(name, `\`) {
			return "", fmt.Errorf("%s needs a name without backslashes", p)
		}
		for _, seg := range strings.Split(name, "/") {
			if seg == ".." {
				return "", fmt.Errorf("selector leaves the package")
			}
		}
		if name = path.Clean(name); name == "." {
			return "", fmt.Errorf("%s needs a name", p)
		}
		return p + name, nil
	}
	if first, _, _ := strings.Cut(sel, "/"); strings.Contains(first, ":") {
		return "", fmt.Errorf("unknown selector form %q; a selector is a repository path, npm:<package>[/<path>], bin:<Name>, class:<FQN>, type:<FQN> or asm:<Assembly>", first)
	}
	return cleanEntrypointPath(sel)
}

// matchesEntryRoot reports whether selector sel, as ParseEntryOverrides normalises it, selects r: it
// equals the root's Selector, is a directory prefix of it, is "npm:<package>" naming a prefix of
// "npm:<package>/...", or is "bin:<Name>" naming the root. "." selects every repository path.
func matchesEntryRoot(sel string, r EntryRoot) bool {
	if sel == r.Selector {
		return true
	}
	if name, ok := strings.CutPrefix(sel, "bin:"); ok {
		return name != "" && r.Name == name
	}
	for _, p := range entrySelectorPrefixes {
		if strings.HasPrefix(sel, p) {
			return p == "npm:" && strings.HasPrefix(r.Selector, sel+"/")
		}
	}
	for _, p := range entrySelectorPrefixes {
		if strings.HasPrefix(r.Selector, p) {
			return false
		}
	}
	return Under(r.Selector, sel)
}

// ApplyEntryOverride applies o to the roots a lane inferred. A root's effective status follows
// EntryOverride's scope rule: it stands when (base ∪ allows) \ denies selects it, where base is the
// inferred set under auto and empty under none or a nominated list, an allow brings in the roots it
// selects, and a deny removes the roots it selects and wins over an allow selecting the same root. A
// selector selects a root when it equals the root's Selector, is a directory prefix of it ("pkg/api"
// selects "pkg/api/x.go" and not "pkg/apiv2/x.go"), is "npm:<package>" as a prefix of
// "npm:<package>/...", or is "bin:<Name>". Roots of lanes other than o.Lane stand untouched.
//
// effective holds the roots the analysis starts from. denied holds every inferred root dropped from
// it, whatever the reason. added holds the roots of Kind "declared" created for an allow that selected
// no inferred root: the caller declares them, so they stand in effective and the lane checks they
// exist. A declared root is not created when a deny selects it. The lane MUST resolve every added
// root against the scanned tree and treat one it cannot resolve as an unmatched selector: the
// matcher cannot tell a declared root from a typo, and a clear must not rest on an unresolved one.
// Resolving is the lane's check alone; this function never reports an added root as unmatched.
//
// unmatched holds the selectors that selected nothing and created nothing: a deny, written with its
// "!", that selected no root it addresses, and an allow whose declared root a deny selects. A
// lane-scope selector addresses every root of the lane and a kind-scope selector the roots of its
// kind. A deny that only covers the declared root of an allow counts as selecting nothing and is
// reported with that allow; both are listed so the lane withholds. It is a report, never an error, and belongs to o.Lane alone: a non-empty result means that
// lane withholds the clears that rest on its override, and no other lane's clears are affected. All
// results are sorted by Selector, then Origin. inferred is not modified.
func ApplyEntryOverride(inferred []EntryRoot, o EntryOverride) (effective, denied, added []EntryRoot, unmatched []string) {
	var laneRoots []EntryRoot
	for _, r := range inferred {
		if o.Lane != "" && r.Lane != o.Lane {
			effective = append(effective, r)
			continue
		}
		laneRoots = append(laneRoots, r)
	}
	matches := func(sels []string, r EntryRoot) bool {
		return slices.ContainsFunc(sels, func(sel string) bool { return matchesEntryRoot(sel, r) })
	}
	selects := func(sel, kind string) bool {
		return slices.ContainsFunc(laneRoots, func(r EntryRoot) bool {
			return (kind == "" || r.Kind == kind) && matchesEntryRoot(sel, r)
		})
	}

	for _, r := range laneRoots {
		ks := o.Kinds[r.Kind]
		mode := o.Mode
		if ks.Mode != "" {
			mode = ks.Mode
		}
		allowed := mode == "" || mode == LibraryEntrypointsAuto || matches(o.Include, r) || matches(ks.Include, r)
		if allowed && !matches(o.Exclude, r) && !matches(ks.Exclude, r) {
			effective = append(effective, r)
		} else {
			denied = append(denied, r)
		}
	}

	// scopes in a fixed order: the lane scope, then each kind.
	type scope struct {
		kind, origin string
		ko           KindOverride
	}
	scopes := []scope{{"", EntryOriginDeclared, o.KindOverride}}
	for _, k := range sortedKeys(o.Kinds) {
		scopes = append(scopes, scope{k, EntryOriginDeclared + ":" + k, o.Kinds[k]})
	}
	for _, sc := range scopes {
		for _, sel := range sc.ko.Include {
			if selects(sel, sc.kind) {
				continue
			}
			d := EntryRoot{Lane: o.Lane, Kind: EntryKindDeclared, Selector: sel, Origin: sc.origin}
			if matches(o.Exclude, d) || matches(sc.ko.Exclude, d) {
				unmatched = append(unmatched, sel)
				continue
			}
			added = append(added, d)
			effective = append(effective, d)
		}
		for _, sel := range sc.ko.Exclude {
			if !selects(sel, sc.kind) {
				unmatched = append(unmatched, "!"+sel)
			}
		}
	}

	for _, set := range []*[]EntryRoot{&effective, &denied, &added} {
		sortEntryRoots(*set)
		*set = slices.Compact(*set)
	}
	slices.Sort(unmatched)
	unmatched = slices.Compact(unmatched)
	return effective, denied, added, unmatched
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// sortEntryRoots orders roots by Selector, then Origin; the remaining fields break ties so the order
// is total.
func sortEntryRoots(rs []EntryRoot) {
	slices.SortFunc(rs, func(a, b EntryRoot) int {
		return cmp.Or(
			cmp.Compare(a.Selector, b.Selector),
			cmp.Compare(a.Origin, b.Origin),
			cmp.Compare(a.Lane, b.Lane),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Name, b.Name),
		)
	})
}

// EntryRootSummary is the run-level disclosure of a lane's entry points: how many roots were
// inferred per kind, the roots themselves except where a kind is too numerous to list, and every
// root the override changed.
type EntryRootSummary struct {
	// Counts is the number of inferred roots per kind.
	Counts map[string]int `json:"counts"`
	// Inferred lists the inferred roots of every kind except module, sorted by Selector, then Origin.
	Inferred []EntryRoot `json:"inferred,omitempty"`
	// Denied and Added list every root the override dropped or declared, sorted likewise.
	Denied []EntryRoot `json:"denied,omitempty"`
	Added  []EntryRoot `json:"added,omitempty"`
	// Unmatched are the selectors ApplyEntryOverride reported as matching nothing.
	Unmatched []string `json:"unmatched,omitempty"`
}

// SummarizeEntryRoots builds the disclosure for the results of ApplyEntryOverride on inferred. A
// module root is counted, never listed: every first-party source file is one. The inputs are not
// modified.
func SummarizeEntryRoots(inferred, denied, added []EntryRoot, unmatched []string) EntryRootSummary {
	s := EntryRootSummary{Counts: map[string]int{}}
	for _, r := range inferred {
		s.Counts[r.Kind]++
		if r.Kind != EntryKindModule {
			s.Inferred = append(s.Inferred, r)
		}
	}
	s.Denied = slices.Clone(denied)
	s.Added = slices.Clone(added)
	s.Unmatched = slices.Clone(unmatched)
	for _, set := range [][]EntryRoot{s.Inferred, s.Denied, s.Added} {
		sortEntryRoots(set)
	}
	slices.Sort(s.Unmatched)
	return s
}

// EntryRootRecord is the run-level disclosure of one lane's entry points, as the report states it.
type EntryRootRecord struct {
	// Lane is the analysis lane the record describes.
	Lane string `json:"lane"`
	// Source is LibraryEntrypointsSourceAuto when the lane inferred the set with nothing declared,
	// LibraryEntrypointsSourceDeclared when it rests on the caller's declaration.
	Source string `json:"source"`
	// Input is the statement the set was resolved from, in the entrypoints input's syntax.
	Input string `json:"input"`
	// Effective is the set of roots the lane analysed, by kind, in the lane's own naming (a Go
	// import path for a library), sorted. A kind with an empty list has no roots; a kind the lane
	// did not report is absent.
	Effective map[string][]string `json:"effective"`
	// Unmatched are the declared selectors, "!" kept on a deny, that matched nothing the lane
	// holds. An unmatched allow leaves the set unknown, and the lane withholds what rests on it.
	Unmatched []string `json:"unmatched,omitempty"`
	// Inferred is what the lane would nominate with nothing declared, by kind, sorted: the guess the
	// customer reads before overriding it. A Go record lists the build's importable library
	// packages under EntryKindLibrary and the packages the build compiles as main under
	// EntryKindMain. A lane that does not report the guess leaves it absent.
	Inferred map[string][]string `json:"inferred,omitempty"`
	// Denied are the declared "!" selectors that took something out of Inferred, "!" kept, sorted.
	// A "!" selector that removed nothing inferred is in Unmatched or in neither.
	Denied []string `json:"denied,omitempty"`
}

// EntryRootRecordOf renders the library set a lane resolved as that lane's record. It reports false
// for an ecosystem whose lane does not report an entry-point set. The record carries no Inferred or
// Denied: a ResolvedLibraryEntrypoints holds neither, since library_entrypoints is a fixed wire
// shape. A lane that knows them sends the whole record (ReachabilityResult.EntryRoots).
func EntryRootRecordOf(r ResolvedLibraryEntrypoints) (EntryRootRecord, bool) {
	if r.Ecosystem != "golang" {
		return EntryRootRecord{}, false
	}
	return EntryRootRecord{
		Lane:      EntryLaneGo,
		Source:    r.Source,
		Input:     r.Input,
		Effective: map[string][]string{EntryKindLibrary: append([]string{}, r.Packages...)},
		Unmatched: slices.Clone(r.Unmatched),
	}, true
}
