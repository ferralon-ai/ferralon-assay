package pythonanalysis

// Selected-set requirements parsing (PLAN-170 E1–E3).
//
// This is the environment-AWARE requirements parser that feeds the forthcoming
// ResolveInventory path (E5). It differs in intent from ResolveDependencyVersions'
// parseRequirementsTxt, which is deliberately environment-BLIND: the advisory-matching path
// wants a coordinate's version regardless of the target environment (a sound
// over-approximation), so it strips markers and ignores extras. That path is retained
// unchanged. This path instead computes the SELECTED set for a declared descriptor —
// evaluating markers (E1), resolving extras against a declared selection (E2), and
// recording every otherwise-dropped line as a partial node (E3) — and returns lane-local
// pyReq records. E5 maps those onto plugin.DependencyInventory nodes.
//
// pyReq is intentionally a lane-local intermediate, not plugin.DependencyNode: the shared
// inventory assembly + reason-code/field wiring is L0-gated (onyx-q6) and lands in E5.

import "strings"

// reqKind classifies a requirements-file line by the source shape it declares. Every kind
// other than reqNormal is a line the old parser dropped entirely (§3.1 silent omission); each
// now becomes a partial node instead.
type reqKind int

const (
	reqNormal   reqKind = iota // a PyPI name(+extras)(+pin) requirement
	reqEditable                // "-e <target>" / "--editable <target>"
	reqInclude                 // "-r <file>" / "-c <file>" include/constraint
	reqVCS                     // "git+…" (or hg+/svn+/bzr+) VCS requirement
	reqURL                     // a direct-URL requirement ("…://…")
)

// pyReq is one parsed requirement line with the fields E1–E3 populate. It is the input E5
// projects onto plugin.DependencyNode.
type pyReq struct {
	Name     string // PyPI project name (or best-effort source identity for non-normal kinds)
	Version  string // exact resolved version; "" when unresolved
	Resolved bool   // an exact "==X.Y.Z" pin was found
	Source   string // manifest/resolver label, e.g. "requirements.txt"
	Kind     reqKind
	Raw      string // original spec text for a non-normal line (VCS/URL/editable/include identity)
	Marker   string // captured PEP 508 marker text ("" = none)

	Selected   bool     // marker true (or no marker) → in the selected set
	Unresolved bool     // marker referenced an unbound variable (§3.1 partial)
	Partial    []string // lane-local partiality reason codes (see partiality.go)

	// E2 extras: the extras group "[a,b]" declared on the requirement, and the subset the
	// declared Selection selects (in declared order — C7 determinism). SelectedExtras is the
	// provenance C2 requires: it records exactly which declared-selection entries produced the
	// inclusion, so a reader can tell an unselected extra was evaluated-and-excluded, not
	// missed. An unselected extra's subtree does not enter the selected set.
	Extras         []string
	SelectedExtras []string

	// E3: --hash tokens retained (declared order) instead of truncated; pip-tools output
	// carries integrity data here (§5.4 deliverable 8).
	Hashes []string
}

// resolveRequirements parses a requirements file into the selected set for the declared
// environment env (variable→value) and extras selection. Each logical line becomes a pyReq
// whose Selected/Unresolved/Partial reflect its marker outcome; a marker-false requirement
// is returned as a node with Selected=false (an explicit, evaluated exclusion — NOT a silent
// drop), so a caller can distinguish "excluded because the marker said so" from "never
// parsed". env may be nil (then any marked line is unresolved).
func resolveRequirements(data []byte, env map[string]string, selection []string) []pyReq {
	var out []pyReq
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}

		// E3: retain --hash tokens rather than truncating them off the line.
		line, hashes := extractHashes(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// E3: a line the old parser dropped — an editable/include option or a VCS/URL
		// requirement — becomes a partial node (source_unpinned), never a silent omission.
		// A pure option line (e.g. --index-url) carries no dependency and is skipped.
		if strings.HasPrefix(line, "-") {
			if kind, ok := optionKind(line); ok {
				out = append(out, buildSourceNode(line, kind, hashes, env, selection))
			}
			continue
		}
		if kind, ok := urlKind(line); ok {
			out = append(out, buildSourceNode(line, kind, hashes, env, selection))
			continue
		}

		// Normal requirement: split marker, parse the spec (name/version/extras).
		marker := ""
		if i := strings.IndexByte(line, ';'); i >= 0 {
			marker = strings.TrimSpace(line[i+1:])
			line = strings.TrimSpace(line[:i])
		}

		name, version, resolved, extras := parseRequirementSpec(line)
		if name == "" {
			continue
		}

		r := pyReq{
			Name:           name,
			Version:        version,
			Resolved:       resolved,
			Source:         "requirements.txt",
			Kind:           reqNormal,
			Marker:         marker,
			Extras:         extras,
			SelectedExtras: selectExtras(extras, selection),
			Hashes:         hashes,
		}
		applyMarker(&r, env, selection)
		out = append(out, r)
	}
	return out
}

// stripReqCommentSafe removes a "# …" inline comment, treating '#' as a comment only at line
// start or when preceded by whitespace. Unlike the advisory path's stripReqComment (which cuts
// at the first '#'), this preserves a URL/VCS fragment such as "…#egg=foo", which the
// selected-set path must read.
func stripReqCommentSafe(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// optionKind classifies a leading-"-" line. It returns (kind, true) for the dependency-
// bearing option lines the old parser dropped — "-e"/"--editable" editables and
// "-r"/"--requirement"/"-c"/"--constraint" includes — and (0, false) for a pure option line
// (e.g. --index-url) that carries no dependency and should be skipped rather than recorded.
func optionKind(line string) (reqKind, bool) {
	flag := line
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		flag = line[:i]
	}
	switch flag {
	case "-e", "--editable":
		return reqEditable, true
	case "-r", "--requirement", "-c", "--constraint":
		return reqInclude, true
	}
	return 0, false
}

// urlKind classifies a VCS or direct-URL requirement. git+/hg+/svn+/bzr+ prefixes are VCS;
// any other "…://…" is a direct URL. Both are unpinned sources.
func urlKind(line string) (reqKind, bool) {
	for _, p := range []string{"git+", "hg+", "svn+", "bzr+"} {
		if strings.HasPrefix(line, p) {
			return reqVCS, true
		}
	}
	if strings.Contains(line, "://") {
		return reqURL, true
	}
	return 0, false
}

// buildSourceNode builds a partial node for a dropped-shape line (editable/include/VCS/URL).
// The node is Selected (the dependency IS installed) but carries source_unpinned partiality:
// its exact identity is undeclared without a fetch (§3.1 — never infer safety from a missing
// node). Any marker still gates selection; retained hashes are attached.
func buildSourceNode(line string, kind reqKind, hashes []string, env map[string]string, selection []string) pyReq {
	marker := ""
	if i := strings.IndexByte(line, ';'); i >= 0 {
		marker = strings.TrimSpace(line[i+1:])
		line = strings.TrimSpace(line[:i])
	}
	r := pyReq{
		Name:    sourceNodeName(line, kind),
		Source:  "requirements.txt",
		Kind:    kind,
		Raw:     line,
		Marker:  marker,
		Hashes:  hashes,
		Partial: []string{reasonSourceUnpinnedPlaceholder},
	}
	applyMarker(&r, env, selection) // a marker still gates selection; may add env_unresolved
	return r
}

// sourceNodeName derives a best-effort identity for a non-normal line: the "#egg=<name>"
// fragment for a VCS/URL requirement when present, otherwise the target following the option
// flag, otherwise the raw spec. Exact registry identity is undeclared (that is the
// source_unpinned partiality) — this is only a stable label.
func sourceNodeName(line string, kind reqKind) string {
	if kind == reqVCS || kind == reqURL {
		if i := strings.Index(line, "#egg="); i >= 0 {
			egg := line[i+len("#egg="):]
			if j := strings.IndexAny(egg, "&; \t"); j >= 0 {
				egg = egg[:j]
			}
			if n := normalizePyCoordinate(egg); n != "" {
				return n
			}
		}
		return line
	}
	// editable/include: the target after the flag.
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		if t := strings.TrimSpace(line[i+1:]); t != "" {
			return t
		}
	}
	return line
}

// extractHashes removes "--hash=<algo>:<digest>" (and the space-separated "--hash <value>")
// tokens from a requirement line, returning the remaining spec and the hash values in
// declared order (E3). pip-tools emits these; the old parser truncated the line at the first
// "--hash", discarding them.
func extractHashes(line string) (rest string, hashes []string) {
	fields := strings.Fields(line)
	kept := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "--hash="):
			hashes = append(hashes, strings.TrimPrefix(f, "--hash="))
		case f == "--hash":
			if i+1 < len(fields) {
				hashes = append(hashes, fields[i+1])
				i++
			}
		default:
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " "), hashes
}

// applyMarker evaluates r.Marker against the descriptor and sets the selection outcome.
// No marker → selected. Marker true → selected. Marker false → not selected (an evaluated
// exclusion). Unbound variable → unresolved with declared partiality naming the variable.
func applyMarker(r *pyReq, env map[string]string, selection []string) {
	if r.Marker == "" {
		r.Selected = true
		return
	}
	mr := evaluateMarker(r.Marker, env, selection)
	switch {
	case mr.unresolved:
		r.Unresolved = true
		r.Partial = append(r.Partial, envUnresolvedReason(mr.unboundVar))
	case mr.selected:
		r.Selected = true
	default:
		r.Selected = false // marker evaluated false: a resolved exclusion, not a drop
	}
}

// selectExtras returns, in declared order, the subset of a requirement's extras group that
// the declared Selection selects (PLAN-170 E2, C2). An extra not in the selection does not
// enter the selected set; the returned slice is the provenance of the inclusion. Extra names
// and selection entries are both PEP 503-normalized so matching is case/separator-insensitive.
// selection is used only for membership lookup — never iterated on an output path (C7).
func selectExtras(extras, selection []string) []string {
	if len(extras) == 0 || len(selection) == 0 {
		return nil
	}
	selSet := make(map[string]bool, len(selection))
	for _, s := range selection {
		if n := normalizePyCoordinate(s); n != "" {
			selSet[n] = true
		}
	}
	var out []string
	for _, e := range extras { // declared order preserved (C7)
		if selSet[normalizePyCoordinate(e)] {
			out = append(out, normalizePyCoordinate(e))
		}
	}
	return out
}

// envUnresolvedReason builds the partiality code for an unbound marker variable, appending
// the specific variable as a ":<var>" detail (architect-ruling item 2 convention). The
// bare code is used when the variable is unknown (malformed marker).
func envUnresolvedReason(unboundVar string) string {
	if unboundVar == "" {
		return reasonEnvUnresolvedPlaceholder
	}
	return reasonEnvUnresolvedPlaceholder + ":" + unboundVar
}
