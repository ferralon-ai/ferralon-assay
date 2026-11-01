package pythonanalysis

// Selected-set requirements parsing (PLAN-170 E1–E3).
//
// This is the environment-AWARE requirements parser that feeds the forthcoming
// ResolveInventory path (E5). It differs in intent from ResolveDependencyVersions'
// parseRequirementLines, which is deliberately environment-BLIND: the advisory-matching path
// wants a coordinate's version regardless of the target environment (a sound
// over-approximation), so it strips markers and ignores extras. That path is retained
// unchanged. This path instead computes the SELECTED set for a declared descriptor —
// evaluating markers (E1), resolving extras against a declared selection (E2), and
// recording every otherwise-dropped line as a partial node (E3) — and returns lane-local
// pyReq records. E5 maps those onto plugin.DependencyInventory nodes.
//
// pyReq is intentionally a lane-local intermediate, not plugin.DependencyNode: the shared
// inventory assembly + reason-code/field wiring is L0-gated (onyx-q6) and lands in E5.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

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

// relKind classifies a node's parent relationship (C4). The zero value is deliberately
// relUnexpressed, NOT relDirect: a node whose source format carries no edge data must never be
// silently promoted to "direct" (C4 negative control). relDirect is only assigned on positive
// evidence — a root/top-level dependency — and relTransitive only when a parent edge names the
// node as another package's dependency.
type relKind int

const (
	relUnexpressed relKind = iota // format expresses no parent relationship (requirements.txt)
	relDirect                     // a root/top-level dependency
	relTransitive                 // pulled in only as another package's dependency
)

// pyReq is one parsed requirement line (E1–E3) or resolved lockfile package (E4) with the
// fields those stages populate. It is the input E5 projects onto plugin.DependencyNode.
type pyReq struct {
	Name     string // PyPI project name (or best-effort source identity for non-normal kinds)
	Version  string // exact resolved version; "" when unresolved
	Resolved bool   // an exact "==X.Y.Z" pin was found
	Source   string // manifest/resolver label, e.g. "requirements.txt", "pdm.lock", "uv.lock"
	Kind     reqKind
	Raw      string // original spec text for a non-normal line (VCS/URL/editable/include identity)
	Marker   string // captured PEP 508 marker text ("" = none)

	// E4 parent edges + classification (C4). Relationship is relUnexpressed for a format with
	// no edge data (requirements.txt); the pdm.lock/uv.lock parsers set relDirect/relTransitive
	// and populate Parents with the normalized names of the packages that declare this node as a
	// dependency, sorted for deterministic emission (C7).
	Relationship relKind
	Parents      []string

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
	return parseRequirementsFile(data, env, selection).reqs
}

// reqFile is one parsed requirements file: the requirements that name a PyPI project, plus
// the selected lines that install something without naming one. Those lines become no node
// (a node named after a path or URL is not a package), so the caller decides from them
// whether the graph is complete.
type reqFile struct {
	reqs        []pyReq
	includes    []string // "-r" targets as written
	constraints []string // "-c" targets: pip installs the "-r" includes inside one, never its pins
	locals      []string // local directory installs (".", "-e ./pkg"), extras stripped
	unnamed     bool     // an archive, URL or VCS install whose project the line does not name
	skipped     bool     // an include or editable option this reader does not follow
}

// parseRequirementsFile is resolveRequirements with the non-node lines kept. A line that is
// not a requirement at all (a TOML "name = ..." key, stray text) is dropped, as pip would
// refuse it rather than install anything.
func parseRequirementsFile(data []byte, env map[string]string, selection []string) reqFile {
	var f reqFile
	for _, raw := range joinContinuations(decodeRequirements(data)) {
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
		// requirement — is recorded, never silently omitted. A pure option line (e.g.
		// --index-url) carries no dependency and is skipped.
		if strings.HasPrefix(line, "-") {
			// pip ignores a marker on an option line: "; python_version < '3'" is leftover words.
			spec, _ := splitMarker(line)
			kind := reqInclude
			target, ok := includeTarget(spec)
			if !ok {
				kind = reqEditable
				target, ok = editableTarget(spec)
			}
			if (!ok && abbreviatesInstallOption(spec)) || laterInstallOption(spec) {
				f.skipped = true
				continue
			}
			switch {
			case ok && target != "" && kind == reqEditable:
				f.addSource(spec, target, kind, hashes, env, selection)
			case ok && target != "" && !isConstraintFlag(spec):
				f.includes = append(f.includes, target)
			default:
				if c, ok := constraintTarget(spec); ok {
					f.constraints = append(f.constraints, c)
				}
			}
			continue
		}
		line = requirementArgs(line)
		if _, ok := urlKind(line); ok || isPathSpec(line) || isFileLink(line) || directRefName(line) != "" {
			if spec, marker := splitMarker(line); markerMaySelect(marker, env, selection) {
				f.addSource(line, spec, reqNormal, hashes, env, selection)
			}
			continue
		}

		// Normal requirement: split marker, parse the spec (name/version/extras).
		line, marker := splitMarker(line)
		if !wellFormedRequirement(line) {
			continue
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
		f.reqs = append(f.reqs, r)
	}
	return f
}

// addSource records an editable, path, URL or VCS line (spec is its target, marker
// stripped). A line that states its project — "name @ url", a "#egg=" fragment, a wheel
// filename — becomes a source_unpinned node under that name; a local directory is kept for
// the caller to check; anything else is an unnamed install.
func (f *reqFile) addSource(line, spec string, kind reqKind, hashes []string, env map[string]string, selection []string) {
	urlK, isURL := urlKind(spec)
	if name := directRefName(spec); name != "" {
		if kind == reqNormal {
			kind = reqURL
			_, ref, _ := strings.Cut(spec, "@")
			if k, ok := urlKind(strings.TrimSpace(ref)); ok {
				kind = k
			}
		}
		f.reqs = append(f.reqs, buildSourceNode(line, name, kind, hashes, env, selection))
		return
	}
	if isURL {
		if kind == reqNormal {
			kind = urlK
		}
		if name := eggName(spec); name != "" {
			f.reqs = append(f.reqs, buildSourceNode(line, name, kind, hashes, env, selection))
			return
		}
	}
	if name := wheelName(spec); name != "" {
		if kind == reqNormal {
			kind = reqURL
		}
		f.reqs = append(f.reqs, buildSourceNode(line, name, kind, hashes, env, selection))
		return
	}
	if isURL || hasArchiveExt(spec) {
		f.unnamed = true
		return
	}
	f.locals = append(f.locals, stripExtrasSuffix(spec))
}

// decodeRequirements decodes a requirements file the way pip's auto_decode does: a UTF-16 or
// UTF-8 byte-order mark selects the encoding, and the mark itself is not text.
func decodeRequirements(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return string(data[3:])
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUTF16(data[2:], binary.LittleEndian)
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUTF16(data[2:], binary.BigEndian)
	}
	return string(data)
}

func decodeUTF16(b []byte, order binary.ByteOrder) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = order.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// splitMarker splits a "; <marker>" suffix off a line.
func splitMarker(line string) (spec, marker string) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// markerMaySelect reports whether a line with this marker may be installed: no marker, a true
// marker, or one that cannot be decided. Only a marker that evaluates false excludes it.
func markerMaySelect(marker string, env map[string]string, selection []string) bool {
	if marker == "" {
		return true
	}
	mr := evaluateMarker(marker, env, selection)
	return mr.unresolved || mr.selected
}

// editableTarget returns the target of an editable line ("-e .", "-e.", "--editable=./pkg").
func editableTarget(line string) (string, bool) {
	return optionValue(line, "--editable", "-e")
}

// abbreviatesInstallOption reports whether line opens with a shortened --requirement or
// --editable, which pip's option parser accepts as the full option.
func abbreviatesInstallOption(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	word, _, _ := strings.Cut(fields[0], "=")
	return len(word) > 2 && (strings.HasPrefix("--requirement", word) || strings.HasPrefix("--editable", word))
}

// laterInstallOption reports whether an option line carries an include or editable after its
// first option ("--pre -r dev.txt"); pip reads every option on the line, shell-unquoted.
func laterInstallOption(line string) bool {
	fields := strings.Fields(line)
	for i := 1; i < len(fields); i++ {
		fields[i] = strings.Trim(fields[i], `'"`)
		if !strings.HasPrefix(fields[i], "-") {
			continue
		}
		if _, ok := editableTarget(fields[i]); ok || abbreviatesInstallOption(fields[i]) {
			return true
		}
		if _, ok := includeTarget(fields[i]); ok && !isConstraintFlag(fields[i]) {
			return true
		}
	}
	return false
}

// constraintTarget returns the file named by the first constraint option on an option line, in
// any of pip's spellings ("-c c.txt", "-cc.txt", "--pre --cons=c.txt"); pip reads only the
// first. A field another option consumes as its value ("-i -c") is not an option.
func constraintTarget(line string) (string, bool) {
	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		f := shellUnquote.Replace(fields[i])
		name, val, attached := strings.Cut(f, "=")
		long := strings.HasPrefix(f, "--")
		switch {
		case long && len(name) >= len("--cons") && strings.HasPrefix("--constraint", name):
			if attached {
				return val, val != ""
			}
		case !long && strings.HasPrefix(f, "-c"):
			if len(f) > 2 {
				return f[2:], true
			}
		case long && !attached && takesValue(name), !long && takesValue(f):
			i++
			continue
		default:
			continue
		}
		if i+1 < len(fields) {
			return shellUnquote.Replace(fields[i+1]), true
		}
		return "", false
	}
	return "", false
}

// shellUnquote drops the quotes and backslashes pip's shell-style split removes from a field.
var shellUnquote = strings.NewReplacer(`"`, "", `'`, "", `\`, "")

func isConstraintFlag(spec string) bool {
	return strings.HasPrefix(spec, "-c") || strings.HasPrefix(spec, "--constraint")
}

// isPathSpec mirrors pip's test for a requirement that names a file or directory rather than
// a project: a path separator, a leading ".", or an archive filename.
func isPathSpec(spec string) bool {
	spec, _ = splitMarker(spec)
	return strings.ContainsAny(spec, `/\`) || strings.HasPrefix(spec, ".") || hasArchiveExt(spec)
}

// isFileLink reports a "file:" link without "//" ("file:.", "file:pkg"), which pip installs
// as a local path.
func isFileLink(spec string) bool {
	return len(spec) >= len("file:") && strings.EqualFold(spec[:len("file:")], "file:")
}

// pipArchiveExts are the archive suffixes pip treats as a file to install.
var pipArchiveExts = []string{
	".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma", ".tar",
}

func hasArchiveExt(spec string) bool {
	base := strings.ToLower(specBase(spec))
	for _, ext := range pipArchiveExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// specBase is the last path element of a path or URL, without a query or fragment.
func specBase(spec string) string {
	if i := strings.IndexAny(spec, "?#"); i >= 0 {
		spec = spec[:i]
	}
	if i := strings.LastIndexAny(spec, `/\`); i >= 0 {
		spec = spec[i+1:]
	}
	return spec
}

// directRefName is the project a PEP 508 direct reference ("name[extras] @ url") names, or ""
// when the line is not one.
func directRefName(spec string) string {
	at := strings.IndexByte(spec, '@')
	if at < 0 {
		return ""
	}
	name := strings.TrimSpace(spec[:at])
	if i := strings.IndexByte(name, '['); i >= 0 && strings.HasSuffix(name, "]") {
		name = strings.TrimSpace(name[:i])
	}
	if !validProjectName(name) {
		return ""
	}
	return normalizePyCoordinate(name)
}

// eggName is the project a VCS or URL requirement's "#egg=<name>" fragment names, or "".
func eggName(spec string) string {
	_, frag, ok := strings.Cut(spec, "#")
	if !ok {
		return ""
	}
	for _, kv := range strings.Split(frag, "&") {
		egg, ok := strings.CutPrefix(kv, "egg=")
		if !ok {
			continue
		}
		if j := strings.IndexAny(egg, "; \t"); j >= 0 {
			egg = egg[:j]
		}
		if !validProjectName(egg) {
			return ""
		}
		return normalizePyCoordinate(egg)
	}
	return ""
}

// wheelName is the project a wheel filename names (PEP 427: the field before the first "-"),
// or "" when spec is not a wheel. An sdist filename does not split unambiguously, so it names
// nothing.
func wheelName(spec string) string {
	base := specBase(spec)
	if !strings.HasSuffix(strings.ToLower(base), ".whl") {
		return ""
	}
	name, _, ok := strings.Cut(base, "-")
	if !ok || !validProjectName(name) {
		return ""
	}
	return normalizePyCoordinate(name)
}

// stripExtrasSuffix drops a trailing "[extras]" from a local path (".[dev]" -> ".").
func stripExtrasSuffix(spec string) string {
	if strings.HasSuffix(spec, "]") {
		if i := strings.LastIndexByte(spec, '['); i > 0 {
			return strings.TrimSpace(spec[:i])
		}
	}
	return spec
}

// requirementArgs returns a requirement line without its trailing per-line options
// ("psycopg2 --no-binary psycopg2"): as pip splits it, the requirement ends at the first
// whitespace-separated token that starts with '-'.
func requirementArgs(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.HasPrefix(f, "-") {
			return strings.Join(fields[:i], " ")
		}
	}
	return line
}

// wellFormedRequirement reports whether spec (marker stripped) reads as a PEP 508 name
// requirement: a valid project name, an optional extras group, then nothing or a version
// specifier. A TOML key line ("name = \"x\"") fails on the bare "=".
func wellFormedRequirement(spec string) bool {
	end := strings.IndexAny(spec, "=<>!~[( \t")
	if end < 0 {
		return validProjectName(spec)
	}
	if !validProjectName(spec[:end]) {
		return false
	}
	rest := strings.TrimSpace(spec[end:])
	if strings.HasPrefix(rest, "[") {
		j := strings.IndexByte(rest, ']')
		if j < 0 {
			return false
		}
		rest = strings.TrimSpace(rest[j+1:])
	}
	if rest == "" || strings.HasPrefix(rest, "(") {
		return true
	}
	for _, op := range []string{"===", "==", "!=", "<=", ">=", "~=", "<", ">"} {
		if strings.HasPrefix(rest, op) {
			return true
		}
	}
	return false
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
// bearing option lines — "-e"/"--editable" editables and "-r"/"--requirement"/"-c"/
// "--constraint" includes, in any of pip's spellings — and (0, false) for a pure option line
// (e.g. --index-url) that carries no dependency.
func optionKind(line string) (reqKind, bool) {
	if _, ok := editableTarget(line); ok {
		return reqEditable, true
	}
	if _, ok := includeTarget(line); ok {
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

// buildSourceNode builds a partial node for an editable/VCS/URL/wheel line that names its
// project. The node is Selected (the dependency IS installed) but carries source_unpinned
// partiality: its version is undeclared without a fetch (§3.1 — never infer safety from a
// missing node). Any marker still gates selection; retained hashes are attached.
func buildSourceNode(line, name string, kind reqKind, hashes []string, env map[string]string, selection []string) pyReq {
	line, marker := splitMarker(line)
	r := pyReq{
		Name:    name,
		Source:  "requirements.txt",
		Kind:    kind,
		Raw:     line,
		Marker:  marker,
		Hashes:  hashes,
		Partial: []string{plugin.PartialReasonSourceUnpinned},
	}
	applyMarker(&r, env, selection) // a marker still gates selection; may add env_unresolved
	return r
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

// relationshipReason returns the declared partiality code for a node whose source format
// expresses no parent relationship (C4), or "" for a node the format lets us classify. E5
// folds this into the plugin.DependencyInventory node's Partiality alongside pyReq.Partial;
// keeping it derived from Relationship (rather than eagerly stored in Partial) leaves the
// E1–E3 source/marker partiality axis untouched and guarantees an unclassified node reads as
// "unexpressed", never "direct".
func (r pyReq) relationshipReason() string {
	if r.Relationship == relUnexpressed {
		return plugin.PartialReasonRelationshipUnexpressed
	}
	return ""
}

// envUnresolvedReason builds the partiality code for an unbound marker variable, appending
// the specific variable as a ":<var>" detail (architect-ruling item 2 convention). The
// bare code is used when the variable is unknown (malformed marker).
func envUnresolvedReason(unboundVar string) string {
	if unboundVar == "" {
		return plugin.PartialReasonEnvConditionUnresolved
	}
	return plugin.PartialReasonEnvConditionUnresolved + ":" + unboundVar
}
