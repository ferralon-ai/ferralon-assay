package pythonanalysis

// pip-compile "# via" provenance edges for requirements files.
//
// pip-tools annotates every requirement it writes with the packages (or input files) that
// pulled it in, in one of three shapes:
//
//	aiosignal==1.3.1
//	    # via aiohttp                       (single line; older releases comma-separate: "# via a, b")
//	aiohttp==3.9.1
//	    # via
//	    #   -r requirements.in
//	    #   langchain                       (multi-line block, one source per line)
//	six==1.16.0               # via python-dateutil   (inline, pip-tools < 5)
//
// A named package is a parent edge (parent → this requirement). An input file ("-r x.in") or
// the project itself ("name (pyproject.toml)") marks the requirement direct. A constraint file
// ("-c x.txt") only bounds a version and proves nothing about why the package is present, so it
// is ignored. A parent the file does not itself list (or lists under a marker that evaluated
// false) yields no edge.

import (
	"sort"
	"strings"
)

// viaAnnotation is the provenance pip-compile recorded for one requirement.
type viaAnnotation struct {
	direct  bool     // pulled in by an input file or by the project itself
	parents []string // normalized names of packages that depend on it
}

// pipCompileVia collects "# via" annotations keyed by the normalized name of the requirement
// they annotate. It returns nil when the file carries no annotations at all.
func pipCompileVia(data []byte) map[string]*viaAnnotation {
	var (
		out   map[string]*viaAnnotation
		cur   string
		inVia bool
	)
	add := func(token string) {
		if cur == "" {
			return
		}
		if out == nil {
			out = map[string]*viaAnnotation{}
		}
		a := out[cur]
		if a == nil {
			a = &viaAnnotation{}
			out[cur] = a
		}
		direct, parent := classifyViaToken(token)
		if direct {
			a.direct = true
		}
		if parent != "" {
			a.parents = append(a.parents, parent)
		}
	}
	addList := func(list string) {
		for _, tok := range strings.Split(list, ",") {
			add(tok)
		}
	}

	for _, raw := range joinContinuations(string(data)) {
		t := strings.TrimSpace(raw)
		if t == "" {
			inVia = false
			continue
		}
		if strings.HasPrefix(t, "#") {
			body := strings.TrimSpace(t[1:])
			switch {
			case body == "via":
				inVia = true
			case strings.HasPrefix(body, "via "):
				addList(body[len("via "):])
				inVia = false
			case inVia && (strings.HasPrefix(t, "#  ") || strings.HasPrefix(t, "#\t")):
				add(body)
			default:
				inVia = false
			}
			continue
		}
		inVia = false
		spec := stripReqCommentSafe(t)
		comment := strings.TrimSpace(t[len(spec):])
		cur = ""
		if !strings.HasPrefix(spec, "-") {
			head := spec
			if i := strings.IndexByte(head, ';'); i >= 0 {
				head = head[:i]
			}
			head, _ = extractHashes(head)
			if name, _, _, _ := parseRequirementSpec(strings.TrimSpace(head)); name != "" {
				cur = normalizePyCoordinate(name)
			}
		}
		if body := strings.TrimSpace(strings.TrimPrefix(comment, "#")); strings.HasPrefix(body, "via ") {
			addList(body[len("via "):])
		}
	}
	return out
}

// classifyViaToken classifies one "# via" source: an input file or the project itself is
// direct; a package name is a parent; a constraint file or anything unrecognized is neither.
func classifyViaToken(token string) (direct bool, parent string) {
	token = strings.TrimSpace(token)
	switch {
	case token == "":
		return false, ""
	case strings.HasPrefix(token, "-r ") || strings.HasPrefix(token, "--requirement "):
		return true, ""
	case strings.HasPrefix(token, "-c ") || strings.HasPrefix(token, "--constraint "):
		return false, ""
	case strings.HasSuffix(token, ")") && strings.Contains(token, " ("):
		// "my-project (pyproject.toml)" / "(setup.cfg)" / "(setup.py)": the project being compiled.
		return true, ""
	}
	name := token
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	if !validProjectName(name) {
		return false, ""
	}
	return false, normalizePyCoordinate(name)
}

// applyViaEdges sets Parents and Relationship on requirements that carry a "# via"
// annotation. Parents are rewritten to the parent requirement's Name as written in the same
// file, because inventory node IDs are built from that Name. A requirement with no annotation,
// or whose annotated parents the file does not list, keeps its relUnexpressed classification.
func applyViaEdges(reqs []pyReq, via map[string]*viaAnnotation) {
	if len(via) == 0 {
		return
	}
	byNorm := map[string]string{}
	for _, r := range reqs {
		if r.Kind != reqNormal || (!r.Selected && !r.Unresolved) {
			continue
		}
		n := normalizePyCoordinate(r.Name)
		if _, dup := byNorm[n]; !dup {
			byNorm[n] = r.Name
		}
	}
	for i := range reqs {
		r := &reqs[i]
		if r.Kind != reqNormal {
			continue
		}
		self := normalizePyCoordinate(r.Name)
		a := via[self]
		if a == nil {
			continue
		}
		set := map[string]bool{}
		for _, p := range a.parents {
			if p == self {
				continue
			}
			if name, ok := byNorm[p]; ok {
				set[name] = true
			}
		}
		parents := make([]string, 0, len(set))
		for p := range set {
			parents = append(parents, p)
		}
		sort.Strings(parents)
		switch {
		case a.direct:
			r.Relationship = relDirect
		case len(parents) > 0:
			r.Relationship = relTransitive
		default:
			continue
		}
		if len(parents) > 0 {
			r.Parents = parents
		}
	}
}
