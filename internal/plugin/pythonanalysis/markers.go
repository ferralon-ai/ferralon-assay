package pythonanalysis

// PEP 508 environment-marker evaluator (PLAN-170 E1, C1).
//
// A requirement in a pip/PEP 508 context may be guarded by an environment marker after a
// ";" — e.g. `foo==1.0 ; python_version < "3.8" and sys_platform == "win32"`. The old
// resolver stripped and discarded the marker unconditionally (versions.go). This evaluates
// it against a DECLARED target-environment descriptor (a variable→value map injected as a
// parameter) and returns a three-valued outcome:
//
//   - selected   — every referenced variable is bound and the expression is true.
//   - not selected — every referenced variable is bound and the expression is false.
//   - unresolved — the marker references a variable the descriptor does not bind (or is
//     malformed / carries an unparseable version value); the caller records declared
//     partiality naming the unbound variable, never silently including or excluding it.
//
// SOUNDNESS / doctrine: this NEVER launches an interpreter to obtain a variable (C5/§3.3).
// Every value is declared. Version-valued comparisons (python_version, python_full_version,
// implementation_version) route through the shared pep440 package — the SAME comparator the
// pipeline disqualification axis uses (C1: two independent comparators would diverge).

import (
	"fmt"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
)

// markerResult is the three-valued outcome of evaluating a PEP 508 marker.
type markerResult struct {
	selected   bool   // marker true (all vars bound) → requirement in the selected set
	unresolved bool   // marker referenced an unbound variable (or was unevaluable)
	unboundVar string // the first (source-order) unbound variable, "" if none/malformed
}

// versionMarkerVars are the marker variables whose values are PEP 440 versions and whose
// comparisons must route through the shared pep440 comparator.
var versionMarkerVars = map[string]bool{
	"python_version":         true,
	"python_full_version":    true,
	"implementation_version": true,
}

// evaluateMarker parses and evaluates marker against the declared descriptor env
// (variable→value). selection is the declared extras selection, used to resolve the PEP 508
// `extra` variable (`extra == "x"` is true iff "x" is selected); pass nil when no selection
// is declared, in which case a marker referencing `extra` is unresolved. It is a pure
// function over declared input — no I/O, no process execution.
func evaluateMarker(marker string, env map[string]string, selection []string) markerResult {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return markerResult{selected: true} // no marker → always selected
	}
	toks, err := lexMarker(marker)
	if err != nil {
		return markerResult{unresolved: true}
	}
	p := &markerParser{toks: toks}
	ast, err := p.parseOr()
	if err != nil || p.pos != len(p.toks) {
		return markerResult{unresolved: true}
	}
	// Anti-drop pre-pass (C1 row 3): if the marker references ANY variable the descriptor
	// does not bind, the requirement is UNRESOLVED — never silently included or excluded —
	// and the first such variable (source order) names the partiality. This is deliberately
	// conservative: an unbound reference anywhere makes the whole marker unresolved.
	for _, name := range markerVarRefs(toks) {
		if !markerVarBound(name, env, selection) {
			return markerResult{unresolved: true, unboundVar: name}
		}
	}
	val, resolved := evalMarkerNode(ast, env, selection)
	if !resolved {
		return markerResult{unresolved: true}
	}
	return markerResult{selected: val}
}

// --- tokens ------------------------------------------------------------------

type markerTokKind int

const (
	tokVar markerTokKind = iota // a bareword variable reference
	tokStr                      // a quoted string literal
	tokOp                       // a comparison/membership operator
	tokAnd
	tokOr
	tokOpen
	tokClose
)

type markerToken struct {
	kind markerTokKind
	text string
}

func isMarkerWordChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

func isMarkerOp(op string) bool {
	switch op {
	case "===", "==", "!=", "~=", "<=", ">=", "<", ">":
		return true
	}
	return false
}

// lexMarker tokenizes a PEP 508 marker. String literals are quoted (' or "); barewords are
// variable references; `and`/`or`/`in`/`not in` are keyword operators; `(`/`)` group.
func lexMarker(s string) ([]markerToken, error) {
	var toks []markerToken
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			toks = append(toks, markerToken{tokOpen, "("})
			i++
		case c == ')':
			toks = append(toks, markerToken{tokClose, ")"})
			i++
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && s[j] != c {
				j++
			}
			if j >= n {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, markerToken{tokStr, s[i+1 : j]})
			i = j + 1
		case strings.IndexByte("<>=!~", c) >= 0:
			j := i
			for j < n && strings.IndexByte("<>=!~", s[j]) >= 0 {
				j++
			}
			op := s[i:j]
			if !isMarkerOp(op) {
				return nil, fmt.Errorf("invalid operator %q", op)
			}
			toks = append(toks, markerToken{tokOp, op})
			i = j
		case isMarkerWordChar(c):
			j := i
			for j < n && isMarkerWordChar(s[j]) {
				j++
			}
			w := s[i:j]
			i = j
			switch w {
			case "and":
				toks = append(toks, markerToken{tokAnd, w})
			case "or":
				toks = append(toks, markerToken{tokOr, w})
			case "in":
				toks = append(toks, markerToken{tokOp, "in"})
			case "not":
				// "not" must be followed by "in".
				k := i
				for k < n && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k+2 <= n && s[k:k+2] == "in" && (k+2 == n || !isMarkerWordChar(s[k+2])) {
					toks = append(toks, markerToken{tokOp, "not in"})
					i = k + 2
				} else {
					return nil, fmt.Errorf("'not' must be followed by 'in'")
				}
			default:
				toks = append(toks, markerToken{tokVar, w})
			}
		default:
			return nil, fmt.Errorf("unexpected character %q", string(c))
		}
	}
	return toks, nil
}

// markerVarRefs returns every variable reference in source order (for the deterministic
// first-unbound choice).
func markerVarRefs(toks []markerToken) []string {
	var vars []string
	for _, t := range toks {
		if t.kind == tokVar {
			vars = append(vars, t.text)
		}
	}
	return vars
}

// markerVarBound reports whether name is bound by the descriptor. `extra` is bound iff a
// (possibly empty) selection was declared; any other variable is bound iff env has the key.
func markerVarBound(name string, env map[string]string, selection []string) bool {
	if name == "extra" {
		return selection != nil
	}
	_, ok := env[name]
	return ok
}

// --- AST + parser ------------------------------------------------------------

type markerNode interface{}

type markerAnd struct{ l, r markerNode }
type markerOr struct{ l, r markerNode }

type markerOperand struct {
	isVar bool
	text  string // variable name (isVar) or literal value
}

type markerCmp struct {
	left, right markerOperand
	op          string
}

type markerParser struct {
	toks []markerToken
	pos  int
}

func (p *markerParser) peek() (markerToken, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return markerToken{}, false
}

func (p *markerParser) parseOr() (markerNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			break
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = markerOr{left, right}
	}
	return left, nil
}

func (p *markerParser) parseAnd() (markerNode, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokAnd {
			break
		}
		p.pos++
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = markerAnd{left, right}
	}
	return left, nil
}

func (p *markerParser) parseTerm() (markerNode, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of marker")
	}
	if t.kind == tokOpen {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		c, ok := p.peek()
		if !ok || c.kind != tokClose {
			return nil, fmt.Errorf("missing ')'")
		}
		p.pos++
		return inner, nil
	}
	return p.parseComparison()
}

func (p *markerParser) parseComparison() (markerNode, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	t, ok := p.peek()
	if !ok || t.kind != tokOp {
		return nil, fmt.Errorf("expected comparison operator")
	}
	p.pos++
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	return markerCmp{left: left, right: right, op: t.text}, nil
}

func (p *markerParser) parseOperand() (markerOperand, error) {
	t, ok := p.peek()
	if !ok {
		return markerOperand{}, fmt.Errorf("expected operand")
	}
	switch t.kind {
	case tokVar:
		p.pos++
		return markerOperand{isVar: true, text: t.text}, nil
	case tokStr:
		p.pos++
		return markerOperand{isVar: false, text: t.text}, nil
	}
	return markerOperand{}, fmt.Errorf("expected variable or string literal")
}

// --- evaluation --------------------------------------------------------------

// evalMarkerNode evaluates the AST. All variables are known-bound by this point (the
// pre-pass ran); resolved is false only when a version value is unparseable (fail-open).
func evalMarkerNode(nd markerNode, env map[string]string, selection []string) (val, resolved bool) {
	switch t := nd.(type) {
	case markerAnd:
		l, lr := evalMarkerNode(t.l, env, selection)
		r, rr := evalMarkerNode(t.r, env, selection)
		if !lr || !rr {
			return false, false
		}
		return l && r, true
	case markerOr:
		l, lr := evalMarkerNode(t.l, env, selection)
		r, rr := evalMarkerNode(t.r, env, selection)
		if !lr || !rr {
			return false, false
		}
		return l || r, true
	case markerCmp:
		return evalMarkerCmp(t, env, selection)
	}
	return false, false
}

func markerOperandValue(o markerOperand, env map[string]string) string {
	if o.isVar {
		return env[o.text]
	}
	return o.text
}

func isExtraOperand(o markerOperand) bool { return o.isVar && o.text == "extra" }

func isVersionVarOperand(o markerOperand) bool { return o.isVar && versionMarkerVars[o.text] }

func isVersionOp(op string) bool {
	switch op {
	case "===", "==", "!=", "~=", "<=", ">=", "<", ">":
		return true
	}
	return false
}

func evalMarkerCmp(c markerCmp, env map[string]string, selection []string) (bool, bool) {
	if isExtraOperand(c.left) || isExtraOperand(c.right) {
		return evalExtraCmp(c, selection)
	}
	lVer := isVersionVarOperand(c.left)
	rVer := isVersionVarOperand(c.right)
	if (lVer || rVer) && isVersionOp(c.op) {
		return evalVersionCmp(c, env, lVer, rVer)
	}
	lv := markerOperandValue(c.left, env)
	rv := markerOperandValue(c.right, env)
	switch c.op {
	case "==", "===":
		return lv == rv, true
	case "!=":
		return lv != rv, true
	case "in":
		return strings.Contains(rv, lv), true
	case "not in":
		return !strings.Contains(rv, lv), true
	case "<":
		return lv < rv, true
	case "<=":
		return lv <= rv, true
	case ">":
		return lv > rv, true
	case ">=":
		return lv >= rv, true
	}
	return false, false
}

// evalExtraCmp resolves the PEP 508 `extra` variable as membership in the declared
// selection: `extra == "x"` iff "x" is selected.
func evalExtraCmp(c markerCmp, selection []string) (bool, bool) {
	var lit string
	if isExtraOperand(c.left) {
		lit = c.right.text
	} else {
		lit = c.left.text
	}
	member := containsString(selection, lit)
	switch c.op {
	case "==", "===", "in":
		return member, true
	case "!=", "not in":
		return !member, true
	}
	return false, false
}

// evalVersionCmp routes the comparison through the shared pep440 comparator. When one side
// is a version variable and the other a literal, it builds the equivalent PEP 440 clause
// and asks pep440.Satisfies; when the version variable is on the right, the operator is
// flipped. Two version variables compare via pep440.Compare.
func evalVersionCmp(c markerCmp, env map[string]string, lVer, rVer bool) (bool, bool) {
	if lVer && rVer {
		a, ok1 := pep440.Parse(env[c.left.text])
		b, ok2 := pep440.Parse(env[c.right.text])
		if !ok1 || !ok2 {
			return false, false
		}
		return applyCmpOp(pep440.Compare(a, b), c.op)
	}
	var varName, litVal, op string
	if lVer {
		varName, litVal, op = c.left.text, markerOperandValue(c.right, env), c.op
	} else {
		varName, litVal, op = c.right.text, markerOperandValue(c.left, env), flipCmpOp(c.op)
		if op == "" {
			return false, false // reversed ~= / === is not meaningfully evaluable
		}
	}
	vv := env[varName]
	v, ok := pep440.Parse(vv)
	if !ok {
		return false, false
	}
	return pep440.Satisfies(v, vv, op+litVal)
}

func applyCmpOp(cmp int, op string) (bool, bool) {
	switch op {
	case "==", "===":
		return cmp == 0, true
	case "!=":
		return cmp != 0, true
	case "<":
		return cmp < 0, true
	case "<=":
		return cmp <= 0, true
	case ">":
		return cmp > 0, true
	case ">=":
		return cmp >= 0, true
	}
	return false, false // ~= cannot be expressed as a single ordering
}

// flipCmpOp reverses an ordering operator so `"3.8" <= python_version` becomes
// `python_version >= "3.8"`. Returns "" for operators with no meaningful reversal.
func flipCmpOp(op string) string {
	switch op {
	case "==", "!=", "===":
		return op
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">":
		return "<"
	case ">=":
		return "<="
	}
	return ""
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
