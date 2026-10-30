package jsanalysis

// Rebinding.
//
// The resolver reads a callee name against the module's import bindings and module-level
// function declarations (resolveName), and a method's receiver against the module's tracked
// instances (resolveReceiverMethod). That is what the name denotes only where nothing else
// binds it. A declined call lists its candidates as Targets only when the scan proves no other
// binding can be in force where the call runs; markRebound marks every call it cannot prove
// that for, and callgraph.go lists such a call unbounded.
//
// The proof is conservative: a binding anywhere in the outermost block that holds the call
// counts, whether or not it is in scope at the call. The name is rebound when
//   - that block, or any block inside it, binds it: a parameter (destructured, defaulted or
//     rest included), a let, const or var, a function declaration, a catch binding, or a
//     destructuring pattern (globalScope reads all of them);
//   - a class or a named function expression in that block, or the named function expression
//     whose body that block is, takes the name;
//   - at the top level, it is assigned, or bound by a let, const or var that is neither a
//     function value (a declaration the resolver also reads) nor the one import or instance
//     binding the resolver used;
//   - it is the target of a for-in or for-of head or of a destructuring assignment anywhere
//     in the module;
//   - the module has a with statement, which can put any object's member in its place.

// markRebound sets rebound on every call in calls whose callee name, or the receiver its
// method is read from, may be bound to something other than what the resolver reads. scope is
// the module's scope model (extractBindingsScoped); mb its bindings.
func markRebound(clean []rune, scope *globalScope, mb moduleBindings, calls []callSite) {
	if scope == nil {
		for k := range calls {
			calls[k].rebound = true
		}
		return
	}
	ri := newReboundIndex(clean, scope, mb, calls)
	for k := range calls {
		cs := &calls[k]
		if cs.opaque || cs.calleeFrame || cs.receiverThis {
			continue // nothing the resolver bounds by name
		}
		cs.rebound = ri.rebound(boundName(*cs), cs.at)
	}
}

// boundName is the name whose binding the resolver relies on for a call: the receiver of a
// method call, the head of a longer chain, or the callee itself.
func boundName(cs callSite) string {
	switch {
	case cs.receiver != "":
		return cs.receiver
	case cs.head != "":
		return cs.head
	}
	return cs.calleeName
}

// reboundIndex answers rebound for one module.
type reboundIndex struct {
	clean    []rune
	gs       *globalScope
	mb       moduleBindings
	with     bool
	scopes   map[string][]int        // name → the blocks (≥0) that bind it
	root     []int                   // block → its outermost enclosing block
	retarget map[string]bool         // names some for head or destructuring assignment rebinds
	nested   map[int]map[string]bool // outermost block → the names namesNested finds in it (lazy)
}

func newReboundIndex(clean []rune, gs *globalScope, mb moduleBindings, calls []callSite) *reboundIndex {
	tf := gs.tf
	ri := &reboundIndex{clean: clean, gs: gs, mb: mb, with: gs.withStatement(clean),
		scopes: map[string][]int{}, root: make([]int, len(tf.opens)), retarget: map[string]bool{}}
	for s, names := range gs.byScope {
		if s < 0 {
			continue
		}
		for name := range names {
			ri.scopes[name] = append(ri.scopes[name], s)
		}
	}
	for k := range tf.opens {
		r := k
		for tf.parent[r] >= 0 {
			r = tf.parent[r]
		}
		ri.root[k] = r
	}
	wanted := map[string]bool{}
	for _, cs := range calls {
		if !cs.opaque && !cs.calleeFrame {
			wanted[boundName(cs)] = true
		}
	}
	n := len(clean)
	for i := 0; i < n; {
		if !isIdentStart(clean[i]) || i > 0 && isIdentPart(clean[i-1]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		// A declaration's own name (const { f } = o) is in scopes; rebound reads the rest.
		if wanted[word] && !ri.retarget[word] && !gs.sites[i] && rebound(clean, gs.bracketsOf(clean), i, next) {
			ri.retarget[word] = true
		}
		i = next
	}
	return ri
}

// rebound reports whether name, read at position at, may denote something other than the
// module-level binding the resolver reads.
func (ri *reboundIndex) rebound(name string, at int) bool {
	if name == "" || ri.with || ri.retarget[name] {
		return true
	}
	if ri.topLevelRebinds(name) {
		return true
	}
	tf := ri.gs.tf
	k := tf.block(at)
	if k < 0 {
		return false
	}
	outer := ri.root[k]
	for _, s := range ri.scopes[name] {
		if ri.root[s] == outer {
			return true
		}
	}
	if ri.namedNested(outer)[name] {
		return true
	}
	// A function expression's own name binds inside its body.
	for b := k; b >= 0; b = tf.parent[b] {
		if kw := tf.fnKw[b]; kw >= 0 && funcKeywordNames(ri.clean, kw, name) && !funcDeclaration(ri.clean, kw) {
			return true
		}
	}
	return false
}

// topLevelRebinds reports whether a top-level binding other than the ones the resolver reads
// gives name a value: an assignment, or a let, const or var that is neither function-valued
// nor the one import or instance binding of the name.
func (ri *reboundIndex) topLevelRebinds(name string) bool {
	values := map[int]bool{}
	for _, d := range ri.gs.byScope[-1][name] {
		decl := ri.gs.decls[d]
		switch decl.kind {
		case 'f', 'i':
		case 'c', 'l', 'v':
			if decl.start < decl.end {
				if _, ok := funcExprAt(ri.clean, decl.start, decl.end); ok {
					continue
				}
			}
			values[decl.at] = true
		default: // 'a' an assignment, or anything else
			return true
		}
	}
	allowed := 0
	if _, ok := ri.mb.imports[name]; ok && !ri.mb.ambiguous[name] {
		allowed = 1
	} else if _, ok := ri.mb.instances[name]; ok {
		allowed = 1
	}
	return len(values) > allowed
}

// namedNested returns the names a class or function keyword in the outermost block outer
// names, read once per block rather than once per name looked up in it.
func (ri *reboundIndex) namedNested(outer int) map[string]bool {
	if names, ok := ri.nested[outer]; ok {
		return names
	}
	if ri.nested == nil {
		ri.nested = map[int]map[string]bool{}
	}
	tf := ri.gs.tf
	names := namesNested(ri.clean, tf.opens[outer], tf.closes[outer])
	ri.nested[outer] = names
	return names
}

// namesNested returns the names a class or function keyword in clean[from:to] names.
func namesNested(clean []rune, from, to int) map[string]bool {
	names := map[string]bool{}
	for i := from; i < to && i < len(clean); {
		if !isIdentStart(clean[i]) || i > 0 && isIdentPart(clean[i-1]) {
			i++
			continue
		}
		word, next := readWord(clean, i)
		if word == "class" || word == "function" {
			names[funcKeywordName(clean, i)] = true
		}
		i = next
	}
	return names
}

// funcKeywordNames reports whether the class or function keyword at kw is followed by name
// (after a generator's '*').
func funcKeywordNames(clean []rune, kw int, name string) bool {
	return funcKeywordName(clean, kw) == name
}

// funcKeywordName returns the word that follows the class or function keyword at kw (after a
// generator's '*').
func funcKeywordName(clean []rune, kw int) string {
	_, p := readWord(clean, kw)
	p = skipSpace(clean, p)
	if p < len(clean) && clean[p] == '*' {
		p = skipSpace(clean, p+1)
	}
	w, _ := peekWord(clean, p)
	return w
}

// funcDeclaration reports whether the function keyword at kw starts a declaration statement,
// whose name binds in the enclosing scope, rather than an expression, whose name binds only in
// its own body.
func funcDeclaration(clean []rune, kw int) bool {
	b := skipSpaceBack(clean, kw-1)
	if w, s := wordBefore(clean, b); w == "async" {
		b = skipSpaceBack(clean, s-1)
	}
	if w, s := wordBefore(clean, b); w == "default" {
		b = skipSpaceBack(clean, s-1)
	}
	if w, _ := wordBefore(clean, b); w == "export" {
		return true
	}
	return b < 0 || clean[b] == ';' || clean[b] == '{' || clean[b] == '}'
}
