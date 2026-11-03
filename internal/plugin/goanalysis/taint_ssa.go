package goanalysis

import (
	"cmp"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// taintAnalysis is a variable-level, inter-procedural value-flow taint engine
// over SSA. Sources are the parameters of ingress functions (the attacker-
// controllable entry args); a finding is a value-flow path from a source Value to
// a tainted argument of a resolved sink call. Sanitizers clear taint on their
// result (sanitizers.go). Partiality triggers (reflection / cgo / unresolved
// dynamic dispatch) encountered on a tainted path are recorded so the result is
// only ever non-Partial on a fully-resolved, clean flow (inv.5).
type taintAnalysis struct {
	sp    *ssaProgram
	sinks map[string]bool // sink SCIP id -> wanted; nil wants every callee

	tainted map[ssa.Value]bool // values reached by taint
	// origin records, for a tainted value, the source ingress SCIP id and the
	// SSA function that introduced it, so a sink hit can name its ingress.
	origin map[ssa.Value]taintOrigin
	// onPath holds every SSA function a tainted value flowed through; the
	// path-scoped partiality check runs over exactly these.
	onPath map[*ssa.Function]bool
	// hits maps a sink SCIP id to the ingress SCIP id that reached it.
	hits map[string]string
}

type taintOrigin struct {
	ingress string
	enclFn  *ssa.Function
}

// runTaint seeds sources from ingress functions and propagates taint to a
// fixpoint, returning each sink reached mapped to its attributed ingress, and the
// path-scoped partiality. ingresses maps an ingress SCIP id to its SSA function;
// a nil sinks records every static callee a tainted argument reaches.
func runTaint(sp *ssaProgram, ingresses map[string]*ssa.Function, sinks map[string]bool) (map[string]string, map[string]bool) {
	ta := &taintAnalysis{
		sp:      sp,
		sinks:   sinks,
		tainted: map[ssa.Value]bool{},
		origin:  map[ssa.Value]taintOrigin{},
		onPath:  map[*ssa.Function]bool{},
		hits:    map[string]string{},
	}

	var work []ssa.Value
	seed := func(v ssa.Value, o taintOrigin) {
		if v == nil || ta.tainted[v] {
			return
		}
		ta.tainted[v] = true
		ta.origin[v] = o
		if o.enclFn != nil {
			ta.onPath[o.enclFn] = true
		}
		work = append(work, v)
	}

	// Sources: every parameter of every ingress function is attacker-controllable.
	// Each ingress is seeded and drained to a fixpoint in turn, in ingressOrder, so a
	// value keeps the first ingress in that order that reaches it, and a sink is
	// credited to the first ingress in that order whose taint reaches it. The tainted
	// set is the same in any order; only the credit depends on it, which ranging over
	// the map left to its iteration order.
	for _, id := range sp.ingressOrder(ingresses) {
		fn := ingresses[id]
		o := taintOrigin{ingress: id, enclFn: fn}
		for _, p := range fn.Params {
			seed(p, o)
		}
		// Method ingresses also expose free vars / the receiver is generally not
		// attacker-controlled, so only parameters are seeded.
		// The receiver is not seeded directly, but a store of tainted data into
		// one of its fields taints it anyway (see the ssa.Store case in
		// propagate), so this choice is only partly honoured.
		for len(work) > 0 {
			v := work[len(work)-1]
			work = work[:len(work)-1]
			ta.propagate(v, seed)
		}
	}

	reasons := map[string]bool{}
	for fn := range ta.onPath {
		classifyFuncPartiality(fn, reasons)
	}

	return ta.hits, reasons
}

// ingressOrder returns the SCIP ids of the ingresses with a function, ordered by the
// function's package path, then its full name, then its source position, then the SCIP
// id, which the map keys make unique. Every part is the same from run to run; a
// token.Pos is not, since it depends on the order files were added to the file set,
// so the position compares as file, line and column.
func (s *ssaProgram) ingressOrder(ingresses map[string]*ssa.Function) []string {
	ids := make([]string, 0, len(ingresses))
	for id, fn := range ingresses {
		if fn != nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if c := s.compareFuncs(ingresses[ids[i]], ingresses[ids[j]]); c != 0 {
			return c < 0
		}
		return ids[i] < ids[j]
	})
	return ids
}

// compareFuncs orders two SSA functions by package path, full name and source position
// (file, line, column).
func (s *ssaProgram) compareFuncs(a, b *ssa.Function) int {
	if c := cmp.Compare(funcPkgPath(a), funcPkgPath(b)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.String(), b.String()); c != 0 {
		return c
	}
	pa, pb := s.prog.Fset.Position(a.Pos()), s.prog.Fset.Position(b.Pos())
	if c := cmp.Compare(pa.Filename, pb.Filename); c != 0 {
		return c
	}
	if c := cmp.Compare(pa.Line, pb.Line); c != 0 {
		return c
	}
	return cmp.Compare(pa.Column, pb.Column)
}

func funcPkgPath(fn *ssa.Function) string {
	if p := funcTypePackage(fn); p != nil {
		return p.Path()
	}
	return ""
}

// propagate pushes taint from a tainted value v to the values its referrers
// derive from it, forwarding through assignments, phi, field/element access, map
// and string lookup, type assertion, extract, conversions, tainted-operand binops,
// and (inter-procedurally) from a call's actual arg to the callee's formal param.
// Sanitizer results are NOT tainted. A tainted arg to a resolved sink records a
// finding.
func (ta *taintAnalysis) propagate(v ssa.Value, seed func(ssa.Value, taintOrigin)) {
	o := ta.origin[v]
	refs := v.Referrers()
	if refs == nil {
		return
	}
	for _, instr := range *refs {
		switch in := instr.(type) {
		case *ssa.Phi:
			seed(in, o)
		case *ssa.UnOp:
			// Loads (*x) and other unary ops carry taint forward.
			seed(in, o)
		case *ssa.BinOp:
			// A binary op with a tainted operand yields a tainted result.
			seed(in, o)
		case *ssa.ChangeType:
			seed(in, o)
		case *ssa.Convert:
			seed(in, o)
		case *ssa.ChangeInterface:
			seed(in, o)
		case *ssa.MakeInterface:
			seed(in, o)
		case *ssa.Slice:
			seed(in, o)
		case *ssa.FieldAddr:
			seed(in, o)
		case *ssa.IndexAddr:
			seed(in, o)
		case *ssa.Field:
			seed(in, o)
		case *ssa.Index:
			seed(in, o)
		case *ssa.Lookup:
			// m[k] on a tainted map (r.Header["X-A"]), or s[i] on a tainted string.
			seed(in, o)
		case *ssa.TypeAssert:
			// x.(T) yields the tainted interface's dynamic value; the comma-ok
			// form's tuple carries it to its Extract.
			seed(in, o)
		case *ssa.Extract:
			seed(in, o)
		case *ssa.Store:
			// Storing a tainted value into an address taints that address, so
			// later loads of the address observe taint.
			if in.Val == v {
				seed(in.Addr, o)
				// A store through a field or element address also taints the
				// address's base, and the base's base, down the whole chain of
				// them (addrBases), so a later read through another field or
				// element of any of them observes taint. &w{r: r} stores through
				// &t0.r; o.in.a = x stores through &(&o.in).a, which taints o, so
				// o.in.b reads as tainted; and a variadic call or a slice literal
				// builds its argument as alloc, IndexAddr, Store, Slice, so
				// fmt.Sprintf("%s", x) and exec.Command("sh", "-c", x) receive a
				// tainted slice. This is field- and element-insensitive by design:
				// every field and element of a base reads as tainted. The chain
				// continues through a load of a field or element address: s.p.a =
				// x, with p a pointer field, stores through *(&s.p), and every later
				// read of s.p is a fresh load of &s.p, so the chain goes on to &s.p
				// and s, and s.p.a then reads as tainted (as s.p.b does). It also
				// continues through a slice view, so s := arr[:]; s[0] = x taints
				// arr. It stops at a load of anything else, such as a global
				// pointer or a variable a closure captures: g.a = x, with g a global
				// pointer, taints only the load of g it stores through, which a later
				// read of g.a, a fresh load of g, does not observe; and a store a
				// closure makes through a pointer it captures is not seen by the
				// enclosing function's later read of that pointer. A package-level
				// struct value is different: cfg.p.a = x, with cfg a package-level
				// struct, takes &cfg.p straight off the global, so the chain does
				// reach cfg and seeds it. The seed goes no further, though: go/ssa
				// records no referrers for a global, so no read of cfg, in this
				// function or any other, observes it, and a store into package state
				// in one handler does not taint a read in another. Nor does a store a
				// call makes through a pointer it is passed reach the caller (see
				// propagateCall).
				//
				// This deliberately over-approximates, and it partly undoes the
				// choice not to seed receivers (see runTaint): in a method, s.last
				// = r.URL.Path taints s, so a call through another field of s
				// (s.db.Query(constQ)) counts as tainted and can be a sink hit. It
				// only affects which trace and entry point are picked, and the
				// grade can only rise; no verdict reads it.
				for _, base := range addrBases(in.Addr) {
					seed(base, o)
				}
			}
		case *ssa.MapUpdate:
			if in.Value == v {
				seed(in.Map, o)
			}
		case ssa.CallInstruction:
			ta.propagateCall(in, v, o, seed)
		}
	}
}

// addrBases returns the bases under a field or element address, nearest first: for
// &(&t0.in).a it is &t0.in, then t0; for &t0[i] it is t0. It also steps through a
// slice view to the value it slices (for &t1[i], t1 = t0[:], it is t1, then t0) and
// through a load of a field or element address to that address (for &t2.a, t2 =
// *(&t0.p), it is t2, then &t0.p, then t0). It stops at the first base that is none
// of these. That last base can be a package-level variable (for &cfg.a it is cfg),
// which propagate cannot follow, since a global has no referrers; a load of a global
// pointer (for &t1.a, t1 = *g, it is t1) never reaches the global.
func addrBases(addr ssa.Value) []ssa.Value {
	var bases []ssa.Value
	for {
		switch a := addr.(type) {
		case *ssa.FieldAddr:
			addr = a.X
		case *ssa.IndexAddr:
			addr = a.X
		case *ssa.Slice:
			addr = a.X
		case *ssa.UnOp:
			if a.Op != token.MUL || !isFieldOrElemAddr(a.X) {
				return bases
			}
			addr = a.X
		default:
			return bases
		}
		bases = append(bases, addr)
	}
}

func isFieldOrElemAddr(v ssa.Value) bool {
	switch v.(type) {
	case *ssa.FieldAddr, *ssa.IndexAddr:
		return true
	}
	return false
}

// propagateCall handles taint at a call site where v is a tainted argument:
// records a sink finding, forwards taint into a static callee's matching formal
// parameter (clearing it for sanitizers), and marks the enclosing/called
// functions on the taint path.
func (ta *taintAnalysis) propagateCall(in ssa.CallInstruction, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin)) {
	common := in.Common()
	if fn := in.Parent(); fn != nil {
		ta.onPath[fn] = true
	}

	if b, ok := common.Value.(*ssa.Builtin); ok {
		propagateBuiltin(b, in, common, v, o, seed)
		return
	}

	callee := common.StaticCallee()

	// Sink check: a tainted value used as an argument to a resolved sink call is
	// a finding. The sink identity is the callee's SCIP id.
	if callee != nil {
		sym := ta.sp.scipFunc(callee)
		if (ta.sinks == nil || ta.sinks[sym]) && argContains(common.Args, v) {
			if _, seen := ta.hits[sym]; !seen {
				ta.hits[sym] = o.ingress
			}
		}
	}

	// Inter-procedural forwarding: taint flows from the actual arg to the callee's
	// formal parameter. A sanitizer call clears taint — its result is not seeded,
	// and we do not forward into its body for sink purposes.
	if callee == nil || callee.Blocks == nil {
		// Only the module's own packages get SSA bodies, so a stdlib or dependency
		// callee (r.Header.Get, url.Values.Get, strings.TrimSpace) has none: an
		// unmodeled transform forwards taint from a tainted argument, the receiver
		// included, to its result. A (T, error) result's tuple carries it to its
		// Extract. A dynamic call with no static callee forwards nothing; the
		// append and copy builtins are modeled above (propagateBuiltin).
		// Only the result is tainted, never a pointer argument the callee writes
		// through: json.Unmarshal(body, &v) and json.NewDecoder(r.Body).Decode(&req)
		// leave v and req clean, so a sink that reads them is not a taint hit. This
		// is a known miss, like the stop points in propagate's store case, and a
		// first-party callee misses it too: a store through its pointer parameter
		// taints that parameter and its bases inside the callee, never the caller's
		// argument. Seeding a call's pointer arguments would have to see through the
		// interface or variadic slice they are usually passed in, and would taint
		// the receiver of every call made with a tainted ctx (a *sql.DB after one
		// db.ExecContext(ctx, q)), so every later call on it would count. The miss
		// can only leave a grade at control_flow_only; it never moves a verdict.
		// This is also how a context.Context becomes tainted: r.Context() is such
		// a call on the tainted request, so its result is tainted. The callees that
		// then receive ctx are not tainted as a whole; ctx spreads three ways. A
		// sink that takes ctx as any argument is a hit (exec.CommandContext(ctx,
		// "const")). The result of every statically resolved call that takes ctx,
		// other than a sanitizer, is tainted, whether or not it depends on ctx
		// (forwardsUnbuilt, and the isSanitizer return below): here, a library
		// call's (context.WithTimeout(ctx, d), db.QueryRowContext(ctx, constQ)),
		// and below, a first-party call's (lookup(ctx, "const")). A ctx passed to
		// an interface method or a function value leaves the result clean, as the
		// dynamic-call sentence above says. And a first-party callee's ctx parameter
		// is tainted, never its other parameters, so the same holds for every call
		// it makes with ctx, down the call tree. Like the field-base seed, this
		// only affects trace and entry-point selection, never a verdict.
		// A request accessor called on a tainted router context is modeled instead:
		// its result is the request data it reads, and a binder's target is the
		// request data it decodes. contextAccess alone decides a call on the router
		// context, so a method that reads no request data (FullPath, GetString)
		// leaves its result clean.
		target, read := contextAccess(common, callee, v)
		if target != nil {
			seed(target, o)
		}
		if read || (!onRouterContext(common, callee, v) && forwardsUnbuilt(common, callee, v)) {
			if val, ok := in.(ssa.Value); ok {
				seed(val, o)
			}
		}
		return
	}
	if isSanitizer(callee) {
		return
	}
	ta.onPath[callee] = true
	forwardArgs(common, callee, v, o, seed)

	// The call result carries taint when a tainted value flows in and the callee
	// is not a sanitizer (conservative: an unmodeled transform forwards taint).
	if val, ok := in.(ssa.Value); ok {
		seed(val, o)
	}
}

// propagateBuiltin models the builtins that move data from one argument to another:
// append's result carries taint from any tainted argument, the slice it extends or the
// elements it adds (args = append(args, x) builds x into a slice first, which the
// store case taints); copy taints its destination, and the bases under it
// (addrBases), when its source is tainted. Every other builtin forwards nothing.
func propagateBuiltin(b *ssa.Builtin, in ssa.CallInstruction, common *ssa.CallCommon, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin)) {
	switch b.Name() {
	case "append":
		if val, ok := in.(ssa.Value); ok {
			seed(val, o)
		}
	case "copy":
		if len(common.Args) == 2 && common.Args[1] == v {
			dst := common.Args[0]
			seed(dst, o)
			for _, base := range addrBases(dst) {
				seed(base, o)
			}
		}
	}
}

// forwardArgs seeds the callee's formal parameters that correspond to the tainted
// actual argument v, accounting for the receiver offset on method calls.
func forwardArgs(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value, o taintOrigin, seed func(ssa.Value, taintOrigin)) {
	for i, a := range common.Args {
		if a != v {
			continue
		}
		if i < len(callee.Params) {
			seed(callee.Params[i], taintOrigin{ingress: o.ingress, enclFn: callee})
		}
	}
}

// forwardsUnbuilt reports whether a call to a callee with no built body taints its
// result: the callee is statically known, is not a modeled sanitizer, and takes
// the tainted value v as an argument (a static method call's receiver is Args[0]).
func forwardsUnbuilt(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value) bool {
	return callee != nil && !isSanitizer(callee) && argContains(common.Args, v)
}

func argContains(args []ssa.Value, v ssa.Value) bool {
	for _, a := range args {
		if a == v {
			return true
		}
	}
	return false
}

// ginContextAccessors are the *gin.Context methods that return attacker-controlled
// request data. A gin handler's *gin.Context parameter is seeded like every ingress
// parameter, and its Request field carries taint through the ordinary field and load
// edges; these accessors are the reads that go through a method instead. ClientIP
// counts: behind trusted proxies it returns the X-Forwarded-For value the client
// sent, and otherwise the peer address, neither of which the application wrote. FullPath is
// not one: it returns the matched route's registered template ("/user/:id"), which
// the application wrote, not anything the request carries.
var ginContextAccessors = map[string]bool{
	"Param": true, "Query": true, "PostForm": true,
	"DefaultQuery": true, "GetQuery": true, "QueryArray": true, "QueryMap": true,
	"GetQueryArray": true, "GetQueryMap": true,
	"GetPostForm": true, "DefaultPostForm": true, "PostFormArray": true, "GetPostFormArray": true,
	"PostFormMap": true, "GetPostFormMap": true, "FormFile": true, "MultipartForm": true,
	"GetHeader": true, "ContentType": true, "Cookie": true, "GetRawData": true,
	"ClientIP": true, "RemoteIP": true,
}

// isGinBinder reports whether name is one of *gin.Context's Bind / ShouldBind* family
// (Bind, BindJSON, BindQuery, BindUri, ..., MustBindWith, ShouldBind, ShouldBindJSON,
// ShouldBindBodyWith, ...), each of which decodes the request into the pointer it is
// given as its first argument.
func isGinBinder(name string) bool {
	return strings.HasPrefix(name, "Bind") || strings.HasPrefix(name, "ShouldBind") || name == "MustBindWith"
}

// echoContextAccessors are the echo.Context methods that return attacker-controlled
// request data: path, query and form values, uploaded files, the raw query string, the
// client IP, the request itself and its cookies.
// echo.Context is an INTERFACE, so these are invoke calls with the context as the
// receiver, never a static callee.
var echoContextAccessors = map[string]bool{
	"Param": true, "ParamValues": true, "QueryParam": true, "QueryParams": true, "FormValue": true,
	"FormParams": true, "FormFile": true, "MultipartForm": true, "QueryString": true,
	"RealIP": true, "Request": true, "Cookie": true, "Cookies": true,
}

// echoContextBinders are the echo.Context methods that decode the request into the
// pointer they are given.
var echoContextBinders = map[string]bool{"Bind": true}

// contextAccess models a call on the tainted router context v whose body is not
// built: read is true when the call's result is request data (an accessor), and
// target is the value a binder decodes the request into (the pointer it is given,
// unboxed), nil otherwise. Both contexts are identified by the import path of the
// package declaring them: gin's *Context receiver of a static call, and echo's
// Context interface an invoke call is made on.
func contextAccess(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value) (target ssa.Value, read bool) {
	var name string
	var args []ssa.Value
	switch {
	case common.IsInvoke():
		if common.Value != v || common.Method == nil || !isNamed(v.Type(), "github.com/labstack/echo/v4", "Context") {
			return nil, false
		}
		name, args = common.Method.Name(), common.Args
		if echoContextBinders[name] && len(args) > 0 {
			return boundTarget(args[0]), false
		}
		return nil, echoContextAccessors[name]
	case callee != nil:
		recv := callee.Signature.Recv()
		if recv == nil || !isPointerToNamed(recv.Type(), "github.com/gin-gonic/gin", "Context") ||
			len(common.Args) == 0 || common.Args[0] != v {
			return nil, false
		}
		name, args = callee.Name(), common.Args[1:]
		if isGinBinder(name) && len(args) > 0 {
			return boundTarget(args[0]), false
		}
		return nil, ginContextAccessors[name]
	}
	return nil, false
}

// onRouterContext reports whether the call is one contextAccess models: a static call
// with gin's *Context receiver v, or an invoke call on echo's Context v.
func onRouterContext(common *ssa.CallCommon, callee *ssa.Function, v ssa.Value) bool {
	if common.IsInvoke() {
		return common.Value == v && common.Method != nil && isNamed(v.Type(), "github.com/labstack/echo/v4", "Context")
	}
	if callee == nil {
		return false
	}
	recv := callee.Signature.Recv()
	return recv != nil && isPointerToNamed(recv.Type(), "github.com/gin-gonic/gin", "Context") &&
		len(common.Args) > 0 && common.Args[0] == v
}

// boundTarget unboxes the pointer a binder is handed as an interface{} argument.
func boundTarget(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		default:
			return v
		}
	}
}
