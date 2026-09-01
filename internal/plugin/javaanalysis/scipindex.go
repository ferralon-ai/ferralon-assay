package javaanalysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// scipindex.go is the SCIP-INDEX READER — the new analysis surface Increment 3
// adds. The existing pure-Go engine only ever WRITES SCIP id strings (scip.go);
// it never consumed a scip-java-emitted `index.scip`. This file parses that
// Protobuf index into the plugin's existing CallEdge/Ingress contract so a
// semantic, type-resolved call graph (interface→impl dispatch that lexical
// analysis cannot resolve) flows through the unchanged pipeline.
//
// inv.5 boundary: this reader resolves edges that ARE in the index; it never
// fabricates one. A missing relationship simply yields no edge. The analyzer
// container does ANALYSIS only — proof is still the sandbox canary detonation.
//
// Dependency hygiene: rather than pull in github.com/sourcegraph/scip (which
// drags google.golang.org/protobuf and a large generated tree into the module —
// a supply-chain cost borne by every build), we
// decode the small, stable subset of the SCIP schema we need with a dependency-
// free Protobuf wire reader. The decoded fields are exactly: Index.documents,
// Document.{occurrences,symbols}, Occurrence.{symbol,roles,range},
// SymbolInformation.{symbol,relationships}, Relationship.{symbol,is_implementation}.
// Field numbers are from scip.proto (stable since SCIP v0.x):
//
//	Index:             documents=2, external_symbols=3
//	Document:          relative_path=1, occurrences=2, symbols=3
//	Occurrence:        range=1, symbol=2, symbol_roles=3,
//	                   single_line_range=8, multi_line_range=9
//	SymbolInformation: symbol=1, relationships=4
//	Relationship:      symbol=1, is_implementation=3
//	SymbolRole.Definition = 0x1
//
// Enclosing-method attribution (the real-output reality): scip-java 0.10.3 emits
// definition occurrences whose `range` spans only the symbol's NAME (e.g. `fetch`
// at line 18, cols 18–23), NOT the method body, and it emits NEITHER
// Occurrence.enclosing_range (field 7) NOR SymbolInformation.enclosing_symbol
// (field 8). A hand-crafted fixture that put body-sized ranges on definitions
// hid this. So a call-site reference's enclosing method is derived positionally:
// each method def owns [startLine, nextMethodDef.startLine) within its document,
// and the enclosing method of a reference is the method def with the greatest
// startLine ≤ the reference line (see enclosingMethod). scip-java also emits the
// "scip-java" scheme as "semanticdb" on local first-party symbols; canonicalize-
// SCIP discards the whole scheme/coordinate header and keeps only the descriptor
// tail, so both schemes normalize to the same canonical id.

// scipRoleDefinition is SymbolRole.Definition (a bit in Occurrence.symbol_roles).
const scipRoleDefinition = 0x1

// scipDocument is the decoded subset of a SCIP Document.
type scipDocument struct {
	occurrences []scipOccurrence
	symbols     []scipSymbolInfo
}

// scipOccurrence is the decoded subset of a SCIP Occurrence: the symbol it refers
// to, its role bits, and its source range (used to find which method body
// encloses a reference occurrence).
type scipOccurrence struct {
	symbol     string
	roles      int32
	startLine  int32
	startChar  int32
	endLine    int32
	endChar    int32
	hasRange   bool
	definition bool
}

// scipSymbolInfo is the decoded subset of a SCIP SymbolInformation: the symbol and
// its relationships (we keep only implementation edges — the interface→impl link).
type scipSymbolInfo struct {
	symbol       string
	implementsOf []string // symbols this one implements (Relationship.is_implementation)
}

// scipIndex is the decoded subset of a SCIP Index.
type scipIndex struct {
	documents []scipDocument
}

// scipGraph is the resolved call graph + ingress set extracted from a SCIP index,
// expressed in the plugin's canonical (arity-based, local-coordinate) SCIP id
// space so it shares equality with the pure-Go emitter and the resolved sink.
type scipGraph struct {
	edges      []plugin.CallEdge
	roots      []string
	ingresses  []plugin.Ingress
	resolvedID map[string]string // scip-java symbol → plugin canonical id
}

// readSCIPIndex parses scip-java-emitted index.scip bytes into the plugin's
// CallEdge / Ingress contract. The returned graph carries:
//   - one edge per resolved reference occurrence (caller method → referenced
//     method), AND, where the referenced method is an interface method, one
//     additional edge to each concrete implementation (the interface→impl
//     dispatch resolution that pure-Go lexical analysis declares
//     Partial(dynamic_dispatch) on);
//   - the @RestController/@GetMapping route methods as http_route ingresses.
//
// It returns an error only for a malformed/truncated index (a tool failure the
// caller maps to Partial(tool_failure) — never a fabricated edge). An index with
// no resolvable edges is a valid, empty graph, not an error.
func readSCIPIndex(data []byte) (scipGraph, error) {
	idx, err := decodeSCIPIndex(data)
	if err != nil {
		return scipGraph{}, err
	}

	// Pass 1: collect every METHOD definition occurrence's start line, and the
	// implementation relationships, across all documents. scip-java/semanticdb
	// definition occurrences span only the symbol's NAME (e.g. `fetch` at
	// [18:18-18:23]), NOT the enclosing body, and emit neither Occurrence.
	// enclosing_range (field 7) nor SymbolInformation.enclosing_symbol (field 8).
	// So a reference's enclosing method cannot be found by range-containment;
	// instead each method owns the source span from its definition line up to the
	// next method definition's line within the same document. We record method def
	// start lines per document (sorted in Pass 2) to derive those spans.
	docMethodDefs := make([][]scipDefSpan, len(idx.documents))
	implementorsOf := map[string][]string{} // interface symbol → impl symbols

	for di, doc := range idx.documents {
		for _, occ := range doc.occurrences {
			if occ.definition && occ.hasRange && isMethodSymbol(occ.symbol) {
				docMethodDefs[di] = append(docMethodDefs[di], scipDefSpan{symbol: occ.symbol, startLine: occ.startLine, endLine: occ.endLine})
			}
		}
		for _, si := range doc.symbols {
			for _, iface := range si.implementsOf {
				implementorsOf[iface] = append(implementorsOf[iface], si.symbol)
			}
		}
	}
	for di := range docMethodDefs {
		sort.Slice(docMethodDefs[di], func(a, b int) bool {
			return docMethodDefs[di][a].startLine < docMethodDefs[di][b].startLine
		})
	}

	canon := map[string]string{}
	canonical := func(sym string) string {
		if c, ok := canon[sym]; ok {
			return c
		}
		c := canonicalizeSCIP(sym)
		canon[sym] = c
		return c
	}

	edgeSet := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	addEdge := func(caller, callee string) {
		if caller == "" || callee == "" || caller == callee {
			return
		}
		e := plugin.CallEdge{Caller: sym(canonical(caller)), Callee: sym(canonical(callee))}
		if !edgeSet[e] {
			edgeSet[e] = true
			edges = append(edges, e)
		}
	}

	// Pass 2: every reference occurrence (a non-definition use of a method symbol)
	// becomes a call edge from its ENCLOSING definition method to the referenced
	// method. The enclosing method is the one whose body span [startLine, next
	// method startLine) contains the reference line — i.e. the method def with the
	// greatest start line at or before the reference. When the referenced method
	// is an interface method with known implementors, ALSO add edges to each
	// implementor — this is the resolved interface→impl dispatch.
	for di, doc := range idx.documents {
		for _, occ := range doc.occurrences {
			if occ.definition || !occ.hasRange || occ.symbol == "" {
				continue
			}
			if !isMethodSymbol(occ.symbol) {
				continue
			}
			caller := enclosingMethod(docMethodDefs[di], occ.startLine)
			if caller == "" {
				continue
			}
			addEdge(caller, occ.symbol)
			for _, impl := range implementorsOf[occ.symbol] {
				addEdge(occ.symbol, impl) // interface method → concrete impl method
			}
		}
	}

	// Ingresses: @RestController/@GetMapping route methods AND container-invoked
	// entrypoints (@Scheduled/@EventListener/@PostConstruct/@KafkaListener and
	// siblings). scip-java records the annotation as a reference occurrence to the
	// annotation type within the method's definition range, so a method carrying
	// such an annotation is an ingress. We detect annotated methods directly. The
	// set is keyed by (method, kind) so a method that carries more than one ingress
	// annotation keeps every Kind rather than collapsing to the last seen.
	ingressSet := map[string]plugin.Ingress{}
	for di, doc := range idx.documents {
		for _, occ := range doc.occurrences {
			if occ.definition || !occ.hasRange {
				continue
			}
			kind, sel, ok := ingressAnnotation(occ.symbol)
			if !ok {
				continue
			}
			method := annotatedMethod(docMethodDefs[di], occ.startLine)
			if method == "" || !isMethodSymbol(method) {
				continue
			}
			cid := canonical(method)
			ingressSet[cid+"\x00"+kind] = plugin.Ingress{Kind: kind, Symbol: sym(cid), Selector: sel}
		}
	}

	rootSet := map[string]bool{}
	var ingresses []plugin.Ingress
	for _, in := range ingressSet {
		ingresses = append(ingresses, in)
		rootSet[in.Symbol.SCIP] = true
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Symbol.SCIP != ingresses[j].Symbol.SCIP {
			return ingresses[i].Symbol.SCIP < ingresses[j].Symbol.SCIP
		}
		return ingresses[i].Selector < ingresses[j].Selector
	})
	roots := make([]string, 0, len(rootSet))
	for r := range rootSet {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	resolvedID := make(map[string]string, len(canon))
	for k, v := range canon {
		resolvedID[k] = v
	}
	return scipGraph{edges: edges, roots: roots, ingresses: ingresses, resolvedID: resolvedID}, nil
}

// scipDefSpan is a method definition's symbol and its name-range start line. Its
// body span is implied as [startLine, nextMethodDef.startLine) within the same
// document (scip-java emits only the name range, not the body range), so defs are
// kept sorted by startLine and the enclosing method is found positionally.
type scipDefSpan struct {
	symbol    string
	startLine int32
	endLine   int32
}

// enclosingMethod returns the method whose body span contains a reference at
// line. Because scip-java definition occurrences span only the method NAME (and
// emit no enclosing_range), each method is treated as owning [startLine, next
// method startLine); the enclosing method is therefore the def with the GREATEST
// startLine ≤ line. defs MUST be sorted by startLine ascending. An empty result
// means the reference precedes the first method definition in the document.
func enclosingMethod(defs []scipDefSpan, line int32) string {
	best := ""
	for _, d := range defs {
		if d.startLine > line {
			break
		}
		best = d.symbol
	}
	return best
}

// annotatedMethod returns the method a Spring mapping annotation at line
// decorates. Annotations sit ON or directly ABOVE the method they decorate, so
// the annotated method is the def with the SMALLEST startLine ≥ line. defs MUST
// be sorted by startLine ascending.
func annotatedMethod(defs []scipDefSpan, line int32) string {
	for _, d := range defs {
		if d.startLine >= line {
			return d.symbol
		}
	}
	return ""
}

// isMethodSymbol reports whether a SCIP symbol's terminal descriptor is a method
// descriptor (ends with "()." in scip-java's erased form, or "(N)." in the
// plugin's arity form). Method descriptors are the only ones that participate in
// the call graph.
func isMethodSymbol(sym string) bool {
	return strings.HasSuffix(sym, ").")
}

// mappingSelectorRegistry is the SCIP-space half of the H1 annotation-classifier
// registry (edge-seam.md §5): a scip-java annotation-type descriptor needle → the
// coarse HTTP selector recorded for it. It is an ordered slice (first-match by append
// order, deterministic — no map iteration on output) that an overlay appends to from
// its OWN file's init() via registerMappingSelector, so overlays never edit
// scipindex.go's classifier in place. Seeded with the built-in Spring mappings.
var mappingSelectorRegistry = []struct{ needle, selector string }{
	{"GetMapping#", "GET"},
	{"PostMapping#", "POST"},
	{"PutMapping#", "PUT"},
	{"DeleteMapping#", "DELETE"},
	{"PatchMapping#", "PATCH"},
	{"RequestMapping#", "ANY"},
}

// registerMappingSelector appends an HTTP-mapping annotation needle→selector to the
// SCIP-space registry. It is the twin of calls.go's registerRouteAnnotation and MUST
// stay in step with it (the C3 dual-track rule).
func registerMappingSelector(needle, selector string) {
	mappingSelectorRegistry = append(mappingSelectorRegistry, struct{ needle, selector string }{needle, selector})
}

// mappingSelector reports whether a SCIP symbol names a Spring HTTP-mapping
// annotation type (@GetMapping/@PostMapping/@RequestMapping and siblings) and, if
// so, returns a coarse selector string. The annotation is recorded as a reference
// to its type symbol within the route method's range.
func mappingSelector(sym string) (string, bool) {
	for _, a := range mappingSelectorRegistry {
		if strings.Contains(sym, a.needle) {
			return a.selector, true
		}
	}
	return "", false
}

// ingressAnnotation classifies a SCIP annotation-type symbol as an ingress: a
// Spring HTTP-mapping annotation (Kind "http_route", with a coarse method
// selector) or a container-invoked entrypoint annotation (Kind "scheduled" /
// "event_listener" / "lifecycle" / "message_listener", no selector). It is the
// SCIP-space twin of the lexical calls.go classification (routeAnnotations +
// containerEntrypoints). ok is false for any other symbol.
func ingressAnnotation(sym string) (kind, selector string, ok bool) {
	if sel, ok := mappingSelector(sym); ok {
		return "http_route", sel, true
	}
	if k, ok := containerEntrypointKind(sym); ok {
		return k, "", true
	}
	return "", "", false
}

// containerEntrypointRegistry is the SCIP-space half of the H1 registry for
// container-invoked entrypoint annotations: a scip-java descriptor needle → ingress
// Kind. Ordered slice (deterministic first-match), appended to via
// registerContainerEntrypointNeedle from an overlay's init(). Seeded with the
// built-ins; MUST stay in step with the lexical containerEntrypoints map.
var containerEntrypointRegistry = []struct{ needle, kind string }{
	{"Scheduled#", "scheduled"},
	{"EventListener#", "event_listener"},
	{"PostConstruct#", "lifecycle"},
	{"PreDestroy#", "lifecycle"},
	{"KafkaListener#", "message_listener"},
	{"JmsListener#", "message_listener"},
	{"RabbitListener#", "message_listener"},
}

// registerContainerEntrypointNeedle appends a container-entrypoint annotation
// needle→kind to the SCIP-space registry. Twin of calls.go's
// registerContainerEntrypoint; keep the two in step (C3 dual-track).
func registerContainerEntrypointNeedle(needle, kind string) {
	containerEntrypointRegistry = append(containerEntrypointRegistry, struct{ needle, kind string }{needle, kind})
}

// containerEntrypointKind reports whether a SCIP symbol names a container-invoked
// entrypoint annotation type (@Scheduled/@EventListener/@PostConstruct/@PreDestroy
// and the message-listener annotations) and, if so, its ingress Kind. Like
// mappingSelector it matches the annotation type by its scip-java descriptor
// needle ("Scheduled#", …). It MUST stay in step with the lexical
// containerEntrypoints map so the two id spaces recognize the same entrypoints.
func containerEntrypointKind(sym string) (string, bool) {
	for _, a := range containerEntrypointRegistry {
		if strings.Contains(sym, a.needle) {
			return a.kind, true
		}
	}
	return "", false
}

// canonicalizeSCIP rewrites a scip-java SCIP symbol into the plugin's own
// canonical id space (the one scip.go emits): the local-source manager+coordinate
// prefix and an arity-based method descriptor. This makes a scip-java-resolved
// edge id-equal to (a) the pure-Go call graph and (b) the resolved advisory sink,
// so firstPartyReachPaths consumes the resolved graph with no change and no
// cross-space matching. A symbol that is already in canonical form is returned
// unchanged.
//
// scip-java method symbols look like:
//
//	scip-java maven com.example/spring-ssrf 0.0.1 com/example/web/UrlServiceImpl#fetch().
//
// We keep the package + enclosing-type descriptors verbatim (they already match
// the plugin's "pkg/ Type# method" shape) and rewrite only (a) the manager
// coordinates to the local placeholder and (b) the method descriptor to the
// arity form. Parameter arity is recovered from the descriptor's parameter list
// when scip-java encodes one; an empty "()." maps to arity 0.
func canonicalizeSCIP(sym string) string {
	fields := splitSCIPHeader(sym)
	if fields == nil {
		return sym
	}
	descriptors := fields.descriptors
	descriptors = rewriteMethodDescriptor(descriptors)
	var b strings.Builder
	b.WriteString(scipManager)
	b.WriteByte(' ')
	b.WriteString(localCoordinate)
	b.WriteByte(' ')
	b.WriteString(localCoordinate)
	b.WriteByte(' ')
	b.WriteString(descriptors)
	return b.String()
}

// scipHeader is a SCIP symbol split into its scheme/manager, the package
// coordinate+version, and the trailing descriptor string.
type scipHeader struct {
	descriptors string
}

// splitSCIPHeader parses the standard SCIP symbol grammar
// "<scheme> <manager> <package> <version> <descriptors>" enough to isolate the
// descriptor tail. scip-java uses scheme "scip-java" and manager "maven", so the
// first FOUR space-separated tokens are the header and the remainder (which may
// itself contain no spaces for our descriptors) is the descriptor string. Returns
// nil if the symbol does not have at least the 4 header tokens + a descriptor.
func splitSCIPHeader(sym string) *scipHeader {
	parts := strings.SplitN(sym, " ", 5)
	if len(parts) < 5 {
		return nil
	}
	return &scipHeader{descriptors: parts[4]}
}

// rewriteMethodDescriptor rewrites the terminal method descriptor of a SCIP
// descriptor string from scip-java's erased-signature form to the plugin's
// arity form. "...fetch()." → "...fetch()." (arity 0); "...fetch(+1)." or a
// scip-java parameterized form → "...fetch(N).". Non-method descriptors are
// returned unchanged.
func rewriteMethodDescriptor(descriptors string) string {
	if !strings.HasSuffix(descriptors, ").") {
		return descriptors
	}
	open := strings.LastIndexByte(descriptors, '(')
	if open < 0 {
		return descriptors
	}
	head := descriptors[:open] // up to and including method name
	inner := descriptors[open+1 : len(descriptors)-2]
	arity := scipDescriptorArity(inner)
	if arity == 0 {
		return head + "()."
	}
	return fmt.Sprintf("%s(%d).", head, arity)
}

// scipDescriptorArity counts the parameters encoded in a scip-java method
// descriptor's parenthesized body. scip-java's disambiguating method descriptors
// encode an overload index/parameter list; an empty body is arity 0. We count
// comma-separated parameter tokens, tolerating scip-java's "+N" disambiguator
// (which is not a parameter and yields arity 0 — the descriptor name already
// disambiguates within one index, see scip.go's replace-not-merge note).
func scipDescriptorArity(inner string) int {
	inner = strings.TrimSpace(inner)
	if inner == "" || strings.HasPrefix(inner, "+") {
		return 0
	}
	return strings.Count(inner, ",") + 1
}

// --- minimal Protobuf wire decoder (no external dependency) ---

// decodeSCIPIndex decodes the subset of a SCIP Index we consume. It walks the
// top-level message reading only documents (field 2); everything else is skipped
// by wire type. A truncated or malformed varint/length is an error (tool failure).
func decodeSCIPIndex(data []byte) (scipIndex, error) {
	var idx scipIndex
	r := protoReader{buf: data}
	for r.more() {
		field, wt, err := r.tag()
		if err != nil {
			return scipIndex{}, err
		}
		if field == 2 && wt == wireBytes { // Index.documents
			sub, err := r.bytesField()
			if err != nil {
				return scipIndex{}, err
			}
			doc, err := decodeDocument(sub)
			if err != nil {
				return scipIndex{}, err
			}
			idx.documents = append(idx.documents, doc)
			continue
		}
		if err := r.skip(wt); err != nil {
			return scipIndex{}, err
		}
	}
	return idx, nil
}

// decodeDocument decodes Document.occurrences (field 2) and Document.symbols
// (field 3); other fields are skipped.
func decodeDocument(data []byte) (scipDocument, error) {
	var doc scipDocument
	r := protoReader{buf: data}
	for r.more() {
		field, wt, err := r.tag()
		if err != nil {
			return scipDocument{}, err
		}
		switch {
		case field == 2 && wt == wireBytes: // occurrences
			sub, err := r.bytesField()
			if err != nil {
				return scipDocument{}, err
			}
			occ, err := decodeOccurrence(sub)
			if err != nil {
				return scipDocument{}, err
			}
			doc.occurrences = append(doc.occurrences, occ)
		case field == 3 && wt == wireBytes: // symbols (SymbolInformation)
			sub, err := r.bytesField()
			if err != nil {
				return scipDocument{}, err
			}
			si, err := decodeSymbolInfo(sub)
			if err != nil {
				return scipDocument{}, err
			}
			doc.symbols = append(doc.symbols, si)
		default:
			if err := r.skip(wt); err != nil {
				return scipDocument{}, err
			}
		}
	}
	return doc, nil
}

// decodeOccurrence decodes range (field 1, packed int32), symbol (field 2),
// symbol_roles (field 3), single_line_range (field 8) and multi_line_range
// (field 9). The deprecated `range` field and the explicit range messages both
// encode positions; we read whichever is present.
func decodeOccurrence(data []byte) (scipOccurrence, error) {
	var occ scipOccurrence
	r := protoReader{buf: data}
	for r.more() {
		field, wt, err := r.tag()
		if err != nil {
			return scipOccurrence{}, err
		}
		switch {
		case field == 1 && wt == wireBytes: // packed range [startLine,startChar,endLine,endChar] or [line,startChar,endChar]
			sub, err := r.bytesField()
			if err != nil {
				return scipOccurrence{}, err
			}
			if err := occ.setRangeFromPacked(sub); err != nil {
				return scipOccurrence{}, err
			}
		case field == 1 && wt == wireVarint: // range as repeated unpacked varints
			v, err := r.varint()
			if err != nil {
				return scipOccurrence{}, err
			}
			occ.appendRangeVarint(int32(v))
		case field == 2 && wt == wireBytes: // symbol
			s, err := r.stringField()
			if err != nil {
				return scipOccurrence{}, err
			}
			occ.symbol = s
		case field == 3 && wt == wireVarint: // symbol_roles
			v, err := r.varint()
			if err != nil {
				return scipOccurrence{}, err
			}
			occ.roles = int32(v)
		default:
			if err := r.skip(wt); err != nil {
				return scipOccurrence{}, err
			}
		}
	}
	occ.definition = occ.roles&scipRoleDefinition != 0
	return occ, nil
}

// setRangeFromPacked reads a packed-varint SCIP range. SCIP ranges are
// [startLine, startCharacter, endLine, endCharacter] (4 elements) or, when the
// range is single-line, [startLine, startCharacter, endCharacter] (3 elements).
func (occ *scipOccurrence) setRangeFromPacked(b []byte) error {
	r := protoReader{buf: b}
	var nums []int32
	for r.more() {
		v, err := r.varint()
		if err != nil {
			return err
		}
		nums = append(nums, int32(v))
	}
	switch len(nums) {
	case 3:
		occ.startLine, occ.startChar, occ.endLine, occ.endChar = nums[0], nums[1], nums[0], nums[2]
		occ.hasRange = true
	case 4:
		occ.startLine, occ.startChar, occ.endLine, occ.endChar = nums[0], nums[1], nums[2], nums[3]
		occ.hasRange = true
	}
	return nil
}

// appendRangeVarint accumulates an unpacked repeated range element. The first two
// are startLine/startChar; remaining map per the 3- or 4-element convention.
func (occ *scipOccurrence) appendRangeVarint(v int32) {
	switch {
	case !occ.hasRange:
		occ.startLine = v
		occ.hasRange = true
	case occ.endLine == 0 && occ.startChar == 0:
		occ.startChar = v
	case occ.endLine == 0:
		occ.endLine = v
	default:
		occ.endChar = v
	}
}

// decodeSymbolInfo decodes SymbolInformation.symbol (field 1) and
// SymbolInformation.relationships (field 4); other fields are skipped.
func decodeSymbolInfo(data []byte) (scipSymbolInfo, error) {
	var si scipSymbolInfo
	r := protoReader{buf: data}
	for r.more() {
		field, wt, err := r.tag()
		if err != nil {
			return scipSymbolInfo{}, err
		}
		switch {
		case field == 1 && wt == wireBytes: // symbol
			s, err := r.stringField()
			if err != nil {
				return scipSymbolInfo{}, err
			}
			si.symbol = s
		case field == 4 && wt == wireBytes: // relationships
			sub, err := r.bytesField()
			if err != nil {
				return scipSymbolInfo{}, err
			}
			relSym, isImpl, err := decodeRelationship(sub)
			if err != nil {
				return scipSymbolInfo{}, err
			}
			if isImpl && relSym != "" {
				si.implementsOf = append(si.implementsOf, relSym)
			}
		default:
			if err := r.skip(wt); err != nil {
				return scipSymbolInfo{}, err
			}
		}
	}
	return si, nil
}

// decodeRelationship decodes Relationship.symbol (field 1) and
// Relationship.is_implementation (field 3, bool). It returns the related symbol
// and whether the relationship is an implementation edge.
func decodeRelationship(data []byte) (sym string, isImpl bool, err error) {
	r := protoReader{buf: data}
	for r.more() {
		field, wt, e := r.tag()
		if e != nil {
			return "", false, e
		}
		switch {
		case field == 1 && wt == wireBytes:
			s, e := r.stringField()
			if e != nil {
				return "", false, e
			}
			sym = s
		case field == 3 && wt == wireVarint:
			v, e := r.varint()
			if e != nil {
				return "", false, e
			}
			isImpl = v != 0
		default:
			if e := r.skip(wt); e != nil {
				return "", false, e
			}
		}
	}
	return sym, isImpl, nil
}

// Protobuf wire types we handle.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// protoReader is a minimal Protobuf wire-format reader over a byte slice.
type protoReader struct {
	buf []byte
	pos int
}

func (r *protoReader) more() bool { return r.pos < len(r.buf) }

// tag reads a field tag, returning the field number and wire type.
func (r *protoReader) tag() (field int, wireType int, err error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	return int(v >> 3), int(v & 0x7), nil
}

// varint reads a base-128 varint.
func (r *protoReader) varint() (uint64, error) {
	var x uint64
	var shift uint
	for {
		if r.pos >= len(r.buf) {
			return 0, fmt.Errorf("scipindex: truncated varint")
		}
		b := r.buf[r.pos]
		r.pos++
		x |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return x, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, fmt.Errorf("scipindex: varint overflow")
		}
	}
}

// bytesField reads a length-delimited field's payload.
func (r *protoReader) bytesField() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if r.pos+int(n) > len(r.buf) {
		return nil, fmt.Errorf("scipindex: truncated length-delimited field")
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

// stringField reads a length-delimited field as a string.
func (r *protoReader) stringField() (string, error) {
	b, err := r.bytesField()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// skip advances past a field of the given wire type whose tag was just read.
func (r *protoReader) skip(wireType int) error {
	switch wireType {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireFixed64:
		if r.pos+8 > len(r.buf) {
			return fmt.Errorf("scipindex: truncated fixed64")
		}
		r.pos += 8
		return nil
	case wireBytes:
		_, err := r.bytesField()
		return err
	case wireFixed32:
		if r.pos+4 > len(r.buf) {
			return fmt.Errorf("scipindex: truncated fixed32")
		}
		r.pos += 4
		return nil
	default:
		return fmt.Errorf("scipindex: unsupported wire type %d", wireType)
	}
}
