package dotnetanalysis

// reachability_il_c5_test.go — C5: the integrated Reachability op over synthesized PEs
// composed into a fixture BuildDir (PLAN-350 barrier-4b criterion). Every .dll is a REAL
// PE32 + ECMA-335 image built in-memory (the peb byte builder, ported from depreach's
// engine_test.go and extended here — test-only — with a settable EntryPoint and an on-disk
// bytes finisher) and parsed by assembly.Read. NOTHING is executed, restored, or loaded:
// no SDK, no MSBuild, no NuGet, no CLR, no real system assembly (every type name is
// synthetic, so no path-convention locator can ever resolve a real dll).
//
// The four fixtures exercise the verdict→ReachabilityResult join end-to-end through the
// plugin op:
//   1. reachable first-party→dep across an AssemblyRef boundary → a ReachPath is emitted.
//   2. provably not_exploitable (searched, hazard-free, empty) → NO path, CLEAN result; the
//      NE→undetermined flip control adds a frontier hazard to the SAME topology and the
//      result flips to reachability_undetermined.
//   3. an undetermined sink (frontier hazard) → reachability_undetermined, never a path.
//   4. degrade (no first-party build output) → lexical fallback + tool_failure; the
//      empty-graph mutation control removes a reachable sink's first-party IL and proves it
//      degrades rather than flipping to a false not_exploitable.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ======================================================================================
// ported peb byte builder (test-only; mirrors depreach/engine_test.go + spanning_test.go)
// ======================================================================================

const (
	xModule      = 0x00
	xTypeRef     = 0x01
	xTypeDef     = 0x02
	xMethodDef   = 0x06
	xMemberRef   = 0x0A
	xAssembly    = 0x20
	xAssemblyRef = 0x23
	xNumTables   = 64
)

var wideCols = map[int]map[int]bool{
	xTypeDef:     {0: true},
	xMethodDef:   {0: true},
	xAssembly:    {0: true, 5: true},
	xAssemblyRef: {4: true},
}

func le2(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func le4(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func le8(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

func mtok(table int, rid uint32) uint32 { return uint32(table)<<24 | (rid & 0x00FFFFFF) }
func tok4(t uint32) []byte              { return le4(t) }

func cResScopeAsmRef(rid uint32) uint32 { return rid<<2 | 2 }
func cTypeDefOrRef(table int, rid uint32) uint32 {
	return rid<<2 | map[int]uint32{xTypeDef: 0, xTypeRef: 1}[table]
}
func cMemberRefParent(table int, rid uint32) uint32 {
	return rid<<3 | map[int]uint32{xTypeDef: 0, xTypeRef: 1, xMethodDef: 3}[table]
}

const opRet = 0x2A

func ilCall(t uint32) []byte     { return append([]byte{0x28}, tok4(t)...) }
func ilCallvirt(t uint32) []byte { return append([]byte{0x6F}, tok4(t)...) }

func body(instrs ...[]byte) []byte {
	var out []byte
	for _, in := range instrs {
		out = append(out, in...)
	}
	return append(out, opRet)
}

var (
	sigInstVoid   = []byte{0x20, 0x00, 0x01} // HASTHIS, 0 params, ret void
	sigStaticVoid = []byte{0x00, 0x00, 0x01} // 0 params, ret void
)

type mspec struct {
	name  string
	flags uint32
	sig   []byte
	il    []byte
}

type mbody struct {
	rid uint32
	il  []byte
}

type peb struct {
	strs, blobs, guids []byte
	tables             map[int][][]uint32
	bodies             []mbody
	entry              uint32 // CLI-header EntryPointToken (0 = none)
}

func newPEB() *peb {
	return &peb{strs: []byte{0}, blobs: []byte{0}, tables: map[int][][]uint32{}}
}

func (b *peb) str(s string) uint32 {
	if s == "" {
		return 0
	}
	off := uint32(len(b.strs))
	b.strs = append(b.strs, s...)
	b.strs = append(b.strs, 0)
	return off
}
func (b *peb) blob(data []byte) uint32 {
	off := uint32(len(b.blobs))
	b.blobs = append(b.blobs, byte(len(data)))
	b.blobs = append(b.blobs, data...)
	return off
}
func (b *peb) guid() uint32 {
	b.guids = append(b.guids, make([]byte, 16)...)
	return uint32(len(b.guids) / 16)
}
func (b *peb) row(table int, cols ...uint32) uint32 {
	b.tables[table] = append(b.tables[table], cols)
	return uint32(len(b.tables[table]))
}

func (b *peb) addType(flags uint32, name, ns string, extends uint32, methods []mspec) (uint32, []uint32) {
	first := uint32(len(b.tables[xMethodDef])) + 1
	var mrids []uint32
	for _, m := range methods {
		rid := b.row(xMethodDef, 0, 0, m.flags, b.str(m.name), b.blob(m.sig), 1)
		mrids = append(mrids, rid)
		if m.il != nil {
			b.bodies = append(b.bodies, mbody{rid, m.il})
		}
	}
	tRID := b.row(xTypeDef, flags, b.str(name), b.str(ns), extends, 1, first)
	return tRID, mrids
}

func scaffold() *peb {
	b := newPEB()
	b.row(xModule, 0, b.str("Test.dll"), b.guid(), 0, 0)
	b.row(xAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str("System.Runtime"), 0, b.blob(nil))
	return b
}

func (b *peb) extTypeRef(ns, name string) uint32 {
	return b.row(xTypeRef, cResScopeAsmRef(1), b.str(name), b.str(ns))
}
func (b *peb) asmRef(name string) uint32 {
	return b.row(xAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str(name), 0, b.blob(nil))
}
func (b *peb) extTypeRefScoped(asmRefRID uint32, ns, name string) uint32 {
	return b.row(xTypeRef, cResScopeAsmRef(asmRefRID), b.str(name), b.str(ns))
}
func (b *peb) memberRef(parentTypeRef uint32, name string, sig []byte) uint32 {
	return mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, parentTypeRef), b.str(name), b.blob(sig)))
}

// bytesNamed writes the Assembly row (naming the assembly `name`), lays out the image, and
// returns the raw PE bytes — the on-disk .dll the plugin op locates and reads.
func (b *peb) bytesNamed(name string) []byte {
	b.row(xAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), b.str(name), 0)
	return b.wrap()
}

func (b *peb) buildTableStream(heapSizes byte) []byte {
	var present []int
	var valid uint64
	for tid := 0; tid < xNumTables; tid++ {
		if len(b.tables[tid]) > 0 {
			present = append(present, tid)
			valid |= uint64(1) << uint(tid)
		}
	}
	var buf bytes.Buffer
	buf.Write(le4(0))
	buf.WriteByte(2)
	buf.WriteByte(0)
	buf.WriteByte(heapSizes)
	buf.WriteByte(1)
	buf.Write(le8(valid))
	buf.Write(le8(0))
	for _, tid := range present {
		buf.Write(le4(uint32(len(b.tables[tid]))))
	}
	for _, tid := range present {
		for _, r := range b.tables[tid] {
			for i, v := range r {
				if wideCols[tid][i] {
					buf.Write(le4(v))
				} else {
					buf.Write(le2(uint16(v)))
				}
			}
		}
	}
	return buf.Bytes()
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func (b *peb) buildMetadata() []byte {
	tableStream := b.buildTableStream(0x00)
	type strm struct {
		name string
		data []byte
	}
	strms := []strm{
		{"#~", tableStream},
		{"#Strings", pad4(append([]byte{}, b.strs...))},
		{"#US", pad4([]byte{0})},
		{"#GUID", b.guids},
		{"#Blob", pad4(append([]byte{}, b.blobs...))},
	}
	version := pad4([]byte("v4.0.30319\x00"))
	var root bytes.Buffer
	root.Write(le4(0x424A5342))
	root.Write(le2(1))
	root.Write(le2(1))
	root.Write(le4(0))
	root.Write(le4(uint32(len(version))))
	root.Write(version)
	root.Write(le2(0))
	root.Write(le2(uint16(len(strms))))
	headerLen := root.Len()
	for _, s := range strms {
		headerLen += 8 + len(pad4(append([]byte(s.name), 0)))
	}
	offset := headerLen
	var blocks bytes.Buffer
	for _, s := range strms {
		root.Write(le4(uint32(offset)))
		root.Write(le4(uint32(len(s.data))))
		root.Write(pad4(append([]byte(s.name), 0)))
		blocks.Write(s.data)
		offset += len(s.data)
	}
	root.Write(blocks.Bytes())
	return root.Bytes()
}

func encodeTinyBody(il []byte) []byte {
	return append([]byte{byte(len(il)<<2) | 0x02}, il...)
}

func (b *peb) wrap() []byte {
	const (
		peSigOff      = 0x80
		coffOff       = peSigOff + 4
		optOff        = coffOff + 20
		optSize       = 224
		secOff        = optOff + optSize
		rawStart      = 0x200
		sectionVA     = 0x2000
		cliHeaderSize = 72
		dirCLIHeader  = 14
		peMagicPE32   = 0x10b
	)
	metaLen := len(b.buildMetadata())
	base := sectionVA + cliHeaderSize + metaLen
	pad := (4 - base%4) % 4
	base += pad

	var blob []byte
	for _, mb := range b.bodies {
		for (base+len(blob))%4 != 0 {
			blob = append(blob, 0)
		}
		b.tables[xMethodDef][mb.rid-1][0] = uint32(base + len(blob))
		blob = append(blob, encodeTinyBody(mb.il)...)
	}
	metadata := b.buildMetadata()

	var cli bytes.Buffer
	cli.Write(le4(72))
	cli.Write(le2(2))
	cli.Write(le2(5))
	cli.Write(le4(sectionVA + cliHeaderSize))
	cli.Write(le4(uint32(len(metadata))))
	cli.Write(le4(0))
	cli.Write(le4(b.entry)) // EntryPointToken
	cli.Write(make([]byte, 48))

	raw := append(cli.Bytes(), metadata...)
	for len(raw) < cliHeaderSize+metaLen+pad {
		raw = append(raw, 0)
	}
	raw = append(raw, blob...)

	data := make([]byte, rawStart+len(raw))
	data[0], data[1] = 'M', 'Z'
	copy(data[0x3C:], le4(peSigOff))
	copy(data[peSigOff:], []byte{'P', 'E', 0, 0})
	copy(data[coffOff+2:], le2(1))
	copy(data[coffOff+16:], le2(optSize))
	copy(data[optOff:], le2(peMagicPE32))
	copy(data[optOff+92:], le4(16))
	dir14 := optOff + 96 + dirCLIHeader*8
	copy(data[dir14:], le4(sectionVA))
	copy(data[dir14+4:], le4(uint32(len(raw))))
	copy(data[secOff:], []byte(".text\x00\x00\x00"))
	copy(data[secOff+8:], le4(uint32(len(raw))))
	copy(data[secOff+12:], le4(sectionVA))
	copy(data[secOff+16:], le4(uint32(len(raw))))
	copy(data[secOff+20:], le4(rawStart))
	copy(data[rawStart:], raw)
	return data
}

// ======================================================================================
// fixture composition + assertions
// ======================================================================================

// composeILBuildDir writes rel→bytes into a fresh temp dir, mirroring a .NET build layout so
// LocateBuildOutput (bin/publish) and findFile (obj/project.assets.json) resolve.
func composeILBuildDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for rel, data := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return dir
}

func hasILReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// depAssetsJSON lists one package dependency so LoadSpanningSet loads it (its dll locates via
// the build-output fallback in bin/).
func depAssetsJSON(pkgKey string) []byte {
	return []byte(`{"version":3,"targets":{"net8.0":{"` + pkgKey + `":{"type":"package"}}},` +
		`"libraries":{"` + pkgKey + `":{"type":"package","path":"dep/1.0.0"}}}`)
}

// ---- fixture 1: reachable first-party → dep across an AssemblyRef boundary ----

// appReachesDep builds App.dll (Ingress.enter is the EntryPoint; calls Dep.Sink.boom across
// an AssemblyRef) and Dep.dll (D.Sink.boom, the sink).
func appReachesDep(t *testing.T) (appDLL, depDLL []byte) {
	// Dep.dll — the leaf sink assembly.
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	depDLL = db.bytesNamed("Dep")

	// App.dll — first-party ingress calls into Dep across the boundary.
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	refDep := ab.asmRef("Dep")
	sinkRef := ab.extTypeRefScoped(refDep, "D", "Sink")
	boomRef := ab.memberRef(sinkRef, "boom", sigInstVoid)
	ab.addType(0, "<Module>", "", 0, nil)
	_, inM := ab.addType(0, "Ingress", "App", aObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(boomRef))}})
	ab.entry = mtok(xMethodDef, inM[0])
	appDLL = ab.bytesNamed("App")
	return appDLL, depDLL
}

func TestC5_Reachable_EmitsPath(t *testing.T) {
	appDLL, depDLL := appReachesDep(t)
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":              []byte("<Project></Project>"),
		"bin/App.dll":             appDLL,
		"bin/Dep.dll":             depDLL,
		"obj/project.assets.json": depAssetsJSON("Dep/1.0.0"),
	})
	sink := funcSCIP("D", []string{"Sink"}, "boom", 0)

	res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("paths = %d, want 1 (reachable across the App→Dep boundary)", len(res.Paths))
	}
	if !res.Partiality.Complete {
		t.Fatalf("reachable+hazard-free result must be Complete (the IL confident graph), got %v", res.Partiality.Reasons)
	}
	tr := res.Paths[0].Trace
	if len(tr) != 2 || tr[0].Name != "enter" || tr[1].Name != "boom" {
		t.Fatalf("trace = %+v, want [enter, boom]", tr)
	}
	if res.Paths[0].Sink.SCIP != sink {
		t.Fatalf("sink SCIP = %q, want %q", res.Paths[0].Sink.SCIP, sink)
	}
}

// ---- fixtures 2 + 3: provably NE, and the NE→undetermined flip on the SAME topology ----

// neOrHazard builds App.dll with Ingress.enter (the EntryPoint) that calls the resolved
// in-set Leaf.noop; when withHazard is set it ALSO calls System.Activator.CreateInstance (a
// reflection completeness hazard). Sink App.Sink.vuln is present but never reached.
func neOrHazard(t *testing.T, withHazard bool) []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0, "Sink", "App", obj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", obj, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	noopTok := mtok(xMethodDef, leafM[0])

	instrs := [][]byte{ilCall(noopTok)}
	if withHazard {
		activator := b.extTypeRef("System", "Activator")
		createRef := b.memberRef(activator, "CreateInstance", sigStaticVoid)
		instrs = append(instrs, ilCall(createRef))
	}
	_, inM := b.addType(0, "Ingress", "App", obj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(instrs...)}})
	b.entry = mtok(xMethodDef, inM[0])
	return b.bytesNamed("App")
}

func TestC5_NotExploitable_And_HazardFlip(t *testing.T) {
	sink := funcSCIP("App", []string{"Sink"}, "vuln", 0)

	// Fixture 2: provably not_exploitable — CLEAN, no path, no undetermined reason.
	cleanDir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":  []byte("<Project></Project>"),
		"bin/App.dll": neOrHazard(t, false),
	})
	ne, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: cleanDir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability(NE): %v", err)
	}
	if len(ne.Paths) != 0 {
		t.Fatalf("not_exploitable must emit NO path, got %d", len(ne.Paths))
	}
	if !ne.Partiality.Complete {
		t.Fatalf("proven not_exploitable is the confident-safe: expected Complete, got %v", ne.Partiality.Reasons)
	}
	if hasILReason(ne.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("a real two-trace NE must NOT carry reachability_undetermined")
	}

	// Fixture 3 / negative control: the SAME topology with a frontier hazard flips to
	// undetermined — proving the clean NE above was EARNED, not a "didn't find it".
	hazDir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":  []byte("<Project></Project>"),
		"bin/App.dll": neOrHazard(t, true),
	})
	un, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: hazDir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability(hazard): %v", err)
	}
	if len(un.Paths) != 0 {
		t.Fatalf("undetermined must emit NO path, got %d", len(un.Paths))
	}
	if un.Partiality.Complete {
		t.Fatalf("a frontier hazard must flip the result off Complete")
	}
	if !hasILReason(un.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("frontier hazard must declare reachability_undetermined, got %v", un.Partiality.Reasons)
	}
}

// ---- fixture 4: degrade (no first-party IL) + the empty-graph mutation control ----

// mutSource is a minimal C# source declaring the sink, so the lexical fallback's loadProgram
// has a .cs to parse and its reconstructed sink SCIP matches the IL one.
const mutSource = "namespace App { class Sink { void vuln() {} } }\n"

// appReachesLocalSink builds App.dll where Ingress.enter (EntryPoint) directly calls the
// in-set App.Sink.vuln (reachable, hazard-free).
func appReachesLocalSink(t *testing.T) []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", obj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	_, inM := b.addType(0, "Ingress", "App", obj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))}})
	b.entry = mtok(xMethodDef, inM[0])
	return b.bytesNamed("App")
}

func TestC5_Degrade_ToLexical_ToolFailure(t *testing.T) {
	sink := funcSCIP("App", []string{"Sink"}, "vuln", 0)

	// Pure degrade: a BuildDir with .cs source but NO first-party build output. The IL tier
	// cannot engage, so the op degrades to the lexical candidate-narrower + tool_failure —
	// never an empty IL graph, never not_exploitable.
	degradeDir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":     []byte("<Project></Project>"),
		"src/Program.cs": []byte(mutSource),
	})
	res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: degradeDir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability(degrade): %v", err)
	}
	if res.Partiality.Complete {
		t.Fatalf("degrade must NOT be a clean confident result")
	}
	if !hasILReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("degrade must declare tool_failure, got %v", res.Partiality.Reasons)
	}
}

func TestC5_EmptyGraphMutationControl(t *testing.T) {
	sink := funcSCIP("App", []string{"Sink"}, "vuln", 0)
	appDLL := appReachesLocalSink(t)

	// With the first-party IL present: the sink is reachable and a path is emitted.
	files := map[string][]byte{
		"App.csproj":     []byte("<Project></Project>"),
		"src/Program.cs": []byte(mutSource), // present so the post-removal fallback can parse
		"bin/App.dll":    appDLL,
	}
	dir := composeILBuildDir(t, files)
	with, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability(with IL): %v", err)
	}
	if len(with.Paths) != 1 || !with.Partiality.Complete {
		t.Fatalf("with first-party IL: want 1 path + Complete, got %d paths / %v", len(with.Paths), with.Partiality.Reasons)
	}

	// MUTATION: remove the first-party IL. The previously-reachable sink must NOT become a
	// false not_exploitable — it must DEGRADE (tool_failure), never a clean/empty result.
	if err := os.Remove(filepath.Join(dir, "bin", "App.dll")); err != nil {
		t.Fatalf("remove first-party dll: %v", err)
	}
	without, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability(mutated): %v", err)
	}
	if without.Partiality.Complete {
		t.Fatalf("removing first-party IL must NOT yield a clean result (that would be a false NE)")
	}
	if !hasILReason(without.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("mutation must degrade with tool_failure, got %v", without.Partiality.Reasons)
	}
}
