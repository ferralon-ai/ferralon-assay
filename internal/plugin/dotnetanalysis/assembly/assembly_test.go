package assembly

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---- byte-synthesis builder: emits valid PE + ECMA-335 metadata without an SDK ----
//
// No CLR or csc is present to compile a fixture, so the tests synthesize the bytes
// directly — which also documents the PE/COFF + ECMA-335 §II layout the reader
// decodes. The builder computes index widths with its OWN small width function
// (bWidth), independent of the reader's colWidth, so a round-trip through both is a
// genuine cross-check rather than a shared-bug tautology.

func le2(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func le4(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func le8(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// bWidth is the builder's independent index-width oracle (ECMA-335 §II.24.2.6).
func bWidth(heapSizes byte, rowCount map[int]int, c column) int {
	switch c.kind {
	case colU2:
		return 2
	case colU4:
		return 4
	case colString:
		if heapSizes&0x01 != 0 {
			return 4
		}
	case colGUID:
		if heapSizes&0x02 != 0 {
			return 4
		}
	case colBlob:
		if heapSizes&0x04 != 0 {
			return 4
		}
	case colTable:
		if rowCount[c.param] >= (1 << 16) {
			return 4
		}
	case colCoded:
		spec := codedIndexes[c.param]
		max := 0
		for _, t := range spec.tables {
			if t != tagUnused && rowCount[t] > max {
				max = rowCount[t]
			}
		}
		if max >= (1 << (16 - spec.tagBits)) {
			return 4
		}
	}
	return 2
}

type mdBuilder struct {
	strings []byte
	blobs   []byte
	guids   []byte
	tables  map[int][][]uint32
}

func newMDBuilder() *mdBuilder {
	return &mdBuilder{
		strings: []byte{0}, // offset 0 = empty string
		blobs:   []byte{0}, // offset 0 = empty blob
		tables:  map[int][][]uint32{},
	}
}

func (b *mdBuilder) str(s string) uint32 {
	if s == "" {
		return 0
	}
	off := uint32(len(b.strings))
	b.strings = append(b.strings, s...)
	b.strings = append(b.strings, 0)
	return off
}

func (b *mdBuilder) blob(data []byte) uint32 {
	off := uint32(len(b.blobs))
	if len(data) >= 0x80 {
		panic("test blobs are kept < 128 bytes")
	}
	b.blobs = append(b.blobs, byte(len(data)))
	b.blobs = append(b.blobs, data...)
	return off
}

func (b *mdBuilder) guid() uint32 {
	g := make([]byte, 16)
	for i := range g {
		g[i] = byte(i + 1)
	}
	b.guids = append(b.guids, g...)
	return uint32(len(b.guids) / 16) // 1-based
}

// addRow appends a raw row (column values already encoded) and returns its RID.
func (b *mdBuilder) addRow(table int, cols ...uint32) uint32 {
	b.tables[table] = append(b.tables[table], cols)
	return uint32(len(b.tables[table]))
}

// coded encodes a coded index: (rid << tagBits) | tag(table).
func coded2(ci, table int, rid uint32) uint32 {
	spec := codedIndexes[ci]
	tag := -1
	for i, t := range spec.tables {
		if t == table {
			tag = i
			break
		}
	}
	if tag < 0 {
		panic("table not in coded-index set")
	}
	return (rid << spec.tagBits) | uint32(tag)
}

func (b *mdBuilder) rowCounts() map[int]int {
	rc := map[int]int{}
	for t, rows := range b.tables {
		rc[t] = len(rows)
	}
	return rc
}

// buildTableStream assembles the #~ stream: header, row counts, and rows emitted at
// their runtime-computed widths (bWidth).
func (b *mdBuilder) buildTableStream(heapSizes byte) []byte {
	rc := b.rowCounts()
	present := []int{}
	var valid uint64
	for t := 0; t < numTables; t++ {
		if rc[t] > 0 {
			present = append(present, t)
			valid |= uint64(1) << uint(t)
		}
	}
	var buf bytes.Buffer
	buf.Write(le4(0))        // Reserved
	buf.WriteByte(2)         // MajorVersion
	buf.WriteByte(0)         // MinorVersion
	buf.WriteByte(heapSizes) // HeapSizes
	buf.WriteByte(1)         // Reserved
	buf.Write(le8(valid))    // Valid
	buf.Write(le8(0))        // Sorted
	for _, t := range present {
		buf.Write(le4(uint32(rc[t])))
	}
	for _, t := range present {
		cols := tableSchemas[t]
		for _, row := range b.tables[t] {
			for i, c := range cols {
				switch bWidth(heapSizes, rc, c) {
				case 4:
					buf.Write(le4(row[i]))
				default:
					buf.Write(le2(uint16(row[i])))
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

// buildMetadata assembles the metadata root + stream headers + heap/table streams.
func (b *mdBuilder) buildMetadata(heapSizes byte) []byte {
	tableStream := b.buildTableStream(heapSizes)
	us := []byte{0} // minimal #US heap

	type strm struct {
		name string
		data []byte
	}
	strms := []strm{
		{"#~", tableStream},
		{"#Strings", pad4(append([]byte{}, b.strings...))},
		{"#US", pad4(us)},
		{"#GUID", b.guids},
		{"#Blob", pad4(append([]byte{}, b.blobs...))},
	}

	// Metadata root header up to and including the stream count.
	version := pad4([]byte("v4.0.30319\x00"))
	var root bytes.Buffer
	root.Write(le4(bsjbSignature))
	root.Write(le2(1)) // MajorVersion
	root.Write(le2(1)) // MinorVersion
	root.Write(le4(0)) // Reserved
	root.Write(le4(uint32(len(version))))
	root.Write(version)
	root.Write(le2(0)) // Flags
	root.Write(le2(uint16(len(strms))))

	// Stream header sizes to compute each stream's offset from the root start.
	headerLen := root.Len()
	for _, s := range strms {
		name := pad4(append([]byte(s.name), 0))
		headerLen += 8 + len(name)
	}
	// Emit headers with offsets, then the data blocks.
	offset := headerLen
	var dataBlocks bytes.Buffer
	for _, s := range strms {
		root.Write(le4(uint32(offset)))
		root.Write(le4(uint32(len(s.data))))
		name := pad4(append([]byte(s.name), 0))
		root.Write(name)
		dataBlocks.Write(s.data)
		offset += len(s.data)
	}
	root.Write(dataBlocks.Bytes())
	return root.Bytes()
}

type peLayout struct {
	data            []byte
	cliFileOffset   int
	metadataFileOff int
	eLfanew         int
}

// wrapPE wraps metadata in a minimal PE32 container with one .text section holding
// the CLI header followed by the metadata.
func wrapPE(metadata []byte) peLayout {
	const (
		peSigOff      = 0x80
		coffOff       = peSigOff + 4
		optOff        = coffOff + 20
		optSize       = 224 // PE32: 96 + 16 data dirs*8
		secOff        = optOff + optSize
		rawStart      = 0x200
		sectionVA     = 0x2000
		cliHeaderSize = 72
	)
	metaRVA := uint32(sectionVA + cliHeaderSize)

	// CLI header (ECMA-335 §II.25.3.3).
	var cli bytes.Buffer
	cli.Write(le4(72))                    // cb
	cli.Write(le2(2))                     // MajorRuntimeVersion
	cli.Write(le2(5))                     // MinorRuntimeVersion
	cli.Write(le4(metaRVA))               // MetaData RVA
	cli.Write(le4(uint32(len(metadata)))) // MetaData Size
	cli.Write(le4(0))                     // Flags
	cli.Write(le4(0x06000001))            // EntryPointToken
	cli.Write(make([]byte, 48))           // 6 remaining data directories

	raw := append(cli.Bytes(), metadata...)

	data := make([]byte, rawStart+len(raw))
	// DOS header.
	data[0] = 'M'
	data[1] = 'Z'
	copy(data[0x3C:], le4(peSigOff))
	// PE signature.
	copy(data[peSigOff:], []byte{'P', 'E', 0, 0})
	// COFF file header.
	copy(data[coffOff+2:], le2(1))        // NumberOfSections
	copy(data[coffOff+16:], le2(optSize)) // SizeOfOptionalHeader
	// Optional header.
	copy(data[optOff:], le2(peMagicPE32)) // Magic
	copy(data[optOff+92:], le4(16))       // NumberOfRvaAndSizes
	// Data directory 14 (CLI header): RVA + Size.
	dir14 := optOff + 96 + dirCLIHeader*8
	copy(data[dir14:], le4(sectionVA))
	copy(data[dir14+4:], le4(uint32(len(raw))))
	// Section header (.text).
	copy(data[secOff:], []byte(".text\x00\x00\x00"))
	copy(data[secOff+8:], le4(uint32(len(raw))))  // VirtualSize
	copy(data[secOff+12:], le4(sectionVA))        // VirtualAddress
	copy(data[secOff+16:], le4(uint32(len(raw)))) // SizeOfRawData
	copy(data[secOff+20:], le4(rawStart))         // PointerToRawData
	// Section raw data.
	copy(data[rawStart:], raw)

	return peLayout{
		data:            data,
		cliFileOffset:   rawStart,
		metadataFileOff: rawStart + cliHeaderSize,
		eLfanew:         peSigOff,
	}
}

// standardFixture builds a complete assembly covering every table the reader parses:
// two TypeRefs (Object base, Console call parent), a <Module> type, a Widget type
// (extends Object, implements IDisposable, one method DoWork), a nested Inner type,
// a MemberRef (Console.WriteLine), a MethodImpl, TypeSpec, and MethodSpec.
func standardFixture(heapSizes byte) peLayout {
	b := newMDBuilder()
	sigDoWork := []byte{0x00, 0x00, 0x01} // DEFAULT, 0 params, void
	sigWL := []byte{0x00, 0x01, 0x01, 0x0e}

	nameModule := b.str("Test.dll")
	nsMyApp := b.str("MyApp")
	nWidget := b.str("Widget")
	nInner := b.str("Inner")
	nModule := b.str("<Module>")
	nsSystem := b.str("System")
	nObject := b.str("Object")
	nConsole := b.str("Console")
	nIDisposable := b.str("IDisposable")
	nDoWork := b.str("DoWork")
	nWriteLine := b.str("WriteLine")
	nAsm := b.str("TestAsm")
	nAsmRef := b.str("System.Runtime")
	mvid := b.guid()

	// Module (0x00).
	b.addRow(tModule, 0, nameModule, mvid, 0, 0)
	// AssemblyRef (0x23) RID 1 — the resolution scope for the TypeRefs.
	ridAsmRef := b.addRow(tAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), nAsmRef, 0, b.blob(nil))
	// TypeRef (0x01): Object (1), Console (2), IDisposable (3).
	scope := coded2(ciResolutionScope, tAssemblyRef, ridAsmRef)
	ridObject := b.addRow(tTypeRef, scope, nObject, nsSystem)
	ridConsole := b.addRow(tTypeRef, scope, nConsole, nsSystem)
	ridIDisp := b.addRow(tTypeRef, scope, nIDisposable, nsSystem)
	// MethodDef (0x06) RID 1 — DoWork, non-zero RVA (02b reads the IL body there).
	b.addRow(tMethodDef, 0x2100, 0, 0x0096, nDoWork, b.blob(sigDoWork), 1)
	// TypeDef (0x02): <Module> (1), Widget (2), Inner (3).
	b.addRow(tTypeDef, 0, nModule, 0, 0, 1, 1)
	ridWidget := b.addRow(tTypeDef, 0x100001, nWidget, nsMyApp, coded2(ciTypeDefOrRef, tTypeRef, ridObject), 1, 1)
	ridInner := b.addRow(tTypeDef, 0x100002, nInner, nsMyApp, coded2(ciTypeDefOrRef, tTypeRef, ridObject), 1, 2)
	// MemberRef (0x0A) RID 1 — Console.WriteLine.
	ridWL := b.addRow(tMemberRef, coded2(ciMemberRefParent, tTypeRef, ridConsole), nWriteLine, b.blob(sigWL))
	// InterfaceImpl (0x09): Widget implements IDisposable.
	b.addRow(tInterfaceImpl, ridWidget, coded2(ciTypeDefOrRef, tTypeRef, ridIDisp))
	// MethodImpl (0x19): Widget's DoWork is the body; declaration is the MemberRef.
	b.addRow(tMethodImpl, ridWidget, coded2(ciMethodDefOrRef, tMethodDef, 1), coded2(ciMethodDefOrRef, tMemberRef, ridWL))
	// NestedClass (0x29): Inner nested in Widget.
	b.addRow(tNestedClass, ridInner, ridWidget)
	// TypeSpec (0x1B) + MethodSpec (0x2B).
	b.addRow(tTypeSpec, b.blob([]byte{0x15, 0x12, 0x08, 0x01, 0x0e})) // GENERICINST ...
	b.addRow(tMethodSpec, coded2(ciMethodDefOrRef, tMethodDef, 1), b.blob([]byte{0x0a, 0x01, 0x0e}))
	// Assembly (0x20).
	b.addRow(tAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), nAsm, 0)

	return wrapPE(b.buildMetadata(heapSizes))
}

// ---- tests ----

func TestRead_ValidRoundTrip(t *testing.T) {
	assertModel(t, standardFixture(0x00), "narrow")
}

// TestRead_WideHeapRegime exercises the 4-byte index path: with all HeapSizes bits
// set, every #Strings/#GUID/#Blob index is 4 bytes wide. A reader that hardcoded
// 2-byte heap indexes would desync and resolve garbage names — this must round-trip
// identically to the narrow fixture.
func TestRead_WideHeapRegime(t *testing.T) {
	assertModel(t, standardFixture(0x07), "wide-heaps")
}

func assertModel(t *testing.T, layout peLayout, label string) {
	t.Helper()
	a, err := Read(layout.data)
	if err != nil {
		t.Fatalf("[%s] Read: %v", label, err)
	}
	if a.Name != "TestAsm" {
		t.Errorf("[%s] Name = %q, want TestAsm", label, a.Name)
	}
	if a.EntryPoint != 0x06000001 {
		t.Errorf("[%s] EntryPoint = 0x%x, want 0x06000001", label, a.EntryPoint)
	}
	if len(a.Types) != 3 {
		t.Fatalf("[%s] want 3 types, got %d", label, len(a.Types))
	}
	widget := a.Types[1]
	if widget.Name != "Widget" || widget.Namespace != "MyApp" {
		t.Errorf("[%s] type[1] = %s.%s, want MyApp.Widget", label, widget.Namespace, widget.Name)
	}
	if widget.Extends.Name != "Object" || widget.Extends.Namespace != "System" {
		t.Errorf("[%s] Widget.Extends = %s.%s, want System.Object", label, widget.Extends.Namespace, widget.Extends.Name)
	}
	if widget.Extends.Scope != "System.Runtime" {
		t.Errorf("[%s] Widget.Extends.Scope = %q, want System.Runtime", label, widget.Extends.Scope)
	}
	if len(widget.Methods) != 1 || widget.Methods[0].Name != "DoWork" {
		t.Fatalf("[%s] Widget methods = %+v, want [DoWork]", label, widget.Methods)
	}
	if widget.Methods[0].RVA != 0x2100 {
		t.Errorf("[%s] DoWork.RVA = 0x%x, want 0x2100 (02b reads the IL body here)", label, widget.Methods[0].RVA)
	}
	if len(widget.Methods[0].SigBlob) != 3 {
		t.Errorf("[%s] DoWork.SigBlob len = %d, want 3", label, len(widget.Methods[0].SigBlob))
	}
	// MethodByRID resolves the MethodDefOrRef target.
	if m := a.MethodByRID(1); m == nil || m.Name != "DoWork" {
		t.Errorf("[%s] MethodByRID(1) = %v, want DoWork", label, m)
	}
	// MemberRef → call target.
	mr := a.MemberRef(1)
	if mr == nil || mr.Name != "WriteLine" || mr.Type != "System.Console" || mr.Assembly != "System.Runtime" {
		t.Errorf("[%s] MemberRef(1) = %+v, want System.Runtime System.Console.WriteLine", label, mr)
	}
}

// TestCodedIndexWidth is the direct proof that index widths are RUNTIME-computed,
// not hardcoded: it drives codedIndexWidth/simpleIndexWidth across the 2^(16-tagBits)
// threshold and asserts the width flips 2→4. This is the coded-index computation the
// dispatch flags as the silent-corruption trap.
func TestCodedIndexWidth(t *testing.T) {
	// TypeDefOrRef has 2 tag bits → threshold 2^14 = 16384 rows in its widest table.
	narrow := &mdTables{}
	narrow.rowCount[tTypeDef] = 16383
	if w := narrow.codedIndexWidth(ciTypeDefOrRef); w != 2 {
		t.Errorf("TypeDefOrRef @16383 rows: width %d, want 2", w)
	}
	wide := &mdTables{}
	wide.rowCount[tTypeDef] = 16384 // crosses 2^14
	if w := wide.codedIndexWidth(ciTypeDefOrRef); w != 4 {
		t.Errorf("TypeDefOrRef @16384 rows: width %d, want 4 (a hardcoded-2 reader corrupts here)", w)
	}
	// MethodDefOrRef has 1 tag bit → threshold 2^15 = 32768.
	m := &mdTables{}
	m.rowCount[tMemberRef] = 32768
	if w := m.codedIndexWidth(ciMethodDefOrRef); w != 4 {
		t.Errorf("MethodDefOrRef @32768 rows: width %d, want 4", w)
	}
	// Simple index: TypeDef index widens at 2^16.
	s := &mdTables{}
	s.rowCount[tTypeDef] = 65535
	if w := s.simpleIndexWidth(tTypeDef); w != 2 {
		t.Errorf("simple TypeDef @65535: width %d, want 2", w)
	}
	s.rowCount[tTypeDef] = 65536
	if w := s.simpleIndexWidth(tTypeDef); w != 4 {
		t.Errorf("simple TypeDef @65536: width %d, want 4", w)
	}
	// Heap widths follow the HeapSizes bits.
	h := &mdTables{heapSizes: 0x04} // #Blob wide only
	if h.heapWidth(0) != 2 || h.heapWidth(2) != 4 {
		t.Errorf("heap widths for HeapSizes=0x04: string=%d blob=%d, want 2/4", h.heapWidth(0), h.heapWidth(2))
	}
}

func TestRead_InterfaceImplAndMethodImpl(t *testing.T) {
	a, err := Read(standardFixture(0x00).data)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	// InterfaceImpl attached to Widget.
	widget := a.Types[1]
	if len(widget.Interfaces) != 1 || widget.Interfaces[0].Name != "IDisposable" {
		t.Errorf("Widget.Interfaces = %+v, want [IDisposable]", widget.Interfaces)
	}
	// MethodImpl body→declaration (the .NET-unique explicit-interface map 02b needs).
	if len(a.MethodImpls) != 1 {
		t.Fatalf("want 1 MethodImpl, got %d", len(a.MethodImpls))
	}
	mi := a.MethodImpls[0]
	if mi.Class.Table() != tTypeDef || mi.Class.RID() != widget.RID {
		t.Errorf("MethodImpl.Class = %v, want TypeDef Widget", mi.Class)
	}
	if mi.Body.Table() != tMethodDef || mi.Body.RID() != 1 {
		t.Errorf("MethodImpl.Body = %v, want MethodDef 1", mi.Body)
	}
	if mi.Declaration.Table() != tMemberRef || mi.Declaration.RID() != 1 {
		t.Errorf("MethodImpl.Declaration = %v, want MemberRef 1", mi.Declaration)
	}
	// NestedClass, TypeSpec, MethodSpec all parsed for 02b.
	if len(a.NestedTypes) != 1 || a.NestedTypes[0].Nested.RID() != a.Types[2].RID {
		t.Errorf("NestedTypes = %+v, want Inner nested in Widget", a.NestedTypes)
	}
	if len(a.TypeSpecs) != 2 || len(a.TypeSpecs[1].Blob) == 0 { // index 0 is placeholder
		t.Errorf("TypeSpecs = %+v, want one non-empty spec at RID 1", a.TypeSpecs)
	}
	if len(a.MethodSpecs) != 2 || a.MethodSpecs[1].Method.RID() != 1 {
		t.Errorf("MethodSpecs = %+v, want MethodSpec over MethodDef 1", a.MethodSpecs)
	}
}

// safeRead runs Read guarded against panics — a panic on hostile dependency bytes
// is a crash-DoS seam and a hard test failure.
func safeRead(data []byte) (a *Assembly, err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	a, err = Read(data)
	return
}

func TestRead_MalformedInputsErrorNeverPanic(t *testing.T) {
	good := standardFixture(0x00)

	corrupt := func(off int, b ...byte) []byte {
		d := append([]byte{}, good.data...)
		copy(d[off:], b)
		return d
	}

	cases := map[string][]byte{
		"empty":                 nil,
		"one-byte":              {0x4D},
		"bad-mz":                corrupt(0, 0x00, 0x00),
		"bad-pe-sig":            corrupt(good.eLfanew, 0xDE, 0xAD),
		"bad-bsjb":              corrupt(good.metadataFileOff, 0xFF, 0xFF, 0xFF, 0xFF),
		"metadata-rva-oob":      corrupt(good.cliFileOffset+8, 0xF0, 0xFF, 0xFF, 0x7F),
		"trunc-before-metadata": good.data[:good.metadataFileOff+4],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err, panicked := safeRead(data)
			if panicked {
				t.Fatalf("panicked on %s (must return an error)", name)
			}
			if err == nil {
				t.Fatalf("want an error for %s, got nil", name)
			}
		})
	}
}

// TestRead_EveryPrefixIsSafe feeds every prefix of the valid assembly to Read: none
// may panic (a panic on truncated/hostile bytes is a crash-DoS seam).
func TestRead_EveryPrefixIsSafe(t *testing.T) {
	good := standardFixture(0x00).data
	for i := 0; i <= len(good); i++ {
		if _, _, panicked := safeRead(good[:i]); panicked {
			t.Fatalf("panicked on prefix length %d", i)
		}
	}
}

// TestReadResult_DegradesNotFails proves the batch path yields a Failed assembly
// (the completeness-hazard analog) rather than an error the caller must special-case.
func TestReadResult_DegradesNotFails(t *testing.T) {
	r := ReadResult("Broken.dll", []byte{0x4D, 0x5A, 0x00})
	if !r.Failed || r.Name != "Broken.dll" || r.FailReason == "" {
		t.Fatalf("ReadResult malformed = %+v, want Failed with reason", r)
	}
	ok := ReadResult("Test.dll", standardFixture(0x00).data)
	if ok.Failed {
		t.Fatalf("ReadResult on valid bytes marked Failed: %s", ok.FailReason)
	}
}
