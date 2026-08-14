package assembly

import "fmt"

// ---- table ids (ECMA-335 §II.22) ----
const (
	tModule                 = 0x00
	tTypeRef                = 0x01
	tTypeDef                = 0x02
	tFieldPtr               = 0x03
	tField                  = 0x04
	tMethodPtr              = 0x05
	tMethodDef              = 0x06
	tParamPtr               = 0x07
	tParam                  = 0x08
	tInterfaceImpl          = 0x09
	tMemberRef              = 0x0A
	tConstant               = 0x0B
	tCustomAttribute        = 0x0C
	tFieldMarshal           = 0x0D
	tDeclSecurity           = 0x0E
	tClassLayout            = 0x0F
	tFieldLayout            = 0x10
	tStandAloneSig          = 0x11
	tEventMap               = 0x12
	tEventPtr               = 0x13
	tEvent                  = 0x14
	tPropertyMap            = 0x15
	tPropertyPtr            = 0x16
	tProperty               = 0x17
	tMethodSemantics        = 0x18
	tMethodImpl             = 0x19
	tModuleRef              = 0x1A
	tTypeSpec               = 0x1B
	tImplMap                = 0x1C
	tFieldRVA               = 0x1D
	tEncLog                 = 0x1E
	tEncMap                 = 0x1F
	tAssembly               = 0x20
	tAssemblyProcessor      = 0x21
	tAssemblyOS             = 0x22
	tAssemblyRef            = 0x23
	tAssemblyRefProcessor   = 0x24
	tAssemblyRefOS          = 0x25
	tFile                   = 0x26
	tExportedType           = 0x27
	tManifestResource       = 0x28
	tNestedClass            = 0x29
	tGenericParam           = 0x2A
	tMethodSpec             = 0x2B
	tGenericParamConstraint = 0x2C
	numTables               = 64
)

// ---- coded-index kinds (ECMA-335 §II.24.2.6) ----
// Each is a set of target tables indexed by the low tag bits, plus the tag-bit
// count. tagUnused marks a reserved tag value that must never appear.
const tagUnused = -1

const (
	ciTypeDefOrRef = iota
	ciHasConstant
	ciHasCustomAttribute
	ciHasFieldMarshall
	ciHasDeclSecurity
	ciMemberRefParent
	ciHasSemantics
	ciMethodDefOrRef
	ciMemberForwarded
	ciImplementation
	ciCustomAttributeType
	ciResolutionScope
	ciTypeOrMethodDef
)

type codedSpec struct {
	tables  []int
	tagBits uint
}

// codedIndexes is the tag→table decode for every coded index. THE correctness
// trap (dispatch §"variable index widths") lives here: a coded index is 2 bytes
// only while max(row counts of its target tables) < 2^(16-tagBits); once any
// target table crosses that, the column widens to 4. See codedIndexWidth.
var codedIndexes = map[int]codedSpec{
	ciTypeDefOrRef: {[]int{tTypeDef, tTypeRef, tTypeSpec}, 2},
	ciHasConstant:  {[]int{tField, tParam, tProperty}, 2},
	ciHasCustomAttribute: {[]int{
		tMethodDef, tField, tTypeRef, tTypeDef, tParam, tInterfaceImpl, tMemberRef,
		tModule, tDeclSecurity, tProperty, tEvent, tStandAloneSig, tModuleRef,
		tTypeSpec, tAssembly, tAssemblyRef, tFile, tExportedType, tManifestResource,
		tGenericParam, tGenericParamConstraint, tMethodSpec,
	}, 5},
	ciHasFieldMarshall:    {[]int{tField, tParam}, 1},
	ciHasDeclSecurity:     {[]int{tTypeDef, tMethodDef, tAssembly}, 2},
	ciMemberRefParent:     {[]int{tTypeDef, tTypeRef, tModuleRef, tMethodDef, tTypeSpec}, 3},
	ciHasSemantics:        {[]int{tEvent, tProperty}, 1},
	ciMethodDefOrRef:      {[]int{tMethodDef, tMemberRef}, 1},
	ciMemberForwarded:     {[]int{tField, tMethodDef}, 1},
	ciImplementation:      {[]int{tFile, tAssemblyRef, tExportedType}, 2},
	ciCustomAttributeType: {[]int{tagUnused, tagUnused, tMethodDef, tMemberRef, tagUnused}, 3},
	ciResolutionScope:     {[]int{tModule, tModuleRef, tAssemblyRef, tTypeRef}, 2},
	ciTypeOrMethodDef:     {[]int{tTypeDef, tMethodDef}, 1},
}

// ---- column model ----
type colType int

const (
	colU2 colType = iota
	colU4
	colString // #Strings heap index
	colGUID   // #GUID heap index
	colBlob   // #Blob heap index
	colTable  // simple index into table param
	colCoded  // coded index of kind param
)

type column struct {
	kind  colType
	param int
}

func u2() column          { return column{colU2, 0} }
func u4() column          { return column{colU4, 0} }
func str() column         { return column{colString, 0} }
func guid() column        { return column{colGUID, 0} }
func blob() column        { return column{colBlob, 0} }
func idx(t int) column    { return column{colTable, t} }
func coded(ci int) column { return column{colCoded, ci} }

// tableSchemas gives every ECMA-335 table's column layout. It is exhaustive on
// purpose: even a table the graph never reads must have its exact row width known,
// or the cursor desyncs and every later table is parsed from garbage. Tables the
// graph reads are decoded (assembly.go); the rest are advanced-over by width.
var tableSchemas = map[int][]column{
	tModule:                 {u2(), str(), guid(), guid(), guid()},
	tTypeRef:                {coded(ciResolutionScope), str(), str()},
	tTypeDef:                {u4(), str(), str(), coded(ciTypeDefOrRef), idx(tField), idx(tMethodDef)},
	tFieldPtr:               {idx(tField)},
	tField:                  {u2(), str(), blob()},
	tMethodPtr:              {idx(tMethodDef)},
	tMethodDef:              {u4(), u2(), u2(), str(), blob(), idx(tParam)},
	tParamPtr:               {idx(tParam)},
	tParam:                  {u2(), u2(), str()},
	tInterfaceImpl:          {idx(tTypeDef), coded(ciTypeDefOrRef)},
	tMemberRef:              {coded(ciMemberRefParent), str(), blob()},
	tConstant:               {u2(), coded(ciHasConstant), blob()}, // Type(1)+pad(1)=u2
	tCustomAttribute:        {coded(ciHasCustomAttribute), coded(ciCustomAttributeType), blob()},
	tFieldMarshal:           {coded(ciHasFieldMarshall), blob()},
	tDeclSecurity:           {u2(), coded(ciHasDeclSecurity), blob()},
	tClassLayout:            {u2(), u4(), idx(tTypeDef)},
	tFieldLayout:            {u4(), idx(tField)},
	tStandAloneSig:          {blob()},
	tEventMap:               {idx(tTypeDef), idx(tEvent)},
	tEventPtr:               {idx(tEvent)},
	tEvent:                  {u2(), str(), coded(ciTypeDefOrRef)},
	tPropertyMap:            {idx(tTypeDef), idx(tProperty)},
	tPropertyPtr:            {idx(tProperty)},
	tProperty:               {u2(), str(), blob()},
	tMethodSemantics:        {u2(), idx(tMethodDef), coded(ciHasSemantics)},
	tMethodImpl:             {idx(tTypeDef), coded(ciMethodDefOrRef), coded(ciMethodDefOrRef)},
	tModuleRef:              {str()},
	tTypeSpec:               {blob()},
	tImplMap:                {u2(), coded(ciMemberForwarded), str(), idx(tModuleRef)},
	tFieldRVA:               {u4(), idx(tField)},
	tEncLog:                 {u4(), u4()},
	tEncMap:                 {u4()},
	tAssembly:               {u4(), u2(), u2(), u2(), u2(), u4(), blob(), str(), str()},
	tAssemblyProcessor:      {u4()},
	tAssemblyOS:             {u4(), u4(), u4()},
	tAssemblyRef:            {u2(), u2(), u2(), u2(), u4(), blob(), str(), str(), blob()},
	tAssemblyRefProcessor:   {u4(), idx(tAssemblyRef)},
	tAssemblyRefOS:          {u4(), u4(), u4(), idx(tAssemblyRef)},
	tFile:                   {u4(), str(), blob()},
	tExportedType:           {u4(), u4(), str(), str(), coded(ciImplementation)},
	tManifestResource:       {u4(), u4(), str(), coded(ciImplementation)},
	tNestedClass:            {idx(tTypeDef), idx(tTypeDef)}, // NestedClass, EnclosingClass — both TypeDef indexes
	tGenericParam:           {u2(), u2(), coded(ciTypeOrMethodDef), str()},
	tMethodSpec:             {coded(ciMethodDefOrRef), blob()},
	tGenericParamConstraint: {idx(tGenericParam), coded(ciTypeDefOrRef)},
}

// mdTables holds the parsed #~ (compressed metadata) tables plus the heaps and the
// runtime-computed widths that decode them. rowCount is indexed by table id.
type mdTables struct {
	heapSizes byte
	rowCount  [numTables]uint32
	rows      map[int][][]uint32 // retained decoded rows, keyed by table id

	stringHeap []byte
	blobHeap   []byte
	guidHeap   []byte
}

// heapWidth returns 4 when the HeapSizes bit for a heap is set, else 2.
// bit0=#Strings, bit1=#GUID, bit2=#Blob (ECMA-335 §II.24.2.6).
func (m *mdTables) heapWidth(bit uint) int {
	if m.heapSizes&(1<<bit) != 0 {
		return 4
	}
	return 2
}

// simpleIndexWidth: an index into a single table is 2 bytes while that table has
// fewer than 2^16 rows, else 4.
func (m *mdTables) simpleIndexWidth(table int) int {
	if table >= 0 && table < numTables && m.rowCount[table] >= (1<<16) {
		return 4
	}
	return 2
}

// codedIndexWidth is THE index-width computation the dispatch flags as the silent-
// corruption trap. A coded index over a set of tables with tagBits tag bits is 2
// bytes iff the largest of those tables has fewer than 2^(16-tagBits) rows; once
// any target table crosses that threshold the column is 4 bytes. Hardcoding 2
// passes tiny fixtures and corrupts real assemblies — so it is always computed.
func (m *mdTables) codedIndexWidth(ci int) int {
	spec := codedIndexes[ci]
	var maxRows uint32
	for _, t := range spec.tables {
		if t == tagUnused {
			continue
		}
		if r := m.rowCount[t]; r > maxRows {
			maxRows = r
		}
	}
	if uint64(maxRows) < (uint64(1) << (16 - spec.tagBits)) {
		return 2
	}
	return 4
}

func (m *mdTables) colWidth(c column) int {
	switch c.kind {
	case colU2:
		return 2
	case colU4:
		return 4
	case colString:
		return m.heapWidth(0)
	case colGUID:
		return m.heapWidth(1)
	case colBlob:
		return m.heapWidth(2)
	case colTable:
		return m.simpleIndexWidth(c.param)
	case colCoded:
		return m.codedIndexWidth(c.param)
	}
	return 0
}

// metadata heap-stream signatures.
const bsjbSignature = 0x424A5342 // "BSJB", metadata root magic (little-endian u4)

// parseMetadata parses the CLI metadata root, stream headers, heaps, and the #~
// compressed table stream into an mdTables. Every read is bounds-checked.
func parseMetadata(pe *peFile) (*mdTables, error) {
	rootOff, err := pe.rvaToOffset(pe.cli.metadataRVA)
	if err != nil {
		return nil, fmt.Errorf("assembly: metadata RVA: %w", err)
	}
	r := &reader{b: pe.data, pos: rootOff}

	// Metadata root (ECMA-335 §II.24.2.1).
	if r.u4() != bsjbSignature {
		return nil, fmt.Errorf("assembly: bad metadata signature (want BSJB)")
	}
	r.u2() // MajorVersion
	r.u2() // MinorVersion
	r.u4() // Reserved
	verLen := int(r.u4())
	r.skip(verLen) // Version string (verLen already padded to 4-byte boundary)
	r.u2()         // Flags
	streamCount := int(r.u2())
	if r.err != nil {
		return nil, fmt.Errorf("assembly: metadata root: %w", r.err)
	}

	// Stream headers (§II.24.2.2): Offset(4, from root), Size(4), Name (null-
	// terminated ASCII padded to a 4-byte boundary, <= 32 bytes).
	type stream struct{ off, size int }
	streams := map[string]stream{}
	for i := 0; i < streamCount; i++ {
		off := int(r.u4())
		size := int(r.u4())
		name := make([]byte, 0, 16)
		for {
			c := r.u1()
			if r.err != nil {
				return nil, fmt.Errorf("assembly: stream header name: %w", r.err)
			}
			if c == 0 {
				break
			}
			name = append(name, c)
			if len(name) > 32 {
				return nil, fmt.Errorf("assembly: stream name too long")
			}
		}
		// Advance to the next 4-byte boundary (name length including the null).
		pad := (len(name) + 1) % 4
		if pad != 0 {
			r.skip(4 - pad)
		}
		if r.err != nil {
			return nil, r.err
		}
		streams[string(name)] = stream{off, size}
	}

	m := &mdTables{rows: map[int][][]uint32{}}

	slice := func(s stream) ([]byte, error) {
		start := rootOff + s.off
		end := start + s.size
		if s.off < 0 || s.size < 0 || start < rootOff || end > len(pe.data) {
			return nil, fmt.Errorf("assembly: stream [%d,%d) out of file size %d", start, end, len(pe.data))
		}
		return pe.data[start:end], nil
	}
	if s, ok := streams["#Strings"]; ok {
		if m.stringHeap, err = slice(s); err != nil {
			return nil, err
		}
	}
	if s, ok := streams["#Blob"]; ok {
		if m.blobHeap, err = slice(s); err != nil {
			return nil, err
		}
	}
	if s, ok := streams["#GUID"]; ok {
		if m.guidHeap, err = slice(s); err != nil {
			return nil, err
		}
	}

	// The table stream is "#~" (compressed/optimized) or "#-" (uncompressed/ENC).
	ts, ok := streams["#~"]
	if !ok {
		ts, ok = streams["#-"]
	}
	if !ok {
		return nil, fmt.Errorf("assembly: no #~ or #- metadata table stream")
	}
	tblBytes, err := slice(ts)
	if err != nil {
		return nil, err
	}
	if err := m.parseTableStream(tblBytes); err != nil {
		return nil, err
	}
	return m, nil
}

// parseTableStream parses the #~ header (row counts + heap-size flags) and then the
// table rows, decoding retained tables and advancing over the rest by exact width.
func (m *mdTables) parseTableStream(b []byte) error {
	r := &reader{b: b}
	r.u4() // Reserved (0)
	r.u1() // MajorVersion
	r.u1() // MinorVersion
	m.heapSizes = r.u1()
	r.u1()          // Reserved (1)
	valid := r.u8() // bit i set => table i is present
	r.u8()          // Sorted bitvector (unused here)
	if r.err != nil {
		return fmt.Errorf("assembly: #~ header: %w", r.err)
	}

	// Row counts: one u4 per present table, in ascending table-id order.
	present := make([]int, 0, numTables)
	for t := 0; t < numTables; t++ {
		if valid&(uint64(1)<<uint(t)) != 0 {
			present = append(present, t)
		}
	}
	for _, t := range present {
		n := r.u4()
		if r.err != nil {
			return fmt.Errorf("assembly: #~ row counts: %w", r.err)
		}
		if _, known := tableSchemas[t]; !known {
			return fmt.Errorf("assembly: unknown metadata table id 0x%x present in Valid vector", t)
		}
		m.rowCount[t] = n
	}

	// Table rows. Widths are now fully determined (all row counts known), so decode
	// each present table row-by-row. Every column advances the cursor by exactly
	// its computed width — retained tables keep their values; the rest are dropped.
	retained := map[int]bool{
		tModule: true, tTypeRef: true, tTypeDef: true, tField: true, tMethodDef: true,
		tParam: true, tInterfaceImpl: true, tMemberRef: true, tMethodImpl: true,
		tTypeSpec: true, tMethodSpec: true, tNestedClass: true, tModuleRef: true,
		tAssembly: true, tAssemblyRef: true,
	}
	for _, t := range present {
		cols := tableSchemas[t]
		n := int(m.rowCount[t])
		var store [][]uint32
		if retained[t] {
			store = make([][]uint32, 0, n)
		}
		for i := 0; i < n; i++ {
			var row []uint32
			if retained[t] {
				row = make([]uint32, len(cols))
			}
			for ci, c := range cols {
				v := m.readColumn(r, c)
				if retained[t] {
					row[ci] = v
				}
			}
			if r.err != nil {
				return fmt.Errorf("assembly: table 0x%x row %d: %w", t, i, r.err)
			}
			if retained[t] {
				store = append(store, row)
			}
		}
		if retained[t] {
			m.rows[t] = store
		}
	}
	return nil
}

// ---- heap accessors ----

// str resolves a #Strings heap index (a byte offset) to its null-terminated UTF-8
// string. Offset 0 is the empty string; an out-of-range index yields "".
func (m *mdTables) str(idx uint32) string {
	if idx == 0 || int(idx) >= len(m.stringHeap) {
		return ""
	}
	end := int(idx)
	for end < len(m.stringHeap) && m.stringHeap[end] != 0 {
		end++
	}
	return string(m.stringHeap[idx:end])
}

// blob resolves a #Blob heap index to a copied byte slice. Each blob is prefixed by
// a compressed-integer length (§II.23.2); an out-of-range or malformed index yields
// nil. The result is copied so callers never alias the underlying file bytes.
func (m *mdTables) blob(idx uint32) []byte {
	if int(idx) >= len(m.blobHeap) {
		return nil
	}
	br := &reader{b: m.blobHeap, pos: int(idx)}
	n, ok := br.compressedUint()
	if !ok {
		return nil
	}
	raw := br.bytes(int(n))
	if br.err != nil {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// compressedUint decodes an ECMA-335 §II.23.2 compressed unsigned integer (1, 2, or
// 4 bytes selected by the leading bits). ok is false on a short read or bad prefix.
func (r *reader) compressedUint() (uint32, bool) {
	b0 := r.u1()
	if r.err != nil {
		return 0, false
	}
	switch {
	case b0&0x80 == 0:
		return uint32(b0), true
	case b0&0xC0 == 0x80:
		b1 := r.u1()
		if r.err != nil {
			return 0, false
		}
		return uint32(b0&0x3F)<<8 | uint32(b1), true
	case b0&0xE0 == 0xC0:
		b1, b2, b3 := r.u1(), r.u1(), r.u1()
		if r.err != nil {
			return 0, false
		}
		return uint32(b0&0x1F)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3), true
	}
	return 0, false
}

// decodeCoded turns a raw coded-index value into a metadata Token (table id + RID),
// splitting off the low tag bits per §II.24.2.6. A reserved/unused tag yields a null
// token (RID 0), which callers treat as an unresolved reference — never a panic.
func decodeCoded(ci int, raw uint32) Token {
	spec := codedIndexes[ci]
	tag := int(raw & ((1 << spec.tagBits) - 1))
	rid := raw >> spec.tagBits
	if tag >= len(spec.tables) || spec.tables[tag] == tagUnused {
		return 0
	}
	return makeToken(spec.tables[tag], rid)
}

// readColumn reads one column at its runtime-computed width (2 or 4 bytes) and
// returns the value widened to uint32 (heap indexes and RIDs both fit, as do the
// fixed 2/4-byte fields). Reading at the computed width is what keeps the cursor
// aligned across every table — the whole point of the index-width machinery.
func (m *mdTables) readColumn(r *reader, c column) uint32 {
	if m.colWidth(c) == 4 {
		return r.u4()
	}
	return uint32(r.u2())
}
