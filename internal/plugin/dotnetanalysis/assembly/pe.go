// Package assembly is a pure-Go, stdlib-only reader for .NET managed assemblies:
// it parses the PE-COFF container (Microsoft PE/COFF spec) and the CLI metadata
// (ECMA-335 §II) into a typed model the Assess-tier call-graph analysis consumes.
// No CLR, no reflection-based runtime load, no cgo, no ildasm: the analyzer reads
// the customer's already-cached dependency bytes and never loads them into a runtime.
//
// It is deliberately defensive. The input is third-party dependency bytecode —
// possibly obfuscated, truncated, or hostile — so no parse path panics: every read
// is bounds-checked, and a malformed assembly returns an error (and, on the batch
// path, an Assembly{Failed:true}) rather than a crash or a silently-wrong graph.
//
// SCOPE: this file (and metadata.go, assembly.go) build the READER only — the PE
// container, the CLI metadata heaps, and the row-parsed tables the graph needs.
// The IL instruction-walk and Class-Hierarchy Analysis are a separate concern
// (agent 02b / il.go): this package stops at the typed model plus the tables and
// coded-index resolution helpers 02b consumes (MethodDef.RVA for the IL body,
// the MethodImpl body→decl slot map, and Token-based coded-index resolution).
package assembly

import (
	"encoding/binary"
	"fmt"
)

// reader is a bounds-checked little-endian cursor (PE and CLI metadata are both
// little-endian). On the first short read it records err and every subsequent read
// is a no-op returning zero, so a whole structure can be decoded and err checked
// once at the boundary — no panics, no per-read error threading.
type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

func (r *reader) has(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 {
		r.fail("assembly: negative length %d", n)
		return false
	}
	if r.pos+n > len(r.b) {
		r.fail("assembly: truncated: want %d bytes at offset %d of %d", n, r.pos, len(r.b))
		return false
	}
	return true
}

// seek positions the cursor at an absolute offset; the next read bounds-checks it.
func (r *reader) seek(abs int) {
	if r.err != nil {
		return
	}
	if abs < 0 || abs > len(r.b) {
		r.fail("assembly: seek out of range: %d of %d", abs, len(r.b))
		return
	}
	r.pos = abs
}

func (r *reader) u1() uint8 {
	if !r.has(1) {
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u2() uint16 {
	if !r.has(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u4() uint32 {
	if !r.has(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *reader) u8() uint64 {
	if !r.has(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b[r.pos:])
	r.pos += 8
	return v
}

func (r *reader) bytes(n int) []byte {
	if !r.has(n) {
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) skip(n int) {
	if !r.has(n) {
		return
	}
	r.pos += n
}

// section is one PE section header entry (Microsoft PE/COFF §3.3): the fields
// rvaToOffset needs to map a Relative Virtual Address to a file offset.
type section struct {
	virtualSize    uint32
	virtualAddress uint32
	sizeOfRawData  uint32
	pointerToRaw   uint32
}

// cliHeader is the CLI header (ECMA-335 §II.25.3.3): where the metadata lives plus
// the assembly-wide flags and the entry-point token.
type cliHeader struct {
	metadataRVA  uint32
	metadataSize uint32
	flags        uint32
	entryPoint   uint32 // EntryPointToken (or RVA if COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
}

// peFile is the parsed PE container: the section table (for RVA mapping) and the
// CLI header (for locating the metadata root).
type peFile struct {
	data     []byte
	sections []section
	cli      cliHeader
}

const (
	peMagicPE32     = 0x10b // optional-header magic: PE32
	peMagicPE32Plus = 0x20b // optional-header magic: PE32+
	// Data directory index 14 (0-based) is the CLI header (a.k.a. COM descriptor).
	dirCLIHeader = 14
	// DataDirectory arrays begin at these offsets from the optional-header start;
	// the difference is PE32's extra 4-byte BaseOfData plus the 4→8-byte widening
	// of ImageBase and the four stack/heap size fields in PE32+.
	dirsOffsetPE32     = 96
	dirsOffsetPE32Plus = 112
)

// parsePE parses the PE-COFF container down to the CLI header and section table.
// Every field is bounds-checked; a malformed container returns a descriptive error.
func parsePE(data []byte) (*peFile, error) {
	r := &reader{b: data}

	// DOS header: "MZ", then e_lfanew (file offset of the PE signature) at 0x3C.
	if r.u1() != 'M' || r.u1() != 'Z' {
		return nil, fmt.Errorf("assembly: not a PE image (missing MZ signature)")
	}
	r.seek(0x3C)
	peSigOff := int(r.u4())
	if r.err != nil {
		return nil, r.err
	}

	// PE signature "PE\0\0".
	r.seek(peSigOff)
	if r.u1() != 'P' || r.u1() != 'E' || r.u1() != 0 || r.u1() != 0 {
		return nil, fmt.Errorf("assembly: bad PE signature at offset %d", peSigOff)
	}

	// COFF file header (20 bytes).
	coffStart := peSigOff + 4
	r.seek(coffStart)
	r.u2() // Machine
	numSections := int(r.u2())
	r.u4() // TimeDateStamp
	r.u4() // PointerToSymbolTable
	r.u4() // NumberOfSymbols
	sizeOfOptional := int(r.u2())
	r.u2() // Characteristics
	if r.err != nil {
		return nil, r.err
	}

	optStart := coffStart + 20
	r.seek(optStart)
	magic := r.u2()
	if r.err != nil {
		return nil, r.err
	}
	var dirsOffset int
	switch magic {
	case peMagicPE32:
		dirsOffset = dirsOffsetPE32
	case peMagicPE32Plus:
		dirsOffset = dirsOffsetPE32Plus
	default:
		return nil, fmt.Errorf("assembly: unknown optional-header magic 0x%x", magic)
	}

	// NumberOfRvaAndSizes sits immediately before the data-directory array.
	r.seek(optStart + dirsOffset - 4)
	numDirs := int(r.u4())
	if r.err != nil {
		return nil, r.err
	}
	if numDirs <= dirCLIHeader {
		return nil, fmt.Errorf("assembly: only %d data directories, no CLI header (dir %d)", numDirs, dirCLIHeader)
	}

	// CLI header data directory (RVA + size).
	r.seek(optStart + dirsOffset + dirCLIHeader*8)
	cliRVA := r.u4()
	cliSize := r.u4()
	if r.err != nil {
		return nil, r.err
	}
	if cliRVA == 0 {
		return nil, fmt.Errorf("assembly: no CLI header (unmanaged PE)")
	}

	// Section table follows the optional header.
	secStart := optStart + sizeOfOptional
	r.seek(secStart)
	pe := &peFile{data: data, sections: make([]section, 0, numSections)}
	for i := 0; i < numSections; i++ {
		r.skip(8) // Name[8]
		s := section{
			virtualSize:    r.u4(),
			virtualAddress: r.u4(),
			sizeOfRawData:  r.u4(),
			pointerToRaw:   r.u4(),
		}
		r.u4() // PointerToRelocations
		r.u4() // PointerToLinenumbers
		r.u2() // NumberOfRelocations
		r.u2() // NumberOfLinenumbers
		r.u4() // Characteristics
		if r.err != nil {
			return nil, r.err
		}
		pe.sections = append(pe.sections, s)
	}

	// CLI header (ECMA-335 §II.25.3.3), located via the data directory RVA.
	cliOff, err := pe.rvaToOffset(cliRVA)
	if err != nil {
		return nil, fmt.Errorf("assembly: CLI header RVA: %w", err)
	}
	cr := &reader{b: data, pos: cliOff}
	cb := cr.u4() // cb (header size)
	cr.u2()       // MajorRuntimeVersion
	cr.u2()       // MinorRuntimeVersion
	pe.cli.metadataRVA = cr.u4()
	pe.cli.metadataSize = cr.u4()
	pe.cli.flags = cr.u4()
	pe.cli.entryPoint = cr.u4()
	if cr.err != nil {
		return nil, fmt.Errorf("assembly: CLI header: %w", cr.err)
	}
	if cb < 72 {
		return nil, fmt.Errorf("assembly: CLI header too small (cb=%d)", cb)
	}
	if pe.cli.metadataRVA == 0 {
		return nil, fmt.Errorf("assembly: CLI header has no metadata RVA")
	}
	_ = cliSize
	return pe, nil
}

// rvaToOffset maps a Relative Virtual Address to a file offset using the section
// table (VirtualAddress/VirtualSize/SizeOfRawData/PointerToRawData). An RVA that
// falls in no section, or whose mapped offset would exceed the file, is an error —
// never an out-of-range slice.
func (pe *peFile) rvaToOffset(rva uint32) (int, error) {
	for _, s := range pe.sections {
		// The section spans max(VirtualSize, SizeOfRawData) so an RVA in the
		// zero-filled tail (VirtualSize > raw) still resolves — but reads past
		// SizeOfRawData will bounds-fail at the reader, which is correct.
		span := s.virtualSize
		if s.sizeOfRawData > span {
			span = s.sizeOfRawData
		}
		if rva >= s.virtualAddress && rva < s.virtualAddress+span {
			delta := rva - s.virtualAddress
			off := int(s.pointerToRaw) + int(delta)
			if off < 0 || off > len(pe.data) {
				return 0, fmt.Errorf("rva 0x%x maps to offset %d out of file size %d", rva, off, len(pe.data))
			}
			return off, nil
		}
	}
	return 0, fmt.Errorf("rva 0x%x falls in no section", rva)
}
