package classfile

import (
	"encoding/binary"
	"fmt"
)

// parseCode walks the Code attribute's bytecode array instruction-by-instruction —
// NOT a naive byte scan, which would mistake operand bytes for opcodes and
// hallucinate calls — and collects one Edge per invoke* site plus the set of
// classes this method's bytecode triggers static initialization of. The fixed-length
// operand table is JVMS §6; tableswitch/lookupswitch/wide are variable and handled
// explicitly. Every read is bounds-checked: malformed bytecode returns an error,
// never a panic, and never a partial edge list masquerading as complete.
//
// initTriggers are the classes whose <clinit> the JVM runs on first active use of
// the class within this method — `new`, `getstatic`/`putstatic`, and `invokestatic`
// (JVMS §5.5). <clinit> is never the target of an explicit invoke instruction, so
// without these a sink reachable only through a static initializer is invisible to
// the call graph — a false-not_exploitable seam the caller closes by walking into
// each triggered class's <clinit>.
func parseCode(code []byte, cp constPool) (edges []Edge, initTriggers []string, err error) {
	// Code attribute prefix: u2 max_stack, u2 max_locals, u4 code_length, code[]...
	if len(code) < 8 {
		return nil, nil, fmt.Errorf("Code attribute too short: %d bytes", len(code))
	}
	codeLen := int(binary.BigEndian.Uint32(code[4:]))
	start := 8
	if codeLen < 0 || start+codeLen > len(code) {
		return nil, nil, fmt.Errorf("Code length %d overflows attribute (%d bytes)", codeLen, len(code))
	}
	insns := code[start : start+codeLen]

	triggered := map[string]bool{}
	trigger := func(owner string) {
		if owner != "" && !triggered[owner] {
			triggered[owner] = true
			initTriggers = append(initTriggers, owner)
		}
	}

	pc := 0
	for pc < len(insns) {
		op := insns[pc]
		switch op {
		case 0xB6, 0xB7, 0xB8: // invokevirtual, invokespecial, invokestatic: u2 index
			if pc+3 > len(insns) {
				return nil, nil, fmt.Errorf("truncated invoke at pc %d", pc)
			}
			// A well-formed invoke site always resolves; an unresolvable methodref
			// (corrupt/mis-tagged constant pool) means malformed bytecode. Surface it
			// as a parse error — LoadJar records it as a Failed entry (a Gap), so the
			// caller withholds not_exploitable rather than silently dropping the edge
			// and hiding the path it would have carried (inv.5).
			ref, ok := resolveMethodRef(cp, binary.BigEndian.Uint16(insns[pc+1:]))
			if !ok {
				return nil, nil, fmt.Errorf("unresolvable methodref for invoke at pc %d: malformed constant pool", pc)
			}
			edges = append(edges, Edge{To: ref, Kind: invokeKind(op)})
			if op == 0xB8 { // invokestatic triggers the target class's <clinit>
				trigger(ref.Owner)
			}
			pc += 3
		case 0xB2, 0xB3: // getstatic, putstatic: u2 fieldref index — triggers the field's class <clinit>
			if pc+3 > len(insns) {
				return nil, nil, fmt.Errorf("truncated static field access at pc %d", pc)
			}
			trigger(cp.fieldOwner(binary.BigEndian.Uint16(insns[pc+1:])))
			pc += 3
		case 0xBB: // new: u2 class index — triggers the instantiated class's <clinit>
			if pc+3 > len(insns) {
				return nil, nil, fmt.Errorf("truncated new at pc %d", pc)
			}
			trigger(cp.className(binary.BigEndian.Uint16(insns[pc+1:])))
			pc += 3
		case 0xB9: // invokeinterface: u2 index, u1 count, u1 0
			if pc+5 > len(insns) {
				return nil, nil, fmt.Errorf("truncated invokeinterface at pc %d", pc)
			}
			ref, ok := resolveMethodRef(cp, binary.BigEndian.Uint16(insns[pc+1:]))
			if !ok {
				return nil, nil, fmt.Errorf("unresolvable methodref for invokeinterface at pc %d: malformed constant pool", pc)
			}
			edges = append(edges, Edge{To: ref, Kind: EdgeInterface})
			pc += 5
		case 0xBA: // invokedynamic: u2 index, u2 0
			if pc+5 > len(insns) {
				return nil, nil, fmt.Errorf("truncated invokedynamic at pc %d", pc)
			}
			// A well-formed invokedynamic always resolves (to owner "" — a hazard the
			// engine handles); an unresolvable one is a corrupt constant pool, surfaced
			// as a Gap rather than a silently omitted hazard edge.
			ref, ok := resolveMethodRef(cp, binary.BigEndian.Uint16(insns[pc+1:]))
			if !ok {
				return nil, nil, fmt.Errorf("unresolvable methodref for invokedynamic at pc %d: malformed constant pool", pc)
			}
			edges = append(edges, Edge{To: ref, Kind: EdgeDynamic})
			pc += 5
		case 0xAA: // tableswitch: pad to 4-byte boundary, default(4) low(4) high(4), (high-low+1) jumps(4)
			pc++
			for pc%4 != 0 {
				pc++
			}
			if pc+12 > len(insns) {
				return nil, nil, fmt.Errorf("truncated tableswitch at pc %d", pc)
			}
			pc += 4 // default
			low := int32(binary.BigEndian.Uint32(insns[pc:]))
			pc += 4
			high := int32(binary.BigEndian.Uint32(insns[pc:]))
			pc += 4
			if high < low {
				return nil, nil, fmt.Errorf("tableswitch high %d < low %d", high, low)
			}
			n := int(high-low) + 1
			pc += 4 * n
		case 0xAB: // lookupswitch: pad, default(4), npairs(4), pairs(8*npairs)
			pc++
			for pc%4 != 0 {
				pc++
			}
			if pc+8 > len(insns) {
				return nil, nil, fmt.Errorf("truncated lookupswitch at pc %d", pc)
			}
			pc += 4 // default
			npairs := int(binary.BigEndian.Uint32(insns[pc:]))
			pc += 4
			if npairs < 0 {
				return nil, nil, fmt.Errorf("lookupswitch npairs %d < 0", npairs)
			}
			pc += 8 * npairs
		case 0xC4: // wide: modifies the following instruction's operand width
			if pc+2 > len(insns) {
				return nil, nil, fmt.Errorf("truncated wide at pc %d", pc)
			}
			if insns[pc+1] == 0x84 { // iinc: wide gives u2 index, u2 const
				pc += 6
			} else { // wide <load/store>: u2 index
				pc += 4
			}
		default:
			pc += 1 + operandLen[op]
		}
	}
	return edges, initTriggers, nil
}

func invokeKind(op byte) EdgeKind {
	switch op {
	case 0xB8:
		return EdgeStatic
	case 0xB7:
		return EdgeSpecial
	default:
		return EdgeVirtual
	}
}

// operandLen[op] = number of operand bytes for fixed-length opcodes (JVMS §6). The
// variable-length opcodes tableswitch/lookupswitch/wide (0xAA/0xAB/0xC4) are handled
// in parseCode; their entries here are unused.
var operandLen = buildOperandLen()

func buildOperandLen() [256]int {
	var t [256]int
	two := []byte{ // 2-byte operand
		0x11,       // sipush
		0x13, 0x14, // ldc_w, ldc2_w
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, // if<cond>
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, // if_icmp<cond>, if_acmp<cond>
		0xa7, 0xa8, // goto, jsr
		0xbb,       // new
		0xbd,       // anewarray
		0xc0, 0xc1, // checkcast, instanceof
		0xc6, 0xc7, // ifnull, ifnonnull
		0xb2, 0xb3, 0xb4, 0xb5, // getstatic, putstatic, getfield, putfield
	}
	for _, op := range two {
		t[op] = 2
	}
	one := []byte{ // 1-byte operand
		0x10,                         // bipush
		0x12,                         // ldc
		0x15, 0x16, 0x17, 0x18, 0x19, // iload, lload, fload, dload, aload
		0x36, 0x37, 0x38, 0x39, 0x3a, // istore, lstore, fstore, dstore, astore
		0xa9, // ret
		0xbc, // newarray
	}
	for _, op := range one {
		t[op] = 1
	}
	t[0x84] = 2 // iinc (non-wide): u1 index + s1 const. The wide form is handled in parseCode.
	t[0xc5] = 3 // multianewarray: u2 index + u1 dimensions
	t[0xc8] = 4 // goto_w
	t[0xc9] = 4 // jsr_w
	return t
}
