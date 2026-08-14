package assembly

// il.go — method-body decode + IL instruction-walk.
//
// This is the .NET analog of cobalt's classfile/bytecode.go. The IL stream is
// walked as an INSTRUCTION STREAM, never a byte scan: each step advances by
// 1 (or 2 for a 0xFE-prefixed opcode) + the operand length. A single miscount
// desyncs the cursor and every subsequent byte is read as a phantom opcode —
// the IL analog of 02a's coded-index-width trap — so the operand-length tables
// below are the load-bearing correctness surface. See walkIL.

import (
	"encoding/binary"
	"fmt"
)

// EdgeKind classifies a call-site edge by the IL instruction that produced it.
type EdgeKind int

const (
	EdgeCall      EdgeKind = iota // call 0x28 — direct, statically bound
	EdgeCallvirt                  // callvirt 0x6F — virtual/interface dispatch
	EdgeNewobj                    // newobj 0x73 — exact constructor
	EdgeLdftn                     // ldftn 0xFE06 — delegate target capture
	EdgeLdvirtftn                 // ldvirtftn 0xFE07 — virtual delegate target capture
	EdgeCalli                     // calli 0x29 — indirect (StandAloneSig), target unknown
	EdgeJmp                       // jmp 0x27 — tail-transfer to another method (hidden call → boundary)
)

func (k EdgeKind) String() string {
	switch k {
	case EdgeCall:
		return "call"
	case EdgeCallvirt:
		return "callvirt"
	case EdgeNewobj:
		return "newobj"
	case EdgeLdftn:
		return "ldftn"
	case EdgeLdvirtftn:
		return "ldvirtftn"
	case EdgeCalli:
		return "calli"
	case EdgeJmp:
		return "jmp"
	}
	return "?"
}

// Edge is one call site collected from an IL body. Token is the raw operand:
// a MethodDef/MemberRef/MethodSpec token for call/callvirt/newobj/ldftn, or a
// StandAloneSig token for calli. Constrained carries the `constrained.` prefix
// type token into the following callvirt (caveat 3 — value-type static resolution);
// it is null otherwise. Offset is the IL offset of the instruction (stable order,
// diagnostics). Resolution to a target is chagraph.go's job — the walk never drops
// a site, it records the token and lets CHA decide.
type Edge struct {
	Kind        EdgeKind
	Token       Token
	Constrained Token // constrained.-prefix type token pinned to a callvirt; null otherwise
	Tail        bool  // tail.-prefixed call
	Offset      int
}

// InitTriggerKind names why a site forces a type initializer (.cctor) to run.
type InitTriggerKind int

const (
	InitNewobj      InitTriggerKind = iota // newobj — constructs an instance of the type
	InitStaticField                        // ldsfld/stsfld — touches a static field of the type
	InitStaticCall                         // static call — invokes a static method of the type
)

// InitTrigger records a .cctor-forcing site for barrier-2's type-init channel.
// Token names the method (newobj/static call) or field (ldsfld/stsfld) whose
// DECLARING type is initialized. The IL walk only RECORDS these; walking the
// type-init closure (base-type chain, ECMA-335 §II.10.5.3) is barrier-2.
type InitTrigger struct {
	Kind   InitTriggerKind
	Token  Token
	Offset int
}

// MethodBody is the decoded result of one method's IL: its call-site edges and
// its recorded type-init triggers.
type MethodBody struct {
	Method       *MethodDef
	Edges        []Edge
	InitTriggers []InitTrigger
}

// ilBody decodes a method-body header at the method's RVA and returns the raw IL
// code region (post-header). It handles the tiny (0x2: 1-byte header, code size in
// the top 6 bits) and fat (0x3: 12-byte header, CodeSize at offset 4) formats
// (ECMA-335 §II.25.4). Every read is bounds-checked through the reader — a
// truncated or malformed body returns an error, never a panic. A method with no
// managed body (RVA 0, or a native/runtime ImplFlag) is an error the caller skips.
func (a *Assembly) ilBody(m *MethodDef) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("il: nil method")
	}
	if m.RVA == 0 {
		return nil, fmt.Errorf("il: method %q has no managed body (RVA 0)", m.Name)
	}
	// ImplFlags §II.23.1.11: CodeTypeMask 0x3 (0=IL, 1=Native, 3=Runtime); 0x4 = Unmanaged.
	if ct := m.ImplFlags & 0x3; ct != 0 {
		return nil, fmt.Errorf("il: method %q is not IL (ImplFlags 0x%x)", m.Name, m.ImplFlags)
	}
	if a.pe == nil {
		return nil, fmt.Errorf("il: no PE image retained")
	}
	off, err := a.pe.rvaToOffset(m.RVA)
	if err != nil {
		return nil, fmt.Errorf("il: method %q body RVA: %w", m.Name, err)
	}
	r := &reader{b: a.pe.data, pos: off}
	first := r.u1()
	if r.err != nil {
		return nil, r.err
	}
	switch first & 0x03 {
	case 0x02: // tiny: header is this one byte; code size is the top 6 bits.
		code := r.bytes(int(first >> 2))
		if r.err != nil {
			return nil, r.err
		}
		return code, nil
	case 0x03: // fat: 12-byte header; re-read from the top.
		r.seek(off)
		r.u2() // Flags | (Size<<12)
		r.u2() // MaxStack
		codeSize := r.u4()
		r.u4() // LocalVarSigTok
		if r.err != nil {
			return nil, r.err
		}
		code := r.bytes(int(codeSize))
		if r.err != nil {
			return nil, r.err
		}
		return code, nil
	default:
		return nil, fmt.Errorf("il: method %q unknown body format 0x%x", m.Name, first&0x03)
	}
}

// MethodBody decodes and walks a method's IL into its call-site edges and init
// triggers. A method with no IL body returns (nil, error) — the caller treats an
// abstract/native/runtime method as a boundary, not a walk failure.
func (a *Assembly) MethodBody(m *MethodDef) (*MethodBody, error) {
	code, err := a.ilBody(m)
	if err != nil {
		return nil, err
	}
	edges, triggers, err := a.walkIL(code)
	if err != nil {
		return nil, fmt.Errorf("il: method %q: %w", m.Name, err)
	}
	return &MethodBody{Method: m, Edges: edges, InitTriggers: triggers}, nil
}

// tok reads a 4-byte metadata token operand at position p; the caller has already
// bounds-checked p+4 <= len(code).
func tok(code []byte, p int) Token { return Token(binary.LittleEndian.Uint32(code[p:])) }

// walkIL is the instruction-walk. It advances the cursor by the exact instruction
// length at every step — the desync defense — and collects one Edge per call site
// plus the type-init triggers. A truncated instruction (an operand running past the
// end of the code region) is an error, never a panic or a phantom edge.
//
// Prefix instructions (`constrained.` 0xFE16, `tail.` 0xFE14, `volatile.` 0xFE13,
// `unaligned.` 0xFE12, `no.` 0xFE19, `readonly.` 0xFE1E) modify the FOLLOWING
// instruction: the loop carries the pending `constrained.` type token and `tail.`
// flag into the next opcode and clears them once a non-prefix instruction consumes
// them. Getting `constrained.` onto the callvirt is caveat 3 (value-type static
// dispatch); dropping it over-approximates or, worse, mis-resolves.
func (a *Assembly) walkIL(code []byte) (edges []Edge, triggers []InitTrigger, err error) {
	pc := 0
	var pendingConstrained Token
	var pendingTail bool
	clear := func() { pendingConstrained = 0; pendingTail = false }

	// need reports whether n operand bytes are available after the opcode at `at`.
	need := func(op string, at, n int) bool {
		if at+n > len(code) {
			err = fmt.Errorf("il: truncated %s operand at offset %d (need %d, have %d)", op, pc, n, len(code)-at)
			return false
		}
		return true
	}

	for pc < len(code) {
		op := code[pc]

		if op == 0xFE { // two-byte opcode
			if pc+1 >= len(code) {
				return nil, nil, fmt.Errorf("il: truncated 0xFE two-byte opcode at offset %d", pc)
			}
			op2 := code[pc+1]
			switch op2 {
			case 0x06, 0x07: // ldftn / ldvirtftn — 4-byte method token (delegate target capture)
				if !need("ldftn", pc+2, 4) {
					return nil, nil, err
				}
				kind := EdgeLdftn
				if op2 == 0x07 {
					kind = EdgeLdvirtftn
				}
				edges = append(edges, Edge{Kind: kind, Token: tok(code, pc+2), Offset: pc})
				pc += 6
				clear()
			case 0x16: // constrained. — 4-byte type token PREFIX; carry to the next callvirt
				if !need("constrained.", pc+2, 4) {
					return nil, nil, err
				}
				pendingConstrained = tok(code, pc+2)
				pc += 6
				// prefix: do NOT clear pending state
			case 0x14: // tail. PREFIX (no operand)
				pendingTail = true
				pc += 2
			case 0x13, 0x1E: // volatile. / readonly. PREFIX (no operand)
				pc += 2
			case 0x12, 0x19: // unaligned. / no. PREFIX — 1-byte operand
				if !need("prefix", pc+2, 1) {
					return nil, nil, err
				}
				pc += 3
			default:
				n := twoByteOperandLen[op2]
				if !need("0xFE opcode", pc+2, n) {
					return nil, nil, err
				}
				pc += 2 + n
				clear()
			}
			continue
		}

		switch op {
		case 0x28: // call — direct call
			if !need("call", pc+1, 4) {
				return nil, nil, err
			}
			t := tok(code, pc+1)
			edges = append(edges, Edge{Kind: EdgeCall, Token: t, Tail: pendingTail, Offset: pc})
			if a.isStaticTarget(t) {
				triggers = append(triggers, InitTrigger{Kind: InitStaticCall, Token: t, Offset: pc})
			}
			pc += 5
			clear()
		case 0x6F: // callvirt — virtual/interface dispatch
			if !need("callvirt", pc+1, 4) {
				return nil, nil, err
			}
			edges = append(edges, Edge{Kind: EdgeCallvirt, Token: tok(code, pc+1), Constrained: pendingConstrained, Tail: pendingTail, Offset: pc})
			pc += 5
			clear()
		case 0x73: // newobj — exact constructor (also delegate construction)
			if !need("newobj", pc+1, 4) {
				return nil, nil, err
			}
			t := tok(code, pc+1)
			edges = append(edges, Edge{Kind: EdgeNewobj, Token: t, Offset: pc})
			triggers = append(triggers, InitTrigger{Kind: InitNewobj, Token: t, Offset: pc})
			pc += 5
			clear()
		case 0x29: // calli — indirect call through a StandAloneSig; target unknown
			if !need("calli", pc+1, 4) {
				return nil, nil, err
			}
			edges = append(edges, Edge{Kind: EdgeCalli, Token: tok(code, pc+1), Offset: pc})
			pc += 5
			clear()
		case 0x27: // jmp — 4-byte method token; tail-transfers out of this method (a hidden
			// call in the obfuscation threat model). Collected as an EdgeJmp so CHA resolves
			// it to a declared boundary, never a silently dropped edge (FIX 2).
			if !need("jmp", pc+1, 4) {
				return nil, nil, err
			}
			edges = append(edges, Edge{Kind: EdgeJmp, Token: tok(code, pc+1), Offset: pc})
			pc += 5
			clear()
		case 0x7E, 0x80: // ldsfld / stsfld — static-field access triggers the field's type .cctor
			if !need("static field", pc+1, 4) {
				return nil, nil, err
			}
			triggers = append(triggers, InitTrigger{Kind: InitStaticField, Token: tok(code, pc+1), Offset: pc})
			pc += 5
			clear()
		case 0x45: // switch — variable length: uint32 N followed by N int32 targets
			if !need("switch", pc+1, 4) {
				return nil, nil, err
			}
			n := binary.LittleEndian.Uint32(code[pc+1:])
			// Guard the multiply against overflow before extending the cursor.
			if uint64(n) > uint64(len(code)) {
				return nil, nil, fmt.Errorf("il: switch count %d overflows code region (%d bytes) at offset %d", n, len(code), pc)
			}
			body := 4 + 4*int(n)
			if !need("switch", pc+1, body) {
				return nil, nil, err
			}
			pc += 1 + body
			clear()
		default:
			n := operandLen[op]
			if !need("opcode", pc+1, n) {
				return nil, nil, err
			}
			pc += 1 + n
			clear()
		}
	}
	return edges, triggers, nil
}

// isStaticTarget reports whether a call target is a static method (no `this`), so
// the site is recorded as a .cctor init trigger. A MethodDef carries the Static
// attribute; a MemberRef is static when its signature blob lacks the HASTHIS bit
// (0x20, ECMA-335 §II.23.2.1). A MethodSpec resolves to its open method. Unknown or
// out-of-set targets are conservatively NOT trigger-recorded here (barrier-2 owns
// the closure); the edge itself is never dropped.
func (a *Assembly) isStaticTarget(t Token) bool {
	switch t.Table() {
	case tMethodDef:
		if m := a.MethodByRID(t.RID()); m != nil {
			return m.Flags&0x10 != 0 // MethodAttributes.Static
		}
	case tMemberRef:
		if mr := a.MemberRef(t.RID()); mr != nil && len(mr.SigBlob) > 0 {
			return mr.SigBlob[0]&0x20 == 0 // no HASTHIS => static
		}
	case tMethodSpec:
		if int(t.RID()) < len(a.MethodSpecs) {
			return a.isStaticTarget(a.MethodSpecs[t.RID()].Method)
		}
	}
	return false
}

// operandLen[op] is the fixed operand-byte count for single-byte IL opcodes
// (ECMA-335 §III opcode encodings). The variable-length switch (0x45) and the
// call-family opcodes are handled explicitly in walkIL; unused opcode slots and
// all InlineNone opcodes are 0. Getting one of these wrong desyncs the walk.
var operandLen = buildOperandLen()

func buildOperandLen() [256]int {
	var t [256]int
	// 1-byte operand: short-form vars, short branches, ldc.i4.s.
	for _, op := range []byte{
		0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, // ldarg.s..stloc.s
		0x1F,                                                             // ldc.i4.s
		0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, // br.s..blt.un.s
		0x36, 0x37,
		0xDE, // leave.s
	} {
		t[op] = 1
	}
	// 2-byte operand: none in the single-byte space (ldarg/ldloc long forms are 0xFE-prefixed).
	// 4-byte operand: ldc.i4, ldc.r4, branches, tokens (field/type/string/ldtoken).
	// jmp (0x27), like the call family (call/callvirt/newobj/calli), is handled
	// explicitly in walkIL — it emits an edge — so it is NOT in this fallthrough table.
	for _, op := range []byte{
		0x20, 0x22, // ldc.i4, ldc.r4
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, // br..bgt.un
		0x43, 0x44,
		0x70, 0x71, 0x72, // cpobj, ldobj, ldstr
		0x74, 0x75, // castclass, isinst
		0x79,             // unbox
		0x7B, 0x7C, 0x7D, // ldfld, ldflda, stfld
		0x7F,             // ldsflda
		0x81,             // stobj
		0x8C, 0x8D, 0x8F, // box, newarr, ldelema
		0xA3, 0xA4, 0xA5, // ldelem, stelem, unbox.any
		0xC2, 0xC6, // refanyval, mkrefany
		0xD0, // ldtoken
		0xDD, // leave
	} {
		t[op] = 4
	}
	// 8-byte operand: ldc.i8, ldc.r8.
	t[0x21] = 8
	t[0x23] = 8
	return t
}

// twoByteOperandLen[op2] is the operand-byte count for 0xFE-prefixed opcodes.
// The call-family (ldftn/ldvirtftn) and every prefix are handled explicitly in
// walkIL; this table covers the rest so the fallthrough advances correctly.
var twoByteOperandLen = buildTwoByteOperandLen()

func buildTwoByteOperandLen() [256]int {
	var t [256]int
	for _, op := range []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E} { // ldarg..stloc (InlineVar, 2 bytes)
		t[op] = 2
	}
	for _, op := range []byte{0x15, 0x1C} { // initobj, sizeof (InlineType token, 4 bytes)
		t[op] = 4
	}
	return t
}
