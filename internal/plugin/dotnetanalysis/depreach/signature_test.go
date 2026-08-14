package depreach

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

func mkTok(table, rid uint32) assembly.Token { return assembly.Token(table<<24 | rid) }

// fakeResolver is a hand-authored TypeResolver so signature decoding is exercised with
// no real assembly (hermetic, byte-synthesis only).
type fakeResolver map[assembly.Token]assembly.TypeRef

func (f fakeResolver) TypeRefFor(tok assembly.Token) assembly.TypeRef { return f[tok] }

const (
	tblTypeRef = 0x01
)

func TestDecodeMethodSig_SimpleRefAndPrimitive(t *testing.T) {
	// void M(string, int) — DEFAULT cc, 2 params, VOID ret, STRING, I4.
	blob := []byte{0x00, 0x02, 0x01, 0x0E, 0x08}
	sig, err := DecodeMethodSig(blob, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := sig.SignatureKey(), "default|void|string,i4"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	// Only the reference-type parameter (string) is surfaced; the int is ignored.
	if len(sig.RefParams) != 1 || sig.RefParams[0].Name != "System.String" {
		t.Fatalf("ref-params = %+v, want [System.String]", sig.RefParams)
	}
}

func TestDecodeMethodSig_GenericInstRefParam(t *testing.T) {
	// T M<T>(IList<T>, int): GENERIC cc, GenParamCount 1, 2 params,
	// ret MVAR 0, param1 GENERICINST CLASS IList`1<MVAR 0>, param2 I4.
	ilist := mkTok(tblTypeRef, 5) // decodeTypeDefOrRef(0x15) -> TypeRef rid 5
	res := fakeResolver{ilist: {Namespace: "System.Collections.Generic", Name: "IList`1", Token: ilist}}
	blob := []byte{
		0x10,       // GENERIC calling convention
		0x01,       // GenParamCount = 1
		0x02,       // ParamCount = 2
		0x1E, 0x00, // ret: MVAR 0
		0x15, 0x12, 0x15, 0x01, 0x1E, 0x00, // param1: GENERICINST CLASS <coded 0x15> argc 1 (MVAR 0)
		0x08, // param2: I4
	}
	sig, err := DecodeMethodSig(blob, res)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sig.GenParamCount != 1 {
		t.Fatalf("genArity = %d, want 1", sig.GenParamCount)
	}
	// SignatureKey is by-signature: generic arity + GENERICINST param encoded exactly.
	const wantKey = "default+g1|!!0|class:System.Collections.Generic.IList`1<!!0>,i4"
	if got := sig.SignatureKey(); got != wantKey {
		t.Fatalf("key = %q, want %q", got, wantKey)
	}
	// The GENERICINST-of-CLASS param is the reference param; MVAR return + I4 ignored.
	if len(sig.RefParams) != 1 || sig.RefParams[0].Name != "System.Collections.Generic.IList`1" {
		t.Fatalf("ref-params = %+v, want [IList`1]", sig.RefParams)
	}
	if sig.RefParams[0].Ref.Token != ilist {
		t.Fatalf("ref-param token = %v, want %v (resolved via assembly)", sig.RefParams[0].Ref.Token, ilist)
	}
}

func TestDecodeMethodSig_ArrayRefElement(t *testing.T) {
	// void M(Foo[]): DEFAULT, 1 param, VOID ret, SZARRAY CLASS Foo.
	foo := mkTok(tblTypeRef, 8) // decodeTypeDefOrRef(0x21) -> TypeRef rid 8
	res := fakeResolver{foo: {Namespace: "MyApp", Name: "Foo", Token: foo}}
	blob := []byte{0x00, 0x01, 0x01, 0x1D, 0x12, 0x21}
	sig, err := DecodeMethodSig(blob, res)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := sig.SignatureKey(), "default|void|class:MyApp.Foo[]"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	// The array element type (Foo) is surfaced as the reference param.
	if len(sig.RefParams) != 1 || sig.RefParams[0].Name != "MyApp.Foo" {
		t.Fatalf("ref-params = %+v, want [MyApp.Foo]", sig.RefParams)
	}
}

func TestSignatureKey_BySignatureNotName(t *testing.T) {
	// The blob carries no method name: two decodes of the same signature bytes key
	// identically, and a different parameter type keys differently.
	a, _ := DecodeMethodSig([]byte{0x00, 0x01, 0x01, 0x0E}, nil) // void M(string)
	b, _ := DecodeMethodSig([]byte{0x00, 0x01, 0x01, 0x0E}, nil) // void N(string)
	if a.SignatureKey() != b.SignatureKey() {
		t.Fatalf("same signature keyed differently: %q vs %q", a.SignatureKey(), b.SignatureKey())
	}
	c, _ := DecodeMethodSig([]byte{0x00, 0x01, 0x01, 0x08}, nil) // void M(int)
	if a.SignatureKey() == c.SignatureKey() {
		t.Fatalf("distinct signatures collided on key %q", a.SignatureKey())
	}
}

func TestReadCompressedUint_WidthForms(t *testing.T) {
	cases := []struct {
		bytes []byte
		want  uint32
		n     int
	}{
		{[]byte{0x03}, 3, 1},                            // 1-byte
		{[]byte{0x7F}, 127, 1},                          // 1-byte max
		{[]byte{0x80, 0x80}, 128, 2},                    // 2-byte min
		{[]byte{0xBF, 0xFF}, 16383, 2},                  // 2-byte max
		{[]byte{0xC0, 0x00, 0x40, 0x00}, 16384, 4},      // 4-byte min
		{[]byte{0xDF, 0xFF, 0xFF, 0xFF}, 0x1FFFFFFF, 4}, // 4-byte max
	}
	for _, c := range cases {
		got, n, err := ReadCompressedUint(c.bytes)
		if err != nil {
			t.Fatalf("%x: %v", c.bytes, err)
		}
		if got != c.want || n != c.n {
			t.Fatalf("%x -> (%d, %d), want (%d, %d)", c.bytes, got, n, c.want, c.n)
		}
	}
}

func TestDecodeMethodSig_TruncatedIsHazardNotPanic(t *testing.T) {
	// DEFAULT, ParamCount 3, VOID ret, then a CLASS whose token bytes are missing.
	blob := []byte{0x00, 0x03, 0x01, 0x12}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decode panicked on truncated blob: %v", r)
		}
	}()
	sig, err := DecodeMethodSig(blob, nil)
	if err == nil {
		t.Fatalf("truncated blob: want error, got nil (confident empty is unsound)")
	}
	if !sig.Malformed {
		t.Fatalf("truncated blob: Malformed must be set so the engine treats it as a hazard")
	}
}

func TestDecodeMethodSig_EmptyBlob(t *testing.T) {
	sig, err := DecodeMethodSig(nil, nil)
	if err == nil || !sig.Malformed {
		t.Fatalf("empty blob: want error + Malformed, got err=%v malformed=%v", err, sig.Malformed)
	}
}
