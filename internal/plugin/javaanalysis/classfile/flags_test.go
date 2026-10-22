package classfile

import "testing"

// TestParseClass_DecodesAccessFlags: class Abstract/Public and method Static/Private/Public
// come from the access_flags words (JVMS §4.1, §4.6).
func TestParseClass_DecodesAccessFlags(t *testing.T) {
	tests := []struct {
		name                     string
		classAcc, methodAcc      uint16
		wantAbstract, wantPublic bool
		wantMethod               [3]bool // Static, Private, Public
	}{
		{"public concrete class, public method", 0x0021, 0x0001, false, true, [3]bool{false, false, true}},
		{"package-private abstract class", 0x0420, 0x0000, true, false, [3]bool{false, false, false}},
		{"interface", 0x0601, 0x0009, true, true, [3]bool{true, false, true}},
		{"interface without ACC_ABSTRACT, private static method", 0x0201, 0x000A, true, true, [3]bool{true, true, false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newClassBuilder()
			raw := b.build("com/example/C", "java/lang/Object", "m", "()V", []byte{0xB1})
			off := 10 // magic, minor, major, constant_pool_count
			for _, e := range b.entries {
				off += len(e)
			}
			copy(raw[off:], be2(tt.classAcc))
			copy(raw[off+12:], be2(tt.methodAcc)) // past access, this, super, interfaces, fields, methods counts
			got, err := ParseClass(raw)
			if err != nil {
				t.Fatalf("ParseClass: %v", err)
			}
			if got.Abstract != tt.wantAbstract || got.Public != tt.wantPublic {
				t.Errorf("class (Abstract, Public) = (%v, %v), want (%v, %v)", got.Abstract, got.Public, tt.wantAbstract, tt.wantPublic)
			}
			m := got.Methods[0]
			if f := [3]bool{m.Static, m.Private, m.Public}; f != tt.wantMethod {
				t.Errorf("method (Static, Private, Public) = %v, want %v", f, tt.wantMethod)
			}
		})
	}
}
