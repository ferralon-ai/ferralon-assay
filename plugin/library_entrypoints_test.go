package plugin

import (
	"reflect"
	"testing"
)

func TestParseLibraryEntrypoints(t *testing.T) {
	cases := []struct {
		in      string
		want    LibraryEntrypoints
		str     string
		decl    bool
		wantErr bool
	}{
		{in: "", want: LibraryEntrypoints{Mode: LibraryEntrypointsAuto}, str: "auto"},
		{in: "auto", want: LibraryEntrypoints{Mode: LibraryEntrypointsAuto}, str: "auto"},
		{in: " none ", want: LibraryEntrypoints{Mode: LibraryEntrypointsNone}, str: "none", decl: true},
		{in: "pkg/api, ./pkg/client/...", want: LibraryEntrypoints{Mode: LibraryEntrypointsPaths, Include: []string{"pkg/api", "pkg/client"}}, str: "pkg/api,pkg/client", decl: true},
		{in: "!internal/tools\n!cmd", want: LibraryEntrypoints{Mode: LibraryEntrypointsAuto, Exclude: []string{"cmd", "internal/tools"}}, str: "!cmd,!internal/tools", decl: true},
		{in: "auto,cmd/x", want: LibraryEntrypoints{Mode: LibraryEntrypointsAuto, Include: []string{"cmd/x"}}, str: "auto,cmd/x", decl: true},
		{in: "pkg,!pkg/x,pkg", want: LibraryEntrypoints{Mode: LibraryEntrypointsPaths, Include: []string{"pkg"}, Exclude: []string{"pkg/x"}}, str: "pkg,!pkg/x", decl: true},
		{in: "./...", want: LibraryEntrypoints{Mode: LibraryEntrypointsPaths, Include: []string{"."}}, str: ".", decl: true},
		{in: "none,pkg", wantErr: true},
		{in: "none,!pkg", wantErr: true},
		{in: "auto,none", wantErr: true},
		{in: "../x", wantErr: true},
		{in: "pkg/../../x", wantErr: true},
		{in: "/abs", wantErr: true},
		{in: `pkg\x`, wantErr: true},
		{in: "!", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseLibraryEntrypoints(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parse = %+v, want %+v", got, tc.want)
			}
			if s := got.String(); s != tc.str {
				t.Errorf("String() = %q, want %q", s, tc.str)
			}
			if d := got.Declared(); d != tc.decl {
				t.Errorf("Declared() = %v, want %v", d, tc.decl)
			}
			again, err := ParseLibraryEntrypoints(got.String())
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Errorf("round trip = %+v, %v, want %+v", again, err, got)
			}
		})
	}
}

func TestUnder(t *testing.T) {
	cases := []struct {
		dir, p string
		want   bool
	}{
		{"pkg/api", "pkg", true},
		{"pkg", "pkg", true},
		{"pkgx", "pkg", false},
		{"pkg/api", "pkg/api/v2", false},
		{".", "pkg", false},
		{"anything", ".", true},
	}
	for _, tc := range cases {
		if got := Under(tc.dir, tc.p); got != tc.want {
			t.Errorf("Under(%q, %q) = %v, want %v", tc.dir, tc.p, got, tc.want)
		}
	}
}
