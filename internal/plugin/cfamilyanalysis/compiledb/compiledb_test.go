package compiledb

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{"plain", "cc -c a.c", []string{"cc", "-c", "a.c"}, false},
		{"runs of whitespace", "  cc\t-c   a.c\n", []string{"cc", "-c", "a.c"}, false},
		{"double quotes", `cc "-DMSG=\"hi there\"" -c a.c`, []string{"cc", `-DMSG="hi there"`, "-c", "a.c"}, false},
		{"single quotes literal", `cc '-DP=\n' a.c`, []string{"cc", `-DP=\n`, "a.c"}, false},
		{"backslash space", `cc -I/my\ dir a.c`, []string{"cc", "-I/my dir", "a.c"}, false},
		{"backslash kept in double quotes", `cc "-DX=a\b" a.c`, []string{"cc", `-DX=a\b`, "a.c"}, false},
		{"empty quoted word", `cc "" a.c`, []string{"cc", "", "a.c"}, false},
		{"unterminated", `cc "-DX a.c`, nil, true},
		{"trailing backslash", `cc a.c \`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SplitCommand(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseEntry covers both entry forms and each per-TU field. Every case is one database entry
// whose directory is /w; the database itself lives in /db.
func TestParseEntry(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  TU
		skip  string // a Skip* reason when the entry must not become a TU
	}{
		{
			name:  "command form, cmake shape",
			entry: `{"directory":"/w/build","command":"/usr/bin/cc   -std=gnu17 -arch arm64 -o a.o -c /w/a.c","file":"/w/a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w/build", Lang: LangC, Std: "gnu17", Compiler: Compiler{Driver: "/usr/bin/cc"}},
		},
		{
			name:  "arguments form",
			entry: `{"directory":"/w","arguments":["clang","-std=c11","--target=aarch64-linux-gnu","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Std: "c11", Target: "aarch64-linux-gnu", Compiler: Compiler{Driver: "clang", Family: "clang"}},
		},
		{
			name:  "arguments preferred over command",
			entry: `{"directory":"/w","arguments":["g++","-std=c++20","-c","b.cpp"],"command":"cc -std=c89 -c b.cpp","file":"b.cpp"}`,
			want:  TU{File: "/w/b.cpp", Directory: "/w", Lang: LangCXX, Std: "c++20", Compiler: Compiler{Driver: "g++", Family: "gcc"}},
		},
		{
			name:  "relative directory resolves against the database dir",
			entry: `{"directory":"out","arguments":["cc","-c","../src/a.c"],"file":"../src/a.c"}`,
			want:  TU{File: "/db/src/a.c", Directory: "/db/out", Lang: LangC, Compiler: Compiler{Driver: "cc"}},
		},
		{
			name:  "C++ driver compiles .c as C++",
			entry: `{"directory":"/w","arguments":["clang++-17","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangCXX, Compiler: Compiler{Driver: "clang++-17", Family: "clang"}},
		},
		{
			name:  "C++ driver compiles preprocessed .i as C++",
			entry: `{"directory":"/w","arguments":["g++","-c","a.i"],"file":"a.i"}`,
			want:  TU{File: "/w/a.i", Directory: "/w", Lang: LangCXX, Compiler: Compiler{Driver: "g++", Family: "gcc"}},
		},
		{
			name:  "C driver leaves preprocessed .i as C",
			entry: `{"directory":"/w","arguments":["gcc","-c","a.i"],"file":"a.i"}`,
			want:  TU{File: "/w/a.i", Directory: "/w", Lang: LangC, Compiler: Compiler{Driver: "gcc", Family: "gcc"}},
		},
		{
			name:  "explicit -x beats extension",
			entry: `{"directory":"/w","arguments":["gcc","-x","c++","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangCXX, Compiler: Compiler{Driver: "gcc", Family: "gcc"}},
		},
		{
			name:  "-x after the source does not apply to it",
			entry: `{"directory":"/w","arguments":["gcc","-c","a.c","-xc++"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Compiler: Compiler{Driver: "gcc", Family: "gcc"}},
		},
		{
			name:  "cross-compiler driver carries the triple",
			entry: `{"directory":"/w","arguments":["/opt/x/bin/arm-none-eabi-gcc-12.2","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Target: "arm-none-eabi", Compiler: Compiler{Driver: "/opt/x/bin/arm-none-eabi-gcc-12.2", Family: "gcc"}},
		},
		{
			name:  "explicit target beats driver triple",
			entry: `{"directory":"/w","arguments":["aarch64-linux-gnu-gcc","-target","x86_64-linux-gnu","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Target: "x86_64-linux-gnu", Compiler: Compiler{Driver: "aarch64-linux-gnu-gcc", Family: "gcc"}},
		},
		{
			name:  "hyphenated driver name does not fabricate a target",
			entry: `{"directory":"/w","arguments":["my-custom-gcc","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Compiler: Compiler{Driver: "my-custom-gcc", Family: "gcc"}},
		},
		{
			name:  "ccache wrapper is stripped and recorded",
			entry: `{"directory":"/w","arguments":["/usr/bin/ccache","g++","-std=gnu++17","-c","b.cc"],"file":"b.cc"}`,
			want:  TU{File: "/w/b.cc", Directory: "/w", Lang: LangCXX, Std: "gnu++17", Compiler: Compiler{Driver: "g++", Family: "gcc", Wrapper: "ccache"}},
		},
		{
			name:  "wrapper with no compiler is declared",
			entry: `{"directory":"/w","arguments":["distcc","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Compiler: Compiler{Wrapper: "distcc"}, Unhandled: []string{UnhandledWrapper}},
		},
		{
			name:  "response file is declared, visible flags still read",
			entry: `{"directory":"/w","arguments":["clang","@flags.rsp","-std=c17","-c","a.c"],"file":"a.c"}`,
			want:  TU{File: "/w/a.c", Directory: "/w", Lang: LangC, Std: "c17", Compiler: Compiler{Driver: "clang", Family: "clang"}, Unhandled: []string{UnhandledResponseFile}},
		},
		{
			name:  "msvc flags are declared, not parsed",
			entry: `{"directory":"C:/w","arguments":["cl.exe","/std:c++20","/TP","/c","a.c"],"file":"C:/w/a.c"}`,
			want:  TU{Lang: LangCXX, Compiler: Compiler{Driver: "cl.exe", Family: "msvc"}, Unhandled: []string{UnhandledMSVC}},
		},
		{name: "header entry is not a TU", entry: `{"directory":"/w","arguments":["cc","-c","a.h"],"file":"a.h"}`, skip: SkipHeader},
		{name: "-x c++-header is not a TU", entry: `{"directory":"/w","arguments":["clang++","-x","c++-header","pch.hpp"],"file":"pch.hpp"}`, skip: SkipHeader},
		{name: "assembly TU is declared", entry: `{"directory":"/w","arguments":["cc","-c","start.S"],"file":"start.S"}`, skip: SkipLang},
		{name: "objective-c TU is declared", entry: `{"directory":"/w","arguments":["clang","-x","objective-c","-c","m.m"],"file":"m.m"}`, skip: SkipLang},
		{name: "missing file", entry: `{"directory":"/w","arguments":["cc","-c","a.c"]}`, skip: SkipMalformed},
		{name: "no command", entry: `{"directory":"/w","file":"a.c"}`, skip: SkipMalformed},
		{name: "unparseable command", entry: `{"directory":"/w","command":"cc \"-c a.c","file":"a.c"}`, skip: SkipMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Parse([]byte("["+tt.entry+"]"), "/db/compile_commands.json")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tt.skip != "" {
				if len(db.TUs) != 0 || len(db.Skipped) != 1 || db.Skipped[0].Reason != tt.skip {
					t.Fatalf("want one skip %q, got TUs=%+v Skipped=%+v", tt.skip, db.TUs, db.Skipped)
				}
				return
			}
			if len(db.TUs) != 1 || len(db.Skipped) != 0 {
				t.Fatalf("want one TU, got TUs=%+v Skipped=%+v", db.TUs, db.Skipped)
			}
			got := db.TUs[0]
			if tt.want.File == "" { // platform-specific paths (the MSVC case): compare the rest
				got.File, got.Directory = "", ""
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseKeepsRawAndOrder(t *testing.T) {
	raw := []byte(`[
		{"directory":"/w","arguments":["cc","-c","a.c"],"file":"a.c"},
		{"directory":"/w","arguments":["cc","-c","a.h"],"file":"a.h"},
		{"directory":"/w","arguments":["c++","-c","b.cpp"],"file":"b.cpp"}
	]`)
	db, err := Parse(raw, "/w/compile_commands.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(db.Raw) != string(raw) {
		t.Fatal("Raw does not hold the bytes as read")
	}
	if len(db.TUs) != 2 || db.TUs[0].Lang != LangC || db.TUs[1].Lang != LangCXX {
		t.Fatalf("TUs = %+v", db.TUs)
	}
	if len(db.Skipped) != 1 || db.Skipped[0].Index != 1 || db.Skipped[0].Reason != SkipHeader {
		t.Fatalf("Skipped = %+v", db.Skipped)
	}
	if db.HasUnsupportedTU() || db.HasMalformedEntry() {
		t.Fatal("a header entry is neither an unsupported TU nor malformed")
	}
}

func TestParseMalformed(t *testing.T) {
	for _, raw := range []string{``, `{}`, `[1]`, `not json`} {
		if _, err := Parse([]byte(raw), "/w/compile_commands.json"); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q) err = %v, want ErrMalformed", raw, err)
		}
	}
}

func TestDiscover(t *testing.T) {
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("[]"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{"none", nil, nil},
		{"root first", []string{"b/compile_commands.json", "compile_commands.json"}, []string{"compile_commands.json", "b/compile_commands.json"}},
		{"build before other dirs", []string{"a/compile_commands.json", "build/compile_commands.json"}, []string{"build/compile_commands.json", "a/compile_commands.json"}},
		{"two levels down", []string{"out/debug/compile_commands.json"}, []string{"out/debug/compile_commands.json"}},
		{"three levels is too deep", []string{"a/b/c/compile_commands.json"}, nil},
		{"hidden and vendored trees skipped", []string{".cache/compile_commands.json", "third_party/z/compile_commands.json"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, f := range tt.files {
				write(t, filepath.Join(root, f))
			}
			var want []string
			for _, w := range tt.want {
				want = append(want, filepath.Join(root, w))
			}
			if got := Discover(root); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}
