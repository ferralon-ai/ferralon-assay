package javaanalysis

import (
	"strings"
	"testing"
)

// TestParseAnnotation_RecoversStringValues is the direct unit guard for the
// raw-source annotation-value pass: with the raw runes supplied, parseAnnotation
// recovers the first string element value inside the argument group (route path,
// @Qualifier value, @Value expression), and returns "" when there is no string or
// when raw is nil (the declaration-scan behavior, preserved).
func TestParseAnnotation_RecoversStringValues(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"request mapping positional", `@RequestMapping("/x")`, "/x"},
		{"qualifier", `@Qualifier("foo")`, "foo"},
		{"get mapping named value first", `@GetMapping(value = "/users", produces = "application/json")`, "/users"},
		{"get mapping method enum then path", `@RequestMapping(method = RequestMethod.GET, path = "/orders")`, "/orders"},
		{"value expression", `@Value("${app.url}")`, "${app.url}"},
		{"spel value", `@Value("#{systemProperties['x']}")`, "#{systemProperties['x']}"},
		{"no string element", `@Scheduled(fixedRate = 60000)`, ""},
		{"marker annotation", `@Override`, ""},
		{"escaped quote in value", `@Query("SELECT \"a\"")`, `SELECT "a"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := []rune(tc.src)
			clean := []rune(stripJava(tc.src))
			at := strings.IndexByte(tc.src, '@')
			_, sel, _ := parseAnnotation(clean, raw, at)
			if sel != tc.want {
				t.Errorf("selector = %q, want %q", sel, tc.want)
			}
			// raw==nil (declaration-scan caller) must never recover a value.
			if _, selNil, _ := parseAnnotation(clean, nil, at); selNil != "" {
				t.Errorf("raw==nil selector = %q, want \"\" (decl-scan behavior)", selNil)
			}
		})
	}
}

// TestParseFile_RouteSelectorRecovered proves the value flows end-to-end: a
// @GetMapping("/users") on a controller method now yields ingress selector "/users"
// (previously "", because stripJava blanked the literal before parseAnnotation).
func TestParseFile_RouteSelectorRecovered(t *testing.T) {
	src := `package com.example;
class UserController {
  @GetMapping("/users")
  public String list() {
    return repo.findAll();
  }
}`
	res := parseFile(src)
	var got string
	found := false
	for _, in := range res.ingresses {
		if in.name == "list" && in.kind == "http_route" {
			got = in.selector
			found = true
		}
	}
	if !found {
		t.Fatalf("no http_route ingress for list(); ingresses=%+v", res.ingresses)
	}
	if got != "/users" {
		t.Errorf("route selector = %q, want /users", got)
	}
}

// TestGeneralStringBlankingUnchanged proves the recovery is scoped to annotation
// context: a string literal that is NOT an annotation argument is still blanked by
// stripJava (its content never reaches the scanner), and a '@GetMapping("/evil")'
// embedded inside a plain string literal is inert — no phantom ingress is produced.
func TestGeneralStringBlankingUnchanged(t *testing.T) {
	// (c) direct: a plain string literal's content is still whitespace in clean.
	clean := stripJava(`log("secret-value")`)
	if strings.Contains(clean, "secret") {
		t.Errorf("non-annotation string literal was not blanked: %q", clean)
	}

	// A string literal that LOOKS like an annotation must not be parsed as one.
	src := `package com.example;
class C {
  void m() {
    String s = "@GetMapping(\"/evil\")";
    log("plain");
  }
}`
	res := parseFile(src)
	for _, in := range res.ingresses {
		if in.selector == "/evil" {
			t.Errorf("string-embedded annotation leaked into an ingress: %+v", in)
		}
	}
}
