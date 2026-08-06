// Package main is a self-contained live-test fixture: it CALLS a known
// vulnerable golang.org/x/text symbol (language.Parse, advisory GO-2021-0113,
// "out-of-bounds read in golang.org/x/text/language", fixed in v0.3.7) so a real
// govulncheck run produces a reachable, symbol-level finding with a call trace
// main -> Trigger -> language.Parse. The dependency is pinned at v0.3.0 (the
// vulnerable version) and vendored, so module loading is offline; only the vuln
// database lookup needs the network.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

// Trigger reaches the vulnerable language.Parse symbol.
func Trigger(tag string) {
	t, _ := language.Parse(tag)
	fmt.Println(t)
}

func main() { Trigger("en-US") }
