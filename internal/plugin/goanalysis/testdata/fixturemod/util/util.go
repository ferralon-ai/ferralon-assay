// Package util holds the leaf Sink function the fixture call chain terminates in.
package util

import "strings"

// Sink is the leaf of the fixture call chain.
func Sink(s string) string {
	return strings.ToUpper(s)
}
