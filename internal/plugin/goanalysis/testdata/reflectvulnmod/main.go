// Package main is a live-test fixture for a call only reflection makes: Tag.MarshalJSON reaches
// the vulnerable golang.org/x/text symbol language.Parse (GO-2021-0113), and nothing calls it but
// encoding/json, which finds the method through reflect when main marshals a Tag. The compiled
// program runs language.Parse; no static call edge leads to it.
package main

import (
	"encoding/json"
	"fmt"

	"golang.org/x/text/language"
)

// Tag marshals as its parsed language tag.
type Tag string

// MarshalJSON reaches the vulnerable language.Parse.
func (t Tag) MarshalJSON() ([]byte, error) {
	p, err := language.Parse(string(t))
	if err != nil {
		return nil, err
	}
	return json.Marshal(p.String())
}

func main() {
	out, _ := json.Marshal(Tag("en-US"))
	fmt.Println(string(out))
}
