package plugin

import "testing"

func TestGoModuleFamily(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/golang-jwt/jwt":    "github.com/golang-jwt/jwt",
		"github.com/golang-jwt/jwt/v4": "github.com/golang-jwt/jwt",
		"github.com/golang-jwt/jwt/v5": "github.com/golang-jwt/jwt",
		"github.com/x/y/v10":           "github.com/x/y",
		"github.com/x/y/v1":            "github.com/x/y/v1",
		"github.com/x/y/v0":            "github.com/x/y/v0",
		"github.com/x/y/v2x":           "github.com/x/y/v2x",
		"github.com/x/v2/y":            "github.com/x/v2/y",
		"gopkg.in/yaml.v3":             "gopkg.in/yaml",
		"golang.org/x/net":             "golang.org/x/net",
	} {
		if got := GoModuleFamily(in); got != want {
			t.Errorf("GoModuleFamily(%q) = %q, want %q", in, got, want)
		}
	}
}
