package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestNamesOtherPackage_GoPackagePaths(t *testing.T) {
	const (
		xnet   = "pkg:golang/golang.org/x/net"
		http2  = "pkg:golang/golang.org/x/net/http2"
		stdlib = "pkg:golang/stdlib"
		ctrd   = "pkg:golang/github.com/containerd/containerd"
		ctrdV2 = "pkg:golang/github.com/containerd/containerd/v2"
	)
	xnetKey := pkgKey{typ: "golang", name: "golang.org/x/net"}
	stdKey := pkgKey{typ: "golang", name: goStdlib}
	ctrdKey := pkgKey{typ: "golang", name: "github.com/containerd/containerd"}
	build := goModules{"golang.org/x/net": true, "golang.org/x/text": true}
	tests := []struct {
		name     string
		purls    []string
		admitted pkgKey
		mods     goModules
		want     bool
	}{
		{"package path under the module that holds it", []string{xnet, http2}, xnetKey, build, false},
		{"package path with no module list", []string{xnet, http2}, xnetKey, nil, true},
		{"package path held by another module", []string{xnet, "pkg:golang/golang.org/x/text/unicode/norm"}, xnetKey, build, true},
		{"package path no build module holds", []string{xnet, "pkg:golang/golang.org/x/crypto/ssh"}, xnetKey, build, false},
		{"module the build does not select", []string{xnet, "pkg:golang/golang.org/x/crypto"}, xnetKey, build, false},
		{"module the build does not select, no module list", []string{xnet, "pkg:golang/golang.org/x/crypto"}, xnetKey, nil, true},
		{"module the build selects", []string{xnet, "pkg:golang/golang.org/x/text"}, xnetKey, build, true},
		{"a nested module the build selects", []string{ctrd, ctrdV2}, ctrdKey,
			goModules{"github.com/containerd/containerd": true, "github.com/containerd/containerd/v2": true}, true},
		{"a nested module path the build does not select", []string{ctrd, ctrdV2}, ctrdKey,
			goModules{"github.com/containerd/containerd": true}, false},
		{"module path sharing a prefix but not a path boundary", []string{xnet, "pkg:golang/golang.org/x/netx"}, xnetKey,
			goModules{"golang.org/x/net": true, "golang.org/x/netx": true}, true},
		{"standard library path under stdlib", []string{stdlib, "pkg:golang/net/http", "pkg:golang/crypto/tls"}, stdKey, nil, false},
		{"toolchain path under stdlib", []string{stdlib, "pkg:golang/cmd/go"}, stdKey, nil, true},
		{"toolchain under stdlib", []string{stdlib, "pkg:golang/toolchain"}, stdKey, nil, true},
		{"toolchain beside a module, module list", []string{xnet, "pkg:golang/toolchain", "pkg:golang/cmd/go"}, xnetKey, build, true},
		{"module the build does not select under stdlib", []string{stdlib, xnet}, stdKey, goModules{"golang.org/x/text": true}, false},
		{"module the build selects beside stdlib", []string{stdlib, xnet}, stdKey, build, true},
		{"standard library under a module", []string{xnet, stdlib}, xnetKey, build, true},
		{"standard library path under a module", []string{xnet, "pkg:golang/net/http"}, xnetKey, build, true},
		{"another ecosystem's package of the same name", []string{xnet, "pkg:npm/golang.org/x/net"}, xnetKey, build, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namesOtherPackage(tt.purls, tt.admitted, tt.mods); got != tt.want {
				t.Errorf("namesOtherPackage(%q, %v) = %v, want %v", tt.purls, tt.admitted, got, tt.want)
			}
		})
	}
}

func TestGoModulesOf(t *testing.T) {
	sbom := report.SBOM{Packages: []report.Package{
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}}
	limit := func(eco string) []report.PartialityNote {
		return []report.PartialityNote{{Ecosystem: eco, Reason: "tool_failure:lockfile_ambiguous"}}
	}
	tests := []struct {
		name   string
		limits []report.PartialityNote
		want   goModules
	}{
		{"complete inventory", nil, goModules{"golang.org/x/net": true}},
		{"another ecosystem's limit", limit("npm"), goModules{"golang.org/x/net": true}},
		{"a Go limit", limit("Go"), nil},
		{"a scan-wide limit", limit(""), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := goModulesOf(sbom, tt.limits)
			if len(got) != len(tt.want) || (got == nil) != (tt.want == nil) {
				t.Fatalf("goModulesOf = %v, want %v", got, tt.want)
			}
			for m := range tt.want {
				if !got[m] {
					t.Errorf("goModulesOf = %v, missing %s", got, m)
				}
			}
		})
	}
}

// TestFinding_GoPackagePathGrounds is CVE-2023-39325's x/net side through the gate: the advisory
// names x/net and its http2 package, and the lane refuted x/net. The refutation grounds only when
// the build's module list shows http2 is part of x/net; the advisory's stdlib entry keeps it
// undetermined either way.
func TestFinding_GoPackagePathGrounds(t *testing.T) {
	const xnet = "pkg:golang/golang.org/x/net"
	build := goModules{"golang.org/x/net": true}
	tests := []struct {
		name       string
		affected   []string
		dropped    []string
		mods       goModules
		wantReason string // "" = not_exploitable
	}{
		{"package path, module list", []string{xnet}, []string{"pkg:golang/golang.org/x/net/http2"}, build, ""},
		{"package path, no module list", []string{xnet}, []string{"pkg:golang/golang.org/x/net/http2"}, nil, report.ReasonVulnerableSymbolUnresolved},
		{"another module the build does not select", []string{xnet, "pkg:golang/golang.org/x/crypto"}, nil, build, ""},
		{"standard library named beside", []string{xnet, "pkg:golang/stdlib"}, []string{"pkg:golang/golang.org/x/net/http2", "pkg:golang/net/http"}, build, report.ReasonVulnerableSymbolUnresolved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := groundsFixture{
				pkg:             &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: xnet + "@v0.15.0"},
				advisoryPURL:    xnet,
				advisorySymbols: []string{"golang.org/x/net/http2.Server.ServeConn"},
				affected:        tt.affected,
				dropped:         tt.dropped,
				resolution:      plugin.SymbolResolutionResult{Partiality: plugin.Complete()},
				reach: plugin.ReachabilityResult{
					Partiality: plugin.Complete(),
					Refutation: refutation(xnet),
				},
				mods: tt.mods,
			}
			f := fx.finding(t)
			if tt.wantReason == "" {
				if f.Verdict != report.VerdictNotExploitable {
					t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
				}
				return
			}
			if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.wantReason {
				t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tt.wantReason)
			}
		})
	}
}
