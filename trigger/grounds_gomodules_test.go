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
	replaced := goModules{"golang.org/x/net": true, "example.com/a": true, "example.com/fork": true}
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
		// replace example.com/a => example.com/fork: the build holds fork's code under a's path, so an
		// advisory naming either is about code in the build.
		{"replaced module named beside another module", []string{xnet, "pkg:golang/example.com/a"}, xnetKey, replaced, true},
		{"replacement module named beside another module", []string{xnet, "pkg:golang/example.com/fork"}, xnetKey, replaced, true},
		{"package path under the replacement module", []string{xnet, "pkg:golang/example.com/fork/sub"}, xnetKey, replaced, true},
		{"the scanned module named beside a dependency", []string{xnet, "pkg:golang/example.com/app/internal/srv"}, xnetKey,
			goModules{"example.com/app": true, "golang.org/x/net": true}, true},
		{"module path in another case than the build's module", []string{xnet, "pkg:golang/github.com/BurntSushi/toml"}, xnetKey,
			goModules{"golang.org/x/net": true, "github.com/burntsushi/toml": true}, true},
		{"package path in another case than the build's module", []string{xnet, "pkg:golang/github.com/BurntSushi/toml/internal"}, xnetKey,
			goModules{"golang.org/x/net": true, "github.com/burntsushi/toml": true}, true},
		{"replacement module named beside the replaced module", []string{"pkg:golang/example.com/a", "pkg:golang/example.com/fork"},
			pkgKey{typ: "golang", name: "example.com/a"}, replaced, true},
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
	pkgs := []report.Package{
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0"},
		{Ecosystem: "Go", Name: "example.com/a", Version: "v1.1.0", Replace: "example.com/fork"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}
	buildList := report.SBOM{GoBuildList: plugin.BuildListGoModGraph, GoMainModule: "example.com/app", Packages: pkgs}
	limit := func(eco string) []report.PartialityNote {
		return []report.PartialityNote{{Ecosystem: eco, Reason: "tool_failure:lockfile_ambiguous"}}
	}
	all := goModules{"example.com/app": true, "golang.org/x/net": true, "example.com/a": true, "example.com/fork": true}
	tests := []struct {
		name   string
		sbom   report.SBOM
		limits []report.PartialityNote
		want   goModules
	}{
		{"complete build list, a replaced module under both paths", buildList, nil, all},
		{"another ecosystem's limit", buildList, limit("npm"), all},
		{"a Go limit", buildList, limit("Go"), nil},
		{"a scan-wide limit", buildList, limit(""), nil},
		{"no build-list source (go.mod alone, or a report written before it was recorded)", report.SBOM{Packages: pkgs}, nil, nil},
		{"a build list with no main module", report.SBOM{GoBuildList: plugin.BuildListGoModGraph, Packages: pkgs}, nil, nil},
		{"a workspace's other main modules", report.SBOM{GoBuildList: plugin.BuildListGoModGraph, GoMainModule: "example.com/app", GoWorkspaceModules: []string{"example.com/lib"}, Packages: pkgs}, nil,
			goModules{"example.com/app": true, "example.com/lib": true, "golang.org/x/net": true, "example.com/a": true, "example.com/fork": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := goModulesOf(tt.sbom, tt.limits)
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

// TestGoModulesOf_FromInventory carries a replaced module from the Go inventory through the SBOM
// projection to the gate: the replacement's path is in the module list, so an advisory naming it
// keeps blocking.
func TestGoModulesOf_FromInventory(t *testing.T) {
	inv := plugin.DependencyInventory{
		Partiality:       plugin.Complete(),
		BuildList:        plugin.BuildListGoModGraph,
		MainModule:       "example.com/app",
		WorkspaceModules: []string{"example.com/lib"},
		Nodes: []plugin.DependencyNode{
			{ID: "a", PURL: "pkg:golang/example.com/a@v1.1.0", Version: "v1.1.0", Partiality: plugin.Complete(), Replace: "example.com/fork"},
			{ID: "net", PURL: "pkg:golang/golang.org/x/net@v0.15.0", Version: "v0.15.0", Partiality: plugin.Complete()},
		},
	}
	sbom, notes := sbomFromInventory(inv, "Go")
	mods := goModulesOf(sbom, notes)
	for _, m := range []string{"example.com/app", "example.com/lib", "example.com/a", "example.com/fork", "golang.org/x/net"} {
		if !mods[m] {
			t.Errorf("goModulesOf = %v, missing %s", mods, m)
		}
	}
	xnetKey := pkgKey{typ: "golang", name: "golang.org/x/net"}
	if !namesOtherPackage([]string{"pkg:golang/golang.org/x/net", "pkg:golang/example.com/fork"}, xnetKey, mods) {
		t.Error("an advisory naming the replacement module beside x/net collapsed to x/net; want it blocking")
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
