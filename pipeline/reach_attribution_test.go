package pipeline

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestCountedReachPaths(t *testing.T) {
	xnet := map[string]any{"module": "golang.org/x/net", "affected_ranges": []map[string]any{{"upper_exclusive": "v0.55.0", "scheme": "gomod"}}}
	idna := map[string]any{"module": "golang.org/x/net/idna", "affected_ranges": []map[string]any{{"upper_exclusive": "v0.55.0", "scheme": "gomod"}}}
	stdlib := map[string]any{"coordinate": "stdlib", "affected_ranges": []map[string]any{
		{"upper_exclusive": "1.25.13", "scheme": "go-toolchain"},
		{"lower_inclusive": "1.26.0", "upper_exclusive": "1.26.6", "scheme": "go-toolchain"},
	}}
	rangelessStdlib := map[string]any{"coordinate": "stdlib"}
	stdlibAt := func(complete bool, versions ...string) map[string]any {
		return map[string]any{"coordinate": "stdlib", "versions": versions, "complete": complete}
	}
	xnetAt := func(versions ...string) map[string]any {
		return map[string]any{"module": "golang.org/x/net", "versions": versions, "complete": true}
	}
	idnaAt := func(versions ...string) map[string]any {
		return map[string]any{"module": "golang.org/x/net/idna", "versions": versions, "complete": true}
	}

	tests := []struct {
		name      string
		module    string
		selected  string
		present   []map[string]any
		packages  []map[string]any
		toolchain *ToolchainFact
		untrusted bool
		paths     []plugin.ReachPath
		want      []string
	}{
		{
			name:     "path into the fixed toolchain is dropped",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.7")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get"), reachTo("golang.org/x/net/http2", "Transport")},
			want:     []string{"Transport"},
		},
		{
			name:     "only a path into the fixed toolchain leaves none",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.7")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get")},
			want:     nil,
		},
		{
			name:     "path into an affected toolchain is kept",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.3")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get")},
			want:     []string{"Get"},
		},
		{
			name:     "incomplete toolchain versions keep the path",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(false, "go1.26.7")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get")},
			want:     []string{"Get"},
		},
		{
			name:     "unknown toolchain version keeps the path",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true)},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get")},
			want:     []string{"Get"},
		},
		{
			name:     "toolchain without ranges keeps the path",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.7")},
			packages: []map[string]any{xnet, rangelessStdlib},
			paths:    []plugin.ReachPath{reachTo("net/http", "Get")},
			want:     []string{"Get"},
		},
		{
			name:      "untrusted advisory keeps the path",
			selected:  "golang.org/x/net",
			present:   []map[string]any{stdlibAt(true, "go1.26.7")},
			packages:  []map[string]any{xnet, stdlib},
			untrusted: true,
			paths:     []plugin.ReachPath{reachTo("net/http", "Get")},
			want:      []string{"Get"},
		},
		{
			name:      "toolchain floor below an introduced bound keeps the path",
			selected:  "golang.org/x/net",
			present:   []map[string]any{stdlibAt(true, "go1.25.13")},
			packages:  []map[string]any{xnet, stdlib},
			toolchain: &ToolchainFact{Version: "go1.25.13", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			paths:     []plugin.ReachPath{reachTo("net/http", "Get")},
			want:      []string{"Get"},
		},
		{
			name:      "exact toolchain below an introduced bound drops the path",
			selected:  "golang.org/x/net",
			present:   []map[string]any{stdlibAt(true, "go1.25.13")},
			packages:  []map[string]any{xnet, stdlib},
			toolchain: &ToolchainFact{Version: "go1.25.13", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			paths:     []plugin.ReachPath{reachTo("net/http", "Get")},
			want:      nil,
		},
		{
			name:     "sink without an import path is kept",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.7")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("", "Opaque")},
			want:     []string{"Opaque"},
		},
		{
			name:     "sink in the scanned project is kept",
			module:   "app",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.7")},
			packages: []map[string]any{xnet, stdlib},
			paths:    []plugin.ReachPath{reachTo("app/handler", "Serve")},
			want:     []string{"Serve"},
		},
		{
			name:     "selected package's path sorts first",
			selected: "golang.org/x/net",
			present:  []map[string]any{stdlibAt(true, "go1.26.3")},
			packages: []map[string]any{xnet, stdlib},
			paths: []plugin.ReachPath{
				reachTo("net/http", "Get"), reachTo("crypto/tls", "Dial"),
				reachTo("golang.org/x/net/http2", "Transport"), reachTo("", "Opaque"),
			},
			want: []string{"Transport", "Opaque", "Get", "Dial"},
		},
		{
			name:     "advisory module orders first without a selection",
			packages: nil,
			paths:    []plugin.ReachPath{reachTo("net/http", "Get"), reachTo("golang.org/x/net/idna", "ToASCII")},
			want:     []string{"ToASCII", "Get"},
		},
		{
			name:     "longer other module owns its subtree",
			selected: "golang.org/x/net",
			present:  []map[string]any{idnaAt("v0.55.0")},
			packages: []map[string]any{xnet, idna},
			paths:    []plugin.ReachPath{reachTo("golang.org/x/net/idna", "ToASCII"), reachTo("golang.org/x/net/http2", "Transport")},
			want:     []string{"Transport"},
		},
		{
			name:     "longer selected module owns its subtree",
			selected: "golang.org/x/net/idna",
			present:  []map[string]any{xnetAt("v0.55.0")},
			packages: []map[string]any{xnet, idna},
			paths:    []plugin.ReachPath{reachTo("golang.org/x/net/idna", "ToASCII"), reachTo("golang.org/x/net/http2", "Transport")},
			want:     []string{"ToASCII"},
		},
		{
			name:     "module name matches only at a path boundary",
			selected: "golang.org/x/net/idna",
			present:  []map[string]any{xnetAt("v0.55.0")},
			packages: []map[string]any{xnet, idna},
			paths:    []plugin.ReachPath{reachTo("golang.org/x/net/idnafoo", "Lookalike")},
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const caseID = "case-attr"
			module := tt.module
			if module == "" {
				module = "example.com/app"
			}
			inv := map[string]any{"language": "go", "module": module, "selected_module": tt.selected, "also_present": tt.present}
			if tt.toolchain != nil {
				inv["toolchain"] = tt.toolchain
			}
			putJSON(t, store, caseID, artifact.TypeInventory, inv)
			adv := map[string]any{"module": "golang.org/x/net", "affected_packages": tt.packages, "trust_tier": string(TrustFirstParty)}
			if tt.untrusted {
				delete(adv, "trust_tier")
			}
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, adv)

			a, ok := readReachAttribution(store, caseID)
			if !ok {
				t.Fatal("readReachAttribution: ok = false")
			}
			var got []string
			for _, p := range countedReachPaths(tt.paths, a) {
				got = append(got, p.Sink.SCIP)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("kept %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadReachAttribution_CountsEveryPathWithoutAGoPackage(t *testing.T) {
	tests := []struct {
		name string
		inv  map[string]any
	}{
		{"non-Go assessment", map[string]any{"language": "java", "selected_coordinate": "org.example:lib"}},
		{"no package named", map[string]any{"language": "go"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, "case-attr", artifact.TypeInventory, tt.inv)
			putJSON(t, store, "case-attr", artifact.TypeNormalizedAdvisory, map[string]any{
				"affected_packages": []map[string]any{{"coordinate": "org.example:lib"}},
			})
			if _, ok := readReachAttribution(store, "case-attr"); ok {
				t.Fatal("readReachAttribution: ok = true, want false")
			}
		})
	}
}

func reachTo(pkg, name string) plugin.ReachPath {
	return plugin.ReachPath{Sink: plugin.Symbol{SCIP: name, Package: pkg}}
}
