package dotnetanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// When the IL tier cannot run, the lexical degrade names why as a tool_failure sub-reason and
// discloses where the IL was looked for as a first-party scoped limit with no Targets.
func TestReachability_DegradeNamesWhyILIsAbsent(t *testing.T) {
	sink := funcSCIP("App", []string{"Sink"}, "vuln", 0)
	appDLL := appReachesLocalSink(t)
	src := []byte(mutSource)
	tests := []struct {
		name  string
		files map[string][]byte
		lock  string // a directory made unreadable before the run
		want  plugin.ScopedReason
	}{
		{"no project file", map[string][]byte{"src/Program.cs": src},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "no project file under the build dir"}},
		{"project never built", map[string][]byte{"App.csproj": []byte("<Project></Project>"), "src/Program.cs": src},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "no built App.dll under bin/ or publish/ for App.csproj"}},
		{"assembly outside bin and publish", map[string][]byte{"App.csproj": []byte("<Project></Project>"), "src/Program.cs": src, "obj/App.dll": appDLL},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "no built App.dll under bin/ or publish/ for App.csproj"}},
		{"another project's assembly", map[string][]byte{"src/Web/Web.csproj": []byte("<Project></Project>"), "src/Program.cs": src, "bin/App.dll": appDLL},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "no built Web.dll under bin/ or publish/ for src/Web/Web.csproj"}},
		{"assembly unreadable", map[string][]byte{"App.csproj": []byte("<Project></Project>"), "src/Program.cs": src, "bin/Release/net8.0/App.dll": []byte("MZ not a PE")},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILUnreadable, Path: "bin/Release/net8.0/App.dll"}},
		{"build directory unreadable", map[string][]byte{"App.csproj": []byte("<Project></Project>"), "src/Program.cs": src, "bin/Release/net8.0/App.dll": appDLL},
			"bin/Release", plugin.ScopedReason{Reason: partialReasonFirstPartyILUnreadable, Path: "bin/Release"}},
		{"only a reference assembly", map[string][]byte{"App.csproj": []byte("<Project></Project>"), "src/Program.cs": src, "bin/Release/net8.0/ref/App.dll": refAppMain()},
			"", plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "only a reference assembly bin/Release/net8.0/ref/App.dll for App.csproj"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := composeILBuildDir(t, tt.files)
			if tt.lock != "" {
				if os.Geteuid() == 0 {
					t.Skip("root reads every directory")
				}
				locked := filepath.Join(dir, filepath.FromSlash(tt.lock))
				if err := os.Chmod(locked, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
			}
			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
			if err != nil {
				t.Fatalf("Reachability: %v", err)
			}
			if res.Partiality.Complete || len(res.Searched) > 0 {
				t.Fatalf("degrade must be partial and unsearched, got %+v", res)
			}
			if !hasILReason(res.Partiality, tt.want.Reason) {
				t.Fatalf("reasons = %v, want %s", res.Partiality.Reasons, tt.want.Reason)
			}
			if hasILReason(res.Partiality, plugin.PartialReasonToolFailure) {
				t.Fatalf("reasons = %v carry a bare tool_failure beside the named one", res.Partiality.Reasons)
			}
			if !reflect.DeepEqual(res.Partiality.Scoped, []plugin.ScopedReason{tt.want}) {
				t.Fatalf("scoped = %+v, want %+v", res.Partiality.Scoped, tt.want)
			}
		})
	}
}
