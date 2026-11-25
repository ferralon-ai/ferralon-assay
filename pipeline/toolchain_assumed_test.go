package pipeline

import (
	"fmt"
	"strings"
	"testing"
)

func TestResolveToolchainFact_PracticalAssumedFloor(t *testing.T) {
	assumed := func(v, strict string) ToolchainFact {
		return ToolchainFact{
			Version:       v,
			Bound:         ToolchainBoundMinimum,
			Source:        ToolchainSourceToolchainDirective,
			Assumption:    fmt.Sprintf("the build runs under GOTOOLCHAIN=auto, so on the toolchain line's %s or newer", v),
			StrictVersion: strict,
		}
	}
	floor := func(v string) ToolchainFact {
		return ToolchainFact{Version: v, Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective}
	}
	tests := []struct {
		name string
		in   toolchainInputs
		want ToolchainFact
	}{
		{
			name: "toolchain line above a full-release go line",
			in:   toolchainInputs{goDirective: "1.24.0", toolchainDirective: "go1.26.10"},
			want: assumed("go1.26.10", "go1.24.0"),
		},
		{
			name: "toolchain line above a two-part go line",
			in:   toolchainInputs{goDirective: "1.23", toolchainDirective: "go1.24.3"},
			want: assumed("go1.24.3", "go1.23.0"),
		},
		{
			name: "toolchain line above the go1.21.0 raise of a pre-1.21 go line",
			in:   toolchainInputs{goDirective: "1.20", toolchainDirective: "go1.22.5"},
			want: assumed("go1.22.5", "go1.21.0"),
		},
		{
			name: "toolchain line with no go line has no floor without it",
			in:   toolchainInputs{toolchainDirective: "go1.21.3"},
			want: assumed("go1.21.3", ""),
		},
		{
			name: "toolchain line with an unparseable go line",
			in:   toolchainInputs{goDirective: "1.21rc1", toolchainDirective: "go1.22.5"},
			want: assumed("go1.22.5", ""),
		},
		{
			name: "toolchain line equal to the go line adds nothing",
			in:   toolchainInputs{goDirective: "1.24.0", toolchainDirective: "go1.24.0"},
			want: floor("go1.24.0"),
		},
		{
			name: "toolchain line below the go line adds nothing",
			in:   toolchainInputs{goDirective: "1.23.0", toolchainDirective: "go1.21.0"},
			want: floor("go1.23.0"),
		},
		{
			name: "a two-part toolchain name is not a full release",
			in:   toolchainInputs{goDirective: "1.21", toolchainDirective: "go1.22"},
			want: floor("go1.21.0"),
		},
		{
			name: "a prerelease toolchain name is not a full release",
			in:   toolchainInputs{goDirective: "1.21", toolchainDirective: "go1.22rc1"},
			want: floor("go1.21.0"),
		},
		{
			name: "a suffixed toolchain name is not a full release",
			in:   toolchainInputs{goDirective: "1.21", toolchainDirective: "go1.22.5-custom"},
			want: floor("go1.21.0"),
		},
		{
			name: "a toolchain name without the go prefix is not one",
			in:   toolchainInputs{goDirective: "1.21", toolchainDirective: "1.22.5"},
			want: floor("go1.21.0"),
		},
		{
			// gitea's shape: no toolchain line and a two-part go line stays unresolved.
			name: "two-part go line and no toolchain line stays unresolved",
			in:   toolchainInputs{goDirective: "1.23"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a declared toolchain outranks the assumption",
			in:   toolchainInputs{subjectDeclared: "go1.24.1", goDirective: "1.24.0", toolchainDirective: "go1.26.10"},
			want: ToolchainFact{Version: "go1.24.1", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "a trusted observation outranks the assumption",
			in:   toolchainInputs{ciObserved: "go1.24.1", trustCIObserved: true, goDirective: "1.24.0", toolchainDirective: "go1.26.10"},
			want: ToolchainFact{Version: "go1.24.1", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			name: "an untrusted observation does not displace the assumption",
			in:   toolchainInputs{ciObserved: "go1.24.1", goDirective: "1.24.0", toolchainDirective: "go1.26.10"},
			want: assumed("go1.26.10", "go1.24.0"),
		},
		{
			name: "a refuted claim resolves as the floor without the assumption",
			in:   toolchainInputs{subjectDeclared: "go1.20.5", goDirective: "1.21.0", toolchainDirective: "go1.26.10"},
			want: ToolchainFact{
				Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective,
				Contradiction: &ToolchainContradiction{ClaimedVersion: "go1.20.5", ClaimedSource: ToolchainSourceSubjectDeclared, FloorVersion: "go1.21.0", FloorSource: ToolchainSourceGoDirective},
			},
		},
		{
			name: "a Bazel workspace reads no toolchain line",
			in:   toolchainInputs{goDirective: "1.24.0", toolchainDirective: "go1.26.10", bazelWorkspace: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "strict reads no toolchain line",
			in:   toolchainInputs{goDirective: "1.24.0", toolchainDirective: "go1.26.10", strict: true},
			want: floor("go1.24.0"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveToolchainFact(tc.in)
			if !toolchainFactEqual(got, tc.want) {
				t.Errorf("resolveToolchainFact(%+v)\n got %+v\nwant %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestResolveToolchainFact_PracticalOnlyRaisesTheFloor: over a grid of inputs, practical mode differs
// from strict only by an assumed floor above strict's minimum, and records strict's floor beside it.
func TestResolveToolchainFact_PracticalOnlyRaisesTheFloor(t *testing.T) {
	var n int
	for _, declared := range []string{"", "go1.20.5", "go1.24.1", "latest"} {
		for _, observed := range []string{"", "go1.19.0", "go1.25.2"} {
			for _, trust := range []bool{false, true} {
				for _, resolved := range []string{"", "go1.22.0"} {
					for _, tl := range []string{"", "go1.20.1", "go1.22.5", "go1.26.10", "go1.22", "go1.23rc1", "default"} {
						for _, gl := range []string{"", "1.17", "1.20", "1.21", "1.21.0", "1.23", "1.24.0", "1.21rc1"} {
							for _, bazel := range []bool{false, true} {
								in := toolchainInputs{subjectDeclared: declared, ciObserved: observed, trustCIObserved: trust, buildResolved: resolved, toolchainDirective: tl, goDirective: gl, bazelWorkspace: bazel}
								practical := resolveToolchainFact(in)
								in.strict = true
								strict := resolveToolchainFact(in)
								n++
								if toolchainFactEqual(practical, strict) {
									if practical.Assumption != "" {
										t.Fatalf("%+v: strict carries an assumption: %+v", in, strict)
									}
									continue
								}
								if strict.Bound == ToolchainBoundExact || strict.Contradiction != nil {
									t.Fatalf("%+v: practical %+v displaced strict %+v", in, practical, strict)
								}
								if practical.Bound != ToolchainBoundMinimum || practical.Assumption == "" || practical.StrictVersion != strict.Version {
									t.Fatalf("%+v: practical %+v is not an assumed floor over strict %+v", in, practical, strict)
								}
								p, _ := parseGoToolchainVersion(practical.Version)
								if s, ok := parseGoToolchainVersion(strict.Version); ok && compareGoToolchain(p, s) <= 0 {
									t.Fatalf("%+v: practical %+v does not raise strict %+v", in, practical, strict)
								}
							}
						}
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("empty grid")
	}
}

// alsoPresentStdlibSource is a two-element advisory whose stdlib element is fixed at go1.21.3, so a
// target requiring a fixed x/net adjudicates x/net and carries stdlib as an also-present package.
type alsoPresentStdlibSource struct{}

func (alsoPresentStdlibSource) Lookup(string) (AdvisoryFacts, bool) {
	return AdvisoryFacts{
		Module:         "golang.org/x/net",
		VersionScheme:  "gomod",
		PURL:           "pkg:golang/golang.org/x/net",
		AffectedRanges: []Range{{Fixed: "v0.17.0", FixedVersion: "v0.17.0"}},
		Provenance:     Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
		AffectedPackages: []AffectedPackage{
			{
				Module:         "golang.org/x/net",
				Coordinate:     "golang.org/x/net",
				VersionScheme:  "gomod",
				PURL:           "pkg:golang/golang.org/x/net",
				AffectedRanges: []Range{{Fixed: "v0.17.0", FixedVersion: "v0.17.0"}},
			},
			{
				Coordinate:     "stdlib",
				VersionScheme:  "go-toolchain",
				PURL:           "pkg:golang/stdlib",
				AffectedRanges: []Range{{Fixed: "go1.21.3", FixedVersion: "go1.21.3"}},
			},
		},
	}, true
}

// TestAssumedToolchainFloor_AlsoPresentStdlib: when stdlib is an also-present package rather than the
// adjudicated element, a clearance that holds only at the toolchain line still names the assumption.
func TestAssumedToolchainFloor_AlsoPresentStdlib(t *testing.T) {
	const assumption = "the build runs under GOTOOLCHAIN=auto, so on the toolchain line's go1.21.3 or newer"
	tests := []struct {
		name           string
		goMod          string
		wantAssumption string
	}{
		{
			name:           "stdlib past the fix only at the toolchain line",
			goMod:          "module example.com/target\n\ngo 1.21.0\n\ntoolchain go1.21.3\n\nrequire golang.org/x/net v0.17.0\n",
			wantAssumption: assumption,
		},
		{
			name:  "stdlib past the fix at the go line alone",
			goMod: "module example.com/target\n\ngo 1.21.4\n\ntoolchain go1.21.5\n\nrequire golang.org/x/net v0.17.0\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := runDisqualWith(t, "CVE-2023-39325", "go", alsoPresentStdlibSource{}, map[string]string{"go.mod": tc.goMod}, goManifestPlugin{})
			if !res.Disqualified || res.Reason != ReasonVersionNotInRange {
				t.Fatalf("disqualified=%v reason=%q, want version_not_in_range", res.Disqualified, res.Reason)
			}
			var named []string
			for _, a := range res.Assumptions {
				if strings.Contains(a, "GOTOOLCHAIN=auto") {
					named = append(named, a)
				}
			}
			switch {
			case tc.wantAssumption == "" && len(named) > 0:
				t.Errorf("assumptions = %q, want none: the go line alone clears stdlib", named)
			case tc.wantAssumption != "" && (len(named) != 1 || !strings.Contains(named[0], "go1.21.3")):
				t.Errorf("assumptions = %q, want exactly %q", res.Assumptions, tc.wantAssumption)
			}
		})
	}
}
