// toolchain_fact_test.go
//
// The toolchain-fact precedence lattice, exhaustively: each single source alone, exact beating a
// floor regardless of which names the higher version, floors combining by maximum, normalization,
// and every junk shape degrading to the next source rather than into the fact.
package pipeline

import "testing"

func TestResolveToolchainFact(t *testing.T) {
	tests := []struct {
		name string
		in   toolchainInputs
		want ToolchainFact
	}{
		// Each source alone.
		{
			name: "subject_declared alone is exact",
			in:   toolchainInputs{subjectDeclared: "go1.21.3"},
			want: ToolchainFact{Version: "go1.21.3", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "ci_observed alone is exact",
			in:   toolchainInputs{ciObserved: "go1.20.10", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.20.10", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			name: "toolchain_directive alone is a floor",
			in:   toolchainInputs{toolchainDirective: "go1.21.3"},
			want: ToolchainFact{Version: "go1.21.3", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "go_directive alone is a floor",
			in:   toolchainInputs{goDirective: "1.22.0"},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "nothing resolves",
			in:   toolchainInputs{},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},

		// The observed tier is OPT-IN (ruling 7). Untrusted, it does not participate AT ALL — the
		// cases below are the same inputs as their trusted counterparts above and must resolve
		// differently. This is the shipped no-config default, so it is the behavior most scans get.
		{
			name: "untrusted ci_observed alone resolves NOTHING",
			in:   toolchainInputs{ciObserved: "go1.26.3"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			// The load-bearing half of "drops out entirely". Demoting the observation to a floor was
			// the tempting half-measure and it is unsound: in the topology the gate exists for, the
			// runner's Go is an artifact of the hosted image and is no lower bound on the subject's
			// toolchain either. A go1.26.3 floor here would disqualify advisories a go1.22 build is
			// still exposed to.
			name: "untrusted ci_observed is not demoted to a floor — it must not become the max",
			in:   toolchainInputs{ciObserved: "go1.26.3", goDirective: "1.22.0"},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "untrusted ci_observed falls through to the toolchain directive floor",
			in:   toolchainInputs{ciObserved: "go1.26.3", toolchainDirective: "go1.20.14", goDirective: "1.20"},
			want: ToolchainFact{Version: "go1.20.14", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			// Tier 1 is unaffected by the gate either way (ruling 7): a declaration is the subject's
			// own statement and needs no assertion about runner topology.
			name: "subject_declared is exact even with the observation untrusted",
			in:   toolchainInputs{subjectDeclared: "go1.19.13", ciObserved: "go1.26.3"},
			want: ToolchainFact{Version: "go1.19.13", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			// Trust is not a version source. Asserting it with nothing observed changes nothing.
			name: "trust with no observation resolves nothing",
			in:   toolchainInputs{trustCIObserved: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "trust with an unparseable observation still falls to the floor",
			in:   toolchainInputs{ciObserved: "devel go1.27-abc123", trustCIObserved: true, goDirective: "1.22.0"},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},

		// The go directive binds only when an enforcing go command (1.21 on) is established: a go line
		// at 1.21 or later, or any toolchain line. Below that the go line is no floor, and the
		// toolchain the build's environment resolves stands in for it, under the observation's trust.
		{
			name: "pre-1.21 go directive alone is no floor",
			in:   toolchainInputs{goDirective: "1.17"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "pre-1.21 go directive: the build-resolved toolchain under trust is exact",
			in:   toolchainInputs{goDirective: "1.17", buildResolved: "go1.16.5", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
		},
		{
			name: "no go directive: the build-resolved toolchain under trust is exact",
			in:   toolchainInputs{buildResolved: "go1.16.5", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
		},
		{
			// The established toolchain is the analyzer's ambient go command; without the assertion
			// that it runs where the subject builds, it says nothing about the subject.
			name: "pre-1.21 go directive: the build-resolved toolchain untrusted resolves nothing",
			in:   toolchainInputs{goDirective: "1.17", buildResolved: "go1.16.5"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "pre-1.21 go directive: no established toolchain resolves nothing",
			in:   toolchainInputs{goDirective: "1.17", trustCIObserved: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "pre-1.21 go directive: an unparseable established toolchain resolves nothing",
			in:   toolchainInputs{goDirective: "1.17", buildResolved: "devel go1.27-abc123", trustCIObserved: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "pre-1.21 go directive: the observation outranks the build-resolved toolchain",
			in:   toolchainInputs{goDirective: "1.17", ciObserved: "go1.16.9", buildResolved: "go1.16.5", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.16.9", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			// No floor binds, so an exact claim below the go line is no contradiction.
			name: "pre-1.21 go directive does not refute a lower declaration",
			in:   toolchainInputs{subjectDeclared: "go1.16.5", goDirective: "1.17"},
			want: ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "three-part 1.21.0 go directive is a floor",
			in:   toolchainInputs{goDirective: "1.21.0"},
			want: ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			// A go command before 1.21 parses a two-part line, and does not enforce it.
			name: "two-part 1.21 go directive is no floor",
			in:   toolchainInputs{goDirective: "1.21"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "two-part 1.22 go directive is no floor",
			in:   toolchainInputs{goDirective: "1.22"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "two-part go directive defers to a trusted build-resolved value",
			in:   toolchainInputs{goDirective: "1.22", buildResolved: "go1.17.13", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.17.13", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
		},
		{
			name: "two-part go directive does not refute a lower declaration",
			in:   toolchainInputs{subjectDeclared: "go1.20.5", goDirective: "1.21"},
			want: ToolchainFact{Version: "go1.20.5", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "three-part go directive past major 1 is a floor",
			in:   toolchainInputs{goDirective: "2.0.0"},
			want: ToolchainFact{Version: "go2.0.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "three-part pre-1.21 go directive is no floor",
			in:   toolchainInputs{goDirective: "1.20.0"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			// A binding directive is a statement about the subject; the analyzer's ambient go command
			// is not consulted in its place.
			name: "binding go directive ignores a build-resolved value",
			in:   toolchainInputs{goDirective: "1.22.0", buildResolved: "go1.26.3", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "pre-1.21 go directive with a toolchain line binds both",
			in:   toolchainInputs{goDirective: "1.17", toolchainDirective: "go1.16.15"},
			want: ToolchainFact{Version: "go1.17.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "pre-1.21 go directive with a toolchain line ignores a build-resolved value",
			in:   toolchainInputs{goDirective: "1.17", toolchainDirective: "go1.21.3", buildResolved: "go1.16.5", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.21.3", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},

		// Precedence among the exact sources.
		{
			name: "subject_declared outranks ci_observed",
			in:   toolchainInputs{subjectDeclared: "go1.19.0", ciObserved: "go1.26.3", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.19.0", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "unparseable subject_declared falls through to ci_observed",
			in:   toolchainInputs{subjectDeclared: "latest", ciObserved: "go1.26.3", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.26.3", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},

		// Exact beats a floor when it is AT OR ABOVE it — a floor is never the tightest available
		// statement when a consistent direct one exists. Below the floor is a different thing
		// entirely: a contradiction, covered by TestResolveToolchainFact_ContradictionGuard.
		{
			name: "exact beats a LOWER floor",
			in:   toolchainInputs{ciObserved: "go1.26.3", toolchainDirective: "go1.20.1", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.26.3", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			name: "exact EQUAL to the floor is consistent, and stays exact",
			in:   toolchainInputs{ciObserved: "go1.24.0", toolchainDirective: "go1.24.0", goDirective: "1.23", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.24.0", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},

		// Floors combine by maximum — both are lower bounds on the same quantity, so the larger is
		// the tightest sound bound, whichever directive it came from.
		{
			name: "max of floors: toolchain directive is higher",
			in:   toolchainInputs{toolchainDirective: "go1.21.3", goDirective: "1.20"},
			want: ToolchainFact{Version: "go1.21.3", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "max of floors: go directive is higher",
			in:   toolchainInputs{toolchainDirective: "go1.20.5", goDirective: "1.22"},
			want: ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "equal floors tie to the toolchain directive",
			in:   toolchainInputs{toolchainDirective: "go1.21.0", goDirective: "1.21"},
			want: ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name: "unparseable toolchain directive leaves the go directive as the floor",
			in:   toolchainInputs{toolchainDirective: "go1.21rc1", goDirective: "1.21"},
			want: ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},

		// Normalization: one spelling reaches the artifact regardless of the source's own.
		{
			name: "go directive two-segment form gains an explicit patch 0",
			in:   toolchainInputs{goDirective: "1.21", toolchainDirective: "go1.20"},
			want: ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name: "bare three-segment declaration gains the go prefix",
			in:   toolchainInputs{subjectDeclared: "1.21.3"},
			want: ToolchainFact{Version: "go1.21.3", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "surrounding whitespace is tolerated",
			in:   toolchainInputs{ciObserved: "  go1.26.3\n", trustCIObserved: true},
			want: ToolchainFact{Version: "go1.26.3", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			name: "an already-canonical value round-trips",
			in:   toolchainInputs{subjectDeclared: "go1.26.3"},
			want: ToolchainFact{Version: "go1.26.3", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},

		// Junk in every slot: unresolved, never a fabricated version.
		{
			name: "every source is junk",
			in: toolchainInputs{
				subjectDeclared:    "tip",
				ciObserved:         "devel go1.27-abc123",
				trustCIObserved:    true,
				toolchainDirective: "default",
				goDirective:        "v1.20.0",
			},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "module semver is the wrong scheme and resolves nothing",
			in:   toolchainInputs{subjectDeclared: "v0.17.0"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a prerelease toolchain resolves nothing",
			in:   toolchainInputs{ciObserved: "go1.22.0-rc.1", trustCIObserved: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a major-only value resolves nothing",
			in:   toolchainInputs{goDirective: "1"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a four-segment value resolves nothing",
			in:   toolchainInputs{subjectDeclared: "go1.21.3.1"},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name: "a bare go prefix resolves nothing",
			in:   toolchainInputs{ciObserved: "go", trustCIObserved: true},
			want: ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
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

// TestResolveToolchainFact_ContradictionGuard covers the boundary at which an exact claim stops being
// believable: strictly below the subject's own go.mod floor.
//
// `GOTOOLCHAIN=auto` switches only UP from a directive, so a repo requiring at least `floor` provably
// does not build with less. An exact claim below it is refuted BY THE REPO — the observed Go was the
// bootstrap that then switched up, or a declaration went stale against a directive bump. The claim is
// dropped and the floor resolves instead, which keeps M3's disqualification (a floor is all it needed)
// and denies M4's gate structurally, since the bound is no longer exact.
//
// The asymmetry is the point: exact ABOVE a floor is the normal case and must stay exact. A guard
// written as `!=` rather than `<` would demote every ordinary build to a floor and silently switch M4
// off for everyone.
func TestResolveToolchainFact_ContradictionGuard(t *testing.T) {
	tests := []struct {
		name string
		in   toolchainInputs
		want ToolchainFact
	}{
		{
			name: "exact BELOW the toolchain directive is refuted, resolves as the floor",
			in:   toolchainInputs{ciObserved: "go1.19.0", toolchainDirective: "go1.24.0", goDirective: "1.23", trustCIObserved: true},
			want: ToolchainFact{
				Version: "go1.24.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective,
				Contradiction: &ToolchainContradiction{
					ClaimedVersion: "go1.19.0", ClaimedSource: ToolchainSourceCIObserved,
					FloorVersion: "go1.24.0", FloorSource: ToolchainSourceToolchainDirective,
				},
			},
		},
		{
			// A DECLARATION is refuted the same way. The guard is about the claim's relation to the
			// manifest, not about which tier made it: an operator can pass a stale value too.
			name: "a subject declaration below the floor is refuted just the same",
			in:   toolchainInputs{subjectDeclared: "go1.18.1", goDirective: "1.22.0"},
			want: ToolchainFact{
				Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective,
				Contradiction: &ToolchainContradiction{
					ClaimedVersion: "go1.18.1", ClaimedSource: ToolchainSourceSubjectDeclared,
					FloorVersion: "go1.22.0", FloorSource: ToolchainSourceGoDirective,
				},
			},
		},
		{
			// Multiple floors: the claim is tested against the MAXIMUM, which is the only sound
			// comparison — a claim above the weaker floor can still be refuted by the stronger one.
			name: "refuted by the MAXIMUM of the floors, not the first one",
			in:   toolchainInputs{subjectDeclared: "go1.21.0", goDirective: "1.20", toolchainDirective: "go1.24.3"},
			want: ToolchainFact{
				Version: "go1.24.3", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective,
				Contradiction: &ToolchainContradiction{
					ClaimedVersion: "go1.21.0", ClaimedSource: ToolchainSourceSubjectDeclared,
					FloorVersion: "go1.24.3", FloorSource: ToolchainSourceToolchainDirective,
				},
			},
		},
		{
			// The discriminating max-of-floors case: the higher floor is the SECOND source in
			// precedence order, and the claim sits BETWEEN the two. Comparing against the first floor
			// found (go1.20.1) would accept the claim; only the maximum refutes it.
			name: "refuted by a lower-precedence floor that is nonetheless the maximum",
			in:   toolchainInputs{subjectDeclared: "go1.21.0", toolchainDirective: "go1.20.1", goDirective: "1.23"},
			want: ToolchainFact{
				Version: "go1.23.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective,
				Contradiction: &ToolchainContradiction{
					ClaimedVersion: "go1.21.0", ClaimedSource: ToolchainSourceSubjectDeclared,
					FloorVersion: "go1.23.0", FloorSource: ToolchainSourceGoDirective,
				},
			},
		},
		{
			name: "exact equal to the maximum floor is NOT a contradiction",
			in:   toolchainInputs{subjectDeclared: "go1.24.3", goDirective: "1.20", toolchainDirective: "go1.24.3"},
			want: ToolchainFact{Version: "go1.24.3", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name: "exact above the maximum floor is NOT a contradiction",
			in:   toolchainInputs{subjectDeclared: "go1.26.4", goDirective: "1.20", toolchainDirective: "go1.24.3"},
			want: ToolchainFact{Version: "go1.26.4", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			// No floor to refute with: the exact claim stands. There is nothing to contradict it, and
			// inventing a demotion here would discard the only statement anyone made.
			name: "no directives: an exact claim cannot be refuted and stays exact",
			in:   toolchainInputs{subjectDeclared: "go1.16.0"},
			want: ToolchainFact{Version: "go1.16.0", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			// An UNTRUSTED observation never reaches the guard: ruling 7 removes it from resolution
			// entirely, so there is no claim to refute and no contradiction to record. The fact is an
			// ordinary floor, indistinguishable from a scan that passed no observation at all.
			name: "an untrusted observation below the floor records no contradiction",
			in:   toolchainInputs{ciObserved: "go1.19.0", toolchainDirective: "go1.24.0"},
			want: ToolchainFact{Version: "go1.24.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			// A refuted claim is still a resolved FLOOR, so the version-empty-iff-unresolved invariant
			// holds and M3's axis is unaffected.
			name: "an unparseable claim is skipped, not treated as a contradiction",
			in:   toolchainInputs{subjectDeclared: "latest", toolchainDirective: "go1.24.0"},
			want: ToolchainFact{Version: "go1.24.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveToolchainFact(tc.in)
			if !toolchainFactEqual(got, tc.want) {
				t.Errorf("resolveToolchainFact(%+v)\n got %+v (contradiction %+v)\nwant %+v (contradiction %+v)",
					tc.in, got, got.Contradiction, tc.want, tc.want.Contradiction)
			}
		})
	}
}

// TestToolchainFactVersionEmptyIffUnresolved pins the invariant the struct's doc comment states, so
// a consumer may branch on either field alone: a version is present exactly when a source resolved.
func TestToolchainFactVersionEmptyIffUnresolved(t *testing.T) {
	for _, in := range []toolchainInputs{
		{},
		{subjectDeclared: "go1.21.3"},
		{ciObserved: "go1.21.3"}, // untrusted ⇒ unresolved
		{ciObserved: "go1.21.3", trustCIObserved: true}, // trusted ⇒ exact
		{ciObserved: "go1.21.3", goDirective: "1.21.0"}, // untrusted ⇒ the floor, not the observation
		{toolchainDirective: "go1.21.3"},
		{goDirective: "1.21"},
		{subjectDeclared: "junk"},
		{subjectDeclared: "junk", goDirective: "1.21"},
		{trustCIObserved: true},
	} {
		got := resolveToolchainFact(in)
		unresolved := got.Source == ToolchainSourceUnresolved
		if unresolved != (got.Version == "") {
			t.Errorf("resolveToolchainFact(%+v) = %+v: Version must be empty iff Source is unresolved", in, got)
		}
		if unresolved != (got.Bound == ToolchainBoundNone) {
			t.Errorf("resolveToolchainFact(%+v) = %+v: Bound must be %q iff Source is unresolved", in, got, ToolchainBoundNone)
		}
	}
}

// TestGoLineFloor: only a binding go line is a floor every build of the subject respects; a toolchain
// line that outranks it is not, since GOTOOLCHAIN=local ignores the toolchain line.
func TestGoLineFloor(t *testing.T) {
	cases := []struct {
		name string
		in   toolchainInputs
		want string
	}{
		{"three-part go line at 1.21", toolchainInputs{goDirective: "1.21.0"}, "go1.21.0"},
		{"three-part go line above 1.21", toolchainInputs{goDirective: "1.22.3"}, "go1.22.3"},
		{"two-part go line, no toolchain line", toolchainInputs{goDirective: "1.22"}, ""},
		{"three-part go line below 1.21", toolchainInputs{goDirective: "1.20.1"}, ""},
		{"two-part go line bound by a toolchain line", toolchainInputs{goDirective: "1.21", toolchainDirective: "go1.22.0"}, "go1.21.0"},
		{"toolchain line above the go line does not raise it", toolchainInputs{goDirective: "1.22.0", toolchainDirective: "go1.23.4"}, "go1.22.0"},
		{"toolchain line below the go line", toolchainInputs{goDirective: "1.23.0", toolchainDirective: "go1.21.0"}, "go1.23.0"},
		{"toolchain line, no go line", toolchainInputs{toolchainDirective: "go1.22.0"}, ""},
		{"prerelease go line", toolchainInputs{goDirective: "1.22rc1", toolchainDirective: "go1.22rc1"}, ""},
		{"exact claims do not move it", toolchainInputs{goDirective: "1.22.0", subjectDeclared: "go1.24.1", ciObserved: "go1.25.0", trustCIObserved: true}, "go1.22.0"},
		{"nothing", toolchainInputs{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := goLineFloor(tc.in); got != tc.want {
				t.Errorf("goLineFloor(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
