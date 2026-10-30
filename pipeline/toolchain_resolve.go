package pipeline

// ToolchainCandidates are the raw sources of the subject's Go toolchain, in the spellings their
// origins produce. Every caller resolving the fact, codebase_inventory included, supplies them
// here, so an input added to the resolution is one every caller sees.
type ToolchainCandidates struct {
	// SubjectDeclared and CIObserved are WithSubjectToolchain's declared and observed values, and
	// TrustCIObserved its trustObserved.
	SubjectDeclared string
	CIObserved      string
	TrustCIObserved bool
	// BuildResolved is the analyzer's plugin.RuntimeSpec.Resolved for the build.
	BuildResolved string
	// ToolchainDirective and GoDirective are go.mod's `toolchain` name ("go1.21.3") and raw `go`
	// version ("1.21").
	ToolchainDirective string
	GoDirective        string
}

// ResolveToolchain resolves the candidates to the subject's Go toolchain fact: the fact
// codebase_inventory hands the version axis, and the one a caller outside the pipeline reads to
// agree with it.
func ResolveToolchain(c ToolchainCandidates) ToolchainFact {
	return resolveToolchainFact(toolchainInputs{
		subjectDeclared:    c.SubjectDeclared,
		ciObserved:         c.CIObserved,
		trustCIObserved:    c.TrustCIObserved,
		buildResolved:      c.BuildResolved,
		toolchainDirective: c.ToolchainDirective,
		goDirective:        c.GoDirective,
	})
}
