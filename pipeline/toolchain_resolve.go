package pipeline

// ToolchainCandidates are the raw sources of the subject's Go toolchain, in the spellings their
// origins produce. They are the inputs codebase_inventory resolves its toolchain fact from.
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

// ResolveToolchain resolves the candidates to the subject's Go toolchain fact by the same rules
// codebase_inventory applies, so a caller outside the pipeline reads the same fact the version axis
// will.
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
