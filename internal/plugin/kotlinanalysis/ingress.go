package kotlinanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// FindIngresses reports the discoverable program entry points of the compiled build
// output. At Assess tier over bytecode, the soundly-discoverable ingress is the program
// entry `main`; each is emitted as an Ingress of kind "main".
//
// SPRING SEAM (deliberately unimplemented — GRANITE's lane): framework-idiomatic HTTP
// ingress (Spring @Controller/@RequestMapping, etc.) is NOT detected here. Doing so
// requires reading class annotations, which this lane deliberately does not (R3/A4: the
// classfile attributes table is a shared-file coordination point, and @Metadata is not
// needed for symbol soundness). registerFrameworkIngresses is the clearly-named seam a
// later GRANITE increment fills; today it contributes nothing, so FindIngresses declares
// exactly what it found — program entries — and never fabricates a framework ingress.
func FindIngresses(_ context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}

	var ingresses []plugin.Ingress
	for _, ref := range mainMethodRefs(prog.classes) {
		ingresses = append(ingresses, plugin.Ingress{
			Kind:   "main",
			Symbol: SymbolFromMethodRef(ref),
		})
	}
	ingresses = append(ingresses, registerFrameworkIngresses(prog)...)

	return plugin.IngressResult{
		Partiality: prog.partiality(),
		Ingresses:  ingresses,
	}, nil
}

// registerFrameworkIngresses is the GRANITE registration seam for framework-idiomatic
// ingress detection (Spring). It is intentionally empty in the Kotlin lane: framework
// ingress is out of scope here and requires annotation reading this lane does not perform.
// A later increment implements it WITHOUT touching FindIngresses' entry-point discovery.
func registerFrameworkIngresses(_ *program) []plugin.Ingress { return nil }
