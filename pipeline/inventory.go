package pipeline

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// targetEnvJavaVersion is the TargetEnv key the Java plugin evaluates Maven <jdk> profile
// activation against.
const targetEnvJavaVersion = "java.version"

// targetEnvMavenProfiles is the TargetEnv key carrying the subject build's explicit Maven profile
// selection, in -P syntax.
const targetEnvMavenProfiles = "maven.profiles"

// WithSubjectJavaVersion passes the java.version of the JVM that runs the SUBJECT's Maven build
// (what `mvn -v` reports; not its compile target or a toolchains JDK) to inventory resolution,
// where Maven profiles conditioned on <jdk> are decided against it. The value is the caller's
// statement; Assay never looks it up. Without it those profiles stay undecided and disclosed.
func WithSubjectJavaVersion(v string) AssessOption {
	return func(c *AssessConfig) { c.SubjectJavaVersion = v }
}

// WithSubjectMavenProfiles passes the SUBJECT build's explicit Maven profile selection to
// inventory resolution, in -P syntax ("a,!b"; "," for none): its -P list together with
// settings.xml <activeProfiles>. The value is the caller's statement; Assay never looks it up.
// Without it every profile of the reactor and its parents stays undecided and disclosed.
func WithSubjectMavenProfiles(v string) AssessOption {
	return func(c *AssessConfig) { c.SubjectMavenProfiles = v }
}

// ResolveCodebaseInventory resolves the WHOLE dependency inventory of a codebase ONCE (§4.1),
// independent of any advisory work set. It is the inventory-keyed replacement for the advisory-keyed
// per-advisory package loop the SBOM producers ran before PLAN-100: a dependency reaches the SBOM
// whether or not any advisory in the work set names it — exactly the property §4.1's closing
// sentence requires and the old advisory-keyed producer denied.
//
// It applies the same AssessOptions the SBOM producers already carry (WithPlugin / WithCheckout),
// resolves the codebase's primary build directory the way codebase_inventory (S2) does, and calls
// the language plugin's ResolveInventory exactly once — never inside the advisory loop, so a
// codebase with dependencies but zero matching advisories still yields a full SBOM.
//
// Returns the plugin's DependencyInventory, the resolved primary project's language ("" when
// nothing was acquired), and its build directory ("" when nothing was acquired).
//
// HONEST ABSENCE — three outcomes a caller MUST keep distinct (§3.1/§3.6):
//   - nothing acquired, or no language-matched plugin -> DependencyInventory{Partiality:
//     Partial(no_language_plugin)}: the inventory was NOT established, which is not "no
//     dependencies". The gap is declared, never presented as a resolved-empty build.
//   - the plugin ran and returned Unsupported() (or any partial) -> its Partiality is returned
//     unchanged, so the SBOM producer can declare it.
//   - the plugin resolved a Complete inventory (possibly zero nodes) -> zero nodes means the build
//     genuinely has no dependencies.
//
// It NEVER fabricates a Complete()-empty inventory for a case it could not resolve.
func ResolveCodebaseInventory(ctx context.Context, codebase assessment.CodebaseRef, ownershipToken string, opts ...AssessOption) (plugin.DependencyInventory, string, string, error) {
	cfg := &AssessConfig{}
	for _, o := range opts {
		o(cfg)
	}

	plan, err := resolveCodebasePlan(ctx, codebase, ownershipToken, cfg.Checkout)
	if err != nil {
		return plugin.DependencyInventory{}, "", "", err
	}

	buildDir, language := "", ""
	if len(plan.Projects) > 0 {
		prim := plan.Primary()
		buildDir, language = prim.Root, prim.Language
	}

	if buildDir == "" || cfg.Plugin == nil || cfg.Plugin.Language() != language {
		// Nothing acquired, or no plugin matches this language: the inventory is not established.
		// Declare it (no_language_plugin) so the SBOM discloses the gap rather than presenting an
		// empty package set as a resolved-empty build.
		return plugin.DependencyInventory{Partiality: plugin.Partial(plugin.PartialReasonNoPlugin)}, language, buildDir, nil
	}

	inv, err := cfg.Plugin.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir, TargetEnv: cfg.targetEnv()})
	if err != nil {
		return plugin.DependencyInventory{}, language, buildDir, err
	}
	return inv, language, buildDir, nil
}

// targetEnv is the TargetEnv the run's stated subject conditions make, shared by every request
// that resolves the inventory; nil when none were stated.
func (cfg *AssessConfig) targetEnv() map[string]string {
	if cfg.SubjectJavaVersion == "" && cfg.SubjectMavenProfiles == "" {
		return nil
	}
	env := map[string]string{}
	if cfg.SubjectJavaVersion != "" {
		env[targetEnvJavaVersion] = cfg.SubjectJavaVersion
	}
	if cfg.SubjectMavenProfiles != "" {
		env[targetEnvMavenProfiles] = cfg.SubjectMavenProfiles
	}
	return env
}

// resolveCodebasePlan resolves a CodebaseRef to its WorkspacePlan the same way codebase_inventory
// (S2) does — vendored_repro via checkout.ResolveVendored, else a real checkout.Fetch under the
// per-fire credential — so the whole-graph inventory resolves the identical build tree the advisory
// pipeline assesses. It is deliberately a sibling of codebaseInventory.Run's switch rather than a
// shared refactor of it: that stage is load-bearing and this keeps the inventory-keying change from
// touching its control flow. An empty plan (nil checkout, non-vendored mode) is the hermetic no-op
// path and yields an unestablished inventory above.
func resolveCodebasePlan(ctx context.Context, codebase assessment.CodebaseRef, ownershipToken string, co checkout.Checkout) (checkout.WorkspacePlan, error) {
	acq := codebase.Acquisition
	switch {
	case acq.Mode == "vendored_repro":
		return checkout.ResolveVendored(acq.Path)
	case co != nil:
		fctx := checkout.WithCredential(ctx, checkout.NewCredential(ownershipToken))
		return co.Fetch(fctx, codebase.Repo, codebase.Revision)
	}
	return checkout.WorkspacePlan{}, nil
}
