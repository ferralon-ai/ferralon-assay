// Package brand holds the single source of truth for every user-facing /
// artifact-visible name string the tool emits at runtime: the CLI/command name,
// the help tagline, the repository URL stamped into projections, and the analyzer
// version suffix.
//
// # White-label extension seam
//
// This file is the ONE file a downstream fork edits to rebrand the tool while
// keeping full code compatibility. Every consumer in the tree reads the identifiers
// below rather than the string each happens to hold today, so re-pointing them
// rebrands every surface at once: the CLI name, the help banner, the SARIF driver
// name and informationUri, the OpenVEX author, the GitHub job-summary and
// PR-comment headings, the pinned-Issue title and its idempotency markers, the
// tool's own environment-variable prefix, and the git-ref namespace its durable
// state lives under.
//
// Because the values are consts, every derived identifier folds at compile time.
// Version is the one deliberate exception: it is a var, because the release cut
// stamps it (see below).
//
// Two rules keep the seam intact:
//
//   - No consumer may re-inline one of these strings as a literal. A literal is a
//     site a downstream rebrand silently misses.
//   - Nothing selects an identity at build time. There is exactly one identity,
//     compiled unconditionally — no build tag. The sole -ldflags override is
//     Version, which names WHICH CUT of that one identity is running; it cannot
//     select a different identity.
package brand

const (
	// Name is the command/CLI name, SARIF driver name, and marker slug.
	Name = "ferralon-assay"
	// Tagline is the help banner subtitle and HTML report subtitle.
	Tagline = "dependency advisory scanner for CI"
	// RepoURL is the informationUri stamped into SARIF / report projections, which
	// GitHub renders in the customer's code-scanning tab. It must be a public,
	// fetchable location so a reader can follow it to the tool that produced the
	// results, and it must carry no operator (person) identity. Specifically it is the
	// public repository this tool is DISTRIBUTED from — not the private monorepo the
	// sources are developed in, which no customer can open.
	RepoURL = "https://github.com/ferralon-ai/ferralon-assay"
	// EnvPrefix is the prefix for the tool's own opt-in/opt-out toggle env vars
	// (e.g. EnvPrefix+"_PAGES"). Brand-derived so a rebranded fork's public workflow
	// YAML carries this project's name nowhere. Prior prefixes stay readable through
	// EnvOrLegacy, because an operator may have set one by hand in workflow YAML.
	EnvPrefix = "ASSAY"
	// RefNamespace is the git-ref namespace segment for the durable StateStore ref
	// (refs/RefNamespace/state). Brand-derived so a rebranded fork's public git refs
	// carry this project's name nowhere. Unlike EnvPrefix there is deliberately NO
	// fallback read of a prior namespace: a repository whose state sits under an
	// older namespace simply re-establishes it on the next run.
	RefNamespace = "assay"

	// Tier0SummaryHeading is the customer-facing heading for the Tier-0 GitHub
	// job-summary surface — the "assess summary" panel a viewer sees right after the
	// Action runs. Kept DISTINCT from SummaryHeading() (the raw Name-derived form) so
	// a downstream can brand the customer-facing panel independently of the tool name
	// without touching any render site.
	Tier0SummaryHeading = "Ferralon Assay"

	// Tier0RenderAnalyzer controls whether the Tier-0 job summary renders the
	// "**Analyzer:** `<analyzer_version>`" provenance line. It is ON: the analyzer
	// identity is public, and the line is the citation anchor tying a rendered verdict
	// back to the build that produced it. A downstream that does not want to disclose
	// its analyzer build flips this to false; either way the recorded
	// provenance.analyzer_version is persisted verbatim (the render never changes it).
	Tier0RenderAnalyzer = true

	// Tier1SummaryHeading is the customer-facing heading for the shared Tier-1 render
	// (renderTier1Body) — the sticky PR comment and the pinned dashboard Issue both use
	// it. Same split as Tier0SummaryHeading; SummaryHeading() itself is left unchanged
	// for any consumer that wants the raw Name-derived form.
	Tier1SummaryHeading = "Ferralon Assay"

	// Tier1IssueTitle is the customer-facing title of the pinned dashboard Issue. Same
	// split as Tier1SummaryHeading; IssueTitle() itself is left unchanged.
	Tier1IssueTitle = "Ferralon Assay: dependency scan dashboard"

	// Tier1RenderAnalyzer controls whether the shared Tier-1 render (sticky PR comment
	// + pinned Issue) shows the "**Analyzer:** `<analyzer_version>`" provenance line.
	// Same rationale as Tier0RenderAnalyzer.
	Tier1RenderAnalyzer = true
)

// Version is the analyzer version suffix (see AnalyzerVersion): WHICH CUT of the
// identity above is running.
//
// It is a var, not a const, and that is load-bearing: the release cut stamps it
// with the tag it is publishing via
//
//	-X github.com/ferralon-ai/ferralon-assay/internal/brand.Version=<tag>
//
// (deploy/assay/publish.sh). The linker cannot patch a const, so a const here
// silently pinned every released binary's self-reported version to "dev" — the
// analyzer line on a rendered verdict then named no build at all.
//
// This is the ONE version symbol. cmd/ferralon-assay's `version` subcommand reads
// it, and brand.AnalyzerVersion() derives the customer-facing provenance string
// from it, so the `version` output and a report's analyzer_version can never
// disagree. Do not reintroduce a second stampable version var anywhere.
//
// "dev" is the default an unstamped local build keeps.
var Version = "dev"
