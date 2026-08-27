package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// acquired holds the resolved scan inputs shared by the baseline / pr-inherit / cve-watch
// run modes: the local BuildDir to inventory (always a vendored_repro path), the detected
// source language, the language-matched analyzer plugin, the neutral repo identity, the
// per-language advisory corpus, and a cleanup for any transient clone. The three run modes
// differ only in what they do with these inputs, not in how the target is materialized.
type acquired struct {
	buildDir   string
	language   string
	plugin     plugin.LanguagePlugin
	repo       string
	advisories []assessment.VulnRef
	cleanup    func()
}

// acquireTarget materializes the scan target into a local BuildDir and selects the
// language-matched analyzer plugin plus advisory corpus. It is the single place both the
// multi-language plugin wiring and the real-checkout wiring live.
//
//   - A remote repo URL (a scheme-carrying URL, an scp-style remote, or a bare
//     host/owner/repo module path) is cloned with checkout.GitCheckout into a temp dir at
//     the requested revision; the returned cleanup removes it after the run. This is the
//     path that lets the CLI scan a repo it does not already have on disk.
//   - An existing local directory is inventoried in place via checkout.ResolveVendored — no
//     clone, no network — preserving the historical hermetic vendored_repro behavior.
//
// The source language is detected from the materialized tree (checkout.DetectLanguage) and
// drives BOTH the plugin (NewGoPlugin / NewJavaPlugin / NewJSPlugin / NewPythonPlugin /
// NewDotNetPlugin) and the advisory corpus, so a Java tree is analyzed by the Java plugin
// against the Maven corpus, a JS tree by the JS plugin against the npm corpus, etc. The
// pipeline's codebase_inventory only runs a plugin whose Language() matches the tree it
// inventories, so selecting the wrong plugin here would silently disable analysis — hence
// detection and selection are bound together in one place.
//
// includeHouseCanaries opts the first-party house canaries (the synthetic FERRALON-APP-* Go
// application-sink advisories and the synthetic Java/JS/Python corpus advisories) into the
// corpus. It defaults OFF so a customer/investor scan never evaluates them (see
// goAdvisoryCorpus); the demo scan sets it via -include-house-canaries so the DOS canary
// surfaces as a reachable_candidate the pipeline can enumerate and fire.
func acquireTarget(ctx context.Context, target, revision, repoOverride, pluginBin string, includeHouseCanaries bool) (*acquired, error) {
	var buildDir, language, repo string
	cleanup := func() {}

	if isRemoteURL(target) {
		plan, err := checkout.NewGitCheckout().Fetch(ctx, target, revision)
		if err != nil {
			return nil, fmt.Errorf("clone %q: %w", target, err)
		}
		prim := plan.Primary()
		buildDir, language = prim.Root, prim.Language
		// Remove the whole checkout tree, not the primary project root: once a plan can
		// enumerate several projects, the primary may be a subdirectory and removing it
		// would leak the rest of the temp checkout.
		cleanup = func() { _ = os.RemoveAll(plan.Root) }
		repo = repoIdentity(target)
	} else {
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return nil, fmt.Errorf("resolve target: %w", err)
		}
		plan, err := checkout.ResolveVendored(absTarget)
		if err != nil {
			return nil, err
		}
		prim := plan.Primary()
		buildDir, language = prim.Root, prim.Language
		repo = filepath.Base(absTarget)
	}
	if repoOverride != "" {
		repo = repoOverride
	}

	lp, err := selectPlugin(language, pluginBin)
	if err != nil {
		cleanup()
		return nil, err
	}

	return &acquired{
		buildDir:   buildDir,
		language:   language,
		plugin:     lp,
		repo:       repo,
		advisories: advisoryCorpus(language, includeHouseCanaries),
		cleanup:    cleanup,
	}, nil
}

// selectPlugin constructs the subprocess-backed analyzer client for the detected language.
// A non-empty bin is an explicit path to that language's tegron-plugin-<lang> binary
// (the -plugin-go flag); when empty each constructor discovers its binary on PATH. Only one
// plugin runs per scan (the tree is a single language), so a single override suffices.
func selectPlugin(language, bin string) (plugin.LanguagePlugin, error) {
	switch language {
	case checkout.LangGo:
		if bin != "" {
			return plugin.NewGoPlugin(plugin.WithBinaryPath(bin))
		}
		return plugin.NewGoPlugin()
	case checkout.LangJava:
		if bin != "" {
			return plugin.NewJavaPlugin(plugin.WithJavaBinaryPath(bin))
		}
		return plugin.NewJavaPlugin()
	case checkout.LangKotlin:
		if bin != "" {
			return plugin.NewKotlinPlugin(plugin.WithKotlinBinaryPath(bin))
		}
		return plugin.NewKotlinPlugin()
	case checkout.LangJS:
		if bin != "" {
			return plugin.NewJSPlugin(plugin.WithJSBinaryPath(bin))
		}
		return plugin.NewJSPlugin()
	case checkout.LangPython:
		if bin != "" {
			return plugin.NewPythonPlugin(plugin.WithPythonBinaryPath(bin))
		}
		return plugin.NewPythonPlugin()
	case checkout.LangDotNet:
		if bin != "" {
			return plugin.NewDotNetPlugin(plugin.WithDotNetBinaryPath(bin))
		}
		return plugin.NewDotNetPlugin()
	default:
		return nil, fmt.Errorf("no analyzer plugin for detected source language %q", language)
	}
}

// isRemoteURL reports whether target names a remote repository to clone rather than a local
// directory to scan in place. An existing local directory is always local (the historical
// -target behavior). Otherwise a scheme-carrying URL (https://, git://, ssh://), an scp-style
// remote (git@host:owner/repo), or a bare host/owner/repo module path (first segment looks
// like a host, i.e. contains a dot) is remote. This mirrors checkout.normalizeCloneURL's own
// notion of what git will treat as a remote.
func isRemoteURL(target string) bool {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		return false
	}
	if strings.Contains(target, "://") {
		return true
	}
	if at := strings.IndexByte(target, '@'); at >= 0 && strings.ContainsRune(target[at:], ':') {
		return true
	}
	if i := strings.IndexByte(target, '/'); i > 0 && strings.Contains(target[:i], ".") {
		return true
	}
	return false
}

// repoIdentity derives the neutral repository identity recorded on the Report from a clone
// URL or module path: it strips any scheme, an scp-style "git@" prefix, a trailing ".git",
// and a trailing slash, leaving the "host/owner/repo" form (e.g. "github.com/owner/repo").
// The -subject-repo flag overrides it when set.
func repoIdentity(target string) string {
	s := target
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if at := strings.IndexByte(s, '@'); at >= 0 { // userinfo (https://user@host/...)
			s = s[at+1:]
		}
	} else if at := strings.IndexByte(s, '@'); at >= 0 { // scp-style git@host:owner/repo
		s = s[at+1:]
		s = strings.Replace(s, ":", "/", 1)
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return s
}

// advisoryCorpus returns the compiled-in advisory FLOOR for a target of the given language — the
// starting point a run's work set is resolved from, not the set it ends up evaluating (the OSV
// widening in workset.go can add to it). Emptiness is therefore judged downstream, on the resolved
// work set, by the gate in run.go; nothing here refuses a scan.
//
// The corpus is language-scoped because an advisory names a package in one ecosystem
// (pkg:golang / pkg:maven / pkg:npm / pkg:pypi / pkg:nuget); running Go advisories against a Java
// tree would resolve nothing.
//
// EVERY SUPPORTED LANGUAGE HAS A NON-EMPTY DEFAULT FLOOR. That is what makes a default scan of a
// Java, JS, Python or .NET repository complete instead of halting on an empty work set, and it is a
// property the five-language regression table in language_support_test.go holds in place.
//
// includeHouseCanaries opts the first-party house canaries into the corpus, ON TOP of that floor
// (default OFF). Every ecosystem honors it: Go carries the FERRALON-APP-* application-sink
// canaries, and Java/JS/Python/.NET carry synthetic first-party sinks and synthetic dependency
// advisories over com.example / tegron-corpus / stand-in packages, none of them public CVE/GHSA/OSV
// records. Nothing gated behind this flag ever reaches a default findings surface.
func advisoryCorpus(language string, includeHouseCanaries bool) []assessment.VulnRef {
	switch language {
	case checkout.LangGo:
		return goAdvisoryCorpus(includeHouseCanaries)
	case checkout.LangJava:
		return javaAdvisoryCorpus(includeHouseCanaries)
	case checkout.LangKotlin:
		return kotlinAdvisoryCorpus(includeHouseCanaries)
	case checkout.LangJS:
		return jsAdvisoryCorpus(includeHouseCanaries)
	case checkout.LangPython:
		return pythonAdvisoryCorpus(includeHouseCanaries)
	case checkout.LangDotNet:
		return dotnetAdvisoryCorpus(includeHouseCanaries)
	default:
		return nil
	}
}

// goAdvisoryCorpus is the set of Go-language advisories the OSS tool evaluates a Go repository
// against. They are the version-resolvable and symbol-reachability Go entries the analyzer knows
// (pipeline.AdvisoryTable). An advisory whose affected module is a dependency of the target resolves
// a real SBOM package; one whose symbol is absent yields a not_exploitable finding.
//
// includeHouseCanaries opts the first-party house canaries in (default OFF, see below). Only the
// DOS canary is opt-in-able today; the SSRF canary stays scrubbed unconditionally.
func goAdvisoryCorpus(includeHouseCanaries bool) []assessment.VulnRef {
	corpus := []assessment.VulnRef{
		{ID: "GO-2021-0113", Source: "osv"}, // golang.org/x/text — version-resolvable
		{ID: "GO-2022-0322", Source: "osv"}, // github.com/prometheus/client_golang — version-resolvable
		{ID: "GO-2021-0264", Source: "osv"}, // archive/zip (stdlib) — symbol reachability
		// The gogs incomplete-fix chain is TWO advisories and both are evaluated: the
		// predecessor traversal and its symlink-bypass successor are separate findings with
		// separate facts (see the AdvisoryTable split). Only CVE-2025-8110 is KEV-listed.
		{ID: "CVE-2024-55947", Source: "ghsa"}, // gogs.io/gogs — first-party application sink (path-traversal predecessor, fixed 0.13.1)
		{ID: "CVE-2025-8110", Source: "ghsa"},  // gogs.io/gogs — first-party application sink (symlink-bypass successor, last_affected 0.13.3; CISA KEV)
		{ID: "CVE-2024-45337", Source: "ghsa"}, // golang.org/x/crypto/ssh — SSH-server authorization bypass (PublicKeyCallback misuse), version-resolvable
		// Four real vuln.go.dev advisories in broad-corpus membership, evaluated on every Go scan.
		// Each carries its GO- alias, because govulncheck keys its findings by the GO- id and never
		// by the CVE/GHSA primary — govulnMatchID resolves the alias so reachability can match.
		{ID: "CVE-2026-46595", Source: "ghsa"}, // golang.org/x/crypto/ssh — authz bypass, incomplete fix of CVE-2024-45337 (< v0.52.0), version-resolvable
		{ID: "CVE-2026-39831", Source: "ghsa"}, // golang.org/x/crypto/ssh — FIDO/U2F user-presence bypass (< v0.52.0), version-resolvable
		{ID: "CVE-2026-39821", Source: "osv"},  // golang.org/x/net/idna — Punycode ASCII-confusion privilege escalation (< v0.55.0), version-resolvable
		{ID: "CVE-2020-36569", Source: "ghsa"}, // github.com/nanobox-io/golang-nanoauth — auth bypass, pseudo-version range (version axis fails open), reachability-decided
	}
	// The synthetic house advisories FERRALON-APP-SSRF-0001 / FERRALON-APP-DOS-0001 are scrubbed
	// from the DEFAULT Go corpus membership. They carry no CVE — they are first-party canaries we
	// wrote to exercise the pipeline — so they must never be evaluated on a customer scan, where a
	// finding with no upstream advisory behind it reads as noise at best and as a fabricated result
	// at worst.
	//
	// The DOS canary is OPT-IN via includeHouseCanaries (the -include-house-canaries flag): our own
	// demo scan sets it so the canary surfaces as a reachable_candidate the pipeline can enumerate →
	// fire → prove → auto-fix-PR end to end. The flag defaults OFF, so the default surface carries no
	// canary at all. Even opted in it stays candidate-only at the scan tier (reachable_candidate +
	// attacker_tainted, never proof — inv. 5); proof comes from the fire. The SSRF canary has no
	// opt-in and stays scrubbed unconditionally. Their AdvisoryTable facts, corpus repros
	// (corpus/testdata/repros/FERRALON-APP-*), and vulnclass entries are unaffected by the flag.
	if includeHouseCanaries {
		corpus = append(corpus, assessment.VulnRef{ID: "FERRALON-APP-DOS-0001", Source: "osv"})
	}
	return corpus
}

// javaAdvisoryCorpus is the set of Java/Maven advisories the OSS tool evaluates a Java source tree
// against (pipeline.AdvisoryTable, pkg:maven ecosystem).
//
// The DEFAULT floor is three real, public Maven advisories — the same kind of membership the Go
// corpus has always had. Until 2026-08-05 this function returned nil unless the canary flag was set,
// which made the default floor empty and halted every default Java scan at the empty-work-set gate
// in run.go. The OSV widening did not rescue it: admitByFacts admits only ids the fact source can
// resolve, and the table held no Maven facts at all, so a live query that returned 55 real GHSA ids
// for a jackson-databind tree admitted none of them. See the block of twelve in
// pipeline.AdvisoryTable for where these came from and how their ranges were verified.
//
// includeHouseCanaries adds the synthetic first-party advisories on top: two SSRF sinks resolved by
// call-graph reachability plus one version-resolvable dependency, all over com.example.* packages
// and none carrying a CVE. They stay off the default surface.
func javaAdvisoryCorpus(includeHouseCanaries bool) []assessment.VulnRef {
	corpus := []assessment.VulnRef{
		{ID: "CVE-2019-14540", Source: "ghsa"}, // com.fasterxml.jackson.core:jackson-databind — HikariConfig deserialization gadget
		{ID: "CVE-2020-36518", Source: "ghsa"}, // com.fasterxml.jackson.core:jackson-databind — nested-object StackOverflow DoS
		{ID: "CVE-2024-22243", Source: "ghsa"}, // org.springframework:spring-web — UriComponentsBuilder open redirect / SSRF
	}
	if includeHouseCanaries {
		corpus = append(corpus,
			assessment.VulnRef{ID: "TEGRON-JAVA-SSRF-0001", Source: "osv"},        // com.example.web/ssrf — UrlFetcher.fetch taint reachability
			assessment.VulnRef{ID: "TEGRON-JAVA-SPRING-SSRF-0001", Source: "osv"}, // com.example.web/spring-ssrf — Spring SSRF taint reachability
			assessment.VulnRef{ID: "TEGRON-JAVA-DEP-0001", Source: "osv"},         // com.example.lib:widget — version-resolvable Maven dependency
		)
	}
	return corpus
}

// kotlinAdvisoryCorpus is the default advisory floor for the Kotlin lane. It is honest-absent
// today: no real Maven/Kotlin advisory has been vetted into pipeline.AdvisoryTable for this lane
// yet (that population, and the fixture repros it needs, are a separate cycle deposit — see
// convergence K6). Returning nil rather than fabricating entries keeps this function truthful;
// checkout.LangKotlin is deliberately absent from supportedLanguages in language_support_test.go
// until the floor is populated, so the empty-floor regression lock does not fire on this lane
// before it is ready to carry one.
func kotlinAdvisoryCorpus(bool) []assessment.VulnRef {
	return nil
}

// jsAdvisoryCorpus is the set of JS/npm advisories the OSS tool evaluates a JS/TS source tree
// against (pipeline.AdvisoryTable, pkg:npm ecosystem): three real, public npm advisories by
// default, with the house canaries — one SSRF sink resolved by reachability plus one
// version-resolvable dependency — added only on the opt-in (see javaAdvisoryCorpus).
func jsAdvisoryCorpus(includeHouseCanaries bool) []assessment.VulnRef {
	corpus := []assessment.VulnRef{
		{ID: "CVE-2022-46175", Source: "ghsa"}, // json5 — JSON5.parse prototype pollution
		{ID: "CVE-2023-26136", Source: "ghsa"}, // tough-cookie — memstore prototype pollution
		{ID: "CVE-2024-29041", Source: "ghsa"}, // express — response.redirect open redirect
	}
	if includeHouseCanaries {
		corpus = append(corpus,
			assessment.VulnRef{ID: "TEGRON-JS-SSRF-0001", Source: "osv"}, // tegron-corpus-ssrf — SSRF taint reachability
			assessment.VulnRef{ID: "TEGRON-JS-DEP-0001", Source: "osv"},  // left-pad — version-resolvable npm dependency
		)
	}
	return corpus
}

// pythonAdvisoryCorpus is the set of Python/PyPI advisories the OSS tool evaluates a Python source
// tree against (pipeline.AdvisoryTable, pkg:pypi ecosystem): three real, public PyPI advisories by
// default, with the house canaries — the Airflow experimental-API get_code sink, whose real removal
// flips reachable_candidate → not_exploitable, plus one version-resolvable dependency — added only
// on the opt-in (see javaAdvisoryCorpus).
func pythonAdvisoryCorpus(includeHouseCanaries bool) []assessment.VulnRef {
	corpus := []assessment.VulnRef{
		{ID: "CVE-2024-22195", Source: "ghsa"}, // jinja2 — xmlattr attribute-key injection
		{ID: "CVE-2024-23334", Source: "ghsa"}, // aiohttp — static-route path traversal via symlink
		{ID: "CVE-2024-3772", Source: "ghsa"},  // pydantic — email-validation ReDoS
	}
	if includeHouseCanaries {
		corpus = append(corpus,
			assessment.VulnRef{ID: "TEGRON-PY-AIRFLOW-EXPAPI-0001", Source: "ghsa"}, // apache-airflow — experimental-API get_code sink (unauth DAG source read), first-party reachability
			assessment.VulnRef{ID: "TEGRON-PY-DEP-0001", Source: "osv"},             // flask — version-resolvable PyPI dependency
		)
	}
	return corpus
}

// dotnetAdvisoryCorpus is the set of .NET/NuGet advisories the OSS tool evaluates a .NET source
// tree against (pipeline.AdvisoryTable, pkg:nuget ecosystem): three real, public NuGet advisories
// by default, adjudicated by the U5 NuGet comparator over the U6 dotnetanalysis resolver, with the
// version-resolvable house canary added only on the opt-in (see javaAdvisoryCorpus).
func dotnetAdvisoryCorpus(includeHouseCanaries bool) []assessment.VulnRef {
	corpus := []assessment.VulnRef{
		{ID: "CVE-2019-0820", Source: "ghsa"},  // System.Text.RegularExpressions — timeout-handling ReDoS
		{ID: "CVE-2020-5234", Source: "ghsa"},  // MessagePack — Typeless deserialization gadget
		{ID: "CVE-2024-21907", Source: "ghsa"}, // Newtonsoft.Json — nesting-depth StackOverflow DoS
	}
	if includeHouseCanaries {
		corpus = append(corpus,
			assessment.VulnRef{ID: "TEGRON-NET-DEP-0001", Source: "osv"}, // Newtonsoft.Json — synthetic stand-in for the real CVE-2024-21907 in the default floor above
		)
	}
	return corpus
}
