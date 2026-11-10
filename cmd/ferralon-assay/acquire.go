package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// acquired holds the resolved scan inputs shared by the baseline / pr-inherit / cve-watch
// run modes: the local BuildDir to inventory (always a vendored_repro path), the detected
// source language, the language-matched analyzer plugin, the neutral repo identity, the
// opted-in house canaries for that language, and a cleanup for any transient clone. The three run modes
// differ only in what they do with these inputs, not in how the target is materialized.
type acquired struct {
	buildDir   string
	language   string
	plugin     plugin.LanguagePlugin
	repo       string
	advisories []assessment.VulnRef
	cleanup    func()

	// analyzeRef / analyzedCommit are set only when the repository config file selected a ref
	// (analyze.ref) and the scan analyzed THAT ref instead of the checked-out tree. Both empty is
	// the default path. See provenance.
	analyzeRef     string
	analyzedCommit string

	// graph is the Java or Kotlin scan's build graph; nil for every other language.
	graph *jvmGraph

	// goWork is the caller's statement of the GOWORK a Go build runs under (-subject-gowork).
	goWork string

	// goToolchain is the caller's statement of the subject's Go toolchain: the declared and observed
	// versions and the observation's trust, as runAssessOptions hands them to the pipeline. The zero
	// value states nothing.
	goToolchain subjectGoToolchain
}

// provenance returns the Revision and ResolvedCommit to record on the Report's subject. By default
// they are the -revision / -commit labels, passed through unchanged. When analyze.ref redirected
// the scan, the labels describe the tree CI checked out — which is NOT what was analyzed — so they
// are replaced by the requested ref and the commit the analyzed worktree actually has checked out.
// A report must never claim the default branch when it scanned an override.
func (a *acquired) provenance(revision, commit string) (string, string) {
	if a.analyzedCommit == "" {
		return revision, commit
	}
	return a.analyzeRef, a.analyzedCommit
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
//     clone, no network — preserving the historical hermetic vendored_repro behavior. The one
//     exception is opt-in and repository-owned: when <target>/.github/ferralon.yml sets
//     analyze.ref, that file (read from the checked-out tree, BEFORE any redirect) selects another
//     ref, which is fetched into a detached worktree (checkout.WorktreeAtRef) and resolved into
//     the WorkspacePlan instead; the returned cleanup removes the worktree, and provenance reports
//     the ref and the commit the plan's tree actually has checked out. No file, or no
//     analyze.ref, is exactly the in-place behavior.
//
// The source language is detected from the materialized tree (checkout.DetectLanguage) and
// drives BOTH the plugin (NewGoPlugin / NewJavaPlugin / NewJSPlugin / NewPythonPlugin /
// NewDotNetPlugin) and the house-canary membership, so a Java tree is analyzed by the Java plugin
// against the Maven canaries, a JS tree by the JS plugin against the npm ones, etc. The
// pipeline's codebase_inventory only runs a plugin whose Language() matches the tree it
// inventories, so selecting the wrong plugin here would silently disable analysis — hence
// detection and selection are bound together in one place.
//
// includeHouseCanaries opts the first-party house canaries into the work set (see houseCanaries).
// It defaults OFF so a customer/investor scan never evaluates them; the demo scan sets it via
// -include-house-canaries so the DOS canary surfaces as a reachable_candidate the pipeline can
// enumerate and fire.
func acquireTarget(ctx context.Context, target, revision, repoOverride, pluginBin string, includeHouseCanaries bool, graphReq graphRequest) (*acquired, error) {
	start := time.Now()
	var buildDir, language, repo, analyzeRef, analyzedCommit string
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
		scanDir := absTarget
		// The config is read from the checked-out tree, before any redirect: it is the tree CI
		// checked out (the default branch) that decides what is analyzed, never the override.
		cfg, warnings, err := repoconfig.Load(absTarget)
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %s: %s\n", repoconfig.DefaultPath, w)
		}
		if cfg.Analyze.Ref != "" {
			dir, commit, done, err := checkout.NewGitCheckout().WorktreeAtRef(ctx, absTarget, cfg.Analyze.Ref)
			if err != nil {
				return nil, fmt.Errorf("%s: analyze.ref %q could not be checked out: %w", repoconfig.DefaultPath, cfg.Analyze.Ref, err)
			}
			scanDir, cleanup = dir, done
			analyzeRef, analyzedCommit = cfg.Analyze.Ref, commit
		}
		plan, err := checkout.ResolveVendored(scanDir)
		if err != nil {
			cleanup()
			if analyzeRef != "" {
				return nil, fmt.Errorf("%s: analyze.ref %q: %w", repoconfig.DefaultPath, analyzeRef, err)
			}
			return nil, err
		}
		if analyzeRef != "" {
			// Provenance is taken from the tree the plan will actually be analyzed from, not
			// from what the fetch said it put there: re-resolve HEAD at the plan root and
			// refuse to label the Report with a commit the analyzed tree does not have.
			head, err := checkout.ResolveHead(ctx, plan.Root)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("%s: analyze.ref %q: %w", repoconfig.DefaultPath, analyzeRef, err)
			}
			if head != analyzedCommit {
				cleanup()
				return nil, fmt.Errorf("%s: analyze.ref %q: analyzed tree %q is at %q, expected %s", repoconfig.DefaultPath, analyzeRef, plan.Root, head, analyzedCommit)
			}
			fmt.Fprintf(os.Stdout, "%s: analyze.ref %q — analyzing commit %s, not the checked-out tree\n", repoconfig.DefaultPath, analyzeRef, analyzedCommit)
		}
		prim := plan.Primary()
		buildDir, language = prim.Root, prim.Language
		repo = filepath.Base(absTarget)
	}
	if repoOverride != "" {
		repo = repoOverride
	}

	var cfOpts []plugin.CFamilyOption
	if language == checkout.LangCFamily {
		if dir := scanWasmCacheDir(); dir != "" {
			prev := cleanup
			cleanup = func() { prev(); _ = os.RemoveAll(dir) }
			cfOpts = append(cfOpts, plugin.WithCFamilyWasmCacheDir(dir))
		}
	}
	var graph *jvmGraph
	var graphTime time.Duration
	if language == checkout.LangJava || language == checkout.LangKotlin {
		var done func()
		graphStart := time.Now()
		graph, done = acquireBuildGraph(ctx, buildDir, graphReq)
		graphTime = time.Since(graphStart)
		logPhase(os.Stderr, "graph", graphTime)
		prev := cleanup
		cleanup = func() { done(); prev() }
	}
	if language == checkout.LangDotNet {
		restoreDotNet(ctx, buildDir, os.Stderr)
	}
	var goOpts []plugin.Option
	if language == checkout.LangGo {
		dir := scanRunCacheDir("go")
		if dir != "" {
			prev := cleanup
			cleanup = func() { prev(); _ = os.RemoveAll(dir) }
		}
		goOpts = append(goOpts, plugin.WithRunCacheDir(dir))
	}
	var jsOpts []plugin.JSOption
	if language == checkout.LangJS {
		dir := scanRunCacheDir("js")
		if dir != "" {
			prev := cleanup
			cleanup = func() { prev(); _ = os.RemoveAll(dir) }
		}
		jsOpts = append(jsOpts, plugin.WithJSRunCacheDir(dir))
	}
	var pyOpts []plugin.PythonOption
	if language == checkout.LangPython {
		dir := scanRunCacheDir("python")
		if dir != "" {
			prev := cleanup
			cleanup = func() { prev(); _ = os.RemoveAll(dir) }
		}
		pyOpts = append(pyOpts, plugin.WithPythonRunCacheDir(dir))
	}
	lp, err := selectPlugin(language, pluginBin, graph, goOpts, jsOpts, pyOpts, cfOpts...)
	if err != nil {
		cleanup()
		var missing *plugin.NotInstalledError
		if errors.As(err, &missing) && !releaseLanguage(language) {
			return nil, &analyzerMissingError{
				acq:     acquired{language: language, repo: repo, analyzeRef: analyzeRef, analyzedCommit: analyzedCommit},
				missing: missing,
			}
		}
		return nil, err
	}
	logPhase(os.Stderr, "acquire", time.Since(start)-graphTime)

	return &acquired{
		buildDir:   buildDir,
		language:   language,
		plugin:     plugin.Memoize(lp),
		repo:       repo,
		advisories: houseCanaries(language, includeHouseCanaries),
		cleanup:    cleanup,

		analyzeRef:     analyzeRef,
		analyzedCommit: analyzedCommit,
		graph:          graph,
	}, nil
}

// supportedLanguages is every language the release claims. A language belongs here exactly when the
// tarball bakes an analyzer plugin for it (scripts/build-release.sh BAKED_TARGETS) — the two lists
// are the same claim made in two places, and language_support_test.go is where the claim is tested.
var supportedLanguages = []string{
	checkout.LangGo,
	checkout.LangJava,
	checkout.LangKotlin,
	checkout.LangJS,
	checkout.LangPython,
	checkout.LangDotNet,
}

// releaseLanguage reports whether the release ships an analyzer for language.
func releaseLanguage(language string) bool {
	return slices.Contains(supportedLanguages, language)
}

// analyzerMissingError is acquireTarget's error for a tree whose detected language is outside the
// release (C/C++ today) and has no analyzer plugin installed. Nothing can be assessed, so the run
// publishes a Report that says so (publishAnalyzerMissing) instead of failing. A release language
// whose analyzer is missing is an install fault, not this: acquireTarget returns the plugin error and
// the run fails without replacing what an earlier run published. acq carries only what the Report
// needs: the language and the subject's identity and provenance. The tree itself was already cleaned
// up.
type analyzerMissingError struct {
	acq     acquired
	missing *plugin.NotInstalledError
}

func (e *analyzerMissingError) Error() string { return e.missing.Error() }

func (e *analyzerMissingError) Unwrap() error { return e.missing }

// selectPlugin constructs the subprocess-backed analyzer client for the detected language.
// A non-empty bin is an explicit path to that language's assay-plugin-<lang> binary
// (the -plugin-go flag); when empty each constructor discovers its binary on PATH, and one that is
// not there is a *plugin.NotInstalledError. Only one plugin runs per scan (the tree is a single
// language), so a single override suffices. cfOpts apply to the C-family plugin only, goOpts to the
// Go plugin only.
func selectPlugin(language, bin string, graph *jvmGraph, goOpts []plugin.Option, jsOpts []plugin.JSOption, pyOpts []plugin.PythonOption, cfOpts ...plugin.CFamilyOption) (plugin.LanguagePlugin, error) {
	var graphFile string
	if graph != nil {
		graphFile = graph.file
	}
	switch language {
	case checkout.LangGo:
		if bin != "" {
			goOpts = append(goOpts, plugin.WithBinaryPath(bin))
		}
		return plugin.NewGoPlugin(goOpts...)
	case checkout.LangJava:
		opts := []plugin.JavaOption{plugin.WithJavaBuildGraph(graphFile)}
		if bin != "" {
			opts = append(opts, plugin.WithJavaBinaryPath(bin))
		}
		return plugin.NewJavaPlugin(opts...)
	case checkout.LangKotlin:
		opts := []plugin.KotlinOption{plugin.WithKotlinBuildGraph(graphFile)}
		if bin != "" {
			opts = append(opts, plugin.WithKotlinBinaryPath(bin))
		}
		return plugin.NewKotlinPlugin(opts...)
	case checkout.LangJS:
		if bin != "" {
			jsOpts = append(jsOpts, plugin.WithJSBinaryPath(bin))
		}
		return plugin.NewJSPlugin(jsOpts...)
	case checkout.LangPython:
		if bin != "" {
			pyOpts = append(pyOpts, plugin.WithPythonBinaryPath(bin))
		}
		return plugin.NewPythonPlugin(pyOpts...)
	case checkout.LangDotNet:
		if bin != "" {
			return plugin.NewDotNetPlugin(plugin.WithDotNetBinaryPath(bin))
		}
		return plugin.NewDotNetPlugin()
	case checkout.LangCFamily:
		if bin != "" {
			cfOpts = append(cfOpts, plugin.WithCFamilyBinaryPath(bin))
		}
		return plugin.NewCFamilyPlugin(cfOpts...)
	default:
		return nil, fmt.Errorf("no analyzer plugin for detected source language %q", language)
	}
}

// envCFamilyWasmCacheDir is plugin.CFamilyWasmCacheDirEnv, read here where the operator sets it.
const envCFamilyWasmCacheDir = brand.EnvPrefix + "_CFAMILY_CGX_WASM_CACHE_DIR"

// scanWasmCacheDir creates the private directory one scan's C-family subprocesses share their
// compiled wasm module through, so only the first of them compiles it. The caller removes it
// when the scan ends. An operator-set CFamilyWasmCacheDirEnv wins, and then nothing is created.
// A directory that cannot be created leaves every spawn compiling cold, which is slower and
// changes no result.
func scanWasmCacheDir() string {
	if os.Getenv(envCFamilyWasmCacheDir) != "" {
		return ""
	}
	dir, err := os.MkdirTemp("", "assay-cfamily-wasm-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cfamily wasm cache dir: %v; each analysis step compiles the module\n", err)
		return ""
	}
	return dir
}

// scanRunCacheDir creates the private directory one scan's analyzer subprocesses for lang share
// per-tree results through (plugin.WithRunCacheDir, plugin.WithJSRunCacheDir, plugin.WithPythonRunCacheDir). The caller removes
// it when the scan ends.
// Unlike the wasm cache it is never taken from the operator: its entries are keyed on the build
// directory's path, so a directory that outlived one scan could answer for another tree at that
// path. A directory that cannot be created leaves every advisory computing its own, which is slower
// and changes no result.
func scanRunCacheDir(lang string) string {
	dir, err := os.MkdirTemp("", "assay-"+lang+"-run-cache-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s run cache dir: %v; each advisory rescans the tree\n", lang, err)
		return ""
	}
	return dir
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

// houseCanaries returns the first-party house canaries for a target of the given language when the
// scan opted them in (-include-house-canaries), and nil otherwise. The binary carries no other
// advisory membership: real work comes from a corpus (its policy) or the OSV widening in
// workset.go, and a run given neither halts at errEmptyWorkSet unless the canaries populate its set.
//
// The canaries are language-scoped because each names a package in one ecosystem; a Go canary
// would resolve nothing in a Java tree. They are first-party demo records, not sourced from a feed:
// mostly sinks and dependencies over com.example / tegron-corpus / stand-in packages, a few
// mirroring a public advisory, that our own demo scan uses to drive enumerate, fire, prove and
// auto-fix end to end. Even opted in they stay
// candidate-only at the scan tier; proof comes from the fire. Kotlin's canary has no facts in
// pipeline's canary source, so it evaluates as unresolved; C-family has none.
func houseCanaries(language string, include bool) []assessment.VulnRef {
	if !include {
		return nil
	}
	switch language {
	case checkout.LangGo:
		return []assessment.VulnRef{
			{ID: "FERRALON-APP-DOS-0001", Source: "osv"}, // tegron/corpus/dos — unbounded allocation sink, application reachability
		}
	case checkout.LangJava:
		return []assessment.VulnRef{
			{ID: "FERRALON-JAVA-SSRF-0001", Source: "osv"},        // com.example.web/ssrf — UrlFetcher.fetch taint reachability
			{ID: "FERRALON-JAVA-SPRING-SSRF-0001", Source: "osv"}, // com.example.web/spring-ssrf — Spring SSRF taint reachability
			{ID: "FERRALON-JAVA-DEP-0001", Source: "osv"},         // com.example.lib:widget — version-resolvable Maven dependency
		}
	case checkout.LangKotlin:
		return []assessment.VulnRef{
			{ID: "FERRALON-KOTLIN-DEP-0001", Source: "osv"}, // com.example.lib:widget — version-resolvable Maven dependency
		}
	case checkout.LangJS:
		return []assessment.VulnRef{
			{ID: "FERRALON-JS-SSRF-0001", Source: "osv"}, // tegron-corpus-ssrf — SSRF taint reachability
			{ID: "FERRALON-JS-DEP-0001", Source: "osv"},  // left-pad — version-resolvable npm dependency
		}
	case checkout.LangPython:
		return []assessment.VulnRef{
			{ID: "FERRALON-PY-AIRFLOW-EXPAPI-0001", Source: "ghsa"}, // apache-airflow — experimental-API get_code sink, first-party reachability
			{ID: "FERRALON-PY-DEP-0001", Source: "osv"},             // flask — version-resolvable PyPI dependency
		}
	case checkout.LangDotNet:
		return []assessment.VulnRef{
			{ID: "FERRALON-NET-DEP-0001", Source: "osv"}, // Newtonsoft.Json — version-resolvable NuGet dependency
		}
	default:
		return nil
	}
}
