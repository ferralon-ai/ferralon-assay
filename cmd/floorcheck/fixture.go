package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// Fixture formats. A fixture is a directory cmd/floorcheck/fixtures/<owner>__<repo>@<sha12>/ holding a
// scenario.yaml (the pinned inputs) and an expect.yaml (the adjudicated truth for a few findings).
const (
	ScenarioSchema = "ferralon.floor-scenario.v1"
	ExpectSchema   = "ferralon.floor-expect.v1"

	fileScenario = "scenario.yaml"
	fileExpect   = "expect.yaml"
	// intelDir is the directory under the floor root holding one copy of each corpus release's bundle
	// and signals, shared by every fixture that pins it.
	intelDir = "intel"
)

// Scenario is scenario.yaml: what a fixture scans, under which toolchain, with which intelligence.
type Scenario struct {
	Schema string        `yaml:"schema"`
	Repo   string        `yaml:"repo"`
	Commit string        `yaml:"commit"`
	Lang   string        `yaml:"lang"`
	Build  ScenarioBuild `yaml:"build"`
	Intel  ScenarioIntel `yaml:"intel"`
	Scan   ScenarioScan  `yaml:"scan"`
}

// ScenarioBuild pins the subject's build. Go is the exact toolchain version without its "go" prefix;
// the go fields belong to the go lane only. JDK, Node and Python are the runtime majors (Python
// major.minor) the CI matrix installs, each for its own lane only.
type ScenarioBuild struct {
	Go     string `yaml:"go,omitempty"`
	GOOS   string `yaml:"goos,omitempty"`
	GOARCH string `yaml:"goarch,omitempty"`
	CGO    *bool  `yaml:"cgo,omitempty"`
	JDK    string `yaml:"jdk,omitempty"`
	Node   string `yaml:"node,omitempty"`
	Python string `yaml:"python,omitempty"`
}

// ScenarioIntel names the intelligence the scan reads. Corpus and Signals are relative to the floor
// root and must resolve under its intel/ directory. Advisories pins a directory corpus's manifest.json,
// relative to the fixture and inside it; the directory holding it is the corpus. Exactly one of Corpus
// and Advisories is the scan's -advisory-corpus: the scanner reads one source and layers none.
type ScenarioIntel struct {
	Policy     string      `yaml:"policy"`
	Corpus     *PinnedFile `yaml:"corpus,omitempty"`
	Signals    *PinnedFile `yaml:"signals,omitempty"`
	Advisories *PinnedFile `yaml:"advisories,omitempty"`
	Provenance string      `yaml:"provenance,omitempty"`
}

// PinnedFile is an intel file by path and the sha256 of its exact bytes (64 lowercase hex).
type PinnedFile struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
}

// ScenarioScan carries extra scanner flags.
type ScenarioScan struct {
	Flags []string `yaml:"flags,omitempty"`
}

// Expect is expect.yaml: sparse, adjudicated expectations.
type Expect struct {
	Schema string `yaml:"schema"`
	// Scan is "complete" (no tool failure, not cut short) or "partial", which tolerates exactly the
	// failure reasons listed in Partiality.
	Scan       string        `yaml:"scan"`
	Partiality []string      `yaml:"partiality,omitempty"`
	Findings   []Expectation `yaml:"findings"`
}

// Expectation is the truth about one finding and the worst verdict accepted today.
type Expectation struct {
	// Advisory is matched against a finding's id and its aliases.
	Advisory string `yaml:"advisory"`
	// Package is the package instance, as packageInstance renders it (module@version).
	Package string         `yaml:"package"`
	Truth   string         `yaml:"truth"`
	Floor   report.Verdict `yaml:"floor"`
	// Basis, when set, is the basis a finding at the truth's best verdict must carry.
	Basis  verdict.NonExploitableBasis `yaml:"basis,omitempty"`
	Review *Review                     `yaml:"review,omitempty"`
	Note   string                      `yaml:"note,omitempty"`
}

// Review records who adjudicated an expectation and the call path they read.
type Review struct {
	By      string `yaml:"by"`
	Date    string `yaml:"date,omitempty"`
	PathSHA string `yaml:"path_sha,omitempty"`
	Packet  string `yaml:"packet,omitempty"`
}

// Truths an expectation may state, besides TruthReachable (shared with the ledger).
const (
	TruthUnreachable = "unreachable"
	TruthNotAffected = "not_affected"
)

// Expected scan completeness.
const (
	ScanComplete = "complete"
	ScanPartial  = "partial"
)

var (
	fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	goVersion  = regexp.MustCompile(`^1\.[0-9]+\.[0-9]+$`)
	majorOnly  = regexp.MustCompile(`^[1-9][0-9]*$`)
	pyVersion  = regexp.MustCompile(`^3\.[0-9]+$`)
	ghName     = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]*$`)
)

// runtimeLane is the lang each non-go build field belongs to.
var runtimeLane = map[string][]string{
	"jdk":    {"java", "kotlin"},
	"node":   {"js"},
	"python": {"python"},
}

// harnessFlags are the scanner flags the harness sets itself; scan.flags may not restate them.
var harnessFlags = []string{
	"target", "out", "subject-repo", "revision", "commit", "advisory-corpus", "advisory-corpus-policy",
	"advisory-signals", "require-advisory-corpus", "scan-timeout",
}

// Fixture is a loaded, verified fixture.
type Fixture struct {
	Name     string
	Dir      string
	Scenario Scenario
	Expect   Expect
	// CorpusPath is what the scan passes as -advisory-corpus; SignalsPath as -advisory-signals ("" for
	// none). Both are absolute and verified against their pins.
	CorpusPath  string
	SignalsPath string
	// AdvisoryIDs are the identifiers an advisories directory holds: the advisories the scan must
	// assess. Empty for a corpus bundle.
	AdvisoryIDs []string
}

// loadError is a fixture that cannot be compared: the kind is the incomplete kind it reports.
type loadError struct {
	kind string
	err  error
}

func (e *loadError) Error() string { return e.err.Error() }
func (e *loadError) Unwrap() error { return e.err }

// Incomplete kinds a fixture adds to the scan's own completeness kinds.
const (
	KindFixtureInvalid  = "fixture_invalid"
	KindIntelUnverified = "intel_unverified"
	KindCheckoutFailed  = "checkout_failed"
	KindSubjectMismatch = "subject_mismatch"
	KindMissingFinding  = "missing_finding"
	// KindObservationFailed is a fixture whose result.json could not be written.
	KindObservationFailed = "observation_failed"
)

func invalid(format string, a ...any) error {
	return &loadError{kind: KindFixtureInvalid, err: fmt.Errorf(format, a...)}
}

func unverified(format string, a ...any) error {
	return &loadError{kind: KindIntelUnverified, err: fmt.Errorf(format, a...)}
}

// loadKind is the incomplete kind of a loadFixture error.
func loadKind(err error) string {
	var le *loadError
	if errors.As(err, &le) {
		return le.kind
	}
	return KindFixtureInvalid
}

// loadFixture reads a fixture directory, validates both files, and verifies every intel pin. Shared
// corpus and signals files resolve under floorRoot/intel; fixture-local advisories inside dir. It
// reads intel only to hash it, so a fixture that loads is one whose scan inputs are what it pins.
func loadFixture(dir, floorRoot string, rules orderRules) (Fixture, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Fixture{}, invalid("%s: %w", dir, err)
	}
	fx := Fixture{Name: filepath.Base(abs), Dir: abs}
	if err := decodeStrict(filepath.Join(abs, fileScenario), &fx.Scenario); err != nil {
		return Fixture{}, invalid("%w", err)
	}
	if err := fx.Scenario.validate(); err != nil {
		return Fixture{}, invalid("%s: %w", fileScenario, err)
	}
	if err := decodeStrict(filepath.Join(abs, fileExpect), &fx.Expect); err != nil {
		return Fixture{}, invalid("%w", err)
	}
	if err := fx.Expect.validate(rules); err != nil {
		return Fixture{}, invalid("%s: %w", fileExpect, err)
	}
	if err := fx.verifyIntel(floorRoot); err != nil {
		return Fixture{}, err
	}
	return fx, nil
}

// decodeStrict decodes one YAML document, refusing unknown fields.
func decodeStrict(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func (s Scenario) validate() error {
	switch {
	case s.Schema != ScenarioSchema:
		return fmt.Errorf("schema %q, want %s", s.Schema, ScenarioSchema)
	case s.Repo == "":
		return errors.New("repo is required")
	case !fullCommit.MatchString(s.Commit):
		return fmt.Errorf("commit %q is not a full 40-hex commit", s.Commit)
	case s.Lang == "":
		return errors.New("lang is required")
	case s.Intel.Policy == "":
		return errors.New("intel.policy is required")
	}
	if _, err := subjectRepo(s.Repo); err != nil {
		return err
	}
	if err := s.Build.validate(s.Lang); err != nil {
		return err
	}
	for _, p := range []*PinnedFile{s.Intel.Corpus, s.Intel.Signals, s.Intel.Advisories} {
		if p != nil && !sha256Hex.MatchString(p.SHA256) {
			return fmt.Errorf("intel file %s: sha256 %q is not 64 lowercase hex", p.Path, p.SHA256)
		}
	}
	for _, f := range s.Scan.Flags {
		name := strings.TrimLeft(f, "-")
		name, _, _ = strings.Cut(name, "=")
		if strings.HasPrefix(f, "-") && slices.Contains(harnessFlags, name) {
			return fmt.Errorf("scan.flags sets -%s, which the harness sets from the scenario", name)
		}
	}
	return nil
}

func (b ScenarioBuild) validate(lang string) error {
	goSet := b.Go != "" || b.GOOS != "" || b.GOARCH != "" || b.CGO != nil
	switch {
	case lang == "go" && (b.Go == "" || b.GOOS == "" || b.GOARCH == "" || b.CGO == nil):
		return errors.New("a go scenario pins build.go, build.goos, build.goarch and build.cgo")
	case lang != "go" && goSet:
		return fmt.Errorf("build.go, goos, goarch and cgo belong to the go lane, not %s", lang)
	case b.Go != "" && !goVersion.MatchString(b.Go):
		return fmt.Errorf("build.go %q is not an exact Go version such as 1.23.12", b.Go)
	case b.JDK != "" && !majorOnly.MatchString(b.JDK):
		return fmt.Errorf("build.jdk %q is not a JDK major such as 17", b.JDK)
	case b.Node != "" && !majorOnly.MatchString(b.Node):
		return fmt.Errorf("build.node %q is not a Node major such as 20", b.Node)
	case b.Python != "" && !pyVersion.MatchString(b.Python):
		return fmt.Errorf("build.python %q is not a Python version such as 3.12", b.Python)
	}
	for field, v := range map[string]string{"jdk": b.JDK, "node": b.Node, "python": b.Python} {
		if v != "" && !slices.Contains(runtimeLane[field], lang) {
			return fmt.Errorf("build.%s belongs to the %s lane, not %s", field, strings.Join(runtimeLane[field], "/"), lang)
		}
	}
	return nil
}

// subjectRepo is owner/name from a repository URL, which must be https://<host>/<owner>/<name>
// (an optional .git suffix) with nothing git could read as an option or a transport.
func subjectRepo(repo string) (string, error) {
	bad := fmt.Errorf("repo %q is not https://<host>/<owner>/<name>", repo)
	if strings.HasPrefix(repo, "-") || strings.ContainsFunc(repo, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return "", bad
	}
	u, err := url.Parse(repo)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Host, "@") {
		return "", bad
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git"), "/")
	if len(parts) != 3 || parts[0] != "" || !ghName.MatchString(parts[1]) || !ghName.MatchString(parts[2]) ||
		strings.Trim(parts[1], ".") == "" || strings.Trim(parts[2], ".") == "" {
		return "", bad
	}
	return parts[1] + "/" + parts[2], nil
}

func (e Expect) validate(rules orderRules) error {
	if e.Schema != ExpectSchema {
		return fmt.Errorf("schema %q, want %s", e.Schema, ExpectSchema)
	}
	switch e.Scan {
	case ScanComplete:
		if len(e.Partiality) > 0 {
			return errors.New("scan: complete lists partiality reasons; use scan: partial")
		}
	case ScanPartial:
		if len(e.Partiality) == 0 {
			return errors.New("scan: partial lists no partiality reasons")
		}
	default:
		return fmt.Errorf("scan %q, want %s or %s", e.Scan, ScanComplete, ScanPartial)
	}
	seen := map[string]bool{}
	for i, x := range e.Findings {
		if err := x.validate(rules); err != nil {
			return fmt.Errorf("findings[%d] %s %s: %w", i, x.Advisory, x.Package, err)
		}
		k := x.Advisory + " " + x.Package
		if seen[k] {
			return fmt.Errorf("findings[%d]: a second expectation for %s", i, k)
		}
		seen[k] = true
	}
	return nil
}

func (x Expectation) validate(rules orderRules) error {
	switch {
	case x.Advisory == "":
		return errors.New("advisory is required")
	case x.Package == "":
		return errors.New("package is required")
	case !slices.Contains([]string{TruthReachable, TruthUnreachable, TruthNotAffected}, x.Truth):
		return fmt.Errorf("truth %q, want %s, %s or %s", x.Truth, TruthReachable, TruthUnreachable, TruthNotAffected)
	}
	if _, ok := rules.rank(x.Truth, x.Floor); !ok {
		return fmt.Errorf("floor %q is always wrong for truth %s", x.Floor, x.Truth)
	}
	if x.Basis != verdict.BasisNone && !slices.ContainsFunc(rules.best(x.Truth), basisCarrier) {
		return fmt.Errorf("basis %s is set, but the best verdict for truth %s carries no basis", x.Basis, x.Truth)
	}
	if r := x.Review; r != nil {
		if r.By == "" {
			return errors.New("review.by is required")
		}
		if r.Packet != "" {
			if err := localPath(r.Packet); err != nil {
				return fmt.Errorf("review.packet: %w", err)
			}
		}
	}
	return nil
}

func basisCarrier(v report.Verdict) bool {
	return v == report.VerdictNotExploitable || v == report.VerdictDisqualified
}

// localPath refuses a path that is absolute or climbs out of the directory it is relative to.
func localPath(rel string) error {
	if rel == "" {
		return errors.New("empty path")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return fmt.Errorf("%q is absolute", rel)
	}
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return fmt.Errorf("%q leaves its directory", rel)
	}
	return nil
}

// containedPath resolves rel under base and refuses it unless it, symlinks followed, stays inside
// base and exists.
func containedPath(base, rel string) (string, error) {
	if err := localPath(rel); err != nil {
		return "", err
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(realBase, real); err != nil || !filepath.IsLocal(r) {
		return "", fmt.Errorf("%q resolves outside %s", rel, base)
	}
	return real, nil
}

// verifyIntel resolves and verifies every intel file the scenario names, before any scan. A missing
// corpus is unverified, never a fallback.
func (fx *Fixture) verifyIntel(floorRoot string) error {
	in := fx.Scenario.Intel
	switch {
	case in.Corpus != nil && in.Advisories != nil:
		return unverified("intel names both a corpus bundle and an advisories directory; the scanner reads one")
	case in.Corpus == nil && in.Advisories == nil:
		return unverified("intel names no corpus: a fixture without one is incomplete")
	}
	if in.Corpus != nil {
		p, err := verifyPinned(floorRoot, *in.Corpus)
		if err != nil {
			return unverified("intel.corpus: %w", err)
		}
		fx.CorpusPath = p
	} else {
		dir, ids, err := verifyAdvisories(fx.Dir, *in.Advisories, in.Signals != nil)
		if err != nil {
			return unverified("intel.advisories: %w", err)
		}
		fx.CorpusPath, fx.AdvisoryIDs = dir, ids
	}
	if in.Signals != nil {
		p, err := verifyPinned(floorRoot, *in.Signals)
		if err != nil {
			return unverified("intel.signals: %w", err)
		}
		fx.SignalsPath = p
	}
	return nil
}

// verifyAdvisories verifies a fixture-local directory corpus: its manifest.json against the pin, then
// every record against the manifest. The scanner reads <dir>/signals.json when no signals are passed,
// so one there is refused unless intel.signals pins the signals the scan uses instead.
func verifyAdvisories(fixtureDir string, pf PinnedFile, signalsPinned bool) (string, []string, error) {
	if filepath.Base(filepath.FromSlash(pf.Path)) != "manifest.json" {
		return "", nil, fmt.Errorf("%q: pin the corpus directory's manifest.json", pf.Path)
	}
	manifest, err := containedPath(fixtureDir, pf.Path)
	if err != nil {
		return "", nil, err
	}
	got, err := fileSHA256(manifest)
	if err != nil {
		return "", nil, err
	}
	if got != pf.SHA256 {
		return "", nil, fmt.Errorf("%s: sha256 %s, scenario pins %s", pf.Path, got, pf.SHA256)
	}
	dir := filepath.Dir(manifest)
	if _, err := os.Lstat(filepath.Join(dir, "signals.json")); err == nil && !signalsPinned {
		return "", nil, errors.New("the directory holds a signals.json the scanner would read unpinned; pin it as intel.signals")
	}
	ids, err := verifyAdvisoryDir(dir)
	if err != nil {
		return "", nil, err
	}
	return dir, ids, nil
}

// verifyPinned resolves a shared intel file relative to the floor root, refuses it unless it lands under
// the root's intel/ directory, and checks its digest.
func verifyPinned(floorRoot string, pf PinnedFile) (string, error) {
	p, err := containedPath(floorRoot, pf.Path)
	if err != nil {
		return "", err
	}
	intel, err := filepath.EvalSymlinks(filepath.Join(floorRoot, intelDir))
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(intel, p); err != nil || !filepath.IsLocal(r) {
		return "", fmt.Errorf("%q resolves outside %s/", pf.Path, intelDir)
	}
	got, err := fileSHA256(p)
	if err != nil {
		return "", err
	}
	if got != pf.SHA256 {
		return "", fmt.Errorf("%s: sha256 %s, scenario pins %s", pf.Path, got, pf.SHA256)
	}
	return p, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dirManifest is the part of a directory corpus's manifest.json the scanner indexes
// (pipeline.advisoryManifest): records located by path and pinned by output_digest.
type dirManifest struct {
	SchemaVersion string `json:"schema_version"`
	RecordCount   int    `json:"record_count"`
	Records       []struct {
		Identifier   string `json:"identifier"`
		Path         string `json:"path"`
		OutputDigest string `json:"output_digest"`
	} `json:"records"`
	// Advisories is the test-fixture index shape (internal/advisorytest), which the scanner does not
	// read: a directory carrying only it scans as an empty corpus.
	Advisories map[string]json.RawMessage `json:"advisories"`
}

// verifyAdvisoryDir checks a directory corpus the way the scanner will read it, and verifies every
// record against its pinned digest now rather than per lookup. Each record must then resolve through
// the scanner's own reader and name an affected package: a record the scanner drops, or one it cannot
// match to a dependency, would leave the fixture with nothing to assess. It returns the identifiers.
func verifyAdvisoryDir(dir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m dirManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	switch {
	case len(m.Records) == 0 && len(m.Advisories) > 0:
		return nil, errors.New("manifest.json indexes advisories in the test-fixture shape (advisories{}), which the scanner does not read; it needs records[]")
	case len(m.Records) == 0:
		return nil, errors.New("manifest.json holds no records")
	case m.RecordCount != len(m.Records):
		return nil, fmt.Errorf("manifest.json: record_count %d, %d records", m.RecordCount, len(m.Records))
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(m.Records))
	for _, r := range m.Records {
		if seen[r.Identifier] {
			return nil, fmt.Errorf("manifest.json: duplicate identifier %q", r.Identifier)
		}
		seen[r.Identifier] = true
		ids = append(ids, r.Identifier)
		p, err := containedPath(dir, r.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Identifier, err)
		}
		got, err := fileSHA256(p)
		if err != nil {
			return nil, err
		}
		if "sha256:"+got != r.OutputDigest {
			return nil, fmt.Errorf("%s: digest sha256:%s, manifest pins %s", r.Path, got, r.OutputDigest)
		}
	}
	src := pipeline.NewArtifactSource(dir)
	for _, id := range ids {
		facts, ok := src.Lookup(id)
		if !ok {
			return nil, fmt.Errorf("%s: the scanner does not read this record", id)
		}
		if len(pipeline.AffectedPackageKeys(facts)) == 0 {
			return nil, fmt.Errorf("%s: the record names no affected package, so no scan can assess it", id)
		}
	}
	return ids, nil
}
