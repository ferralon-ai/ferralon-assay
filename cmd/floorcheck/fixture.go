package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// Fixture formats. A fixture is a directory floor/fixtures/<owner>__<repo>@<sha12>/ holding a
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

// ScenarioBuild pins the subject's build. Go is the toolchain version without its "go" prefix.
type ScenarioBuild struct {
	Go     string `yaml:"go,omitempty"`
	GOOS   string `yaml:"goos,omitempty"`
	GOARCH string `yaml:"goarch,omitempty"`
	CGO    *bool  `yaml:"cgo,omitempty"`
}

// ScenarioIntel names the intelligence the scan reads. Corpus and Signals are relative to the floor
// root and must resolve under its intel/ directory; Advisories is relative to the fixture and stays
// inside it. Exactly one of Corpus and Advisories is the scan's -advisory-corpus: the scanner reads one
// source and layers none.
type ScenarioIntel struct {
	Policy     string      `yaml:"policy"`
	Corpus     *PinnedFile `yaml:"corpus,omitempty"`
	Signals    *PinnedFile `yaml:"signals,omitempty"`
	Advisories string      `yaml:"advisories,omitempty"`
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
	goVersion  = regexp.MustCompile(`^1\.[0-9]+(\.[0-9]+|rc[0-9]+)?$`)
)

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
	b := s.Build
	if s.Lang == "go" && (b.Go == "" || b.GOOS == "" || b.GOARCH == "" || b.CGO == nil) {
		return errors.New("a go scenario pins build.go, build.goos, build.goarch and build.cgo")
	}
	if b.Go != "" && !goVersion.MatchString(b.Go) {
		return fmt.Errorf("build.go %q is not a Go version such as 1.23.12", b.Go)
	}
	for _, p := range []*PinnedFile{s.Intel.Corpus, s.Intel.Signals} {
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

// subjectRepo is owner/name from a repository URL.
func subjectRepo(repo string) (string, error) {
	s := strings.TrimSuffix(strings.TrimSuffix(repo, "/"), ".git")
	i := strings.Index(s, "://")
	if i < 0 {
		return "", fmt.Errorf("repo %q is not a URL", repo)
	}
	parts := strings.Split(s[i+3:], "/")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("repo %q is not https://<host>/<owner>/<name>", repo)
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
	case in.Corpus != nil && in.Advisories != "":
		return unverified("intel names both a corpus bundle and an advisories directory; the scanner reads one")
	case in.Corpus == nil && in.Advisories == "":
		return unverified("intel names no corpus: a fixture without one is incomplete")
	}
	if in.Corpus != nil {
		p, err := verifyPinned(floorRoot, *in.Corpus)
		if err != nil {
			return unverified("intel.corpus: %w", err)
		}
		fx.CorpusPath = p
	} else {
		p, err := containedPath(fx.Dir, in.Advisories)
		if err != nil {
			return unverified("intel.advisories: %w", err)
		}
		if err := verifyAdvisoryDir(p); err != nil {
			return unverified("intel.advisories: %w", err)
		}
		fx.CorpusPath = p
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
// record against its pinned digest now rather than per lookup.
func verifyAdvisoryDir(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	var m dirManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	switch {
	case len(m.Records) == 0 && len(m.Advisories) > 0:
		return errors.New("manifest.json indexes advisories in the test-fixture shape (advisories{}), which the scanner does not read; it needs records[]")
	case len(m.Records) == 0:
		return errors.New("manifest.json holds no records")
	case m.RecordCount != len(m.Records):
		return fmt.Errorf("manifest.json: record_count %d, %d records", m.RecordCount, len(m.Records))
	}
	seen := map[string]bool{}
	for _, r := range m.Records {
		if seen[r.Identifier] {
			return fmt.Errorf("manifest.json: duplicate identifier %q", r.Identifier)
		}
		seen[r.Identifier] = true
		p, err := containedPath(dir, r.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", r.Identifier, err)
		}
		got, err := fileSHA256(p)
		if err != nil {
			return err
		}
		if "sha256:"+got != r.OutputDigest {
			return fmt.Errorf("%s: digest sha256:%s, manifest pins %s", r.Path, got, r.OutputDigest)
		}
	}
	return nil
}
