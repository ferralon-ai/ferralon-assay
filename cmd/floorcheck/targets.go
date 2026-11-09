package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Targets is floor/targets.json: the demo repositories the nightly floor run scans and the corpus
// policy they use, the pinned lane of real repositories, and the repositories deliberately left out,
// each with its reason.
type Targets struct {
	// Policy is the advisory-corpus policy the demo targets read. It is the policy the demo
	// repositories' own ferralon-assay.yml workflows use, and never `full`: a demo repository's
	// default branch moves, so the lane stays bounded by its policy.
	Policy   string     `json:"policy"`
	Targets  []Target   `json:"targets"`
	Pinned   *Lane      `json:"pinned,omitempty"`
	Excluded []Excluded `json:"excluded,omitempty"`
}

// Lane is the pinned lane: real public repositories, each at a full commit, scanned under their own
// policy. Every target is a fixed commit, so the lane is bounded by its targets and may read `full`;
// it measures what Assay finds on real code under the whole corpus.
type Lane struct {
	Policy  string   `json:"policy"`
	Targets []Target `json:"targets"`
}

// lane is one policy and the targets scanned under it.
type lane struct {
	policy  string
	targets []Target
}

// lanes is every lane in run order: the demo targets, then the pinned lane when there is one.
func (t Targets) lanes() []lane {
	out := []lane{{t.Policy, t.Targets}}
	if t.Pinned != nil {
		out = append(out, lane{t.Pinned.Policy, t.Pinned.Targets})
	}
	return out
}

// Target is one repository the floor run scans.
type Target struct {
	// Repo is owner/name on GitHub.
	Repo string `json:"repo"`
	// Language is the language the repository's build files show, in Assay's language vocabulary.
	Language string `json:"language"`
	// Ref is the branch, tag or commit to scan. Empty is the default branch.
	Ref string `json:"ref,omitempty"`
	// IncludeHouseCanaries mirrors the repository's own workflow setting include-house-canaries.
	IncludeHouseCanaries bool `json:"include_house_canaries,omitempty"`
}

// Excluded is a demo repository the floor run does not scan, and why.
type Excluded struct {
	Repo   string `json:"repo"`
	Reason string `json:"reason"`
}

// Name is the repository name without its owner. It names the target's scan job and artifact, so
// it is unique within a targets file.
func (t Target) Name() string {
	_, name, _ := strings.Cut(t.Repo, "/")
	return name
}

// languages is every language the summary reports on, in display order: Assay's analyzer languages
// (checkout.Lang*) and Rust, which has no analyzer. A language with no target is shown as a gap.
var languages = []string{"go", "java", "kotlin", "js", "python", "dotnet", "cfamily", "rust"}

var (
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	policyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// refPattern admits branch, tag and commit names and nothing a shell or git would read as an
	// option: the ref reaches actions/checkout as data, but a leading '-' is refused anyway.
	refPattern = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_./-]*$`)
	// commitPattern is a full commit id, the only ref a pinned target may name.
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// unboundedPolicy is the corpus policy only the pinned lane may use.
const unboundedPolicy = "full"

// parseTargets decodes and validates a targets file. Unknown fields are refused, so a misspelt key
// fails here instead of being silently ignored.
func parseTargets(data []byte) (Targets, error) {
	var t Targets
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Targets{}, fmt.Errorf("targets: %w", err)
	}
	if err := t.validate(); err != nil {
		return Targets{}, fmt.Errorf("targets: %w", err)
	}
	return t, nil
}

func loadTargets(path string) (Targets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Targets{}, err
	}
	return parseTargets(data)
}

func (t Targets) validate() error {
	switch {
	case t.Policy == "":
		return fmt.Errorf("policy is required")
	case t.Policy == unboundedPolicy:
		return fmt.Errorf("policy %q is not allowed: the floor run must stay bounded", t.Policy)
	case !policyPattern.MatchString(t.Policy):
		return fmt.Errorf("policy %q is not a policy id (lowercase letters, digits, '-')", t.Policy)
	case len(t.Targets) == 0:
		return fmt.Errorf("no targets")
	}
	seen := map[string]string{}
	for _, tg := range t.Targets {
		if err := checkTarget(tg, seen); err != nil {
			return err
		}
	}
	if p := t.Pinned; p != nil {
		switch {
		case !policyPattern.MatchString(p.Policy):
			return fmt.Errorf("pinned: policy %q is not a policy id (lowercase letters, digits, '-')", p.Policy)
		case len(p.Targets) == 0:
			return fmt.Errorf("pinned: no targets")
		}
		for _, tg := range p.Targets {
			if !commitPattern.MatchString(tg.Ref) {
				return fmt.Errorf("pinned: %s: ref %q is not a full commit id, so the lane would not be bounded", tg.Repo, tg.Ref)
			}
			if err := checkTarget(tg, seen); err != nil {
				return fmt.Errorf("pinned: %w", err)
			}
		}
	}
	for _, ex := range t.Excluded {
		if !repoPattern.MatchString(ex.Repo) || ex.Reason == "" {
			return fmt.Errorf("excluded %q needs owner/name and a reason", ex.Repo)
		}
		if _, ok := seen[strings.ToLower(ex.Name())]; ok {
			return fmt.Errorf("%s is both a target and excluded", ex.Repo)
		}
	}
	return nil
}

// checkTarget validates one target and records its name in seen, which spans every lane: the name
// names the scan job and its artifact.
func checkTarget(tg Target, seen map[string]string) error {
	if !repoPattern.MatchString(tg.Repo) {
		return fmt.Errorf("repo %q is not owner/name", tg.Repo)
	}
	if !knownLanguage(tg.Language) {
		return fmt.Errorf("%s: language %q is not one of %s", tg.Repo, tg.Language, strings.Join(languages, ", "))
	}
	if tg.Ref != "" && !refPattern.MatchString(tg.Ref) {
		return fmt.Errorf("%s: ref %q is not a branch, tag or commit name", tg.Repo, tg.Ref)
	}
	key := strings.ToLower(tg.Name())
	if prev, ok := seen[key]; ok {
		return fmt.Errorf("%s and %s share the name %q, which names the scan job", prev, tg.Repo, tg.Name())
	}
	seen[key] = tg.Repo
	return nil
}

// Name is the excluded repository's name without its owner.
func (e Excluded) Name() string {
	_, name, _ := strings.Cut(e.Repo, "/")
	return name
}

func knownLanguage(l string) bool {
	for _, k := range languages {
		if l == k {
			return true
		}
	}
	return false
}

// matrixEntry is one scan job of the workflow's matrix.
type matrixEntry struct {
	Repo                 string `json:"repo"`
	Name                 string `json:"name"`
	Language             string `json:"language"`
	Ref                  string `json:"ref"`
	IncludeHouseCanaries bool   `json:"include_house_canaries"`
	Policy               string `json:"policy"`
}

// matrixOutput renders the GitHub Actions step outputs the workflow's build job publishes: the scan
// matrix (one entry per target, carrying its lane's policy) and the policies whose corpus bundles
// the build job fetches, space-separated.
func matrixOutput(t Targets) (string, error) {
	m := struct {
		Include []matrixEntry `json:"include"`
	}{}
	var policies []string
	for _, l := range t.lanes() {
		if !slices.Contains(policies, l.policy) {
			policies = append(policies, l.policy)
		}
		for _, tg := range l.targets {
			m.Include = append(m.Include, matrixEntry{
				Repo: tg.Repo, Name: tg.Name(), Language: tg.Language, Ref: tg.Ref,
				IncludeHouseCanaries: tg.IncludeHouseCanaries, Policy: l.policy,
			})
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("matrix=%s\npolicies=%s\n", b, strings.Join(policies, " ")), nil
}
