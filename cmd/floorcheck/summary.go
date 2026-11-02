package main

import (
	"fmt"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// SummarySchema names the floor-summary.json format.
const SummarySchema = "ferralon.floor-summary.v1"

// Summary is floor-summary.json: one floor run over every target.
type Summary struct {
	Schema      string           `json:"schema"`
	Pass        bool             `json:"pass"`
	AssayCommit string           `json:"assay_commit,omitempty"`
	Policy      string           `json:"policy"`
	RunURL      string           `json:"run_url,omitempty"`
	Languages   []LanguageResult `json:"languages"`
	Repos       []RepoResult     `json:"repos"`
	Excluded    []Excluded       `json:"excluded,omitempty"`
}

// LanguageResult is the per-language line: how many targets the language has and how they fared.
// A language with no target has Targets 0, and is the gap the summary exists to show.
type LanguageResult struct {
	Language string `json:"language"`
	Targets  int    `json:"targets"`
	Passed   int    `json:"passed"`
	Failed   int    `json:"failed"`
}

// summarize evaluates every target against the scan results and builds the run's summary.
func summarize(t Targets, results map[string]*scanResult, assayCommit, runURL string) Summary {
	s := Summary{Schema: SummarySchema, Pass: true, AssayCommit: assayCommit, Policy: t.Policy,
		RunURL: runURL, Excluded: t.Excluded}
	byLang := map[string]*LanguageResult{}
	for _, l := range languages {
		byLang[l] = &LanguageResult{Language: l}
	}
	for _, tg := range t.Targets {
		res := evaluate(tg, t.Policy, results[tg.Repo])
		s.Repos = append(s.Repos, res)
		lr := byLang[tg.Language]
		lr.Targets++
		if res.Pass {
			lr.Passed++
		} else {
			lr.Failed++
			s.Pass = false
		}
	}
	for _, l := range languages {
		s.Languages = append(s.Languages, *byLang[l])
	}
	return s
}

// failedRepos is the repositories that failed, in target order.
func (s Summary) failedRepos() []RepoResult {
	var out []RepoResult
	for _, r := range s.Repos {
		if !r.Pass {
			out = append(out, r)
		}
	}
	return out
}

// shortSHA abbreviates a commit for display.
func shortSHA(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// repoName is a repository's name without its owner.
func repoName(repo string) string {
	return Target{Repo: repo}.Name()
}

func formatDuration(secs *int64) string {
	if secs == nil {
		return "—"
	}
	return fmt.Sprintf("%dm%02ds", *secs/60, *secs%60)
}

func formatVerdicts(v map[report.Verdict]int) string {
	if v == nil {
		return "—"
	}
	var parts []string
	for _, k := range verdictOrder {
		if v[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, v[k]))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, " · ")
}

func formatReasons(rs []ReasonCount) string {
	if len(rs) == 0 {
		return "—"
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = fmt.Sprintf("`%s` %d", r.Reason, r.Count)
	}
	return strings.Join(parts, ", ")
}

// cell makes a value safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

// markdown renders the job summary: the verdict, the per-language table, the per-repository table,
// what failed and why, and what the run does not cover.
func (s Summary) markdown() string {
	var b strings.Builder
	failed := s.failedRepos()
	if s.Pass {
		fmt.Fprintf(&b, "## Floor run: PASS — %d of %d repos\n\n", len(s.Repos), len(s.Repos))
	} else {
		fmt.Fprintf(&b, "## Floor run: FAIL — %d of %d repos failed\n\n", len(failed), len(s.Repos))
	}
	fmt.Fprintf(&b, "Assay `%s`, corpus policy `%s`.", shortSHA(s.AssayCommit), s.Policy)
	if s.RunURL != "" {
		fmt.Fprintf(&b, " [Run](%s).", s.RunURL)
	}
	b.WriteString("\n\n### By language\n\n| Language | Targets | Passed | Failed |\n|---|---|---|---|\n")
	for _, l := range s.Languages {
		if l.Targets == 0 {
			fmt.Fprintf(&b, "| %s | **no target** | — | — |\n", l.Language)
			continue
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", l.Language, l.Targets, l.Passed, l.Failed)
	}
	b.WriteString("\n### By repo\n\n| Repo | Language | Assay commit | Policy | Verdicts | Top undetermined reasons | Truncated | Duration | Result |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range s.Repos {
		name := repoName(r.Repo)
		if r.Ref != "" {
			name += "@" + r.Ref
		}
		result := "pass"
		if !r.Pass {
			result = "**FAIL**"
		}
		truncated := "no"
		if r.ScanTruncated {
			truncated = "**yes**"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %s | %s | %s |\n",
			cell(name), r.Language, shortSHA(r.AssayCommit), cell(r.Policy), formatVerdicts(r.Verdicts),
			cell(formatReasons(r.TopUndetermined)), truncated, formatDuration(r.DurationSeconds), result)
	}
	if len(failed) > 0 {
		b.WriteString("\n### Failures\n\n")
		for _, r := range failed {
			for _, f := range r.Failures {
				fmt.Fprintf(&b, "- **%s** — `%s`: %s", repoName(r.Repo), f.Kind, cell(f.Detail))
				if len(f.Findings) > 0 {
					fmt.Fprintf(&b, ": %s", cell(strings.Join(f.Findings, ", ")))
				}
				b.WriteString("\n")
			}
		}
	}
	var unverifiable []string
	for _, r := range s.Repos {
		if len(r.Unverifiable) > 0 {
			unverifiable = append(unverifiable, fmt.Sprintf("%s %d", repoName(r.Repo), len(r.Unverifiable)))
		}
	}
	if len(unverifiable) > 0 {
		fmt.Fprintf(&b, "\n`disqualified` with no version or symbol basis to check (counted, not failed): %s.\n",
			strings.Join(unverifiable, ", "))
	}
	if len(s.Excluded) > 0 {
		b.WriteString("\n### Not scanned\n\n")
		for _, e := range s.Excluded {
			fmt.Fprintf(&b, "- %s: %s\n", cell(e.Repo), cell(e.Reason))
		}
	}
	return b.String()
}

// alertBullets is the most lines the failure alert may carry.
const alertBullets = 4

// alert renders the failure alert: at most four short bullets in plain words, the last one the run
// link. It is empty when the run passed.
func (s Summary) alert() string {
	failed := s.failedRepos()
	if len(failed) == 0 {
		return ""
	}
	lines := []string{fmt.Sprintf("Nightly Assay floor run failed on %d of %d demo repos.", len(failed), len(s.Repos))}
	room := alertBullets - 2 // the headline and the run link
	for i, r := range failed {
		if i == room-1 && len(failed) > room {
			lines = append(lines, fmt.Sprintf("%d more repos failed; the run summary lists them.", len(failed)-i))
			break
		}
		lines = append(lines, repoName(r.Repo)+": "+plainFailure(r.Failures[0])+".")
	}
	link := s.RunURL
	if link == "" {
		link = "(no run link)"
	}
	lines = append(lines, "Run: "+link)
	for i := range lines {
		lines[i] = "• " + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}

// plainFailure says what a failure means in plain words, for the alert.
func plainFailure(f Failure) string {
	switch f.Kind {
	case KindUngroundedNE:
		return fmt.Sprintf("%d not_exploitable without grounds (%s)", len(f.Findings), firstOf(f.Findings))
	case KindUngroundedDisq:
		return fmt.Sprintf("%d disqualified without valid grounds (%s)", len(f.Findings), firstOf(f.Findings))
	case KindTruncated:
		return "the scan ran out of time"
	case KindNoResult:
		return "the scan job did not finish"
	case KindMalformed:
		return "the report could not be read"
	default:
		return "the scan failed"
	}
}

func firstOf(ids []string) string {
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return ids[0]
	default:
		return fmt.Sprintf("%s and %d more", ids[0], len(ids)-1)
	}
}
