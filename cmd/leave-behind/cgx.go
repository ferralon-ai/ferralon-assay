// cgx.go — a thin subprocess client for the cgx CLI (Path A). Every call shells
// to `cgx <sub> [args...] --repo <repo> --format json` once and decodes the
// stdout JSON into a typed value. The `approximation` envelope (cgx's per-query,
// machine-readable declared-incompleteness disclosure) is kept as a raw message
// wherever cgx emits one, so it can be re-embedded verbatim in a leave-behind.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// fallbackCgxPath is the real cgx binary location documented for this repo when
// `cgx` is not resolvable on PATH. In this environment `cgx` is a shell alias
// (cargo run …), which os/exec cannot expand — the operator must pass -cgx-bin.
const fallbackCgxPath = "~/workspace/cgx/main/target/release/cgx"

// cgxClient runs cgx subcommands against a single indexed repository.
type cgxClient struct {
	bin  string
	repo string
}

// resolveCgxBin picks the cgx binary: the -cgx-bin flag wins; otherwise cgx is
// looked up on PATH. A missing binary is a hard, clearly-worded error naming the
// documented fallback — os/exec cannot see the shell alias, so silence here would
// strand the operator.
func resolveCgxBin(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	p, err := exec.LookPath("cgx")
	if err != nil {
		return "", fmt.Errorf("cgx not found on PATH; pass -cgx-bin (the real binary is typically %s). "+
			"Note: `cgx` is often a shell alias, which os/exec cannot resolve", fallbackCgxPath)
	}
	return p, nil
}

// argv returns the full argument vector a call would run, for reproducibility
// notes embedded in each artifact.
func (c *cgxClient) argv(args ...string) []string {
	return append(append([]string{"cgx"}, args...), "--repo", c.repo, "--format", "json")
}

// run executes one cgx subcommand and returns its stdout. A non-zero exit is
// surfaced as an error carrying stderr — cgx writes "no symbol matched", ref
// failures, and plan errors there while exiting non-zero.
func (c *cgxClient) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append(append([]string{}, args...), "--repo", c.repo, "--format", "json")
	cmd := exec.CommandContext(ctx, c.bin, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cgx %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// --- decoders ---------------------------------------------------------------

// searchRow is one row of `cgx search` (a bare JSON array of these).
type searchRow struct {
	File string `json:"file"`
	Fqn  string `json:"fqn"`
	Kind string `json:"kind"`
	Line int    `json:"line"`
}

func (c *cgxClient) search(ctx context.Context, pattern, kind string, limit int) ([]searchRow, error) {
	args := []string{"search", pattern, "--limit", fmt.Sprintf("%d", limit)}
	if kind != "" {
		args = append(args, "--kind", kind)
	}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var rows []searchRow
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("decode search: %w", err)
	}
	return rows, nil
}

func (c *cgxClient) searchAll(ctx context.Context, limit int) ([]searchRow, error) {
	out, err := c.run(ctx, "search", "--all", "--limit", fmt.Sprintf("%d", limit))
	if err != nil {
		return nil, err
	}
	var rows []searchRow
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("decode search --all: %w", err)
	}
	return rows, nil
}

// degreeBreakdown is the per-symbol edge decomposition `cgx symbols` attaches to
// each ranked row — the honesty carrier for a command that emits no envelope.
type degreeBreakdown struct {
	ByCondition  map[string]int `json:"by_condition"`
	ByConfidence map[string]int `json:"by_confidence"`
	ByFamily     map[string]int `json:"by_family"`
	Total        int            `json:"total"`
}

type symbolRank struct {
	File      string          `json:"file"`
	Fqn       string          `json:"fqn"`
	Kind      string          `json:"kind"`
	Line      int             `json:"line"`
	InDegree  int             `json:"in_degree"`
	OutDegree int             `json:"out_degree"`
	Inbound   degreeBreakdown `json:"inbound"`
	Outbound  degreeBreakdown `json:"outbound"`
}

func (c *cgxClient) symbols(ctx context.Context, rank string, top int) ([]symbolRank, error) {
	out, err := c.run(ctx, "symbols", "--rank", rank, "--top", fmt.Sprintf("%d", top))
	if err != nil {
		return nil, err
	}
	var rows []symbolRank
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("decode symbols: %w", err)
	}
	return rows, nil
}

// explainEdge is one incident edge from `cgx explain`. Confidence and condition
// are per-edge — `explain` carries no top-level approximation envelope, so the
// honesty lives on every row here.
type explainEdge struct {
	Condition        string          `json:"condition"`
	Confidence       string          `json:"confidence"`
	Direction        string          `json:"direction"`
	Peer             string          `json:"peer"`
	PeerFile         string          `json:"peer_file"`
	PeerLine         int             `json:"peer_line"`
	ResolutionSource json.RawMessage `json:"resolution_source"`
	Rule             string          `json:"rule"`
	Site             struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"site"`
	Tier string `json:"tier"`
}

type explainResult struct {
	Symbol       string        `json:"symbol"`
	File         string        `json:"file"`
	Line         int           `json:"line"`
	Kind         string        `json:"kind"`
	CallersCount int           `json:"callers_count"`
	CalleesCount int           `json:"callees_count"`
	Edges        []explainEdge `json:"edges"`
}

func (c *cgxClient) explain(ctx context.Context, fqn string) (*explainResult, error) {
	out, err := c.run(ctx, "explain", fqn)
	if err != nil {
		return nil, err
	}
	var res explainResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("decode explain %q: %w", fqn, err)
	}
	return &res, nil
}

// forestRow is one node in a `cgx callers`/`callees` reverse/forward closure.
type forestRow struct {
	Condition  string `json:"condition"`
	Confidence string `json:"confidence"`
	Depth      int    `json:"depth"`
	File       string `json:"file"`
	Fqn        string `json:"fqn"`
	Kind       string `json:"kind"`
	Line       int    `json:"line"`
}

// forestResult keeps the approximation envelope raw for verbatim re-embedding.
type forestResult struct {
	Approximation json.RawMessage `json:"approximation"`
	Count         int             `json:"count"`
	Results       []forestRow     `json:"results"`
}

func (c *cgxClient) callers(ctx context.Context, fqn string, depth int) (*forestResult, error) {
	out, err := c.run(ctx, "callers", fqn, "--depth", fmt.Sprintf("%d", depth))
	if err != nil {
		return nil, err
	}
	var res forestResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("decode callers %q: %w", fqn, err)
	}
	return &res, nil
}

type unusedRow struct {
	File string `json:"file"`
	Fqn  string `json:"fqn"`
	Kind string `json:"kind"`
	Line int    `json:"line"`
}

type unusedResult struct {
	Approximation json.RawMessage `json:"approximation"`
	Count         int             `json:"count"`
	Results       []unusedRow     `json:"results"`
	Vacuous       bool            `json:"vacuous"`
}

func (c *cgxClient) unused(ctx context.Context, kind string) (*unusedResult, error) {
	out, err := c.run(ctx, "unused", "--kind", kind)
	if err != nil {
		return nil, err
	}
	var res unusedResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("decode unused: %w", err)
	}
	return &res, nil
}

// queryResult is the CQL result shape. Rows are returned as raw cells so mixed
// column types decode without loss; DATA_FLOW provenance returns FQN strings.
type queryResult struct {
	Approximation json.RawMessage     `json:"approximation"`
	Columns       []string            `json:"columns"`
	Count         int                 `json:"count"`
	Rows          [][]json.RawMessage `json:"rows"`
	Vacuous       bool                `json:"vacuous"`
}

func (c *cgxClient) query(ctx context.Context, cql string) (*queryResult, error) {
	out, err := c.run(ctx, "query", cql)
	if err != nil {
		return nil, err
	}
	var res queryResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("decode query: %w", err)
	}
	return &res, nil
}

// diffResult holds the five edge/node sets of `cgx diff`. Each element is kept
// raw — the diff output carries no per-edge confidence, and its element shape is
// re-embedded verbatim rather than remodeled.
type diffResult struct {
	AddedEdges   []json.RawMessage `json:"added_edges"`
	RemovedEdges []json.RawMessage `json:"removed_edges"`
	ChangedEdges []json.RawMessage `json:"changed_edges"`
	AddedNodes   []json.RawMessage `json:"added_nodes"`
	RemovedNodes []json.RawMessage `json:"removed_nodes"`
}

func (c *cgxClient) diff(ctx context.Context, base, head string) (*diffResult, error) {
	out, err := c.run(ctx, "diff", base, head)
	if err != nil {
		return nil, err
	}
	var res diffResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("decode diff %s..%s: %w", base, head, err)
	}
	return &res, nil
}

// doctor returns the graph-honesty header verbatim (node/edge counts, confidence
// distribution, trust, unresolved rate) for the manifest.
func (c *cgxClient) doctor(ctx context.Context) (json.RawMessage, error) {
	out, err := c.run(ctx, "doctor")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(out)), nil
}
