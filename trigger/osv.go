// Package trigger implements the three run modes of the ferralon-assay OSS tool:
// a full baseline scan, a PR-adjacent inherit/diff run, and a scheduled CVE-watch.
//
// Each run mode is a thin orchestration over the Phase-2 substrate:
//
//   - the deterministic S1–S6 Assess pipeline (package pipeline) builds the
//     analysis artifacts;
//   - those artifacts are mapped into a neutral report.Report;
//   - the Report (plus SBOM and advisory cursor) is persisted under a
//     fast-forward-only CAS in the statestore.
//
// # Rung 0
//
// This package makes exactly one outbound call: the CVE-watch advisory query to
// OSV.dev's public querybatch endpoint (a list of {ecosystem, name, version}
// coordinates from the stored SBOM). It sends package coordinates only — never
// source, never analysis results. The baseline and PR-inherit run modes do not make
// it: the scan-path OSV work-set widening (-osv-work-set / TEGRON_OSV_WORK_SET,
// defaulting to cmd/ferralon-assay's osvWorkSetDefault, which is false) is the ONE
// switch that turns it on, and switched on it sends the same shape of payload to the
// same endpoint.
//
// THAT IS A CLAIM ABOUT THIS PACKAGE, NOT ABOUT THE TOOL. Every run mode — baseline
// and PR-inherit at their shipped defaults included — also contacts
// https://vuln.go.dev: the Go analyzer's reachability stage runs govulncheck with no
// -db flag (internal/plugin/goanalysis/reach.go), so it resolves golang.org/x/vuln's default
// vulnerability database, uncached, on every run, and the module paths it looks up are
// visible to that host. Resolving the subject's module graph likewise contacts
// proxy.golang.org. Neither is configurable from the Action.
// README.md ("Network egress") enumerates all three hosts and is the authoritative list.
//
// Whoever flips the OSV default owns re-checking every sentence above AND the
// customer-facing OUTBOUND paragraph in the scaffolded workflow, which enumerates the
// endpoints a run contacts.
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// osvAPIURL is the public OSV.dev batched-query endpoint. It is the single network
// egress of the whole package (Rung 0): CVE-watch posts SBOM coordinates here and
// receives advisory IDs back.
const osvAPIURL = "https://api.osv.dev/v1/querybatch"

// OSVClient queries an advisory database for the vulnerabilities affecting a set of
// packages. It is an interface so tests inject a fixture and no test touches the
// network; the production implementation is HTTPOSVClient.
type OSVClient interface {
	// QueryBatch returns, for the given packages, the set of advisory IDs that affect
	// them. The result is a flat, de-duplicated, sorted-by-the-caller set of advisory
	// IDs across all queried packages — exactly what CVE-watch diffs against its cursor.
	QueryBatch(ctx context.Context, pkgs []report.Package) (OSVResult, error)
}

// OSVResult is the parsed outcome of one querybatch call: the advisory IDs that
// affect the queried SBOM. AdvisoryIDs is the union across every package, with each
// id paired to the package it was reported against so an earnest run can be scoped
// to just the newly-relevant advisory/package pairs.
type OSVResult struct {
	// Advisories is one entry per (advisory id, affected package) the query returned.
	Advisories []OSVAdvisory
}

// OSVAdvisory is one advisory OSV.dev reported as affecting a queried package.
type OSVAdvisory struct {
	// ID is the advisory identifier (e.g. "GHSA-xxxx", "GO-2021-0113", "CVE-...").
	ID string
	// Package is the SBOM package the advisory was reported against.
	Package report.Package
}

// IDs returns the de-duplicated set of advisory IDs in the result. Order follows
// first appearance; callers that need a stable cursor sort the result.
func (r OSVResult) IDs() []string {
	seen := make(map[string]struct{}, len(r.Advisories))
	ids := make([]string, 0, len(r.Advisories))
	for _, a := range r.Advisories {
		if _, ok := seen[a.ID]; ok {
			continue
		}
		seen[a.ID] = struct{}{}
		ids = append(ids, a.ID)
	}
	return ids
}

// HTTPOSVClient is the production OSVClient: it POSTs the querybatch request to
// OSV.dev over HTTP. It is the sole network caller in the package (Rung 0).
type HTTPOSVClient struct {
	// HTTPClient is the client used for the request. nil means a default client with
	// a bounded timeout.
	HTTPClient *http.Client
	// URL overrides the endpoint (tests against a local server); "" means osvAPIURL.
	URL string
}

var _ OSVClient = (*HTTPOSVClient)(nil)

// osvBatchRequest is the querybatch wire request: a list of per-package queries.
// OSV.dev keys an ecosystem package query on package.{ecosystem,name} + version.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Version string        `json:"version,omitempty"`
	Package osvPackageRef `json:"package"`
}

// osvPackageRef identifies a package to OSV.dev by its {ecosystem, name}
// coordinate. OSV treats a query that carries a "purl" as a PURL-query and then
// rejects any co-present "ecosystem"/"name" ("name specified in a PURL query"),
// so the two identification forms are mutually exclusive. CVE-watch always has a
// complete {ecosystem, name, version} triple from the SBOM (the documented Rung-0
// coordinate), so it uses the coordinate form exclusively and never sends a purl.
type osvPackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvBatchResponse is the querybatch wire response: results are positional — the
// i-th result corresponds to the i-th query in the request.
type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch posts the SBOM coordinates to OSV.dev and parses the batched response
// into the union of affecting advisory IDs, each attributed to its package.
func (c *HTTPOSVClient) QueryBatch(ctx context.Context, pkgs []report.Package) (OSVResult, error) {
	if len(pkgs) == 0 {
		return OSVResult{}, nil
	}

	reqBody := osvBatchRequest{Queries: make([]osvQuery, 0, len(pkgs))}
	for _, p := range pkgs {
		reqBody.Queries = append(reqBody.Queries, osvQuery{
			Version: p.Version,
			Package: osvPackageRef{Ecosystem: p.Ecosystem, Name: p.Name},
		})
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return OSVResult{}, fmt.Errorf("osv: marshal querybatch request: %w", err)
	}

	url := c.URL
	if url == "" {
		url = osvAPIURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return OSVResult{}, fmt.Errorf("osv: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return OSVResult{}, fmt.Errorf("osv: querybatch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return OSVResult{}, fmt.Errorf("osv: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return OSVResult{}, fmt.Errorf("osv: querybatch returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return parseOSVResponse(body, pkgs)
}

// parseOSVResponse maps the positional querybatch response back onto the queried
// packages. It is split out so tests can exercise parsing against a fixture body.
func parseOSVResponse(body []byte, pkgs []report.Package) (OSVResult, error) {
	var raw osvBatchResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return OSVResult{}, fmt.Errorf("osv: decode response: %w", err)
	}
	var out OSVResult
	for i, res := range raw.Results {
		if i >= len(pkgs) {
			break
		}
		for _, v := range res.Vulns {
			if v.ID == "" {
				continue
			}
			out.Advisories = append(out.Advisories, OSVAdvisory{ID: v.ID, Package: pkgs[i]})
		}
	}
	return out, nil
}
