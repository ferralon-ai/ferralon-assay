package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/selfcleanup"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Environment contract set by the Ferralon Assay Action (ferralon-assay/action.yml).
// All self-cleanup wiring is gated on the explicit FERRALON_LINK_TO_CONSOLE opt-in (see link.go):
// unlinked, the scanner never beacons and behaves exactly as before (the OSS/dogfood path is
// untouched). The two URL vars below are OVERRIDES for that link, not the switch itself — the
// endpoint a linked run uses is baked into the release.
const (
	envIngestURL      = "FERRALON_INGEST_URL"     // ingest endpoint OVERRIDE (empty ⇒ the baked release default)
	envRunsURL        = "FERRALON_RUNS_URL"       // run-snapshot endpoint OVERRIDE (empty ⇒ the baked release default)
	envOIDCToken      = "FERRALON_OIDC_TOKEN"     // pre-minted OIDC token (else minted from the Actions env)
	envDefaultBranch  = "FERRALON_DEFAULT_BRANCH" // github.event.repository.default_branch
	envRefName        = "GITHUB_REF_NAME"         // github.ref_name — the branch/tag this run is on
	envEventAction    = "FERRALON_EVENT_ACTION"   // github.event.action (for repository_dispatch)
	envClientPayload  = "FERRALON_CLIENT_PAYLOAD" // github.event.client_payload JSON
	envGitHubRepo     = "GITHUB_REPOSITORY"       // owner/repo
	envGitHubToken    = "GITHUB_TOKEN"            // actuation token (git push / gh)
	envGitHubWorkspce = "GITHUB_WORKSPACE"        // checkout root
	envGitHubSHA      = "GITHUB_SHA"              // resolved commit
	envActionsIDURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envActionsIDTok   = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	workflowFile = "ferralon-assay.yml"
	workflowPath = ".github/workflows/" + workflowFile
	oidcAudience = "ferralon-ingest"
)

// rescanFromEnv decodes an advisory-rescan repository_dispatch cause from the env the
// Action forwards. It returns nil (fall back to a normal scan) for any other trigger
// or a malformed payload.
func rescanFromEnv() *selfcleanup.RescanPayload {
	p, ok := selfcleanup.ParseRescanPayload(os.Getenv(envEventAction), []byte(os.Getenv(envClientPayload)))
	if !ok {
		return nil
	}
	return p
}

// printRescanContext surfaces the advisory-rescan cause in the run summary so an
// operator (and the console) can see why the scan ran.
func printRescanContext(p *selfcleanup.RescanPayload) {
	if p == nil {
		return
	}
	fmt.Fprintf(os.Stdout, "  rescan:     advisory re-scan (reason=%s", p.Reason)
	if p.GHSAID != "" {
		fmt.Fprintf(os.Stdout, ", ghsa=%s", p.GHSAID)
	}
	if p.Package.Name != "" {
		fmt.Fprintf(os.Stdout, ", package=%s/%s", p.Package.Ecosystem, p.Package.Name)
	}
	fmt.Fprintln(os.Stdout, ")")
}

// refStater is implemented by the concrete StateStores that can report the ref they
// actually read/write (GitRefStore, GitHubRefStore) — never the bare StateStore
// interface, which is deliberately Read/Write-only. Asserted against locally so a
// caller holding a live store (self-cleanup) can discover its real ref instead of
// assuming statestore.DefaultRef, which is wrong the moment an operator sets a
// custom state-ref.
type refStater interface {
	StateRef() string
}

// stateRefOf returns the ref store actually reads/writes, falling back to
// statestore.DefaultRef only for a StateStore implementation with no ref to report
// (statestore.MemStore — test-only, never constructed by a real run).
func stateRefOf(store statestore.StateStore) string {
	if rs, ok := store.(refStater); ok {
		return rs.StateRef()
	}
	return statestore.DefaultRef
}

// postScan runs the env-gated self-cleanup revoke check after a scan published its
// results. store is the SAME StateStore the run used (so the counter lives beside the
// baseline). subject supplies the resolved commit when GITHUB_SHA is absent. It is
// best-effort: it never returns an error that would fail the customer's build — a
// problem is logged and swallowed.
func postScan(ctx context.Context, store statestore.StateStore, subject trigger.Subject, rescan *selfcleanup.RescanPayload) {
	ingestURL := resolveEndpoint(linkedToConsole(), os.Getenv(envIngestURL), bakedIngestURL)
	if ingestURL == "" {
		return // not linked to a console (OSS / dogfood / local run, or an explicit opt-out)
	}
	full := os.Getenv(envGitHubRepo) // "owner/name"
	if full == "" {
		return
	}
	// The backend signs the revoke over org=<owner>, repo=<short name> (derived from
	// the OIDC repository claim, dispatch 03) — so the beacon binds against those short
	// forms, while the actuator needs the full "owner/name" for gh --repo.
	org, repoShort := full, full
	if i := strings.IndexByte(full, '/'); i > 0 {
		org, repoShort = full[:i], full[i+1:]
	}
	commit := os.Getenv(envGitHubSHA)
	if commit == "" {
		commit = subject.ResolvedCommit
	}

	pub, keyID, err := selfcleanup.TrustedKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  self-cleanup: bad revoke key, skipping: %v\n", err)
		return
	}

	beacon := selfcleanup.BeaconRequest{Org: org, Repo: repoShort, Commit: commit}
	if rescan != nil {
		beacon.Reason = rescan.Reason
		beacon.GHSAID = rescan.GHSAID
	}

	cfg := selfcleanup.CheckConfig{
		Store: store,
		Ingest: selfcleanup.IngestClient{
			URL:    ingestURL,
			Token:  resolveOIDCToken(ctx),
			PubKey: pub,
			KeyID:  keyID,
		},
		Beacon: beacon,
		NewActuator: func() selfcleanup.Actuator {
			return selfcleanup.NewGitActuator(selfcleanup.ActuatorConfig{
				Repo:          full,
				DefaultBranch: firstNonEmpty(os.Getenv(envDefaultBranch), "main"),
				WorkflowPath:  workflowPath,
				WorkflowFile:  workflowFile,
				GitDir:        firstNonEmpty(os.Getenv(envGitHubWorkspce), "."),
				StateRef:      stateRefOf(store),
				Token:         os.Getenv(envGitHubToken),
			})
		},
	}

	res, err := selfcleanup.RunCheck(ctx, cfg)
	if err != nil {
		// A persist/actuation hiccup is logged, not fatal.
		fmt.Fprintf(os.Stderr, "  self-cleanup: %v\n", err)
	}
	switch {
	case res.Actuated:
		fmt.Fprintf(os.Stdout, "  self-cleanup: install revoked — cleanup actuated (%s)\n", res.Rung)
	case res.Outcome == selfcleanup.OutcomeRevoked:
		fmt.Fprintf(os.Stdout, "  self-cleanup: signed revoke %d/%d (awaiting confirmation)\n", res.Count, selfcleanup.RevokeThreshold)
	}
}

// resolveOIDCToken returns a bearer token for the ingest POST: an explicitly-provided
// FERRALON_OIDC_TOKEN, else a token minted from the GitHub Actions OIDC endpoint
// (best-effort — an empty token still POSTs, the backend decides). Minting failure is
// non-fatal: a missing token cannot itself trigger self-cleanup (a rejected beacon is
// a transient Outcome).
func resolveOIDCToken(ctx context.Context) string {
	if t := os.Getenv(envOIDCToken); t != "" {
		return t
	}
	reqURL, reqTok := os.Getenv(envActionsIDURL), os.Getenv(envActionsIDTok)
	if reqURL == "" || reqTok == "" {
		return ""
	}
	url := reqURL
	if !strings.Contains(url, "audience=") {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "audience=" + oidcAudience
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return ""
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return v.Value
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
