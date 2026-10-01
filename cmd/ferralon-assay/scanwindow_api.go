package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// The scan-window policy lookup: for a console-linked repository that sets no scan.window, the
// window the repository's Ferralon customer policy selects. The lookup is FAIL-OPEN — any failure
// (no OIDC token, as on a fork's pull request; a network error; a timeout; a non-200; a body this
// scanner does not understand) passes resolution on to the workflow's advisory-corpus-policy input,
// and the run log says why. It never fails the scan.
const (
	// scanWindowPath is the lookup's path on the Ferralon API origin the run-snapshot endpoint
	// lives on.
	scanWindowPath = "/policy/scan-window"
	// envScanWindowAPISource carries the API's source record from the Action's scan-window step
	// to the scan, as JSON, when the window came from the lookup.
	envScanWindowAPISource = brand.EnvPrefix + "_SCAN_WINDOW_API_SOURCE"

	scanWindowAttemptTimeout = 3 * time.Second
	scanWindowTotalTimeout   = 10 * time.Second
	scanWindowMaxAttempts    = 2
	scanWindowMaxBody        = 64 << 10
	// scanWindowMaxDistance bounds an ancestor hop count; the policy tree is never this deep.
	scanWindowMaxDistance = 64
)

// customerIDPattern is the shape an opaque customer id must have before it reaches a step output,
// the run log or the Report.
var customerIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// noRedirectClient never follows a redirect, so the bearer token goes only to the lookup endpoint;
// a 3xx is a non-200 answer like any other.
var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// scanWindowEndpoint derives the lookup URL from the run-snapshot endpoint: same scheme and host,
// scanWindowPath. "" (no lookup) when runsURL is empty or not an absolute http(s) URL.
func scanWindowEndpoint(runsURL string) string {
	if runsURL == "" {
		return ""
	}
	u, err := url.Parse(runsURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: scanWindowPath}).String()
}

// scanWindowLookup is one lookup against endpoint, authenticated with the token token returns.
type scanWindowLookup struct {
	endpoint string
	token    func(context.Context) string
	client   *http.Client
	// attemptTimeout and totalTimeout default to scanWindowAttemptTimeout / scanWindowTotalTimeout.
	attemptTimeout, totalTimeout time.Duration
	log                          io.Writer
}

// source is the lookup as a resolution step. A failure is logged and passes resolution on.
func (l scanWindowLookup) source(ctx context.Context) windowSource {
	return func() (report.ScanWindow, bool, error) {
		sw, err := l.fetch(ctx)
		if err != nil {
			fmt.Fprintf(l.log, "scan window: Ferralon policy lookup unavailable (%v); using the workflow's advisory-corpus-policy\n", err)
			return report.ScanWindow{}, false, nil
		}
		return sw, true, nil
	}
}

// final marks a lookup failure a second attempt would not change. It reads as the error it wraps.
type final struct{ error }

func (f final) Unwrap() error { return f.error }

func isFinal(err error) bool {
	var f final
	return errors.As(err, &f)
}

// fetch runs the lookup within totalTimeout, OIDC token request included.
func (l scanWindowLookup) fetch(ctx context.Context) (report.ScanWindow, error) {
	attempt, total := l.attemptTimeout, l.totalTimeout
	if attempt == 0 {
		attempt = scanWindowAttemptTimeout
	}
	if total == 0 {
		total = scanWindowTotalTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	token := l.token(ctx)
	if token == "" {
		return report.ScanWindow{}, errors.New("no OIDC token for this run")
	}

	var err error
	for i := 0; i < scanWindowMaxAttempts; i++ {
		var sw report.ScanWindow
		sw, err = l.attempt(ctx, token, attempt)
		if err == nil {
			return sw, nil
		}
		if isFinal(err) || ctx.Err() != nil {
			break
		}
	}
	return report.ScanWindow{}, err
}

// attempt makes one request. A network error or a 5xx is retryable; everything else is final.
func (l scanWindowLookup) attempt(ctx context.Context, token string, timeout time.Duration) (report.ScanWindow, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.endpoint, nil)
	if err != nil {
		return report.ScanWindow{}, final{err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	client := l.client
	if client == nil {
		client = noRedirectClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return report.ScanWindow{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		return report.ScanWindow{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return report.ScanWindow{}, final{fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, scanWindowMaxBody+1))
	if err != nil {
		return report.ScanWindow{}, fmt.Errorf("reading the response: %w", err)
	}
	if len(body) > scanWindowMaxBody {
		return report.ScanWindow{}, final{fmt.Errorf("response exceeds %d bytes", scanWindowMaxBody)}
	}
	sw, err := parseScanWindowResponse(body)
	if err != nil {
		return report.ScanWindow{}, final{err}
	}
	return sw, nil
}

// scanWindowResponse is the lookup's response body. Unknown fields are ignored.
type scanWindowResponse struct {
	Version int            `json:"version"`
	Window  string         `json:"window"`
	Policy  string         `json:"policy"`
	Source  scanWindowAPIS `json:"source"`
}

// scanWindowAPIS is the API's source record, also handed from the scan-window step to the scan.
type scanWindowAPIS struct {
	Kind       string `json:"kind"`
	CustomerID string `json:"customer_id,omitempty"`
	Distance   *int   `json:"distance,omitempty"`
}

func parseScanWindowResponse(body []byte) (report.ScanWindow, error) {
	var r scanWindowResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return report.ScanWindow{}, fmt.Errorf("malformed response: %w", err)
	}
	if r.Version != 1 {
		return report.ScanWindow{}, fmt.Errorf("unknown response version %d", r.Version)
	}
	w, err := repoconfig.ParseWindow(r.Window)
	if err != nil {
		return report.ScanWindow{}, fmt.Errorf("response window: %w", err)
	}
	if r.Policy != w.Policy() {
		return report.ScanWindow{}, fmt.Errorf("response policy %q does not back window %s", r.Policy, w)
	}
	src, err := validAPISource(r.Source)
	if err != nil {
		return report.ScanWindow{}, err
	}
	return report.ScanWindow{Window: string(w), Policy: r.Policy, ResolvedVia: report.ScanWindowViaAPI, Source: src}, nil
}

// validAPISource checks a source record from the API (or relayed from the scan-window step).
func validAPISource(s scanWindowAPIS) (report.ScanWindowSource, error) {
	switch s.Kind {
	case report.ScanWindowKindDefault:
		return report.ScanWindowSource{Kind: s.Kind}, nil
	case report.ScanWindowKindCustomer, report.ScanWindowKindAncestor:
	default:
		return report.ScanWindowSource{}, fmt.Errorf("unknown source kind %q", s.Kind)
	}
	if !customerIDPattern.MatchString(s.CustomerID) {
		return report.ScanWindowSource{}, fmt.Errorf("source customer_id is missing or malformed")
	}
	if s.Distance == nil || *s.Distance < 0 || *s.Distance > scanWindowMaxDistance {
		return report.ScanWindowSource{}, fmt.Errorf("source distance is missing or out of range")
	}
	if (s.Kind == report.ScanWindowKindCustomer) != (*s.Distance == 0) {
		return report.ScanWindowSource{}, fmt.Errorf("source kind %s does not match distance %d", s.Kind, *s.Distance)
	}
	d := *s.Distance
	return report.ScanWindowSource{Kind: s.Kind, CustomerID: s.CustomerID, Distance: &d}, nil
}

// encodeAPISource renders a validated API source record for the scan-window step's outputs: one
// line of JSON whose every value has passed validAPISource.
func encodeAPISource(s report.ScanWindowSource) string {
	b, _ := json.Marshal(scanWindowAPIS{Kind: s.Kind, CustomerID: s.CustomerID, Distance: s.Distance})
	return string(b)
}

// decodeAPISource parses and re-validates envScanWindowAPISource.
func decodeAPISource(raw string) (report.ScanWindowSource, error) {
	var s scanWindowAPIS
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return report.ScanWindowSource{}, fmt.Errorf("%s is not a source record: %w", envScanWindowAPISource, err)
	}
	src, err := validAPISource(s)
	if err != nil {
		return report.ScanWindowSource{}, fmt.Errorf("%s: %w", envScanWindowAPISource, err)
	}
	return src, nil
}
