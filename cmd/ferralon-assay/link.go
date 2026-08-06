package main

import (
	"os"
	"strconv"
	"strings"
)

// Build-time endpoint defaults for the pinned Ferralon Assay scanner release. These are string
// vars — NOT consts — so the publish pipeline (deploy/assay/publish.sh) substitutes them at cut
// time, exactly like selfcleanup's baked revoke key:
//
//	go build -ldflags "\
//	  -X main.bakedIngestURL=https://api.ferralon.com/ingest \
//	  -X main.bakedRunsURL=https://api.ferralon.com/runs" ./cmd/ferralon-assay
//
// They live in the BINARY rather than in the caller's workflow YAML on purpose. That workflow
// file is committed into a repository we do not own, so a host written into it is a wrong value
// we cannot correct — the customer would have to merge a fix to a file we asked them to trust.
// Baked here, the endpoint is a property of which release they pinned: a dev cut points at dev
// by construction, and the customer's committed workflow names no environment at all.
//
// A plain `go build` leaves both empty. The OSS/dogfood binary then has no Ferralon endpoint to
// call and stays a pure local scanner no matter how the toggle below is set — the location-is-tier
// default-deny posture is unchanged.
var (
	bakedIngestURL string
	bakedRunsURL   string
)

// envLinkToConsole carries the action's `link-to-console` input: the EXPLICIT opt-in for talking
// to Ferralon at all. It is a boolean, not a URL — the caller states whether this run is linked;
// which host it links to is the release's business, not theirs. Absent, empty, or unparseable
// ⇒ false ⇒ fully standalone.
//
// Explicit rather than inferred from an empty URL because the scaffolded workflow is a CONSENT
// artifact. The customer merges a PR carrying `link-to-console: true`, so the affirmative is
// written down in their file, in their history, in their own merge commit — and deleting the line
// disables the link instead of silently inheriting whatever default the action happens to declare.
const envLinkToConsole = "FERRALON_LINK_TO_CONSOLE"

// linkedToConsole reports whether this run may talk to Ferralon at all. It fails closed: any
// value that is not an explicit true (strconv.ParseBool: "true"/"1"/"t"/"T"/"TRUE"/"True") reads
// as not linked, so a typo degrades to a standalone scan rather than to an unintended beacon.
func linkedToConsole() bool {
	linked, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(envLinkToConsole)))
	return err == nil && linked
}

// resolveEndpoint returns the endpoint a Ferralon-bound call should use, or "" for OFF. The
// precedence is explicit at every step, with no state inferred from emptiness in the consent path:
//
//	not linked          → "" (off, unconditionally — the toggle wins over any configured URL)
//	linked + override   → the override (the GHE / dev / substrate escape hatch)
//	linked, no override → the baked release default
//	linked, baked empty → "" (off — an OSS build has no endpoint to fall back to)
//
// Returning "" for off keeps every downstream gate exactly as it was: postScan and
// selectRunSnapshotSink both already treat an empty URL as "this surface is disabled", so the
// OSS/dogfood path reaches them unchanged.
func resolveEndpoint(linked bool, override, baked string) string {
	if !linked {
		return ""
	}
	if override != "" {
		return override
	}
	return baked
}
