package repoconfig

import (
	"fmt"
	"strings"
)

// Window is a scan window: how far back the advisories a scan evaluates were published. Each
// window is backed by one advisory corpus policy (Policy).
type Window string

// The scan windows. These four are the whole vocabulary; anything else is rejected.
const (
	Window24h  Window = "24h"
	Window7d   Window = "7d"
	Window30d  Window = "30d"
	WindowFull Window = "full"
)

// windowPolicies maps each window to the advisory corpus policy that backs it.
var windowPolicies = []struct {
	window Window
	policy string
}{
	{Window24h, "published-24h"},
	{Window7d, "published-7d"},
	{Window30d, "published-30d"},
	{WindowFull, "full"},
}

// ParseWindow accepts exactly one of the four window names.
func ParseWindow(s string) (Window, error) {
	for _, wp := range windowPolicies {
		if s == string(wp.window) {
			return wp.window, nil
		}
	}
	names := make([]string, len(windowPolicies))
	for i, wp := range windowPolicies {
		names[i] = string(wp.window)
	}
	return "", fmt.Errorf("scan.window %q is not a scan window (one of %s)", s, strings.Join(names, ", "))
}

// Policy is the advisory corpus policy id that backs w, or "" for the zero Window.
func (w Window) Policy() string {
	for _, wp := range windowPolicies {
		if w == wp.window {
			return wp.policy
		}
	}
	return ""
}

// WindowForPolicy is the window a policy id backs, or "" when the policy is not one of the four
// window policies (a corpus can publish others, e.g. kev).
func WindowForPolicy(policy string) Window {
	for _, wp := range windowPolicies {
		if policy == wp.policy {
			return wp.window
		}
	}
	return ""
}
