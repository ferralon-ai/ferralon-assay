// Package hostmatch compiles a trusted, static allowlist of host patterns into an
// immutable Matcher and tests bare hostnames for membership. It is a positive
// allowlist primitive: names via a reverse-label trie with single-label wildcards,
// IPs/CIDRs via net.IPNet membership. It holds no policy — callers decide what a
// deny or an error means.
//
// # Fail-error doctrine
//
// Allows returns a three-way outcome:
//
//	(true,  nil)  host is well-formed and in the allowlist
//	(false, nil)  host is well-formed and NOT in the allowlist   (normal deny)
//	(false, err)  host violates the input contract               (never a silent deny)
//
// It NEVER returns (true, non-nil). A malformed host reaching the matcher is an
// upstream plumbing bug; erroring surfaces it rather than masking it as a "deny"
// (which pressures someone to loosen the allowlist). The deny-loud-on-error policy
// lives in the caller, not in this primitive.
//
// # Concurrency
//
// A Matcher is immutable once built by New and is safe for concurrent use by
// multiple goroutines.
package hostmatch

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrMalformedHost is returned (wrapped, via fmt.Errorf("%w: …", …)) by Allows when
// the queried host violates the input contract — so callers can branch with
// errors.Is(err, hostmatch.ErrMalformedHost).
var ErrMalformedHost = errors.New("hostmatch: malformed host")

// Matcher is an immutable, concurrency-safe compiled allowlist.
type Matcher struct {
	root   *node        // reverse-label trie of name patterns (apex first)
	ipNets []*net.IPNet // exact IPs (family-correct full mask) and CIDR ranges
}

// node is one label of the reverse-label trie. It is written only during New and
// read-only thereafter.
type node struct {
	exact    map[string]*node // exact-label children
	wild     *node            // single "*" edge (matches exactly one label)
	terminal bool             // a complete pattern ends here
}

func newNode() *node { return &node{exact: map[string]*node{}} }

// match walks the trie against labels (already reversed and validated). It tries the
// exact child first, then backtracks to the wildcard edge, so interior wildcards and
// exact-vs-wildcard precedence both resolve correctly.
func (n *node) match(labels []string) bool {
	if len(labels) == 0 {
		return n.terminal
	}
	head, rest := labels[0], labels[1:]
	if c := n.exact[head]; c != nil && c.match(rest) {
		return true
	}
	if n.wild != nil {
		return n.wild.match(rest)
	}
	return false
}

// New compiles patterns (TRUSTED, static — never attacker input) into a Matcher.
// Each pattern is one of:
//
//	exact name      "github.com"
//	wildcard name   "*.ghe.com"            (* = exactly one label; may be interior:
//	                "git-codecommit.*.amazonaws.com")
//	exact IP        "10.0.0.1" | "2001:db8::1"
//	CIDR range      "10.0.0.0/8" | "2001:db8::/32"
//
// Compilation fails as a whole (returns an error naming the offending pattern) on any
// malformed pattern: a bad LDH label, a wildcard that is not a whole single label,
// more than one wildcard, a wildcard with fewer than 2 fixed labels to its right
// (blocks "*" and "*.com"), or an unparseable IP/CIDR.
func New(patterns []string) (*Matcher, error) {
	m := &Matcher{root: newNode()}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("hostmatch: empty pattern")
		}
		switch {
		case strings.Contains(p, "/"):
			_, ipNet, err := net.ParseCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("hostmatch: bad CIDR pattern %q: %w", p, err)
			}
			m.ipNets = append(m.ipNets, ipNet)
		default:
			if ip := net.ParseIP(p); ip != nil {
				m.ipNets = append(m.ipNets, exactIPNet(ip))
				continue
			}
			if err := m.insertName(p); err != nil {
				return nil, fmt.Errorf("hostmatch: bad name pattern %q: %w", p, err)
			}
		}
	}
	return m, nil
}

// insertName validates a name pattern and inserts it (reversed, apex first) into the
// trie. Wildcard rules: at most one "*" label; a "*" label is a whole single label;
// a "*" must have at least 2 fixed labels to its right.
func (m *Matcher) insertName(p string) error {
	labels := strings.Split(strings.ToLower(p), ".")
	wildCount := 0
	for i, label := range labels {
		if label == "*" {
			wildCount++
			if wildCount > 1 {
				return fmt.Errorf("more than one wildcard label")
			}
			// fixed labels to the right of this "*"
			if len(labels)-1-i < 2 {
				return fmt.Errorf("wildcard needs at least 2 fixed labels to its right")
			}
			continue
		}
		if strings.Contains(label, "*") {
			return fmt.Errorf("wildcard must be a whole label (%q)", label)
		}
		if err := validLabel(label); err != nil {
			return err
		}
	}
	// Insert reversed (apex first).
	n := m.root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if label == "*" {
			if n.wild == nil {
				n.wild = newNode()
			}
			n = n.wild
			continue
		}
		c := n.exact[label]
		if c == nil {
			c = newNode()
			n.exact[label] = c
		}
		n = c
	}
	n.terminal = true
	return nil
}

// Allows reports whether host is admitted. host MUST be a single bare host exactly as
// url.URL.Hostname() yields it: no scheme, no port, no brackets, no CIDR/mask, no
// userinfo, no zone id. Contract:
//
//	(true,  nil) host is well-formed and in the allowlist
//	(false, nil) host is well-formed and NOT in the allowlist   (normal deny)
//	(false, err) host violates the input contract               (never a silent deny)
//
// It NEVER returns (true, non-nil). Only a single IP is valid on the IP path; a CIDR
// or any "/" in the input is a contract violation -> error. A trailing-dot FQDN form
// ("github.com.") yields a trailing empty label and so errors rather than normalizing;
// pass the host exactly as url.URL.Hostname() yields it.
func (m *Matcher) Allows(host string) (bool, error) {
	if host == "" {
		return false, fmt.Errorf("%w: empty host", ErrMalformedHost)
	}
	// Input contract: a bare Hostname() carries none of these.
	if strings.Contains(host, "/") {
		return false, fmt.Errorf("%w: contains '/': %q", ErrMalformedHost, host)
	}
	if strings.Contains(host, "%") {
		return false, fmt.Errorf("%w: contains zone id '%%': %q", ErrMalformedHost, host)
	}
	if strings.ContainsAny(host, "[]") {
		return false, fmt.Errorf("%w: contains bracket: %q", ErrMalformedHost, host)
	}

	if ip := net.ParseIP(host); ip != nil {
		return m.anyContains(ip.To16()), nil
	}

	labels := strings.Split(strings.ToLower(host), ".")
	for _, label := range labels {
		if label == "*" {
			return false, fmt.Errorf("%w: literal '*' label: %q", ErrMalformedHost, host)
		}
		if err := validLabel(label); err != nil {
			return false, fmt.Errorf("%w: %w: %q", ErrMalformedHost, err, host)
		}
	}
	reversed := make([]string, len(labels))
	for i, label := range labels {
		reversed[len(labels)-1-i] = label
	}
	return m.root.match(reversed), nil
}

// anyContains reports whether any compiled IP/CIDR net contains ip.
func (m *Matcher) anyContains(ip net.IP) bool {
	for _, n := range m.ipNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// exactIPNet builds a family-correct full-mask net for an exact IP. It derives the
// bit length from the address family — never hardcodes /32, or an IPv6 host would
// silently become a 2^96 range.
func exactIPNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// validLabel reports whether label is a valid LDH DNS label: non-empty, at most 63
// bytes, characters in [a-z0-9-], with no leading or trailing hyphen. Callers must
// lower-case before validating.
func validLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label exceeds 63 bytes")
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return fmt.Errorf("label has non-LDH byte")
		}
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label has leading or trailing hyphen")
	}
	return nil
}
