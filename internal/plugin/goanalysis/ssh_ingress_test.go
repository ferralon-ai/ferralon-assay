// Hermetic goanalysis test for SSH server ingress detection (ingress.go). It loads a
// real fixture (sshmod) with the Go toolchain — no live model, no Docker, no network:
// the fixture's go.mod replaces golang.org/x/crypto/ssh with a local stub so the
// detector matches the package path without fetching the real module.
//
// It pins the demo-go-svc CVE-2024-45337 shape: handleSSHConn(sconn *ssh.ServerConn,
// ...) reading sconn.Permissions.Extensions["role"] must surface as an
// Ingress{Kind:"ssh"} — the attacker-input boundary that was previously invisible, so
// the sink reached only via main graded control_flow_only. It also proves the detector
// does not over-fire: non-ssh helpers and trusted-context ssh types (PublicKey /
// ServerConfig) are not ssh ingresses, and the net/http detectors are unregressed.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const sshFixtureDir = "testdata/sshmod"

func TestSSH_ServerConnHandlerIsIngress(t *testing.T) {
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: sshFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	var sshIngresses, httpIngresses []string
	sawTrusted, sawNonIngress := false, false
	for _, in := range res.Ingresses {
		switch in.Kind {
		case "ssh":
			sshIngresses = append(sshIngresses, in.Symbol.SCIP)
			if strings.Contains(in.Symbol.SCIP, "trustedKeySetup") {
				sawTrusted = true
			}
			if strings.Contains(in.Symbol.SCIP, "notAnIngress") {
				sawNonIngress = true
			}
		case "http_route", "handler":
			httpIngresses = append(httpIngresses, in.Symbol.SCIP)
		}
	}

	sshOK := false
	for _, s := range sshIngresses {
		if strings.Contains(s, "handleSSHConn") {
			sshOK = true
		}
	}
	if !sshOK {
		t.Fatalf("handleSSHConn not surfaced as an ssh ingress; ssh ingresses = %v; all = %+v", sshIngresses, res.Ingresses)
	}

	// Honesty guard: excluded/trusted-context types must not become ssh ingresses.
	if sawTrusted {
		t.Errorf("trustedKeySetup (PublicKey/ServerConfig only) must NOT be an ssh ingress; ssh ingresses = %v", sshIngresses)
	}
	if sawNonIngress {
		t.Errorf("notAnIngress (no ssh param) must NOT be an ssh ingress; ssh ingresses = %v", sshIngresses)
	}

	// Regression: net/http detection unaffected in the same module.
	stdlibOK := false
	for _, s := range httpIngresses {
		if strings.Contains(s, "stdlibHandler") {
			stdlibOK = true
		}
	}
	if !stdlibOK {
		t.Errorf("net/http detection regressed: stdlibHandler not an http ingress; http ingresses = %v", httpIngresses)
	}
}
