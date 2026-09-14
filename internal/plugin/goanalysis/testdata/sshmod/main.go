// Command sshmod is a hermetic fixture exercising SSH server ingress detection
// (ingress.go). handleSSHConn mirrors the demo-go-svc CVE-2024-45337 shape: it
// takes the accepted *ssh.ServerConn (plus the channel/request streams) and reads
// the attacker-influenced sconn.Permissions.Extensions["role"] — the SSH attacker-
// input boundary the detector must surface as an Ingress{Kind:"ssh"}.
//
// The file also carries counter-shapes the detector must NOT flag as ssh ingresses:
// a stdlib net/http handler (still its own http_route/handler ingress), a func that
// takes no ssh param, and a func whose only ssh param is a PublicKey/ServerConfig
// (trusted-context types deliberately excluded from the attacker set).
package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

// handleSSHConn is the SSH attacker-input boundary: the accepted server connection
// and its channel/request streams are all attacker-controlled.
func handleSSHConn(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	role := sconn.Permissions.Extensions["role"]
	_ = role
	_ = chans
	_ = reqs
}

// stdlibHandler is a net/http handler — proves the http detectors are unaffected.
func stdlibHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.Method
}

// notAnIngress takes no ssh param and must not be flagged.
func notAnIngress(s string) string { return s + "!" }

// trustedKeySetup takes only excluded ssh types (PublicKey / ServerConfig) and must
// NOT be flagged as an ssh ingress.
func trustedKeySetup(cfg *ssh.ServerConfig, key ssh.PublicKey) {
	_ = cfg
	_ = key
}

func main() {
	http.HandleFunc("/health", stdlibHandler)
	_ = handleSSHConn
	_ = notAnIngress
	_ = trustedKeySetup
}
