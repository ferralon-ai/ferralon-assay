// Package ssh is a minimal local stand-in for golang.org/x/crypto/ssh, just enough
// for the SSH ingress detector to recognize the attacker-input boundary hermetically
// (no network fetch of the real module). The package PATH is what the detector matches
// (golang.org/x/crypto/ssh), supplied via a go.mod module directive + a replace in the
// fixture. The type shapes mirror the real ssh types the detector keys on:
// ServerConn/ConnMetadata (the live connection), NewChannel/Channel (offered channels),
// and Request (out-of-band requests). PublicKey and ServerConfig are included so the
// fixture can prove they are NOT treated as ingress params.
package ssh

// Permissions carries the authenticated principal's granted extensions/critical
// options — attacker-influenced values populated during the handshake.
type Permissions struct {
	Extensions map[string]string
}

// ConnMetadata is the metadata of an established connection.
type ConnMetadata interface {
	User() string
}

// ServerConn is a server-side established connection.
type ServerConn struct {
	Permissions *Permissions
}

// NewChannel is an offered channel from the peer.
type NewChannel interface {
	Accept() (Channel, <-chan *Request, error)
}

// Channel is an accepted bidirectional channel.
type Channel interface {
	Read(p []byte) (int, error)
}

// Request is an out-of-band request on a connection or channel.
type Request struct {
	Type    string
	Payload []byte
}

// PublicKey is an offered or trusted key — appears in both attacker and trusted
// contexts, so the detector deliberately does NOT key on it.
type PublicKey interface {
	Type() string
}

// ServerConfig holds server setup — a trusted-configuration type, not attacker input.
type ServerConfig struct {
	PublicKeyCallback func(conn ConnMetadata, key PublicKey) (*Permissions, error)
}
