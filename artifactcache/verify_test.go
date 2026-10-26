package artifactcache

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // lock SRI algorithm under test
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"testing"
)

type verifyHandle struct{ *bytes.Reader }

func (verifyHandle) Path() string { return "" }
func (verifyHandle) Close() error { return nil }

func TestVerify(t *testing.T) {
	body := []byte("pinned tarball bytes")
	other := []byte("some other bytes")
	s1, s256, s512 := sha1.Sum(body), sha256.Sum256(body), sha512.Sum512(body) //nolint:gosec // lock SRI algorithm under test
	b64 := base64.StdEncoding.EncodeToString
	tests := []struct {
		name    string
		digest  string
		bytes   []byte
		wantErr error // nil, ErrIntegrityMismatch or ErrMalformedRef
	}{
		{name: "sha1 match", digest: "sha1:" + b64(s1[:]), bytes: body},
		{name: "sha1 mismatch", digest: "sha1:" + b64(s1[:]), bytes: other, wantErr: ErrIntegrityMismatch},
		{name: "sha1 malformed", digest: "sha1:" + b64(s1[:10]), bytes: body, wantErr: ErrMalformedRef},
		{name: "sha256 match", digest: "sha256:" + b64(s256[:]), bytes: body},
		{name: "sha256 mismatch", digest: "sha256:" + b64(s256[:]), bytes: other, wantErr: ErrIntegrityMismatch},
		{name: "sha256 malformed", digest: "sha256:" + b64(s256[:10]), bytes: body, wantErr: ErrMalformedRef},
		{name: "sha512 match", digest: "sha512:" + b64(s512[:]), bytes: body},
		{name: "sha512 mismatch", digest: "sha512:" + b64(s512[:]), bytes: other, wantErr: ErrIntegrityMismatch},
		{name: "sha512 malformed", digest: "sha512:" + b64(s512[:10]), bytes: body, wantErr: ErrMalformedRef},
		{name: "unsupported algorithm", digest: "sha384:" + b64(s512[:48]), bytes: body, wantErr: ErrMalformedRef},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(verifyHandle{bytes.NewReader(tt.bytes)}, Ref{PURL: "pkg:npm/qs@6.5.2", Digest: tt.digest})
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("Verify = %v, want nil", err)
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("Verify = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
