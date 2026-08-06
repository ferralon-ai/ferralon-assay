// internal/ids/ids.go
package ids

import "github.com/google/uuid"

// New returns a new UUIDv7 string (RFC 9562). Time-ordered, monotonic.
func New() string {
	return uuid.Must(uuid.NewV7()).String()
}
