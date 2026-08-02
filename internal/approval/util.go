package approval

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// randomString returns a url-safe random string of the given byte length, or
// an error if the system's CSPRNG could not fill the buffer.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: generate random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}
