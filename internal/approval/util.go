package approval

import (
	"crypto/rand"
	"encoding/base64"
)

// randomString returns a url-safe random string of the given byte length.
func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}
