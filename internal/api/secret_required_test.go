package api

import (
	"strings"
	"testing"

	"uml-container/internal/state"
)

// TestStartE2BServer_MissingSecretRefusesToStart pins the no-default-credential
// behavior: with API_SECRET unset the server must return an error instead of
// silently authenticating everyone who guesses the old "secret" fallback.
func TestStartE2BServer_MissingSecretRefusesToStart(t *testing.T) {
	t.Setenv("API_SECRET", "")
	state.RootDir = t.TempDir()
	port := freePort(t)
	err := StartE2BServer(port)
	if err == nil {
		t.Fatal("StartE2BServer must refuse to start without API_SECRET")
	}
	if !strings.Contains(err.Error(), "API_SECRET") {
		t.Errorf("error should mention API_SECRET, got: %v", err)
	}
}
