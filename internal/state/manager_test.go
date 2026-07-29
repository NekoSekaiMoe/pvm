package state

import (
	"testing"
)

func TestContainerDir(t *testing.T) {
	// Test valid ID
	dir, err := ContainerDir("valid-id_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := RootDir + "/valid-id_123"
	if dir != expected {
		t.Errorf("Expected %s, got %s", expected, dir)
	}

	_, err = ContainerDir("../invalid")
	if err == nil {
		t.Errorf("Expected error for invalid ID, got nil")
	}
}
