package state

import (
	"testing"
)

func TestContainerDir(t *testing.T) {
	// Test valid ID
	dir := ContainerDir("valid-id_123")
	expected := RootDir + "/valid-id_123"
	if dir != expected {
		t.Errorf("Expected %s, got %s", expected, dir)
	}

	// Test invalid ID using defer recover
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic on invalid ID")
		}
	}()
	ContainerDir("../invalid")
}
