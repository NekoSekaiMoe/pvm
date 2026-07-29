package config

import (
	"testing"
)

func TestContainerConfig(t *testing.T) {
	cfg := &ContainerConfig{
		ID:        "test-id",
		Name:      "test-name",
		Memory:    "512M",
		UseVirtio: true,
	}

	if cfg.ID != "test-id" {
		t.Errorf("Expected ID to be test-id, got %s", cfg.ID)
	}
	if cfg.Memory != "512M" {
		t.Errorf("Expected Memory to be 512M, got %s", cfg.Memory)
	}
}
