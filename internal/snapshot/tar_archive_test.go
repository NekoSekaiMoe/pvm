package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshot_ExportImport(t *testing.T) {
	// Setup test environment
	baseDir := "/var/lib/uml-container/containers"
	// Ensure base dir exists for test, or we can mock the paths if they were configurable.
	// Since paths are hardcoded to /var/lib in the implementation, we might face permission issues
	// if not running as root. We will mock the paths in the functions if we want it fully unit-testable,
	// but for now, we will create a lightweight test that checks if tar is invoked or we'll skip 
	// if we don't have permissions.
	
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Skipf("Skipping test due to permission error on %s (run as root): %v", baseDir, err)
	}
	
	containerID := "test-snap-1"
	containerDir := filepath.Join(baseDir, containerID)
	os.MkdirAll(containerDir, 0755)
	
	// Create dummy file
	dummyFile := filepath.Join(containerDir, "config.json")
	os.WriteFile(dummyFile, []byte(`{"test":true}`), 0644)
	
	tgzPath := "/tmp/test-export.tgz"
	
	err := Export(containerID, tgzPath)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	
	if _, err := os.Stat(tgzPath); err != nil {
		t.Fatalf("Export did not create archive: %v", err)
	}
	defer os.Remove(tgzPath)
	
	newID := "test-snap-2"
	err = Import(tgzPath, newID)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	
	importedFile := filepath.Join(baseDir, newID, "config.json")
	data, err := os.ReadFile(importedFile)
	if err != nil {
		t.Fatalf("Failed to read imported file: %v", err)
	}
	
	if string(data) != `{"test":true}` {
		t.Errorf("Imported content mismatch: %q", string(data))
	}
	
	// Cleanup
	os.RemoveAll(containerDir)
	os.RemoveAll(filepath.Join(baseDir, newID))
}
