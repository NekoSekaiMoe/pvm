package fsjson

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrite_RoundTripAndNoTempLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")

	type rec struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	if err := Write(path, rec{Name: "demo", N: 7}); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got rec
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, data)
	}
	if got.Name != "demo" || got.N != 7 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Overwrite must replace content, still without temp leftovers.
	if err := Write(path, rec{Name: "v2", N: 8}); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !strings.Contains(string(data), "\"v2\"") {
		t.Fatalf("content not replaced: %s", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "meta.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temp leftovers: %v", names)
	}
}

func TestWrite_UnwritableTarget(t *testing.T) {
	// Missing parent directory: CreateTemp must fail cleanly.
	if err := Write(filepath.Join(t.TempDir(), "nope", "meta.json"), struct{}{}); err == nil {
		t.Fatalf("expected error for missing parent dir")
	}
}
