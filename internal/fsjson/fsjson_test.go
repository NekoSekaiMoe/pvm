package fsjson

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWrite drives the Write scenarios as a table of named cases executed via
// t.Run: successful writes (with overwrite and no temp leftovers), unwritable
// targets, and encode failures that must leave the previous content intact.
func TestWrite(t *testing.T) {
	cases := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{"round trip and no temp leftovers", func(t *testing.T) {
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
			assertOnlyFile(t, dir, "meta.json")
		}},
		{"unwritable target", func(t *testing.T) {
			// Missing parent directory: CreateTemp must fail cleanly.
			if err := Write(filepath.Join(t.TempDir(), "nope", "meta.json"), struct{}{}); err == nil {
				t.Fatalf("expected error for missing parent dir")
			}
		}},
		{"encode failure keeps target intact", func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "meta.json")

			type rec struct {
				Name string `json:"name"`
			}
			if err := Write(path, rec{Name: "original"}); err != nil {
				t.Fatalf("seed write: %v", err)
			}

			// chan cannot be JSON-encoded; the overwrite must fail after CreateTemp.
			if err := Write(path, struct{ Ch chan int }{Ch: make(chan int)}); err == nil {
				t.Fatalf("expected encode error for chan value")
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !strings.Contains(string(data), "\"original\"") {
				t.Fatalf("target content changed after failed write: %s", data)
			}
			assertOnlyFile(t, dir, "meta.json")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.fn)
	}
}

// assertOnlyFile fails unless dir contains exactly the single named file.
func assertOnlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir contents = %v, want exactly [%s]", names, name)
	}
}
