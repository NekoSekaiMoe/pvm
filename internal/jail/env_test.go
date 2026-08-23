package jail

import (
	"strings"
	"testing"
)

// existingDirs returns a dirExists predicate backed by a fixed set.
func existingDirs(dirs ...string) func(string) bool {
	set := map[string]bool{}
	for _, d := range dirs {
		set[d] = true
	}
	return func(p string) bool { return set[p] }
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

func TestJailHomeEnv(t *testing.T) {
	tests := []struct {
		name      string
		env       []string
		dirs      []string
		wantHome  string
		wantFirst bool // HOME must be replaced in place, not appended
	}{
		{
			name:     "inherited HOME missing in jail is repointed to /tmp",
			env:      []string{"PATH=/usr/bin", "HOME=/root", "USER=root"},
			dirs:     []string{"/tmp"},
			wantHome: "/tmp",
		},
		{
			name:     "existing HOME is kept",
			env:      []string{"HOME=/data"},
			dirs:     []string{"/data", "/tmp"},
			wantHome: "/data",
		},
		{
			name:     "missing HOME is set",
			env:      []string{"PATH=/usr/bin"},
			dirs:     []string{"/tmp"},
			wantHome: "/tmp",
		},
		{
			name:     "empty HOME is replaced",
			env:      []string{"HOME="},
			dirs:     []string{"/tmp"},
			wantHome: "/tmp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jailHomeEnv(append([]string{}, tt.env...), existingDirs(tt.dirs...))
			home, ok := envValue(got, "HOME")
			if !ok {
				t.Fatalf("HOME missing from result env: %v", got)
			}
			if home != tt.wantHome {
				t.Errorf("HOME=%q, want %q (env %v)", home, tt.wantHome, got)
			}
			// Exactly ONE HOME entry: an appended duplicate would be
			// shadowed by the first match in getenv, defeating the fix.
			n := 0
			for _, e := range got {
				if strings.HasPrefix(e, "HOME=") {
					n++
				}
			}
			if n != 1 {
				t.Errorf("result has %d HOME entries, want exactly 1: %v", n, got)
			}
			// Non-HOME entries survive untouched.
			for _, e := range tt.env {
				if strings.HasPrefix(e, "HOME=") {
					continue
				}
				found := false
				for _, g := range got {
					if g == e {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("env entry %q lost: %v", e, got)
				}
			}
		})
	}
}
