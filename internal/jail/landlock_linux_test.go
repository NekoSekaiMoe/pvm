//go:build linux

package jail

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLandlockRuleAccess(t *testing.T) {
	tests := []struct {
		name string
		mode uint32
		want uint64
	}{
		{"directory keeps full RW set", unix.S_IFDIR | 0755, landlockAccessFSRw},
		{"regular file masked to exec|write|read", unix.S_IFREG | 0644, 0x01 | 0x02 | 0x04},
		{"unix socket masked (vhost-user bind)", unix.S_IFSOCK | 0755, 0x01 | 0x02 | 0x04},
		{"char device masked (/dev/net/tun bind)", unix.S_IFCHR | 0666, 0x01 | 0x02 | 0x04},
		{"fifo masked", unix.S_IFIFO | 0644, 0x01 | 0x02 | 0x04},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := landlockRuleAccess(tt.mode); got != tt.want {
				t.Errorf("landlockRuleAccess(%#o) = %#x, want %#x", tt.mode, got, tt.want)
			}
		})
		// The mask must always be a subset of the ruleset's handled rights,
		// otherwise LANDLOCK_ADD_RULE fails EINVAL.
		if got := landlockRuleAccess(tt.mode); got|landlockAccessFSRw != landlockAccessFSRw {
			t.Errorf("%s: mask %#x not a subset of handled %#x", tt.name, got, uint64(landlockAccessFSRw))
		}
	}
}
