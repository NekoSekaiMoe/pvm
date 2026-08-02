package config

import (
	"math"
	"strings"
	"testing"
)

// TestParseMemory_Valid covers every accepted unit suffix (with case and
// "B"-suffixed variants) and boundary values like zero.
func TestParseMemory_Valid(t *testing.T) {
	const (
		KiB = int64(1024)
		MiB = 1024 * KiB
		GiB = 1024 * MiB
	)
	cases := []struct {
		in   string
		want int64
	}{
		{"256K", 256 * KiB},
		{"256k", 256 * KiB},
		{"128KB", 128 * KiB},
		{"128kb", 128 * KiB},
		{"512M", 512 * MiB},
		{"512m", 512 * MiB},
		{"512MB", 512 * MiB},
		{"512mb", 512 * MiB},
		{"1G", 1 * GiB},
		{"2g", 2 * GiB},
		{"2GB", 2 * GiB},
		{"2gb", 2 * GiB},
		{"0M", 0},
		// fmt.Sscanf("%d%s") skips intermediate whitespace.
		{"512 M", 512 * MiB},
		// Largest value that still fits after the G multiplier.
		{"8191G", 8191 * GiB},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseMemory(c.in)
			if err != nil {
				t.Fatalf("ParseMemory(%q) returned error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("ParseMemory(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestParseMemory_Invalid covers malformed input, negative values, unknown
// units and multiplier overflow.
func TestParseMemory_Invalid(t *testing.T) {
	cases := []struct {
		in      string
		wantSub string // substring expected in the error
	}{
		{"", "empty"},
		{"512", "invalid memory format"},   // no unit -> Sscanf shortfall
		{"abc", "invalid memory format"},   // no leading number
		{"M512", "invalid memory format"},  // unit before number
		{"-5M", "negative"},                // negative value
		{"-1G", "negative"},                // negative value, other unit
		{"10T", "unsupported or missing"},  // unknown unit
		{"512MiB", "unsupported or missing"}, // IEC suffix not accepted
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseMemory(c.in)
			if err == nil {
				t.Fatalf("ParseMemory(%q) = %d, want error containing %q", c.in, got, c.wantSub)
			}
			if got != 0 {
				t.Errorf("ParseMemory(%q) returned %d on error, want 0", c.in, got)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("ParseMemory(%q) error = %q, want substring %q", c.in, err, c.wantSub)
			}
		})
	}
}

// TestParseMemory_Overflow drives every unit past the int64 ceiling and
// expects a dedicated overflow error rather than a wrapped-around value.
func TestParseMemory_Overflow(t *testing.T) {
	// 9e18 parses into int64 but overflows when multiplied by any unit.
	huge := func(unit string) string { return "9000000000000000000" + unit }
	for _, in := range []string{huge("K"), huge("M"), huge("G"), "9223372036854775807G"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseMemory(in)
			if err == nil {
				t.Fatalf("ParseMemory(%q) = %d, want overflow error", in, got)
			}
			if !strings.Contains(err.Error(), "overflow") {
				t.Errorf("ParseMemory(%q) error = %q, want overflow", in, err)
			}
		})
	}
}

// TestParseMemory_MaxInt64Boundary makes sure the largest representable value
// in each unit does not falsely trip the overflow guard.
func TestParseMemory_MaxInt64Boundary(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		// MaxInt64/1024 = 9007199254740991 K
		{"9007199254740991K", math.MaxInt64 / 1024 * 1024},
		// MaxInt64/1MiB = 8796093022207 M
		{"8796093022207M", math.MaxInt64 / (1024 * 1024) * 1024 * 1024},
		// MaxInt64/1GiB = 8589934591 G
		{"8589934591G", math.MaxInt64 / (1024 * 1024 * 1024) * 1024 * 1024 * 1024},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseMemory(c.in)
			if err != nil {
				t.Fatalf("ParseMemory(%q) returned error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("ParseMemory(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
