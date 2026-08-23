//go:build !linux

package jail

func probeHostCapabilities() HostCapabilities {
	return HostCapabilities{
		HasSeccomp:  false,
		HasMountNS:  false,
		HasUserNS:   false,
		HasLandlock: false,
		Details:     "non-linux platform (security primitives unavailable)",
	}
}
