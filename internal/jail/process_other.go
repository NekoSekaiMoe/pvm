//go:build !linux

package jail

import (
	"fmt"
	"os/exec"
)

// ConfigureProcessIsolation fails closed on non-Linux platforms: namespace
// and pivot_root isolation are Linux-only, so there is no way to uphold the
// jail contract here. Returning nil would let Manager.Boot / StartTask sail
// past CheckSecurity with allow_insecure_degraded and run the workload
// completely un-isolated.
func ConfigureProcessIsolation(cmd *exec.Cmd, j *JailEnvironment) error {
	return fmt.Errorf("jail: process isolation requires Linux; refusing to start an un-isolated process on this platform")
}
