//go:build !linux

package jail

import "os/exec"

func ConfigureProcessIsolation(cmd *exec.Cmd, j *JailEnvironment) error {
	return nil
}
