package network

import (
	"fmt"
	"os/exec"
)

func CreateTap(name string) error {
	cmd := exec.Command("ip", "tuntap", "add", "mode", "tap", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create tap %s: %v", name, err)
	}

	cmd = exec.Command("ip", "link", "set", name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up tap %s: %v", name, err)
	}

	return nil
}
