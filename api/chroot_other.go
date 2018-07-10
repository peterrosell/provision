// +build !linux

package api

import (
	"fmt"
	"os/exec"
	"runtime"
)

func mountChroot(chroot, agentDir string) error {
	return fmt.Errorf("mountChroot not supported on %v", runtime.GOOS)
}

func exitChroot(chroot string) error { return nil }

func (r *TaskRunner) enterChroot(cmd *exec.Cmd) error {
	if r.chrootDir == "" {
		return nil
	}
	return fmt.Errorf("enterChroot not supported on %v", runtime.GOOS)
}
