// +build !linux

package api

import (
	"fmt"
	"runtime"
)

func mountChroot(chroot, agentDir string) error {
	return fmt.Errorf("enterChroot not supported on %v", runtime.GOOS)
}

func exitChroot() error { return nil }
