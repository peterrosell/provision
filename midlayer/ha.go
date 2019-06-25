package midlayer

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"time"

	"github.com/j-keck/arping"
)

func runCmd(command ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	return stdout.Bytes(), stderr.Bytes(), err
}

func AddIP(addr, iface string) error {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return err
	}
	var cmd []string
	switch runtime.GOOS {
	case "darwin":
		cmd = []string{"ifconfig", iface, "alias", addr}
	case "linux":
		cmd = []string{"ip", "address", "add", addr, "dev", iface}
	default:
		return fmt.Errorf("Unsupported platform: %s", runtime.GOOS)
	}
	if _, _, err := runCmd(cmd...); err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		if err := arping.GratuitousArpOverIfaceByName(ip, iface); err != nil {
			return err
		}
		time.Sleep(time.Millisecond * 50)
	}
	return nil
}

func RemoveIP(addr, iface string) error {
	var cmd []string
	switch runtime.GOOS {
	case "darwin":
		cmd = []string{"ifconfig", iface, "-alias", addr}
	case "linux":
		cmd = []string{"ip", "address", "del", addr, "dev", iface}
	default:
		return fmt.Errorf("Unsupported platform: %s", runtime.GOOS)
	}
	_, _, err := runCmd(cmd...)
	return err

}
