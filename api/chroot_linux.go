// +build linux

package api

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"syscall"
)

// bind mount a filesystem from the parent env into the new chroot.
func bindMount(newRoots string, srcFS ...string) error {
	if len(srcFS) == 0 {
		return nil
	}
	tgt := path.Join(newRoots, srcFS[0])
	if err := os.MkdirAll(tgt, os.ModePerm); err != nil {
		return err
	}
	if err := syscall.Mount(srcFS[0], tgt, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	if err := bindMount(newRoots, srcFS[1:]...); err != nil {
		syscall.Unmount(tgt, 0)
		return err
	}
	return nil
}

// In the chroot, mount a filesystem using definitions contained in
// the /etc/fstab in that chroot.  Bind mounts need to be mounted
// first to make /dev and /sys available.
func subMount(newRoots string, srcFS ...string) error {
	if len(srcFS) == 0 {
		return nil
	}
	tgt := path.Join(newRoots, srcFS[0])
	if err := os.MkdirAll(tgt, os.ModePerm); err != nil {
		return err
	}
	cmd := exec.Command("mount", srcFS[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: newRoots}
	if err := cmd.Run(); err != nil {
		return err
	}
	if err := bindMount(newRoots, srcFS[1:]...); err != nil {
		syscall.Unmount(tgt, 0)
		return err
	}
	return nil
}

// Get a map containing the already mounted filesystems.
// This lets us call the chroot setup code multiple times
// safely.
func mountedFSes() (map[string]struct{}, error) {
	mounts, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil, fmt.Errorf("Error reading mounted filesystems: %v", err)
	}
	defer mounts.Close()
	res := map[string]struct{}{}
	lines := bufio.NewScanner(mounts)
	for lines.Scan() {
		line := strings.Fields(lines.Text())
		res[line[1]] = struct{}{}
	}
	return res, nil
}

// Get a list of all the file systems we should bind mount.  We want
// to bind mount the first proc, sysfs, devtmpfs, efivarfs, and devpts
// filesystems that are listed in /proc/self/mounts.
func basicBinds(chrootDir string) ([]string, error) {
	currentMounts, err := mountedFSes()
	if err != nil {
		return nil, err
	}
	mounts, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil, fmt.Errorf("Unable to determine mounted filesystems: %v", err)
	}
	defer mounts.Close()
	fses := map[string]string{}
	lines := bufio.NewScanner(mounts)
	for lines.Scan() {
		line := strings.Fields(lines.Text())
		switch line[2] {
		case "proc", "sysfs", "devtmpfs", "efivarfs", "devpts":
			{
				if _, ok := fses[line[0]]; !ok {
					fses[line[0]] = line[1]
				}
			}
		}
	}
	res := []string{}
	for _, v := range fses {
		if _, ok := currentMounts[path.Join(chrootDir, v)]; !ok {
			res = append(res, v)
		}
	}
	sort.Slice(res, func(i, j int) bool { return len(res[i]) < len(res[j]) })
	return res, nil
}

// In addition, we want to bind-mount the agent dir into the chroot.
func bindFSes(chroot string) ([]string, error) {
	return basicBinds(chroot)
}

func ignoreFSes() (map[string]struct{}, error) {
	res := map[string]struct{}{}
	fses, err := os.Open("/proc/filesystems")
	if err != nil {
		return nil, fmt.Errorf("Error determinig supported filesystems: %v", err)
	}
	defer fses.Close()
	lines := bufio.NewScanner(fses)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if strings.HasPrefix(line, "nodev") && line != `nodev	tmpfs` {
			continue
		}
		res[line] = struct{}{}
	}
	return res, nil
}

// In addition to the bind-mounts, we want to mount all
// of the device based filesystems mentioned in
// the /etc/fstab inside the chroot, if available.
// This code makes that list.
func mountOthers(chroot string) ([]string, error) {
	ignore, err := ignoreFSes()
	if err != nil {
		return nil, err
	}
	currentMounts, err := mountedFSes()
	if err != nil {
		return nil, err
	}
	res := []string{}
	fstabPath := path.Join(chroot, "/etc/fstab")
	fstab, err := os.Open(fstabPath)
	if err != nil {
		return res, nil
	}
	defer fstab.Close()
	lines := bufio.NewScanner(fstab)
	for lines.Scan() {
		line := lines.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		dev, fs, fstype := fields[0], fields[1], fields[2]
		if fs == "/" || !strings.HasPrefix(fs, "/") {
			continue
		}
		if !(strings.HasPrefix(dev, "/") ||
			strings.HasPrefix(dev, "LABEL=") ||
			strings.HasPrefix(dev, "UUID=")) {
			continue
		}
		if _, ok := ignore[fs]; ok || fstype == "swap" {
			continue
		}
		if _, ok := currentMounts[fs]; ok {
			continue
		}
		res = append(res, fs)
	}
	sort.Slice(res, func(i, j int) bool { return len(res[i]) < len(res[j]) })
	return res, nil
}

// mountChroot mounts all the required bind mounts along with all of
// the sub file systems mentioned in the /etc/fstab in the chroot.
// If / in the chroot is a seperate filesystem, it must already be mounted.
//
// Mounts must happen in the following order:
//
// 1. Basic bind mounts
//
// 2. Mount "real" filesystems mentioned in /etc/fatab in the chroot, if any
//
// 3. Bind mount the agent dir into the chroot.
func mountChroot(chroot, agentDir string) error {
	binds, err := bindFSes(chroot)
	if err != nil {
		return err
	}
	if err = bindMount(chroot, binds...); err != nil {
		return err
	}
	others, err := mountOthers(chroot)
	if err != nil {
		return err
	}
	if err := subMount(chroot, others...); err != nil {
		return err
	}
	return bindMount(chroot, agentDir)
}

// exitChroot unmounts all the filesystems in the chroot,
// including / if it is a seperate filesystem as well.
func exitChroot(chroot string) error {
	fses, err := mountedFSes()
	if err != nil {
		return err
	}
	toUmount := []string{}
	for k := range fses {
		if !strings.HasPrefix(k, chroot) {
			toUmount = append(toUmount, k)
		}
	}
	sort.Slice(toUmount, func(i, j int) bool { return len(toUmount[i]) < len(toUmount[j]) })
	for i := len(toUmount) - 1; i > -1; i-- {
		syscall.Unmount(toUmount[i], 0)
	}
	return nil
}

func (r *TaskRunner) enterChroot(cmd *exec.Cmd) error {
	if r.chrootDir == "" {
		return nil
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: r.chrootDir}
	return nil
}
