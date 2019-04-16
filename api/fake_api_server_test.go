package api

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/digitalrebar/provision/embedded"
	"github.com/digitalrebar/provision/server"
	flags "github.com/jessevdk/go-flags"
)

var session *Client
var tmpDir string

func generateArgs(args []string) (*server.ProgOpts, error) {
	var c_opts server.ProgOpts

	parser := flags.NewParser(&c_opts, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			return nil, err
		}
	}

	return &c_opts, nil
}

func fakeServer() error {
	var err error

	embedded.IncludeMeFunction()

	testArgs := []string{
		"--base-root", tmpDir,
		"--tls-key", tmpDir + "/server.key",
		"--tls-cert", tmpDir + "/server.crt",
		"--api-port", "10011",
		"--static-port", "10012",
		"--tftp-port", "10013",
		"--dhcp-port", "10014",
		"--binl-port", "10015",
		"--metrics-port", "10016",
		"--fake-pinger",
		"--drp-id", "Fred",
		"--backend", "memory:///",
		"--local-content", "directory:../test-data/etc/dr-provision?codec=yaml",
		"--default-content", "file:../test-data/usr/share/dr-provision/default.yaml?codec=yaml",
	}

	err = os.MkdirAll(tmpDir+"/plugins", 0755)
	if err != nil {
		log.Printf("Error creating required directory %s: %v", tmpDir+"/plugins", err)
		return err
	}

	out, err := exec.Command("go", "generate", "../cmds/incrementer/incrementer.go").CombinedOutput()
	if err != nil {
		log.Printf("Failed to generate incrementer plugin: %v, %s", err, string(out))
		return err
	}

	out, err = exec.Command("go", "build", "-o", tmpDir+"/plugins/incrementer", "../cmds/incrementer/incrementer.go", "../cmds/incrementer/content.go").CombinedOutput()
	if err != nil {
		log.Printf("Failed to build incrementer plugin: %v, %s", err, string(out))
		return err
	}

	c_opts, err := generateArgs(testArgs)
	if err != nil {
		return err
	}
	go server.Server(c_opts)

	count := 0
	for count < 30 {
		session, err = UserSession("https://127.0.0.1:10011", "rocketskates", "r0cketsk8ts")
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
		count++
	}
	if session == nil {
		return fmt.Errorf("Failed to create UserSession: %v", err)
	}
	if err != nil {
		return err
	}
	return nil
}
