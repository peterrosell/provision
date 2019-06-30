package cli

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/api"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/embedded"
	"github.com/digitalrebar/provision/midlayer"
	"github.com/digitalrebar/provision/server"
	"github.com/jessevdk/go-flags"
)

var (
	tmpDir  string
	myToken string
)

func generateArgs(args []string) *server.ProgOpts {
	var c_opts server.ProgOpts

	parser := flags.NewParser(&c_opts, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	return &c_opts
}

func fakeServer() error {
	var err error

	os.Setenv("RS_TOKEN_PATH", path.Join(tmpDir, "tokens"))
	os.Setenv("RS_ENDPOINT", "https://127.0.0.1:10001")

	testArgs := []string{
		"--base-root", tmpDir,
		"--tls-key", tmpDir + "/server.key",
		"--tls-cert", tmpDir + "/server.crt",
		"--api-port", "10001",
		"--static-port", "10002",
		"--tftp-port", "10003",
		"--dhcp-port", "10004",
		"--binl-port", "10005",
		"--metrics-port", "10006",
		"--static-ip", "127.0.0.1",
		"--fake-pinger",
		"--no-watcher",
		"--drp-id", "Fred",
		"--backend", "memory:///",
		"--plugin-comm-root", "/tmp",
		"--local-content", "directory:../test-data/etc/dr-provision?codec=yaml",
		"--default-content", "file:../test-data/usr/share/dr-provision/default.yaml?codec=yaml",
		"--base-token-secret", "token-secret-token-secret-token1",
		"--system-grantor-secret", "system-grantor-secret",
	}

	err = os.MkdirAll(tmpDir+"/plugins", 0755)
	if err != nil {
		log.Printf("Error creating required directory %s: %v", tmpDir, err)
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

	embedded.IncludeMeFunction()

	c_opts := generateArgs(testArgs)
	go server.Server(c_opts)
	count := 0
	for count < 30 {
		var apierr error
		session, apierr = api.UserSession("https://127.0.0.1:10001", "rocketskates", "r0cketsk8ts")
		if apierr == nil {
			break
		}
		count++
		time.Sleep(1 * time.Second)
	}
	if session == nil {
		return fmt.Errorf("Server failed to start in time allowed")
	} else {
		log.Printf("Server started after %d seconds", count)
		myToken = session.Token()
		session.Close()
		session = nil
		midlayer.ServeStatic("127.0.0.1:10003",
			backend.NewFS("test-data", nil),
			logger.New(nil).Log(""),
			backend.NewPublishers(nil))
	}
	return nil
}
