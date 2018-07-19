package server

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/digitalrebar/provision"
	"github.com/jessevdk/go-flags"
)

var (
	tmpDir string
)

func generateArgs(args []string) *ProgOpts {
	var cOpts ProgOpts

	parser := flags.NewParser(&cOpts, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	return &cOpts
}

func badArgTest(t *testing.T, errString string, args ...string) {
	t.Helper()
	cOpts := generateArgs(args)
	localLogger := log.New(os.Stderr, "dr-provision", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	if answer := server(localLogger, cOpts); !strings.HasPrefix(answer, errString) {
		t.Errorf("Failed to get error string: %s: Got: %s\n", errString, answer)
	}
}

func TestServerArgs(t *testing.T) {
	badArgTest(t, fmt.Sprintf("Version: %s", provision.RSVersion), "--version")

	certFile := fmt.Sprintf("/%s/certfile.pem", tmpDir)
	existingFile := fmt.Sprintf("/%s/placeholder.txt", tmpDir)
	f, err := os.OpenFile(existingFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Errorf(err.Error())
	}
	if err := f.Close(); err != nil {
		t.Errorf(err.Error())
	}

	f, err = os.OpenFile("/tmp/greg.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Errorf(err.Error())
	}
	if err := f.Close(); err != nil {
		t.Errorf(err.Error())
	}

	badArgTest(t, "Error creating required directory", "--base-root", existingFile)
	badArgTest(t, "PluginCommRoot Must be less than 70 characters", "--base-root", tmpDir, "--plugin-comm-root", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--file-root", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--replace-root", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--plugin-root", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--plugin-comm-root", "/tmp/greg.txt")
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--data-root", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--log-root", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--local-ui", existingFile)
	badArgTest(t, "Error creating required directory", "--base-root", tmpDir, "--saas-content-root", existingFile)

	badArgTest(t, "Unable to create DataStack: Failed to open local content: Unknown schema type:", "--base-root", tmpDir, "--local-content", existingFile, "--metrics-port", "10101")
	badArgTest(t, "Unable to create DataStack: Failed to open default content: Unknown schema type:", "--base-root", tmpDir, "--local-content", "", "--default-content", existingFile, "--metrics-port", "10102")
	badArgTest(t, "Try one of `trace`,`debug`,`info`,`warn`,`error`,`fatal`,`panic`", "--base-root", tmpDir, "--default-content", "", "--local-content", "", "--log-level", "cow")

	badArgTest(t, "Error building certs: failed to open key.pem for writing: open", "--base-root", tmpDir, "--default-content", "", "--local-content", "", "--drp-id", "gregfield", "--tls-cert", certFile, "--tls-key", tmpDir, "--metrics-port", "10103")

	os.Remove(certFile)
	os.Remove(existingFile)
	os.Remove("/tmp/greg.txt")
}

func TestServer(t *testing.T) {

	testArgs := []string{
		"--base-root", tmpDir,
		"--tls-key", tmpDir + "/server.key",
		"--tls-cert", tmpDir + "/server.crt",
		"--api-port", "10001",
		"--static-port", "10002",
		"--tftp-port", "10003",
		"--metrics-port", "10004",
		"--disable-dhcp",
		"--local-content", "directory:../test-data/etc/dr-provision?codec=yaml",
		"--default-content", "file:../test-data/usr/share/dr-provision/default.yaml?codec=yaml",
	}

	cOpts := generateArgs(testArgs)
	go Server(cOpts)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	_, apierr := client.Get("https://127.0.0.1:10001/api/v3/subnets")
	count := 0
	for apierr != nil && count < 30 {
		t.Logf("Failed to get file: %v", apierr)
		time.Sleep(1 * time.Second)
		count++
		_, apierr = client.Get("https://127.0.0.1:10001/api/v3/subnets")
	}
	if count == 30 {
		t.Errorf("Server failed to start in time allowed")
	}

	// test presences of all the above
	if _, err := os.Stat(cOpts.TlsCertFile); os.IsNotExist(err) {
		t.Errorf("Failed to create cert file: %s", cOpts.TlsCertFile)
	} else {
		t.Logf("Cert file correctly created")
	}

	if _, err := os.Stat(cOpts.TlsKeyFile); os.IsNotExist(err) {
		t.Errorf("Failed to create cert file: %s", cOpts.TlsKeyFile)
	} else {
		t.Logf("Key file correctly created")
	}

	if _, err := os.Stat(cOpts.DataRoot); os.IsNotExist(err) {
		t.Errorf("Failed to create data dir: %s", cOpts.DataRoot)
	} else {
		t.Logf("DataRoot directory correctly created")
	}

	if _, err := os.Stat(cOpts.FileRoot); os.IsNotExist(err) {
		t.Errorf("Failed to create data dir: %s", cOpts.FileRoot)
	} else {
		t.Logf("FileRoot directory correctly created")
	}

	// Extract assets handle separately.

}

func TestMain(m *testing.M) {
	var err error
	tmpDir, err = ioutil.TempDir("", "server-")
	if err != nil {
		log.Printf("Creating temp dir for file root failed: %v", err)
		os.Exit(1)
	}

	ret := m.Run()

	err = os.RemoveAll(tmpDir)
	if err != nil {
		log.Printf("Creating temp dir for file root failed: %v", err)
		os.Exit(1)
	}

	os.Exit(ret)
}
