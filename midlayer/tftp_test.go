// +build !race
//
// The TFTP server has a potential race between starting and shutting down.  This will never get hit in our
// code, it is possible.
//

package midlayer

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/tftp"
)

func TestTftpFiles(t *testing.T) {
	locallogger := log.New(os.Stderr, "", log.LstdFlags)
	l := logger.New(locallogger).Log("static")
	fs := backend.NewFS(".", l)
	_, hh := ServeTftp(":3235235", fs.TftpResponder(), l, backend.NewPublishers(locallogger))
	if hh != nil {
		if hh.Error() != "address 3235235: invalid port" {
			t.Errorf("Expected a different error: %v", hh.Error())
		}
	} else {
		t.Errorf("Should have returned an error")
	}

	_, hh = ServeTftp("1.1.1.1:11112", fs.TftpResponder(), l, backend.NewPublishers(locallogger))
	if hh != nil {
		if !strings.Contains(hh.Error(), "1.1.1.1:11112: bind: ") {
			t.Errorf("Expected a different error: %v", hh.Error())
		}
	} else {
		t.Errorf("Should have returned an error")
	}

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fs = backend.NewFS(dir, l)
	srv, hh := ServeTftp("127.0.0.1:11112", fs.TftpResponder(), l, backend.NewPublishers(locallogger))
	if hh != nil {
		t.Errorf("Should not return an error: %v", hh)
	} else {
		c, err := tftp.NewClient("127.0.0.1:11112")
		if err != nil {
			t.Errorf("tftpClient create: Should not return an error: %v", err)
		}
		wt, err := c.Receive("dhcp.go", "octet")
		if err != nil {
			t.Errorf("tftpClient receive: Should not return an error: %v", err)
		}
		buf := new(bytes.Buffer)
		_, err = wt.WriteTo(buf)
		if err != nil {
			t.Errorf("tftpClient write: Should not return an error: %v", err)
		}
		if !strings.HasPrefix(buf.String(), "package midlayer") {
			t.Errorf("Should have served the file: missing content")
		}

		wt, err = c.Receive("missing_file.go", "octet")
		if err != nil {
			s := fmt.Sprintf("code: 1, message: open %s/missing_file.go: no such file or directory", dir)
			s1 := err.Error()
			if !strings.Contains(s1, s) {
				t.Errorf("tftpClient receive: Should have returned the error: \n%s\n%s\n", s, s1)
			}
		} else {
			t.Errorf("tftpClient receive: Should return an error: %v", err)
		}

		wt, err = c.Receive("../bootenv.go", "octet")
		if err != nil {
			s := fmt.Sprintf("code: 1, message: open %s/bootenv.go: no such file or directory", dir)
			s1 := err.Error()
			if !strings.Contains(s1, s) {
				t.Errorf("tftpClient receive: Should have returned the error: \n%s\n%s\n", s, s1)
			}
		} else {
			t.Errorf("tftpClient receive: Should return an error: %v", err)
		}

		os.MkdirAll("test-data", 0700)

		f, err := os.Create("test-data/write-only.txt")
		if err != nil {
			t.Errorf("tftpClient create write-only file: Should not return an error: %v", err)
		}
		defer f.Close()

		f.WriteString("Test data")
		f.Sync()
		err = os.Chmod("test-data/write-only.txt", 0200)
		if err != nil {
			t.Errorf("tftpClient chmod write-only file: Should not return an error: %v", err)
		}

		wt, err = c.Receive("test-data/write-only.txt", "octet")
		if err != nil {
			s := fmt.Sprintf("code: 1, message: open %s/test-data/write-only.txt: permission denied", dir)
			s1 := err.Error()
			if !strings.Contains(s1, s) {
				t.Errorf("tftpClient receive: Should have returned the error: \n%s\n%s\n", s, s1)
			}
		} else {
			t.Errorf("tftpClient receive: Should return an error: %v", err)
		}

		err = os.Remove("test-data/write-only.txt")
		if err != nil {
			t.Errorf("tftpClient remove write-only file: Should not return an error: %v", err)
		}

		srv.Shutdown(context.Background())
	}

}
