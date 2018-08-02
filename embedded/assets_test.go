package embedded

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestExtractAssets(t *testing.T) {
	tgt, err := ioutil.TempDir("", "assetTest")
	if err != nil {
		t.Errorf("Failed to make temporary directory for asset tests: %v", err)
		return
	}
	defer os.RemoveAll(tgt)
	if err := ExtractAssets("jj", tgt); err != nil {
		t.Errorf("Could not extract assets: %v", err)
		return
	}

	files := []string{
		"ALL-LICENSE",
		"explode_iso.sh",
		"files/jq",
		"files/drpcli.amd64.linux",
		"files/drpcli.amd64.windows",
		"bootia32.efi",
		"bootia64.efi",
		"esxi.0",
		"ipxe.efi",
		"ipxe.lkrn",
		"ipxe.pxe",
		"ldlinux.c32",
		"libutil.c32",
		"lpxelinux.0",
		"pxechn.c32",
		"libcom32.c32",
		"wimboot",
	}

	for _, f := range files {
		if _, err := os.Stat(path.Join(tgt, f)); os.IsNotExist(err) {
			t.Errorf("File %s does NOT exist, but should.", f)
		}
	}

	if err := ExtractAssets("extract_test", tgt); err != nil {
		t.Errorf("Could not extract assets: %v", err)
		return
	}

	for _, f := range files {
		if _, err := os.Stat(path.Join(tgt, f)); os.IsNotExist(err) {
			t.Errorf("File %s does NOT exist, but should.", f)
		}
	}

	buf1, _ := ioutil.ReadFile(path.Join(tgt, "explode_iso.sh"))
	buf2, _ := ioutil.ReadFile(path.Join(tgt, "files", "jq"))
	if string(buf1) != "Test2\n" {
		t.Error("Expected explode_iso.sh to be replaced")
	}
	if string(buf2) != "Test1\n" {
		t.Error("Expected files/jq to be replaced")
	}
}
