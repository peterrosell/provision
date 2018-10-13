package embedded

// Yes - Twice - once to get the basic pieces in place to let swagger run, then the final parts
//
//go:generate ../tools/download-assets.sh ../embedded
//go:generate go-bindata -prefix ../embedded/assets -pkg embedded -o ../embedded/embed.go ../embedded/assets/...
//go:generate swagger generate spec -i ../server/swagger.base.yml -o ../embedded/assets/swagger.json -b ../server
//go:generate ../tools/build-all-license.sh .. embedded/assets/ALL-LICENSE
//go:generate ../tools/build-all-license.sh .. ALL-LICENSE
//go:generate ../tools/build_cli.sh
//go:generate go-bindata -prefix ../embedded/assets -pkg embedded -o ../embedded/embed.go ../embedded/assets/...

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/frontend"
	"github.com/digitalrebar/provision/server"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gin-gonic/gin"
)

func init() {
	frontend.EmbeddedAssetsServerFunc = Easf
	server.EmbeddedAssetsExtractFunc = ExtractAssets
}

func Easf(mgmtApi *gin.Engine, logger logger.Logger) error {
	// Swagger.json serve
	buf, err := Asset("swagger.json")
	if err != nil {
		logger.Fatalf("Failed to load swagger.json asset")
	}
	var f interface{}
	json.Unmarshal(buf, &f)
	mgmtApi.GET("/swagger.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, f)
	})

	// Server Swagger UI.
	mgmtApi.StaticFS("/swagger-ui",
		&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: "swagger-ui"})

	return nil
}

func IncludeMeFunction() {}

func ExtractAssets(replaceRoot, fileRoot string) error {
	dirs := []string{"isos", "files", "machines", "pxelinux.cfg"}
	for _, dest := range dirs {
		destDir := path.Join(fileRoot, dest)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return err
		}
	}

	assets := map[string]string{
		// General LICENSE thing
		"ALL-LICENSE": "",

		// CLI things
		"drpcli.amd64.linux":   "files",
		"drpcli.arm64.linux":   "files",
		"drpcli.amd64.windows": "files",

		// General ISO things
		"explode_iso.sh": "",

		// Sledgehammer things
		"jq": "files",

		// General Boot things
		"bootia32.efi":   "",
		"bootia64.efi":   "",
		"bootx64.efi":    "",
		"chain.c32":      "",
		"esxi.0":         "",
		"ipxe.efi":       "",
		"ipxe.lkrn":      "",
		"ipxe-arm64.efi": "",
		"ipxe.pxe":       "",
		"ldlinux.c32":    "",
		"libutil.c32":    "",
		"lpxelinux.0":    "",
		"pxechn.c32":     "",
		"libcom32.c32":   "",
		"wimboot":        "",
		"grubarm64.efi":  "",
		"grubamd64.efi":  "",
	}

	for src, dest := range assets {
		buf, err := Asset(src)
		if err != nil {
			return fmt.Errorf("No such embedded asset %s: %v", src, err)
		}

		// If a file is present in replaceRoot,
		// use it instead of the embedded asset
		srcFile := path.Join(replaceRoot, dest, src)
		if s, err := os.Lstat(srcFile); err == nil && s.Mode().IsRegular() {
			sbuf, err := ioutil.ReadFile(srcFile)
			if err == nil {
				buf = sbuf
			}
		}

		info, err := AssetInfo(src)
		if err != nil {
			return fmt.Errorf("No mode info for embedded asset %s: %v", src, err)
		}

		destFile := path.Join(fileRoot, dest, src)
		destDir := path.Dir(destFile)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return err
		}

		if err := ioutil.WriteFile(destFile, buf, info.Mode()); err != nil {
			return err
		}
		if err := os.Chtimes(destFile, info.ModTime(), info.ModTime()); err != nil {
			return err
		}
	}

	return nil
}
