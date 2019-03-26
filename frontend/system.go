package frontend

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
	"github.com/kardianos/osext"
)

// SystemActionsPathParameter used to find a System / Actions in the path
// swagger:parameters getSystemActions
type SystemActionsPathParameter struct {
	// in: query
	Plugin string `json:"plugin"`
}

// SystemActionPathParameter used to find a System / Action in the path
// swagger:parameters getSystemAction
type SystemActionPathParameter struct {
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
}

// SystemActionBodyParameter used to post a System / Action in the path
// swagger:parameters postSystemAction
type SystemActionBodyParameter struct {
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
	// in: body
	// required: true
	Body map[string]interface{}
}

func (f *Frontend) InitSystemApi() {
	profile := &backend.Profile{}
	pActions, pAction, pRun := f.makeActionEndpoints("system", profile, "name")

	// swagger:route GET /system/actions System getSystemActions
	//
	// List system actions System
	//
	// List System actions
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionsResponse
	//       401: NoSystemResponse
	//       403: NoSystemResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/system/actions", pActions)

	// swagger:route GET /system/actions/{cmd} System getSystemAction
	//
	// List specific action for System
	//
	// List specific {cmd} action for System
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionResponse
	//       400: ErrorResponse
	//       401: NoSystemResponse
	//       403: NoSystemResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/system/actions/:cmd", pAction)

	// swagger:route POST /system/actions/{cmd} System postSystemAction
	//
	// Call an action on the system.
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//
	//     Responses:
	//       400: ErrorResponse
	//       200: ActionPostResponse
	//       401: NoSystemResponse
	//       403: NoSystemResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/system/actions/:cmd", pRun)

	// swagger:route POST /system/upgrade System systemUpdate
	//
	// Upload a file to upgrade the DRP system
	//
	// The file will be uploaded and used to replace the running DRP instance.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       202: FileInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       403: ErrorResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/system/upgrade",
		func(c *gin.Context) {
			err := &models.Error{
				Model: "system",
				Key:   "upgrade",
				Type:  c.Request.Method,
			}
			if !f.assureSimpleAuth(c, f.rt(c), "system", "upgrade", "*") {
				return
			}
			var copied int64
			ctype := c.Request.Header.Get(`Content-Type`)
			switch strings.Split(ctype, "; ")[0] {
			case `application/octet-stream`:
				if c.Request.Body == nil {
					err.Code = http.StatusBadRequest
					err.Errorf("Missing upload body")
					c.JSON(err.Code, err)
					return
				}
			case `multipart/form-data`:
				_, headErr := c.FormFile("file")
				if headErr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(headErr)
					err.Errorf("Cannot find multipart file")
					c.JSON(err.Code, err)
					return
				}
			default:
				err.Code = http.StatusBadRequest
				err.Errorf("Want content-type application/octet-stream, not %s", ctype)
				c.JSON(err.Code, err)
				return
			}

			name := "drpupgrade.zip"

			dir, derr := ioutil.TempDir("", "drp-upgrade")
			if derr != nil {
				err.Code = http.StatusInternalServerError
				err.Errorf("Failed to create temp directory: %v", derr)
				c.JSON(err.Code, err)
				return
			}
			defer os.RemoveAll(dir) // clean up

			fileTmpName := path.Join(dir, name)

			if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil {
				err.Code = http.StatusConflict
				err.Errorf("Cannot create directory %s", path.Dir(name))
				c.JSON(err.Code, err)
				return
			}
			tgt, openErr := os.Create(fileTmpName)
			defer tgt.Close()
			if openErr != nil {
				err.Code = http.StatusConflict
				err.Errorf("Unable to upload")
				err.AddError(openErr)
				c.JSON(err.Code, err)
				return
			}
			var copyErr error
			switch strings.Split(ctype, "; ")[0] {
			case `application/octet-stream`:
				copied, copyErr = io.Copy(tgt, c.Request.Body)
				if copyErr != nil {
					os.Remove(fileTmpName)
					err.Code = http.StatusInsufficientStorage
					err.AddError(copyErr)
					c.JSON(err.Code, err)
					return
				}

				if c.Request.ContentLength > 0 && copied != c.Request.ContentLength {
					os.Remove(fileTmpName)
					err.Code = http.StatusBadRequest
					err.Errorf("%d bytes expected, but only %d bytes received",
						c.Request.ContentLength,
						copied)
					c.JSON(err.Code, err)
					return
				}
			case `multipart/form-data`:
				header, _ := c.FormFile("file")
				file, headerErr := header.Open()
				if headerErr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(headerErr)
					c.JSON(err.Code, err)
					return
				}
				defer file.Close()
				copied, copyErr = io.Copy(tgt, file)
				if copyErr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(copyErr)
					c.JSON(err.Code, err)
					return
				}
				file.Close()
			}
			tgt.Close()

			cmd := exec.Command("unzip", fileTmpName)
			cmd.Dir = dir
			if _, zerr := cmd.CombinedOutput(); zerr != nil {
				err.Code = http.StatusBadRequest
				err.AddError(zerr)
				c.JSON(err.Code, err)
				return
			}

			arch := runtime.GOARCH
			osLocal := runtime.GOOS
			currentDrp, oserr := osext.Executable()
			if oserr != nil {
				err.Code = http.StatusBadRequest
				err.AddError(oserr)
				c.JSON(err.Code, err)
				return
			}
			tmpcurrentDrp := currentDrp + ".next"

			for _, fname := range []string{"drpcli", "drbundler"} {
				newfname := path.Join(dir, "bin", osLocal, arch, fname)
				var oldFname string

				for _, dname := range []string{"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin"} {
					oldFname = path.Join(dname, fname)
					if _, serr := os.Stat(oldFname); serr == nil {
						break
					}
					oldFname = ""
				}
				if oldFname != "" {
					if terr := CopyFile(oldFname, oldFname+".bak"); terr != nil {
						err.Code = http.StatusBadRequest
						err.AddError(terr)
						c.JSON(err.Code, err)
						return
					}
					if terr := os.Rename(newfname, oldFname); terr != nil {
						err.Code = http.StatusBadRequest
						err.AddError(terr)
						c.JSON(err.Code, err)
						return
					}
				}
			}

			if terr := CopyFile(currentDrp, currentDrp+".bak"); terr != nil {
				err.Code = http.StatusBadRequest
				err.AddError(terr)
				c.JSON(err.Code, err)
				return
			}
			newfname := path.Join(dir, "bin", osLocal, arch, "dr-provision")
			if terr := os.Rename(newfname, tmpcurrentDrp); terr != nil {
				err.Code = http.StatusBadRequest
				err.AddError(terr)
				c.JSON(err.Code, err)
				return
			}

			os.RemoveAll(dir) // clean up
			c.JSON(http.StatusCreated, &models.BlobInfo{Path: "drpupgrade.zip", Size: copied})

			if terr := os.Rename(tmpcurrentDrp, currentDrp); terr != nil {
				f.Logger.Errorf("Failed to rename %s to %s: %v\n", tmpcurrentDrp, currentDrp, terr)
			}
		})
}

// CopyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Otherise, attempt to create a hard link
// between the two files. If that fail, copy the file contents from src to dst.
func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
