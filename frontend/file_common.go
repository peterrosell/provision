package frontend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

func (f *Frontend) FileCommonFuncs(base string) (func(*gin.Context), func(*gin.Context), func(*gin.Context), func(*gin.Context), func(*gin.Context)) {

	return func(c *gin.Context) { // List
			pathPart, _ := c.GetQuery("path")
			if pathPart == "" {
				pathPart = "/"
			}
			if !f.assureSimpleAuth(c, f.rt(c), base, "list", pathPart) {
				return
			}
			ents, err := ioutil.ReadDir(path.Join(f.FileRoot, base, path.Clean(pathPart)))
			if err != nil {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Type:  c.Request.Method,
					Model: base,
				}
				res.Errorf("list: error listing %s", base)
				res.AddError(err)
				c.JSON(res.Code, res)
				return
			}
			res := make(FilePaths, 0, 0)
			for _, ent := range ents {
				if ent.Mode().IsRegular() {
					res = append(res, ent.Name())
				} else if ent.Mode().IsDir() {
					res = append(res, ent.Name()+"/")
				}
			}
			c.JSON(http.StatusOK, res)
		},
		func(c *gin.Context) { // Get
			if !f.assureSimpleAuth(c, f.rt(c), base, "get", c.Param(`path`)) {
				return
			}
			fileName := path.Join(f.FileRoot, base, path.Clean(c.Param(`path`)))
			if st, err := os.Stat(fileName); err != nil || !st.Mode().IsRegular() {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Key:   c.Param(`path`),
					Model: base,
					Type:  c.Request.Method,
				}
				res.Errorf("Not a regular file")
				c.JSON(res.Code, res)
				return
			}
			c.Writer.Header().Set("Content-Type", "application/octet-stream")
			c.File(fileName)
		},
		func(c *gin.Context) { // Head
			if !f.assureSimpleAuth(c, f.rt(c), base, "get", c.Param(`path`)) {
				return
			}
			fileName := path.Join(f.FileRoot, base, path.Clean(c.Param(`path`)))
			if st, err := os.Stat(fileName); err != nil || !st.Mode().IsRegular() {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Key:   c.Param(`path`),
					Model: base,
					Type:  c.Request.Method,
				}
				res.Errorf("Not a regular file")
				c.JSON(res.Code, res)
				return
			}

			hasher := sha256.New()
			f, err := os.Open(fileName)
			if err != nil {
				res := &models.Error{
					Code:  http.StatusInternalServerError,
					Key:   c.Param(`path`),
					Model: base,
					Type:  c.Request.Method,
				}
				res.Errorf("Failed to open file: %s", err)
				c.JSON(res.Code, res)
				return
			}
			defer f.Close()
			if _, err := io.Copy(hasher, f); err != nil {
				res := &models.Error{
					Code:  http.StatusInternalServerError,
					Key:   c.Param(`path`),
					Model: base,
					Type:  c.Request.Method,
				}
				res.Errorf("Failed to sum file: %s", err)
				c.JSON(res.Code, res)
				return
			}

			c.Header("X-DRP-SHA256SUM", hex.EncodeToString(hasher.Sum(nil)))
			c.Status(http.StatusOK)
		},
		func(c *gin.Context) { // Post
			err := &models.Error{
				Model: base,
				Key:   c.Param(`path`),
				Type:  c.Request.Method,
			}
			name := c.Param(`path`)
			if !f.assureSimpleAuth(c, f.rt(c), base, "post", name) {
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
				header, headErr := c.FormFile("file")
				if headErr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(headErr)
					err.Errorf("Cannot find multipart file")
					c.JSON(err.Code, err)
					return
				}
				if name == "/" {
					name = path.Base(header.Filename)
				}
			default:
				err.Code = http.StatusBadRequest
				err.Errorf("Want content-type application/octet-stream, not %s", ctype)
				c.JSON(err.Code, err)
				return
			}
			if strings.HasSuffix(name, "/") {
				err.Code = http.StatusForbidden
				err.Errorf("Cannot upload a directory")
				c.JSON(err.Code, err)
				return
			}

			fileTmpName := path.Join(f.FileRoot, base, fmt.Sprintf(`.%s.part`, path.Clean(name)))
			fileName := path.Join(f.FileRoot, base, path.Clean(name))
			if mkdirErr := os.MkdirAll(path.Dir(fileName), 0755); mkdirErr != nil {
				err.Code = http.StatusConflict
				err.Errorf("Cannot create directory %s", path.Dir(name))
				c.JSON(err.Code, err)
				return
			}

			if _, openErr := os.Open(fileTmpName); openErr == nil {
				os.Remove(fileName)
				err.Code = http.StatusConflict
				err.Errorf("File already uploading")
				err.AddError(openErr)
				c.JSON(err.Code, err)
				return
			}

			tgt, openErr := os.Create(fileTmpName)
			defer tgt.Close()
			if openErr != nil {
				os.Remove(fileName)
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
					os.Remove(fileName)
					os.Remove(fileTmpName)
					err.Code = http.StatusInsufficientStorage
					err.AddError(copyErr)
					c.JSON(err.Code, err)
					return
				}

				if c.Request.ContentLength > 0 && copied != c.Request.ContentLength {
					os.Remove(fileName)
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

			os.Remove(fileName)
			os.Rename(fileTmpName, fileName)

			// Explode is only valid on files
			if base == "files" && c.Query("explode") == "true" {
				cmd := exec.Command("bsdtar", "-zxvf", fileName)
				cmd.Dir = path.Dir(fileName)
				if _, zerr := cmd.CombinedOutput(); zerr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(zerr)
					c.JSON(err.Code, err)
					return
				}
			}

			// If isos, we need to reload the bootenvs.
			if base == "isos" {
				name = strings.TrimPrefix(name, "/")
				ref := &backend.BootEnv{}
				rt := f.rt(c, ref.Locks("update")...)
				exploders := []func(*backend.RequestTracker){}
				rt.Do(func(d backend.Stores) {
					for _, blob := range d("bootenvs").Items() {
						env := backend.AsBootEnv(blob)
						if env.IsoFor(name) {
							exploders = append(exploders, env.IsoExploders(rt)...)
						}
					}
				})
				for i := range exploders {
					exploders[i](rt)
				}
			}

			c.JSON(http.StatusCreated, &models.BlobInfo{Path: name, Size: copied})
		},
		func(c *gin.Context) { // Delete
			name := c.Param(`path`)
			err := &models.Error{
				Model: base,
				Key:   name,
				Type:  c.Request.Method,
			}
			if !f.assureSimpleAuth(c, f.rt(c), base, "delete", name) {
				return
			}
			fileName := path.Join(f.FileRoot, base, name)
			if !strings.HasPrefix(fileName, path.Join(f.FileRoot, base)) {
				err.Code = http.StatusForbidden
				err.Errorf("Cannot delete")
				c.JSON(err.Code, err)
				return
			}
			if rmErr := os.Remove(fileName); rmErr != nil {
				err.Code = http.StatusNotFound
				err.Errorf("Unable to delete")
				c.JSON(err.Code, err)
				return
			}
			c.Data(http.StatusNoContent, gin.MIMEJSON, nil)
		}
}
