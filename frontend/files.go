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

	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

type FilePaths []string

// FilesResponse returned on a successful GET of files
// swagger:response
type FilesResponse struct {
	// in: body
	Body FilePaths
}

// This is a HACK - I can't figure out how to get
// swagger to render this a binary.  So we lie.
// We also override this object from the server
// directory to have a binary format which
// turns it into a stream.
//
// FileResponse returned on a successful GET of a file
// swagger:response
type FileResponse struct {
	// in: body
	Body string
}

// FileInfoResponse returned on a successful upload of a file
// swagger:response
type FileInfoResponse struct {
	// in: body
	Body *models.BlobInfo
}

// swagger:parameters listFiles
type FilesPathQueryParameter struct {
	// in: query
	Path string `json:"path"`
}

// swagger:parameters uploadFile getFile deleteFile headFile
type FilePathPathParameter struct {
	// in: path
	Path string `json:"path"`
	// in: explode
	Explode string `json:"explode"`
}

// FileData body of the upload
// swagger:parameters uploadFile
type FileData struct {
	// in: body
	Body interface{}
}

func (f *Frontend) InitFileApi() {
	// swagger:route GET /files Files listFiles
	//
	// Lists files in files directory or subdirectory per query parameter
	//
	// Lists the files in a directory under /files.  path=<path to return>
	// Path defaults to /
	//
	//     Responses:
	//       200: FilesResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/files",
		func(c *gin.Context) {
			pathPart, _ := c.GetQuery("path")
			if pathPart == "" {
				pathPart = "/"
			}
			if !f.assureSimpleAuth(c, f.rt(c), "files", "list", pathPart) {
				return
			}
			ents, err := ioutil.ReadDir(path.Join(f.FileRoot, "files", path.Clean(pathPart)))
			if err != nil {
				c.JSON(http.StatusNotFound,
					models.NewError("API ERROR", http.StatusNotFound,
						fmt.Sprintf("list: error listing files: %v", err)))
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
		})

	// swagger:route GET /files/{path} Files getFile
	//
	// Get a specific File with {path}
	//
	// Get a specific file specified by {path} under files.
	//
	//     Produces:
	//       application/octet-stream
	//       application/json
	//
	//     Responses:
	//       200: FileResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/files/*path",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, f.rt(c), "files", "get", c.Param(`path`)) {
				return
			}
			fileName := path.Join(f.FileRoot, `files`, path.Clean(c.Param(`path`)))
			if st, err := os.Stat(fileName); err != nil || !st.Mode().IsRegular() {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Key:   c.Param(`path`),
					Model: "files",
					Type:  c.Request.Method,
				}
				res.Errorf("Not a regular file")
				c.JSON(res.Code, res)
				return
			}
			c.Writer.Header().Set("Content-Type", "application/octet-stream")
			c.File(fileName)
		})

	// swagger:route HEAD /files/{path} Files headFile
	//
	// See if a file exists and return a checksum in the header
	//
	// Return 200 if the file specified by {path} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/files/*path",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, f.rt(c), "files", "get", c.Param(`path`)) {
				return
			}
			fileName := path.Join(f.FileRoot, `files`, path.Clean(c.Param(`path`)))
			if st, err := os.Stat(fileName); err != nil || !st.Mode().IsRegular() {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Key:   c.Param(`path`),
					Model: "files",
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
					Model: "files",
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
					Model: "files",
					Type:  c.Request.Method,
				}
				res.Errorf("Failed to sum file: %s", err)
				c.JSON(res.Code, res)
				return
			}

			c.Header("X-DRP-SHA256SUM", hex.EncodeToString(hasher.Sum(nil)))
			c.Status(http.StatusOK)
		})

	// swagger:route POST /files/{path} Files uploadFile
	//
	// Upload a file to a specific {path} in the tree under files.
	//
	// The file will be uploaded to the {path} in /files.  The {path} will be created.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       201: FileInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       403: ErrorResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/files/*path",
		func(c *gin.Context) {
			err := &models.Error{
				Model: "files",
				Key:   c.Param(`path`),
				Type:  c.Request.Method,
			}
			name := c.Param(`path`)
			if !f.assureSimpleAuth(c, f.rt(c), "files", "post", name) {
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
				name = path.Base(header.Filename)
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

			fileTmpName := path.Join(f.FileRoot, `files`, fmt.Sprintf(`.%s.part`, path.Clean(name)))
			fileName := path.Join(f.FileRoot, `files`, path.Clean(name))

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

			if c.Query("explode") == "true" {
				cmd := exec.Command("bsdtar", "-zxvf", fileName)
				cmd.Dir = path.Dir(fileName)
				if _, zerr := cmd.CombinedOutput(); zerr != nil {
					err.Code = http.StatusBadRequest
					err.AddError(zerr)
					c.JSON(err.Code, err)
					return
				}
			}

			c.JSON(http.StatusCreated, &models.BlobInfo{Path: name, Size: copied})
		})

	// swagger:route DELETE /files/{path} Files deleteFile
	//
	// Delete a file to a specific {path} in the tree under files.
	//
	// The file will be removed from the {path} in /files.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/files/*path",
		func(c *gin.Context) {
			name := c.Param(`path`)
			err := &models.Error{
				Model: "files",
				Key:   name,
				Type:  c.Request.Method,
			}
			if !f.assureSimpleAuth(c, f.rt(c), "files", "delete", name) {
				return
			}
			fileName := path.Join(f.FileRoot, `files`, name)
			if !strings.HasPrefix(fileName, path.Join(f.FileRoot, `files`)) {
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
		})

}
