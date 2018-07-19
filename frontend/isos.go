package frontend

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

type IsoPaths []string

// IsosResponse returned on a successful GET of isos
// swagger:response
type IsosResponse struct {
	// in: body
	Body IsoPaths
}

// XXX: One day resolve the binary blob appropriately:
// {
//   "name": "BinaryData",
//   "in": "body",
//   "required": true,
//   "schema": {
//     "type": "string",
//     "format": "byte"
//   }
// }
//

// IsoResponse returned on a successful GET of an iso
// swagger:response
type IsoResponse struct {
	// in: body
	Body interface{}
}

// IsoInfoResponse returned on a successful upload of an iso
// swagger:response
type IsoInfoResponse struct {
	// in: body
	Body *models.BlobInfo
}

// swagger:parameters uploadIso getIso deleteIso
type IsoPathPathParameter struct {
	// in: path
	Path string `json:"path"`
}

// IsoData body of the upload
// swagger:parameters uploadIso
type IsoData struct {
	// in: body
	Body interface{}
}

func (f *Frontend) InitIsoApi() {
	// swagger:route GET /isos Isos listIsos
	//
	// Lists isos in isos directory
	//
	// Lists the isos in a directory under /isos.
	//
	//     Responses:
	//       200: IsosResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/isos",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "isos", "list", "") {
				return
			}
			ents, err := ioutil.ReadDir(path.Join(f.FileRoot, "isos"))
			if err != nil {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Type:  c.Request.Method,
					Model: "isos",
				}
				res.Errorf("Could not list isos")
				res.AddError(err)
				c.JSON(res.Code, res)
				return
			}
			res := []string{}
			for _, ent := range ents {
				if !ent.Mode().IsRegular() {
					continue
				}
				res = append(res, ent.Name())
			}
			c.JSON(http.StatusOK, res)
		})
	// swagger:route GET /isos/{path} Isos getIso
	//
	// Get a specific Iso with {path}
	//
	// Get a specific iso specified by {path} under isos.
	//
	//     Produces:
	//       application/octet-stream
	//       application/json
	//
	//     Responses:
	//       200: IsoResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/isos/:name",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "isos", "get", c.Param(`name`)) {
				return
			}
			fileName := path.Join(f.FileRoot, `isos`, path.Clean(c.Param(`name`)))
			if st, err := os.Stat(fileName); err != nil || !st.Mode().IsRegular() {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Key:   c.Param(`name`),
					Model: "isos",
					Type:  c.Request.Method,
				}
				res.Errorf("Not a regular file")
				c.JSON(res.Code, res)
				return
			}
			c.File(fileName)
		})
	// swagger:route POST /isos/{path} Isos uploadIso
	//
	// Upload an iso to a specific {path} in the tree under isos.
	//
	// The iso will be uploaded to the {path} in /isos.  The {path} will be created.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       201: IsoInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/isos/:name",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "isos", "post", c.Param(`name`)) {
				return
			}
			uploadIso(c, f.FileRoot, c.Param(`name`), f.dt)
		})
	// swagger:route DELETE /isos/{path} Isos deleteIso
	//
	// Delete an iso to a specific {path} in the tree under isos.
	//
	// The iso will be removed from the {path} in /isos.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/isos/:name",
		func(c *gin.Context) {
			name := c.Param(`name`)
			if !f.assureSimpleAuth(c, "isos", "delete", name) {
				return
			}
			isoName := path.Join(f.FileRoot, `isos`, path.Base(name))
			if err := os.Remove(isoName); err != nil {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Type:  c.Request.Method,
					Model: "isos",
					Key:   name,
				}
				res.Errorf("no such iso")
				c.JSON(res.Code, res)
				return
			}
			c.Data(http.StatusNoContent, gin.MIMEJSON, nil)
		})
}

func reloadBootenvsForIso(rt *backend.RequestTracker, name string) {
	rt.Do(func(d backend.Stores) {
		for _, blob := range d("bootenvs").Items() {
			env := backend.AsBootEnv(blob)
			if env.OS.IsoFile != name {
				continue
			}
			rt.Save(env)
		}
	})
}

func uploadIso(c *gin.Context, fileRoot, name string, dt *backend.DataTracker) {
	res := &models.Error{
		Type:  c.Request.Method,
		Model: "isos",
		Key:   name,
	}
	if err := os.MkdirAll(path.Join(fileRoot, `isos`), 0755); err != nil {
		res.Code = http.StatusConflict
		res.Errorf("Failed to create ISO directory")
		c.JSON(res.Code, res)
		return
	}
	var copied int64

	ctype := c.Request.Header.Get(`Content-Type`)
	switch strings.Split(ctype, "; ")[0] {
	case `application/octet-stream`:
		if c.Request.Body == nil {
			res.Code = http.StatusBadRequest
			res.Errorf("Missing request body")
			c.JSON(res.Code, res)
			return
		}
	case `multipart/form-data`:
		_, err := c.FormFile("file")
		if err != nil {
			res.Code = http.StatusBadRequest
			res.Errorf("Missing multipart file")
			res.AddError(err)
			c.JSON(res.Code, res)
			return
		}
	default:
		res.Code = http.StatusUnsupportedMediaType
		res.Errorf("Invalid content type %s,", ctype)
		res.Errorf("Want application/octet-stream or multipart/form-data")
		c.JSON(res.Code, res)
		return
	}

	isoTmpName := path.Join(fileRoot, `isos`, fmt.Sprintf(`.%s.part`, path.Base(name)))
	isoName := path.Join(fileRoot, `isos`, path.Base(name))

	out, err := os.Create(isoTmpName)
	if err != nil {
		res.Code = http.StatusConflict
		res.Errorf("Already uploading")
		c.JSON(res.Code, res)
		return
	}
	defer out.Close()

	if err != nil {
		res.Code = http.StatusConflict
		res.Errorf("Unable to upload")
		res.AddError(err)
		c.JSON(res.Code, res)
		return
	}

	switch strings.Split(ctype, "; ")[0] {
	case `application/octet-stream`:
		copied, err = io.Copy(out, c.Request.Body)
		if c.Request.ContentLength > 0 && copied != c.Request.ContentLength {
			os.Remove(isoTmpName)
			res.Code = http.StatusBadRequest
			res.Errorf("%d bytes expected, %d bytes received", c.Request.ContentLength, copied)
			c.JSON(res.Code, res)
			return
		}
		if err != nil {
			os.Remove(isoTmpName)
			res.Code = http.StatusInsufficientStorage
			res.Errorf("Upload failed")
			res.AddError(err)
			c.JSON(res.Code, res)
			return
		}
	case `multipart/form-data`:
		header, _ := c.FormFile("file")
		file, _ := header.Open()
		defer file.Close()
		copied, err = io.Copy(out, file)
		if err != nil {
			res.Code = http.StatusConflict
			res.Errorf("Upload failed")
			res.AddError(err)
			c.JSON(res.Code, res)
			return
		}
		file.Close()
	}

	os.Remove(isoName)
	os.Rename(isoTmpName, isoName)
	ref := &backend.BootEnv{}
	rt := dt.Request(dt.Logger.Fork().Switch("bootenv"), ref.Locks("update")...)
	go reloadBootenvsForIso(rt, name)
	c.JSON(http.StatusCreated, &models.BlobInfo{Path: name, Size: copied})
}
