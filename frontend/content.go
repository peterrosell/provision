package frontend

import (
	"fmt"
	"net/http"
	"os"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"github.com/gin-gonic/gin"
)

// ContentsResponse returned on a successful GET of a contents
// swagger:response
type ContentResponse struct {
	// in: body
	Body *models.Content
}

// ContentSummaryResponse returned on a successful Post of a content
// swagger:response
type ContentSummaryResponse struct {
	// in: body
	Body *models.ContentSummary
}

// ContentsResponse returned on a successful GET of all contents
// swagger:response
type ContentsResponse struct {
	// in: body
	Body []*models.ContentSummary
}

// swagger:parameters uploadContent createContent
type ContentBodyParameter struct {
	// in: body
	Body *models.Content
}

// swagger:parameters getContent deleteContent uploadContent
type ContentParameter struct {
	// in: path
	Name string `json:"name"`
}

func (f *Frontend) buildNewStore(content *models.Content) (newStore store.Store, err error) {
	filename := fmt.Sprintf("/%s/%s-%s.yaml", f.SaasDir, content.Meta.Name, content.Meta.Version)
	count := 1
	for true {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			break
		}
		filename = fmt.Sprintf("/%s/%s-%s-%d.yaml", f.SaasDir, content.Meta.Name, content.Meta.Version, count)
		count += 1
	}

	filenameUrl := fmt.Sprintf("file://%s?codec=yaml", filename)
	newStore, err = store.Open(filenameUrl)
	if err != nil {
		return
	}

	content.Meta.Type = "dynamic"
	err = content.ToStore(newStore)
	return
}

func buildSummary(st store.Store) *models.ContentSummary {
	cs := &models.ContentSummary{}
	cs.FromStore(st)
	return cs
}

func (f *Frontend) buildContent(rt *backend.RequestTracker, st store.Store) (*models.Content, *models.Error) {
	content := &models.Content{}
	err := content.FromStore(st)
	if err != nil {
		return nil, models.NewError("ServerError", http.StatusInternalServerError, err.Error())
	}
	for section := range content.Sections {
		if len(content.Sections[section]) == 0 {
			continue
		}
		for key := range content.Sections[section] {
			obj, ok := content.Sections[section][key].(models.Paramer)
			if !ok {
				continue
			}
			params := rt.GetParams(obj, false, true)
			obj.SetParams(params)
			content.Sections[section][key] = obj
		}
	}
	return content, nil
}

func (f *Frontend) findContent(name string) (cst store.Store) {
	for _, st := range f.dt.Backend.Layers() {
		mst, ok := st.(store.MetaSaver)
		if !ok {
			continue
		}
		metaData := mst.MetaData()
		if metaData["Name"] == name {
			cst = st
			break
		}
	}
	return
}

func (f *Frontend) InitContentApi() {
	// swagger:route GET /contents Contents listContents
	//
	// Lists possible contents on the system to serve DHCP
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: ContentsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/contents",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "contents", "list", "") {
				return
			}

			contents := []*models.ContentSummary{}
			rt := f.rt(c)
			rt.AllLocked(func(d backend.Stores) {
				for _, st := range f.dt.Backend.Layers() {
					cs := buildSummary(st)
					if cs != nil {
						contents = append(contents, cs)
					}
				}
			})
			c.JSON(http.StatusOK, contents)
		})

	// swagger:route GET /contents/{name} Contents getContent
	//
	// Get a specific content with {name}
	//
	// Get a specific content specified by {name}.
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: ContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/contents/:name",
		func(c *gin.Context) {
			name := c.Param(`name`)
			if !f.assureSimpleAuth(c, "contents", "get", name) {
				return
			}
			rt := f.rt(c)
			rt.AllLocked(func(d backend.Stores) {
				if cst := f.findContent(name); cst == nil {
					res := &models.Error{
						Model: "contents",
						Key:   name,
						Type:  c.Request.Method,
						Code:  http.StatusNotFound,
					}
					res.Errorf("No such content store")
					c.JSON(http.StatusNotFound, res)
				} else {
					content, err := f.buildContent(rt, cst)
					if err != nil {
						c.JSON(err.Code, err)
					} else {
						c.JSON(http.StatusOK, content)
					}
				}
			})
		})

	// swagger:route POST /contents Contents createContent
	//
	// Create content into Digital Rebar Provision
	//
	//     Responses:
	//       201: ContentSummaryResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       403: ErrorResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       422: ErrorResponse
	//       500: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/contents",
		func(c *gin.Context) {
			content := &models.Content{}
			if !assureDecode(c, content) {
				return
			}
			if !f.assureSimpleAuth(c, "contents", "create", content.AuthKey()) {
				return
			}
			name := content.Meta.Name
			rt := f.rt(c)
			res := &models.Error{
				Model: "contents",
				Key:   name,
				Type:  c.Request.Method,
				Code:  http.StatusInternalServerError,
			}
			var cs *models.ContentSummary
			rt.AllLocked(func(d backend.Stores) {
				if cst := f.findContent(name); cst != nil {
					res.Code = http.StatusConflict
					res.Errorf("Content %s already exists", name)
					return
				}
				newStore, err := f.buildNewStore(content)
				if err != nil {
					res.AddError(err)
					return
				}
				cs = buildSummary(newStore)
				ds := f.dt.Backend
				nbs, hard, soft := ds.AddReplaceSAAS(name, newStore, f.dt.Secrets, f.Logger, nil)
				if hard != nil {
					backend.CleanUpStore(newStore)
					res = hard.(*models.Error)
					return
				}
				if soft != nil {
					if berr, ok := soft.(*models.Error); ok {
						cs.Warnings = berr.Messages
					}
				}
				f.dt.ReplaceBackend(rt, nbs)
				rt.Publish("contents", "create", name, cs)
			})
			if res.ContainsError() {
				c.JSON(res.Code, res)
			} else {
				c.JSON(http.StatusCreated, cs)
			}
		})

	// swagger:route PUT /contents/{name} Contents uploadContent
	//
	// Replace content in Digital Rebar Provision
	//
	//     Responses:
	//       200: ContentSummaryResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       403: ErrorResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       422: ErrorResponse
	//       500: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.PUT("/contents/:name",
		func(c *gin.Context) {
			content := &models.Content{}
			if !assureDecode(c, content) {
				return
			}
			if !f.assureSimpleAuth(c, "contents", "update", content.AuthKey()) {
				return
			}
			name := c.Param(`name`)
			res := &models.Error{
				Model: "contents",
				Key:   name,
				Type:  c.Request.Method,
				Code:  http.StatusBadRequest,
			}
			var cs *models.ContentSummary
			if name != content.Meta.Name {
				res.Errorf("Cannot change name from %s to %s", name, content.Meta.Name)
				c.JSON(http.StatusBadRequest, res)
				return
			}
			rt := f.rt(c)
			rt.AllLocked(func(d backend.Stores) {
				if cst := f.findContent(name); cst == nil {
					res.Code = http.StatusNotFound
					res.Errorf("Cannot find %s", name)
					return
				}

				newStore, err := f.buildNewStore(content)
				if err != nil {
					res.Code = http.StatusInternalServerError
					res.Errorf("Failed to build content")
					res.AddError(err)
					return
				}
				cs = buildSummary(newStore)
				ds := f.dt.Backend
				nbs, hard, soft := ds.AddReplaceSAAS(name, newStore, f.dt.Secrets, f.Logger, nil)
				if hard != nil {
					backend.CleanUpStore(newStore)
					res.Code = http.StatusInternalServerError
					res.AddError(hard)
					res.AddError(soft)
					return
				}
				if soft != nil {
					if berr, ok := soft.(*models.Error); ok {
						cs.Warnings = berr.Messages
					}
				}
				f.dt.ReplaceBackend(rt, nbs)
				rt.Publish("contents", "update", name, cs)
			})
			if res.ContainsError() {
				c.JSON(res.Code, res)
			} else {
				c.JSON(http.StatusOK, cs)
			}
		})

	// swagger:route DELETE /contents/{name} Contents deleteContent
	//
	// Delete a content set.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/contents/:name",
		func(c *gin.Context) {
			name := c.Param(`name`)
			if !f.assureSimpleAuth(c, "contents", "delete", name) {
				return
			}
			res := &models.Error{
				Model: "contents",
				Key:   name,
				Type:  c.Request.Method,
				Code:  http.StatusNotFound,
			}

			rt := f.rt(c)
			rt.AllLocked(func(d backend.Stores) {
				cst := f.findContent(name)
				if cst == nil {
					res.Code = http.StatusNotFound
					res.Errorf("No such content store")
					return
				}
				cs := buildSummary(cst)
				ds := f.dt.Backend
				nbs, hard, _ := ds.RemoveSAAS(name, f.Logger, f.dt.Secrets)
				if hard != nil {
					res.AddError(hard)
					return
				}
				rt.Publish("contents", "delete", name, cs)
				f.dt.ReplaceBackend(rt, nbs)
			})
			if res.ContainsError() {
				c.JSON(res.Code, res)
			} else {
				c.Data(http.StatusNoContent, gin.MIMEJSON, nil)
			}
		})
}
