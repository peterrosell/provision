package frontend

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// MetaResponse is returned on a successful GET of metadata.
// swagger:response getMeta patchMeta
type MetaResponse struct {
	// in:body
	Body models.Meta
}

// MetaParameter is used to get or patch metadata on a thing.
// swagger:parameters getMeta patchMeta
type MetaParameter struct {
	// in:path
	// required: true
	Type string `json:"type"`
	// in:path
	// required: true
	ID string `json:"id"`
}

func getMetaFor(c *gin.Context, objType string) models.MetaHaver {
	obj, err := models.New(objType)
	if err != nil {
		retErr := &models.Error{
			Code:  http.StatusBadRequest,
			Model: objType,
		}
		retErr.AddError(err)
		c.AbortWithStatusJSON(retErr.Code, retErr)
		return nil
	}
	ret, ok := obj.(models.MetaHaver)
	if !ok {
		retErr := &models.Error{
			Code: http.StatusBadRequest,
			Type: obj.Prefix(),
			Key:  obj.Key(),
		}
		retErr.Errorf("Object type does not have metadata")
		c.AbortWithStatusJSON(retErr.Code, retErr)
		return nil
	}
	return backend.ModelToBackend(ret).(models.MetaHaver)
}

func (f *Frontend) InitMetaApi() {
	// swagger:route GET /meta/{type}/{id} Meta getMeta
	//
	// Get Metadata for an Object of {type} idendified by {id}
	//
	// Get the appropriate Metadata or return NotFound.
	//
	//     Responses:
	//       200: MetaResponse
	//       401: NoContentResponse
	//       403: NoContentRespons
	f.ApiGroup.GET("/meta/:type/*id",
		func(c *gin.Context) {
			prefix, id := c.Param(`type`), strings.TrimPrefix(c.Param(`id`), "/")
			ref := getMetaFor(c, prefix)
			if ref == nil {
				return
			}
			rt := f.rt(c, ref.(Lockable).Locks("get")...)
			if !f.assureSimpleAuth(c, rt, prefix, "get", id) {
				return
			}
			res := f.Find(c, rt, prefix, id)
			if res == nil {
				return
			}
			meta := res.(models.MetaHaver).GetMeta()
			c.JSON(http.StatusOK, meta)
		})

	// swagger:route PATCH /meta/{type}/{id} Meta patchMeta
	//
	// Patch metadata on an Object of {type} with an ID of {id}
	//
	// Update metadata on a specific Object using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: MetasResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/meta/:type/:id",
		func(c *gin.Context) {
			prefix, id := c.Param(`type`), strings.TrimPrefix(c.Param(`id`), "/")
			ref := getMetaFor(c, prefix)
			if ref == nil {
				return
			}
			rt := f.rt(c, ref.(Lockable).Locks("update")...)
			res := f.Find(c, rt, prefix, id)
			if res == nil {
				return
			}
			mh := res.(models.MetaHaver)
			if mh == nil {
				return
			}
			changed := models.Clone(mh).(models.MetaHaver)
			// resolve the patch against the metadata
			var metaPatch jsonpatch2.Patch
			if !assureDecode(c, &metaPatch) {
				return
			}
			meta := changed.GetMeta()
			patchErr := &models.Error{
				Code:  http.StatusConflict,
				Type:  c.Request.Method,
				Model: prefix,
				Key:   id,
			}
			buf, err := json.Marshal(meta)
			if err != nil {
				patchErr.AddError(err)
				c.AbortWithStatusJSON(patchErr.Code, patchErr)
				return
			}
			patched, err, loc := metaPatch.Apply(buf)
			if err != nil {
				patchErr.Errorf("Patch failed to apply at line %d", loc)
				patchErr.AddError(err)
				c.AbortWithStatusJSON(patchErr.Code, patchErr)
				return
			}
			var newMeta models.Meta
			if err := json.Unmarshal(patched, &newMeta); err != nil {
				patchErr.AddError(err)
				c.AbortWithStatusJSON(patchErr.Code, patchErr)
				return
			}
			// Metadata patched.  Resolve the patch against the metadata holders.
			changed.SetMeta(newMeta)
			patch, err := models.GenPatch(mh, changed, false)
			if err != nil {
				patchErr.AddError(err)
			} else if !f.assureAuthUpdate(c, rt, prefix, "update", id, patch) {
				return
			} else {
				rt.Do(func(_ backend.Stores) {
					_, err := rt.Patch(changed, changed.Key(), patch)
					patchErr.AddError(err)
				})
			}
			if patchErr.ContainsError() {
				c.AbortWithStatusJSON(patchErr.Code, patchErr)
				return
			}
			c.JSON(http.StatusOK, newMeta)
		})
}
