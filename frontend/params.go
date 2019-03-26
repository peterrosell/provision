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

func (f *Frontend) makeParamEndpoints(obj models.Paramer, idKey string) (
	getAll, getOne, patchThem, setThem, setOne, deleteOne, getPubKey func(c *gin.Context)) {
	trimmer := func(s string) string {
		return strings.TrimLeft(s, `/`)
	}
	aggregator := func(c *gin.Context) bool {
		return c.Query("aggregate") == "true"
	}
	idrtkey := func(c *gin.Context, op string) (string, *backend.RequestTracker, string) {
		id := c.Param(idKey)
		return id,
			f.rt(c, obj.(Lockable).Locks(op)...),
			trimmer(c.Param("key"))
	}
	viewAuth := func(c *gin.Context, rt *backend.RequestTracker, key string) bool {
		if !f.assureSimpleAuth(c, rt, obj.Prefix(), "get", key) {
			return false
		}
		if !f.wantDecodeSecure(c) {
			return true
		}
		return f.assureSimpleAuth(c, rt, obj.Prefix(), "getSecure", key)
	}
	mutator := func(c *gin.Context,
		rt *backend.RequestTracker,
		id string,
		mutfunc func(map[string]interface{}) (map[string]interface{}, *models.Error)) map[string]interface{} {
		ob := f.Find(c, rt, obj.Prefix(), id)
		if ob == nil {
			return nil
		}
		orig := models.Clone(ob).(models.Paramer)
		changed := models.Clone(ob).(models.Paramer)
		params := orig.GetParams()
		rt.Tracef("Object %s:%s exists, has params %#v", orig.Prefix(), id, params)
		if params == nil {
			params = map[string]interface{}{}
		}
		newParams, muterr := mutfunc(params)
		if muterr != nil {
			c.AbortWithStatusJSON(muterr.Code, muterr)
			return nil
		}
		changed.SetParams(newParams)
		patchErr := &models.Error{
			Code:  http.StatusConflict,
			Type:  c.Request.Method,
			Model: obj.Prefix(),
			Key:   id,
		}
		patch, err := models.GenPatch(orig, changed, false)
		if err != nil {
			patchErr.AddError(err)
		} else if !f.assureAuthUpdate(c, rt, obj.Prefix(), "update", id, patch) {
			return nil
		} else {
			rt.Do(func(_ backend.Stores) {
				_, err := rt.Patch(changed, changed.Key(), patch)
				patchErr.AddError(err)
			})
		}
		if patchErr.ContainsError() {
			c.AbortWithStatusJSON(patchErr.Code, patchErr)
			return nil
		}
		return newParams
	}
	return /* getAll */ func(c *gin.Context) {
			id, rt, _ := idrtkey(c, "get")
			if !viewAuth(c, rt, id) {
				return
			}
			var params map[string]interface{}
			ob := f.Find(c, rt, obj.Prefix(), id)
			if ob == nil {
				return
			}
			rt.Do(func(_ backend.Stores) {
				params = rt.GetParams(ob.(models.Paramer), aggregator(c), f.wantDecodeSecure(c))
			})
			c.JSON(http.StatusOK, params)
		},
		/* getOne */ func(c *gin.Context) {
			id, rt, key := idrtkey(c, "get")
			if !viewAuth(c, rt, id) {
				return
			}
			ob := f.Find(c, rt, obj.Prefix(), id)
			if ob == nil {
				return
			}
			var val interface{}
			rt.Do(func(d backend.Stores) {
				val, _ = rt.GetParam(ob.(models.Paramer), key, aggregator(c), f.wantDecodeSecure(c))
			})
			c.JSON(http.StatusOK, val)
		},
		/* patchThem */ func(c *gin.Context) {
			var patch jsonpatch2.Patch
			if !assureDecode(c, &patch) {
				return
			}
			id, rt, _ := idrtkey(c, "update")
			newParams := mutator(c, rt, id,
				func(params map[string]interface{}) (map[string]interface{}, *models.Error) {
					patchErr := &models.Error{
						Code:  http.StatusConflict,
						Type:  c.Request.Method,
						Model: obj.Prefix(),
						Key:   id,
					}
					buf, err := json.Marshal(params)
					if err != nil {
						patchErr.AddError(err)
						return nil, patchErr
					}
					patched, err, loc := patch.Apply(buf)
					if err != nil {
						patchErr.Errorf("Patch failed to apply at line %d", loc)
						patchErr.AddError(err)
						return nil, patchErr
					}
					var res map[string]interface{}
					if err := json.Unmarshal(patched, &res); err != nil {
						patchErr.AddError(err)
						return nil, patchErr
					}
					return res, nil
				})
			if newParams != nil {
				c.JSON(http.StatusOK, newParams)
			}
		},
		/* setThem */ func(c *gin.Context) {
			id, rt, _ := idrtkey(c, "update")
			var replacement map[string]interface{}
			if !assureDecode(c, &replacement) {
				return
			}
			newParams := mutator(c, rt, id,
				func(params map[string]interface{}) (map[string]interface{}, *models.Error) {
					return replacement, nil
				})
			if newParams != nil {
				c.JSON(http.StatusOK, newParams)
			}
		},
		/* setOne */ func(c *gin.Context) {
			id, rt, key := idrtkey(c, "update")
			var replacement interface{}
			if !assureDecode(c, &replacement) {
				return
			}
			newParams := mutator(c, rt, id,
				func(params map[string]interface{}) (map[string]interface{}, *models.Error) {
					params[key] = replacement
					return params, nil
				})
			if newParams != nil {
				c.JSON(http.StatusOK, replacement)
			}
		},
		/* deleteOne */ func(c *gin.Context) {
			id, rt, key := idrtkey(c, "update")
			var found bool
			var val interface{}
			if mutator(c, rt, id,
				func(params map[string]interface{}) (map[string]interface{}, *models.Error) {
					val, found = params[key]
					if !found {
						err := &models.Error{
							Code:  http.StatusNotFound,
							Type:  "DELETE",
							Model: "params",
							Key:   key,
						}
						err.Errorf("Not Found")
						return nil, err
					}
					delete(params, key)
					return params, nil
				}) != nil && found {
				c.JSON(http.StatusOK, val)
			}
		},
		/* getPubKey */ func(c *gin.Context) {
			id, rt, _ := idrtkey(c, "get")
			if !f.assureSimpleAuth(c, rt, obj.Prefix(), "updateSecure", id) {
				return
			}
			ob := f.Find(c, rt, obj.Prefix(), id)
			if ob == nil {
				return
			}
			pk, err := rt.PublicKeyFor(ob)
			if err != nil {
				ret := &models.Error{
					Code:  500,
					Model: ob.Prefix(),
					Key:   ob.Key(),
					Type:  "Bad Secret",
				}
				ret.AddError(err)
				c.JSON(ret.Code, ret)
			} else {
				c.JSON(http.StatusOK, pk)
			}
		}
}

// ParamResponse returned on a successful GET, PUT, PATCH, or POST of a single param
// swagger:response
type ParamResponse struct {
	// in: body
	Body *models.Param
}

// ParamsResponse returned on a successful GET of all the params
// swagger:response
type ParamsResponse struct {
	//in: body
	Body []*models.Param
}

// ParamParamsResponse return on a successful GET of all Param's Params
// swagger:response
type ParamParamsResponse struct {
	// in: body
	Body map[string]interface{}
}

// ParamBodyParameter used to inject a Param
// swagger:parameters createParam putParam
type ParamBodyParameter struct {
	// in: body
	// required: true
	Body *models.Param
}

// ParamPatchBodyParameter used to patch a Param
// swagger:parameters patchParam
type ParamPatchBodyParameter struct {
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

// ParamPathParameter used to name a Param in the path
// swagger:parameters putParams getParam putParam patchParam deleteParam getParamParams postParamParams headParam
type ParamPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
}

// ParamParamsBodyParameter used to set Param Params
// swagger:parameters postParamParams
type ParamParamsBodyParameter struct {
	// in: body
	// required: true
	Body map[string]interface{}
}

// ParamListPathParameter used to limit lists of Param by path options
// swagger:parameters listParams listStatsParams
type ParamListPathParameter struct {
	// in: query
	Offest int `json:"offset"`
	// in: query
	Limit int `json:"limit"`
	// in: query
	Available string
	// in: query
	Valid string
	// in: query
	ReadOnly string
	// in: query
	Name string
}

func (f *Frontend) InitParamApi() {
	// swagger:route GET /params Params listParams
	//
	// Lists Params filtered by some parameters.
	//
	// This will show all Params by default.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Available = boolean
	//    Valid = boolean
	//    ReadOnly = boolean
	//
	// Functions:
	//    Eq(value) = Return items that are equal to value
	//    Lt(value) = Return items that are less than value
	//    Lte(value) = Return items that less than or equal to value
	//    Gt(value) = Return items that are greater than value
	//    Gte(value) = Return items that greater than or equal to value
	//    Between(lower,upper) = Return items that are inclusively between lower and upper
	//    Except(lower,upper) = Return items that are not inclusively between lower and upper
	//
	// Example:
	//    Name=fred - returns items named fred
	//    Name=Lt(fred) - returns items that alphabetically less than fred.
	//
	// Responses:
	//    200: ParamsResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.GET("/params",
		func(c *gin.Context) {
			f.List(c, &backend.Param{})
		})

	// swagger:route HEAD /params Params listStatsParams
	//
	// Stats of the List Params filtered by some parameters.
	//
	// This will return headers with the stats of the list.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Available = boolean
	//    Valid = boolean
	//    ReadOnly = boolean
	//
	// Functions:
	//    Eq(value) = Return items that are equal to value
	//    Lt(value) = Return items that are less than value
	//    Lte(value) = Return items that less than or equal to value
	//    Gt(value) = Return items that are greater than value
	//    Gte(value) = Return items that greater than or equal to value
	//    Between(lower,upper) = Return items that are inclusively between lower and upper
	//    Except(lower,upper) = Return items that are not inclusively between lower and upper
	//
	// Example:
	//    Name=fred - returns items named fred
	//    Name=Lt(fred) - returns items that alphabetically less than fred.
	//
	// Responses:
	//    200: NoContentResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.HEAD("/params",
		func(c *gin.Context) {
			f.ListStats(c, &backend.Param{})
		})

	// swagger:route POST /params Params createParam
	//
	// Create a Param
	//
	// Create a Param from the provided object
	//
	//     Responses:
	//       201: ParamResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/params",
		func(c *gin.Context) {
			b := &backend.Param{}
			f.Create(c, b)
		})
	// swagger:route GET /params/{name} Params getParam
	//
	// Get a Param
	//
	// Get the Param specified by {name} or return NotFound.
	//
	//     Responses:
	//       200: ParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/params/*name",
		func(c *gin.Context) {
			name := strings.TrimLeft(c.Param(`name`), `/`)
			f.Fetch(c, &backend.Param{}, name)
		})

	// swagger:route HEAD /params/{name} Params headParam
	//
	// See if a Param exists
	//
	// Return 200 if the Param specifiec by {name} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/params/*name",
		func(c *gin.Context) {
			name := strings.TrimLeft(c.Param(`name`), `/`)
			f.Exists(c, &backend.Param{}, name)
		})

	// swagger:route PATCH /params/{name} Params patchParam
	//
	// Patch a Param
	//
	// Update a Param specified by {name} using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: ParamResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/params/*name",
		func(c *gin.Context) {
			name := strings.TrimLeft(c.Param(`name`), `/`)
			f.Patch(c, &backend.Param{}, name)
		})

	// swagger:route PUT /params/{name} Params putParam
	//
	// Put a Param
	//
	// Update a Param specified by {name} using a JSON Param
	//
	//     Responses:
	//       200: ParamResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/params/*name",
		func(c *gin.Context) {
			name := strings.TrimLeft(c.Param(`name`), `/`)
			f.Update(c, &backend.Param{}, name)
		})

	// swagger:route DELETE /params/{name} Params deleteParam
	//
	// Delete a Param
	//
	// Delete a Param specified by {name}
	//
	//     Responses:
	//       200: ParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/params/*name",
		func(c *gin.Context) {
			name := strings.TrimLeft(c.Param(`name`), `/`)
			f.Remove(c, &backend.Param{}, name)
		})
}
