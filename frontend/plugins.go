package frontend

import (
	"net/http"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// PluginResponse return on a successful GET, PUT, PATCH or POST of a single Plugin
// swagger:response
type PluginResponse struct {
	// in: body
	Body *models.Plugin
}

// PluginsResponse return on a successful GET of all Plugins
// swagger:response
type PluginsResponse struct {
	// in: body
	Body []*models.Plugin
}

// PluginParamsResponse return on a successful GET of all Plugin's Params
// swagger:response
type PluginParamsResponse struct {
	// in: body
	Body map[string]interface{}
}

// PluginParamResponse return on a successful GET of one Plugin's Param
// swagger:response
type PluginParamResponse struct {
	// in: body
	Body interface{}
}

// PluginBodyParameter used to inject a Plugin
// swagger:parameters createPlugin putPlugin
type PluginBodyParameter struct {
	// in: body
	// required: true
	Body *models.Plugin
}

// PluginPatchBodyParameter used to patch a Plugin
// swagger:parameters patchPlugin
type PluginPatchBodyParameter struct {
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

// PluginPathParameter used to find a Plugin in the path
// swagger:parameters putPlugins getPlugin putPlugin patchPlugin deletePlugin getPluginParams postPluginParams headPlugin patchPluginParams getPluginPubKey
type PluginPathParameter struct {
	// in: query
	Decode string `json:"decode"`
	// in: query
	Params string `json:"params"`
	// in: path
	// required: true
	Name string `json:"name"`
}

// PluginParamsPathParameter used to find a Plugin in the path
// swagger:parameters getPluginParam postPluginParam
type PluginParamsPathParameter struct {
	// in: query
	Decode string `json:"decode"`
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Key string `json:"key"`
}

// PluginParamsBodyParameter used to set Plugin Params
// swagger:parameters postPluginParams
type PluginParamsBodyParameter struct {
	// in: body
	// required: true
	Body map[string]interface{}
}

// PluginParamBodyParameter used to set Plugin Param
// swagger:parameters postPluginParam
type PluginParamBodyParameter struct {
	// in: body
	// required: true
	Body interface{}
}

// PluginListPathParameter used to limit lists of Plugin by path options
// swagger:parameters listPlugins listStatsPlugins
type PluginListPathParameter struct {
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
	// in: query
	Provider string
	// in: query
	Decode bool `json:"decode"`
	// in: query
	Slim bool `json:"slim"`
	// in: query
	Params string `json:"params"`
}

// PluginActionsPathParameter used to find a Plugin / Actions in the path
// swagger:parameters getPluginActions
type PluginActionsPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: query
	Plugin string `json:"plugin"`
}

// PluginActionPathParameter used to find a Plugin / Action in the path
// swagger:parameters getPluginAction
type PluginActionPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
}

// PluginActionBodyParameter used to post a Plugin / Action in the path
// swagger:parameters postPluginAction
type PluginActionBodyParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
	// in: body
	// required: true
	Body map[string]interface{}
}

func (f *Frontend) InitPluginApi() {
	// swagger:route GET /plugins Plugins listPlugins
	//
	// Lists Plugins filtered by some parameters.
	//
	// This will show all Plugins by default.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Provider = string
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
	//    Name=Lt(fred)&Available=true - returns items with Name less than fred and Available is true
	//
	// Responses:
	//    200: PluginsResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.GET("/plugins",
		func(c *gin.Context) {
			f.List(c, &backend.Plugin{})
		})

	// swagger:route HEAD /plugins Plugins listStatsPlugins
	//
	// Stats of the List Plugins filtered by some parameters.
	//
	// This will return headers with the stats of the list.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Name = string
	//    Provider = string
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
	//    Name=Lt(fred)&Available=true - returns items with Name less than fred and Available is true
	//
	// Responses:
	//    200: NoContentResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.HEAD("/plugins",
		func(c *gin.Context) {
			f.ListStats(c, &backend.Plugin{})
		})

	// swagger:route POST /plugins Plugins createPlugin
	//
	// Create a Plugin
	//
	// Create a Plugin from the provided object
	//
	//     Responses:
	//       201: PluginResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/plugins",
		func(c *gin.Context) {
			// We don't use f.Create() because we need to be able to assign random
			// UUIDs to new Plugins without forcing the client to do so, yet allow them
			// for testing purposes amd if they alrady have a UUID scheme for plugins.
			b := &backend.Plugin{}
			if !assureDecode(c, b) {
				return
			}
			rt := f.rt(c, b.Locks("create")...)
			if !f.assureSimpleAuth(c, rt, b.Prefix(), "create", "") {
				return
			}
			var err error
			var res models.Model
			rt.Do(func(d backend.Stores) {
				if _, err = rt.Create(b); err != nil {
					return
				}
				s, ok := models.Model(b).(Sanitizable)
				if ok {
					res = s.Sanitize()
					return
				}
				res = models.Clone(b)
			})
			if err != nil {
				be, ok := err.(*models.Error)
				if ok {
					c.JSON(be.Code, be)
				} else {
					c.JSON(http.StatusBadRequest, models.NewError("API_ERROR", http.StatusBadRequest, err.Error()))
				}
			} else {
				c.JSON(http.StatusCreated, res)
			}
		})

	// swagger:route GET /plugins/{name} Plugins getPlugin
	//
	// Get a Plugin
	//
	// Get the Plugin specified by {name} or return NotFound.
	//
	//     Responses:
	//       200: PluginResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/plugins/:name",
		func(c *gin.Context) {
			f.Fetch(c, &backend.Plugin{}, c.Param(`name`))
		})

	// swagger:route HEAD /plugins/{name} Plugins headPlugin
	//
	// See if a Plugin exists
	//
	// Return 200 if the Plugin specifiec by {name} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/plugins/:name",
		func(c *gin.Context) {
			f.Exists(c, &backend.Plugin{}, c.Param(`name`))
		})

	// swagger:route PATCH /plugins/{name} Plugins patchPlugin
	//
	// Patch a Plugin
	//
	// Update a Plugin specified by {name} using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: PluginResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/plugins/:name",
		func(c *gin.Context) {
			f.Patch(c, &backend.Plugin{}, c.Param(`name`))
		})

	// swagger:route PUT /plugins/{name} Plugins putPlugin
	//
	// Put a Plugin
	//
	// Update a Plugin specified by {name} using a JSON Plugin
	//
	//     Responses:
	//       200: PluginResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/plugins/:name",
		func(c *gin.Context) {
			f.Update(c, &backend.Plugin{}, c.Param(`name`))
		})

	// swagger:route DELETE /plugins/{name} Plugins deletePlugin
	//
	// Delete a Plugin
	//
	// Delete a Plugin specified by {name}
	//
	//     Responses:
	//       200: PluginResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/plugins/:name",
		func(c *gin.Context) {
			f.Remove(c, &backend.Plugin{}, c.Param(`name`))
		})

	pGetAll, pGetOne, pPatch, pSetThem, pSetOne, pDeleteOne, pGetPubKey := f.makeParamEndpoints(&backend.Plugin{}, "name")

	// swagger:route GET /plugins/{name}/pubkey Plugins getPluginPubKey
	//
	// Get the public key for secure params on a plugin
	//
	// Get the public key for a Plugin specified by {name}
	//
	//     Responses:
	//       200: PubKeyResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/plugins/:name/pubkey", pGetPubKey)

	// swagger:route GET /plugins/{name}/params Plugins getPluginParams
	//
	// List plugin params Plugin
	//
	// List Plugin parms for a Plugin specified by {name}
	//
	//     Responses:
	//       200: PluginParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/plugins/:name/params", pGetAll)

	// swagger:route GET /plugins/{name}/params/{key} Plugins getPluginParam
	//
	// Get a single plugin parameter
	//
	// Get a single parameter {key} for a Plugin specified by {name}
	//
	//     Responses:
	//       200: PluginParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/plugins/:name/params/*key", pGetOne)

	// swagger:route DELETE /plugins/{uuid}/params/{key} Plugins getPluginParam
	//
	// Delete a single plugin parameter
	//
	// Delete a single parameter {key} for a Plugin specified by {uuid}
	//
	//     Responses:
	//       200: PluginParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.DELETE("/plugins/:name/params/*key", pDeleteOne)

	// swagger:route PATCH /plugins/{name}/params Plugins patchPluginParams
	//
	// Update params for Plugin {name} with the passed-in patch
	//
	//     Responses:
	//       200: PluginParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.PATCH("/plugins/:name/params", pPatch)

	// swagger:route POST /plugins/{name}/params Plugins postPluginParams
	//
	// Sets parameters for a plugin specified by {name}
	//
	//     Responses:
	//       200: PluginParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/plugins/:name/params", pSetThem)

	// swagger:route POST /plugins/{name}/params/{key} Plugins postPluginParam
	//
	// Set as single Parameter {key} for a plugin specified by {name}
	//
	//     Responses:
	//       200: PluginParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/plugins/:name/params/*key", pSetOne)

	plugin := &backend.Plugin{}
	pActions, pAction, pRun := f.makeActionEndpoints(plugin.Prefix(), plugin, "name")

	// swagger:route GET /plugins/{name}/actions Plugins getPluginActions
	//
	// List plugin actions Plugin
	//
	// List Plugin actions for a Plugin specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionsResponse
	//       401: NoPluginResponse
	//       403: NoPluginResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/plugins/:name/actions", pActions)

	// swagger:route GET /plugins/{name}/actions/{cmd} Plugins getPluginAction
	//
	// List specific action for a plugin Plugin
	//
	// List specific {cmd} action for a Plugin specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionResponse
	//       400: ErrorResponse
	//       401: NoPluginResponse
	//       403: NoPluginResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/plugins/:name/actions/:cmd", pAction)

	// swagger:route POST /plugins/{name}/actions/{cmd} Plugins postPluginAction
	//
	// Call an action on the node.
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//
	//     Responses:
	//       400: ErrorResponse
	//       200: ActionPostResponse
	//       401: NoPluginResponse
	//       403: NoPluginResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/plugins/:name/actions/:cmd", pRun)
}
