package frontend

import (
	"fmt"
	"net/http"

	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// PluginProvidersResponse returned on a successful GET of an plugin_provider
// swagger:response
type PluginProviderResponse struct {
	// in: body
	Body *models.PluginProvider
}

// PluginProvidersResponse returned on a successful GET of all plugin_provider
// swagger:response
type PluginProvidersResponse struct {
	// in: body
	Body []*models.PluginProvider
}

// swagger:parameters getPluginProvider headPluginProviders uploadPluginProvider deletePluginProvider
type PluginProviderParameter struct {
	// in: path
	Name string `json:"name"`
}

// PluginProviderData body of the upload
// swagger:parameters uploadPluginProvider
type PluginProviderData struct {
	// in: body
	Body interface{}
}

// PluginProviderInfoResponse returned on a successful upload of an iso
// swagger:response
type PluginProviderInfoResponse struct {
	// in: body
	Body *models.PluginProviderUploadInfo
}

func (f *Frontend) InitPluginProviderApi() {
	// swagger:route GET /plugin_providers PluginProviders listPluginProviders
	//
	// Lists possible plugin_provider on the system to create plugins
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: PluginProvidersResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/plugin_providers",
		func(c *gin.Context) {
			res := []*models.PluginProvider{}
			if f.getAuth(c).matchClaim(models.MakeRole("", "plugin_providers", "list", "").Compile()) {
				pps := f.pc.GetPluginProviders()
				for _, pp := range pps {
					if f.getAuth(c).tenantOK("plugin_providers", pp.Name) {
						res = append(res, pp)
					}
				}
			}
			c.JSON(http.StatusOK, res)
		})

	// swagger:route HEAD /plugin_providers PluginProviders headPluginProviders
	//
	// Stats of the list of plugin_provider on the system to create plugins
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: PluginProvidersResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       406: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.HEAD("/plugin_providers",
		func(c *gin.Context) {
			count := "0"
			if f.getAuth(c).matchClaim(models.MakeRole("", "plugin_providers", "list", "").Compile()) {
				res := []*models.PluginProvider{}
				pps := f.pc.GetPluginProviders()
				for _, pp := range pps {
					if f.getAuth(c).tenantOK("plugin_providers", pp.Name) {
						res = append(res, pp)
					}
				}
				count = fmt.Sprintf("%d", len(res))
			}
			c.Header("X-DRP-LIST-TOTAL-COUNT", count)
			c.Header("X-DRP-LIST-COUNT", count)
			c.Status(http.StatusOK)
		})

	// swagger:route GET /plugin_providers/{name} PluginProviders getPluginProvider
	//
	// Get a specific plugin with {name}
	//
	// Get a specific plugin specified by {name}.
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: PluginProviderResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/plugin_providers/:name",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "plugin_providers", "get", c.Param(`name`)) {
				return
			}

			pp := f.pc.GetPluginProvider(c.Param(`name`))
			if pp != nil {
				c.JSON(http.StatusOK, pp)
			} else {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Type:  c.Request.Method,
					Model: "plugin_providers",
					Key:   c.Param(`name`),
				}
				res.Errorf("Not Found")
				c.JSON(res.Code, res)
			}

		})

	// swagger:route HEAD /plugin_providers/{name} PluginProviders headPluginProvider
	//
	// See if a Plugin Provider exists
	//
	// Return 200 if the Plugin Provider specified by {name} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/plugin_providers/:name",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "plugin_providers", "get", c.Param(`name`)) {
				return
			}
			pp := f.pc.GetPluginProvider(c.Param(`name`))
			if pp != nil {
				c.Status(http.StatusOK)
			} else {
				c.Status(http.StatusNotFound)
			}
		})

	// swagger:route POST /plugin_providers/{name} PluginProviders uploadPluginProvider
	//
	// Upload a plugin provider to a specific {name}.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       201: PluginProviderInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/plugin_providers/:name",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "plugin_providers", "post", c.Param(`name`)) {
				return
			}
			answer, err := f.pc.UploadPluginProvider(c, f.FileRoot, c.Param(`name`))
			if err != nil {
				c.JSON(err.Code, err)
				return
			}
			c.JSON(http.StatusCreated, answer)
		})

	// swagger:route DELETE /plugin_providers/{name} PluginProviders deletePluginProvider
	//
	// Delete a plugin provider
	//
	// The plugin provider will be removed from the system.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/plugin_providers/:name",
		func(c *gin.Context) {
			name := c.Param(`name`)
			if !f.assureSimpleAuth(c, "plugin_providers", "delete", name) {
				return
			}
			if err := f.pc.RemovePluginProvider(name); err != nil {
				res := &models.Error{
					Code:  http.StatusNotFound,
					Type:  c.Request.Method,
					Model: "plugin_providers",
					Key:   c.Param(`name`),
				}
				res.Errorf("Not Found")
				c.JSON(res.Code, res)
				return
			}
			c.Data(http.StatusNoContent, gin.MIMEJSON, nil)
		})
}
