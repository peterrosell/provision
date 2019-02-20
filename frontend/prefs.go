package frontend

import (
	"net/http"
	"strconv"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// PrefsResponse returned on a successful GET of all preferences
// swagger:response
type PrefsResponse struct {
	// in: body
	Body map[string]string
}

// PrefBodyParameter is used to create or update a Pref
// swagger:parameters setPrefs
type PrefBodyParameter struct {
	// in: body
	Body map[string]string
}

func (f *Frontend) InitPrefApi() {
	// swagger:route GET /prefs Prefs listPrefs
	//
	// Lists Prefs
	//
	// This will show all Prefs by default
	//
	//      Responses:
	//        200: PrefsResponse
	//        401: NoContentResponse
	//        403: NoContentResponse
	f.ApiGroup.GET("/prefs",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, "prefs", "list", "") {
				return
			}
			c.JSON(http.StatusOK, f.dt.Prefs())
		})

	// swagger:route POST /prefs Prefs setPrefs
	//
	// Create a Pref
	//
	// Create a Pref from the provided object
	//
	//      Responses:
	//       201: PrefsResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/prefs",
		func(c *gin.Context) {
			prefs := map[string]string{}
			if !assureDecode(c, &prefs) {
				return
			}
			err := &models.Error{
				Type:  c.Request.Method,
				Model: "prefs",
				Code:  http.StatusBadRequest,
			}
			restartPlugins := false
			// Filter unknown preferences here
			for k := range prefs {
				if k == "baseTokenSecret" || k == "systemGrantorSecret" {
					restartPlugins = true
				}
				switch k {
				case "baseTokenSecret":
					if !f.assureSimpleAuth(c, "prefs", "post", k) {
						return
					}
					if len(prefs[k]) != 32 {
						err.Errorf("%s: Must be 32 bytes long", k)
					}
				case "defaultBootEnv", "unknownBootEnv", "defaultStage", "defaultWorkflow", "systemGrantorSecret",
					"debugRenderer", "debugDhcp", "debugBootEnv", "debugFrontend", "debugPlugins", "logLevel":
					if !f.assureSimpleAuth(c, "prefs", "post", k) {
						return
					}
				case "knownTokenTimeout", "unknownTokenTimeout":
					if !f.assureSimpleAuth(c, "prefs", "post", k) {
						return
					}
					if _, e := strconv.Atoi(prefs[k]); e != nil {
						err.Errorf("%s: %v", k, e)
					}
				default:
					err.Errorf("Unknown Preference %s", k)
				}
			}
			if !err.ContainsError() {
				obj := &backend.Pref{}
				rt := f.rt(c, obj.Locks("update")...)
				rt.Do(func(d backend.Stores) {
					err.AddError(f.dt.SetPrefs(rt, prefs))
				})
			}
			if err.ContainsError() {
				c.JSON(err.Code, err)
			} else {
				if restartPlugins {
					f.pc.RestartPlugins()
				}
				c.JSON(http.StatusCreated, f.dt.Prefs())
			}
		})
}
