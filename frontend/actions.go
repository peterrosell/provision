package frontend

import (
	"net/http"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// ActionResponse return on a successful GET of a single Action
// swagger:response
type ActionResponse struct {
	// in: body
	Body *models.AvailableAction
}

// ActionsResponse return on a successful GET of all Actions
// swagger:response
type ActionsResponse struct {
	// in: body
	Body []*models.AvailableAction
}

// ActionPostResponse return on a successful POST of action
// swagger:response
type ActionPostResponse struct {
	// in: body
	Body interface{}
}

func (f *Frontend) makeActionEndpoints(cmdSet string, obj models.Model, idKey string) (
	getActions, getAction, runAction func(c *gin.Context)) {
	plugin := func(c *gin.Context) string {
		return c.Query("plugin")
	}
	idrtkeyok := func(c *gin.Context, op string) (string, *backend.RequestTracker, string, bool) {
		if op == "" {
			op = "action:" + c.Param("cmd")
		}
		id := c.Param(idKey)
		if id == "" {
			id = "global"
		}
		rt := f.rt(c, obj.(Lockable).Locks("actions")...)
		return id,
			rt,
			c.Param("cmd"),
			f.assureSimpleAuth(c, rt, cmdSet, op, id)
	}

	return /* allActions */ func(c *gin.Context) {
			id, rt, _, ok := idrtkeyok(c, "actions")
			if !ok {
				return
			}
			actions := []models.AvailableAction{}
			ref := f.Find(c, rt, obj.Prefix(), id)
			if ref == nil {
				return
			}
			if fok, mok := f.processRequestWithForwarding(c, ref, nil); fok || mok {
				return
			}
			rt.Do(func(_ backend.Stores) { actions = rt.AllActions(ref, cmdSet, plugin(c), nil) })
			c.JSON(http.StatusOK, actions)
		},
		/* oneAction */ func(c *gin.Context) {
			id, rt, cmd, ok := idrtkeyok(c, "")
			if !ok {
				return
			}
			ref := f.Find(c, rt, obj.Prefix(), id)
			if ref == nil {
				return
			}
			if fok, mok := f.processRequestWithForwarding(c, ref, nil); fok || mok {
				return
			}
			var err *models.Error
			var aa []models.AvailableAction
			rt.Do(func(_ backend.Stores) { aa, err = rt.Actions(ref, cmdSet, cmd, plugin(c), nil) })
			if len(aa) == 0 {
				c.AbortWithStatusJSON(err.Code, err)
			} else {
				c.JSON(http.StatusOK, aa[0])
			}
		},
		/* runAction */ func(c *gin.Context) {
			var val map[string]interface{}
			if !assureDecode(c, &val) {
				return
			}
			id, rt, cmd, ok := idrtkeyok(c, "")
			if !ok {
				return
			}
			ref := f.Find(c, rt, obj.Prefix(), id)
			if ref == nil {
				return
			}
			if fok, mok := f.processRequestWithForwarding(c, ref, val); fok || mok {
				return
			}
			var out interface{}
			var err error
			var ma *models.Action
			rt.Do(func(_ backend.Stores) { ma, err = rt.BuildAction(ref, cmdSet, cmd, plugin(c), val) })
			if err.(*models.Error) == nil {
				rt.Publish(ma.CommandSet, ma.Command, id, ma)
				out, err = rt.RunAction(ma)
			}
			be, ok := err.(*models.Error)
			if !ok && err != nil {
				c.JSON(409, err)
			} else if ok && be != nil {
				be.Type = "INVOKE"
				c.JSON(be.Code, be)
			} else {
				c.JSON(http.StatusOK, out)
			}
		}
}
