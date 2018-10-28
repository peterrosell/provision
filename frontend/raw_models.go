package frontend

import (
	"fmt"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

func (f *Frontend) AddStorageType(prefix string) {
	base := fmt.Sprintf("/api/v3/%s", prefix)
	for _, r := range f.MgmtApi.Routes() {
		if r.Path == base {
			return
		}
	}

	f.ApiGroup.GET(fmt.Sprintf("/%s", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.List(c, obj)
		})

	f.ApiGroup.HEAD(fmt.Sprintf("/%s", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.ListStats(c, obj)
		})

	f.ApiGroup.POST(fmt.Sprintf("/%s", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Create(c, obj)
		})

	f.ApiGroup.GET(fmt.Sprintf("/%s/:name", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Fetch(c, obj, c.Param(`name`))
		})

	f.ApiGroup.HEAD(fmt.Sprintf("/%s/:name", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Exists(c, obj, c.Param(`name`))
		})

	f.ApiGroup.PATCH(fmt.Sprintf("/%s/:name", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Patch(c, obj, c.Param(`name`))
		})

	f.ApiGroup.PUT(fmt.Sprintf("/%s/:name", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Update(c, obj, c.Param(`name`))
		})

	f.ApiGroup.DELETE(fmt.Sprintf("/%s/:name", prefix),
		func(c *gin.Context) {
			obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
			f.Remove(c, obj, c.Param(`name`))
		})

	obj := &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
	pGetAll, pGetOne, pPatch, pSetThem, pSetOne, pDeleteOne, pGetPubKey := f.makeParamEndpoints(obj, "name")
	f.ApiGroup.GET(fmt.Sprintf("/%s/:name/pubkey", prefix), pGetPubKey)
	f.ApiGroup.GET(fmt.Sprintf("/%s/:name/params", prefix), pGetAll)
	f.ApiGroup.GET(fmt.Sprintf("/%s/:name/params/*key", prefix), pGetOne)
	f.ApiGroup.DELETE(fmt.Sprintf("/%s/:name/params/*key", prefix), pDeleteOne)
	f.ApiGroup.PATCH(fmt.Sprintf("/%s/:name/params", prefix), pPatch)
	f.ApiGroup.POST(fmt.Sprintf("/%s/:name/params", prefix), pSetThem)
	f.ApiGroup.POST(fmt.Sprintf("/%s/:name/params/*key", prefix), pSetOne)

	obj = &backend.RawModel{RawModel: &models.RawModel{"Type": prefix}}
	pActions, pAction, pRun := f.makeActionEndpoints(prefix, obj, "name")
	f.ApiGroup.GET(fmt.Sprintf("/%s/:name/actions", prefix), pActions)
	f.ApiGroup.GET(fmt.Sprintf("/%s/:name/actions/:cmd", prefix), pAction)
	f.ApiGroup.POST(fmt.Sprintf("/%s/:name/actions/:cmd", prefix), pRun)
}
