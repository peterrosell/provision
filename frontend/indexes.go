package frontend

import (
	"fmt"
	"net/http"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

type Indexer interface {
	Indexes() map[string]index.Maker
}

// IndexResponse lists all of the static indexes for a specific type of object
// swagger:response
type IndexResponse struct {
	// in: body
	Body map[string]models.Index
}

// IndexesResponse lists all the static indexes for all the object types
// swagger:response
type IndexesResponse struct {
	// in: body
	Body map[string]map[string]models.Index
}

// SingleIndexResponse tests to see if a single specific index exists.
// Unlike the other index API endpoints, you can probe for dynamic indexes
// this way.
// swagger:response
type SingleIndexResponse struct {
	// in: body
	Body models.Index
}

// swagger:parameters getIndex
type IndexParameter struct {
	// in: path
	Prefix string `json:"prefix"`
}

// swagger:parameters getSingleIndex
type SingleIndexParameter struct {
	// in: path
	Prefix string `json:"prefix"`
	// in: path
	Param string `json:"param"`
}

func indexesFor(i Indexer) map[string]index.Maker {
	res := map[string]index.Maker{}
	for k, v := range i.Indexes() {
		v.Unordered = !v.Sortable()
		res[k] = v
	}
	return res
}

func (f *Frontend) InitIndexApi() {
	//swagger:route GET /indexes Indexes listIndexes
	//
	// List all static indexes for objects
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: IndexesResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/indexes",
		func(c *gin.Context) {
			res := map[string]map[string]index.Maker{}
			for _, m := range models.All() {
				bm := backend.ModelToBackend(m)
				idxer, ok := bm.(Indexer)
				if !ok {
					continue
				}
				res[m.Prefix()] = indexesFor(idxer)
			}
			c.JSON(http.StatusOK, res)
		})

	// swagger:route GET /indexes/{prefix} Indexes getIndex
	//
	// Get static indexes for a specific object type
	//
	//     Produces:
	//       application/json
	//     Responses:
	//       200: IndexResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/indexes/:prefix",
		func(c *gin.Context) {
			m, err := models.New(c.Param("prefix"))
			if err != nil {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s", c.Param("prefix"))))
				return
			}
			bm := backend.ModelToBackend(m)
			if bm == nil {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s", c.Param("prefix"))))
				return
			}
			idxer, ok := bm.(Indexer)
			if !ok {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s", c.Param("prefix"))))
				return
			}
			idxes := indexesFor(idxer)
			c.JSON(http.StatusOK, idxes)
		})

	// swagger:route GET /indexes/{prefix}/{param} Indexes getSingleIndex
	//
	// Get information on a specific index for a specific object type.
	// Unlike the other routes, you can probe for parameter-defined
	// indexes using this route.
	//
	//     Produces:
	//       application/json
	//     Responses:
	//       200: IndexResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/indexes/:prefix/:param",
		func(c *gin.Context) {
			prefix := c.Param("prefix")
			paramName := c.Param("param")
			m, err := models.New(prefix)
			if err != nil {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s/%s", prefix, paramName)))
				return
			}
			bm := backend.ModelToBackend(m)
			idxer, ok := bm.(Indexer)
			if !ok {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s/%s", prefix, paramName)))
				return
			}
			staticIndexes := idxer.Indexes()
			if staticIndex, ok := staticIndexes[c.Param("param")]; ok {
				staticIndex.Unordered = !staticIndex.Sortable()
				c.JSON(http.StatusOK, staticIndex)
			}
			dpm, ok := bm.(dynParameter)
			if !ok {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s/%s", prefix, paramName)))
				return
			}
			param := &backend.Param{}
			rt := f.rt(c, param.Locks("get")...)
			var dynIndex index.Maker
			rt.Do(func(d backend.Stores) {
				dynIndex, err = dpm.ParameterMaker(rt, paramName)
			})
			if err != nil {
				c.JSON(http.StatusNotFound,
					models.NewError(c.Request.Method, http.StatusNotFound,
						fmt.Sprintf("index get: not found: %s/%s", prefix, paramName)))
				return
			}
			dynIndex.Unordered = !dynIndex.Sortable()
			c.JSON(http.StatusOK, dynIndex)
		})
}
