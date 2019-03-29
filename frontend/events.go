package frontend

import (
	"net/http"

	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// EventBodyParameter is used to create an Event
// swagger:parameters postEvent
type EventBodyParameter struct {
	// in: body
	Body *models.Event
}

func (f *Frontend) InitEventApi() {
	// swagger:route POST /events Events postEvent
	//
	// Create an Event
	//
	// Create an Event from the provided object
	//
	//      Responses:
	//       204: NoContentResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/events",
		func(c *gin.Context) {
			rt := f.rt(c)
			if !f.assureSimpleAuth(c, rt, "events", "post", "*") {
				return
			}
			event := models.Event{}
			if !assureDecode(c, &event) {
				return
			}

			if err := rt.PublishEvent(&event); err != nil {
				be, ok := err.(*models.Error)
				if ok {
					c.JSON(be.Code, be)
				} else {
					c.JSON(http.StatusBadRequest, models.NewError("API_ERROR", http.StatusBadRequest, err.Error()))
				}

			} else {
				c.Data(http.StatusNoContent, gin.MIMEJSON, nil)
			}
		})
}
