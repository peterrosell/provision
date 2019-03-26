package frontend

import (
	"net/http"

	"github.com/digitalrebar/logger"
	"github.com/gin-gonic/gin"
)

// LogResponse is returned in response to a log dump request.
// swagger:response
type LogResponse struct {
	// in: body
	Body []*logger.Line
}

func (f *Frontend) InitLogApi() {
	// swagger:route GET /logs Logs getLogs
	//
	// Return current contents of the log buffer
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       200: LogResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/logs",
		func(c *gin.Context) {
			if !f.assureSimpleAuth(c, f.rt(c), "logs", "get", "") {
				return
			}
			c.JSON(http.StatusOK, f.Logger.Buffer().Lines(-1))
		})
}
