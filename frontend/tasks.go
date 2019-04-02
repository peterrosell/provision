package frontend

import (
	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
)

// TaskResponse return on a successful GET, PUT, PATCH or POST of a single Task
// swagger:response
type TaskResponse struct {
	// in: body
	Body *models.Task
}

// TasksResponse return on a successful GET of all Tasks
// swagger:response
type TasksResponse struct {
	// in: body
	Body []*models.Task
}

// TaskParamsResponse return on a successful GET of all Task's Params
// swagger:response
type TaskParamsResponse struct {
	// in: body
	Body map[string]interface{}
}

// TaskBodyParameter used to inject a Task
// swagger:parameters createTask putTask
type TaskBodyParameter struct {
	// in: body
	// required: true
	Body *models.Task
}

// TaskPatchBodyParameter used to patch a Task
// swagger:parameters patchTask
type TaskPatchBodyParameter struct {
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

// TaskPathParameter used to find a Task in the path
// swagger:parameters putTasks getTask putTask patchTask deleteTask getTaskParams postTaskParams headTask
type TaskPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
}

// TaskParamsBodyParameter used to set Task Params
// swagger:parameters postTaskParams
type TaskParamsBodyParameter struct {
	// in: body
	// required: true
	Body map[string]interface{}
}

// TaskListPathParameter used to limit lists of Task by path options
// swagger:parameters listTasks listStatsTasks
type TaskListPathParameter struct {
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

// TaskActionsPathParameter used to find a Task / Actions in the path
// swagger:parameters getTaskActions
type TaskActionsPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: query
	Plugin string `json:"plugin"`
}

// TaskActionPathParameter used to find a Task / Action in the path
// swagger:parameters getTaskAction
type TaskActionPathParameter struct {
	// in: path
	// required: true
	Name string `json:"name"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
}

// TaskActionBodyParameter used to post a Task / Action in the path
// swagger:parameters postTaskAction
type TaskActionBodyParameter struct {
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

func (f *Frontend) InitTaskApi() {
	// swagger:route GET /tasks Tasks listTasks
	//
	// Lists Tasks filtered by some parameters.
	//
	// This will show all Tasks by default.
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
	//    200: TasksResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.GET("/tasks",
		func(c *gin.Context) {
			f.List(c, &backend.Task{})
		})

	// swagger:route HEAD /tasks Tasks listStatsTasks
	//
	// Stats of the List Tasks filtered by some parameters.
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
	f.ApiGroup.HEAD("/tasks",
		func(c *gin.Context) {
			f.ListStats(c, &backend.Task{})
		})

	// swagger:route POST /tasks Tasks createTask
	//
	// Create a Task
	//
	// Create a Task from the provided object
	//
	//     Responses:
	//       201: TaskResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/tasks",
		func(c *gin.Context) {
			b := &backend.Task{}
			if !assureDecode(c, b) {
				return
			}
			// All newly created tasks are assumed to have sane-exit-codes if not specified.
			b.Fill()
			if !b.HasFeature("original-exit-codes") {
				b.AddFeature("sane-exit-codes")
			}
			f.create(c, b)
		})

	// swagger:route GET /tasks/{name} Tasks getTask
	//
	// Get a Task
	//
	// Get the Task specified by {name} or return NotFound.
	//
	//     Responses:
	//       200: TaskResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/tasks/:name",
		func(c *gin.Context) {
			f.Fetch(c, &backend.Task{}, c.Param(`name`))
		})

	// swagger:route HEAD /tasks/{name} Tasks headTask
	//
	// See if a Task exists
	//
	// Return 200 if the Task specifiec by {name} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/tasks/:name",
		func(c *gin.Context) {
			f.Exists(c, &backend.Task{}, c.Param(`name`))
		})

	// swagger:route PATCH /tasks/{name} Tasks patchTask
	//
	// Patch a Task
	//
	// Update a Task specified by {name} using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: TaskResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/tasks/:name",
		func(c *gin.Context) {
			f.Patch(c, &backend.Task{}, c.Param(`name`))
		})

	// swagger:route PUT /tasks/{name} Tasks putTask
	//
	// Put a Task
	//
	// Update a Task specified by {name} using a JSON Task
	//
	//     Responses:
	//       200: TaskResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/tasks/:name",
		func(c *gin.Context) {
			f.Update(c, &backend.Task{}, c.Param(`name`))
		})

	// swagger:route DELETE /tasks/{name} Tasks deleteTask
	//
	// Delete a Task
	//
	// Delete a Task specified by {name}
	//
	//     Responses:
	//       200: TaskResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/tasks/:name",
		func(c *gin.Context) {
			f.Remove(c, &backend.Task{}, c.Param(`name`))
		})

	task := &backend.Task{}
	pActions, pAction, pRun := f.makeActionEndpoints(task.Prefix(), task, "name")

	// swagger:route GET /tasks/{name}/actions Tasks getTaskActions
	//
	// List task actions Task
	//
	// List Task actions for a Task specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionsResponse
	//       401: NoTaskResponse
	//       403: NoTaskResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/tasks/:name/actions", pActions)

	// swagger:route GET /tasks/{name}/actions/{cmd} Tasks getTaskAction
	//
	// List specific action for a task Task
	//
	// List specific {cmd} action for a Task specified by {name}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionResponse
	//       400: ErrorResponse
	//       401: NoTaskResponse
	//       403: NoTaskResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/tasks/:name/actions/:cmd", pAction)

	// swagger:route POST /tasks/{name}/actions/{cmd} Tasks postTaskAction
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
	//       401: NoTaskResponse
	//       403: NoTaskResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/tasks/:name/actions/:cmd", pRun)
}
