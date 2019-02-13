package frontend

import (
	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
	"github.com/pborman/uuid"
)

// PubKeyResponse is returned on a successful GET of a Paramer public key for secure params.
// swagger:response
type PubKeyResponse struct {
	// in: body
	Body string
}

// MachineResponse return on a successful GET, PUT, PATCH or POST of a single Machine
// swagger:response
type MachineResponse struct {
	// in: body
	Body *models.Machine
}

// MachinesResponse return on a successful GET of all Machines
// swagger:response
type MachinesResponse struct {
	// in: body
	Body []*models.Machine
}

// MachineParamsResponse return on a successful GET of all Machine's Params
// swagger:response
type MachineParamsResponse struct {
	// in: body
	Body map[string]interface{}
}

// MachineParamResponse return on a successful GET of a single Machine param
// swagger:response
type MachineParamResponse struct {
	// in: body
	Body interface{}
}

// MachineBodyParameter used to inject a Machine
// swagger:parameters createMachine putMachine
type MachineBodyParameter struct {
	// in: query
	Force string `json:"force"`
	// in: body
	// required: true
	Body *models.Machine
}

// MachinePatchBodyParameter used to patch a Machine
// swagger:parameters patchMachine
type MachinePatchBodyParameter struct {
	// in: query
	Force string `json:"force"`
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

// MachinePatchBodyParameter used to patch a Machine
// swagger:parameters patchMachineParams
type MachinePatchParamsParameter struct {
	// in: body
	// required: true
	Body jsonpatch2.Patch
}

//MachinePostParamParameter used to POST a machine parameter
//swagger:parameters postMachineParam
type MachinePostParamParameter struct {
	// in: body
	// required: true
	Body interface{}
}

//MachinePostParamsParameter used to POST machine parameters
//swagger:parameters postMachineParams
type MachinePostParamsParameter struct {
	// in: body
	// required: true
	Body map[string]interface{}
}

// MachinePathParameter used to find a Machine in the path
// swagger:parameters putMachines getMachine putMachine patchMachine deleteMachine headMachine patchMachineParams postMachineParams getMachinePubKey
type MachinePathParameter struct {
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
}

// MachinePostParamPathParemeter used to get a single Parameter for a single Machine
// swagger:parameters postMachineParam
type MachinePostParamPathParemeter struct {
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
	// in: path
	//required: true
	Key string `json:"key"`
}

// MachineGetParamsPathParameter used to find a Machine in the path
// swagger:parameters getMachineParams
type MachineGetParamsPathParameter struct {
	// in: query
	Aggregate string `json:"aggregate"`
	// in: query
	Decode string `json:"decode"`
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
}

//  MachineGetParamPathParemeter used to get a single Parameter for a single Machine
// swagger:parameters getMachineParam
type MachineGetParamPathParemeter struct {
	// in: query
	Aggregate string `json:"aggregate"`
	// in: query
	Decode string `json:"decode"`
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
	// in: path
	//required: true
	Key string `json:"key"`
}

// MachineActionsPathParameter used to find a Machine / Actions in the path
// swagger:parameters getMachineActions
type MachineActionsPathParameter struct {
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
	// in: query
	Plugin string `json:"plugin"`
}

// MachineActionPathParameter used to find a Machine / Action in the path
// swagger:parameters getMachineAction
type MachineActionPathParameter struct {
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
}

// MachineActionBodyParameter used to post a Machine / Action in the path
// swagger:parameters postMachineAction
type MachineActionBodyParameter struct {
	// in: path
	// required: true
	// swagger:strfmt uuid
	Uuid uuid.UUID `json:"uuid"`
	// in: path
	// required: true
	Cmd string `json:"cmd"`
	// in: query
	Plugin string `json:"plugin"`
	// in: body
	// required: true
	Body map[string]interface{}
}

// MachineListPathParameter used to limit lists of Machine by path options
// swagger:parameters listMachines listStatsMachines
type MachineListPathParameter struct {
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
	Uuid string
	// in: query
	Name string
	// in: query
	BootEnv string
	// in: query
	Address string
	// in: query
	Runnable string
	// in: query
	Decode bool `json:"decode"`
}

func (f *Frontend) InitMachineApi() {
	// swagger:route GET /machines Machines listMachines
	//
	// Lists Machines filtered by some parameters.
	//
	// This will show all Machines by default.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Uuid = UUID string
	//    Name = string
	//    BootEnv = string
	//    Address = IP Address
	//    Runnable = true/false
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
	//    200: MachinesResponse
	//    401: NoContentResponse
	//    403: NoContentResponse
	//    406: ErrorResponse
	f.ApiGroup.GET("/machines",
		func(c *gin.Context) {
			f.List(c, &backend.Machine{})
		})

	// swagger:route HEAD /machines Machines listStatsMachines
	//
	// Stats of the List Machines filtered by some parameters.
	//
	// This will return headers with the stats of the list.
	//
	//   X-DRP-LIST-COUNT - number of objects in the list.
	//
	// You may specify:
	//    Offset = integer, 0-based inclusive starting point in filter data.
	//    Limit = integer, number of items to return
	//
	// Functional Indexs:
	//    Uuid = UUID string
	//    Name = string
	//    BootEnv = string
	//    Address = IP Address
	//    Runnable = true/false
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
	f.ApiGroup.HEAD("/machines",
		func(c *gin.Context) {
			f.ListStats(c, &backend.Machine{})
		})

	// swagger:route POST /machines Machines createMachine
	//
	// Create a Machine
	//
	// Create a Machine from the provided object
	//
	//     Responses:
	//       201: MachineResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.POST("/machines",
		func(c *gin.Context) {
			// We don't use f.Create() because we need to be able to assign random
			// UUIDs to new Machines without forcing the client to do so, yet allow them
			// for testing purposes amd if they alrady have a UUID scheme for machines.
			b := &backend.Machine{}
			if !assureDecode(c, b) {
				return
			}
			if b.Uuid == nil || len(b.Uuid) == 0 {
				b.Uuid = uuid.NewRandom()
			}
			f.create(c, b)
		})

	// swagger:route GET /machines/{uuid} Machines getMachine
	//
	// Get a Machine
	//
	// Get the Machine specified by {uuid} or return NotFound.
	//
	//     Responses:
	//       200: MachineResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid",
		func(c *gin.Context) {
			f.Fetch(c, &backend.Machine{}, c.Param(`uuid`))
		})

	// swagger:route HEAD /machines/{uuid} Machines headMachine
	//
	// See if a Machine exists
	//
	// Return 200 if the Machine specifiec by {uuid} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/machines/:uuid",
		func(c *gin.Context) {
			f.Exists(c, &backend.Machine{}, c.Param(`uuid`))
		})

	// swagger:route PATCH /machines/{uuid} Machines patchMachine
	//
	// Patch a Machine
	//
	// Update a Machine specified by {uuid} using a RFC6902 Patch structure
	//
	//     Responses:
	//       200: MachineResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       406: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PATCH("/machines/:uuid",
		func(c *gin.Context) {
			machine := &backend.Machine{}
			backend.Fill(machine)
			if c.Query("force") == "true" {
				machine.ForceChange()
			}
			f.Patch(c, machine, c.Param(`uuid`))
		})

	// swagger:route PUT /machines/{uuid} Machines putMachine
	//
	// Put a Machine
	//
	// Update a Machine specified by {uuid} using a JSON Machine
	//
	//     Responses:
	//       200: MachineResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.PUT("/machines/:uuid",
		func(c *gin.Context) {
			machine := &backend.Machine{}
			backend.Fill(machine)
			if c.Query("force") == "true" {
				machine.ForceChange()
			}
			f.Update(c, machine, c.Param(`uuid`))
		})

	// swagger:route DELETE /machines/{uuid} Machines deleteMachine
	//
	// Delete a Machine
	//
	// Delete a Machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/machines/:uuid",
		func(c *gin.Context) {
			f.Remove(c, &backend.Machine{}, c.Param(`uuid`))
		})

	pGetAll, pGetOne, pPatch, pSetThem, pSetOne, pDeleteOne, pGetPubKey := f.makeParamEndpoints(&backend.Machine{}, "uuid")

	// swagger:route GET /machines/{uuid}/pubkey Machines getMachinePubKey
	//
	// Get the public key for secure params on a machine
	//
	// Get the public key for a Machine specified by {uuid}
	//
	//     Responses:
	//       200: PubKeyResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       500: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid/pubkey", pGetPubKey)

	// swagger:route GET /machines/{uuid}/params Machines getMachineParams
	//
	// List machine params Machine
	//
	// List Machine parms for a Machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid/params", pGetAll)

	// swagger:route GET /machines/{uuid}/params/{key} Machines getMachineParam
	//
	// Get a single machine parameter
	//
	// Get a single parameter {key} for a Machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid/params/*key", pGetOne)

	// swagger:route DELETE /machines/{uuid}/params/{key} Machines getMachineParam
	//
	// Delete a single machine parameter
	//
	// Delete a single parameter {key} for a Machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.DELETE("/machines/:uuid/params/*key", pDeleteOne)

	// swagger:route PATCH /machines/{uuid}/params Machines patchMachineParams
	//
	// Update params for Machine {uuid} with the passed-in patch
	//
	//     Responses:
	//       200: MachineParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.PATCH("/machines/:uuid/params", pPatch)

	// swagger:route POST /machines/{uuid}/params Machines postMachineParams
	//
	// Sets parameters for a machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineParamsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/machines/:uuid/params", pSetThem)

	// swagger:route POST /machines/{uuid}/params/{key} Machines postMachineParam
	//
	// Set as single Parameter {key} for a machine specified by {uuid}
	//
	//     Responses:
	//       200: MachineParamResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/machines/:uuid/params/*key", pSetOne)

	machine := &backend.Machine{}
	pActions, pAction, pRun := f.makeActionEndpoints(machine.Prefix(), machine, "uuid")

	// swagger:route GET /machines/{uuid}/actions Machines getMachineActions
	//
	// List machine actions Machine
	//
	// List Machine actions for a Machine specified by {uuid}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionsResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid/actions", pActions)

	// swagger:route GET /machines/{uuid}/actions/{cmd} Machines getMachineAction
	//
	// List specific action for a machine Machine
	//
	// List specific {cmd} action for a Machine specified by {uuid}
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       200: ActionResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/machines/:uuid/actions/:cmd", pAction)

	// swagger:route POST /machines/{uuid}/actions/{cmd} Machines postMachineAction
	//
	// Call an action on the node.
	//
	// Optionally, a query parameter can be used to limit the scope to a specific plugin.
	//   e.g. ?plugin=fred
	//
	//     Responses:
	//       400: ErrorResponse
	//       200: ActionPostResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	f.ApiGroup.POST("/machines/:uuid/actions/:cmd", pRun)

}
