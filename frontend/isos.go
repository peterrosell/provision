package frontend

import (
	"github.com/digitalrebar/provision/models"
)

// IsoPaths is a list of isos
type IsoPaths []string

// IsosResponse returned on a successful GET of isos
// swagger:response
type IsosResponse struct {
	// in: body
	Body IsoPaths
}

// This is a HACK - I can't figure out how to get
// swagger to render this a binary.  So we lie.
// We also override this object from the server
// directory to have a binary format which
// turns it into a stream.
//
// IsoResponse returned on a successful GET of an iso
// swagger:response
type IsoResponse struct {
	// in: body
	Body interface{}
}

// IsoInfoResponse returned on a successful upload of an iso
// swagger:response
type IsoInfoResponse struct {
	// in: body
	Body *models.BlobInfo
}

// swagger:parameters uploadIso getIso deleteIso headIso
type IsoPathPathParameter struct {
	// in: path
	Path string `json:"path"`
}

// IsoData body of the upload
// swagger:parameters uploadIso
type IsoData struct {
	// in: body
	Body interface{}
}

func (f *Frontend) InitIsoApi() {
	list, get, head, post, delete := f.FileCommonFuncs("isos")

	// swagger:route GET /isos Isos listIsos
	//
	// Lists isos in isos directory
	//
	// Lists the isos in a directory under /isos.
	//
	//     Responses:
	//       200: IsosResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/isos", list)

	// swagger:route GET /isos/{path} Isos getIso
	//
	// Get a specific Iso with {path}
	//
	// Get a specific iso specified by {path} under isos.
	//
	//     Produces:
	//       application/octet-stream
	//       application/json
	//
	//     Responses:
	//       200: IsoResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/isos/*path", get)

	// swagger:route HEAD /isos/{path} Files headIso
	//
	// See if a iso exists and return a checksum in the header
	//
	// Return 200 if the iso specified by {path} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/isos/*path", head)

	// swagger:route POST /isos/{path} Isos uploadIso
	//
	// Upload an iso to a specific {path} in the tree under isos.
	//
	// The iso will be uploaded to the {path} in /isos.  The {path} will be created.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       201: IsoInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/isos/*path", post)

	// swagger:route DELETE /isos/{path} Isos deleteIso
	//
	// Delete an iso to a specific {path} in the tree under isos.
	//
	// The iso will be removed from the {path} in /isos.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/isos/*path", delete)
}
