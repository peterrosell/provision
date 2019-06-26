package frontend

import (
	"github.com/digitalrebar/provision/models"
)

// FilePaths is a list of files
type FilePaths []string

// FilesResponse returned on a successful GET of files
// swagger:response
type FilesResponse struct {
	// in: body
	Body FilePaths
}

// This is a HACK - I can't figure out how to get
// swagger to render this a binary.  So we lie.
// We also override this object from the server
// directory to have a binary format which
// turns it into a stream.
//
// FileResponse returned on a successful GET of a file
// swagger:response
type FileResponse struct {
	// in: body
	Body string
}

// FileInfoResponse returned on a successful upload of a file
// swagger:response
type FileInfoResponse struct {
	// in: body
	Body *models.BlobInfo
}

// swagger:parameters listFiles
type FilesPathQueryParameter struct {
	// in: query
	Path string `json:"path"`
}

// swagger:parameters uploadFile getFile deleteFile headFile
type FilePathPathParameter struct {
	// in: path
	Path string `json:"path"`
	// in: explode
	Explode string `json:"explode"`
}

// FileData body of the upload
// swagger:parameters uploadFile
type FileData struct {
	// in: body
	Body interface{}
}

func (f *Frontend) InitFileApi() {
	list, get, head, post, delete := f.FileCommonFuncs("files")

	// swagger:route GET /files Files listFiles
	//
	// Lists files in files directory or subdirectory per query parameter
	//
	// Lists the files in a directory under /files.  path=<path to return>
	// Path defaults to /
	//
	//     Responses:
	//       200: FilesResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/files", list)

	// swagger:route GET /files/{path} Files getFile
	//
	// Get a specific File with {path}
	//
	// Get a specific file specified by {path} under files.
	//
	//     Produces:
	//       application/octet-stream
	//       application/json
	//
	//     Responses:
	//       200: FileResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	f.ApiGroup.GET("/files/*path", get)

	// swagger:route HEAD /files/{path} Files headFile
	//
	// See if a file exists and return a checksum in the header
	//
	// Return 200 if the file specified by {path} exists, or return NotFound.
	//
	//     Responses:
	//       200: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: NoContentResponse
	f.ApiGroup.HEAD("/files/*path", head)

	// swagger:route POST /files/{path} Files uploadFile
	//
	// Upload a file to a specific {path} in the tree under files.
	//
	// The file will be uploaded to the {path} in /files.  The {path} will be created.
	//
	//     Consumes:
	//       application/octet-stream
	//
	//     Produces:
	//       application/json
	//
	//     Responses:
	//       201: FileInfoResponse
	//       400: ErrorResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       403: ErrorResponse
	//       404: ErrorResponse
	//       409: ErrorResponse
	//       415: ErrorResponse
	//       507: ErrorResponse
	f.ApiGroup.POST("/files/*path", post)

	// swagger:route DELETE /files/{path} Files deleteFile
	//
	// Delete a file to a specific {path} in the tree under files.
	//
	// The file will be removed from the {path} in /files.
	//
	//     Responses:
	//       204: NoContentResponse
	//       401: NoContentResponse
	//       403: NoContentResponse
	//       404: ErrorResponse
	//       422: ErrorResponse
	f.ApiGroup.DELETE("/files/*path", delete)
}
